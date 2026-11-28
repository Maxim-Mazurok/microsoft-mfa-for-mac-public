#!/usr/bin/env python3
"""E01: one ActivateNew bootstrap probe, never a completed enrollment.

Python 3.11+, standard library only. Default/demo/check/inspect are offline.
Publication scope and limitations: diagnostic/README.md.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import getpass
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import ssl
import stat
import sys
import time
from urllib.parse import parse_qsl, urlsplit
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0"
RESPONSE_PARSER_REVISION = 2
DEVICE_NAME = "Mac E01 diagnostic"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
PF = "http://www.phonefactor.com/PfPaWs"
ACTION = PF + "/ActivateNew"
MAX_INPUT = 16_384
MAX_RESPONSE = 262_144
DEADLINE_SECONDS = 30

# ActivationParametersParserEntraMfa.java:44. No arbitrary-host override.
SERVICE_DOMAINS = (
    "mobileappcommunicator.auth.microsoft.com",
    "mobileappcommunicator.auth-ppe.microsoft.com",
    "mobileappcommunicator.auth.microsoft.us",
    "mobileappcommunicator.auth.microsoft.cn",
    "mobileappcommunicator.svc.sovcloud.fr",
    "mobileappcommunicator.svc.sovcloud.de",
    "mobileappcommunicator.svc.sovcloud.sg",
    "adnotifications.windowsazure.com",
    "adnotifications-ppe.windowsazure.com",
    "adnotifications.windowsazure.us",
    "strongauthentication.svc.sovcloud.fr",
    "strongauthentication.svc.sovcloud.de",
    "strongauthentication.svc.sovcloud.sg",
    "phonefactor.net",
)
# ActivationConstants.java:10-19,35-38,49-50.
APP_LINK_HOSTS = (
    "login.microsoftonline.com", "login.microsoftonline.us", "login.chinacloudapi.cn",
    "login.sovcloud-identity.fr", "login.sovcloud-identity.de", "login.sovcloud-identity.sg",
)
SECRET_FIELDS = (
    "Username", "AzureObjectId", "TenantId", "ConfirmationCode", "OathTokenSecretKey",
    "RoutingHint", "ReplicationScope", "CountryCode",
)
PARSED_FIELDS = SECRET_FIELDS + ("ActivateNewResult", "OathTokenEnabled", "Code", "Description")


class DiagnosticError(Exception):
    """Only fixed local identifiers; never include user or service strings."""


@dataclass(frozen=True, repr=False)
class Destination:
    host: str
    path: str
    domain: str


@dataclass(frozen=True, repr=False)
class Enrollment:
    code: str
    base_url: str
    destination: Destination
    link_kind: str


@dataclass(repr=False)
class ParsedResponse:
    result: bool | None
    fields: dict[str, str]
    fault: bool = False
    request_id_present: bool = False


def _clean_uri(value: str) -> None:
    # urlsplit otherwise silently strips some controls; fail before parsing.
    if not value or len(value) > MAX_INPUT or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise DiagnosticError("invalid_uri_characters")
    if "\\" in value or re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise DiagnosticError("invalid_uri_encoding")


def validate_destination(value: str) -> Destination:
    _clean_uri(value)
    try:
        parts = urlsplit(value)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise DiagnosticError("invalid_destination") from None
    if (parts.scheme.lower() != "https" or not host or parts.username is not None
            or parts.password is not None or port not in (None, 443)
            or "?" in value or "#" in value):
        raise DiagnosticError("invalid_destination")
    if parts.netloc.lower() not in (host, host + ":443"):
        raise DiagnosticError("invalid_destination_authority")
    if len(host) > 253 or host.endswith(".") or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in host.split(".")
    ):
        raise DiagnosticError("invalid_destination_host")
    domain = next((d for d in SERVICE_DOMAINS if host == d or host.endswith("." + d)), None)
    if domain is None:
        raise DiagnosticError("destination_not_allowlisted")
    # Preserve ordinary service base paths; reject ambiguous encodings/traversal.
    path = parts.path
    if (not re.fullmatch(r"(?:/[A-Za-z0-9_.~-]+)*/?", path)
            or any(segment in (".", "..") for segment in path.split("/"))
            or path.lower().rstrip("/").endswith(".asmx")):
        raise DiagnosticError("invalid_service_base_path")
    return Destination(host, path.rstrip("/") + "/PfPaWs.asmx", domain)


def _validate_code(code: str) -> None:
    if not code or len(code) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in code):
        raise DiagnosticError("invalid_activation_code")


def parse_qr(payload: str) -> Enrollment:
    """Parse decoded QR text; does not fetch links or decode image pixels."""
    payload = payload.strip()
    _clean_uri(payload)
    try:
        parts = urlsplit(payload)
        if (parts.username is not None or parts.password is not None or parts.port is not None
                or parts.netloc.lower() != parts.hostname or "#" in payload):
            raise DiagnosticError("invalid_qr_link")
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict", max_num_fields=16)
    except (ValueError, UnicodeError):
        raise DiagnosticError("invalid_qr_link") from None
    params: dict[str, str] = {}
    for name, value in pairs:
        if name in params:
            raise DiagnosticError("duplicate_qr_parameter")
        params[name] = value
    if (parts.scheme.lower() in ("phonefactor", "microsoft-authenticator")
            and parts.hostname in ("activate_account", "activatemfa") and parts.path in ("", "/")):
        kind = "legacy"
    elif (parts.scheme.lower() == "https" and parts.hostname in APP_LINK_HOSTS
          and parts.path.lower() == "/authenticatorapp/activateaccount"
          and params.get("accountType") == "mfa"
          and params.get("source") in ("qrCode", "sameDevicePair")):
        kind = "app_link"
    else:
        raise DiagnosticError("unsupported_qr_link")
    if "code" not in params or "url" not in params:
        raise DiagnosticError("missing_qr_parameters")
    # Avoid silently accepting consumer-account data on a legacy wrapper.
    if "accountType" in params and params["accountType"] != "mfa":
        raise DiagnosticError("unsupported_account_type")
    _validate_code(params["code"])
    destination = validate_destination(params["url"])
    return Enrollment(params["code"], params["url"], destination, kind)


def serialize_activate_new(enrollment: Enrollment, counter: int | None = None) -> bytes:
    validate_destination(enrollment.base_url)
    _validate_code(enrollment.code)
    counter = int(time.time()) // 30 if counter is None else counter
    if type(counter) is not int or counter <= 0 or counter > 2**63 - 1:
        raise DiagnosticError("invalid_counter")
    envelope = ET.Element("soap:Envelope", {
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
        "xmlns:soap": SOAP, "xmlns:ns4": PF,
    })
    ET.SubElement(envelope, "soap:Header")
    body = ET.SubElement(envelope, "soap:Body")
    activation = ET.SubElement(body, "ns4:ActivateNew")
    params = ET.SubElement(activation, "ns4:activationParams")
    for name, value in (
        ("ActivationCode", enrollment.code), ("DeviceToken", ""),
        ("DeviceName", DEVICE_NAME), ("OathCounter", str(counter)), ("Version", VERSION),
    ):
        ET.SubElement(params, "ns4:" + name).text = value
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=False)


def parse_response(data: bytes) -> ParsedResponse:
    if len(data) > MAX_RESPONSE:
        raise DiagnosticError("response_too_large")
    try:
        text = data.decode("utf-8-sig")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I):
            raise DiagnosticError("unsafe_xml_declaration")
        encoding = re.search(r"<\?xml\b[^?]*encoding\s*=\s*['\"]([^'\"]+)", text, re.I)
        if encoding and encoding[1].lower() not in ("utf-8", "utf8"):
            raise DiagnosticError("unsupported_xml_encoding")
        root = ET.fromstring(text)
    except (UnicodeError, ET.ParseError, ValueError):
        raise DiagnosticError("invalid_xml_response") from None
    stack, count = [(root, 0)], 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if depth > 32 or count > 2048:
            raise DiagnosticError("xml_structure_limit")
        stack.extend((child, depth + 1) for child in node)
    bodies = root.findall(f"{{{SOAP}}}Body")
    if root.tag != f"{{{SOAP}}}Envelope" or len(bodies) != 1:
        raise DiagnosticError("unexpected_soap_envelope")
    # Observed service response: one operation followed by soap:RequestId.
    # Allow only that scalar metadata sibling, never arbitrary extra operations.
    # Do not retain its value: it can be sensitive and is not an account proof.
    operations, request_ids = [], []
    for child in bodies[0]:
        if child.tag in (f"{{{PF}}}ActivateNewResponse", f"{{{SOAP}}}Fault"):
            operations.append(child)
        elif child.tag == f"{{{SOAP}}}RequestId":
            request_ids.append(child)
        else:
            raise DiagnosticError("unexpected_soap_operation")
    if len(operations) != 1:
        raise DiagnosticError("ambiguous_or_missing_soap_operation")
    if len(request_ids) > 1 or any(len(node) or node.attrib for node in request_ids):
        raise DiagnosticError("ambiguous_or_invalid_soap_metadata")
    response = operations[0]
    if response.tag == f"{{{SOAP}}}Fault":
        return ParsedResponse(None, {}, fault=True, request_id_present=bool(request_ids))
    fields: dict[str, str] = {}
    for node in response.iter():
        name = node.tag.removeprefix("{" + PF + "}")
        if name not in PARSED_FIELDS:
            continue
        if name in fields or len(node):
            raise DiagnosticError("ambiguous_response_field")
        fields[name] = node.text or ""
    result_text = fields.get("ActivateNewResult", "").strip()
    if result_text not in ("true", "false", "1", "0"):
        raise DiagnosticError("missing_or_invalid_activation_result")
    if "OathTokenEnabled" in fields and fields["OathTokenEnabled"].strip() not in ("true", "false", "1", "0"):
        raise DiagnosticError("invalid_oath_enabled_boolean")
    return ParsedResponse(result_text in ("true", "1"), fields,
                          request_id_present=bool(request_ids))


def report_response(parsed: ParsedResponse, status: int, forbidden: tuple[str, ...] = ()) -> dict:
    report = {
        "response_parser_revision": RESPONSE_PARSER_REVISION,
        "http_status": status,
        "bootstrap_state": "inconclusive",
        "activate_new_result": parsed.result,
        "soap_fault": parsed.fault,
        "soap_request_id_present": parsed.request_id_present,
        "enrollment_completed": False,
        "device_token_validated": False,
        "confirmation_sent": False,
        "field_presence": {name: bool(parsed.fields.get(name)) for name in SECRET_FIELDS},
        "error_description_present": bool(parsed.fields.get("Description")),
        "service_error_code": None,
        "oath_token_enabled": (parsed.fields["OathTokenEnabled"].strip() in ("true", "1"))
        if "OathTokenEnabled" in parsed.fields else None,
    }
    if 300 <= status < 400:
        report["bootstrap_state"] = "redirect_blocked"
    elif not 200 <= status < 300:
        report["bootstrap_state"] = "http_error"
    elif parsed.fault:
        report["bootstrap_state"] = "soap_fault"
    elif parsed.result is True:
        report["bootstrap_state"] = "progress_reported_not_enrolled"
    elif parsed.result is False:
        report["bootstrap_state"] = "rejected"
    # Only a bounded numeric error code can leave the private response, never
    # Description/fault text, identifiers, URLs, tokens, or unrecognized content.
    code = parsed.fields.get("Code", "").strip()
    sensitive = forbidden + tuple(parsed.fields.get(name, "") for name in SECRET_FIELDS)
    if re.fullmatch(r"-?[0-9]{1,10}", code) and -(2**31) <= int(code) < 2**31:
        if not any(code in secret for secret in sensitive if secret):
            report["service_error_code"] = int(code)
    return report


def request_report(enrollment: Enrollment) -> dict:
    # Even a host/path could contain an enrollment code. Print only the fixed
    # allowlist suffix and static shape, never a full destination or body hash.
    return {
        "experiment": "E01", "diagnostic_version": VERSION,
        "service_domain": validate_destination(enrollment.base_url).domain, "link_kind": enrollment.link_kind,
        "operation": "ActivateNew", "endpoint_suffix": "/PfPaWs.asmx",
        "activation_code_present": True, "device_token": "intentionally_empty",
        "device_name": DEVICE_NAME, "version_field": VERSION,
        "request_fields": ["ActivationCode", "DeviceToken", "DeviceName", "OathCounter", "Version"],
        "enrollment_completed": False, "device_token_validated": False,
        "confirmation_sent": False, "request_attempt_budget_consumed": 0,
    }


def read_private_file(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > limit):
            raise DiagnosticError("private_file_permissions_or_size")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise DiagnosticError("private_file_too_large")
        return data
    finally:
        os.close(fd)


def secret_prompt(label: str) -> str:
    if not sys.stdin.isatty():
        raise DiagnosticError("hidden_prompt_requires_terminal_or_private_file")
    # Never allow getpass's fallback to an echoing input stream.
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(label)


def read_enrollment(args: argparse.Namespace) -> Enrollment:
    if args.qr_file:
        return parse_qr(read_private_file(Path(args.qr_file), MAX_INPUT).decode("utf-8"))
    if args.manual:
        code = secret_prompt("Activation code (hidden): ").strip()
        base = secret_prompt("Service base URL (hidden): ").strip()
        _validate_code(code)
        return Enrollment(code, base, validate_destination(base), "manual")
    return parse_qr(secret_prompt("Decoded enrollment QR text (hidden): "))


class PrivateRun:
    """Fixed ignored destination, 0700 directories, exclusive 0600 files."""

    def __init__(self, root: Path = ROOT):
        self.run_id = uuid.uuid4().hex
        self.fd: int | None = None
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in (".secrets", "e01", self.run_id):
                try:
                    os.mkdir(name, mode=0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                info = os.fstat(child)
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    os.close(child)
                    raise DiagnosticError("private_directory_permissions")
                os.close(parent)
                parent = child
            self.fd, parent = parent, None
        finally:
            if parent is not None:
                os.close(parent)

    def write(self, name: str, data: bytes) -> None:
        if name not in ("attempt.json", "response.bin", "report.json"):
            raise DiagnosticError("invalid_private_filename")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class DirectHTTPSConnection(http.client.HTTPSConnection):
    """No proxy, redirect, alternate-IP retry, cookies or auth negotiation."""

    def connect(self) -> None:
        addresses = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
            raise DiagnosticError("nonpublic_service_address")
        family, kind, protocol, _, sockaddr = addresses[0]
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(self.timeout)
            sock.connect(sockaddr)  # One selected address, no fallback/retry.
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


@contextmanager
def deadline():
    def expired(_signum, _frame):
        raise DiagnosticError("request_deadline_exceeded")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, DEADLINE_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def send_once(enrollment: Enrollment, body: bytes) -> tuple[int, bytes]:
    target = validate_destination(enrollment.base_url)  # Validate again at send boundary.
    # Construct explicitly so SSLKEYLOGFILE cannot enable TLS-secret logging.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    context.keylog_filename = None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    conn = DirectHTTPSConnection(target.host, 443, timeout=DEADLINE_SECONDS, context=context)
    conn.set_debuglevel(0)
    try:
        with deadline():
            conn.request("POST", target.path, body=body, headers={
                "Content-Type": "text/xml; charset=utf-8", "SOAPAction": ACTION,
                "User-Agent": "Microsoft-MFA-for-Mac-E01/" + VERSION,
                "Accept-Encoding": "identity", "Connection": "close",
            })
            response = conn.getresponse()
            return response.status, response.read(MAX_RESPONSE + 1)
    finally:
        conn.close()


def run_live(enrollment: Enrollment, root: Path = ROOT) -> tuple[dict, int]:
    body = serialize_activate_new(enrollment)
    report = request_report(enrollment)
    report.update(mode="live", cleanup_required=True, submission_state="not_attempted",
                  started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    run = PrivateRun(root)
    report["private_run_id"] = run.run_id
    try:
        # Durable marker before any network call. A crash/timeout means the QR
        # may be consumed; there is no resume or automatic retry.
        report.update(request_attempt_budget_consumed=1, submission_state="attempted_outcome_unknown")
        run.write("attempt.json", json.dumps(report, indent=2).encode())
        try:
            status, response = send_once(enrollment, body)
            report.update(http_status=status, submission_state="http_response_received")
            run.write("response.bin", response)
            if 300 <= status < 400:
                report["bootstrap_state"] = "redirect_blocked"
            else:
                try:
                    parsed = parse_response(response)
                    report.update(report_response(parsed, status, (enrollment.code, enrollment.base_url)))
                except DiagnosticError as exc:
                    report.update(bootstrap_state="unparsed_response", response_error=str(exc))
        except (DiagnosticError, OSError, http.client.HTTPException):
            # Exception strings can contain URLs, headers or response content.
            report.update(bootstrap_state="transport_or_storage_error", error="request_outcome_uncertain")
        run.write("report.json", json.dumps(report, indent=2).encode())
    finally:
        run.close()
    return report, 0 if report.get("bootstrap_state") == "progress_reported_not_enrolled" else 3


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal errors can echo a secret mistakenly supplied as an argument.
        raise DiagnosticError("invalid_arguments_use_help_no_secrets_on_command_line")


def parser() -> argparse.ArgumentParser:
    p = SafeArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="command", parser_class=SafeArgumentParser)
    commands.add_parser("demo", help="Run fixed synthetic fixtures offline (default)")
    for command in ("check", "live"):
        sub = commands.add_parser(command, help="Offline validation" if command == "check" else "Explicit one-request E01 probe")
        inputs = sub.add_mutually_exclusive_group()
        inputs.add_argument("--qr-file", metavar="PRIVATE_FILE", help="Owner-only text file containing decoded QR text")
        inputs.add_argument("--manual", action="store_true", help="Hidden prompts for code and service base URL")
        if command == "live":
            sub.add_argument("--one-request", action="store_true", help="Required acknowledgement of one live POST")
    inspect = commands.add_parser("inspect", help="Parse a private saved response offline")
    inspect.add_argument("--response-file", required=True, metavar="PRIVATE_FILE")
    inspect.add_argument("--http-status", type=int, required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        args = parser().parse_args(argv)
        command = args.command or "demo"
        if command == "demo":
            fixtures = Path(__file__).with_name("fixtures")
            enrollment = parse_qr((fixtures / "enrollment.txt").read_text())
            serialize_activate_new(enrollment, counter=60_000_000)
            report = request_report(enrollment)
            report.update(mode="offline_synthetic", network_used=False)
            report["synthetic_responses"] = {
                name: report_response(parse_response((fixtures / (name + ".xml")).read_bytes()), 200)
                for name in ("success", "rejected", "fault")
            }
            exit_code = 0
        elif command == "inspect":
            if not 100 <= args.http_status <= 599:
                raise DiagnosticError("invalid_http_status")
            parsed = parse_response(read_private_file(Path(args.response_file), MAX_RESPONSE))
            report = report_response(parsed, args.http_status)
            report.update(mode="offline_inspection", network_used=False)
            exit_code = 0
        else:
            if command == "live" and not args.one_request:
                raise DiagnosticError("live_requires_one_request_flag")
            enrollment = read_enrollment(args)
            if command == "check":
                serialize_activate_new(enrollment)
                report = request_report(enrollment)
                report.update(mode="offline_check", network_used=False)
                exit_code = 0
            else:
                report, exit_code = run_live(enrollment)
        print(json.dumps(report, indent=2, sort_keys=True))
        return exit_code
    except DiagnosticError as exc:
        print(json.dumps({"error": str(exc), "enrollment_completed": False}), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('{"error":"interrupted_check_private_attempt_marker_before_any_new_run"}', file=sys.stderr)
        return 130
    except Exception:
        # No exception text, traceback, payload, filename, or environment dump.
        print('{"error":"local_failure_check_permissions_and_private_attempt_marker"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
