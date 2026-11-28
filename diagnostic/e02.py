#!/usr/bin/env python3
"""One fresh enrollment experiment with concurrent native MCS reception.

Default/check/setup are offline. Live needs an explicit one-attempt flag and a
fresh protected local input. Never approves authentication notifications.
"""
import argparse
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import socket
import sys
import threading
import time
from urllib.parse import urlsplit

import e01
import enrollment_protocol as ep
import p01
import p02
import p03
import p02_prepare as prep
import push_protocol as p
import research_runtime as rt

ROOT = Path(__file__).resolve().parents[1]
SECONDS = 120
HTTP_SECONDS = 30
PUSH_SECONDS = 60
INPUT_MAX_AGE = 600
FILES = {"attempt.json", "report.json", "activation.json", "validation.json", "confirmation.json",
         "notification.json", "activate-response.bin", "validate-response.bin", "confirm-response.bin",
         "activate-body.bin", "validate-body.bin", "confirm-body.bin", "mcs-response.bin"}
require = p01.require


def load_identity(root):
    config, credentials = p03.prerequisites(root)
    lock = rt.private_json(root / ".secrets/push/p03-attempt.lock")
    require(isinstance(lock.get("run_id"), str) and re.fullmatch(r"[0-9a-f]{32}", lock["run_id"]),
            "invalid_p03_locator")
    directory = root / ".secrets/push" / lock["run_id"]
    report = rt.private_json(directory / "report.json")
    require(report.get("experiment") == "P03" and report.get("run_id") == lock["run_id"]
            and report.get("aad_registration_issued") is True
            and report.get("fis_http_status") == 200 and report.get("register3_http_status") == 200,
            "successful_p03_provenance_required")
    registration = rt.private_json(directory / "registration.json")
    require(set(registration) == {"token"}, "invalid_registration_record")
    return config, credentials, ep.scalar(registration["token"])


def validate_input(data, *, now=None):
    require(set(data) == {"expected_account", "activation_code", "service_base_url", "created_at", "fresh_code"},
            "invalid_enrollment_input")
    now = time.time() if now is None else now
    require(type(data["created_at"]) in (float, int) and 0 <= now - data["created_at"] <= INPUT_MAX_AGE
            and data["fresh_code"] is True, "fresh_enrollment_input_required")
    account = ep.scalar(data["expected_account"], 320)
    require(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", account) is not None, "account_upn_required")
    e01._validate_code(data["activation_code"])
    dest = ep.destination(data["service_base_url"])
    enrollment = e01.Enrollment(data["activation_code"], data["service_base_url"], dest, "manual")
    return enrollment, account


def prerequisites(root):
    config, credentials, token = load_identity(root)
    data = rt.private_json(root / ".secrets/push/e02-setup/input.json")
    enrollment, account = validate_input(data)
    ep.activate(enrollment, token)
    return config, credentials, token, enrollment, account


def setup(root, manual, *, setup_id="e02", existing_account=None):
    require(setup_id in ("e02", "e02b"), "invalid_setup_identifier")
    setup_name = setup_id + "-setup"
    load_identity(root)  # Local provenance checks before requesting short-lived input.
    parent = rt.private_directory(root / ".secrets/push")
    try:
        try:
            os.mkdir(setup_name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
    finally:
        os.close(parent)
    parent = rt.private_directory(root / ".secrets/push" / setup_name)
    try:
        require("input.json" not in os.listdir(parent), "protected_input_already_exists")
    finally:
        os.close(parent)
    account = existing_account or e01.secret_prompt("Intended Microsoft work/school account UPN (hidden): ").strip()
    if manual:
        code = e01.secret_prompt("Fresh activation code from 'Can't scan image?' (hidden): ").strip()
        base = e01.secret_prompt("Service URL shown beside that code (hidden): ").strip()
    else:
        enrollment = e01.parse_qr(e01.secret_prompt("Fresh decoded QR text (hidden): "))
        code, base = enrollment.code, enrollment.base_url
    require(e01.secret_prompt("Type FRESH to confirm this is a newly generated, unused code: ") == "FRESH",
            "fresh_code_confirmation_required")
    data = {"expected_account": account, "activation_code": code, "service_base_url": base,
            "created_at": time.time(), "fresh_code": True}
    validate_input(data)
    if setup_id == "e02b":
        old = rt.private_json(root / ".secrets/push/e02-setup/input.json")
        require(code != old["activation_code"], "previous_activation_code_reuse_forbidden")
        require(account.casefold() == old["expected_account"].casefold(), "designated_account_must_match")
    parent = rt.private_directory(root / ".secrets/push" / setup_name)
    try:
        fd = os.open("input.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(rt.json_bytes(data)); stream.flush(); os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)
    return {"experiment": setup_id.upper(), "input_saved_privately": True, "network_requests": 0,
            "fresh_input_maximum_age_seconds": INPUT_MAX_AGE}


def new_report():
    report = {"experiment": "E02", "mode": "live", "started_utc": datetime.now(timezone.utc).isoformat(),
              "stage": "local_prerequisites", "failed_stage": None, "outcome": "not_completed", "error": None,
              "http_posts_attempted": 0, "new_google_checkins": 0, "provider_registrations": 0,
              "automatic_retries": 0, "mcs_logins_attempted": 0, "mcs_accepted": False,
              "mcs_frames_after_login": 0, "validation_push_observed": False,
              "prior_own_project_control_messages_ignored": 0,
              "prior_validation_notifications_ignored": 0,
              "device_token_validated": False, "dos_preventer_present": False,
              "bootstrap_accepted": False, "confirmation_accepted": False,
              "enrollment_completed": False, "security_info_method_observed": False,
              "same_mac_sign_in_approved": False, "authentication_approvals_sent": 0,
              "maximum_seconds": SECONDS, "http_timeout_seconds": HTTP_SECONDS,
              "push_window_seconds": PUSH_SECONDS, "receive_limit_per_connection": p.LIMIT,
              "service_error_code": None, "acknowledgments_sent": 0}
    for kind in ("activate", "validate", "confirm", "mcs"):
        report[kind + "_connections_attempted"] = 0
        report[kind + "_tls_verified"] = False
        report[kind + "_received_bytes"] = 0
        if kind != "mcs":
            report[kind + "_posts_attempted"] = 0
            report[kind + "_http_status"] = None
    return report


async def resolve(host, port):
    """One resolver call; a stalled OS resolver cannot hold process shutdown.

    Cancellation discards the result before any connection can be initiated.
    The daemon performs DNS only, never HTTP/TLS or credential operations.
    """
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    def publish(result, error):
        if not future.done():
            if error is not None:
                future.set_exception(error)
            else:
                future.set_result(result)
    def worker():
        try:
            result = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            error = None
        except Exception as exc:
            result, error = None, exc
        try:
            loop.call_soon_threadsafe(publish, result, error)
        except RuntimeError:
            pass  # Deadline ended and loop closed; never connect afterward.
    threading.Thread(target=worker, name="e02-bounded-dns", daemon=True).start()
    return await future


@asynccontextmanager
async def connection(host, port, kind, report):
    require(report[kind + "_connections_attempted"] == 0, "connection_budget_exhausted")
    report[kind + "_connections_attempted"] += 1
    loop = asyncio.get_running_loop()
    answers = await resolve(host, port)
    require(bool(answers) and all(row[0] in (socket.AF_INET, socket.AF_INET6)
            and ipaddress.ip_address(row[4][0]).is_global for row in answers), "invalid_or_nonpublic_dns")
    family, socktype, proto, _, address = answers[0]
    sock, writer = socket.socket(family, socktype, proto), None
    try:
        sock.setblocking(False)
        await loop.sock_connect(sock, address)  # One resolved address, no fallback/retry.
        reader, writer = await asyncio.open_connection(sock=sock, ssl=p01.tls_context(), server_hostname=host,
                                                       ssl_handshake_timeout=HTTP_SECONDS, limit=p.LIMIT)
        sock = None
        report[kind + "_tls_verified"] = True
        yield reader, writer
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (TimeoutError, OSError):
                pass
        if sock is not None:
            sock.close()


def request_wire(kind, request, enrollment):
    require(kind in ("activate", "validate", "confirm"), "invalid_http_operation")
    parts = urlsplit(request.url)
    if kind == "validate":
        dest = ep.validate_pad_request_url(request.url)
    else:
        dest = ep.destination(enrollment.base_url)
    require(request.url == "https://" + dest.host + dest.path, "destination_operation_mismatch")
    headers = {"Host": dest.host, "Connection": "close", "Accept-Encoding": "identity",
               "Content-Length": str(len(request.body)), "User-Agent": "Mac-E02-research/0.1"}
    seen = {k.lower() for k in headers}
    for key, value in request.headers.items():
        require(re.fullmatch(r"[A-Za-z0-9-]+", key) and key.lower() not in seen
                and isinstance(value, str) and value.isascii()
                and all(32 <= ord(c) < 127 for c in value), "invalid_http_header")
        seen.add(key.lower()); headers[key] = value
    require(0 < len(request.body) <= 32768, "request_size_limit")
    wire = (f"POST {dest.path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
            + "\r\n").encode("ascii") + request.body
    return dest.host, wire


def parse_http(raw):
    require(0 < len(raw) <= p.LIMIT and b"\r\n\r\n" in raw, "invalid_http_response")
    require(raw.index(b"\r\n\r\n") <= 32768, "http_headers_too_large")
    class Buffer(io.BytesIO):
        def close(self):
            pass  # Preserve read position for trailing-data validation.
    stream = Buffer(raw)
    class Source:
        def makefile(self, *args, **kwargs):
            return stream
    response = http.client.HTTPResponse(Source(), debuglevel=0)
    try:
        response.begin()
        h = response.headers
        for name in ("Content-Length", "Transfer-Encoding", "Content-Encoding"):
            require(len(h.get_all(name, [])) <= 1, "ambiguous_http_headers")
        require(h.get("Content-Encoding", "identity").strip().lower() == "identity", "unexpected_content_encoding")
        length, transfer = h.get("Content-Length"), h.get("Transfer-Encoding")
        require(length is None or transfer is None, "ambiguous_http_framing")
        require(transfer is None or transfer.strip().lower() == "chunked", "unsupported_transfer_encoding")
        require(length is None or (length.isascii() and length.isdigit() and len(length) <= 6
                                  and int(length) <= p.LIMIT), "invalid_content_length")
        body = response.read(p.LIMIT)
        require(length is None or len(body) == int(length), "truncated_http_body")
        require(stream.tell() == len(raw), "trailing_http_data")
        if length is not None:
            require(len(raw) - raw.index(b"\r\n\r\n") - 4 == int(length), "trailing_http_data")
        return response.status, body
    finally:
        response.close()


async def post(kind, request, enrollment, run, report):
    host, wire = request_wire(kind, request, enrollment)
    require(report["http_posts_attempted"] < 3 and report[kind + "_posts_attempted"] == 0,
            "http_request_budget_exhausted")
    async with asyncio.timeout(HTTP_SECONDS):
        async with connection(host, 443, kind, report) as (reader, writer):
            report["stage"] = kind + "_send"
            report["http_posts_attempted"] += 1; report[kind + "_posts_attempted"] += 1
            writer.write(wire); await writer.drain()
            report["stage"] = kind + "_response"
            raw = bytearray()
            with run.capture(kind + "-response.bin") as capture:
                while True:
                    chunk = await reader.read(min(4096, p.LIMIT - len(raw) + 1))
                    if not chunk:
                        break
                    require(len(raw) + len(chunk) <= p.LIMIT, "http_receive_limit")
                    raw.extend(chunk); capture.write(chunk)
                    report[kind + "_received_bytes"] += len(chunk)
            status, body = parse_http(bytes(raw))
            report[kind + "_http_status"] = status
            run.write(kind + "-body.bin", body)
            require(200 <= status < 300, kind + "_http_rejected")
            return body


class MCS:
    def __init__(self, reader, writer, capture, report):
        self.reader, self.writer, self.capture, self.report = reader, writer, capture, report
        self.decoder, self.pending = p.MCSDecoder(), []

    async def frame(self):
        while not self.pending:
            chunk = await self.reader.read(4096)
            require(bool(chunk), "mcs_connection_closed")
            require(self.report["mcs_received_bytes"] + len(chunk) <= p.LIMIT, "mcs_receive_limit")
            self.report["mcs_received_bytes"] += len(chunk); self.capture.write(chunk)
            self.pending.extend(self.decoder.feed(chunk))
        return self.pending.pop(0)

    async def login(self, credentials):
        require(self.report["mcs_logins_attempted"] == 0, "mcs_login_budget_exhausted")
        self.report["mcs_logins_attempted"] += 1
        self.writer.write(p.build_mcs_login(credentials)); await self.writer.drain()
        accepted = p.parse_mcs_login(await self.frame())
        self.report["mcs_accepted"] = accepted
        require(accepted, "mcs_login_rejected")


async def receive_validation(mcs, config, token, enrollment, run, report, *, ignored_guids=frozenset()):
    async with asyncio.timeout(PUSH_SECONDS):
        for _ in range(128):
            frame = await mcs.frame()
            report["mcs_frames_after_login"] += 1
            if frame.tag == 8:
                # P02 closed without ACKs, so its one control may be replayed on
                # the reused independent identity. Ignore only that known app/
                # sender/control kind; never treat it as Microsoft validation.
                if p02.is_prior_control_message(frame):
                    report["prior_own_project_control_messages_ignored"] += 1
                    continue
                data = p.parse_android_data(frame, sender_id=config.sender_id, package=config.package)
                if (data.properties.get("source") in ("SAS", "MFA Server")
                        and data.properties.get("type") == "validate" and data.properties.get("guid") in ignored_guids):
                    report["prior_validation_notifications_ignored"] += 1
                    continue
                run.write("notification.json", rt.json_bytes(data.properties))
                notice = ep.validation_notification(data.properties)
                report["validation_push_observed"] = True
                body = await post("validate", ep.validate(notice, token), enrollment, run, report)
                fields = ep.validation_response(body)
                run.write("validation.json", rt.json_bytes(fields))
                report["device_token_validated"] = True
                report["dos_preventer_present"] = bool(fields["dosPreventer"])
                return fields
            require(frame.tag != 4, "mcs_server_closed_stream")
            # The bounded listener can observe control frames but does not guess
            # transport ACK semantics or replay pending messages.
            p02.housekeeping(frame)
        require(False, "mcs_frame_count_limit_reached")


async def activation(enrollment, token, account, run, report, *, device_name=ep.DEVICE_NAME):
    body = await post("activate", ep.activate(enrollment, token, device_name=device_name), enrollment, run, report)
    parsed = ep.activation_response(body)
    run.write("activation.json", rt.json_bytes(parsed.fields))
    safe = e01.report_response(parsed, report["activate_http_status"], (enrollment.code, token))
    report["service_error_code"] = safe["service_error_code"]
    report["bootstrap_accepted"] = parsed.result is True
    require(parsed.result is True, "activation_rejected")
    require(parsed.fields.get("Username", "").casefold() == account.casefold(), "unexpected_activation_account")
    return parsed.fields


async def exchange(inputs, run, report, *, ignored_guids=frozenset(), device_name=ep.DEVICE_NAME):
    config, credentials, token, enrollment, account = inputs
    tasks = []
    async with asyncio.timeout(SECONDS):
        async with connection("mtalk.google.com", 5228, "mcs", report) as (reader, writer):
            with run.capture("mcs-response.bin") as capture:
                mcs = MCS(reader, writer, capture, report)
                async with asyncio.timeout(HTTP_SECONDS):
                    await mcs.login(credentials)
                report["stage"] = "bootstrap_and_push_validation"
                try:
                    tasks = [asyncio.create_task(activation(enrollment, token, account, run, report, device_name=device_name)),
                             asyncio.create_task(receive_validation(mcs, config, token, enrollment, run, report,
                                                                    ignored_guids=ignored_guids))]
                    # FIRST_EXCEPTION cancels counterpart on an explicit rejection;
                    # either response may arrive first. No busy polling or retries.
                    done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
                    for index, task in enumerate(tasks):
                        if task in done and task.exception() is not None:
                            report["failed_stage"] = "activate" if index == 0 else "validation_push_or_callback"
                            # A local push-parser failure must not discard a
                            # bootstrap already sent to Microsoft. Let its
                            # original bounded request finish once, no resend.
                            if index == 1 and not tasks[0].done():
                                await asyncio.gather(tasks[0], return_exceptions=True)
                            raise task.exception()
                    fields, validation = [t.result() for t in tasks]
                    require(fields.get("Username", "").casefold() == account.casefold(), "unexpected_activation_account")
                    require(not validation.get("username") or validation["username"].casefold() == account.casefold(),
                            "unexpected_validation_account")
                    require(fields.get("ConfirmationCode") and fields.get("OathTokenSecretKey")
                            and fields.get("AzureObjectId") and fields.get("TenantId"), "bootstrap_credentials_missing")
                    report["stage"] = "confirm_activation"
                    body = await post("confirm", ep.confirm(enrollment, fields["ConfirmationCode"]), enrollment, run, report)
                    confirmation = ep.confirmation_response(body)
                    run.write("confirmation.json", rt.json_bytes(confirmation))
                    report["confirmation_accepted"] = confirmation["ConfirmActivationResult"] in ("true", "1")
                    require(report["confirmation_accepted"], "confirmation_rejected")
                    require(bool(confirmation.get("phoneAppDetailId")), "confirmed_method_identifier_missing")
                    report["enrollment_completed"] = True
                    report["stage"] = "complete"
                    report["outcome"] = "confirmed_registration_sign_in_approval_untested"
                finally:
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)


def safe_error(exc):
    if isinstance(exc, (p01.ProbeError, e01.DiagnosticError)):
        return str(exc)  # These classes are exclusively fixed local identifiers.
    if isinstance(exc, p.ProtocolError):
        return "invalid_provider_message"
    if isinstance(exc, http.client.HTTPException):
        return "invalid_http_response"
    return p01.safe_error(exc)


def run_once(root):
    inputs = prerequisites(root)
    run = rt.PrivateRun(root, "e02", FILES)
    report, started = new_report(), time.monotonic()
    try:
        run.write("attempt.json", rt.json_bytes({"experiment": "E02", "maximum_http_posts": 3,
                  "maximum_mcs_connections": 1, "maximum_seconds": SECONDS, "automatic_retries": 0,
                  "operations": ["ActivateNew", "phoneAppValidateDeviceTokenRequest", "ConfirmActivation"],
                  "existing_accounts_sent": 0, "sign_in_approval_permitted": False}))
        asyncio.run(exchange(inputs, run, report))
    except Exception as exc:
        report["error"] = safe_error(exc)
        report["outcome"] = "stopped_at_recorded_stage"
    except KeyboardInterrupt:
        report["error"], report["outcome"] = "interrupted_no_retry", "stopped_at_recorded_stage"
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        run.write("report.json", rt.json_bytes({**report, "run_id": run.run_id}))
        run.close()
    return report


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("manifest", "check", "setup", "live"), nargs="?", default="manifest")
    parser.add_argument("--manual", action="store_true")
    parser.add_argument("--one-attempt", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "setup":
            require(not args.one_attempt, "invalid_cli_combination")
            result = setup(ROOT, args.manual)
        elif args.command == "check":
            prerequisites(ROOT)
            result = {"experiment": "E02", "offline_prerequisites_passed": True, "network_requests": 0}
        elif args.command == "live":
            require(args.one_attempt and not args.manual, "explicit_one_attempt_required")
            result = run_once(ROOT)
        else:
            result = {"experiment": "E02", "mode": "offline", "maximum_http_posts": 3,
                      "maximum_mcs_connections": 1, "maximum_seconds": SECONDS,
                      "sign_in_approvals": 0, "fresh_private_input_required": True}
    except Exception as exc:
        result = {"experiment": "E02", "error": safe_error(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result.get("error") else 0


if __name__ == "__main__":
    sys.exit(main())
