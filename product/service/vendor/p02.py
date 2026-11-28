#!/usr/bin/env python3
"""One owned-project FIS/register3/send control; one reused P01 MCS identity.

No check-in, OAuth acquisition, retries, redirects, Microsoft endpoints or cleanup.
Default is offline. Live requires exactly `live --one-attempt` and a fresh lock.
P01's executed sources remain unchanged; only its inert I/O helpers are reused.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import secrets
import signal
import socket
import sys
import time
import uuid

import p01 as base
import p02_prepare as prep
import push_protocol as p

ROOT = Path(__file__).resolve().parents[1]
SECONDS = 60
RECEIVE_SECONDS = 30
ENDPOINTS = {"fis": ("firebaseinstallations.googleapis.com", 443),
             "register3": ("android.clients.google.com", 443),
             "send": ("fcm.googleapis.com", 443), "mcs": ("mtalk.google.com", 5228)}
FILES = {"attempt.json", "probe.json", "installation.json", "registration.json", "report.json",
         "fis-response.bin", "register3-response.bin", "send-response.bin", "mcs-response.bin"}
require = base.require
ProbeError = base.ProbeError
json_bytes = base.json_bytes


def private_json(path):
    value = json.loads(prep.private_config(path), object_pairs_hook=p._object)
    require(isinstance(value, dict), "invalid_private_json")
    return value


def is_prior_control_message(frame, root=ROOT):
    if frame.tag != 8 or p.decode_fields(frame.payload).one(5, 2) != prep.PACKAGE.encode():
        return False
    config = prep.config_from_json(prep.private_config(root / ".secrets/push/p02-setup/config.json"))
    message = p.parse_android_data(frame, sender_id=config.sender_id, package=config.package)
    require(message.properties.get("p02_kind") == "native-mac-control", "unexpected_own_project_payload")
    return True


def prerequisites(root):
    """Local only; do not reserve an attempt until inputs pass validation."""
    setup = root / ".secrets/push/p02-setup"
    config = prep.config_from_json(prep.private_config(setup / "config.json"))
    certificate = prep.private_config(setup / "probe.der")
    require(hashlib.sha1(certificate).hexdigest().lower() == config.certificate_sha1.lower(),
            "certificate_config_mismatch")
    prep.prepare(config)
    lock = private_json(root / ".secrets/push/p01-attempt.lock")
    require(isinstance(lock.get("run_id"), str) and re.fullmatch(r"[0-9a-f]{32}", lock["run_id"]),
            "invalid_p01_locator")
    prior = root / ".secrets/push" / lock["run_id"]
    report = private_json(prior / "report.json")
    require(report.get("experiment") == "P01" and report.get("run_id") == lock["run_id"]
            and report.get("fresh_credentials_observed") is True
            and report.get("mcs_accepted") is True and report.get("checkin_posts_attempted") == 1,
            "successful_p01_provenance_required")
    data = private_json(prior / "credentials.json")
    require(set(data) == {"android_id", "security_token"}
            and all(isinstance(v, str) and re.fullmatch(r"[1-9][0-9]{0,19}", v) for v in data.values()),
            "invalid_p01_credentials")
    credentials = p.CheckinCredentials(int(data["android_id"]), int(data["security_token"]))
    credentials.validate()
    token = private_json(setup / "sender-token.json")
    require(set(token) == {"access_token", "issued_at", "expires_at", "service_account", "project_id"},
            "invalid_sender_credential")
    require(token["project_id"] == config.project_id
            and token["service_account"] == f"p02-sender@{config.project_id}.iam.gserviceaccount.com",
            "authorized_sender_required")
    require(type(token["issued_at"]) in (int, float) and type(token["expires_at"]) in (int, float)
            and 0 < token["expires_at"] - token["issued_at"] <= 600
            and token["issued_at"] <= time.time() < token["expires_at"] - SECONDS - 10,
            "sender_token_expired_or_too_close_to_expiry")
    prep.build_one_data_message(config, "synthetic-offline-token", token["access_token"], "0" * 32)
    return config, credentials, token


class PrivateRun:
    """Exclusive persistent P02 lock, separate from the immutable P01 lock."""
    def __init__(self, root):
        self.fd = None
        self.run_id = uuid.uuid4().hex
        require(root.is_absolute() and ".." not in root.parts, "invalid_storage_root")
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for name in root.parts[1:]:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
                info = os.fstat(parent)
                require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022,
                        "insecure_storage_ancestor")
            require(os.fstat(parent).st_uid == os.getuid(), "storage_root_not_owned")
            for name in (".secrets", "push"):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
                info = os.fstat(parent)
                require(info.st_uid == os.getuid() and not info.st_mode & 0o077,
                        "insecure_private_directory")
            try:
                fd = os.open("p02-attempt.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
            except FileExistsError:
                raise ProbeError("p02_attempt_already_reserved_no_retry") from None
            with os.fdopen(fd, "wb") as stream:
                stream.write(json_bytes({"run_id": self.run_id, "retry_permitted": False}))
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent)
            os.mkdir(self.run_id, 0o700, dir_fd=parent)
            self.fd = os.open(self.run_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        finally:
            os.close(parent)

    @contextmanager
    def capture(self, name):
        require(name in FILES, "invalid_private_filename")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, "wb") as stream:
            try:
                yield stream
            finally:
                stream.flush()
                os.fsync(stream.fileno())

    write = base.PrivateRun.write
    close = base.PrivateRun.close


class Deadline(base.Deadline):
    def __enter__(self):
        require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "existing_process_timer")
        self.end = time.monotonic() + SECONDS
        self.previous = signal.signal(signal.SIGALRM, self.expired)
        signal.setitimer(signal.ITIMER_REAL, SECONDS)
        return self


class ReceiveWindow:
    def __init__(self, overall):
        self.overall = overall
        self.end = time.monotonic() + RECEIVE_SECONDS

    def remaining(self):
        remaining = self.end - time.monotonic()
        require(remaining > 0, "nonce_delivery_not_observed_within_window")
        return min(remaining, self.overall.remaining())


def connect_tls(kind, deadline, report):
    require(kind in ENDPOINTS, "destination_not_permitted")
    key = kind + "_connections_attempted"
    require(report[key] == 0, "connection_budget_exhausted")
    report[key] += 1
    host, port = ENDPOINTS[kind]
    context = base.tls_context()
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    require(bool(answers), "dns_empty")
    require(all(row[0] in (socket.AF_INET, socket.AF_INET6)
                and ipaddress.ip_address(row[4][0]).is_global for row in answers), "nonpublic_dns_answer")
    family, type_, protocol, _, address = answers[0]
    sock = socket.socket(family, type_, protocol)
    try:
        sock.settimeout(deadline.remaining())
        sock.connect(address)  # Exactly one address; no fallback after failure.
        sock.settimeout(deadline.remaining())
        secured = context.wrap_socket(sock, server_hostname=host)
        report[kind + "_tls_verified"] = True
        return secured
    except BaseException:
        sock.close()
        raise


def request_wire(kind, request, config):
    paths = {"fis": f"/v1/projects/{config.project_id}/installations", "register3": "/c2dm/register3",
             "send": f"/v1/projects/{config.project_id}/messages:send"}
    require(kind in paths, "destination_not_permitted")
    host = ENDPOINTS[kind][0]
    require(request.url == "https://" + host + paths[kind], "destination_not_permitted")
    require(len(request.body) < p.LIMIT, "request_body_too_large")
    headers = {"Host": host, "Accept-Encoding": "identity", "Connection": "close",
               "Content-Length": str(len(request.body)), "User-Agent": "Mac-P02-diagnostic/0.1.0"}
    seen = {key.lower() for key in headers}
    # Only the register3 builder intentionally supplies User-Agent.
    for key, value in request.headers.items():
        require(re.fullmatch(r"[A-Za-z0-9-]+", key) and isinstance(value, str)
                and value.isascii() and all(32 <= ord(c) < 127 for c in value), "invalid_request_header")
        if key == "User-Agent" and kind == "register3":
            headers[key] = value
            continue
        require(key.lower() not in seen, "duplicate_request_header")
        seen.add(key.lower())
        headers[key] = value
    return (f"POST {paths[kind]} HTTP/1.1\r\n"
            + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode("ascii") + request.body


JSON_STATUS = {"INVALID_ARGUMENT", "PERMISSION_DENIED", "UNAUTHENTICATED", "NOT_FOUND",
               "RESOURCE_EXHAUSTED", "INTERNAL", "UNAVAILABLE", "FAILED_PRECONDITION"}
REGISTER_ERRORS = {"INVALID_SENDER", "AUTHENTICATION_FAILED", "PHONE_REGISTRATION_ERROR",
                   "SERVICE_NOT_AVAILABLE", "INVALID_PARAMETERS", "MISSING_INSTANCEID_SERVICE",
                   "TOO_MANY_REGISTRATIONS", "INVALID_TARGET", "INVALID_SCOPE", "InternalServerError"}


def provider_error(kind, body):
    """Output only fixed allowlisted enums; never provider messages/details."""
    if kind == "register3":
        for code in REGISTER_ERRORS:
            if body.strip() == ("Error=" + code).encode():
                return code
        return "unclassified_provider_error"
    try:
        obj = json.loads(body, object_pairs_hook=p._object)
        status = obj["error"]["status"]
        return status if isinstance(status, str) and status in JSON_STATUS else "unclassified_provider_error"
    except Exception:
        return "unclassified_provider_error"


def post(kind, request, config, run, deadline, report):
    wire = request_wire(kind, request, config)  # Validate before DNS/socket use.
    key = kind + "_posts_attempted"
    require(report[key] == 0 and report["http_posts_attempted"] < 3, "http_request_budget_exhausted")
    report["stage"] = kind + "_connect"
    with connect_tls(kind, deadline, report) as sock:
        report["stage"] = kind + "_send"
        report[key] += 1
        report["http_posts_attempted"] += 1  # Partial writes consume the attempt.
        sock.settimeout(deadline.remaining())
        sock.sendall(wire)
        report["stage"] = kind + "_response"
        with run.capture(kind + "-response.bin") as capture:
            reader = base.CaptureReader(sock, capture, deadline, report, kind)
            response = http.client.HTTPResponse(base.HTTPInput(reader), debuglevel=0)
            try:
                response.begin()
                report[kind + "_http_status"] = response.status
                h = response.headers
                for name in ("Content-Length", "Transfer-Encoding", "Content-Encoding"):
                    require(len(h.get_all(name, [])) <= 1, "ambiguous_http_headers")
                require(h.get("Content-Encoding", "identity").strip().lower() == "identity",
                        "unexpected_content_encoding")
                length, transfer = h.get("Content-Length"), h.get("Transfer-Encoding")
                require(length is None or transfer is None, "ambiguous_http_framing")
                if transfer is not None:
                    require(transfer.strip().lower() == "chunked", "unsupported_transfer_encoding")
                if length is not None:
                    require(length.isascii() and length.isdigit() and len(length) <= 6,
                            "invalid_content_length")
                    require(int(length) < p.LIMIT, "response_body_too_large")
                body = response.read(p.LIMIT)
                require(length is None or len(body) == int(length), "truncated_http_body")
                if not 200 <= response.status < 300:
                    report[kind + "_provider_error"] = provider_error(kind, body)
                    raise ProbeError(kind + "_http_rejected")
                report["stage"] = kind + "_parse"
                return body
            finally:
                response.close()


def read_exact(reader, size):
    result = bytearray()
    while len(result) < size:
        buf = bytearray(min(4096, size - len(result)))
        n = reader.readinto(buf)
        require(n > 0, "mcs_connection_closed")
        result.extend(buf[:n])
    return bytes(result)


def read_frame(reader, *, first=False):
    if first:
        require(read_exact(reader, 1)[0] in (38, 41), "unsupported_mcs_version")
    tag = read_exact(reader, 1)[0]
    require(tag <= 16, "invalid_mcs_tag")
    encoded = bytearray()
    for _ in range(5):
        encoded.extend(read_exact(reader, 1))
        if encoded[-1] < 128:
            break
    else:
        raise ProbeError("invalid_mcs_frame_length")
    length, _ = p._read_varint(encoded, 0)
    require(length <= p.LIMIT - reader.count, "mcs_frame_too_large")
    return p.Frame(tag, read_exact(reader, length))


def housekeeping(frame):
    """Validate pinned Chromium mcs.proto control messages; do not reply/replay."""
    f = p.decode_fields(frame.payload)
    if frame.tag in (0, 1):
        require(all(n in (1, 2, 3) for n, _, _ in f.values), "unknown_heartbeat_field")
        for n in (1, 2, 3):
            f.one(n, 0, required=False)
        return "heartbeat_ping" if frame.tag == 0 else "heartbeat_ack"
    require(frame.tag == 7, "unexpected_mcs_event")
    schema = {1: 0, 2: 0, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 2, 9: 0, 10: 0, 11: 0, 12: 0}
    require(all(n in schema for n, _, _ in f.values), "unknown_iq_field")
    for n, wire in schema.items():
        f.one(n, wire, required=n in (2, 3))
    require(f.one(2, 0) in (1, 2) and f.one(6, 2, required=False) is None,
            "unexpected_iq_type_or_error")
    raw = f.one(7, 2, required=False)
    require(raw is not None, "unknown_iq_without_extension")
    ext = p.decode_fields(raw)
    require(all(n in (1, 2) for n, _, _ in ext.values), "unknown_iq_extension_field")
    kind, data = ext.one(1, 0), ext.one(2, 2)
    require(kind in (12, 13), "unknown_iq_extension")
    ack = p.decode_fields(data)
    if kind == 13:
        require(not ack.values, "invalid_stream_ack")
        return "stream_ack"
    require(all(n == 1 and wire == 2 for n, wire, _ in ack.values), "invalid_selective_ack")
    for _, _, value in ack.values:
        value.decode("utf-8")
    return "selective_ack"


def mcs_login(sock, reader, credentials, deadline, report):
    report["stage"] = "mcs_login_send"
    require(report["mcs_logins_attempted"] == 0, "mcs_login_budget_exhausted")
    report["mcs_logins_attempted"] = 1
    sock.settimeout(deadline.remaining())
    sock.sendall(p.build_mcs_login(credentials))
    report["stage"] = "mcs_login_response"
    frame = read_frame(reader, first=True)
    accepted = p.parse_mcs_login(frame)
    if not accepted:
        error = p.decode_fields(p.decode_fields(frame.payload).one(3, 2))
        code = error.one(1, 0)
        if 0 <= code <= 65535 and code not in (credentials.android_id, credentials.security_token):
            report["mcs_error_code"] = code
    report["mcs_accepted"] = report["mcs_authenticated"] = accepted
    require(accepted, "mcs_login_rejected")


def parse_send(body, config):
    obj = json.loads(body, object_pairs_hook=p._object)
    require(isinstance(obj, dict) and set(obj) == {"name"} and isinstance(obj["name"], str),
            "invalid_send_response")
    # HTTP v1 commonly uses project ID; accept the same project's numeric ID too.
    prefixes = [f"projects/{project}/messages/" for project in (config.project_id, config.sender_id)]
    require(any(obj["name"].startswith(prefix) and len(obj["name"]) > len(prefix) for prefix in prefixes),
            "unexpected_send_project")


def receive_nonce(reader, deadline, config, nonce, report):
    report["stage"] = "nonce_receive"
    reader.deadline = ReceiveWindow(deadline)
    for _ in range(128):
        try:
            frame = read_frame(reader)
        except (TimeoutError, socket.timeout):
            raise ProbeError("nonce_delivery_not_observed_within_window") from None
        report["mcs_frames_after_login"] += 1
        if frame.tag == 8:
            data = p.parse_android_data(frame, sender_id=config.sender_id, package=config.package)
            require(data.properties.get("p02_kind") == "native-mac-control", "unexpected_payload_kind")
            require(data.properties.get("p02_nonce") == nonce, "unexpected_payload_nonce")
            report["nonce_delivered"] = True
            report["sender_package_kind_nonce_matched"] = True
            report["persistent_id_present"] = data.persistent_id is not None
            return
        require(frame.tag != 4, "mcs_server_closed_stream")
        kind = housekeeping(frame)
        report["housekeeping"][kind] += 1
    raise ProbeError("mcs_frame_count_limit_reached")


def new_report():
    report = {"experiment": "P02", "mode": "live", "started_utc": datetime.now(timezone.utc).isoformat(),
              "stage": "local_prerequisites", "outcome": "not_completed", "error": None,
              "new_google_checkins": 0, "oauth_requests_during_probe": 0, "automatic_retries": 0,
              "microsoft_requests": 0, "http_posts_attempted": 0, "p01_credentials_reused": False,
              "mcs_logins_attempted": 0, "mcs_accepted": None, "mcs_error_code": None,
              "send_accepted": False, "nonce_delivered": False, "sender_package_kind_nonce_matched": False,
              "persistent_id_present": False, "mcs_frames_after_login": 0,
              "housekeeping": dict.fromkeys(("heartbeat_ping", "heartbeat_ack", "selective_ack", "stream_ack"), 0),
              "acknowledgments_sent": 0, "maximum_seconds": SECONDS, "receive_window_seconds": RECEIVE_SECONDS,
              "plaintext_receive_limit_per_connection": p.LIMIT, **p.redacted_status()}
    for kind in ENDPOINTS:
        report[kind + "_connections_attempted"] = 0
        report[kind + "_tls_verified"] = False
        report[kind + "_received_bytes"] = 0
        if kind != "mcs":
            report[kind + "_posts_attempted"] = 0
            report[kind + "_http_status"] = None
            report[kind + "_provider_error"] = None
    return report


def safe_error(exc):
    if isinstance(exc, p.ProtocolError) and str(exc) in {
        "unexpected_sender", "unexpected_package", "raw_payload_not_supported", "duplicate_data_key",
        "duplicate_protobuf_field", "missing_protobuf_field", "wrong_wire_type", "expected_login_response"}:
        return str(exc)
    return base.safe_error(exc)


def run_once(root=ROOT):
    report, run = new_report(), None
    started = time.monotonic()
    try:
        config, credentials, sender = prerequisites(root)
        report["p01_credentials_reused"] = report["checkin_credentials_present"] = True
        report["stage"] = "private_storage"
        run = PrivateRun(root)
        # Locator is private; the returned public report deliberately omits it.
        run.write("attempt.json", json_bytes({**report, "run_id": run.run_id}))
        fid, nonce = p.new_fid(), secrets.token_hex(16)
        run.write("probe.json", json_bytes({"fid": fid, "nonce": nonce,
                                            "declared_unattested_profile": prep.PROFILE}))
        with Deadline() as deadline:
            body = post("fis", p.build_fis_create(config, fid), config, run, deadline, report)
            installation = p.parse_fis_create(body, config, fid)
            report["firebase_installation_present"] = True
            run.write("installation.json", json_bytes({"fid": installation.fid,
                      "refresh_token": installation.refresh_token, "auth_token": installation.auth_token,
                      "expires_seconds": installation.expires_seconds}))
            request = p.build_android_registration(config, installation, credentials, **prep.PROFILE)
            body = post("register3", request, config, run, deadline, report)
            registration = p.parse_registration(body)
            if not registration.accepted:
                report["register3_provider_error"] = provider_error("register3", body)
                raise ProbeError("register3_rejected")
            report["registration_token_present"] = True
            run.write("registration.json", json_bytes({"token": registration.token}))
            report["stage"] = "mcs_connect"
            with connect_tls("mcs", deadline, report) as sock, run.capture("mcs-response.bin") as capture:
                reader = base.CaptureReader(sock, capture, deadline, report, "mcs")
                mcs_login(sock, reader, credentials, deadline, report)
                require(time.time() < sender["expires_at"] - deadline.remaining(), "sender_token_expired")
                request = prep.build_one_data_message(config, registration.token, sender["access_token"], nonce)
                body = post("send", request, config, run, deadline, report)
                parse_send(body, config)
                report["send_accepted"] = True
                receive_nonce(reader, deadline, config, nonce, report)
            report["stage"] = "complete"
            report["outcome"] = "owned_project_nonce_delivered_on_mac"
    except (Exception, KeyboardInterrupt) as exc:
        report["error"] = safe_error(exc)
        report["outcome"] = "stopped_without_retry"
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if run is not None:
            try:
                run.write("report.json", json_bytes({**report, "run_id": run.run_id}))
            finally:
                run.close()
    return report


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args in ([], ["prepare"]):
        print(json_bytes({"experiment": "P02", "mode": "offline", "live_executor_included": True,
                          "maximum_http_posts": 3, "maximum_mcs_connections": 1,
                          "new_checkins": 0, "automatic_retries": 0, "microsoft_requests": 0}).decode(), end="")
        return 0
    if args not in (["check"], ["live", "--one-attempt"]):
        print('{"error":"requires_check_or_explicit_live_one_attempt"}')
        return 2
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if args == ["check"]:
            prerequisites(ROOT)
            print('{"local_prerequisites_valid":true,"network_requests":0}')
            return 0
        report = run_once()
        print(json_bytes(report).decode(), end="")
        return 0 if report["error"] is None else 1
    except (Exception, KeyboardInterrupt):
        print('{"error":"local_execution_or_report_failure_no_retry"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
