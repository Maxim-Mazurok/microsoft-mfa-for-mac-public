#!/usr/bin/env python3
"""P01: one new Google check-in, at most one MCS login. No sender/enrollment.

Default is offline preparation. Live requires exactly `live --one-attempt` and
an unused persistent attempt lock. No input credentials, URL overrides or retry.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import resource
import signal
import socket
import ssl
import stat
import sys
import time
import uuid

import push_protocol as p

ROOT = Path(__file__).resolve().parents[1]
SECONDS = 30
ENDPOINTS = {"checkin": ("android.clients.google.com", 443), "mcs": ("mtalk.google.com", 5228)}
FILENAMES = {"attempt.json", "checkin-response.bin", "credentials.json", "mcs-response.bin", "report.json"}


class ProbeError(Exception):
    """Fixed local identifiers only."""


def require(condition, code):
    if not condition:
        raise ProbeError(code)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


class PrivateRun:
    """Owned 0700 storage; exclusive 0600 files; persistent one-attempt guard."""
    def __init__(self, root: Path):
        self.fd = None
        self.run_id = uuid.uuid4().hex
        require(root.is_absolute() and ".." not in root.parts, "invalid_storage_root")
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            # Walk every ancestor, not just the final component, without symlinks.
            for name in root.parts[1:]:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
                info = os.fstat(parent)
                require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022,
                        "insecure_storage_ancestor")
            require(os.fstat(parent).st_uid == os.getuid(), "storage_root_not_owned")
            for name in (".secrets", "push"):
                try:
                    os.mkdir(name, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
                info = os.fstat(parent)
                require(info.st_uid == os.getuid() and not info.st_mode & 0o077,
                        "insecure_private_directory")
            try:
                fd = os.open("p01-attempt.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
            except FileExistsError:
                raise ProbeError("p01_attempt_already_reserved_no_retry") from None
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
        require(name in FILENAMES, "invalid_private_filename")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, "wb") as stream:
            try:
                yield stream
            finally:
                stream.flush()
                os.fsync(stream.fileno())

    def write(self, name, value):
        with self.capture(name) as stream:
            stream.write(value)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Deadline:
    def __enter__(self):
        require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "existing_process_timer")
        self.end = time.monotonic() + SECONDS
        self.previous = signal.signal(signal.SIGALRM, self.expired)
        signal.setitimer(signal.ITIMER_REAL, SECONDS)
        return self

    @staticmethod
    def expired(_signum, _frame):
        raise ProbeError("overall_deadline_exceeded")

    def remaining(self):
        remaining = self.end - time.monotonic()
        require(remaining > 0, "overall_deadline_exceeded")
        return remaining

    def __exit__(self, *_):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.previous)


def tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.keylog_filename = None
    require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED,
            "tls_verification_required")
    return context


def connect_tls(kind, deadline, report):
    require(kind in ENDPOINTS, "destination_not_permitted")
    key = kind + "_connections_attempted"
    require(report[key] == 0, "connection_budget_exhausted")
    report[key] += 1
    host, port = ENDPOINTS[kind]
    context = tls_context()
    # SIGALRM covers DNS too. Every address is checked; only the first is tried.
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    require(bool(answers), "dns_empty")
    require(all(row[0] in (socket.AF_INET, socket.AF_INET6)
                and ipaddress.ip_address(row[4][0]).is_global for row in answers), "nonpublic_dns_answer")
    family, kind_, protocol, _, address = answers[0]
    sock = socket.socket(family, kind_, protocol)
    try:
        sock.settimeout(deadline.remaining())
        sock.connect(address)
        sock.settimeout(deadline.remaining())
        secured = context.wrap_socket(sock, server_hostname=host)
        report[kind + "_tls_verified"] = True
        return secured
    except BaseException:
        sock.close()
        raise


class CaptureReader(io.RawIOBase):
    """Cap all received plaintext, including HTTP headers and chunk framing.

    Two connections, each <=256 KiB: <=512 KiB combined. TLS overhead is managed
    by the verified system TLS stack. Deadline bounds slow peers and handshakes.
    """
    def __init__(self, sock, capture, deadline, report, kind):
        self.sock, self.capture, self.deadline = sock, capture, deadline
        self.report, self.kind = report, kind
        self.count = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        require(self.count < p.LIMIT, "response_receive_limit_reached")
        self.sock.settimeout(self.deadline.remaining())
        data = self.sock.recv(min(len(buffer), p.LIMIT - self.count))
        self.capture.write(data)
        self.count += len(data)
        self.report[self.kind + "_received_bytes"] = self.count
        buffer[:len(data)] = data
        return len(data)


class HTTPInput:
    def __init__(self, reader):
        self.reader = reader

    def makefile(self, mode):
        require(mode == "rb", "unexpected_http_io")
        return io.BufferedReader(self.reader, buffer_size=4096)


def checkin(sock, run, deadline, report):
    request = p.build_checkin()  # Fixed fresh request; accepts no external config.
    require(request.url == p.CHECKIN_URL, "unexpected_checkin_destination")
    wire = ("POST /checkin HTTP/1.1\r\nHost: android.clients.google.com\r\n"
            "Content-Type: application/x-protobuf\r\nAccept-Encoding: identity\r\n"
            "Connection: close\r\nUser-Agent: Mac-P01-diagnostic/0.1.0\r\n"
            f"Content-Length: {len(request.body)}\r\n\r\n").encode("ascii") + request.body
    report["stage"] = "checkin_send"
    require(report["checkin_posts_attempted"] == 0, "http_request_budget_exhausted")
    report["checkin_posts_attempted"] = 1  # Conservative: bytes may be partly sent.
    sock.settimeout(deadline.remaining())
    sock.sendall(wire)
    report["stage"] = "checkin_response"
    with run.capture("checkin-response.bin") as capture:
        reader = CaptureReader(sock, capture, deadline, report, "checkin")
        response = http.client.HTTPResponse(HTTPInput(reader), debuglevel=0)
        try:
            response.begin()
            report["checkin_http_status"] = response.status
            headers = response.headers
            for key in ("Content-Length", "Transfer-Encoding", "Content-Encoding"):
                require(len(headers.get_all(key, [])) <= 1, "ambiguous_http_headers")
            encoding = headers.get("Content-Encoding", "identity").strip().lower()
            require(encoding == "identity", "unexpected_content_encoding")
            length, transfer = headers.get("Content-Length"), headers.get("Transfer-Encoding")
            require(not (length is not None and transfer is not None), "ambiguous_http_framing")
            if transfer is not None:
                require(transfer.strip().lower() == "chunked", "unsupported_transfer_encoding")
            if length is not None:
                require(length.isascii() and length.isdigit() and len(length) <= 6,
                        "invalid_content_length")
                require(int(length) < p.LIMIT, "response_body_too_large")
            body = response.read(p.LIMIT)
            if length is not None:
                require(len(body) == int(length), "truncated_http_body")
            require(200 <= response.status < 300, "checkin_http_rejected")
            report["stage"] = "checkin_parse"
            return p.parse_checkin(body)
        finally:
            response.close()


def read_exact(reader, size):
    value = bytearray()
    while len(value) < size:
        buf = bytearray(min(4096, size - len(value)))
        count = reader.readinto(buf)
        require(count > 0, "mcs_closed_before_login_response")
        value.extend(buf[:count])
    return bytes(value)


def mcs_login(sock, credentials, run, deadline, report):
    report["stage"] = "mcs_login_send"
    require(report["mcs_logins_attempted"] == 0, "mcs_login_budget_exhausted")
    report["mcs_logins_attempted"] = 1
    sock.settimeout(deadline.remaining())
    sock.sendall(p.build_mcs_login(credentials))
    report["stage"] = "mcs_login_response"
    with run.capture("mcs-response.bin") as capture:
        reader = CaptureReader(sock, capture, deadline, report, "mcs")
        header = read_exact(reader, 2)
        require(header[0] in (38, 41), "unsupported_mcs_version")
        require(header[1] == 3, "unexpected_mcs_event_before_login")
        length_bytes = bytearray()
        for _ in range(5):
            length_bytes.extend(read_exact(reader, 1))
            if length_bytes[-1] < 128:
                break
        else:
            raise ProbeError("invalid_mcs_frame_length")
        length, _ = p._read_varint(length_bytes, 0)
        require(length <= p.LIMIT - reader.count, "mcs_frame_too_large")
        decoder = p.MCSDecoder()
        frames = decoder.feed(header + length_bytes + read_exact(reader, length))
        decoder.finish()
        require(len(frames) == 1, "ambiguous_mcs_response")
        accepted = p.parse_mcs_login(frames[0])
        if not accepted:
            fields = p.decode_fields(frames[0].payload)
            error = p.decode_fields(fields.one(3, 2))
            code = error.one(1, 0)
            # Expose only a small numeric enum, never server message/type/JID.
            if 0 <= code <= 65535 and code not in (credentials.android_id, credentials.security_token):
                report["mcs_error_code"] = code
        report["mcs_accepted"] = accepted
        report["mcs_authenticated"] = accepted
        require(accepted, "mcs_login_rejected")


def safe_error(exc):
    if isinstance(exc, ProbeError):
        return str(exc)  # Only fixed identifiers constructed in this module.
    if isinstance(exc, p.ProtocolError):
        return "invalid_provider_protocol"  # Raw source stays private for diagnosis.
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls_certificate_verification_failed"
    if isinstance(exc, ssl.SSLError):
        return "tls_handshake_or_record_failed"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "network_timeout"
    if isinstance(exc, socket.gaierror):
        return "dns_resolution_failed"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, ConnectionResetError):
        return "connection_reset"
    if isinstance(exc, http.client.HTTPException):
        return "invalid_or_truncated_http_response"
    if isinstance(exc, OSError):
        return "local_io_or_network_failure"
    if isinstance(exc, KeyboardInterrupt):
        return "interrupted"
    return "internal_failure"


def run_once(root=ROOT):
    report = {"experiment": "P01", "mode": "live", "started_utc": datetime.now(timezone.utc).isoformat(),
              "stage": "private_storage", "outcome": "not_completed", "error": None,
              "fresh_credentials_observed": False, "mcs_accepted": None, "mcs_error_code": None,
              "checkin_http_status": None, "checkin_connections_attempted": 0,
              "checkin_posts_attempted": 0, "mcs_connections_attempted": 0, "mcs_logins_attempted": 0,
              "checkin_received_bytes": 0, "mcs_received_bytes": 0,
              "checkin_tls_verified": False, "mcs_tls_verified": False,
              "automatic_retries": 0, "microsoft_requests": 0, "fcm_sender_registrations": 0,
              **p.redacted_status()}
    run = None
    started = time.monotonic()
    try:
        run = PrivateRun(root)
        report["run_id"] = run.run_id
        run.write("attempt.json", json_bytes(report))
        with Deadline() as deadline:
            report["stage"] = "checkin_connect"
            with connect_tls("checkin", deadline, report) as sock:
                credentials = checkin(sock, run, deadline, report)
            report["fresh_credentials_observed"] = True
            report["checkin_credentials_present"] = True
            report["stage"] = "credential_storage"
            run.write("credentials.json", json_bytes({"android_id": str(credentials.android_id),
                                                       "security_token": str(credentials.security_token)}))
            report["stage"] = "mcs_connect"
            with connect_tls("mcs", deadline, report) as sock:
                mcs_login(sock, credentials, run, deadline, report)
            report["stage"] = "complete"
            report["outcome"] = "provider_identity_and_mcs_login_accepted"
    except (Exception, KeyboardInterrupt) as exc:
        report["error"] = safe_error(exc)
        report["outcome"] = "stopped_without_retry"
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if run is not None:
            try:
                run.write("report.json", json_bytes(report))
            finally:
                run.close()
    return report


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args in ([], ["prepare"]):
        report = p.prepare_checkin_probe()
        report["live_executor_included"] = True
        print(json_bytes(report).decode(), end="")
        return 0
    if args != ["live", "--one-attempt"]:
        print('{"error":"requires_live_and_one_attempt_flags"}')
        return 2
    try:
        # Fail before any request if core-dump suppression cannot be applied.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        report = run_once()
        print(json_bytes(report).decode(), end="")
        return 0 if report["error"] is None else 1
    except (Exception, KeyboardInterrupt):
        # Never emit raw exceptions, paths, credentials or traceback locals.
        print('{"error":"local_execution_or_report_failure_no_retry"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
