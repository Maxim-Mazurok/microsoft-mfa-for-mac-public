"""Offline push protocol primitives. No sockets, retries, persistence or enrollment.

Historical binary evidence is not distributed. These are codecs, not proof that
Google accepts a custom client or that Microsoft can send to its registration.
All request/response objects can contain secrets: never log their attributes.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import gzip
import hashlib
import json
import re
import struct
import sys
from urllib.parse import urlencode
import uuid

LIMIT = 262144
CHECKIN_URL = "https://android.clients.google.com/checkin"
REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
MCS_HOST = "mtalk.google.com"
MCS_PORT = 5228


class ProtocolError(ValueError):
    """Fixed local error identifiers only; no input or provider text."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ProtocolError(code)


def _text(value: str, maximum: int = 16384) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= maximum
             and all(32 <= ord(c) < 127 for c in value), "invalid_text")
    return value


@dataclass(frozen=True, repr=False)
class Request:
    url: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True, repr=False)
class AndroidConfig:
    project_id: str
    sender_id: str
    app_id: str
    api_key: str
    package: str
    certificate_sha1: str
    firebase_name: str
    app_version: str
    app_version_code: str

    def validate(self) -> None:
        _require(bool(re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", self.project_id)), "invalid_project")
        _require(bool(re.fullmatch(r"[1-9][0-9]{0,19}", self.sender_id)), "invalid_sender")
        _require(bool(re.fullmatch(r"1:" + self.sender_id + r":android:[0-9a-f]+", self.app_id)), "invalid_app_id")
        _require(bool(re.fullmatch(r"[A-Za-z0-9_-]{10,100}", self.api_key)), "invalid_api_key")
        _require(bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", self.package)), "invalid_package")
        _require(bool(re.fullmatch(r"[0-9A-Fa-f]{40}", self.certificate_sha1)), "invalid_certificate_digest")
        _text(self.firebase_name, 100)
        _text(self.app_version, 100)
        _require(bool(re.fullmatch(r"[0-9]{1,12}", self.app_version_code)), "invalid_app_version")


def new_fid(installation_uuid: uuid.UUID | None = None) -> str:
    """APK RandomFidGenerator: 128 random bits with 0111 prefix, 22 chars."""
    raw = bytearray((installation_uuid or uuid.uuid4()).bytes)
    raw.append(raw[0])
    raw[0] = (raw[0] & 15) | 112
    return base64.urlsafe_b64encode(raw).decode("ascii")[:22]


def _fid(value: str) -> str:
    _require(isinstance(value, str) and bool(re.fullmatch(r"[c-f][A-Za-z0-9_-]{21}", value)), "invalid_fid")
    return value


def build_fis_create(config: AndroidConfig, fid: str) -> Request:
    config.validate()
    body = {"fid": _fid(fid), "appId": config.app_id,
            "authVersion": "FIS_v2", "sdkVersion": "a:16.3.5"}
    return Request(
        f"https://firebaseinstallations.googleapis.com/v1/projects/{config.project_id}/installations",
        {"Content-Type": "application/json", "Accept": "application/json",
         "Content-Encoding": "gzip", "Cache-Control": "no-cache",
         "X-Android-Package": config.package, "X-Android-Cert": config.certificate_sha1.upper(),
         "x-goog-api-key": config.api_key},
        gzip.compress(json.dumps(body, separators=(",", ":")).encode(), mtime=0))


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate_json_field")
        result[key] = value
    return result


@dataclass(frozen=True, repr=False)
class Installation:
    fid: str
    refresh_token: str
    auth_token: str
    expires_seconds: int


def parse_fis_create(data: bytes, config: AndroidConfig, requested_fid: str) -> Installation:
    """Parse a successful HTTP response only. Do not interpret errors as credentials."""
    config.validate()
    _require(len(data) <= LIMIT, "response_too_large")
    _fid(requested_fid)
    try:
        obj = json.loads(data, object_pairs_hook=_object)
        _require(isinstance(obj, dict) and "error" not in obj, "fis_not_success")
        fid = _fid(obj["fid"])
        # Fail closed on identity replacement until observed and explicitly reviewed.
        _require(fid == requested_fid, "fis_identity_changed")
        expected_names = {f"projects/{project}/installations/{fid}"
                          for project in (config.project_id, config.sender_id)}
        _require(obj["name"] in expected_names, "fis_identity_mismatch")
        auth = obj["authToken"]
        _require(isinstance(auth, dict), "invalid_fis_response")
        expiry = auth["expiresIn"]
        _require(isinstance(expiry, str) and bool(re.fullmatch(r"[1-9][0-9]{0,8}s", expiry)), "invalid_fis_expiry")
        return Installation(fid, _text(obj["refreshToken"]), _text(auth["token"]), int(expiry[:-1]))
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise ProtocolError("invalid_fis_response") from None


@dataclass(frozen=True, repr=False)
class CheckinCredentials:
    android_id: int
    security_token: int

    def validate(self) -> None:
        for value in (self.android_id, self.security_token):
            _require(type(value) is int and 0 < value < 2**64, "invalid_checkin_credentials")


def build_android_registration(config: AndroidConfig, installation: Installation,
                               credentials: CheckinCredentials, *,
                               gms_version: int, android_sdk: int, target_sdk: int,
                               device_name: str, build_id: str) -> Request:
    """Experimental mapping: APK GmsRpc bundle + microG register3 serializer.

    Not traced Google Play services wire bytes; no claim of server acceptance.
    Caller must supply explicit profile values. No invented signing credentials.
    """
    config.validate()
    credentials.validate()
    _require(type(gms_version) is int and 0 < gms_version < 2**31, "invalid_profile")
    _require(type(android_sdk) is int and 0 < android_sdk < 1000, "invalid_profile")
    _require(type(target_sdk) is int and 0 < target_sdk < 1000, "invalid_profile")
    _text(device_name, 100)
    _text(build_id, 100)
    bundle = {
        "scope": "*", "sender": config.sender_id, "subtype": config.sender_id,
        "appid": _fid(installation.fid), "gmp_app_id": config.app_id,
        "gmsv": str(gms_version), "osv": str(android_sdk),
        "app_ver": config.app_version_code, "app_ver_name": config.app_version,
        "firebase-app-name-hash": base64.urlsafe_b64encode(
            hashlib.sha1(config.firebase_name.encode()).digest()).decode().rstrip("="),
        "Goog-Firebase-Installations-Auth": _text(installation.auth_token),
        "cliv": "fiid-21.0.1",
    }
    form = {"app": config.package, "cert": config.certificate_sha1.lower(),
            "app_ver": config.app_version_code, "device": str(credentials.android_id),
            "sender": config.sender_id, "target_ver": str(target_sdk)}
    form.update({"X-" + key: value for key, value in bundle.items() if key != "sender"})
    return Request(REGISTER_URL,
                   {"Authorization": f"AidLogin {credentials.android_id}:{credentials.security_token}",
                    "User-Agent": f"Android-GCM/1.5 ({device_name} {build_id})",
                    "app": config.package, "Content-Type": "application/x-www-form-urlencoded"},
                   urlencode(form).encode("ascii"))


@dataclass(frozen=True, repr=False)
class Registration:
    token: str | None
    accepted: bool


def parse_registration(data: bytes) -> Registration:
    _require(len(data) <= LIMIT, "response_too_large")
    try:
        value = data.decode("ascii").rstrip("\r\n")
    except UnicodeError:
        raise ProtocolError("invalid_registration_response") from None
    _require("\r" not in value and "\n" not in value, "ambiguous_registration_response")
    key, separator, payload = value.partition("=")
    _require(separator == "=" and bool(payload), "invalid_registration_response")
    if key == "token":
        return Registration(_text(payload), True)
    if key == "Error":
        return Registration(None, False)  # Never reflect provider error text.
    raise ProtocolError("invalid_registration_response")


def varint(value: int) -> bytes:
    _require(type(value) is int and 0 <= value < 2**64, "invalid_uint64")
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _read_varint(data: bytes | bytearray, offset: int) -> tuple[int, int]:
    value = 0
    for i in range(10):
        if offset + i >= len(data):
            raise ProtocolError("truncated_varint")
        byte = data[offset + i]
        _require(i < 9 or byte < 2, "varint_overflow")
        value |= (byte & 127) << (7 * i)
        if byte < 128:
            _require(i == 0 or byte != 0, "noncanonical_varint")
            return value, offset + i + 1
    raise ProtocolError("varint_overflow")


def field(number: int, value: int | bytes | str, wire: int | None = None) -> bytes:
    _require(type(number) is int and 0 < number < 2**29, "invalid_field_number")
    if isinstance(value, str):
        value = value.encode("utf-8")
    wire = (2 if isinstance(value, bytes) else 0) if wire is None else wire
    tag = varint(number * 8 + wire)
    if wire == 2:
        _require(isinstance(value, bytes) and len(value) <= LIMIT, "invalid_bytes_field")
        return tag + varint(len(value)) + value
    _require(type(value) is int and 0 <= value < 2**64, "invalid_integer_field")
    if wire == 0:
        return tag + varint(value)
    if wire == 1:
        return tag + struct.pack("<Q", value)
    raise ProtocolError("unsupported_wire_type")


@dataclass(frozen=True, repr=False)
class Fields:
    values: tuple[tuple[int, int, int | bytes], ...]

    def one(self, number: int, wire: int, *, required: bool = True):
        entries = [(w, v) for n, w, v in self.values if n == number]
        _require(len(entries) <= 1, "duplicate_protobuf_field")
        if not entries:
            _require(not required, "missing_protobuf_field")
            return None
        _require(entries[0][0] == wire, "wrong_wire_type")
        return entries[0][1]


def decode_fields(data: bytes) -> Fields:
    _require(len(data) <= LIMIT, "response_too_large")
    result = []
    offset = 0
    while offset < len(data):
        _require(len(result) < 4096, "too_many_fields")
        tag, offset = _read_varint(data, offset)
        number, wire = tag >> 3, tag & 7
        _require(0 < number < 2**29, "invalid_field_number")
        if wire == 0:
            value, offset = _read_varint(data, offset)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, offset = _read_varint(data, offset)
            else:
                length = 8 if wire == 1 else 4
            _require(length <= LIMIT and length <= len(data) - offset, "truncated_field")
            value = data[offset:offset + length]
            offset += length
            if wire != 2:
                value = int.from_bytes(value, "little")
        else:
            raise ProtocolError("unsupported_wire_type")
        result.append((number, wire, value))
    return Fields(tuple(result))


def build_checkin(version: str = "0.1.0") -> Request:
    """Fresh Chromium-style MAC check-in. No Google account or phone identifiers.

    Chrome channel UNKNOWN (5); diagnostic version, not a claim to be Chrome.
    This profile's compatibility with Android registration is untested.
    """
    _text(version, 64)
    chrome = field(1, 2) + field(2, version) + field(3, 5)
    checkin = field(12, 3) + field(13, chrome)
    body = field(2, 0) + field(4, checkin) + field(13, 0, 1) + field(14, 3) + field(22, 0)
    return Request(CHECKIN_URL, {"Content-Type": "application/x-protobuf"}, body)


def parse_checkin(data: bytes) -> CheckinCredentials:
    fields = decode_fields(data)
    _require(fields.one(1, 0) == 1, "checkin_not_success")
    result = CheckinCredentials(fields.one(7, 1), fields.one(8, 1))
    result.validate()
    # Settings and provider-suggested URLs are deliberately not executed.
    return result


def mcs_frame(tag: int, payload: bytes, *, first: bool = False) -> bytes:
    _require(type(tag) is int and 0 <= tag <= 16, "invalid_mcs_tag")
    _require(len(payload) <= LIMIT, "frame_too_large")
    return (b"\x29" if first else b"") + bytes([tag]) + varint(len(payload)) + payload


def build_mcs_login(credentials: CheckinCredentials) -> bytes:
    credentials.validate()
    identity = str(credentials.android_id)
    payload = b"".join(field(n, v) for n, v in (
        (1, "chrome-mac-mfa-diagnostic-0.1.0"), (2, "mcs.android.com"),
        (3, identity), (4, identity), (5, str(credentials.security_token)),
        (6, f"android-{credentials.android_id:x}"),
        (8, field(1, "new_vc") + field(2, "1")),
        (12, 0), (14, 1), (16, 2), (17, 1)))
    return mcs_frame(2, payload, first=True)


@dataclass(frozen=True, repr=False)
class Frame:
    tag: int
    payload: bytes


class MCSDecoder:
    """Bounded incremental server stream decoder; first byte is protocol version.

    Frames are untrusted until their payloads are validated. No automatic reply,
    reconnect, acknowledgment, heartbeat scheduling or notification dispatch.
    """
    def __init__(self):
        self._buffer = bytearray()
        self._version = False
        self._failed = False

    def feed(self, data: bytes) -> list[Frame]:
        _require(not self._failed, "decoder_failed")
        try:
            _require(len(self._buffer) + len(data) <= LIMIT + 7, "stream_buffer_too_large")
            self._buffer.extend(data)
            if not self._version:
                if not self._buffer:
                    return []
                _require(self._buffer.pop(0) in (38, 41), "unsupported_mcs_version")
                self._version = True
            frames = []
            while len(self._buffer) >= 2:
                _require(self._buffer[0] <= 16, "invalid_mcs_tag")
                try:
                    length, offset = _read_varint(self._buffer, 1)
                except ProtocolError as exc:
                    if str(exc) == "truncated_varint" and len(self._buffer) < 6:
                        break
                    raise
                _require(offset <= 6 and length <= LIMIT, "frame_too_large")
                if len(self._buffer) < offset + length:
                    break
                frames.append(Frame(self._buffer[0], bytes(self._buffer[offset:offset + length])))
                del self._buffer[:offset + length]
            return frames
        except ProtocolError:
            self._failed = True
            self._buffer.clear()
            raise

    def finish(self) -> None:
        _require(not self._failed and self._version and not self._buffer, "truncated_mcs_stream")


def parse_mcs_login(frame: Frame) -> bool:
    _require(frame.tag == 3, "expected_login_response")
    fields = decode_fields(frame.payload)
    fields.one(1, 2)  # Required id may be empty; never report it.
    error = fields.one(3, 2, required=False)
    return error is None


@dataclass(frozen=True, repr=False)
class PushData:
    properties: dict[str, str]
    persistent_id: bytes | None


def parse_android_data(frame: Frame, *, sender_id: str, package: str) -> PushData:
    """Android data payload only. A Web Push token can use a different payload."""
    _require(frame.tag == 8, "expected_data_message")
    _text(sender_id, 100)
    _text(package, 200)
    fields = decode_fields(frame.payload)
    _require(fields.one(3, 2) == sender_id.encode("ascii"), "unexpected_sender")
    _require(fields.one(5, 2) == package.encode("ascii"), "unexpected_package")
    _require(not fields.one(21, 2, required=False), "raw_payload_not_supported")
    result = {}
    for number, wire, value in fields.values:
        if number != 7:
            continue
        _require(wire == 2, "wrong_wire_type")
        entry = decode_fields(value)
        try:
            key = entry.one(1, 2).decode("utf-8")
            val = entry.one(2, 2).decode("utf-8")
        except UnicodeError:
            raise ProtocolError("invalid_data_encoding") from None
        _require(key not in result, "duplicate_data_key")
        result[key] = val
    return PushData(result, fields.one(9, 2, required=False))


def redacted_status(*, checkin: CheckinCredentials | None = None,
                    installation: Installation | None = None,
                    registration: Registration | None = None,
                    mcs_authenticated: bool = False) -> dict:
    return {
        "checkin_credentials_present": checkin is not None,
        "firebase_installation_present": installation is not None,
        "registration_token_present": registration is not None and registration.accepted,
        "mcs_authenticated": mcs_authenticated,
        "microsoft_delivery_proven": False,
        "microsoft_device_token_validated": False,
        "dos_preventer_obtained": False,
        "enrollment_completed": False,
    }


def prepare_checkin_probe() -> dict:
    """Concrete P01 payload and bounds, without contacting a provider.

    This particular request contains only zero credential placeholders and a
    diagnostic version. Do not extend this report to populated credentials.
    """
    request = build_checkin()
    return {
        "mode": "prepared_not_executed", "experiment": "P01",
        "request": {"method": "POST", "url": request.url,
                    "headers": request.headers, "fresh_request_hex": request.body.hex()},
        "conditional_second_exchange": {"tls_host": MCS_HOST, "port": MCS_PORT,
                                        "operation": "one_mcs_login_using_new_checkin_credentials"},
        "maximum_http_posts": 1, "maximum_mcs_connections": 1,
        "automatic_retries": 0, "redirects_allowed": False,
        "proposed_overall_deadline_seconds": 30,
        "maximum_response_bytes": LIMIT,
        "fcm_registration_requested": False,
        "microsoft_requests": 0, "live_executor_included": False,
    }


if __name__ == "__main__":
    # Intentionally no live subcommand or credential arguments. Never echo argv.
    if sys.argv[1:] == ["prepare-checkin"]:
        print(json.dumps(prepare_checkin_probe(), indent=2))
    elif not sys.argv[1:]:
        print(json.dumps({"mode": "offline_codecs_only", **redacted_status()}, indent=2))
    else:
        print('{"error":"offline_mode_only"}')
        raise SystemExit(2)
