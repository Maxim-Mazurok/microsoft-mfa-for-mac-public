"""Offline-only own-project P02 preparation; no live execution or token reads."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import sys

import push_protocol as p

PACKAGE = "org.example.macmfaprobe"
PROFILE = {"gms_version": 1, "android_sdk": 35, "target_sdk": 35,
           "device_name": "MacP02", "build_id": "NATIVE_DIAGNOSTIC"}
ROOT = Path(__file__).resolve().parents[1]


def config_from_json(raw: bytes) -> p.AndroidConfig:
    p._require(len(raw) <= 16384, "config_too_large")
    try:
        obj = json.loads(raw, object_pairs_hook=p._object)
        p._require(isinstance(obj, dict) and obj.get("owned_project_confirmed") is True,
                   "own_project_confirmation_required")
        required = {"owned_project_confirmed", "project_id", "sender_id", "app_id", "api_key", "certificate_sha1"}
        p._require(set(obj) == required, "unexpected_config_fields")
        p._require(all(isinstance(obj[key], str) for key in required - {"owned_project_confirmed"}), "invalid_config_type")
        config = p.AndroidConfig(obj["project_id"], obj["sender_id"], obj["app_id"], obj["api_key"],
                                 PACKAGE, obj["certificate_sha1"], "macP02", "0.1.0", "1")
        config.validate()
        p._require(config.certificate_sha1 != "0" * 40, "placeholder_certificate")
        return config
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise p.ProtocolError("invalid_own_project_config") from None


def private_config(path: Path) -> bytes:
    p._require(path.is_absolute() and ".." not in path.parts, "absolute_private_path_required")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            p._require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022, "insecure_config_ancestor")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        p._require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                   and not info.st_mode & 0o077 and info.st_size <= 16384, "insecure_or_large_config")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read(16385)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def build_one_data_message(config: p.AndroidConfig, registration_token: str,
                           access_token: str, nonce: str) -> p.Request:
    config.validate()
    p._require(config.package == PACKAGE, "own_probe_package_required")
    p._text(registration_token)
    p._text(access_token)
    p._require(bool(re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", access_token)), "invalid_access_token")
    p._require(bool(re.fullmatch(r"[0-9a-f]{32}", nonce)), "invalid_probe_nonce")
    body = {"validate_only": False, "message": {
        "token": registration_token,
        "data": {"p02_kind": "native-mac-control", "p02_nonce": nonce},
        "android": {"ttl": "60s", "priority": "normal", "restricted_package_name": PACKAGE}}}
    return p.Request(f"https://fcm.googleapis.com/v1/projects/{config.project_id}/messages:send",
                     {"Authorization": "Bearer " + access_token, "Content-Type": "application/json"},
                     json.dumps(body, separators=(",", ":")).encode())


def prepare(config: p.AndroidConfig) -> dict:
    """Exercise all request builders with dummy issuer credentials, never P01's."""
    fid = "cAAAAAAAAAAAAAAAAAAAAA"
    p.build_fis_create(config, fid)
    p.build_android_registration(config, p.Installation(fid, "synthetic-refresh", "synthetic-auth", 60),
                                 p.CheckinCredentials(123, 456), **PROFILE)
    build_one_data_message(config, "synthetic-fcm-token", "synthetic-oauth-token", "0" * 32)
    return {
        "experiment": "P02", "mode": "offline_preparation_only", "local_config_valid": True,
        "ownership_independently_verified": False, "live_executor_included": False,
        "network_requests": 0, "read_p01_credentials": False,
        "package": PACKAGE, "declared_unattested_profile": PROFILE,
        "prospective_limits": {"new_google_checkins": 0, "fis_create_posts": 1,
                               "register3_posts": 1, "fcm_data_message_posts": 1,
                               "mcs_connections": 1, "mcs_logins": 1, "oauth_requests_during_probe": 0,
                               "automatic_retries": 0, "microsoft_requests": 0,
                               "overall_seconds": 60, "receive_window_seconds": 30,
                               "plaintext_receive_bytes_per_connection": p.LIMIT},
        "next_gate": "owned_project_setup_then_separately_authorized_bounded_executor",
    }


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if not args or args == ["demo"]:
            raw = (ROOT / "diagnostic/fixtures/p02-synthetic-config.json").read_bytes()
        elif len(args) == 3 and args[:2] == ["check", "--config-file"]:
            raw = private_config(Path(args[2]))
        else:
            raise p.ProtocolError("offline_modes_only")
        result = prepare(config_from_json(raw))
        result["synthetic_config"] = not args or args == ["demo"]
        print(json.dumps(result, indent=2))
        return 0
    except Exception:
        # No raw provider/user value, filename, exception or traceback to output.
        print('{"error":"invalid_or_insecure_p02_configuration","network_requests":0}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
