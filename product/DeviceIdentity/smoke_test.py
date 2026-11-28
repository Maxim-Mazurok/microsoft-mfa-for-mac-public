#!/usr/bin/env python3
"""Create two NEW random synthetic research keys, verify signatures, delete only those keys."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent
HELPER = ROOT.parent / "build" / "DeviceIdentity" / "DeviceIdentityTool"

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--synthetic-only", action="store_true", required=True)
    parser.parse_args()
    namespace = str(uuid.uuid4())  # Never accepts a real/existing namespace.
    report = {"synthetic_only": True, "network_requests": 0, "real_research_keys_created": 0,
              "device_created": False, "transport_created": False, "public_spki_valid": False,
              "role_keys_distinct": False, "duplicate_create_rejected": False, "rs256_verified": False,
              "tampered_message_rejected": False, "cleanup_complete": False, "error": None}
    def call(action: str, role: str, message: bytes | None = None) -> dict:
        request = {"v": 1, "action": action, "namespace": namespace, "role": role}
        if message is not None: request["data_base64"] = base64.b64encode(message).decode()
        result = subprocess.run([str(HELPER)], input=json.dumps(request).encode(), capture_output=True, timeout=30)
        response = json.loads(result.stdout)
        if response.get("ok"):
            if any(response.get(k) != request[k] for k in ("v", "action", "namespace", "role")):
                raise RuntimeError("response_binding_failed")
        return response
    try:
        device = call("create", "device")
        report["device_created"] = device.get("ok") is True
        if not report["device_created"]: raise RuntimeError(device.get("error", "device_create_failed"))
        transport = call("create", "transport")
        report["transport_created"] = transport.get("ok") is True
        if not report["transport_created"]: raise RuntimeError(transport.get("error", "transport_create_failed"))
        report["role_keys_distinct"] = device["public_key_base64"] != transport["public_key_base64"]
        duplicate = call("create", "device")
        report["duplicate_create_rejected"] = duplicate.get("error") == "research_key_exists"
        public = call("public", "device")
        if public.get("public_key_base64") != device["public_key_base64"]: raise RuntimeError("public_identity_changed")
        message = b"Microsoft MFA for Mac synthetic local RSA test. Not an enrollment request."
        signed = call("sign", "device", message)
        if not signed.get("ok"): raise RuntimeError(signed.get("error", "sign_failed"))
        with tempfile.TemporaryDirectory(prefix="mfa-device-key-synthetic-") as temp:
            temp = Path(temp)
            (temp / "public.der").write_bytes(base64.b64decode(device["public_key_base64"]))
            (temp / "signature.bin").write_bytes(base64.b64decode(signed["signature_base64"]))
            (temp / "message.bin").write_bytes(message)
            (temp / "tampered.bin").write_bytes(message + b" changed")
            converted = subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", str(temp / "public.der"), "-out", str(temp / "public.pem")], capture_output=True)
            report["public_spki_valid"] = converted.returncode == 0
            for name, expected, field in [("message.bin", 0, "rs256_verified"), ("tampered.bin", 1, "tampered_message_rejected")]:
                checked = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(temp / "public.pem"), "-signature", str(temp / "signature.bin"), str(temp / name)], capture_output=True)
                report[field] = checked.returncode == expected
    except Exception as error:
        allowed = {"key_creation_failed", "key_protection_unverified", "cleanup_failed", "keychain_unavailable", "response_binding_failed", "public_identity_changed", "signing_failed"}
        report["error"] = str(error) if str(error) in allowed else "synthetic_check_failed"
    finally:
        cleaned = []
        for role in ("device", "transport"):
            try: cleaned.append(call("delete", role).get("ok") is True)
            except Exception: cleaned.append(False)
        report["cleanup_complete"] = all(cleaned)
        if not report["cleanup_complete"]:
            # Identifier belongs only to the freshly generated synthetic keys.
            report["synthetic_namespace_needing_cleanup"] = namespace
        path = ROOT.parent / "build" / "DeviceIdentity" / "synthetic-smoke-result.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, sort_keys=True))
    return 0 if all(report[k] for k in ("device_created", "transport_created", "public_spki_valid", "role_keys_distinct", "duplicate_create_rejected", "rs256_verified", "tampered_message_rejected", "cleanup_complete")) else 1

if __name__ == "__main__": raise SystemExit(main())
