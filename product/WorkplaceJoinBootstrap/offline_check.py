#!/usr/bin/env python3
"""Exercise the built app's no-UI validation path with invented input only."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent
BINARY = ROOT.parent / "build/WorkplaceJoinBootstrap/Device Registration Authorization.app/Contents/MacOS/WorkplaceJoinBootstrap"


def fixture():
    tenant = "00000000-0000-4000-8000-000000000001"
    endpoint = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize"
    state = "s" * 43
    query = {"client_id": "29d9ed98-a469-4536-ade2-f981bc1d605e", "redirect_uri": "msauth://Microsoft.AAD.BrokerPlugin",
        "response_type": "code", "response_mode": "query", "scope": "urn:ms-drs:enterpriseregistration.windows.net/.default openid profile offline_access",
        "login_hint": "synthetic@example.invalid", "hsu": "1", "msafed": "0", "state": state,
        "code_challenge": "c" * 43, "code_challenge_method": "S256"}
    return {"v": 1, "experiment": "WPJ-A01", "authorize_endpoint": endpoint, "authorize_url": endpoint + "?" + urlencode(query),
        "tenant_id": tenant, "callback_scheme": "msauth", "callback_host": "Microsoft.AAD.BrokerPlugin", "callback_path": "",
        "state": state, "expires_at": int(time.time()) + 120}


def main():
    expected = ("input_validated", "invalid_input", "invalid_input", "invalid_input")
    with tempfile.TemporaryDirectory(prefix="wpj-native-offline-") as location:
        directory = Path(location).resolve()
        os.chmod(directory, 0o700)
        path = directory / "auth-input.json"
        for index, status in enumerate(expected):
            value = fixture()
            if index == 1: value["authorize_url"] += "&claims=%7B%7D"
            if index == 2: value["callback_path"] = "/"
            if index == 3: value["experiment"] = "NGC-B01"
            path.write_text(json.dumps(value), encoding="utf-8")
            os.chmod(path, 0o600)
            completed = subprocess.run(["rtk", "proxy", str(BINARY), "--validate-input", str(path)], capture_output=True, text=True, timeout=10)
            result = json.loads(completed.stdout)
            assert result == {"experiment": "WPJ-A01", "native_status": status}
            assert completed.returncode == (0 if index == 0 else 1)
            assert not completed.stderr
            assert list(directory.iterdir()) == [path]
    print(json.dumps({"experiment": "WPJ-A01", "synthetic_validation_cases": len(expected), "all_passed": True,
        "ui_launched": False, "authentication_sessions_started": 0, "network_requests": 0,
        "attempt_locks_created": 0, "callbacks_created": 0, "research_credentials_read": False}, indent=2))


if __name__ == "__main__":
    main()
