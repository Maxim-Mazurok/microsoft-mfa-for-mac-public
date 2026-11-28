#!/usr/bin/env python3
"""Reproduce the bounded synthetic LaunchServices sandbox directory check."""
from pathlib import Path
import json
import os
import plistlib
import subprocess
import uuid


def main() -> int:
    root = Path(__file__).resolve().parents[3]
    identifier = str(uuid.uuid4()).upper()
    work = root / "work/safari-bridge-probe"
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    app = work / "SandboxBridgeProbe.app"
    (app / "Contents/MacOS").mkdir(parents=True, exist_ok=True)
    info = {
        "CFBundleIdentifier": "org.example.microsoftmfamac.SandboxBridgeProbe",
        "CFBundleName": "SandboxBridgeProbe",
        "CFBundleExecutable": "SandboxBridgeProbe",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1",
        "LSUIElement": True,
        "LSMinimumSystemVersion": "15.4",
    }
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    subprocess.run([
        "rtk", "proxy", "xcrun", "swiftc", "-parse-as-library",
        str(root / "product/SafariExtension/tests/SandboxProbe.swift"),
        "-o", str(app / "Contents/MacOS/SandboxBridgeProbe"),
    ], check=True)
    subprocess.run([
        "rtk", "proxy", "codesign", "--force", "--sign", "-", "--entitlements",
        str(root / "product/SafariExtension/Development.entitlements"), str(app),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    product = Path.home() / "Library/Application Support/org.example.microsoftmfamac"
    allowed = product / "BrowserBridge"
    allowed.mkdir(parents=True, exist_ok=True, mode=0o700)
    if allowed.is_symlink() or allowed.stat().st_uid != os.getuid():
        raise RuntimeError("unsafe_probe_directory")
    os.chmod(allowed, 0o700)
    live = product / "Live"
    live_existed = live.exists()
    live.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = f"probe-denied-{identifier}.txt"
    fixtures = [product / name, live / name, work / name]
    receipt = allowed / f"sandbox-probe-{identifier}.json"
    try:
        for path in fixtures:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, b"synthetic sandbox fixture only")
            finally:
                os.close(fd)
        subprocess.run([
            "rtk", "proxy", "open", "-W", "-n", str(app), "--args",
            identifier, str(fixtures[2]),
        ], timeout=30, check=True, capture_output=True)
        result = json.loads(receipt.read_text()) if receipt.exists() else {"probe_receipt_created": False}
        result.update(allowed_write=receipt.exists(), ad_hoc_signed=True, sandbox_entitlement=True)
        result_path = work / "sandbox-probe-result.json"
        result_path.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 0 if all(result.get(key) is True for key in (
            "allowed_write", "adjacent_product_denied", "adjacent_live_denied", "research_fixture_denied"
        )) else 1
    finally:
        for fixture in fixtures:
            fixture.unlink(missing_ok=True)
        receipt.unlink(missing_ok=True)
        if not live_existed:
            try:
                live.rmdir()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
