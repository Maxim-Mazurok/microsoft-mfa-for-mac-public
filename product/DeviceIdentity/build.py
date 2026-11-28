#!/usr/bin/env python3
"""Build only: namespace-restricted local device keys, no registration or key creation."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent
DEST = ROOT.parent / "build" / "DeviceIdentity" / "DeviceIdentityTool"

def main():
    DEST.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["rtk", "proxy", "swift", "test", "--package-path", str(ROOT)], check=True)
    subprocess.run(["rtk", "proxy", "xcrun", "swiftc", "-swift-version", "5", "-target", "arm64-apple-macos15.4", "-O",
                    str(ROOT / "Core" / "DeviceIdentityCore.swift"), str(ROOT / "main.swift"), "-framework", "Security", "-o", str(DEST)], check=True)
    subprocess.run(["rtk", "proxy", "codesign", "--force", "--sign", "-", "--timestamp=none", str(DEST)], check=True)
    subprocess.run(["rtk", "proxy", "codesign", "--verify", "--strict", str(DEST)], check=True)
    print("Built device-key helper:", DEST)
    print("Build does not create keys, read research credentials, or contact any service.")

if __name__ == "__main__": main()
