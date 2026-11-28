#!/usr/bin/env python3
"""Build only: isolated ASWebAuthenticationSession helper; never launches authentication."""
from pathlib import Path
import plistlib
import subprocess

ROOT = Path(__file__).resolve().parent
DEST = ROOT.parent / "build" / "RemoteNGCBootstrap" / "Phone Sign-in Research.app"


def main():
    contents = DEST / "Contents"
    binary = contents / "MacOS" / "RemoteNGCBootstrap"
    binary.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["rtk", "proxy", "swift", "test", "--package-path", str(ROOT)], check=True)
    subprocess.run(["rtk", "proxy", "xcrun", "swiftc", "-swift-version", "5", "-target", "arm64-apple-macos15.4", "-O",
                    str(ROOT / "Core" / "BootstrapCore.swift"), str(ROOT / "App.swift"),
                    "-framework", "AppKit", "-framework", "AuthenticationServices", "-o", str(binary)], check=True)
    info = {"CFBundleIdentifier": "org.example.microsoftmfamac.RemoteNGCBootstrap", "CFBundleExecutable": "RemoteNGCBootstrap",
            "CFBundleName": "Phone Sign-in Research", "CFBundleDisplayName": "Phone Sign-in Research",
            "CFBundlePackageType": "APPL", "CFBundleVersion": "1", "CFBundleShortVersionString": "0.1",
            "LSMinimumSystemVersion": "15.4", "NSHighResolutionCapable": True}
    # Deliberately no CFBundleURLTypes: this helper never installs a global msauth handler.
    with (contents / "Info.plist").open("wb") as output:
        plistlib.dump(info, output)
    subprocess.run(["rtk", "proxy", "codesign", "--force", "--sign", "-", "--timestamp=none", str(DEST)], check=True)
    subprocess.run(["rtk", "proxy", "codesign", "--verify", "--deep", "--strict", str(DEST)], check=True)
    print("Built isolated helper:", DEST)
    print("No authentication launched; no credentials read; no token exchange or enrollment performed.")


if __name__ == "__main__":
    main()
