#!/usr/bin/env python3
"""Build a local, ad-hoc signed development app. Never opens private research state."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def run(*args: str) -> None:
    subprocess.run(["rtk", "proxy", *args], cwd=ROOT, check=True)


def build(*args: str, log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    print("Building app and Safari extension…", flush=True)
    with log.open("w") as output:
        result = subprocess.run(["rtk", "proxy", *args], cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        print("Build failed; diagnostics:", log, file=sys.stderr)
        raise SystemExit(result.returncode)


def build_paths(derived_data: str | None) -> tuple[Path, Path, Path]:
    derived = Path(derived_data).absolute() if derived_data else ROOT / "build" / "DerivedData"
    app = derived / "Build" / "Products" / "Debug" / "Microsoft MFA for Mac.app"
    return derived, app, derived.parent / "xcodebuild.log"


def runtime_sources() -> list[Path]:
    """Product runtime only; the standalone authorization probe is never shipped."""
    service = ROOT / "service"
    return [source for source in sorted(service.rglob("*.py"))
            if not source.is_symlink()
            and not {"tests", "__pycache__"}.intersection(source.relative_to(service).parts)
            and source.name != "ngc_bootstrap.py"]


def ensure_target_not_running(app: Path, running_paths: list[str] | None = None) -> None:
    """Never replace a currently running app, including a symlink to its bundle."""
    if running_paths is None:
        code = ('import AppKit; import Foundation; '
                'let paths = NSRunningApplication.runningApplications(withBundleIdentifier: '
                '"org.example.microsoftmfamac").compactMap { $0.bundleURL?.path }; '
                'let data = try JSONSerialization.data(withJSONObject: paths); '
                'print(String(data: data, encoding: .utf8)!)')
        try:
            result = subprocess.run(["xcrun", "swift", "-e", code], capture_output=True, text=True, timeout=15, check=True)
            running_paths = json.loads(result.stdout)
            if not isinstance(running_paths, list) or not all(isinstance(path, str) for path in running_paths):
                raise ValueError("invalid running-app result")
        except (OSError, subprocess.SubprocessError, ValueError):
            raise RuntimeError("Could not verify that the target app is stopped; build was not started") from None
    if any(Path(path).resolve() == app.resolve() for path in running_paths):
        raise RuntimeError("The target app is running. Use --derived-data with a different output directory; the running app was not changed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable, help="Absolute Python 3.11+ executable for this local build")
    parser.add_argument("--test", action="store_true", help="Run native core tests before building")
    parser.add_argument("--bridge-mode", choices=("development", "app-group"), default="development",
                        help="Explicit bridge architecture: development uses a scoped private directory; app-group requires proper signing/provisioning")
    parser.add_argument("--derived-data", help="Separate Xcode output directory; use product/build/RemoteNGC/DerivedData to preserve the running classic app")
    args = parser.parse_args()
    derived, app, build_log = build_paths(args.derived_data)
    try:
        ensure_target_not_running(app)
    except RuntimeError as error:
        parser.error(str(error))
    python = Path(args.python).absolute()
    if not python.is_absolute() or not os.access(python, os.X_OK):
        parser.error("--python must be an executable absolute path")
    version = subprocess.check_output([str(python), "-c", "import sys; print(sys.version_info.major,sys.version_info.minor)"], text=True).strip()
    if tuple(map(int, version.split())) < (3, 11):
        parser.error("Python 3.11 or later is required")
    if not shutil.which("xcodegen"):
        parser.error("xcodegen is required (brew install xcodegen)")
    runtime = ROOT / "build" / "Runtime"
    if runtime.exists():
        shutil.rmtree(runtime)
    runtime.mkdir(parents=True)
    # Bundle source-only protocol code, never research artifacts, private files or logs.
    for source in runtime_sources():
        target = runtime / "service" / source.relative_to(ROOT / "service")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    if not (runtime / "service" / "main.py").exists():
        parser.error("service/main.py is not ready")
    if args.test:
        run("swift", "test", "--package-path", str(ROOT / "macOS"))
    run("xcodegen", "generate", "--spec", "project.yml")
    build("xcodebuild", "-project", "MicrosoftMFAForMac.xcodeproj", "-scheme", "Microsoft MFA for Mac",
        "-configuration", "Debug", "-derivedDataPath", str(derived),
        "-destination", "platform=macOS,arch=arm64", "-quiet",
        "CODE_SIGNING_ALLOWED=NO", "MFA_BRIDGE_MODE=" + args.bridge_mode,
        "MFA_DEVELOPMENT_PYTHON=" + str(python), "build", log=build_log)
    # Xcode otherwise requests an app-group provisioning profile even for ad-hoc
    # development. Compile unsigned, then sign locally without a paid identity.
    extension = app / "Contents" / "PlugIns" / "SafariExtension.appex"
    extension_entitlements = "Development.entitlements" if args.bridge_mode == "development" else "Extension.entitlements"
    app_entitlements = "DevelopmentApp.entitlements" if args.bridge_mode == "development" else "App.entitlements"
    run("codesign", "--force", "--sign", "-", "--timestamp=none", "--entitlements",
        str(ROOT / "SafariExtension" / extension_entitlements), str(extension))
    run("codesign", "--force", "--sign", "-", "--timestamp=none", "--entitlements",
        str(ROOT / "macOS" / app_entitlements), str(app))
    run("codesign", "--verify", "--deep", "--strict", str(app))
    print("Built local development app:", app)
    print("Python runtime dependency:", python)
    print("Explicit browser bridge mode:", args.bridge_mode)
    print("No credentials imported and no live connection started.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
