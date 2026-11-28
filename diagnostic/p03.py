#!/usr/bin/env python3
"""P03: one FIS create and one conditional register3 for traced AAD config.

No Microsoft backend, check-in, MCS, sender token, enrollment or retries.
Public configuration is extracted locally; issuer-returned secrets stay private.
"""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sys
import time

import p01
import p02
import push_protocol as p
import research_runtime as r

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "work/android/jadx/sources/com/microsoft/authenticator/notifications/entities/MfaFcmConfiguration.java"
SOURCE_HASH = "481330c7abb597587ef0513ce1c0cdbcc7c988fb38bbdb7ae53f4947308727e4"
PROJECT = "api-project-275572744697"
SENDER = "275572744697"
APP = "1:275572744697:android:bf0d7a4869fb0571411d28"
PACKAGE = "com.azure.authenticator"
CERTIFICATE = "868d38d12ddf7d9926c6ab50ad2c294d53a7f6bd"
PROFILE = {"gms_version": 1, "android_sdk": 35, "target_sdk": 36,
           "device_name": "MacP03", "build_id": "NATIVE_DIAGNOSTIC"}
FILES = {"attempt.json", "probe.json", "installation.json", "registration.json",
         "fis-response.bin", "register3-response.bin", "report.json"}
require = r.require


def config_from_json(raw):
    require(len(raw) <= 16384, "config_too_large")
    obj = json.loads(raw, object_pairs_hook=p._object)
    require(isinstance(obj, dict) and set(obj) == set(p.AndroidConfig.__dataclass_fields__),
            "invalid_aad_configuration")
    require(all(isinstance(value, str) for value in obj.values()), "invalid_aad_configuration")
    config = p.AndroidConfig(**obj)
    config.validate()
    require((config.project_id, config.sender_id, config.app_id, config.package, config.certificate_sha1,
             config.firebase_name, config.app_version, config.app_version_code) ==
            (PROJECT, SENDER, APP, PACKAGE, CERTIFICATE, "mfaProdV1", "6.2610.7075", "202670753"),
            "traced_aad_configuration_required")
    return config


def artifact_config(root):
    raw = (root / SOURCE).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SOURCE_HASH, "artifact_configuration_source_changed")
    fields = dict(re.findall(r'(MFA_PROD_[A-Z_]+)\s*=\s*"([^"\n]+)"', raw.decode()))
    require(set(fields) == {"MFA_PROD_API_KEY", "MFA_PROD_APPLICATION_ID", "MFA_PROD_APP_NAME",
                            "MFA_PROD_GCM_SENDER_ID", "MFA_PROD_PROJECT_ID"}, "ambiguous_artifact_configuration")
    config = p.AndroidConfig(fields["MFA_PROD_PROJECT_ID"], fields["MFA_PROD_GCM_SENDER_ID"],
                             fields["MFA_PROD_APPLICATION_ID"], fields["MFA_PROD_API_KEY"], PACKAGE,
                             CERTIFICATE, fields["MFA_PROD_APP_NAME"], "6.2610.7075", "202670753")
    return config_from_json(r.json_bytes(asdict(config)))


def prepare_private(root=ROOT):
    """Local extraction only. Refuse to overwrite an existing configuration."""
    config = artifact_config(root)
    parent = r.private_directory(root / ".secrets/push")
    try:
        os.mkdir("p03-setup", 0o700, dir_fd=parent)
        fd = os.open("p03-setup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            output = os.open("config.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fd)
            with os.fdopen(output, "wb") as stream:
                stream.write(r.json_bytes(asdict(config))); stream.flush(); os.fsync(stream.fileno())
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    return {"local_extraction_complete": True, "network_requests": 0, "apk_publisher_identity_verified": False}


def prerequisites(root=ROOT):
    config = config_from_json(p02.prep.private_config(root / ".secrets/push/p03-setup/config.json"))
    require(config == artifact_config(root), "private_configuration_differs_from_artifact")
    credentials = r.load_p01(root)
    p.build_fis_create(config, "cAAAAAAAAAAAAAAAAAAAAA")
    p.build_android_registration(config, p.Installation("cAAAAAAAAAAAAAAAAAAAAA", "synthetic", "synthetic", 60),
                                 credentials, **PROFILE)
    return config, credentials


def post(kind, request, config, run, deadline, report):
    require(kind in ("fis", "register3") and report["http_posts_attempted"] < 2,
            "p03_request_budget_or_destination_exceeded")
    return p02.post(kind, request, config, run, deadline, report)


def manifest():
    return {"experiment": "P03", "mode": "offline", "hypothesis": "google_accepts_traced_aad_app_registration",
            "maximum_http_posts": 2, "maximum_fis_create_posts": 1, "maximum_register3_posts": 1,
            "maximum_seconds": 30, "maximum_response_plaintext_bytes_per_connection": p.LIMIT,
            "new_checkins": 0, "mcs_connections": 0, "microsoft_backend_requests": 0,
            "automatic_retries": 0, "sender_oauth_requests": 0, "enrollment_requests": 0,
            "apk_publisher_identity_verified": False, "declared_unattested_profile": PROFILE,
            "success_does_not_establish_microsoft_delivery_or_enrollment": True}


def run_once(root=ROOT):
    report = p02.new_report()
    report.update(experiment="P03", maximum_seconds=30, receive_window_seconds=0,
                  microsoft_firebase_configuration_used=True, aad_registration_issued=False,
                  apk_publisher_identity_verified=False)
    run = None
    started = time.monotonic()
    try:
        config, credentials = prerequisites(root)
        report["p01_credentials_reused"] = report["checkin_credentials_present"] = True
        report["stage"] = "private_storage"
        run = r.PrivateRun(root, "p03", FILES)
        run.write("attempt.json", r.json_bytes({**report, "run_id": run.run_id, "limits": manifest()}))
        fid = p.new_fid()
        run.write("probe.json", r.json_bytes({"fid": fid, "declared_unattested_profile": PROFILE}))
        with p01.Deadline() as deadline:
            body = post("fis", p.build_fis_create(config, fid), config, run, deadline, report)
            installation = p.parse_fis_create(body, config, fid)
            report["firebase_installation_present"] = True
            run.write("installation.json", r.json_bytes(asdict(installation)))
            request = p.build_android_registration(config, installation, credentials, **PROFILE)
            body = post("register3", request, config, run, deadline, report)
            registration = p.parse_registration(body)
            if not registration.accepted:
                report["register3_provider_error"] = p02.provider_error("register3", body)
                raise p01.ProbeError("register3_rejected")
            report["registration_token_present"] = report["aad_registration_issued"] = True
            run.write("registration.json", r.json_bytes({"token": registration.token}))
        report["stage"] = "complete"
        report["outcome"] = "google_issued_registration_for_traced_aad_configuration"
    except (Exception, KeyboardInterrupt) as exc:
        report["error"] = p02.safe_error(exc)
        report["outcome"] = "stopped_without_retry"
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if run is not None:
            try:
                run.write("report.json", r.json_bytes({**report, "run_id": run.run_id}))
            finally:
                run.close()
    return report


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args in ([], ["prepare"]):
        print(r.json_bytes(manifest()).decode(), end="")
        return 0
    if args not in (["extract-config"], ["check"], ["live", "--one-attempt"]):
        print('{"error":"explicit_p03_mode_required"}')
        return 2
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if args == ["extract-config"]:
            report = prepare_private()
        elif args == ["check"]:
            prerequisites()
            report = {"local_prerequisites_valid": True, "network_requests": 0}
        else:
            report = run_once()
        print(r.json_bytes(report).decode(), end="")
        return 1 if report.get("error") else 0
    except (Exception, KeyboardInterrupt):
        print('{"error":"local_p03_failure_no_retry","raw_output_suppressed":true}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
