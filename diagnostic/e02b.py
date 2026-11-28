#!/usr/bin/env python3
"""Fresh-code E02B after identified E02 parser failures. No automatic retry."""
import argparse
import asyncio
from datetime import datetime
import json
import os
from pathlib import Path
import re
import resource
import sys
import time
import uuid

import e02
import enrollment_protocol as ep
import research_runtime as rt

ROOT = Path(__file__).resolve().parents[1]
DEVICE_NAME = "Mac E02B research"


def prior(root, experiment):
    lock = rt.private_json(root / ".secrets/push" / (experiment + "-attempt.lock"))
    rt.require(isinstance(lock.get("run_id"), str) and re.fullmatch(r"[0-9a-f]{32}", lock["run_id"]),
               "invalid_prior_locator")
    directory = root / ".secrets/push" / lock["run_id"]
    report = rt.private_json(directory / "report.json")
    rt.require(report.get("run_id") == lock["run_id"] and report.get("experiment") == experiment.upper(),
               "invalid_prior_report")
    return directory, report


def previous_state(root):
    first, report = prior(root, "e02")
    rt.require(report.get("activate_posts_attempted") == 1 and report.get("validate_posts_attempted") == 0
               and report.get("confirm_posts_attempted") == 0 and report.get("mcs_accepted") is True
               and report.get("error") == "invalid_notification_service_host", "unexpected_e02_state")
    callback, report = prior(root, "v01")
    rt.require(report.get("validate_posts_attempted") == 1 and report.get("validate_http_status") == 200
               and report.get("activate_posts_attempted") == 0 and report.get("confirm_posts_attempted") == 0,
               "unexpected_v01_state")
    parsed = ep.parse_validation_response(e02.prep.private_config(callback / "validate-body.bin"))
    rt.require(parsed.status_disposition == "success" and parsed.status_error_id == 0
               and not any(parsed.fields.values()), "prior_callback_requires_analysis")
    notice = ep.validation_notification(rt.private_json(first / "notification.json"))
    old = rt.private_json(root / ".secrets/push/e02-setup/input.json")
    return old, frozenset((notice.guid,)), datetime.fromisoformat(report["started_utc"]).timestamp()


def prerequisites(root):
    config, credentials, token = e02.load_identity(root)
    old, ignored, callback_time = previous_state(root)
    data = rt.private_json(root / ".secrets/push/e02b-setup/input.json")
    enrollment, account = e02.validate_input(data)
    rt.require(data["created_at"] > callback_time, "new_input_must_follow_prior_attempts")
    rt.require(data["activation_code"] != old["activation_code"], "previous_activation_code_reuse_forbidden")
    rt.require(account.casefold() == old["expected_account"].casefold(), "designated_account_must_match")
    ep.activate(enrollment, token, device_name=DEVICE_NAME)
    return (config, credentials, token, enrollment, account), ignored


class PrivateRun(rt.PrivateRun):
    """Separate fixed E02B lock; leave original E02/V01 locks untouched."""
    def __init__(self, root):
        self.fd, self.run_id, self.filenames = None, uuid.uuid4().hex, frozenset(e02.FILES)
        parent = rt.private_directory(root / ".secrets/push")
        try:
            try:
                fd = os.open("e02b-attempt.lock", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
            except FileExistsError:
                raise e02.p01.ProbeError("e02b_attempt_already_reserved_no_retry") from None
            with os.fdopen(fd, "wb") as stream:
                stream.write(rt.json_bytes({"experiment": "E02B", "run_id": self.run_id,
                                             "automatic_retry_permitted": False}))
                stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent)
            os.mkdir(self.run_id, 0o700, dir_fd=parent)
            self.fd = os.open(self.run_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        finally:
            os.close(parent)


def run_once(root=ROOT):
    inputs, ignored = prerequisites(root)
    run = PrivateRun(root)
    report, started = e02.new_report(), time.monotonic()
    report.update(experiment="E02B", device_name=DEVICE_NAME)
    try:
        run.write("attempt.json", rt.json_bytes({"experiment": "E02B", "maximum_http_posts": 3,
                  "maximum_mcs_connections": 1, "maximum_seconds": 120, "automatic_retries": 0,
                  "fresh_code_compared_to_e02": True, "existing_accounts_sent": 0,
                  "prior_validation_guid_excluded": True, "sign_in_approval_permitted": False}))
        asyncio.run(e02.exchange(inputs, run, report, ignored_guids=ignored, device_name=DEVICE_NAME))
    except Exception as exc:
        report["error"], report["outcome"] = e02.safe_error(exc), "stopped_at_recorded_stage"
    except KeyboardInterrupt:
        report["error"], report["outcome"] = "interrupted_no_retry", "stopped_at_recorded_stage"
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        run.write("report.json", rt.json_bytes({**report, "run_id": run.run_id})); run.close()
    return report


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("manifest", "setup", "check", "live"), nargs="?", default="manifest")
    parser.add_argument("--manual", action="store_true")
    parser.add_argument("--one-attempt", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "setup":
            old, _, _ = previous_state(ROOT)
            result = e02.setup(ROOT, args.manual, setup_id="e02b", existing_account=old["expected_account"])
        elif args.command == "check":
            prerequisites(ROOT)
            result = {"experiment": "E02B", "offline_prerequisites_passed": True, "network_requests": 0}
        elif args.command == "live":
            rt.require(args.one_attempt and not args.manual, "explicit_one_attempt_required")
            result = run_once()
        else:
            result = {"experiment": "E02B", "mode": "offline", "maximum_http_posts": 3,
                      "maximum_mcs_connections": 1, "maximum_seconds": 120,
                      "fresh_code_required": True, "previous_code_reuse_forbidden": True}
    except Exception as exc:
        result = {"experiment": "E02B", "error": e02.safe_error(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return bool(result.get("error"))


if __name__ == "__main__": sys.exit(main())
