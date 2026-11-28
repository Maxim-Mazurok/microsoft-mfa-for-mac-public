#!/usr/bin/env python3
"""One saved E02 validation callback, never bootstrap/code reuse or approval."""
import asyncio
import json
from pathlib import Path
import re
import resource
import sys
import time
from datetime import datetime

import e02
import enrollment_protocol as ep
import research_runtime as rt

ROOT = Path(__file__).resolve().parents[1]
FILES = {"attempt.json", "report.json", "parent.json", "validation.json",
         "validate-response.bin", "validate-body.bin"}
MAX_PARENT_AGE = 1200


def prerequisites(root):
    _, _, token = e02.load_identity(root)
    parent = rt.private_json(root / ".secrets/push/e02-attempt.lock")
    rt.require(isinstance(parent.get("run_id"), str) and re.fullmatch(r"[0-9a-f]{32}", parent["run_id"]),
               "invalid_parent_locator")
    directory = root / ".secrets/push" / parent["run_id"]
    report = rt.private_json(directory / "report.json")
    rt.require(report.get("experiment") == "E02" and report.get("run_id") == parent["run_id"]
               and report.get("mcs_accepted") is True and report.get("activate_posts_attempted") == 1
               and report.get("validate_posts_attempted") == 0 and report.get("confirm_posts_attempted") == 0
               and report.get("error") == "invalid_notification_service_host", "unexpected_parent_attempt_state")
    age = time.time() - datetime.fromisoformat(report["started_utc"]).timestamp()
    rt.require(0 <= age <= MAX_PARENT_AGE, "saved_validation_notification_too_old")
    notice = ep.validation_notification(rt.private_json(directory / "notification.json"))
    # Do not serialize or reuse the saved activation code. The callback uses
    # only the genuine new-token notification and its GUID/routing data.
    account = ep.scalar(rt.private_json(root / ".secrets/push/e02-setup/input.json")["expected_account"], 320)
    ep.validate(notice, token)
    return notice, token, account, parent["run_id"]


async def perform(inputs, run, report):
    notice, token, account, _ = inputs
    async with asyncio.timeout(30):
        body = await e02.post("validate", ep.validate(notice, token), None, run, report)
        fields = ep.validation_response(body)
        run.write("validation.json", rt.json_bytes(fields))
        rt.require(not fields.get("username") or fields["username"].casefold() == account.casefold(),
                   "unexpected_validation_account")
        report["device_token_validated"] = True
        report["dos_preventer_present"] = True
        report["outcome"] = "validation_credentials_received_bootstrap_outcome_unknown"
        report["stage"] = "complete"


def run_once(root=ROOT):
    inputs = prerequisites(root)
    run = rt.PrivateRun(root, "v01", FILES)
    report, started = e02.new_report(), time.monotonic()
    report.update(experiment="V01", maximum_seconds=30, push_window_seconds=0,
                  validation_push_observed=True, bootstrap_outcome="unknown_response_not_captured")
    try:
        run.write("attempt.json", rt.json_bytes({"experiment": "V01", "maximum_http_posts": 1,
                  "maximum_seconds": 30, "mcs_connections": 0, "activate_requests": 0,
                  "confirmation_requests": 0, "sign_in_approvals": 0, "automatic_retries": 0}))
        run.write("parent.json", rt.json_bytes({"experiment": "E02", "run_id": inputs[3]}))
        asyncio.run(perform(inputs, run, report))
    except Exception as exc:
        report["error"] = e02.safe_error(exc)
        report["outcome"] = "stopped_at_recorded_stage"
    except KeyboardInterrupt:
        report["error"], report["outcome"] = "interrupted_no_retry", "stopped_at_recorded_stage"
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        run.write("report.json", rt.json_bytes({**report, "run_id": run.run_id})); run.close()
    return report


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        if sys.argv[1:] == ["check"]:
            prerequisites(ROOT)
            result = {"experiment": "V01", "offline_prerequisites_passed": True, "network_requests": 0}
        elif sys.argv[1:] == ["live", "--one-attempt"]:
            result = run_once()
        else:
            result = {"experiment": "V01", "mode": "offline", "maximum_http_posts": 1,
                      "maximum_mcs_connections": 0, "maximum_seconds": 30, "enrollment_code_reused": False}
    except Exception as exc:
        result = {"experiment": "V01", "error": e02.safe_error(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return bool(result.get("error"))


if __name__ == "__main__": sys.exit(main())
