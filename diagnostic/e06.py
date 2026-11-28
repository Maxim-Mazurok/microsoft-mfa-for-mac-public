#!/usr/bin/env python3
"""Continue the existing E05 registration; no enrollment/code reuse/provider setup."""
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import resource
import sys
import time

import e02
import e04
import e05
import mfa_protocol as mfa
import research_runtime as rt
from local_terminal import Terminal

ROOT = Path(__file__).resolve().parents[1]
FILES = {"attempt.json", "report.json", "mcs-response.bin"}
for phase in ("setup", "signin"):
    FILES.update(phase + "-" + name for name in ("notification.json", "request-details.json", "retrieve-response.bin",
                                               "retrieve-body.bin", "number-response.bin", "number-body.bin"))


def prerequisites(root):
    old, config, credentials, ignored = e04.prerequisites(root)
    locator = rt.private_json(root / ".secrets/push/e05-attempt.lock")
    run_id = locator.get("run_id")
    rt.require(isinstance(run_id, str) and re.fullmatch(r"[0-9a-f]{32}", run_id), "invalid_e05_locator")
    directory = root / ".secrets/push" / run_id
    report = rt.private_json(directory / "report.json")
    rt.require(report.get("experiment") == "E05" and report.get("run_id") == run_id
               and report.get("enrollment_completed") is True and report.get("confirmation_accepted") is True
               and report.get("device_token_validated") is True and report.get("dos_preventer_present") is True
               and report.get("authentication_approvals_sent") == 0
               and report.get("error") == "request_expiration_required", "expected_e05_continuation_state_required")
    a = rt.private_json(directory / "activation.json")
    v = rt.private_json(directory / "validation.json")
    c = rt.private_json(directory / "confirmation.json")
    rt.require(a.get("Username", "").casefold() == old.username.casefold()
               and (not v.get("username") or v["username"].casefold() == old.username.casefold())
               and c.get("ConfirmActivationResult") in ("true", "1"), "e05_confirmed_account_mismatch")
    account = mfa.Account(old.token, a["OathTokenSecretKey"], a["Username"], a["TenantId"], a["AzureObjectId"],
                          v["groupKey"], c["phoneAppDetailId"], v["dosPreventer"],
                          a.get("ReplicationScope", ""), a.get("RoutingHint", ""), a.get("CountryCode", ""))
    for name in ("token", "secret", "username", "tenant_id", "object_id", "group_key", "method_id", "dos_preventer"):
        e05.ep.scalar(getattr(account, name))
    mfa.oath_proof(account.secret, 1)
    ignored |= {rt.private_json(directory / name)["guid"] for name in ("notification.json", "setup-notification.json")}
    rt.require(not (root / ".secrets/push/e06-attempt.lock").exists(), "experiment_attempt_already_reserved_no_retry")
    return account, config, credentials, ignored, frozenset({old.method_id} - {account.method_id})


def new_report():
    state = e02.new_report()
    state.update(experiment="E06", existing_registration="Mac E05 research", existing_registration_confirmed=True,
                 maximum_http_posts=4, maximum_seconds=900, maximum_mcs_connections=1, maximum_approvals=2,
                 heartbeat_replies_sent=0, prior_control_messages_ignored=0, prior_validation_messages_ignored=0,
                 authentication_push_observed=False, browser_setup_success_user_reported=False,
                 browser_sign_in_success_user_reported=False, new_enrollment_requests=0)
    return state


async def session(ready, purpose, run, state, terminal, root):
    account, config, credentials, ignored, prior_methods = ready
    async with asyncio.timeout(900):
        async with e02.connection("mtalk.google.com", 5228, "mcs", state) as (reader, writer):
            with run.capture("mcs-response.bin") as capture:
                mcs = e02.MCS(reader, writer, capture, state)
                async with asyncio.timeout(30): await mcs.login(credentials)
                pump = e05.Pump(mcs, state); task = asyncio.create_task(pump.run())
                try:
                    if purpose == "SETUP":
                        message = ("READY: use Retry/Resend on the EXISTING Authenticator setup verification page to create a NEW request.\n"
                                   "If you returned to its existing QR step, press Next once. Do not add another method or reuse an old number.\n"
                                   "If no retry/continuation is available, press Ctrl-C and report the browser state.")
                        guid = await e05.auth_phase("setup", pump, config, account, ignored, run, state, terminal, root,
                                     ignored_methods=prior_methods, trigger_message=message)
                        ignored |= {guid}
                        state["stage"] = "browser_setup_confirmation"
                        done = await terminal.ask("Finish browser setup. Type DONE only if Microsoft says it succeeded:", seconds=120, limit=32)
                        rt.require(done == "DONE", "browser_setup_success_not_confirmed")
                        state["browser_setup_success_user_reported"] = True
                        choice = await terminal.ask("Type SIGNIN to test an actual new sign-in now, or STOP to finish after setup:", seconds=120, limit=32)
                        if choice != "SIGNIN":
                            state["stage"] = "setup_complete_sign_in_not_tested"
                            return
                    else:
                        state["browser_setup_success_user_reported"] = True
                    await e05.auth_phase("signin", pump, config, account, ignored, run, state, terminal, root,
                                         ignored_methods=prior_methods)
                    state["stage"] = "browser_sign_in_confirmation"
                    done = await terminal.ask("Type SIGNEDIN only if that new browser sign-in completed successfully on this Mac:", seconds=120, limit=32)
                    state["browser_sign_in_success_user_reported"] = done == "SIGNEDIN"
                    state["same_mac_sign_in_approved"] = done == "SIGNEDIN"
                    state["stage"] = "complete" if done == "SIGNEDIN" else "service_approved_browser_unconfirmed"
                finally:
                    task.cancel(); await asyncio.gather(task, return_exceptions=True)


async def run_once(root, terminal):
    ready = prerequisites(root)
    terminal.show("E06 continues the existing Mac E05 research registration. No enrollment code or URL is needed.\n"
                  "Keep the existing browser setup page open. Preserve every phone method. No request is approved automatically.")
    purpose = await terminal.ask("Type SETUP to retry its pending setup verification. Type SIGNIN only if browser setup already completed:", limit=32)
    rt.require(purpose in ("SETUP", "SIGNIN"), "local_session_purpose_required")
    run = rt.PrivateRun(root, "e06", FILES); state = new_report(); started = time.monotonic()
    state.update(started_utc=datetime.now(timezone.utc).isoformat(), purpose=purpose)
    try:
        run.write("attempt.json", rt.json_bytes({"experiment": "E06", "maximum_http_posts": 4,
            "maximum_mcs_connections": 1, "maximum_seconds": 900, "maximum_user_approved_requests": 2,
            "maximum_heartbeat_replies": 8, "new_enrollments": 0, "new_provider_registrations": 0,
            "automatic_retries": 0, "stale_e05_request_excluded": True}))
        await session(ready, purpose, run, state, terminal, root)
    except Exception as exc: state["error"] = e02.safe_error(exc)
    except (KeyboardInterrupt, asyncio.CancelledError): state["error"] = "interrupted_no_retry"
    finally:
        state["elapsed_seconds"] = round(time.monotonic() - started, 3)
        state["outcome"] = state["stage"] if not state.get("error") else "stopped_at_recorded_stage"
        run.write("report.json", rt.json_bytes({**state, "run_id": run.run_id})); run.close()
    return state


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); terminal = None
    try:
        if sys.argv[1:] == ["check"]:
            prerequisites(ROOT)
            result = {"experiment": "E06", "offline_prerequisites_passed": True, "network_requests": 0}
        elif sys.argv[1:] == ["live", "--one-session"]:
            terminal = Terminal(); result = asyncio.run(run_once(ROOT, terminal))
            if result.get("error"):
                terminal.show("Stopped without retry. Private diagnostics are saved; report E06 stopped without any secret values.\n"
                              "Keep Mac E05 research for continuation; preserve all phone methods.")
        else: result = {"experiment": "E06", "mode": "offline", "maximum_http_posts": 4, "new_enrollments": 0}
    except Exception as exc: result = {"experiment": "E06", "error": e02.safe_error(exc)}
    except KeyboardInterrupt: result = {"experiment": "E06", "error": "interrupted_no_retry"}
    finally:
        if terminal: terminal.close()
    print(json.dumps(result, indent=2, sort_keys=True)); return bool(result.get("error"))


if __name__ == "__main__": sys.exit(main())
