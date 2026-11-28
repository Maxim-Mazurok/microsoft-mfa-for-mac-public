#!/usr/bin/env python3
"""One MCS listener and at most one request retrieval. Cannot approve or deny."""
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import resource
import sys
import time

import auth_request as auth
import e02
import mfa_protocol as mfa
import mfa_transport as transport
import research_runtime as rt

ROOT = Path(__file__).resolve().parents[1]
FILES = {"attempt.json", "report.json", "notification.json", "request-details.json", "mcs-response.bin",
         "retrieve-response.bin", "retrieve-body.bin"}


def prerequisites(root):
    account = mfa.load_account(root)
    config, credentials, token = e02.load_identity(root)
    rt.require(token == account.token, "provider_identity_mismatch")
    old_guids = set()
    for experiment in ("e02", "e02b"):
        locator = rt.private_json(root / f".secrets/push/{experiment}-attempt.lock")
        run_id = locator.get("run_id")
        rt.require(isinstance(run_id, str) and re.fullmatch(r"[0-9a-f]{32}", run_id), "invalid_prior_locator")
        notice = rt.private_json(root / ".secrets/push" / run_id / "notification.json")
        old_guids.add(notice["guid"])
    return account, config, credentials, frozenset(old_guids)


async def receive(mcs, config, old_guids, run, state):
    for _ in range(128):
        frame = await mcs.frame(); state["mcs_frames_after_login"] += 1
        if frame.tag == 8:
            if e02.p02.is_prior_control_message(frame):
                state["prior_control_messages_ignored"] += 1
                continue
            data = e02.p.parse_android_data(frame, sender_id=config.sender_id, package=config.package)
            props = data.properties
            if props.get("source") in ("SAS", "MFA Server") and props.get("type") == "validate" and props.get("guid") in old_guids:
                state["prior_validation_messages_ignored"] += 1
                continue
            run.write("notification.json", rt.json_bytes(props))
            rt.require(props.get("type") == "auth" and props.get("source") in ("SAS", "MFA Server"),
                       "unexpected_microsoft_notification")
            state["authentication_push_observed"] = True
            return props
        rt.require(frame.tag != 4, "mcs_server_closed_stream")
        e02.p02.housekeeping(frame)
    rt.require(False, "mcs_frame_count_limit_reached")


async def perform(inputs, run, state, ready=lambda: None):
    account, config, credentials, old_guids = inputs
    async with asyncio.timeout(180):
        async with e02.connection("mtalk.google.com", 5228, "mcs", state) as (reader, writer):
            with run.capture("mcs-response.bin") as capture:
                mcs = e02.MCS(reader, writer, capture, state)
                async with asyncio.timeout(30): await mcs.login(credentials)
                state["stage"] = "waiting_for_user_triggered_push"
                ready()
                async with asyncio.timeout(120): props = await receive(mcs, config, old_guids, run, state)
        service, guid, counter = auth.notification(props, account)
        state["notification_account_bound"] = True
        state["stage"] = "retrieve_prepare"
        body = await transport.post("retrieve", mfa.retrieve(account, service, guid, counter), run, state)
        fields = auth.response(body, account)
        run.write("request-details.json", rt.json_bytes(fields))
        state.update(auth.summary(fields), stage="complete")


def new_report():
    state = transport.report("E04", ("retrieve", "mcs"), 1)
    state.update(mcs_logins_attempted=0, mcs_accepted=False, mcs_frames_after_login=0,
                 prior_control_messages_ignored=0, prior_validation_messages_ignored=0,
                 authentication_push_observed=False, notification_account_bound=False,
                 request_details_retrieved=False, maximum_mcs_connections=1, maximum_seconds=180,
                 new_checkins=0, enrollment_requests=0, authentication_denials_sent=0,
                 same_mac_sign_in_approved=False)
    return state


def run_once(root=ROOT, ready=lambda: None):
    inputs = prerequisites(root)
    run = rt.PrivateRun(root, "e04", FILES)
    state, started = new_report(), time.monotonic()
    state["started_utc"] = datetime.now(timezone.utc).isoformat()
    try:
        run.write("attempt.json", rt.json_bytes({"experiment": "E04", "maximum_http_posts": 1,
            "maximum_mcs_connections": 1, "maximum_seconds": 180, "approvals": 0, "denials": 0,
            "automatic_retries": 0, "new_provider_registrations": 0}))
        asyncio.run(perform(inputs, run, state, ready))
    except Exception as exc: state["error"] = e02.safe_error(exc)
    except KeyboardInterrupt: state["error"] = "interrupted_no_retry"
    finally:
        state["mcs_connections"] = state["mcs_connections_attempted"]
        state["elapsed_seconds"] = round(time.monotonic() - started, 3)
        run.write("report.json", rt.json_bytes({**state, "run_id": run.run_id})); run.close()
    return state


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        if sys.argv[1:] == ["check"]:
            prerequisites(ROOT)
            state = {"experiment": "E04", "offline_prerequisites_passed": True, "network_requests": 0}
        elif sys.argv[1:] == ["live", "--one-attempt"]:
            def ready():
                print("READY: now press Next once on the existing Microsoft Authenticator QR page. "
                      "Leave any number/request visible. This diagnostic only retrieves; it cannot approve.", flush=True)
            state = run_once(ready=ready)
        else:
            state = {"experiment": "E04", "mode": "offline", "maximum_http_posts": 1,
                     "maximum_mcs_connections": 1, "approvals": 0}
    except Exception as exc: state = {"experiment": "E04", "error": e02.safe_error(exc)}
    print(json.dumps(state, indent=2, sort_keys=True))
    return bool(state.get("error"))


if __name__ == "__main__": sys.exit(main())
