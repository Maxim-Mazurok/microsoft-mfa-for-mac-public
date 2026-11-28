#!/usr/bin/env python3
"""One continuous fresh enrollment, setup approval and optional sign-in session."""
import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import resource
import sys
import time

import approval_protocol as approval
import auth_request
import e01
import e02
import e04
import enrollment_protocol as ep
from local_terminal import Terminal
import mfa_protocol as mfa
import mfa_transport as transport
import research_runtime as rt

ROOT = Path(__file__).resolve().parents[1]
DEVICE_NAME = "Mac E05 research"
FILES = set(e02.FILES) | {"input.json", "account.json"}
for phase in ("setup", "signin"):
    FILES.update(phase + "-" + name for name in ("notification.json", "request-details.json", "retrieve-response.bin",
                                                "retrieve-body.bin", "number-response.bin", "number-body.bin"))


class PrefixRun:
    def __init__(self, run, prefix): self.run, self.prefix = run, prefix + "-"
    def write(self, name, data): self.run.write(self.prefix + name, data)
    @contextmanager
    def capture(self, name):
        with self.run.capture(self.prefix + name) as stream: yield stream


class Pump:
    """Single reader while terminal prompts run; bounded heartbeat replies."""
    def __init__(self, stream, state):
        self.stream, self.state = stream, state
        self.queue = asyncio.Queue(maxsize=257)
        self.last_received = 0
    async def run(self):
        try:
            for _ in range(256):
                frame = await self.stream.frame()
                received = time.monotonic()
                if frame.tag == 0:
                    e02.p02.housekeeping(frame)
                    rt.require(self.state["heartbeat_replies_sent"] < 8, "heartbeat_reply_budget_exhausted")
                    self.state["heartbeat_replies_sent"] += 1
                    self.stream.writer.write(e02.p.mcs_frame(1, b"")); await self.stream.writer.drain()
                else: self.queue.put_nowait((frame, received))
            raise e02.p01.ProbeError("mcs_frame_count_limit_reached")
        except asyncio.CancelledError: raise
        except Exception as exc:
            # The maximum queue length exceeds the number of queued frames.
            self.queue.put_nowait((exc, time.monotonic()))
    async def frame(self):
        value, self.last_received = await self.queue.get()
        if isinstance(value, Exception): raise value
        return value


def prerequisites(root):
    account, config, credentials, ignored = e04.prerequisites(root)
    old_codes = {rt.private_json(root / f".secrets/push/{name}-setup/input.json")["activation_code"]
                 for name in ("e02", "e02b")}
    rt.require((root / "work/native/AppLockProbe").is_file(), "native_user_verification_helper_missing")
    rt.require(not (root / ".secrets/push/e05-attempt.lock").exists(), "experiment_attempt_already_reserved_no_retry")
    return account, config, credentials, ignored, old_codes


async def inputs(terminal, old_account, old_codes):
    terminal.show("E05: fresh independent enrollment, then local number matching. Existing phone methods stay intact.\n"
                  "Use a NEW Authenticator QR/manual code for the same designated account. Leave its page open before Next.\n"
                  "All answers are hidden. Ctrl-C cancels. No secret values will be printed.")
    code = await terminal.ask("Fresh activation code:")
    url = await terminal.ask("Paired service URL:")
    fresh = await terminal.ask("Type FRESH to confirm this code is newly generated and unused:", limit=32)
    rt.require(fresh == "FRESH" and code not in old_codes, "fresh_unused_enrollment_code_required")
    data = {"activation_code": code, "service_base_url": url, "expected_account": old_account.username,
            "created_at": time.time(), "fresh_code": True}
    enrollment, expected = e02.validate_input(data)
    return enrollment, expected, data


async def enroll(stream, config, token, enrollment, expected, ignored, run, state):
    tasks = [asyncio.create_task(e02.activation(enrollment, token, expected, run, state, device_name=DEVICE_NAME)),
             asyncio.create_task(e02.receive_validation(stream, config, token, enrollment, run, state, ignored_guids=ignored))]
    try:
        async with asyncio.timeout(120):
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
            for index, task in enumerate(tasks):
                if task in done and task.exception() is not None:
                    if index == 1 and not tasks[0].done(): await asyncio.gather(tasks[0], return_exceptions=True)
                    raise task.exception()
            fields, validation = [t.result() for t in tasks]
            rt.require(fields.get("Username", "").casefold() == expected.casefold()
                       and (not validation.get("username") or validation["username"].casefold() == expected.casefold()),
                       "unexpected_enrollment_account")
            rt.require(all(fields.get(k) for k in ("ConfirmationCode", "OathTokenSecretKey", "AzureObjectId", "TenantId")),
                       "bootstrap_credentials_missing")
            body = await e02.post("confirm", ep.confirm(enrollment, fields["ConfirmationCode"]), enrollment, run, state)
            confirmation = ep.confirmation_response(body); run.write("confirmation.json", rt.json_bytes(confirmation))
            rt.require(confirmation.get("ConfirmActivationResult") in ("true", "1") and confirmation.get("phoneAppDetailId"),
                       "confirmation_rejected")
            state.update(confirmation_accepted=True, enrollment_completed=True)
            account = mfa.Account(token, fields["OathTokenSecretKey"], expected, fields["TenantId"], fields["AzureObjectId"],
                                  validation["groupKey"], confirmation["phoneAppDetailId"], validation["dosPreventer"],
                                  fields.get("ReplicationScope", ""), fields.get("RoutingHint", ""), fields.get("CountryCode", ""))
            mfa.oath_proof(account.secret, 1)
            return account
    finally:
        for task in tasks:
            if not task.done(): task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def verify_user(root):
    process = await asyncio.create_subprocess_exec(str(root / "work/native/AppLockProbe"), "--verify",
                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        async with asyncio.timeout(48): output, _ = await process.communicate()
        return process.returncode == 0 and output == b"authenticated\n"
    finally:
        if process.returncode is None:
            process.kill(); await process.wait()


async def explicit_consent(terminal, root, account, fields, received, verify=verify_user):
    required, shown = approval.requirements(fields)
    deadline = approval.expiry.deadline(fields["expiration"], received)
    rt.require(time.monotonic() < deadline, "approval_request_expired")
    terminal.show("Request for account: " + json.dumps(account.username, ensure_ascii=True))
    for key, value in shown.items(): terminal.show(key + ": " + json.dumps(value, ensure_ascii=True))
    if not shown: terminal.show("Microsoft supplied no application/location context. Verify this is the setup/sign-in you just initiated.")
    terminal.show("Approve ONLY the request you just initiated on this Mac. Cancel for anything unexpected.")
    async with asyncio.timeout_at(deadline):
        number = await terminal.ask("Enter the number currently shown in your Microsoft browser page (hidden):", limit=8)
        phrase = await terminal.ask("Type APPROVE to approve this request; anything else cancels:", limit=32)
        rt.require(phrase == "APPROVE", "approval_not_explicitly_confirmed")
        locked = False
        if required["app_lock"]:
            terminal.show("Microsoft requires local user verification. Complete the macOS verification dialog.")
            locked = await verify(root)
            rt.require(locked, "local_user_verification_failed")
        return approval.consent(fields, number, phrase, deadline, app_lock_used=locked,
                    app_context_shown=bool(shown.get("ApplicationDisplayName")), location_context_shown="Latitude" in shown)


async def receive_auth(stream, config, ignored, ignored_methods, private, state):
    for _ in range(128):
        frame = await stream.frame(); state["mcs_frames_after_login"] += 1
        if frame.tag != 8:
            rt.require(frame.tag != 4, "mcs_server_closed_stream")
            e02.p02.housekeeping(frame)
            continue
        if e02.p02.is_prior_control_message(frame):
            state["prior_control_messages_ignored"] += 1
            continue
        props = e02.p.parse_android_data(frame, sender_id=config.sender_id, package=config.package).properties
        trusted = props.get("source") in ("SAS", "MFA Server")
        if trusted and props.get("type") in ("auth", "validate") and props.get("guid") in ignored:
            state["prior_session_messages_ignored"] = state.get("prior_session_messages_ignored", 0) + 1
            continue
        if trusted and props.get("type") == "auth" and props.get("phoneAppDetailId") in ignored_methods:
            state["older_research_method_messages_ignored"] = state.get("older_research_method_messages_ignored", 0) + 1
            continue
        private.write("notification.json", rt.json_bytes(props))
        rt.require(trusted and props.get("type") == "auth", "unexpected_microsoft_notification")
        state["authentication_push_observed"] = True
        return props
    rt.require(False, "mcs_frame_count_limit_reached")


async def auth_phase(phase, stream, config, account, ignored, run, state, terminal, root, *, verify=verify_user, ignored_methods=frozenset(), trigger_message=None):
    local = transport.report("E05", ("retrieve", "number"), 2)
    phase_run = PrefixRun(run, phase)
    try:
        gate_start = time.monotonic()
        state["stage"] = phase + "_waiting_for_browser_request"
        if trigger_message:
            terminal.show(trigger_message)
        elif phase == "setup":
            terminal.show("ENROLLED. Now press Next once on the open QR page. Keep its number visible; this terminal is already listening.")
        else:
            terminal.show("Now initiate a NEW Microsoft sign-in in a private browser window on this Mac using the same account.\n"
                          "Choose the new research Authenticator method if offered. Do not approve on your phone. Keep the number visible.")
        async with asyncio.timeout(180):
            props = await receive_auth(stream, config, ignored, ignored_methods, phase_run, state)
        received = stream.last_received
        rt.require(received >= gate_start, "request_arrived_before_user_trigger")
        rt.require(props.get("guid") not in ignored, "authentication_guid_reuse_forbidden")
        fields = approval.push_details(props, account)
        service = props["url"]
        entropy_keys = ("firstEntropyChallenge", "secondEntropyChallenge", "thirdEntropyChallenge")
        if not all(fields.get(k) for k in entropy_keys):
            service, guid, counter = auth_request.notification(props, account)
            body = await transport.post("retrieve", mfa.retrieve(account, service, guid, counter), phase_run, local)
            fields = auth_request.response(body, account)
            local["details_source"] = "retrieval"
        else: local["details_source"] = "authenticated_push"
        phase_run.write("request-details.json", rt.json_bytes(fields))
        state["stage"] = phase + "_local_review"
        approved = await explicit_consent(terminal, root, account, fields, received, verify)
        # Build only after explicit local input, then enforce expiry once more.
        request = approval.number_request(account, service, fields, approved)
        state["stage"] = phase + "_number_approval"
        async with asyncio.timeout_at(approved.deadline):
            body = await transport.post("number", request, phase_run, local)
        parsed = approval.number_response(body); local.update(parsed)
        rt.require(parsed["number_approval_accepted"], "number_approval_not_accepted")
        terminal.show("Microsoft accepted this number-match approval.")
        return props["guid"]
    finally:
        local["authentication_approvals_sent"] = local["number_posts_attempted"]
        state[phase] = local
        state["http_posts_attempted"] += local["http_posts_attempted"]
        state["authentication_approvals_sent"] += local["number_posts_attempted"]
        rt.require(state["http_posts_attempted"] <= 7, "session_http_budget_exhausted")


async def session(inputs_tuple, enrollment, expected, run, state, terminal, root):
    old_account, config, credentials, ignored, _ = inputs_tuple
    async with asyncio.timeout(900):
        async with e02.connection("mtalk.google.com", 5228, "mcs", state) as (reader, writer):
            with run.capture("mcs-response.bin") as capture:
                mcs = e02.MCS(reader, writer, capture, state)
                async with asyncio.timeout(30): await mcs.login(credentials)
                pump = Pump(mcs, state); pump_task = asyncio.create_task(pump.run())
                try:
                    terminal.show("Connected. Enrolling the new Mac research method...")
                    account = await enroll(pump, config, old_account.token, enrollment, expected, ignored, run, state)
                    # Suppress the current validation GUID if redelivered.
                    notice = rt.private_json(root / ".secrets/push" / run.run_id / "notification.json")
                    ignored = ignored | {notice["guid"]}
                    prior_methods = frozenset({old_account.method_id} - {account.method_id})
                    setup_guid = await auth_phase("setup", pump, config, account, ignored, run, state, terminal, root,
                                                  ignored_methods=prior_methods)
                    state["stage"] = "browser_setup_confirmation"
                    finished = await terminal.ask("Finish the browser setup. Type DONE only if Microsoft says it succeeded:", seconds=120, limit=32)
                    rt.require(finished == "DONE", "browser_setup_success_not_confirmed")
                    state["browser_setup_success_user_reported"] = True
                    choice = await terminal.ask("To test actual sign-in now, type SIGNIN. Otherwise type STOP to finish with setup only:", seconds=120, limit=32)
                    if choice != "SIGNIN":
                        state["stage"] = "setup_complete_sign_in_not_tested"
                        return
                    # An old authentication replay must not be approved again.
                    signin_guid = await auth_phase("signin", pump, config, account, ignored | {setup_guid}, run, state, terminal, root,
                                                   ignored_methods=prior_methods)
                    rt.require(signin_guid != setup_guid, "authentication_guid_reuse_forbidden")
                    state["stage"] = "browser_sign_in_confirmation"
                    finished = await terminal.ask("Type SIGNEDIN only if the new browser sign-in completed successfully on this Mac:", seconds=120, limit=32)
                    state["browser_sign_in_success_user_reported"] = finished == "SIGNEDIN"
                    state["same_mac_sign_in_approved"] = finished == "SIGNEDIN"
                    state["stage"] = "complete" if finished == "SIGNEDIN" else "service_approved_browser_unconfirmed"
                finally:
                    pump_task.cancel(); await asyncio.gather(pump_task, return_exceptions=True)


async def run_once(root, terminal):
    ready = prerequisites(root)
    enrollment, expected, data = await inputs(terminal, ready[0], ready[4])
    run = rt.PrivateRun(root, "e05", FILES)
    state, started = e02.new_report(), time.monotonic()
    state.update(experiment="E05", device_name=DEVICE_NAME, maximum_http_posts=7, maximum_seconds=900,
                 maximum_mcs_connections=1, maximum_approvals=2, heartbeat_replies_sent=0,
                 prior_control_messages_ignored=0, prior_validation_messages_ignored=0,
                 authentication_push_observed=False, browser_setup_success_user_reported=False,
                 browser_sign_in_success_user_reported=False, started_utc=datetime.now(timezone.utc).isoformat())
    try:
        run.write("input.json", rt.json_bytes(data))
        run.write("attempt.json", rt.json_bytes({"experiment": "E05", "maximum_http_posts": 7,
            "maximum_mcs_connections": 1, "maximum_seconds": 900, "maximum_user_approved_requests": 2,
            "maximum_heartbeat_replies": 8, "automatic_retries": 0, "new_provider_registrations": 0}))
        await session(ready, enrollment, expected, run, state, terminal, root)
    except Exception as exc: state["error"] = e02.safe_error(exc)
    except (KeyboardInterrupt, asyncio.CancelledError): state["error"] = "interrupted_no_retry"
    finally:
        state["elapsed_seconds"] = round(time.monotonic() - started, 3)
        state["outcome"] = state["stage"] if not state.get("error") else "stopped_at_recorded_stage"
        run.write("report.json", rt.json_bytes({**state, "run_id": run.run_id})); run.close()
    return state


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    terminal = None
    try:
        if sys.argv[1:] == ["check"]:
            prerequisites(ROOT)
            result = {"experiment": "E05", "offline_prerequisites_passed": True, "network_requests": 0}
        elif sys.argv[1:] == ["live", "--one-session"]:
            terminal = Terminal(); result = asyncio.run(run_once(ROOT, terminal))
            if result.get("error"):
                terminal.show("Stopped safely; do not rerun this consumed session. Private diagnostics were saved.\n"
                              "If abandoning it, remove only a clearly identified 'Mac E05 research' method in Security info.\n"
                              "Preserve every existing phone method. Report that E05 stopped; do not send secret values.")
        else:
            result = {"experiment": "E05", "mode": "offline", "maximum_http_posts": 7,
                      "maximum_mcs_connections": 1, "automatic_approvals": 0}
    except Exception as exc: result = {"experiment": "E05", "error": e02.safe_error(exc)}
    except KeyboardInterrupt: result = {"experiment": "E05", "error": "interrupted_no_retry"}
    finally:
        if terminal: terminal.close()
    print(json.dumps(result, indent=2, sort_keys=True)); return bool(result.get("error"))


if __name__ == "__main__": sys.exit(main())
