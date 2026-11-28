#!/usr/bin/env python3
"""One foreground polling diagnostic; never retrieve, approve or deny."""
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import resource
import sys
import time

import e02
import mfa_protocol as protocol
import mfa_transport as transport
import research_runtime as rt

ROOT = Path(__file__).resolve().parents[1]
FILES = {"attempt.json", "report.json", "pending.json", "poll-response.bin", "poll-body.bin"}


async def perform(account, run, state):
    body = await transport.post("poll", protocol.poll(account), run, state)
    result, fields = protocol.poll_response(body, account)
    run.write("pending.json", rt.json_bytes(fields))
    state.update(poll_result=result["result"], pending_request_observed=result["pending"],
                 polling_credentials_accepted=result["result"] == 1, stage="complete")


def run_once(root=ROOT):
    account = protocol.load_account(root)
    run = rt.PrivateRun(root, "e03", FILES)
    state, started = transport.report("E03", ("poll",), 1), time.monotonic()
    state.update(started_utc=datetime.now(timezone.utc).isoformat(), maximum_seconds=30,
                 pending_request_observed=False, polling_credentials_accepted=False, same_mac_approval=False)
    try:
        run.write("attempt.json", rt.json_bytes({"experiment": "E03", "maximum_http_posts": 1,
                  "maximum_seconds": 30, "approvals": 0, "retrieval_requests": 0, "automatic_retries": 0}))
        asyncio.run(perform(account, run, state))
    except Exception as exc:
        state["error"] = e02.safe_error(exc)
    except KeyboardInterrupt:
        state["error"] = "interrupted_no_retry"
    finally:
        state["elapsed_seconds"] = round(time.monotonic() - started, 3)
        run.write("report.json", rt.json_bytes({**state, "run_id": run.run_id})); run.close()
    return state


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        if sys.argv[1:] == ["check"]:
            protocol.load_account(ROOT)
            state = {"experiment": "E03", "offline_prerequisites_passed": True, "network_requests": 0}
        elif sys.argv[1:] == ["live", "--one-attempt"]:
            state = run_once()
        else:
            state = {"experiment": "E03", "mode": "offline", "maximum_http_posts": 1, "approvals": 0}
    except Exception as exc:
        state = {"experiment": "E03", "error": e02.safe_error(exc)}
    print(json.dumps(state, indent=2, sort_keys=True))
    return bool(state.get("error"))


if __name__ == "__main__": sys.exit(main())
