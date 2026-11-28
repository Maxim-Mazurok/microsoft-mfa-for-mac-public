#!/usr/bin/env python3
"""Private JSON-lines subprocess. Default start is offline; no hidden network work."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import resource
import sys

# python -I path/main.py excludes the script path; explicitly use only this bundle.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from controller import Controller, ServiceError
from correlation import CorrelationError
from credentials import export_research
from state import StateStore, StateError


MAX_LINE = 65536


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def emit(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n")
    sys.stdout.flush()


async def run(store, synthetic):
    service = Controller(store, emit, synthetic=synthetic)
    reader = asyncio.StreamReader(limit=MAX_LINE)
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    service.output("ready", synthetic=synthetic, protocol=1)
    service.status("import_required" if not synthetic else "synthetic_not_configured")
    async def ticker():
        while not service.closed:
            await asyncio.sleep(1)
            await service.tick()
    tick = asyncio.create_task(ticker())
    try:
        while not service.closed:
            try:
                line = await reader.readline()
            except ValueError:
                service.output("error", code="input_size_limit"); break
            if not line: break
            try:
                if len(line) > MAX_LINE: raise ValueError()
                value = json.loads(line, object_pairs_hook=unique_object,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                await service.command(value)
            except (ServiceError, CorrelationError) as exc:
                # These classes originate solely in our fixed-code validators.
                service.output("error", code=str(exc))
            except Exception:
                service.output("error", code="invalid_input_or_local_failure")
    finally:
        tick.cancel()
        await asyncio.gather(tick, return_exceptions=True)
        await service.command({"version": 1, "command": "shutdown"})
        transport.close()


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description="Microsoft MFA for Mac private service")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--synthetic", action="store_true")
    parser.add_argument("--export-research", type=Path)
    args = parser.parse_args()
    if args.export_research:
        # Native import captures this private stdout directly, then writes Keychain.
        # Refuse direct interactive terminal output or mixed synthetic/runtime use.
        if sys.stdout.isatty() or args.synthetic or args.state_dir:
            emit({"version": 1, "event": "error", "code": "private_capture_required"}); return 1
        try:
            bundle = export_research(args.export_research)
            emit(bundle)
            return 0
        except Exception:
            emit({"version": 1, "event": "error", "code": "research_import_failed"}); return 1
    if args.state_dir is None:
        emit({"version": 1, "event": "error", "code": "private_state_directory_required"}); return 1
    store = None
    try:
        store = StateStore(args.state_dir, synthetic=args.synthetic)
        asyncio.run(run(store, args.synthetic))
        return 0
    except KeyboardInterrupt:
        return 0
    except StateError as exc:
        emit({"version": 1, "event": "error", "code": str(exc)}); return 1
    except Exception:
        emit({"version": 1, "event": "error", "code": "service_stopped_local_failure"}); return 1
    finally:
        if store: store.close()


if __name__ == "__main__":
    raise SystemExit(main())
