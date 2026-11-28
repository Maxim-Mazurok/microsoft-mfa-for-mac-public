"""Explicit keyless sender-token setup, separate from P02's network budget.

Requires an existing isolated gcloud user login. One gcloud invocation, no local
retry, no service-account key, no ADC export. Never prints credential output.
"""
import json
import os
from pathlib import Path
import resource
import re
import shutil
import subprocess
import sys
import time

import p02

def isolated_environment(setup):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("CLOUDSDK_") and k != "SSLKEYLOGFILE"}
    env.update(CLOUDSDK_CONFIG=str(setup / "gcloud"), CLOUDSDK_CORE_DISABLE_FILE_LOGGING="true",
               CLOUDSDK_CORE_LOG_HTTP="false", CLOUDSDK_CORE_VERBOSITY="error",
               CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK="true",
               CLOUDSDK_AUTH_DISABLE_SSL_VALIDATION="false")
    return env


def mint_once(account, root=p02.ROOT):
    p02.require(isinstance(account, str) and
                re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", account),
                "explicit_gcloud_account_required")
    executable = shutil.which("gcloud")
    p02.require(executable is not None, "gcloud_executable_required")
    setup = root / ".secrets/push/p02-setup"
    config = p02.prep.config_from_json(p02.prep.private_config(setup / "config.json"))
    # Validate every parent and keep a directory descriptor for exclusive output.
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in setup.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            p02.require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022, "insecure_setup_ancestor")
        info = os.fstat(parent)
        p02.require(info.st_uid == os.getuid() and not info.st_mode & 0o077, "insecure_setup_directory")
        # An existing/empty file is a consumed mint attempt; never silently renew.
        fd = os.open("sender-token.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.flush(); os.fsync(stream.fileno()); os.fsync(parent)
            started = time.time()
            service = f"p02-sender@{config.project_id}.iam.gserviceaccount.com"
            command = [executable, "auth", "print-access-token", f"--account={account}",
                       f"--project={config.project_id}", f"--impersonate-service-account={service}", "--lifetime=600"]
            result = subprocess.run(command, env=isolated_environment(setup), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
            p02.require(result.returncode == 0, "sender_impersonation_failed")
            p02.require(len(result.stdout) <= 16384, "invalid_sender_token_output")
            token = result.stdout.decode("ascii").strip()
            p02.prep.build_one_data_message(config, "synthetic-validation", token, "0" * 32)
            stream.write(p02.json_bytes({"access_token": token, "issued_at": started,
                         "expires_at": started + 600, "service_account": service, "project_id": config.project_id}))
            stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(parent)
    return {"sender_token_stored_privately": True, "requested_lifetime_seconds": 600,
            "service_account_key_downloaded": False, "gcloud_invocations": 1}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print('{"mode":"offline","explicit_setup_command":"mint --once --account ACCOUNT"}')
        return 0
    if len(args) != 4 or args[:3] != ["mint", "--once", "--account"]:
        print('{"error":"explicit_mint_once_required"}')
        return 2
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        previous = os.umask(0o077)
        try:
            result = mint_once(args[3])
        finally:
            os.umask(previous)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, p02.ProbeError, p02.p.ProtocolError, subprocess.SubprocessError):
        print('{"error":"sender_setup_failed_no_local_retry","raw_output_suppressed":true}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
