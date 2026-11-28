"""Offline tests for explicit sender setup. gcloud is always mocked."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "diagnostic"))
import p02_sender as x
import test_p02 as fixtures


class SenderSetupTests(unittest.TestCase):
    def setUp(self):
        executable = patch.object(x.shutil, "which", return_value="/synthetic/gcloud")
        executable.start()
        self.addCleanup(executable.stop)

    def root(self):
        root = fixtures.P02Tests.root(self)
        (root / ".secrets/push/p02-setup/sender-token.json").unlink()
        return root

    def test_one_keyless_invocation_isolated_environment_and_private_output(self):
        root = self.root()
        with patch.object(x.subprocess, "run", return_value=Mock(returncode=0, stdout=b"synthetic-secret-token\n")) as run:
            result = x.mint_once("researcher@example.test", root)
            self.assertTrue(result["sender_token_stored_privately"])
            run.assert_called_once()
            args, kwargs = run.call_args
            self.assertIn("--lifetime=600", args[0])
            self.assertIn("--impersonate-service-account=p02-sender@synthetic-p02-project.iam.gserviceaccount.com", args[0])
            self.assertIn("--account=researcher@example.test", args[0])
            self.assertIn("--project=synthetic-p02-project", args[0])
            self.assertEqual(kwargs["env"]["CLOUDSDK_CONFIG"], str(root / ".secrets/push/p02-setup/gcloud"))
            self.assertEqual(kwargs["env"]["CLOUDSDK_CORE_LOG_HTTP"], "false")
            self.assertEqual(kwargs["stderr"], x.subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 60)
            with self.assertRaises(FileExistsError):
                x.mint_once("researcher@example.test", root)
            run.assert_called_once()
        path = root / ".secrets/push/p02-setup/sender-token.json"
        token = json.loads(path.read_text())
        self.assertEqual(token["expires_at"] - token["issued_at"], 600)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertNotIn(token["access_token"], json.dumps(result))

    def test_failed_or_malformed_mint_is_not_retried(self):
        for response in (Mock(returncode=1, stdout=b"private-error"),
                         Mock(returncode=0, stdout=b"secret\ninjected")):
            root = self.root()
            with patch.object(x.subprocess, "run", return_value=response) as run:
                with self.assertRaises(Exception):
                    x.mint_once("researcher@example.test", root)
                with self.assertRaises(FileExistsError):
                    x.mint_once("researcher@example.test", root)
                run.assert_called_once()
            self.assertEqual((root / ".secrets/push/p02-setup/sender-token.json").read_bytes(), b"")

    def test_inherited_sdk_overrides_and_tls_keylog_are_not_used(self):
        with patch.dict(os.environ, {"CLOUDSDK_API_ENDPOINT_OVERRIDES_IAMCREDENTIALS": "https://evil.invalid/",
                                     "CLOUDSDK_AUTH_DISABLE_SSL_VALIDATION": "true", "SSLKEYLOGFILE": "secret-path"}):
            env = x.isolated_environment(Path("/synthetic"))
        self.assertNotIn("CLOUDSDK_API_ENDPOINT_OVERRIDES_IAMCREDENTIALS", env)
        self.assertNotIn("SSLKEYLOGFILE", env)
        self.assertEqual(env["CLOUDSDK_AUTH_DISABLE_SSL_VALIDATION"], "false")

    def test_cli_defaults_offline_explicit_gate_and_exception_redaction(self):
        for args in ([], ["mint"], ["mint", "--once"], ["mint", "--once", "secret-argument"]):
            output = io.StringIO()
            with patch.object(x, "mint_once") as mint, redirect_stdout(output):
                x.main(args)
            mint.assert_not_called()
            self.assertNotIn("secret-argument", output.getvalue())
        output = io.StringIO()
        with patch.object(x.resource, "setrlimit"), \
             patch.object(x, "mint_once", side_effect=ValueError("secret-exception")), redirect_stdout(output):
            self.assertEqual(x.main(["mint", "--once", "--account", "researcher@example.test"]), 1)
        self.assertNotIn("secret-exception", output.getvalue())

    def test_invalid_account_or_missing_executable_does_not_consume_attempt(self):
        for account in ("", "--account=other", "private\nvalue"):
            root = self.root()
            with patch.object(x.subprocess, "run") as invocation:
                with self.assertRaises(x.p02.ProbeError):
                    x.mint_once(account, root)
            invocation.assert_not_called()
            self.assertFalse((root / ".secrets/push/p02-setup/sender-token.json").exists())
        root = self.root()
        with patch.object(x.shutil, "which", return_value=None), patch.object(x.subprocess, "run") as invocation:
            with self.assertRaises(x.p02.ProbeError):
                x.mint_once("researcher@example.test", root)
        invocation.assert_not_called()
        self.assertFalse((root / ".secrets/push/p02-setup/sender-token.json").exists())


if __name__ == "__main__":
    unittest.main()
