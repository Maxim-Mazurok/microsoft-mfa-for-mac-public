"""Synthetic fresh-input, provenance and separate-attempt protections."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import e02b as x
import test_e02 as f


class E02B(unittest.TestCase):
    def root(self):
        tmp = tempfile.TemporaryDirectory(prefix="e02b-offline-", dir=Path(__file__).resolve().parents[2] / "work")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for p in (".secrets", ".secrets/push", ".secrets/push/e02-setup", ".secrets/push/e02b-setup",
                  ".secrets/push/" + "a" * 32, ".secrets/push/" + "b" * 32):
            (root / p).mkdir(mode=0o700)
        def put(name, value):
            p = root / ".secrets/push" / name
            p.write_bytes(value if isinstance(value, bytes) else x.rt.json_bytes(value)); p.chmod(0o600)
        put("e02-attempt.lock", {"run_id": "a" * 32})
        put("v01-attempt.lock", {"run_id": "b" * 32})
        put("a" * 32 + "/report.json", {"experiment": "E02", "run_id": "a" * 32,
            "mcs_accepted": True, "activate_posts_attempted": 1, "validate_posts_attempted": 0,
            "confirm_posts_attempted": 0, "error": "invalid_notification_service_host"})
        put("b" * 32 + "/report.json", {"experiment": "V01", "run_id": "b" * 32,
            "started_utc": datetime.fromtimestamp(time.time()-50, timezone.utc).isoformat(),
            "validate_posts_attempted": 1, "validate_http_status": 200, "activate_posts_attempted": 0,
            "confirm_posts_attempted": 0})
        raw = f.VALIDATION.replace(b"<response>", b"<response>" + f.STATUS)
        raw = raw.replace(b"synthetic-group", b"").replace(b"synthetic-name", b"").replace(b"synthetic-dos", b"")
        put("b" * 32 + "/validate-body.bin", raw)
        put("a" * 32 + "/notification.json", {**f.PROPERTIES, "guid": "synthetic-old-guid"})
        data = {"expected_account": f.ACCOUNT, "activation_code": f.CODE, "service_base_url": f.BASE,
                "created_at": time.time()-60, "fresh_code": True}
        put("e02-setup/input.json", data)
        put("e02b-setup/input.json", {**data, "activation_code": "synthetic-new-code-b", "created_at": time.time()})
        return root, put

    def test_new_code_provenance_and_old_guid_exclusion(self):
        root, _ = self.root()
        with patch.object(x.e02, "load_identity", return_value=(None, f.CREDS, f.TOKEN)):
            inputs, ignored = x.prerequisites(root)
        self.assertEqual(inputs[3].code, "synthetic-new-code-b")
        self.assertEqual(ignored, frozenset(("synthetic-old-guid",)))

    def test_same_code_and_different_account_rejected_before_attempt(self):
        root, put = self.root()
        new = x.rt.private_json(root / ".secrets/push/e02b-setup/input.json")
        for change in ({"activation_code": f.CODE}, {"expected_account": "other@example.invalid"}, {"created_at": time.time()-999}):
            put("e02b-setup/input.json", {**new, **change})
            with patch.object(x.e02, "load_identity", return_value=(None, f.CREDS, f.TOKEN)):
                with self.assertRaises(Exception): x.run_once(root)
            self.assertFalse((root / ".secrets/push/e02b-attempt.lock").exists())

    def test_distinct_lock_and_private_capture_no_second_run(self):
        root, _ = self.root()
        old = (root / ".secrets/push/e02-attempt.lock").read_bytes()
        run = x.PrivateRun(root); run.write("report.json", b"{}"); run.close()
        with self.assertRaisesRegex(Exception, "already_reserved"): x.PrivateRun(root)
        self.assertEqual((root / ".secrets/push/e02-attempt.lock").read_bytes(), old)
        lock = x.rt.private_json(root / ".secrets/push/e02b-attempt.lock")
        file = root / ".secrets/push" / lock["run_id"] / "report.json"
        self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_setup_reuses_designated_account_without_requesting_it(self):
        root, _ = self.root()
        (root / ".secrets/push/e02b-setup/input.json").unlink()
        with patch.object(x.e02, "load_identity"), \
             patch.object(x.e02.e01, "secret_prompt", side_effect=["synthetic-new-code-b", f.BASE, "FRESH"]) as prompt:
            result = x.e02.setup(root, True, setup_id="e02b", existing_account=f.ACCOUNT)
        self.assertEqual(prompt.call_count, 3)
        self.assertTrue(result["input_saved_privately"])
        self.assertNotIn(f.ACCOUNT, json.dumps(result))


if __name__ == "__main__": unittest.main()
