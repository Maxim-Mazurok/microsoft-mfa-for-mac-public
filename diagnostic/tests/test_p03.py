"""P03 synthetic tests: no real artifact API keys, credentials, DNS or sockets."""
from contextlib import redirect_stdout
from dataclasses import asdict, replace
import hashlib
import io
import json
from pathlib import Path
import socket
import stat
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "diagnostic"))
import p03 as x
import push_protocol as p
import test_p02 as fixtures
from test_p01 import FakeSocket, http

CONFIG = p.AndroidConfig(x.PROJECT, x.SENDER, x.APP, "synthetic-api-key", x.PACKAGE,
                         x.CERTIFICATE, "mfaProdV1", "6.2610.7075", "202670753")
FID = fixtures.FID
FIS = json.dumps({"fid": FID, "name": f"projects/{x.PROJECT}/installations/{FID}",
                  "refreshToken": "synthetic-fis-refresh", "authToken": {"token": "synthetic-fis-auth",
                                                                          "expiresIn": "3600s"}}).encode()


class P03Tests(unittest.TestCase):
    def setUp(self):
        self.no_dns = patch.object(socket, "getaddrinfo", side_effect=AssertionError("Real DNS forbidden")).start()
        self.no_socket = patch.object(socket, "socket", side_effect=AssertionError("Real socket forbidden")).start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        self.no_dns.assert_not_called(); self.no_socket.assert_not_called()

    def root(self):
        root = fixtures.P02Tests.root(self)
        setup = root / ".secrets/push/p03-setup"; setup.mkdir(mode=0o700)
        file = setup / "config.json"; file.write_bytes(x.r.json_bytes(asdict(CONFIG))); file.chmod(0o600)
        return root

    def simulate(self, *, root=None, fis=http(FIS), registration=http(b"token=synthetic-fcm-token"), fragment=4096):
        root = root or self.root(); sockets = [FakeSocket(fis, fragment), FakeSocket(registration, fragment)]
        calls = []
        def connect(kind, deadline, report):
            self.assertIn(kind, ("fis", "register3")); calls.append(kind)
            self.assertEqual(report[kind + "_connections_attempted"], 0)
            report[kind + "_connections_attempted"] = 1; report[kind + "_tls_verified"] = True
            return sockets[0 if kind == "fis" else 1]
        with patch.object(x.p02, "connect_tls", side_effect=connect), \
             patch.object(x, "artifact_config", return_value=CONFIG), patch.object(p, "new_fid", return_value=FID):
            report = x.run_once(root)
        return report, sockets, calls, root

    def test_two_posts_success_no_mcs_oauth_checkin_or_microsoft(self):
        report, sockets, calls, root = self.simulate(fragment=1)
        self.assertEqual(calls, ["fis", "register3"])
        self.assertTrue(report["aad_registration_issued"]); self.assertIsNone(report["error"])
        self.assertEqual(report["http_posts_attempted"], 2)
        for key in ("mcs_connections_attempted", "microsoft_requests", "new_google_checkins", "send_posts_attempted", "automatic_retries", "oauth_requests_during_probe"):
            self.assertEqual(report[key], 0)
        self.assertFalse(report["microsoft_delivery_proven"]); self.assertFalse(report["enrollment_completed"])
        for secret in ("synthetic-api-key", "synthetic-fcm-token", "synthetic-fis-auth", "synthetic-fis-refresh", FID, *fixtures.CREDS.values()):
            self.assertNotIn(secret, json.dumps(report))
        self.assertTrue(all(len(sock.sent) == 1 and sock.closed for sock in sockets))
        self.assertIn(b"sender=" + x.SENDER.encode(), sockets[1].sent[0])
        self.assertIn(b"target_ver=36", sockets[1].sent[0])
        lock = x.r.private_json(root / ".secrets/push/p03-attempt.lock")
        run = root / ".secrets/push" / lock["run_id"]
        for file in run.iterdir(): self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(run.stat().st_mode), 0o700)

    def test_fis_rejection_redirect_invalid_identity_stops(self):
        for fis in (http(b'{"error":{"status":"PERMISSION_DENIED","message":"private-detail"}}',403),
                    http(b"private-detail",302,"Location: https://evil.invalid/\r\n"),
                    http(FIS.replace(FID.encode(),b"dBBBBBBBBBBBBBBBBBBBBB"))):
            report, _, calls, _ = self.simulate(fis=fis)
            self.assertEqual(calls, ["fis"]); self.assertFalse(report["aad_registration_issued"])
            self.assertNotIn("private-detail",json.dumps(report))

    def test_registration_error_no_fallback_or_retry(self):
        for registration in (http(b"Error=AUTHENTICATION_FAILED"),http(b"Error=private-secret"),http(b"token=x\ntoken=y")):
            report, _, calls, _ = self.simulate(registration=registration)
            self.assertEqual(calls,["fis","register3"]); self.assertFalse(report["aad_registration_issued"])
            self.assertIsNotNone(report["error"]); self.assertNotIn("private-secret",json.dumps(report))

    def test_lock_prevents_second_attempt_and_prior_locks_unchanged(self):
        root=self.root(); p01=(root/".secrets/push/p01-attempt.lock").read_bytes()
        self.simulate(root=root)
        report,_,calls,_=self.simulate(root=root)
        self.assertEqual(calls,[])
        self.assertEqual(report["error"],"experiment_attempt_already_reserved_no_retry")
        self.assertEqual(p01,(root/".secrets/push/p01-attempt.lock").read_bytes())

    def test_project_package_certificate_version_and_api_binding(self):
        for change in ({"project_id":"wrong-project"},{"package":"other.app"},{"certificate_sha1":"a"*40},{"firebase_name":"mfaPpe"},{"app_version_code":"1"}):
            with self.assertRaises(Exception): x.config_from_json(x.r.json_bytes(asdict(replace(CONFIG,**change))))
        root=self.root(); f=root/".secrets/push/p03-setup/config.json"
        f.write_bytes(x.r.json_bytes(asdict(replace(CONFIG,api_key="different-api-key"))))
        report,_,calls,_=self.simulate(root=root)
        self.assertEqual(calls,[]); self.assertEqual(report["error"],"private_configuration_differs_from_artifact")

    def test_third_post_and_send_kind_rejected_before_transport(self):
        report=x.p02.new_report();report["http_posts_attempted"]=2
        with patch.object(x.p02,"post") as post:
            for kind in ("fis","send","checkin","mcs"):
                with self.assertRaises(x.p01.ProbeError): x.post(kind,None,None,None,None,report)
            post.assert_not_called()

    def test_runtime_private_directory_symlink_and_file_overwrite(self):
        root=self.root(); run=x.r.PrivateRun(root,"p03",x.FILES);self.addCleanup(run.close)
        run.write("report.json",b"{}")
        with self.assertRaises(FileExistsError):run.write("report.json",b"{}")
        with self.assertRaises(x.p01.ProbeError):run.write("../escape",b"{}")
        link=root/"linked";link.symlink_to(root/".secrets/push",target_is_directory=True)
        with self.assertRaises(OSError): x.r.private_directory(link)

    def test_synthetic_extraction_hash_pin_and_exclusive_setup(self):
        root=fixtures.P02Tests.root(self);file=root/x.SOURCE;file.parent.mkdir(parents=True)
        fields={"MFA_PROD_PROJECT_ID":x.PROJECT,"MFA_PROD_GCM_SENDER_ID":x.SENDER,"MFA_PROD_APPLICATION_ID":x.APP,
                "MFA_PROD_API_KEY":"synthetic-api-key","MFA_PROD_APP_NAME":"mfaProdV1"}
        file.write_text("\n".join(f'public static final String {k} = "{v}";' for k,v in fields.items()))
        with self.assertRaises(x.p01.ProbeError): x.artifact_config(root)
        with patch.object(x,"SOURCE_HASH",hashlib.sha256(file.read_bytes()).hexdigest()):
            result=x.prepare_private(root)
            self.assertEqual(result["network_requests"],0)
            self.assertEqual(x.prerequisites(root)[0],CONFIG)
            with self.assertRaises(FileExistsError):x.prepare_private(root)

    def test_cli_default_and_live_gate_redaction(self):
        for args in ([],["prepare"],["live"],["live","--one-attempt","private-secret"]):
            out=io.StringIO()
            with patch.object(x,"run_once") as run,redirect_stdout(out): x.main(args)
            run.assert_not_called();self.assertNotIn("private-secret",out.getvalue())
        out=io.StringIO()
        with patch.object(x.resource,"setrlimit"),patch.object(x,"run_once",side_effect=ValueError("private-secret")),redirect_stdout(out):
            self.assertEqual(x.main(["live","--one-attempt"]),1)
        self.assertNotIn("private-secret",out.getvalue())


if __name__ == "__main__": unittest.main()
