"""All identities, callbacks and token strings below are invented fixtures."""
import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ngc_bootstrap as n

TID = "11111111-2222-3333-4444-555555555555"
OID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
NOW = 1800000000
IDENTITY = {"account": "synthetic@example.invalid", "tenant_id": TID, "object_id": OID}
RESOURCE = "urn:ms-drs:enterpriseregistration.windows.net"
ENDPOINT = "https://login.microsoftonline.com/" + TID + "/oauth2/"
DISCOVERY = {"TenantInfo": {"TenantId": TID}, "AuthenticationService": {"OAuth2": {
    "AuthCodeEndpoint": ENDPOINT + "authorize", "TokenEndpoint": ENDPOINT + "token"}},
    "KeyProvisioningService": {"KeyProvisionEndpoint": "https://enterpriseregistration.windows.net/EnrollmentServer/key/",
                               "KeyProvisionResourceId": RESOURCE}}


def prepared():
    return n.prepare(n.parse_discovery(json.dumps(DISCOVERY), TID), IDENTITY,
                     now=NOW, verifier="a" * 43, state="b" * 43)


def callback(transaction, **kwargs):
    return json.dumps({"v": 1, "experiment": "NGC-B01", "callback_url": n.REDIRECT + "?" +
                       urlencode({"state": transaction["state"], "code": "invented-one-use-code", **kwargs})}).encode()


def native_receipt(status="callback_saved", **overrides):
    saved = status in ("callback_saved", "authorization_rejected")
    return {"v": 1, "experiment": "NGC-B01", "status": status, "terminal": status in n.NATIVE_TERMINAL,
        "session_started": True, "callback_received": saved, "callback_saved": saved,
        "callback_candidate_saved": saved, "system_error_domain": "none", "system_error_code": None, **overrides}


class BootstrapTests(unittest.TestCase):
    def assertBad(self, fn, *args, **kwargs):
        with self.assertRaises(n.BootstrapError): fn(*args, **kwargs)

    def test_discovery_uses_traced_production_url(self):
        url = n.discovery_url(TID)
        self.assertEqual(url, "https://enterpriseregistration.windows.net/" + TID + "/Discover?api-version=1.9&managed=True")
        self.assertBad(n.discovery_url, "example.invalid/?leak=1")

    def test_discovery_exact_tenant_endpoint_resource_binding(self):
        got = n.parse_discovery(json.dumps(DISCOVERY), TID)
        self.assertEqual(got.resource, RESOURCE)
        self.assertEqual(got.token_endpoint, ENDPOINT + "token")
        self.assertNotIn(TID, repr(got))
        self.assertBad(n.parse_discovery, json.dumps(DISCOVERY), OID)
        for value in ("https://evil.invalid/", "urn:ms-drs:evil.invalid", "https://graph.microsoft.com/"):
            fixture = copy.deepcopy(DISCOVERY); fixture["KeyProvisioningService"]["KeyProvisionResourceId"] = value
            self.assertBad(n.parse_discovery, json.dumps(fixture), TID)
        fixture = copy.deepcopy(DISCOVERY); fixture["KeyProvisioningService"]["KeyProvisionEndpoint"] += "?secret=x"
        self.assertBad(n.parse_discovery, json.dumps(fixture), TID)

    def test_endpoints_reject_redirect_ports_paths_unknown_cloud(self):
        good = ENDPOINT + "authorize"
        for value in (good.replace("https", "http", 1), good.replace(".com/", ".com:443/"), good + "?x=y",
                      good + "#fragment", good.replace("login.microsoftonline.com", "evil.invalid"),
                      good.replace(TID, OID), good.replace("oauth2/", "oauth2/v2.0/"), good.replace("oauth2/", "../oauth2/"),
                      good.replace("login.microsoftonline.com", "user@login.microsoftonline.com")):
            self.assertBad(n.oauth_endpoint, value, "authorize", TID)
        for segment in ("common", "organizations"):
            self.assertEqual(n.oauth_endpoint(good.replace(TID, segment), "authorize", TID), good.replace(TID, segment))

    def test_discovery_requires_matched_endpoint_pair_and_unique_json(self):
        fixture = copy.deepcopy(DISCOVERY)
        fixture["AuthenticationService"]["OAuth2"]["TokenEndpoint"] = ENDPOINT.replace("login.microsoftonline.com", "login.windows.net") + "token"
        self.assertBad(n.parse_discovery, json.dumps(fixture), TID)
        self.assertBad(n.parse_discovery, '{"TenantInfo":{},"TenantInfo":{}}', TID)

    def test_pkce_exact_and_fresh_prepare(self):
        native, state = prepared()
        params = parse_qs(native["authorize_url"].split("?", 1)[1], strict_parsing=True)
        self.assertEqual(params["code_challenge"], [n.pkce("a" * 43)])
        self.assertEqual(params["redirect_uri"], [n.REDIRECT])
        self.assertEqual(params["scope"], [RESOURCE + "/.default openid profile offline_access"])
        self.assertEqual(native["authorize_endpoint"], ENDPOINT + "v2.0/authorize")
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["response_mode"], ["query"])
        self.assertEqual(params["client_id"], [n.CLIENT_ID])
        self.assertEqual(json.loads(params["claims"][0]), n.CLAIMS)
        self.assertEqual(native["expires_at"], NOW + 600)
        self.assertNotIn("verifier", native)
        self.assertNotIn("a" * 43, native["authorize_url"])
        self.assertNotIn("resource", params)
        for key, value in n.EXTRAS.items(): self.assertEqual(params[key], [value])
        self.assertBad(n.pkce, "invalid verifier")
        first, second = [n.prepare(n.parse_discovery(json.dumps(DISCOVERY), TID), IDENTITY, now=NOW)[1] for _ in range(2)]
        self.assertNotEqual(first["state"], second["state"])
        self.assertNotEqual(first["verifier"], second["verifier"])

    def test_callback_exact_state_redirect_no_ambiguous_duplicate(self):
        _, state = prepared()
        self.assertEqual(n.parse_callback(callback(state), state, now=NOW + 1), "invented-one-use-code")
        self.assertBad(n.parse_callback, callback(state, state="c" * 43), state, now=NOW + 1)
        good = json.loads(callback(state))
        for change in (lambda u: u.replace("com.azure.authenticator", "evil.invalid"),
                       lambda u: u + "&code=second", lambda u: u + "&state=" + state["state"],
                       lambda u: u + "#fragment", lambda u: u.replace("%3D", "%253D"),
                       lambda u: u + "&error=access_denied"):
            bad = dict(good, callback_url=change(good["callback_url"]))
            self.assertBad(n.parse_callback, json.dumps(bad), state, now=NOW + 1)
        self.assertBad(n.parse_callback, callback(state), state, now=NOW + 600)

    def test_callback_accepts_equivalent_decoded_path_and_known_sdk_metadata(self):
        _, state = prepared()
        original = json.loads(callback(state))
        for ending in ("=", "%3D", "%3d"):
            obj = dict(original, callback_url=original["callback_url"].replace("%3D", ending))
            self.assertEqual(n.parse_callback(json.dumps(obj), state, now=NOW), "invented-one-use-code")
        for ending in ("%", "%3", "%GG", "%253D", "=/extra", "%00", "%2F"):
            obj = dict(original, callback_url=original["callback_url"].replace("%3D", ending))
            self.assertBad(n.parse_callback, json.dumps(obj), state, now=NOW)
        # MicrosoftStsAuthorizationResponse's cloud_instance_name is metadata,
        # never an instruction to use that value as a token endpoint.
        raw = callback(state, cloud_instance_name="evil.invalid", error_subcode="synthetic")
        url, _ = n.token_request(state, raw, now=NOW)
        self.assertEqual(url, ENDPOINT + "v2.0/token")
        self.assertEqual(n.parse_callback(callback(state, unrecognized="field"), state, now=NOW), "invented-one-use-code")

    def test_inert_unknown_callback_metadata_cannot_change_exchange_binding(self):
        _, state = prepared()
        raw = callback(state, token_endpoint="https://evil.invalid/token", redirect_uri="https://evil.invalid/redirect",
            resource="https://graph.microsoft.com", STATE="lookalike", extra="", device_code="inert-device-code", user_code="inert-user-code")
        url, body = n.token_request(state, raw, now=NOW)
        fields = parse_qs(body.decode())
        self.assertEqual(url, ENDPOINT + "v2.0/token")
        self.assertEqual(fields["redirect_uri"], [n.REDIRECT])
        self.assertEqual(fields["scope"], [RESOURCE + "/.default openid profile offline_access"])
        self.assertNotIn("evil.invalid", body.decode())
        self.assertNotIn("lookalike", body.decode())
        self.assertEqual(fields["grant_type"], ["authorization_code"])
        self.assertNotIn("inert-device-code", body.decode())
        encoded = json.loads(raw); encoded["callback_url"] += "&extra=again"
        self.assertBad(n.parse_callback, json.dumps(encoded), state, now=NOW)
        no_code = json.loads(raw)
        no_code["callback_url"] = no_code["callback_url"].replace("code=invented-one-use-code&", "")
        self.assertBad(n.token_request, state, json.dumps(no_code), now=NOW)

    def test_callback_provider_error_redacts_description(self):
        _, state = prepared()
        raw = json.dumps({"v": 1, "experiment": "NGC-B01", "callback_url": n.REDIRECT + "?" +
            urlencode({"state": state["state"], "error": "access_denied", "error_description": "private-user-data"})})
        with self.assertRaisesRegex(n.BootstrapError, "^authorization_access_denied$"):
            n.parse_callback(raw, state, now=NOW)

    def test_callback_diagnosis_reports_structure_without_secret_values_or_replay(self):
        _, state = prepared()
        raw = callback(state, cloud_instance_name="synthetic-cloud.invalid")
        data = json.loads(raw); data["callback_url"] = data["callback_url"].replace("%3D", "=")
        with patch.object(n, "one_http") as network:
            report = n.callback_diagnosis(json.dumps(data), state, now=NOW + 900)
            self.assertTrue(report["interpretation_only"])
            self.assertTrue(report["current_input_expired"])
            self.assertTrue(report["decoded_path_matches"])
            self.assertFalse(report["literal_path_matches"])
            self.assertTrue(report["sdk_cloud_metadata_present"])
            self.assertEqual(report["structural_parser_status"], "accepted_shape_only")
            self.assertFalse(network.called)
        for secret in ("invented-one-use-code", "synthetic-cloud.invalid", state["state"], state["verifier"]):
            self.assertNotIn(secret, json.dumps(report))
        broken = n.callback_diagnosis(b'not-json with private material', state, now=NOW)
        self.assertFalse(broken["json_parseable"])
        self.assertEqual(broken["structural_parser_status"], "invalid_bootstrap_json")
        duplicate = json.loads(raw); duplicate["callback_url"] += "&state=duplicate"
        report = n.callback_diagnosis(json.dumps(duplicate), state, now=NOW)
        self.assertTrue(report["duplicate_query_keys"])
        self.assertEqual(report["structural_parser_status"], "invalid_bootstrap_callback")

    def test_state_revalidated_before_exchange(self):
        _, state = prepared()
        for change in (lambda s: s["discovery"].update(token_endpoint="https://evil.invalid/token"),
                       lambda s: s["identity"].update(tenant_id=OID), lambda s: s.update(expires_at=NOW + 9999),
                       lambda s: s.update(verifier="x"), lambda s: s.update(created_at=NOW + 10)):
            bad = copy.deepcopy(state); change(bad)
            self.assertBad(n.token_request, bad, callback(state), now=NOW)

    def test_code_exchange_has_no_secret_or_unsupported_fallback(self):
        _, state = prepared()
        url, body = n.token_request(state, callback(state), now=NOW)
        self.assertEqual(url, ENDPOINT + "v2.0/token")
        fields = parse_qs(body.decode())
        self.assertEqual(set(fields), {"grant_type", "client_id", "redirect_uri", "code", "code_verifier", "scope", "claims"})
        self.assertEqual(fields["grant_type"], ["authorization_code"])
        self.assertEqual(fields["code_verifier"], ["a" * 43])
        self.assertEqual(json.loads(fields["claims"][0]), n.CLAIMS)
        self.assertEqual(fields["scope"], [RESOURCE + "/.default openid profile offline_access"])

    def test_msal_resource_conversion_preserves_literal_slash_and_known_origin(self):
        self.assertEqual(n.msal_scopes("https://enterpriseregistration.windows.net/"),
            "https://enterpriseregistration.windows.net//.default openid profile offline_access")
        self.assertBad(n.msal_scopes, "https://graph.microsoft.com/")
        self.assertBad(n.msal_endpoint, "https://evil.invalid/common/oauth2/authorize", "authorize", TID)

    def test_token_report_never_promotes_decoded_claims_to_validation(self):
        _, state = prepared()
        claims = {"tid": TID, "oid": OID, "aud": RESOURCE, "deviceid": "invented-device",
                  "amr": ["ngcmfa"], "acrs": ["urn:user:registersecurityinfo"]}
        token = "invented." + n.b64url(json.dumps(claims).encode()) + ".fake-signature"
        report = n.token_report(json.dumps({"access_token": token, "token_type": "Bearer"}), state)
        self.assertTrue(report["access_token_returned"])
        self.assertTrue(report["deviceid_present"])
        self.assertTrue(report["tenant_matches_designated"])
        self.assertTrue(report["object_matches_designated"])
        self.assertFalse(report["token_signature_validated"])
        self.assertFalse(report["token_binding_established"])
        self.assertFalse(report["credential_registration_performed"])
        self.assertNotIn(token, json.dumps(report))
        self.assertNotIn("invented-device", json.dumps(report))
        opaque = n.token_report(json.dumps({"access_token": "invented-opaque", "token_type": "Bearer"}), state)
        self.assertEqual(opaque["claims_observation"], "unavailable")
        self.assertEqual(opaque["binding_status"], "identity_claims_unavailable")
        error = n.token_report(json.dumps({"error": "invalid_grant", "error_description": "private-user-data", "error_codes": [50076]}), state)
        self.assertEqual(error["provider_error_codes"], [50076])
        self.assertNotIn("private-user-data", json.dumps(error))

    def test_decoded_token_wrong_identity_stops_with_fixed_reason(self):
        _, state = prepared()
        for changed in ({"tid": OID}, {"oid": TID}, {"upn": "other@example.invalid"}, {"aud": "https://graph.microsoft.com"}):
            claims = {"tid": TID, "oid": OID, "aud": RESOURCE, **changed}
            token = "invented." + n.b64url(json.dumps(claims).encode()) + ".fake-signature"
            report = n.token_report(json.dumps({"access_token": token, "token_type": "Bearer"}), state)
            self.assertEqual(report["error"], "decoded_token_identity_mismatch")
            self.assertFalse(report["token_binding_established"])
            self.assertNotIn("other@example.invalid", json.dumps(report))

    def make_directory(self, temp):
        parent = Path(temp) / "private"; parent.mkdir(mode=0o700)
        directory = parent / "run"; directory.mkdir(mode=0o700)
        return directory

    def test_private_io_no_overwrite_symlink_or_unprotected_file(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp)
            file = directory / "state.json"
            n.private_write(file, b'{"private":true}')
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            self.assertEqual(n.private_read(file), b'{"private":true}')
            with self.assertRaises(FileExistsError): n.private_write(file, b"replacement")
            link = directory / "link"; link.symlink_to(file)
            with self.assertRaises(OSError): n.private_read(link)
            file.chmod(0o644)
            self.assertBad(n.private_read, file)

    def test_discovery_lock_prevents_second_request_and_preserves_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp)
            with patch.object(n, "identity_from_research", return_value=IDENTITY), \
                 patch.object(n, "one_http", return_value=(200, json.dumps(DISCOVERY).encode())) as network:
                report = n.discover_command(directory, Path(temp))
                self.assertTrue(report["validated_metadata"])
                self.assertEqual(report["get_attempts"], 1)
                with self.assertRaises(FileExistsError): n.discover_command(directory, Path(temp))
                self.assertEqual(network.call_count, 1)
            with patch.object(n.time, "time", return_value=NOW): report = n.prepare_command(directory)
            self.assertEqual(report["network_requests"], 0)
            saved = n.safe_json(n.private_read(directory / "state.json"))
            self.assertEqual(saved["identity"], IDENTITY)
            with self.assertRaises(FileExistsError): n.prepare_command(directory)

    def test_failed_network_attempt_cannot_be_repeated(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp)
            with patch.object(n, "identity_from_research", return_value=IDENTITY), \
                 patch.object(n, "one_http", side_effect=OSError("private-error-text")) as network:
                report = n.discover_command(directory, temp)
                self.assertEqual(report["error"], "local_io_or_network_failure")
                self.assertNotIn("private-error-text", json.dumps(report))
                with self.assertRaises(FileExistsError): n.discover_command(directory, temp)
                self.assertEqual(network.call_count, 1)

    def test_exchange_lock_prevents_retry_even_uncertain_send(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp)
            _, state = prepared()
            n.write_json(directory / "state.json", state)
            n.private_write(directory / "callback.json", callback(state))
            n.write_json(directory / "native-result.json", native_receipt())
            with patch.object(n.time, "time", return_value=NOW), patch.object(n, "one_http", side_effect=OSError("private-error")) as network:
                report = n.exchange_command(directory)
                self.assertEqual(report["error"], "local_io_or_network_failure")
                with self.assertRaises(FileExistsError): n.exchange_command(directory)
                self.assertEqual(network.call_count, 1)

    def seed_cached_discovery(self, directory):
        n.write_json(directory / "identity.json", IDENTITY)
        n.private_write(directory / "discovery-response.bin", json.dumps(DISCOVERY).encode())
        n.write_json(directory / "discovery-report.json", {"validated_metadata": True, "tls_verified": True,
                     "get_attempts": 1, "http_status": 200})

    def test_cache_staging_copies_only_validated_metadata_without_oauth_material(self):
        with tempfile.TemporaryDirectory() as temp:
            source = self.make_directory(temp); self.seed_cached_discovery(source)
            for name in ("state.json", "auth-input.json", "callback.json", "token-response.bin", "live-attempt.lock"):
                n.private_write(source / name, b"synthetic-consumed-secret")
            before = {p.name: p.read_bytes() for p in source.iterdir()}
            target = source.parent / "next"
            with patch.object(n, "one_http") as network:
                report = n.stage_command(target, source)
                self.assertEqual(report["get_attempts"], 0)
                self.assertFalse(report["fresh_pkce_created"])
                self.assertFalse(report["oauth_material_copied"])
                self.assertFalse(network.called)
                for name in ("state.json", "auth-input.json", "callback.json", "token-response.bin", "live-attempt.lock"):
                    self.assertFalse((target / name).exists())
                with patch.object(n.time, "time", return_value=NOW): n.prepare_command(target)
                saved = n.safe_json(n.private_read(target / "state.json"))
                self.assertEqual(saved["created_at"], NOW)
                self.assertNotEqual(saved["state"], "synthetic-consumed-secret")
                self.assertBad(n.stage_command, target, source)
                self.assertBad(n.stage_command, source, source)
            self.assertEqual({p.name: p.read_bytes() for p in source.iterdir()}, before)

    def test_cache_staging_rejects_unvalidated_or_wrong_tenant_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            source = self.make_directory(temp); self.seed_cached_discovery(source)
            bad = copy.deepcopy(DISCOVERY); bad["TenantInfo"]["TenantId"] = OID
            (source / "discovery-response.bin").write_text(json.dumps(bad))
            target = source.parent / "next"
            self.assertBad(n.stage_command, target, source)
            self.assertFalse(target.exists())

    def test_one_session_wrapper_prepares_then_exchanges_only_once(self):
        class Ended:
            def poll(self): return 0
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp); self.seed_cached_discovery(directory)
            def launch(path, private):
                state = n.safe_json(n.private_read(private / "state.json"))
                n.private_write(private / "callback.json", callback(state))
                n.write_json(private / "native-result.json", native_receipt())
                return Ended()
            with patch.object(n.time, "time", return_value=NOW), \
                 patch.object(n, "helper_path", return_value=Path("/synthetic/helper.app")), \
                 patch.object(n, "validate_native_input"), \
                 patch.object(n, "launch_helper", side_effect=launch) as launched, \
                 patch.object(n, "one_http", return_value=(200, b'{"token_type":"Bearer","access_token":"synthetic-opaque"}')) as network:
                report = n.live_command(directory)
                self.assertTrue(report["access_token_returned"])
                self.assertEqual(report["get_attempts"], 0)
                self.assertEqual(report["post_attempts"], 1)
                self.assertEqual(network.call_args.args[0], "POST")
                self.assertEqual(network.call_count, 1)
                self.assertEqual(launched.call_count, 1)
                with self.assertRaises(FileExistsError): n.live_command(directory)
                self.assertEqual(network.call_count, 1)
                self.assertEqual(launched.call_count, 1)
                self.assertFalse(report["token_binding_established"])

    def test_wrapper_cancel_does_not_exchange_or_retry(self):
        class Ended:
            def poll(self): return 0
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp); self.seed_cached_discovery(directory)
            with patch.object(n.time, "time", return_value=NOW), \
                 patch.object(n, "helper_path", return_value=Path("/synthetic/helper.app")), \
                 patch.object(n, "validate_native_input"), \
                 patch.object(n, "launch_helper", return_value=Ended()) as launched, \
                 patch.object(n, "one_http") as network:
                report = n.live_command(directory)
                self.assertEqual(report["error"], "native_result_missing")
                self.assertEqual(report["post_attempts"], 0)
                self.assertFalse(network.called)
                self.assertEqual(launched.call_count, 1)

    def test_wrapper_invalid_callback_stops_before_post(self):
        class Ended:
            def poll(self): return 0
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp); self.seed_cached_discovery(directory)
            def launch(path, private):
                state = n.safe_json(n.private_read(private / "state.json"))
                n.private_write(private / "callback.json", callback(state, state="c" * 43))
                n.write_json(private / "native-result.json", native_receipt())
                return Ended()
            with patch.object(n.time, "time", return_value=NOW), \
                 patch.object(n, "helper_path", return_value=Path("/synthetic/helper.app")), \
                 patch.object(n, "validate_native_input"), \
                 patch.object(n, "launch_helper", side_effect=launch), patch.object(n, "one_http") as network:
                report = n.live_command(directory)
                self.assertEqual(report["error"], "bootstrap_state_mismatch")
                self.assertFalse(network.called)
                self.assertFalse((directory / "exchange-attempt.lock").exists())

    def test_wrapper_waits_for_native_exit_not_partially_created_callback(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp); self.seed_cached_discovery(directory)
            class Running:
                calls = 0
                def poll(self):
                    self.calls += 1
                    return None if self.calls == 1 else 0
            process = Running()
            def launch(path, private):
                n.private_write(private / "callback.json", b"")  # Native creation, not fsync completion.
                return process
            def tick(_):
                state = n.safe_json(n.private_read(directory / "state.json"))
                (directory / "callback.json").write_bytes(callback(state))
                n.write_json(directory / "native-result.json", native_receipt())
            with patch.object(n.time, "time", return_value=NOW), patch.object(n.time, "sleep", side_effect=tick), \
                 patch.object(n, "helper_path", return_value=Path("/synthetic/helper.app")), \
                 patch.object(n, "validate_native_input"), patch.object(n, "launch_helper", side_effect=launch), \
                 patch.object(n, "one_http", return_value=(200, b'{"token_type":"Bearer","access_token":"synthetic-opaque"}')) as network:
                report = n.live_command(directory)
                self.assertTrue(report["access_token_returned"])
                self.assertGreaterEqual(process.calls, 2)
                self.assertEqual(network.call_count, 1)

    def test_native_receipt_requires_fixed_schema_and_consistent_outcome(self):
        self.assertEqual(n.native_result(json.dumps(native_receipt()))["status"], "callback_saved")
        for overrides in ({"v": True}, {"terminal": 1}, {"callback_saved": False}, {"terminal": False}, {"callback_received": False},
            {"callback_candidate_saved": False}, {"session_started": False}, {"status": "raw-private-provider-message"},
            {"system_error_domain": "raw-domain"}, {"system_error_code": True}, {"system_error_code": 999999},
            {"system_error_code": 1}, {"extra": "secret"}):
            self.assertBad(n.native_result, json.dumps(native_receipt(**overrides)))
        duplicate = json.dumps(native_receipt())[:-1] + ',"status":"callback_saved"}'
        self.assertBad(n.native_result, duplicate)
        failed = native_receipt("authentication_session_failed", system_error_domain="authentication_services", system_error_code=3)
        self.assertEqual(n.native_result(json.dumps(failed))["system_error_code"], 3)

    def test_terminal_native_failure_reports_reason_and_candidate_without_exchange(self):
        class Ended:
            def poll(self): return 0
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp); self.seed_cached_discovery(directory)
            def launch(path, private):
                state = n.safe_json(n.private_read(private / "state.json"))
                # Even a structurally valid candidate is inert after rejection.
                n.private_write(private / "native-callback-candidate.json", callback(state))
                n.write_json(private / "native-result.json", native_receipt("callback_path_mismatch",
                    callback_received=True, callback_candidate_saved=True))
                return Ended()
            with patch.object(n.time, "time", return_value=NOW), \
                 patch.object(n, "helper_path", return_value=Path("/synthetic/helper.app")), \
                 patch.object(n, "validate_native_input"), patch.object(n, "launch_helper", side_effect=launch), \
                 patch.object(n, "one_http") as network:
                report = n.live_command(directory)
                self.assertEqual(report["native_status"], "callback_path_mismatch")
                self.assertEqual(report["error"], "native_callback_path_mismatch")
                self.assertTrue(report["callback_diagnostic"]["interpretation_only"])
                self.assertEqual(report["callback_diagnostic"]["structural_parser_status"], "accepted_shape_only")
                self.assertFalse(network.called)
                self.assertFalse((directory / "exchange-attempt.lock").exists())
                self.assertNotIn("invented-one-use-code", json.dumps(report))

    def test_callback_saved_flag_requires_matching_terminal_status(self):
        for status in ("cancelled", "authentication_session_failed", "ready", "session_started"):
            self.assertBad(n.native_result, json.dumps(native_receipt(status, callback_saved=True,
                callback_received=True, callback_candidate_saved=True)))

    def test_receipt_rejection_never_exchanges_even_if_callback_contains_valid_code(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp)
            _, state = prepared()
            n.write_json(directory / "state.json", state)
            n.private_write(directory / "callback.json", callback(state))
            n.write_json(directory / "native-result.json", native_receipt("authorization_rejected"))
            with patch.object(n.time, "time", return_value=NOW), patch.object(n, "one_http") as network:
                self.assertBad(n.exchange_command, directory)
                self.assertFalse(network.called)
                self.assertFalse((directory / "exchange-attempt.lock").exists())

    def test_receipt_cancel_conflict_never_exchanges_existing_accepted_file(self):
        class Ended:
            def poll(self): return 0
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp); self.seed_cached_discovery(directory)
            def launch(path, private):
                state = n.safe_json(n.private_read(private / "state.json"))
                n.private_write(private / "callback.json", callback(state))
                n.write_json(private / "native-result.json", native_receipt("cancelled", callback_saved=True,
                    callback_received=True, callback_candidate_saved=True))
                return Ended()
            with patch.object(n.time, "time", return_value=NOW), \
                 patch.object(n, "helper_path", return_value=Path("/synthetic/helper.app")), \
                 patch.object(n, "validate_native_input"), patch.object(n, "launch_helper", side_effect=launch), \
                 patch.object(n, "one_http") as network:
                report = n.live_command(directory)
                self.assertEqual(report["error"], "invalid_native_result")
                self.assertFalse(network.called)
                self.assertFalse((directory / "exchange-attempt.lock").exists())

    def test_nonterminal_receipt_cannot_authorize_exchange(self):
        class Ended:
            def poll(self): return 0
        with tempfile.TemporaryDirectory() as temp:
            directory = self.make_directory(temp); self.seed_cached_discovery(directory)
            def launch(path, private):
                state = n.safe_json(n.private_read(private / "state.json"))
                n.private_write(private / "callback.json", callback(state))
                n.write_json(private / "native-result.json", native_receipt("session_started"))
                return Ended()
            with patch.object(n.time, "time", return_value=NOW), \
                 patch.object(n, "helper_path", return_value=Path("/synthetic/helper.app")), \
                 patch.object(n, "validate_native_input"), patch.object(n, "launch_helper", side_effect=launch), \
                 patch.object(n, "one_http") as network:
                report = n.live_command(directory)
                self.assertEqual(report["error"], "native_result_incomplete")
                self.assertEqual(report["native_status"], "session_started")
                self.assertFalse(network.called)

    def test_http_verifies_tls_no_follow_and_bounded_body(self):
        class Response:
            status = 302
            def read1(self, nbytes): return b""
        class Connection:
            sock = None
            requests = []
            def __init__(self, host, port, timeout, context):
                self.context = context
                self.assertions = (host, port, timeout, context.check_hostname, context.verify_mode)
            def request(self, *args, **kwargs): self.requests.append((args, kwargs))
            def getresponse(self): return Response()
            def close(self): pass
        saved = []
        def factory(*args, **kwargs):
            value = Connection(*args, **kwargs); saved.append(value); return value
        status, body = n.one_http("GET", n.discovery_url(TID), connection_factory=factory)
        self.assertEqual(status, 302)
        self.assertEqual(len(saved), 1)
        self.assertEqual(len(saved[0].requests), 1)
        headers = saved[0].requests[0][1]["headers"]
        self.assertEqual(headers["ocp-adrs-client-name"], "Microsoft MFA for Mac research")
        self.assertEqual(headers["ocp-adrs-client-version"], "1.0.0")
        self.assertRegex(headers["client-request-id"], r"^[0-9a-f-]{36}$")
        self.assertTrue(saved[0].assertions[3])
        self.assertEqual(saved[0].assertions[4], 2)
        self.assertBad(n.one_http, "GET", "https://evil.invalid/", connection_factory=factory)
        self.assertEqual(len(saved), 1)


if __name__ == "__main__": unittest.main()
