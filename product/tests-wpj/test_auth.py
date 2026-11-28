"""Synthetic WPJ authorization tests. No live identity, UI, or network access."""
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import parse_qsl, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service"))
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import ngc_bootstrap as n
import wpj_auth as a
import wpj_protocol as w

NOW = 1_800_000_000
TENANT = "11111111-2222-3333-4444-555555555555"
OBJECT = "22222222-3333-4444-5555-666666666666"
IDENTITY = {"account": "research@example.test", "tenant_id": TENANT, "object_id": OBJECT}
RESOURCE = "urn:ms-drs:enterpriseregistration.windows.net"
STATE = "s" * 43
VERIFIER = "v" * 43
ISSUER = "https://sts.windows.net/" + TENANT + "/"
BINARY = a.HELPER / "Contents/MacOS/WorkplaceJoinBootstrap"


def discovery():
    return w.Discovery(TENANT, RESOURCE, RESOURCE,
        "https://enterpriseregistration.windows.net/EnrollmentServer/device/",
        "https://login.microsoftonline.com/common/oauth2/authorize",
        "https://login.microsoftonline.com/common/oauth2/token")


def prepared(now=NOW):
    return a.prepare(discovery(), dict(IDENTITY), now=now, verifier=VERIFIER, state=STATE)


def callback(items=None, *, redirect=a.REDIRECT):
    items = [("code", "SYNTHETIC_CODE"), ("state", STATE)] if items is None else items
    return w.encode({"v": 1, "experiment": "WPJ-A01", "callback_url": redirect + "?" + urlencode(items)})


def receipt(status="callback_saved"):
    saved = status in ("callback_saved", "authorization_rejected")
    return {"v": 1, "experiment": "WPJ-A01", "status": status, "terminal": True,
        "session_started": True, "callback_received": saved, "callback_saved": saved,
        "callback_candidate_saved": saved, "system_error_domain": "none", "system_error_code": None}


class Authorization(unittest.TestCase):
    def setUp(self):
        self.native, self.state = prepared()

    def test_prepare_is_distinct_preregistration_request(self):
        params = dict(parse_qsl(urlsplit(self.native["authorize_url"]).query))
        self.assertEqual(set(params), {"client_id", "redirect_uri", "response_type", "response_mode", "scope",
            "login_hint", "hsu", "state", "code_challenge", "code_challenge_method", "msafed"})
        self.assertEqual(params["client_id"], "29d9ed98-a469-4536-ade2-f981bc1d605e")
        self.assertEqual(params["redirect_uri"], "msauth://Microsoft.AAD.BrokerPlugin")
        self.assertEqual((params["hsu"], params["msafed"], params["code_challenge_method"]), ("1", "0", "S256"))
        self.assertEqual(params["code_challenge"], n.pkce(VERIFIER))
        self.assertEqual(set(params["scope"].split()), {RESOURCE + "/.default", "openid", "profile", "offline_access"})
        self.assertNotIn("claims", params)
        self.assertNotIn("code_verifier", self.native)
        self.assertEqual(self.native["callback_path"], "")
        self.assertEqual(self.native["expires_at"], NOW + 600)
        self.assertEqual(self.state["verifier"], VERIFIER)
        self.assertEqual(self.state["experiment"], "WPJ-A01")

    def test_msal_conversion_preserves_discovered_resource(self):
        for resource in n.RESOURCES:
            with self.subTest(resource=resource):
                native, _ = a.prepare(replace(discovery(), registration_resource=resource), IDENTITY, now=NOW)
                params = dict(parse_qsl(urlsplit(native["authorize_url"]).query))
                self.assertIn(resource + "/.default", params["scope"].split())

    def test_prepare_rejects_wrong_identity_endpoint_resource_and_pkce(self):
        cases = [replace(discovery(), tenant_id=OBJECT),
            replace(discovery(), authorize_endpoint="https://untrusted.invalid/common/oauth2/authorize"),
            replace(discovery(), token_endpoint="https://login.microsoftonline.com/" + OBJECT + "/oauth2/token"),
            replace(discovery(), registration_resource="https://graph.microsoft.com")]
        for metadata in cases:
            with self.subTest(metadata=repr(metadata)):
                with self.assertRaises((w.WpjError, n.BootstrapError)):
                    a.prepare(metadata, IDENTITY, now=NOW)
        for fields in ({"state": "short"}, {"verifier": "short"}, {"now": True}):
            with self.assertRaises((w.WpjError, n.BootstrapError)):
                a.prepare(discovery(), IDENTITY, **({"now": NOW} | fields))

    def test_state_is_fresh_and_experiment_specific(self):
        self.assertEqual(a.validate_state(self.state, NOW + 1), discovery())
        for change in ({"experiment": "NGC-B01"}, {"v": True}, {"expires_at": NOW + 601},
                       {"created_at": NOW + 5, "expires_at": NOW + 605}, {"verifier": "bad"}):
            with self.subTest(fields=tuple(change)):
                with self.assertRaises((w.WpjError, n.BootstrapError)):
                    a.validate_state(self.state | change, NOW)
        with self.assertRaises(w.WpjError):
            a.validate_state(self.state, NOW + 600)

    def test_callback_metadata_is_inert_and_host_case_insensitive(self):
        items = [("code", "SYNTHETIC_CODE"), ("state", STATE),
            ("cloud_instance_name", "metadata.invalid"), ("token_endpoint", "https://untrusted.invalid/token"),
            ("redirect_uri", "https://untrusted.invalid/callback"), ("access_token", "IGNORED_SYNTHETIC_TOKEN")]
        for redirect in (a.REDIRECT, a.REDIRECT.lower()):
            self.assertEqual(a.callback(callback(items, redirect=redirect), self.state, now=NOW + 1), "SYNTHETIC_CODE")
        url, body = a.code_request(self.state, callback(items), now=NOW + 1)
        self.assertEqual(url, "https://login.microsoftonline.com/common/oauth2/v2.0/token")
        params = dict(parse_qsl(body.decode()))
        self.assertEqual(set(params), {"client_id", "grant_type", "redirect_uri", "code", "code_verifier", "scope"})
        self.assertEqual(params["client_id"], a.CLIENT_ID)
        self.assertEqual(params["code"], "SYNTHETIC_CODE")
        self.assertEqual(params["code_verifier"], VERIFIER)
        self.assertNotIn(b"untrusted", body)
        self.assertNotIn(b"IGNORED", body)

    def test_callback_duplicate_ambiguous_wrong_state_and_token_only_rejected(self):
        cases = [[("code", "one"), ("code", "two"), ("state", STATE)],
            [("code", "one"), ("state", STATE), ("state", STATE)],
            [("code", "one"), ("error", "access_denied"), ("state", STATE)],
            [("code", "one"), ("state", "wrong")],
            [("access_token", "synthetic"), ("state", STATE)],
            [("code", ""), ("state", STATE)],
            [("code", "one"), ("state", STATE), ("metadata", "one"), ("metadata", "two")]]
        for items in cases:
            with self.subTest(keys=[key for key, _ in items]):
                with self.assertRaises(w.WpjError):
                    a.callback(callback(items), self.state, now=NOW + 1)

    def test_error_callback_returns_fixed_code_without_description(self):
        raw = callback([("error", "service-supplied-value"), ("error_description", "PRIVATE_SYNTHETIC_DESCRIPTION"), ("state", STATE)])
        with self.assertRaises(w.WpjError) as captured:
            a.callback(raw, self.state, now=NOW + 1)
        self.assertEqual(str(captured.exception), "authorization_rejected")

    def test_callback_destination_and_encoding_fail_closed(self):
        for redirect in (a.REDIRECT + "/", "msauth://other.invalid", "https://Microsoft.AAD.BrokerPlugin",
                         "msauth://user@Microsoft.AAD.BrokerPlugin", a.REDIRECT + ":443",
                         "msauth://com.azure.authenticator/ho040S3ffZkmxqtQrSwpTVOn9r0%3D"):
            with self.subTest(redirect=redirect):
                with self.assertRaises(w.WpjError):
                    a.callback(callback(redirect=redirect), self.state, now=NOW + 1)
        for suffix in ("code=%FF&state=" + STATE, "code=%GG&state=" + STATE,
                       "code=ok&state=" + STATE + "#fragment", "code=ok&state=" + STATE + "&incomplete"):
            raw = w.encode({"v": 1, "experiment": "WPJ-A01", "callback_url": a.REDIRECT + "?" + suffix})
            with self.assertRaises(w.WpjError):
                a.callback(raw, self.state, now=NOW + 1)

    def test_management_stop_receipt_is_terminal_without_callback(self):
        value = receipt("device_management_prompt_stopped")
        self.assertEqual(a.receipt(w.encode(value)), value)
        self.assertFalse(value["callback_saved"])
        for key in ("callback_saved", "callback_candidate_saved"):
            with self.assertRaises((w.WpjError, n.BootstrapError)):
                a.receipt(w.encode(value | {key: True}))

    def test_receipt_consistency_and_experiment_fail_closed(self):
        self.assertEqual(a.receipt(w.encode(receipt())), receipt())
        for change in ({"experiment": "NGC-B01"}, {"terminal": False}, {"session_started": False},
                       {"callback_candidate_saved": False}, {"system_error_domain": "other"},
                       {"raw_error": "DO_NOT_RETAIN"}, {"v": True}):
            with self.subTest(fields=tuple(change)):
                with self.assertRaises((w.WpjError, n.BootstrapError)):
                    a.receipt(w.encode(receipt() | change))
        candidate_only = receipt("callback_state_mismatch") | {"callback_received": True, "callback_candidate_saved": True}
        self.assertFalse(a.receipt(w.encode(candidate_only))["callback_saved"])

    @unittest.skipUnless(BINARY.is_file(), "Build isolated WorkplaceJoinBootstrap before executable integration check")
    def test_python_manifest_accepted_by_compiled_native_without_side_effects(self):
        with tempfile.TemporaryDirectory(prefix="wpj-auth-manifest-synthetic-") as location:
            directory = Path(location).resolve()
            os.chmod(directory, 0o700)
            path = directory / "auth-input.json"
            native, _ = prepared(int(time.time()))
            path.write_bytes(w.encode(native)); os.chmod(path, 0o600)
            result = subprocess.run(["rtk", "proxy", str(BINARY), "--validate-input", str(path)],
                capture_output=True, timeout=10, check=False)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout), {"experiment": "WPJ-A01", "native_status": "input_validated"})
            self.assertFalse(result.stderr)
            self.assertEqual(list(directory.iterdir()), [path])


class TokenVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)

    def key(self, signer=None, **changes):
        numbers = (signer or self.signer).public_key().public_numbers()
        def integer(value):
            return w.b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))
        return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "synthetic-key", "n": integer(numbers.n), "e": integer(numbers.e)} | changes

    def metadata(self, **changes):
        return {"issuer": ISSUER, "jwks_uri": "https://login.microsoftonline.com/common/discovery/keys"} | changes

    def claims(self, **changes):
        return {"iss": ISSUER, "tid": TENANT, "oid": OBJECT, "aud": RESOURCE, "appid": a.CLIENT_ID, "exp": NOW + 3600,
            "nbf": NOW - 1, "iat": NOW - 1, "upn": IDENTITY["account"]} | changes

    def token(self, *, claims=None, header=None, signer=None):
        header = {"alg": "RS256", "kid": "synthetic-key"} if header is None else header
        claims = self.claims() if claims is None else claims
        encoded = (w.b64url(w.encode(header)) + "." + w.b64url(w.encode(claims))).encode()
        signature = (signer or self.signer).sign(encoded, padding.PKCS1v15(), hashes.SHA256())
        return encoded.decode() + "." + w.b64url(signature)

    def verify(self, token=None, *, metadata=None, keys=None, response=None):
        return a.verified_token(w.encode(response or {"token_type": "Bearer", "access_token": token or self.token()}),
            w.encode(metadata or self.metadata()), w.encode({"keys": [self.key()] if keys is None else keys}),
            IDENTITY, RESOURCE, now=NOW)

    def test_valid_signature_identity_audience_lifetime_and_tenant_template(self):
        token = self.token()
        self.assertEqual(self.verify(token), token)
        self.assertEqual(self.verify(token, keys=[self.key(issuer="https://sts.windows.net/{tenantid}/")]), token)

    def test_client_claim_required_and_every_present_claim_must_match(self):
        claims = self.claims()
        del claims["appid"]
        with self.assertRaisesRegex(w.WpjError, "^token_client_mismatch$"):
            self.verify(self.token(claims=claims))
        for value in (claims | {"azp": a.CLIENT_ID}, self.claims(azp=a.CLIENT_ID)):
            token = self.token(claims=value)
            self.assertEqual(self.verify(token), token)
        for value in (self.claims(azp="other-client"), self.claims(appid="other-client", azp=a.CLIENT_ID),
                      self.claims(appid=[a.CLIENT_ID]), self.claims(azp=None)):
            with self.assertRaisesRegex(w.WpjError, "^token_client_mismatch$"):
                self.verify(self.token(claims=value))

    def test_wrong_signature_and_tampered_claims_rejected(self):
        with self.assertRaisesRegex(w.WpjError, "^invalid_token_signature$"):
            self.verify(self.token(signer=self.other))
        parts = self.token().split(".")
        parts[1] = w.b64url(w.encode(self.claims(oid=TENANT)))
        with self.assertRaisesRegex(w.WpjError, "^invalid_token_signature$"):
            self.verify(".".join(parts))

    def test_signed_wrong_issuer_tenant_object_audience_and_account_rejected(self):
        for change in ({"iss": "https://untrusted.invalid/"}, {"tid": OBJECT}, {"oid": TENANT},
                       {"aud": "https://graph.microsoft.com"}, {"aud": [RESOURCE]},
                       {"upn": "other@example.test"}, {"preferred_username": "other@example.test"},
                       {"appid": None}, {"appid": "4813382a-8fa7-425e-ab75-3b753aab3abb"}, {"azp": "other-client"}):
            with self.subTest(fields=tuple(change)):
                with self.assertRaises(w.WpjError):
                    self.verify(self.token(claims=self.claims(**change)))
        self.assertEqual(self.verify(self.token(claims=self.claims(upn=IDENTITY["account"].upper()))).count("."), 2)

    def test_expired_unbounded_not_yet_valid_and_old_tokens_rejected(self):
        for change in ({"exp": NOW}, {"exp": NOW + 30}, {"exp": NOW + 86401}, {"exp": True},
                       {"nbf": NOW + 31}, {"iat": NOW - 601}, {"iat": NOW + 31}, {"iat": None}):
            with self.subTest(fields=tuple(change)):
                with self.assertRaises(w.WpjError):
                    self.verify(self.token(claims=self.claims(**change)))

    def test_ambiguous_missing_or_wrong_purpose_jwks_rejected(self):
        for keys in ([], [self.key(), self.key()], [self.key(kid="different-key")],
                     [self.key(use="enc")], [self.key(alg="HS256")], [self.key(kty="EC")],
                     [self.key(issuer="https://sts.windows.net/" + OBJECT + "/")]):
            with self.subTest(key_count=len(keys)):
                with self.assertRaises(w.WpjError):
                    self.verify(keys=keys)
        with self.assertRaises(w.WpjError):
            self.verify(self.token(signer=self.weak), keys=[self.key(self.weak)])

    def test_algorithm_and_untrusted_key_selection_headers_rejected(self):
        for header in ({"alg": "none", "kid": "synthetic-key"}, {"alg": "HS256", "kid": "synthetic-key"},
                       {"alg": "RS256", "kid": "synthetic-key", "jku": "https://untrusted.invalid/keys"},
                       {"alg": "RS256", "kid": "synthetic-key", "x5u": "https://untrusted.invalid/cert"},
                       {"alg": "RS256", "kid": "synthetic-key", "jwk": self.key()},
                       {"alg": "RS256", "kid": "synthetic-key", "crit": []}):
            with self.assertRaises(w.WpjError):
                self.verify(self.token(header=header))

    def test_jwks_modulus_exponent_and_key_count_are_bounded(self):
        for update in ({"n": w.b64url(b"\xff" * 255)}, {"n": w.b64url(b"\xff" * 1025)},
                       {"e": w.b64url(b"\xff" * 9)}, {"e": "AA=="}):
            with self.subTest(fields=tuple(update)):
                with self.assertRaises(w.WpjError):
                    self.verify(keys=[self.key(**update)])
        with self.assertRaisesRegex(w.WpjError, "^invalid_issuer_keys$"):
            self.verify(keys=[self.key(kid=str(index)) for index in range(65)])

    def test_issuer_metadata_and_jwks_destinations_pinned(self):
        for metadata in (self.metadata(issuer="https://sts.windows.net/" + OBJECT + "/"),
                         self.metadata(jwks_uri="https://untrusted.invalid/keys"),
                         self.metadata(jwks_uri="https://login.microsoftonline.com/common/discovery/keys?redirect=evil"),
                         self.metadata(jwks_uri="https://login.microsoftonline.com:443/common/discovery/keys"),
                         self.metadata(jwks_uri="https://login.microsoftonline.com/" + OBJECT + "/discovery/keys")):
            with self.assertRaises(w.WpjError):
                self.verify(metadata=metadata)

    def test_extra_metadata_inert_opaque_and_wrong_token_type_rejected(self):
        token = self.token()
        self.assertEqual(self.verify(token, metadata=self.metadata(token_endpoint="https://untrusted.invalid/token")), token)
        for response in ({"token_type": "MAC", "access_token": token}, {"token_type": None, "access_token": token},
                         {"token_type": 1, "access_token": token}, {"token_type": ["Bearer"], "access_token": token},
                         {"token_type": "Bearer", "access_token": "opaque"}, {"token_type": "Bearer", "access_token": "a.b.c.d.e"}):
            with self.assertRaises(w.WpjError):
                self.verify(response=response)


if __name__ == "__main__":
    unittest.main()
