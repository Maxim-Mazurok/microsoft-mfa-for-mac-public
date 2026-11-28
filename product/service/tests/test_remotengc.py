"""RemoteNGC fixtures are invented; no archive, credentials or requests are used."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import remotengc as n

OBJECT = "00112233-4455-6677-8899-aabbccddeeff"
TENANT = "ffeeddcc-bbaa-9988-7766-554433221100"
DEVICE = "12345678-1234-5678-9abc-0123456789ab"
NOW = 1800000000
ENDPOINT = "https://login.microsoftonline.com/common/oauth2/token"


def notification():
    return {"source": "SAS", "sessiontype": "NGC", "type": "NGC", "userobjectidhash": n.object_id_hash(OBJECT),
            "sessionid": "opaque-SyntheticIdentifier_" + "A" * 650, "requesttime": str(NOW - 1), "expirationtime": str(NOW + 90),
            "firstentropychallenge": "10", "secondentropychallenge": "20", "thirdentropychallenge": "30",
            "tenantid": TENANT, "fidochallenge": "synthetic-fido-challenge", "authDetails": json.dumps({"ApplicationDisplayName": "Synthetic app"})}


def parsed(props=None):
    return n.parse_notification(props or notification(), account="demo@example.test", tenant_id=TENANT, object_id=OBJECT, now=NOW)


class Notification(unittest.TestCase):
    def test_opaque_session_preserved_and_correlates_only_by_domain_separated_hash(self):
        props = notification(); session = parsed(props)
        self.assertEqual(session.session_id, props["sessionid"])
        self.assertEqual(session.session_hash, hashlib.sha256(("remote_ngc\0" + props["sessionid"]).encode()).hexdigest())
        self.assertNotEqual(session.session_hash, n.remote_session_hash(props["sessionid"].lower()))
        self.assertNotEqual(session.session_hash, hashlib.sha256(props["sessionid"].encode()).hexdigest())
        self.assertNotIn(props["sessionid"], repr(session))

    def test_guid_endianness_and_user_handle_are_exact(self):
        self.assertEqual(n.guid_bytes(OBJECT).hex(), "33221100554477668899aabbccddeeff")
        expected = base64.urlsafe_b64encode(hashlib.sha256(bytes.fromhex("33221100554477668899aabbccddeeff")).digest()).rstrip(b"=").decode()
        self.assertEqual(n.object_id_hash(OBJECT), expected)
        handle = n.user_handle(TENANT, OBJECT)
        self.assertEqual(handle[:3], b"ON:"); self.assertEqual(len(handle), 51)
        self.assertEqual(handle[3:19], n.guid_bytes(TENANT))

    def test_wrong_account_tenant_source_type_and_expiration_rejected(self):
        for change in ({"userobjectidhash": "other"}, {"tenantid": DEVICE}, {"source": "MSA"}, {"sessiontype": "auth"},
                       {"expirationtime": str(NOW)}, {"requesttime": str(NOW + 60)}, {"requesttime": str(NOW - 500)},
                       {"sessionid": "A" * 16385}, {"firstentropychallenge": ""}):
            with self.subTest(change=list(change)):
                with self.assertRaises(n.NgcError): parsed({**notification(), **change})

    def test_case_insensitive_context_key_with_ambiguous_duplicates_rejected(self):
        props = notification(); props["AUTHDETAILS"] = props.pop("authDetails")
        self.assertEqual(parsed(props).context["ApplicationDisplayName"], "Synthetic app")
        props["authdetails"] = "{}"
        with self.assertRaises(n.NgcError): parsed(props)

    def test_optional_fido_challenge_missing_is_parseable_but_ec_approval_blocked(self):
        session = parsed({**notification(), "fidochallenge": ""})
        with self.assertRaises(n.NgcError): n.fido_client_data(session, device_id=DEVICE, app_state="synthetic")

    def test_classic_bundle_does_not_establish_ngc_capability(self):
        self.assertEqual(n.capability({"provider": {"token": "synthetic"}, "account": {"secret": "synthetic"}}), "passwordless_registration_required")
        self.assertEqual(n.capability({"ngc": {"key_type": "ec"}}), "passwordless_credential_incomplete")


class OfflineProtocol(unittest.TestCase):
    def test_registration_schema_preserves_server_creation_challenge(self):
        raw = json.dumps({"credentialCreationOptions": {"publicKey": {"rp": {"id": "login.microsoft.com", "name": "Microsoft"},
            "challenge": "c3ludGhldGljLWNoYWxsZW5nZQ", "pubKeyCredParams": [{"type": "public-key", "alg": -7}]}}})
        options = n.credential_creation_options(raw)
        client = n.registration_client_data(options)
        self.assertEqual(json.loads(client)["challenge"], "c3ludGhldGljLWNoYWxsZW5nZQ")
        data = json.loads(n.registration_payload(options, local_key_id=DEVICE, client_data_json=client,
                                                 attestation_object=b"synthetic-cbor-placeholder-never-sent"))
        self.assertEqual(data["attributes"], {"supports_notification": "true"})
        self.assertIsNone(data["credentialDisplayName"])
        self.assertEqual(data["publicKeyCredential"]["id"], DEVICE)
        with self.assertRaises(n.NgcError): n.credential_creation_options(raw.replace("login.microsoft.com", "example.com"))
        with self.assertRaises(n.NgcError): n.credential_creation_options(raw.replace('"alg": -7', '"alg": -257'))
        with self.assertRaises(n.NgcError):
            n.registration_payload(options, local_key_id=DEVICE, client_data_json=client.replace(b"webauthn.create", b"webauthn.get"), attestation_object=b"synthetic")

    def test_endpoints_and_nonce_schema(self):
        req = n.nonce_request(ENDPOINT)
        self.assertFalse(req.network_permitted)
        self.assertEqual(req.url, ENDPOINT)
        self.assertEqual(parse_qs(req.body.decode()), {"grant_type": ["srv_challenge"]})
        self.assertEqual(n.endpoint(ENDPOINT, "approvesession"), "https://login.microsoftonline.com/common/oauth2/approvesession")
        req = n.list_sessions_request(ENDPOINT, "synthetic-token")
        self.assertEqual(req.headers["Authorization"], "Bearer synthetic-token")
        self.assertNotIn("synthetic-token", repr(req))

    def test_unobserved_destinations_queries_ports_and_redirect_inputs_rejected(self):
        for url in ("https://example.com/common/oauth2/token", ENDPOINT + "?token=secret", ENDPOINT + "#x",
                    ENDPOINT.replace("https", "http"), ENDPOINT.replace(".com/", ".com:443/"),
                    ENDPOINT.replace("common", "../common"), ENDPOINT.replace("common", "common%2Fother")):
            with self.assertRaises(n.NgcError): n.nonce_request(url)

    def test_ec_client_data_challenge_is_encoded_text_not_decoded_blob(self):
        session = parsed()
        data = json.loads(n.fido_client_data(session, device_id=DEVICE, app_state="synthetic-state"))
        self.assertEqual(data, {"type": "webauthn.get", "challenge": n.b64url(b"synthetic-fido-challenge"),
                               "origin": "https://login.microsoft.com", "apc": "synthetic-state", "deviceId": DEVICE})

    def test_rsa_input_is_unsigned_and_nonce_bound(self):
        raw = n.unsigned_rsa_assertion(key_id="synthetic-key", account="demo@example.test", nonce="synthetic-nonce",
                                       device_id=DEVICE, app_state="synthetic-state", now=NOW)
        parts = raw.split(b"."); self.assertEqual(len(parts), 2)
        decode = lambda value: json.loads(base64.urlsafe_b64decode(value + b"=" * (-len(value) % 4)))
        self.assertEqual(decode(parts[0]), {"typ": "JWT", "alg": "RS256", "kid": "synthetic-key", "use": "ngc"})
        claims = decode(parts[1]); self.assertEqual(claims["request_nonce"], "synthetic-nonce")
        self.assertEqual(claims["exp"] - claims["iat"], 300)

    def test_ec_and_rsa_approval_are_distinct_from_classic_xml(self):
        for key_type, field in (("ec", "fidoassertion"), ("rsa", "assertion")):
            request = n.approval_request(ENDPOINT, parsed(), object_id=OBJECT, number="42",
                                         signed_assertion="synthetic-signed-value", key_type=key_type, now=NOW)
            fields = parse_qs(request.body.decode())
            self.assertEqual(fields["sessionstate"], ["approve"]); self.assertEqual(fields["sessiontype"], ["ngc"])
            self.assertEqual(fields[field], ["synthetic-signed-value"])
            self.assertEqual(fields["oathcounter"], [str(NOW // 30)])
            self.assertNotIn("deviceToken", fields); self.assertNotIn("oathCode", fields)
            self.assertFalse(request.network_permitted)

    def test_success_response_requires_real_boolean_and_unique_fields(self):
        self.assertTrue(n.approval_response('{"success":true}'))
        self.assertFalse(n.approval_response('{"success":false}'))
        for raw in ('{"success":"true"}', '{"success":1}', '{"success":true,"success":false}', '{"success":NaN}'):
            with self.assertRaises(n.NgcError): n.approval_response(raw)


if __name__ == "__main__": unittest.main()
