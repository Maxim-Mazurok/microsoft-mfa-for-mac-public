"""Offline Entra phone-sign-in codecs. Never sends, registers or signs a request.

RemoteNGC is distinct from classic MFA. A classic OATH/FCM bundle cannot become
an NGC signing credential through parsing or a browser-selector change.
See product/service/README.md for publication limits and open live gates.
"""
from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import math
import re
import time
from urllib.parse import urlencode, urlsplit, urlunsplit
import uuid


class NgcError(ValueError):
    """Fixed error code only; never include provider input in an exception."""


def require(ok, code):
    if not ok: raise NgcError(code)


def scalar(value, limit=16384, empty=False):
    require(isinstance(value, str) and len(value) <= limit and (bool(value) or empty)
            and all(32 <= ord(c) != 127 for c in value), "invalid_ngc_scalar")
    return value


def opaque_session(value):
    value = scalar(value)
    require(value.isascii() and not any(c.isspace() for c in value), "invalid_ngc_session")
    return value  # Deliberately no UUID conversion, base64 decoding or case folding.


def remote_session_hash(value):
    return hashlib.sha256(("remote_ngc\0" + opaque_session(value)).encode("utf-8")).hexdigest()


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def guid_bytes(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value), "invalid_ngc_account_id")
    try: return uuid.UUID(value).bytes_le
    except ValueError: raise NgcError("invalid_ngc_account_id") from None


def object_id_hash(object_id):
    return b64url(hashlib.sha256(guid_bytes(object_id)).digest())


def user_handle(tenant_id, object_id):
    # C# Guid byte order is little endian for the first 4/2/2-byte fields.
    return b"ON:" + guid_bytes(tenant_id) + hashlib.sha256(guid_bytes(object_id)).digest()


def unix_seconds(value):
    require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{8,11}", value), "invalid_ngc_timestamp")
    return int(value)


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, "duplicate_ngc_json_field")
        obj[key] = value
    return obj


def parse_json(raw, limit=262144):
    require(isinstance(raw, (str, bytes)) and len(raw) <= limit, "invalid_ngc_json")
    try:
        result = json.loads(raw, object_pairs_hook=_unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(NgcError("invalid_ngc_json")))
    except (ValueError, TypeError): raise NgcError("invalid_ngc_json") from None
    require(isinstance(result, dict), "invalid_ngc_json")
    return result


@dataclass(frozen=True, repr=False)
class NgcSession:
    session_id: str
    account: str
    tenant_id: str
    object_id_hash: str
    request_time: int
    expiration_time: int
    challenges: tuple[str, str, str]
    fido_challenge: str
    user_credential_policy: str
    context: dict
    phone_app_details: str

    @property
    def session_hash(self): return remote_session_hash(self.session_id)


def parse_notification(props, *, account, tenant_id, object_id, now=None):
    """Call only after MCS sender/package validation. Return private session data."""
    require(isinstance(props, dict) and len(props) <= 100, "invalid_ngc_notification")
    require(props.get("source") in ("SAS", "MFA Server"), "invalid_ngc_source")
    require(isinstance(props.get("sessiontype"), str) and props["sessiontype"].lower() == "ngc", "unsupported_ngc_session_type")
    # Dispatch may use type=NGC, or fall back to sessiontype=NGC when type is not
    # a recognized abstract notification enum. It is not classic type=auth.
    account = scalar(account, 320)
    require(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", account), "invalid_ngc_account")
    expected_hash = object_id_hash(object_id)
    actual_hash = scalar(props.get("userobjectidhash"), 128)
    require(hmac.compare_digest(actual_hash, expected_hash), "ngc_account_mismatch")
    guid_bytes(tenant_id)
    supplied_tenant = props.get("tenantid", "")
    require(not supplied_tenant or (guid_bytes(supplied_tenant) == guid_bytes(tenant_id)), "ngc_tenant_mismatch")
    request_time, expires = unix_seconds(props.get("requesttime")), unix_seconds(props.get("expirationtime"))
    now = time.time() if now is None else now
    require(type(now) in (int, float) and math.isfinite(now), "invalid_ngc_clock")
    require(request_time <= now + 3 and request_time < expires and now < expires and now - request_time <= 120,
            "ngc_request_expired_or_not_fresh")
    keys = [key for key in props if isinstance(key, str) and key.lower() == "authdetails"]
    require(len(keys) <= 1, "ambiguous_ngc_context")
    context = parse_json(props[keys[0]], 16384) if keys and props[keys[0]] else {}
    # Only safe local-display fields survive. Provider request/session data do not.
    shown = {}
    for key in ("ApplicationDisplayName", "CallerApplicationDisplayName"):
        if context.get(key): shown[key] = scalar(context[key], 1024)
    if "Latitude" in context or "Longitude" in context:
        for key, bound in (("Latitude", 90), ("Longitude", 180)):
            value = context.get(key)
            require(type(value) in (int, float) and math.isfinite(value) and -bound <= value <= bound, "invalid_ngc_location")
            shown[key] = value
    return NgcSession(opaque_session(props.get("sessionid")), account, tenant_id, actual_hash, request_time, expires,
        tuple(scalar(props.get(k), 128) for k in ("firstentropychallenge", "secondentropychallenge", "thirdentropychallenge")),
        scalar(props.get("fidochallenge", ""), empty=True), scalar(props.get("usercredentialpolicy", ""), 32768, empty=True),
        shown, scalar(props.get("phoneappdetails", ""), 32768, empty=True))


def capability(bundle):
    """Shape diagnosis only. Never treats possession of FCM/OATH as NGC enrollment."""
    ngc = bundle.get("ngc") if isinstance(bundle, dict) else None
    if not isinstance(ngc, dict): return "passwordless_registration_required"
    if ngc.get("key_type") not in ("ec", "rsa"): return "passwordless_key_type_unsupported"
    required = ("server_key_id", "device_id", "private_key_reference", "authority", "object_id", "tenant_id")
    if any(not isinstance(ngc.get(k), str) or not ngc[k] for k in required): return "passwordless_credential_incomplete"
    return "passwordless_credential_requires_validation"  # Never evidence of issuer acceptance.


@dataclass(frozen=True, repr=False)
class OfflineRequest:
    method: str
    url: str
    headers: dict
    body: bytes
    network_permitted: bool = False


def endpoint(token_endpoint, operation):
    require(operation in ("nonce", "listSessions", "approvesession"), "unsupported_ngc_operation")
    value = scalar(token_endpoint, 4096)
    parts = urlsplit(value)
    require(parts.scheme == "https" and parts.hostname in ("login.microsoftonline.com", "login.microsoft.com", "login.windows.net")
            and parts.netloc == parts.hostname and not parts.query and not parts.fragment
            and re.fullmatch(r"/[A-Za-z0-9.-]+/oauth2/(?:v2\.0/)?token", parts.path), "invalid_ngc_destination")
    path = parts.path if operation == "nonce" else parts.path.rsplit("/", 1)[0] + "/" + operation
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def form_request(token_endpoint, operation, fields, *, bearer=None):
    headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
               "client-request-id": str(uuid.uuid4()), "return-client-request-id": "true"}
    if bearer is not None: headers["Authorization"] = "Bearer " + scalar(bearer)
    return OfflineRequest("POST", endpoint(token_endpoint, operation), headers, urlencode(fields).encode())


def nonce_request(token_endpoint): return form_request(token_endpoint, "nonce", {"grant_type": "srv_challenge"})


def list_sessions_request(token_endpoint, bearer): return form_request(token_endpoint, "listSessions", {}, bearer=bearer)


@dataclass(frozen=True, repr=False)
class CredentialCreationOptions:
    challenge: str
    rp_id: str
    rp_name: str


def credential_creation_options(raw):
    """Parse production RP/challenge only; caller must preserve issuer provenance."""
    obj = parse_json(raw)
    options = obj.get("credentialCreationOptions")
    require(isinstance(options, dict) and isinstance(options.get("publicKey"), dict), "invalid_ngc_credential_options")
    public = options["publicKey"]; rp = public.get("rp")
    require(isinstance(rp, dict) and rp.get("id") == "login.microsoft.com", "unsupported_ngc_relying_party")
    algorithms = public.get("pubKeyCredParams")
    require(isinstance(algorithms, list) and any(isinstance(a, dict) and a.get("type") == "public-key"
            and type(a.get("alg")) is int and a["alg"] == -7 for a in algorithms), "ngc_es256_not_offered")
    challenge = scalar(public.get("challenge"))
    require(re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", challenge), "invalid_ngc_creation_challenge")
    return CredentialCreationOptions(challenge, rp["id"], scalar(rp.get("name"), 1024))


def registration_client_data(options):
    require(type(options) is CredentialCreationOptions and options.rp_id == "login.microsoft.com", "invalid_ngc_credential_options")
    # Creation uses the server's already encoded challenge unchanged; assertion
    # uses UTF-8 bytes of fidochallenge, then base64url (different traced paths).
    return json.dumps({"type": "webauthn.create", "challenge": options.challenge,
                       "origin": "https://login.microsoft.com"}, separators=(",", ":")).encode()


def registration_payload(options, *, local_key_id, client_data_json, attestation_object):
    """Serialize supplied genuine key proof; does not generate/fake attestation.

    A caller must separately implement the exact PSI CBOR/signature and verify it
    offline before any enrollment. This schema does not establish proof validity.
    """
    guid_bytes(local_key_id)
    require(isinstance(client_data_json, bytes) and isinstance(attestation_object, bytes)
            and 0 < len(attestation_object) <= 65536, "ngc_attestation_required")
    require(parse_json(client_data_json) == parse_json(registration_client_data(options)), "ngc_creation_binding_mismatch")
    payload = {"publicKeyCredential": {"id": local_key_id,
                "response": {"clientDataJSON": b64url(client_data_json), "attestationObject": b64url(attestation_object)}},
               "credentialDisplayName": None, "attributes": {"supports_notification": "true"}}
    return json.dumps(payload, separators=(",", ":")).encode()


def approval_response(raw):
    obj = parse_json(raw)
    require(type(obj.get("success")) is bool, "invalid_ngc_approval_response")
    return obj["success"]


def fido_client_data(session, *, device_id, app_state):
    """Unsigned bytes to be hashed and signed by a separately registered EC key.

    app_state must describe real policy UI/verification. This function does not
    set UV/UP flags, fabricate verification, select a key or sign anything.
    """
    require(type(session) is NgcSession and bool(session.fido_challenge), "ngc_fido_challenge_required")
    guid_bytes(device_id)
    payload = {"type": "webauthn.get", "challenge": b64url(session.fido_challenge.encode("utf-8")),
               "origin": "https://login.microsoft.com", "apc": scalar(app_state, 32768), "deviceId": device_id}
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()


def unsigned_rsa_assertion(*, key_id, account, nonce, device_id, app_state, now):
    """Legacy RS256 signing input only; there is no live RSA registration executor."""
    guid_bytes(device_id)
    require(type(now) is int and now > 0, "invalid_ngc_clock")
    header = {"typ": "JWT", "alg": "RS256", "kid": scalar(key_id), "use": "ngc"}
    claims = {"iat": now, "exp": now + 300, "iss": scalar(account, 320), "aud": "", "scope": "openid aza",
              "request_nonce": scalar(nonce), "deviceid": device_id, "app_state": scalar(app_state, 32768)}
    return (b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
            b64url(json.dumps(claims, separators=(",", ":")).encode())).encode()


def approval_request(token_endpoint, session, *, object_id, number, signed_assertion, key_type, now):
    require(type(session) is NgcSession and type(now) in (int, float) and math.isfinite(now)
            and session.request_time <= now + 3 and now < session.expiration_time, "ngc_request_expired_or_not_fresh")
    require(object_id_hash(object_id) == session.object_id_hash, "ngc_account_mismatch")
    require(isinstance(number, str) and re.fullmatch(r"[0-9]{1,2}", number), "invalid_ngc_number")
    require(key_type in ("ec", "rsa"), "unsupported_ngc_key_type")
    require(key_type != "ec" or bool(session.fido_challenge), "ngc_fido_challenge_required")
    # The assertion is an opaque *already signed* value from a real registered
    # credential. Shape validation does not establish the signature's validity.
    fields = {"userobjectid": object_id, "sessionid": session.session_id, "sessionstate": "approve", "sessiontype": "ngc",
              "fidoassertion" if key_type == "ec" else "assertion": scalar(signed_assertion, 65536),
              "entropy": str(int(number)), "oathcounter": str(int(now) // 30)}
    return form_request(token_endpoint, "approvesession", fields)
