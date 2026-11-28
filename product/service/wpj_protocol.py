"""Registration-only Workplace Join primitives. No network, management or UI.

Historical wire evidence is not distributed with this source snapshot. A parsed
certificate is not issuer proof by itself: authenticated registration provenance
is required separately. Values in these objects must never be logged.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from urllib.parse import parse_qsl, urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier

import ngc_bootstrap as bootstrap

DRS = "enterpriseregistration.windows.net"
DEVICE_OID = ObjectIdentifier("1.2.840.113556.1.5.284.2")
TENANT_OID = ObjectIdentifier("1.2.840.113556.1.5.284.5")
MAX_BYTES = 262144


class WpjError(ValueError):
    """Fixed codes only. No untrusted response text or credential values."""


def require(ok, code):
    if not ok:
        raise WpjError(code)


def canonical_uuid(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value), "invalid_identifier")
    require(uuid.UUID(value).int != 0, "invalid_identifier")
    return value


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def parse_json(raw, maximum=MAX_BYTES):
    require(isinstance(raw, bytes) and 0 < len(raw) <= maximum, "invalid_json")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_field")
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(WpjError("invalid_json")))
    except (ValueError, UnicodeError, RecursionError):
        raise WpjError("invalid_json") from None
    require(isinstance(result, dict), "invalid_json")
    return result


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def unb64(value, maximum=65536):
    require(isinstance(value, str) and 0 < len(value) <= maximum * 2, "invalid_base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError):
        raise WpjError("invalid_base64") from None
    require(len(raw) <= maximum and b64(raw) == value, "invalid_base64")
    return raw


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_key(spki):
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, TypeError):
        raise WpjError("invalid_public_key") from None
    require(isinstance(key, rsa.RSAPublicKey) and key.key_size == 2048 and key.public_numbers().e == 65537, "unsupported_public_key")
    require(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == spki, "noncanonical_public_key")
    return key


def der(tag, content):
    require(len(content) <= MAX_BYTES, "der_too_large")
    length = len(content)
    size = bytes([length]) if length < 128 else bytes([0x80 + (length.bit_length() + 7) // 8]) + length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag]) + size + content


def make_csr(spki, sign):
    """Exact Android user-WPJ CSR shape, signed through an injected key handle.

    CN=AGREEYA is the traced SDK placeholder, not a device claim. Key usage and
    clientAuth are direct CSR attributes, not an invented attestation request.
    """
    key = public_key(spki)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AGREEYA")]).public_bytes()
    usage = der(0x30, bytes.fromhex("0603551d0f") + der(0x31, bytes.fromhex("030203b8")))
    eku = der(0x30, bytes.fromhex("0603551d25") + der(0x31, bytes.fromhex("300a06082b06010505070302")))
    request_info = der(0x30, b"\x02\x01\x00" + subject + spki + der(0xa0, b"".join(sorted((usage, eku)))))
    signature = sign(request_info)
    try:
        key.verify(signature, request_info, padding.PKCS1v15(), hashes.SHA256())
    except (ValueError, InvalidSignature):
        raise WpjError("csr_signature_mismatch") from None
    result = der(0x30, request_info + bytes.fromhex("300d06092a864886f70d01010b0500") + der(3, b"\x00" + signature))
    try:
        csr = x509.load_der_x509_csr(result)
        require(csr.is_signature_valid, "invalid_csr_signature")
    except ValueError:
        raise WpjError("invalid_csr") from None
    return result


def encoded_transport_key(spki, key_id):
    """Android API2 STK: Base64(JSON), standard Base64 n/e (not RFC7517)."""
    numbers = public_key(spki).public_numbers()
    canonical_uuid(key_id)
    return b64(encode({"kty": "RSA", "n": b64(numbers.n.to_bytes(256, "big")), "e": b64(b"\x01\x00\x01"), "alg": "RS256", "kid": key_id}))


@dataclass(frozen=True, repr=False)
class Discovery:
    tenant_id: str
    registration_resource: str
    join_resource: str
    join_endpoint: str
    authorize_endpoint: str
    token_endpoint: str
    version: str = "2.0"


def discovery(raw, expected_tenant):
    canonical_uuid(expected_tenant)
    value = parse_json(raw)
    try:
        require(value["TenantInfo"]["TenantId"].lower() == expected_tenant, "discovery_tenant_mismatch")
        join = value["DeviceJoinService"]
        require(join["ServiceVersion"] == "2.0", "unsupported_join_version")
        require(join["JoinEndpoint"] in (f"https://{DRS}/EnrollmentServer/device", f"https://{DRS}/EnrollmentServer/device/"), "unsupported_join_endpoint")
        registration_resource = value["DeviceRegistrationService"]["RegistrationResourceId"]
        require(registration_resource in bootstrap.RESOURCES and join["JoinResourceId"] in bootstrap.RESOURCES, "unsupported_registration_resource")
        oauth = value["AuthenticationService"]["OAuth2"]
        auth = bootstrap.oauth_endpoint(oauth["AuthCodeEndpoint"], "authorize", expected_tenant)
        token = bootstrap.oauth_endpoint(oauth["TokenEndpoint"], "token", expected_tenant)
        require(auth.rsplit("/", 1)[0] == token.rsplit("/", 1)[0], "discovery_endpoint_mismatch")
        # DeviceManagementService and MDM discovery data are deliberately inert.
        return Discovery(expected_tenant, registration_resource, join["JoinResourceId"], join["JoinEndpoint"], auth, token)
    except (KeyError, TypeError, AttributeError, bootstrap.BootstrapError):
        raise WpjError("invalid_discovery") from None


def registration_request(metadata, csr_der, device_spki, transport_spki, transport_id, os_version, display_name):
    require(type(metadata) is Discovery and metadata.version == "2.0", "validated_discovery_required")
    canonical_uuid(metadata.tenant_id)
    require(metadata.join_endpoint in (f"https://{DRS}/EnrollmentServer/device", f"https://{DRS}/EnrollmentServer/device/"), "unsupported_join_endpoint")
    public_key(device_spki); public_key(transport_spki)
    require(device_spki != transport_spki, "distinct_device_transport_keys_required")
    require(isinstance(os_version, str) and re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){1,2}", os_version), "invalid_os_version")
    require(isinstance(display_name, str) and re.fullmatch(r"Mac MFA WPJ research W[0-9]{2}", display_name), "invalid_research_device_name")
    try:
        csr = x509.load_der_x509_csr(csr_der)
        require(csr.is_signature_valid and csr.signature_hash_algorithm.name == "sha256", "invalid_csr_signature")
        require(csr.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == device_spki, "csr_key_mismatch")
        # Accept only the serializer's deterministic request-info shape.
        expected = make_csr(device_spki, lambda _: csr.signature)
        require(expected == csr_der, "unexpected_csr_attributes")
    except ValueError:
        raise WpjError("invalid_csr") from None
    body = {"CertificateRequest": {"Type": "pkcs10", "Data": b64(csr_der)},
        "TransportKey": encoded_transport_key(transport_spki, transport_id),
        "TargetDomain": metadata.tenant_id, "DeviceType": "MacOS", "OSVersion": os_version,
        "DeviceDisplayName": display_name, "JoinType": 4, "Attributes": {}}
    return metadata.join_endpoint + "?api-version=2.0", encode(body)


@dataclass(frozen=True, repr=False)
class DeviceCertificate:
    certificate_der: bytes
    device_id: str
    tenant_id: str
    public_spki: bytes
    expires_at: int
    fingerprint: str
    certificate_tenant_id: str | None


def certificate_identity(raw, expected_spki, tenant_id, *, now=None):
    """Structural/key binding only; issuer names never establish provenance."""
    now = int(time.time()) if now is None else now
    canonical_uuid(tenant_id); public_key(expected_spki)
    require(isinstance(raw, bytes) and len(raw) <= 32768, "invalid_certificate")
    try:
        cert = x509.load_der_x509_certificate(raw)
        require(cert.public_bytes(serialization.Encoding.DER) == raw, "noncanonical_certificate")
        require(cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == expected_spki, "certificate_key_mismatch")
        require(cert.not_valid_before_utc.timestamp() <= now < cert.not_valid_after_utc.timestamp(), "certificate_not_current")
        require(cert.signature_hash_algorithm.name in ("sha256", "sha384", "sha512"), "weak_certificate_signature")
        require(any(item.value == "MS-Organization-Access" for item in cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)), "unexpected_certificate_issuer")
        require(cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature, "certificate_cannot_sign")
        require(ExtendedKeyUsageOID.CLIENT_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value, "certificate_not_client_auth")
        def identifier(oid):
            ext = cert.extensions.get_extension_for_oid(oid)
            require(not ext.critical and isinstance(ext.value, x509.UnrecognizedExtension), "invalid_device_certificate_extension")
            data = ext.value.value
            require(len(data) == 18 and data[:2] == b"\x04\x10", "invalid_device_certificate_extension")
            return canonical_uuid(str(uuid.UUID(bytes_le=data[2:])))
        device_id = identifier(DEVICE_OID)
        try: actual_tenant = identifier(TENANT_OID)
        except x509.ExtensionNotFound: actual_tenant = None
        require(actual_tenant is None or actual_tenant == tenant_id, "certificate_tenant_mismatch")
        # tenant_id is the expected authenticated operation context; an absent
        # certificate extension is never reported as a certificate tenant claim.
        return DeviceCertificate(raw, device_id, tenant_id, expected_spki, int(cert.not_valid_after_utc.timestamp()), cert.fingerprint(hashes.SHA256()).hex(), actual_tenant)
    except (ValueError, TypeError, x509.ExtensionNotFound, x509.DuplicateExtension):
        raise WpjError("invalid_certificate") from None


def registration_response(raw, expected_spki, tenant_id, account, *, now=None):
    value = parse_json(raw)
    try:
        item = value["Certificate"]
        require(isinstance(item, dict) and isinstance(item["RawBody"], str), "registration_certificate_missing")
        if "User" in value:
            require(isinstance(value["User"], dict), "invalid_registration_user")
            if value["User"].get("Upn"):
                require(value["User"]["Upn"].casefold() == account.casefold(), "registration_account_mismatch")
        require(len(item["RawBody"]) <= 65536, "invalid_certificate")
        # The SDK parses RawBody through PEM, where ASCII line wrapping is legal.
        # Remove only those whitespace characters, then enforce canonical Base64.
        encoded = re.sub(r"[ \t\r\n]", "", item["RawBody"])
        return certificate_identity(unb64(encoded, 32768), expected_spki, tenant_id, now=now)
    except (KeyError, TypeError, AttributeError):
        raise WpjError("invalid_registration_response") from None


def auth_url(value):
    require(isinstance(value, str) and 0 < len(value) <= 8192 and all(32 < ord(c) < 127 for c in value) and "\\" not in value, "invalid_proof_destination")
    try:
        parts = urlsplit(value)
    except ValueError:
        raise WpjError("invalid_proof_destination") from None
    require(parts.scheme == "https" and parts.hostname in bootstrap.AUTH_HOSTS and parts.netloc == parts.hostname and not parts.fragment, "invalid_proof_destination")
    require(re.fullmatch(r"/(?:common|organizations|[0-9a-f-]{36})/(?:DeviceAuthPKeyAuth|oauth2/(?:v2\.0/)?token)", parts.path) is not None, "unsupported_proof_path")
    require(re.search(r"%(?![0-9a-fA-F]{2})", value) is None, "invalid_proof_destination")
    return parts


@dataclass(frozen=True, repr=False)
class Challenge:
    nonce: str
    context: str
    submit_url: str
    tenant_id: str
    authorities: tuple
    thumbprint: str | None
    received_at: int
    binding: str


def challenge(value, *, origin, tenant_id, browser_session, now=None):
    """Parse an already TLS-delivered challenge, requiring same-origin proof.

    The browser adapter must bind origin/session to its own active navigation.
    This function cannot infer that trust from a pasted URL.
    """
    now = int(time.time()) if now is None else now
    require(type(now) is int and now > 0, "invalid_challenge_time")
    canonical_uuid(tenant_id); canonical_uuid(browser_session)
    require(isinstance(value, dict) and set(value) <= {"Nonce", "nonce", "Context", "Version", "SubmitUrl", "TenantId", "CertAuthorities", "CertThumbprint"}, "invalid_challenge")
    require(("Nonce" in value) != ("nonce" in value), "ambiguous_challenge_nonce")
    actual_tenant = value.get("TenantId", tenant_id)
    require(value.get("Version") == "1.0" and isinstance(actual_tenant, str) and actual_tenant.lower() == tenant_id, "challenge_tenant_or_version_mismatch")
    nonce, context = value.get("Nonce", value.get("nonce")), value.get("Context")
    for item in (nonce, context):
        require(isinstance(item, str) and 0 < len(item) <= 8192 and all(32 < ord(c) < 127 for c in item) and not any(c in item for c in ('"', '\\', '\r', '\n')), "invalid_challenge_scalar")
    submit = auth_url(value.get("SubmitUrl"))
    require(submit.path.split('/')[1] in (tenant_id, 'common', 'organizations'), "challenge_path_tenant_mismatch")
    try: source = urlsplit(origin)
    except (TypeError, ValueError): raise WpjError("invalid_challenge_origin") from None
    require(source.scheme == "https" and source.hostname in bootstrap.AUTH_HOSTS and source.netloc == source.hostname and submit.netloc == source.netloc, "challenge_origin_mismatch")
    authorities = value.get("CertAuthorities", "")
    require(isinstance(authorities, str) and len(authorities) <= 4096, "invalid_certificate_selector")
    authorities = tuple(authorities.split(";")) if authorities else ()
    require(len(authorities) <= 16, "invalid_certificate_selector")
    thumbprint = value.get("CertThumbprint")
    require(thumbprint is None or (isinstance(thumbprint, str) and re.fullmatch(r"[0-9a-fA-F]{40}", thumbprint)), "invalid_certificate_selector")
    require(authorities or thumbprint, "certificate_selector_required")
    binding = hashlib.sha256(encode({"session":browser_session,"origin":origin,"challenge":value})).hexdigest()
    return Challenge(nonce, context, value["SubmitUrl"], tenant_id, authorities, thumbprint, now, binding)


def pkeyauth_response(item, device, sign, *, now=None):
    """Produce real signed proof. Sending/replay/provenance are executor gates."""
    now = int(time.time()) if now is None else now
    require(type(item) is Challenge and type(device) is DeviceCertificate, "validated_challenge_and_certificate_required")
    require(type(now) is int and item.received_at <= now < item.received_at + 120, "challenge_expired")
    require(now < device.expires_at and item.tenant_id == device.tenant_id, "device_not_eligible")
    auth_url(item.submit_url)
    cert = x509.load_der_x509_certificate(device.certificate_der)
    issuer = cert.issuer.rfc4514_string()
    matched = issuer in item.authorities
    if item.thumbprint:
        matched = matched or hmac.compare_digest(cert.fingerprint(hashes.SHA1()).hex(), item.thumbprint.lower())
    require(matched, "certificate_selector_mismatch")
    header = {"alg": "RS256", "typ": "JWT", "x5c": [b64(device.certificate_der)]}
    claims = {"aud": item.submit_url, "iat": now, "nonce": item.nonce}
    payload = (b64url(encode(header)) + "." + b64url(encode(claims))).encode()
    signature = sign(payload)
    try: public_key(device.public_spki).verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError): raise WpjError("device_signature_mismatch") from None
    token = payload.decode() + "." + b64url(signature)
    return 'PKeyAuth AuthToken="' + token + '",Context="' + item.context + '",Version="1.0"'


class ProofBudget:
    """One durable proof claim. Failed/uncertain sends remain consumed."""
    def __init__(self, claim_once):
        self._claim_once, self._consumed = claim_once, False

    def claim(self, item):
        require(type(item) is Challenge and not self._consumed, "device_proof_already_attempted")
        self._claim_once(item.binding)
        self._consumed = True
