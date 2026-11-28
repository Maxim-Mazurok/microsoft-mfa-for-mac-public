"""Bounded, separate RemoteNGC OAuth compatibility probe; never enrolls a key.

Pure helpers are used by offline tests. Network CLI stages are explicit and
single-use: one DRS GET, then at most one authorization-code POST. Authentication
itself belongs to the isolated native ASWebAuthenticationSession helper. Secrets
are written only into new protected files; stdout contains fixed redacted data.
"""
from dataclasses import dataclass, asdict
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import ssl
import stat
import subprocess
import time
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit
import uuid

from remotengc import NgcError, parse_json, scalar, guid_bytes, b64url

CLIENT_ID = "4813382a-8fa7-425e-ab75-3b753aab3abb"
REDIRECT = "msauth://com.azure.authenticator/ho040S3ffZkmxqtQrSwpTVOn9r0%3D"
CALLBACK_PATH = "/ho040S3ffZkmxqtQrSwpTVOn9r0%3D"
DECODED_CALLBACK_PATH = "/ho040S3ffZkmxqtQrSwpTVOn9r0="
DRS_HOST = "enterpriseregistration.windows.net"
AUTH_HOSTS = frozenset(("login.microsoftonline.com", "login.windows.net", "login.microsoft.com"))
RESOURCES = frozenset(("urn:ms-drs:enterpriseregistration.windows.net", "https://enterpriseregistration.windows.net", "https://enterpriseregistration.windows.net/"))
CLAIMS = {"access_token": {"deviceid": {"essential": True},
    "amr": {"essential": True, "values": ["ngcmfa"]},
    "acrs": {"essential": True, "values": ["urn:user:registersecurityinfo"]}},
    "id_token": {"acrs": {"essential": True, "values": ["urn:user:registersecurityinfo"]}}}
EXTRAS = {"nux": "1", "msafed": "0", "instance_aware": "true", "is_remote_login_allowed": "true", "hsu": "1"}
MAX_BYTES = 262144
TIMEOUT = 30
LIFETIME = 600
OAUTH_ERRORS = frozenset(("access_denied", "invalid_request", "unauthorized_client", "invalid_client",
    "invalid_grant", "invalid_resource", "interaction_required", "login_required", "consent_required",
    "temporarily_unavailable", "server_error"))
CALLBACK_KEYS = frozenset(("code", "state", "session_state", "client_info", "cloud_instance_host_name",
    "cloud_instance_name", "cloud_graph_host_name", "error", "error_description", "error_uri", "suberror",
    "error_subcode", "correlation_id"))
NATIVE_NONTERMINAL = frozenset(("starting", "ready", "session_started", "callback_received"))
NATIVE_TERMINAL = frozenset(("callback_saved", "authorization_rejected", "input_expired", "session_start_failed",
    "authentication_cancelled", "authentication_session_failed", "authentication_presentation_context_missing",
    "authentication_presentation_context_invalid", "callback_missing", "cancelled", "window_closed", "callback_save_failed",
    "callback_capture_failed", "native_operation_failed", "invalid_input", "invalid_destination", "expired_input",
    "invalid_callback", "private_storage_unavailable", "session_already_attempted", "output_already_exists",
    "callback_too_large", "callback_destination_mismatch", "callback_path_mismatch", "callback_duplicate_parameter",
    "callback_state_mismatch", "callback_fields_unsupported", "callback_payload_invalid", "native_report_already_exists",
    "native_report_unavailable", "callback_before_session_start"))


class BootstrapError(ValueError):
    """Fixed diagnostic code, never a provider body, URL or secret."""


def require(ok, code):
    if not ok: raise BootstrapError(code)


def safe_json(raw):
    try: return parse_json(raw, MAX_BYTES)
    except NgcError: raise BootstrapError("invalid_bootstrap_json") from None


def identity(value):
    require(isinstance(value, dict) and set(value) == {"account", "tenant_id", "object_id"}, "invalid_bootstrap_identity")
    account = value["account"]
    require(isinstance(account, str) and len(account) <= 320 and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", account), "invalid_bootstrap_identity")
    try:
        guid_bytes(value["tenant_id"]); guid_bytes(value["object_id"])
    except NgcError: raise BootstrapError("invalid_bootstrap_identity") from None
    return dict(value)


def discovery_url(tenant_id):
    try: guid_bytes(tenant_id)
    except NgcError: raise BootstrapError("invalid_bootstrap_tenant") from None
    return "https://" + DRS_HOST + "/" + tenant_id + "/Discover?api-version=1.9&managed=True"


def oauth_endpoint(value, kind, tenant_id):
    require(kind in ("authorize", "token") and isinstance(value, str) and len(value) <= 4096, "invalid_bootstrap_endpoint")
    try: parts = urlsplit(value)
    except ValueError: raise BootstrapError("invalid_bootstrap_endpoint") from None
    # Validate the DRS metadata's v1 endpoint before applying the separately
    # traced MSAL v2 conversion. Never use a copied browser/federation URL.
    allowed_segments = (tenant_id.casefold(), "common", "organizations")
    require(parts.scheme == "https" and parts.hostname in AUTH_HOSTS and parts.netloc == parts.hostname
            and not parts.query and not parts.fragment, "invalid_bootstrap_endpoint")
    matched = re.fullmatch(r"/([^/]+)/oauth2/" + kind, parts.path)
    require(matched is not None and matched[1].casefold() in allowed_segments, "invalid_bootstrap_endpoint")
    return value


def msal_endpoint(value, kind, tenant_id):
    """MSAL fallback route on the validated authority, not a URL from a page."""
    oauth_endpoint(value, kind, tenant_id)
    return value.rsplit("/oauth2/", 1)[0] + "/oauth2/v2.0/" + kind


def msal_scopes(resource):
    require(resource in RESOURCES, "unsupported_key_provision_resource")
    # TokenParameters.Builder.withResource appends literally; a resource with
    # a trailing slash gets //.default. Scope order is immaterial to OAuth.
    return resource + "/.default openid profile offline_access"


@dataclass(frozen=True, repr=False)
class Discovery:
    tenant_id: str
    authorize_endpoint: str
    token_endpoint: str
    resource: str
    key_provision_endpoint: str


def parse_discovery(raw, expected_tenant):
    try: guid_bytes(expected_tenant)
    except NgcError: raise BootstrapError("invalid_bootstrap_tenant") from None
    obj = safe_json(raw)
    try:
        tenant = obj["TenantInfo"]["TenantId"]
        require(guid_bytes(tenant) == guid_bytes(expected_tenant), "discovery_tenant_mismatch")
        oauth = obj["AuthenticationService"]["OAuth2"]
        auth = oauth_endpoint(oauth["AuthCodeEndpoint"], "authorize", expected_tenant)
        token = oauth_endpoint(oauth["TokenEndpoint"], "token", expected_tenant)
        require(auth.rsplit("/", 1)[0] == token.rsplit("/", 1)[0], "discovery_endpoint_mismatch")
        keys = obj["KeyProvisioningService"]
        resource = keys["KeyProvisionResourceId"]
        require(resource in RESOURCES, "unsupported_key_provision_resource")
        key_endpoint = keys["KeyProvisionEndpoint"]
        require(key_endpoint in ("https://" + DRS_HOST + "/EnrollmentServer/key/",
                                "https://" + DRS_HOST + "/EnrollmentServer/key"), "unsupported_key_provision_endpoint")
        return Discovery(tenant, auth, token, resource, key_endpoint)
    except (KeyError, TypeError, NgcError): raise BootstrapError("invalid_discovery_metadata") from None


def pkce(verifier):
    require(isinstance(verifier, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", verifier), "invalid_pkce_verifier")
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def prepare(discovery, designated, *, now=None, verifier=None, state=None):
    require(type(discovery) is Discovery, "validated_discovery_required")
    designated = identity(designated)
    require(guid_bytes(designated["tenant_id"]) == guid_bytes(discovery.tenant_id), "discovery_tenant_mismatch")
    # Revalidate even constructed objects; tests and callers cannot turn a
    # dataclass into an arbitrary network destination.
    oauth_endpoint(discovery.authorize_endpoint, "authorize", designated["tenant_id"])
    oauth_endpoint(discovery.token_endpoint, "token", designated["tenant_id"])
    require(discovery.authorize_endpoint.rsplit("/", 1)[0] == discovery.token_endpoint.rsplit("/", 1)[0], "discovery_endpoint_mismatch")
    require(discovery.resource in RESOURCES, "unsupported_key_provision_resource")
    now = int(time.time()) if now is None else now
    require(type(now) is int and now > 0, "invalid_bootstrap_clock")
    verifier, state = verifier or secrets.token_urlsafe(32), state or secrets.token_urlsafe(32)
    challenge = pkce(verifier)
    require(isinstance(state, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", state), "invalid_bootstrap_state")
    params = {"client_id": CLIENT_ID, "redirect_uri": REDIRECT, "response_type": "code", "response_mode": "query",
        "scope": msal_scopes(discovery.resource), "login_hint": designated["account"], "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "claims": json.dumps(CLAIMS, separators=(",", ":")), **EXTRAS}
    authorize = msal_endpoint(discovery.authorize_endpoint, "authorize", designated["tenant_id"])
    native = {"v": 1, "experiment": "NGC-B01", "authorize_url": authorize + "?" + urlencode(params),
        "authorize_endpoint": authorize, "tenant_id": designated["tenant_id"],
        "callback_scheme": "msauth", "callback_host": "com.azure.authenticator", "callback_path": CALLBACK_PATH,
        "state": state, "expires_at": now + LIFETIME}
    private = {"v": 1, "experiment": "NGC-B01", "identity": designated, "discovery": asdict(discovery),
               "verifier": verifier, "state": state, "created_at": now, "expires_at": now + LIFETIME}
    return native, private


def validate_state(value, *, now=None):
    require(isinstance(value, dict) and set(value) == {"v", "experiment", "identity", "discovery", "verifier", "state", "created_at", "expires_at"}
            and type(value["v"]) is int and value["v"] == 1 and value["experiment"] == "NGC-B01", "invalid_bootstrap_state")
    now = time.time() if now is None else now
    require(type(value["created_at"]) is int and type(value["expires_at"]) is int
            and value["created_at"] <= now + 3 and value["expires_at"] == value["created_at"] + LIFETIME
            and now < value["expires_at"], "bootstrap_session_expired")
    try: discovery = Discovery(**value["discovery"])
    except (TypeError, KeyError): raise BootstrapError("invalid_bootstrap_state") from None
    # All endpoint, account, state and verifier checks are shared with preparation.
    prepare(discovery, value["identity"], now=value["created_at"], verifier=value["verifier"], state=value["state"])
    return value


def parse_callback(raw, state, *, now=None):
    validate_state(state, now=now)
    obj = safe_json(raw)
    require(set(obj) == {"v", "experiment", "callback_url"} and type(obj["v"]) is int
            and obj["v"] == 1 and obj["experiment"] == "NGC-B01", "invalid_bootstrap_callback")
    url = obj["callback_url"]
    require(isinstance(url, str) and len(url) <= 65536 and all(32 <= ord(c) < 127 for c in url), "invalid_bootstrap_callback")
    try:
        parts = urlsplit(url)
        require(re.search(r"%(?![0-9A-Fa-f]{2})", parts.path + parts.query) is None, "invalid_bootstrap_callback")
        decoded_path = unquote(parts.path, encoding="utf-8", errors="strict")
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=16, errors="strict")
    except (ValueError, UnicodeError): raise BootstrapError("invalid_bootstrap_callback") from None
    require(parts.scheme == "msauth" and parts.netloc == "com.azure.authenticator"
            and decoded_path == DECODED_CALLBACK_PATH and not parts.fragment, "bootstrap_callback_destination_mismatch")
    params = dict(pairs)
    # RFC 6749 section 4.1.2 requires ignoring unrecognized response metadata.
    # Only exact core names below affect this flow; no response field chooses a
    # token URL, resource, client, redirect or PKCE value. Duplicates still fail.
    require(len(params) == len(pairs) and all(len(k.encode("utf-8")) <= 32768 and len(v.encode("utf-8")) <= 32768
            for k, v in pairs), "invalid_bootstrap_callback")
    require(isinstance(params.get("state"), str) and hmac.compare_digest(params["state"], state["state"]), "bootstrap_state_mismatch")
    require(not ("error" in params and "code" in params), "ambiguous_bootstrap_callback")
    if "error" in params:
        require(bool(params["error"]), "invalid_bootstrap_callback")
        code = params["error"] if params["error"] in OAUTH_ERRORS else "oauth_error"
        raise BootstrapError("authorization_" + code)
    code = params.get("code")
    require(isinstance(code, str) and 0 < len(code) <= 16384 and all(32 <= ord(c) < 127 for c in code), "invalid_bootstrap_code")
    return code


def callback_diagnosis(raw, state, *, now=None):
    """Fixed observations only. Never returns code/URL or authorizes an exchange.

    The structural parser is evaluated at the original transaction's creation
    time so a later forensic read can distinguish expiry from the original
    shape problem. Current expiry is a separate boolean. This helper must never
    supply a callback/code to the exchange path.
    """
    report = {"interpretation_only": True, "network_requests": 0, "raw_values_reported": False,
        "json_parseable": False, "callback_url_present": False, "scheme_matches": False,
        "host_matches": False, "literal_path_matches": False, "decoded_path_matches": False,
        "malformed_percent_escape": False, "query_parseable": False, "duplicate_query_keys": False,
        "known_query_keys_only": False, "state_matches": False, "code_present": False,
        "provider_error_present": False, "sdk_cloud_metadata_present": False,
        "current_input_expired": None, "structural_parser_status": "not_evaluated"}
    now = time.time() if now is None else now
    if isinstance(state, dict) and type(state.get("expires_at")) is int:
        report["current_input_expired"] = now >= state["expires_at"]
    try:
        obj = safe_json(raw); report["json_parseable"] = True
        url = obj.get("callback_url")
        if not isinstance(url, str) or len(url) > 65536: return report
        report["callback_url_present"] = True
        parts = urlsplit(url)
        report["scheme_matches"] = parts.scheme == "msauth"
        report["host_matches"] = parts.netloc == "com.azure.authenticator"
        report["literal_path_matches"] = parts.path == CALLBACK_PATH
        malformed = re.search(r"%(?![0-9A-Fa-f]{2})", parts.path + parts.query) is not None
        report["malformed_percent_escape"] = malformed
        if not malformed:
            report["decoded_path_matches"] = unquote(parts.path, encoding="utf-8", errors="strict") == DECODED_CALLBACK_PATH
            pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True, max_num_fields=16, errors="strict")
            values = dict(pairs)
            report.update(query_parseable=True, duplicate_query_keys=len(values) != len(pairs),
                known_query_keys_only=set(values) <= CALLBACK_KEYS, code_present="code" in values,
                provider_error_present="error" in values,
                sdk_cloud_metadata_present=any(k in values for k in ("cloud_instance_name", "cloud_instance_host_name", "cloud_graph_host_name")),
                state_matches=isinstance(state, dict) and isinstance(state.get("state"), str)
                    and isinstance(values.get("state"), str) and hmac.compare_digest(state["state"], values["state"]))
    except (BootstrapError, ValueError, UnicodeError): pass
    try:
        require(isinstance(state, dict) and type(state.get("created_at")) is int, "invalid_bootstrap_state")
        parse_callback(raw, state, now=state["created_at"])
        report["structural_parser_status"] = "accepted_shape_only"
    except BootstrapError as exc: report["structural_parser_status"] = str(exc)
    return report


def token_request(state, callback_raw, *, now=None):
    code = parse_callback(callback_raw, state, now=now)
    discovery = state["discovery"]
    # MSAL resource helper -> v2 scope-mode code exchange. Claims are copied
    # into the token request by MicrosoftStsOAuth2Strategy.java:238.
    fields = {"grant_type": "authorization_code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT,
              "code": code, "code_verifier": state["verifier"], "scope": msal_scopes(discovery["resource"]),
              "claims": json.dumps(CLAIMS, separators=(",", ":"))}
    return msal_endpoint(discovery["token_endpoint"], "token", state["identity"]["tenant_id"]), urlencode(fields).encode("ascii")


def token_report(raw, state, *, now=None):
    obj = safe_json(raw)
    if "error" in obj:
        error = obj["error"] if obj["error"] in OAUTH_ERRORS else "oauth_error"
        return {"access_token_returned": False, "error": "token_" + error,
                "provider_error_codes": [n for n in obj.get("error_codes", []) if type(n) is int and 0 <= n <= 9999999][:8]
                    if isinstance(obj.get("error_codes"), list) else []}
    token = obj.get("access_token")
    require(isinstance(token, str) and 0 < len(token) <= 131072 and isinstance(obj.get("token_type"), str)
            and obj["token_type"].casefold() == "bearer", "invalid_token_response")
    report = {"access_token_returned": True, "refresh_token_returned": isinstance(obj.get("refresh_token"), str),
              "token_signature_validated": False, "credential_registration_performed": False,
              "token_reused": False, "claims_observation": "unavailable", "token_binding_established": False,
              "binding_status": "identity_claims_unavailable", "error": None}
    # Decoding is explicitly not signature validation. Boolean observations may
    # guide a subsequent validation experiment but never authorize key creation.
    try:
        parts = token.split(".")
        if len(parts) != 3: return report
        require(len(parts[1]) <= 65536, "invalid_token_response")
        claims = safe_json(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        expected = state["identity"]
        report.update(claims_observation="decoded_without_signature_validation",
            tenant_matches_designated=claims.get("tid", "").casefold() == expected["tenant_id"].casefold() if isinstance(claims.get("tid"), str) else False,
            object_matches_designated=claims.get("oid", "").casefold() == expected["object_id"].casefold() if isinstance(claims.get("oid"), str) else False,
            audience_matches_resource=claims.get("aud") == state["discovery"]["resource"],
            deviceid_present=isinstance(claims.get("deviceid"), str) and bool(claims["deviceid"]),
            amr_ngcmfa_present=isinstance(claims.get("amr"), list) and "ngcmfa" in claims["amr"],
            registration_acrs_present=isinstance(claims.get("acrs"), list) and "urn:user:registersecurityinfo" in claims["acrs"])
        usernames = [claims[k] for k in ("upn", "preferred_username", "unique_name") if k in claims]
        report["account_claim_present"] = bool(usernames)
        report["account_claims_match_designated"] = bool(usernames) and all(
            isinstance(name, str) and name.casefold() == expected["account"].casefold() for name in usernames)
        mismatch = (("tid" in claims and not report["tenant_matches_designated"])
            or ("oid" in claims and not report["object_matches_designated"])
            or ("aud" in claims and not report["audience_matches_resource"])
            or (usernames and not report["account_claims_match_designated"]))
        if mismatch:
            report.update(binding_status="decoded_identity_or_audience_mismatch", error="decoded_token_identity_mismatch")
        elif all(k in claims for k in ("tid", "oid", "aud")):
            report["binding_status"] = "signature_and_claims_validation_required"
    except (BootstrapError, ValueError, TypeError):
        report["claims_observation"] = "unreadable"
    return report


def private_dir(path, *, create=False):
    path = Path(path).absolute()
    if create:
        # Only the final two research directories may be created. Existing
        # parent directories must already be protected and nonsymlinked.
        if not path.parent.exists():
            require(path.parent.parent.is_dir(), "private_parent_required")
            path.parent.mkdir(mode=0o700)
        if not path.exists(): path.mkdir(mode=0o700)
    for candidate in (path.parent, path):
        info = candidate.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "private_directory_required")
    return path


def private_write(path, data):
    path = Path(path)
    private_dir(path.parent)
    require(isinstance(data, bytes) and len(data) <= MAX_BYTES, "private_output_too_large")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def write_json(path, value):
    private_write(path, json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8"))


def private_read(path):
    path = Path(path)
    private_dir(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size <= MAX_BYTES, "private_file_required")
        result = stream.read(MAX_BYTES + 1)
    require(len(result) <= MAX_BYTES, "private_input_too_large")
    return result


def identity_from_research(root):
    # Reuse the strict read-only provenance check, but load no FCM/OATH secrets
    # into a saved bootstrap bundle. Original registration and locks untouched.
    import credentials
    import research_runtime as rt
    root = Path(root).absolute()
    directory, enrollment = credentials._run(root, "e05")
    _, approval = credentials._run(root, "e06")
    require(all(enrollment.get(k) is True for k in ("enrollment_completed", "confirmation_accepted", "device_token_validated"))
            and approval.get("same_mac_sign_in_approved") is True and approval.get("error") is None, "verified_research_identity_required")
    saved = rt.private_json(directory / "activation.json")
    designated = rt.private_json(root / ".secrets/push/e02-setup/input.json")["expected_account"]
    require(isinstance(designated, str) and saved.get("Username", "").casefold() == designated.casefold(), "research_identity_mismatch")
    return identity({"account": designated, "tenant_id": saved["TenantId"], "object_id": saved["AzureObjectId"]})


def one_http(method, url, body=None, *, connection_factory=http.client.HTTPSConnection):
    """Exactly one verified TLS request, no redirect handling, bounded read."""
    parts = urlsplit(url)
    require(method in ("GET", "POST") and parts.scheme == "https" and parts.netloc == parts.hostname,
            "invalid_bootstrap_destination")
    if method == "GET":
        require(parts.hostname == DRS_HOST and re.fullmatch(r"/[0-9a-fA-F-]{36}/Discover", parts.path)
                and parts.query == "api-version=1.9&managed=True", "invalid_bootstrap_destination")
    else:
        require(parts.hostname in AUTH_HOSTS and re.fullmatch(r"/(?:[0-9a-fA-F-]{36}|common|organizations)/oauth2/v2\.0/token", parts.path)
                and not parts.query, "invalid_bootstrap_destination")
    require(not parts.fragment, "invalid_bootstrap_destination")
    connection = connection_factory(parts.hostname, 443, timeout=TIMEOUT, context=ssl.create_default_context())
    headers = {"Accept": "application/json", "User-Agent": "MicrosoftMFAForMac-Research-NGC-B01/1",
               "Content-Type": "application/json" if method == "GET" else "application/x-www-form-urlencoded"}
    if method == "GET":
        headers.update({"ocp-adrs-disc-addl-members": "WebBrowserZones",
            "ocp-adrs-client-name": "Microsoft MFA for Mac research",
            "ocp-adrs-client-version": "1.0.0", "client-request-id": str(uuid.uuid4())})
    deadline = time.monotonic() + TIMEOUT
    try:
        connection.request(method, parts.path + ("?" + parts.query if parts.query else ""), body=body, headers=headers)
        response = connection.getresponse()
        chunks, total = [], 0
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "bootstrap_response_timeout")
            if connection.sock is not None: connection.sock.settimeout(remaining)
            block = response.read1(min(65536, MAX_BYTES + 1 - total))
            if not block: break
            chunks.append(block); total += len(block)
            require(total <= MAX_BYTES, "bootstrap_response_too_large")
        return response.status, b"".join(chunks)
    finally: connection.close()


def discover_command(directory, research_root):
    directory = private_dir(directory, create=True)
    designated = identity_from_research(research_root)
    # Persist immutable attempt lock before any network activity. A failed or
    # uncertain request is consumed; do not remove the lock to repeat it.
    write_json(directory / "discovery-attempt.lock", {"experiment": "NGC-B01", "maximum_gets": 1})
    write_json(directory / "identity.json", designated)
    report = {"experiment": "NGC-B01", "stage": "discovery", "get_attempts": 1,
              "automatic_retries": 0, "post_attempts": 0, "tls_verified": False, "http_status": None}
    try:
        status, raw = one_http("GET", discovery_url(designated["tenant_id"]))
        private_write(directory / "discovery-response.bin", raw)
        report.update(http_status=status, tls_verified=True, received_bytes=len(raw))
        require(status == 200, "discovery_http_rejected")
        parsed = parse_discovery(raw, designated["tenant_id"])
        write_json(directory / "discovery.json", asdict(parsed))
        report.update(validated_metadata=True, error=None)
    except BootstrapError as exc: report.update(validated_metadata=False, error=str(exc))
    except Exception: report.update(validated_metadata=False, error="local_io_or_network_failure")
    write_json(directory / "discovery-report.json", report)
    return report


def load_validated_cache(directory):
    directory = private_dir(directory)
    report = safe_json(private_read(directory / "discovery-report.json"))
    if report.get("origin") == "validated_cache_copy":
        require(report.get("validated_metadata") is True and report.get("source_tls_verified") is True
                and report.get("get_attempts") == 0 and report.get("post_attempts") == 0
                and report.get("source_http_status") == 200 and report.get("error") is None,
                "validated_discovery_required")
    else:
        require(report.get("validated_metadata") is True and report.get("tls_verified") is True
                and report.get("get_attempts") == 1 and report.get("http_status") == 200
                and report.get("error") is None, "validated_discovery_required")
    designated = identity(safe_json(private_read(directory / "identity.json")))
    raw = private_read(directory / "discovery-response.bin")
    discovery = parse_discovery(raw, designated["tenant_id"])
    return designated, discovery, raw


def stage_command(directory, source_directory):
    """Start a separate cache-only attempt; no consumed OAuth material copied."""
    source = private_dir(source_directory)
    designated, discovery, raw = load_validated_cache(source)
    target = Path(directory).absolute()
    require(target != source, "fresh_bootstrap_directory_required")
    require(not os.path.lexists(target), "fresh_bootstrap_directory_required")
    target = private_dir(target, create=True)
    write_json(target / "cache-attempt.lock", {"experiment": "NGC-B01", "network_requests": 0})
    write_json(target / "identity.json", designated)
    private_write(target / "discovery-response.bin", raw)
    write_json(target / "discovery.json", asdict(discovery))
    write_json(target / "cache-source.json", {"source_directory": str(source),
        "discovery_sha256": hashlib.sha256(raw).hexdigest(), "copied_files": ["identity.json", "discovery-response.bin"],
        "oauth_material_copied": False})
    report = {"experiment": "NGC-B01", "stage": "cache_prepared", "origin": "validated_cache_copy",
        "validated_metadata": True, "source_tls_verified": True, "source_http_status": 200,
        "get_attempts": 0, "post_attempts": 0, "automatic_retries": 0, "error": None}
    write_json(target / "discovery-report.json", report)
    return {**report, "fresh_pkce_created": False, "oauth_material_copied": False,
            "next_action": "run_live_one_session_when_present"}


def prepare_command(directory):
    directory = private_dir(directory)
    designated, discovery, _ = load_validated_cache(directory)
    native, state = prepare(discovery, designated)
    # If preparation partially fails, an existing private state is never
    # replaced with another PKCE transaction under the same attempt directory.
    write_json(directory / "state.json", state)
    write_json(directory / "auth-input.json", native)
    return {"experiment": "NGC-B01", "stage": "prepared", "network_requests": 0,
            "expires_in_seconds": LIFETIME, "interactive_authentication_required": True,
            "credential_registration_performed": False}


def exchange_command(directory):
    directory = private_dir(directory)
    receipt = native_result(private_read(directory / "native-result.json"))
    require(receipt["terminal"] and receipt["status"] == "callback_saved", "native_callback_acceptance_required")
    state = safe_json(private_read(directory / "state.json"))
    callback = private_read(directory / "callback.json")
    url, body = token_request(state, callback)
    write_json(directory / "exchange-attempt.lock", {"experiment": "NGC-B01", "maximum_posts": 1})
    report = {"experiment": "NGC-B01", "stage": "code_exchange", "post_attempts": 1,
              "automatic_retries": 0, "tls_verified": False, "http_status": None,
              "credential_registration_performed": False, "token_reused": False}
    try:
        status, raw = one_http("POST", url, body)
        private_write(directory / "token-response.bin", raw)
        report.update(http_status=status, tls_verified=True, received_bytes=len(raw))
        parsed = token_report(raw, state)
        report.update(parsed)
        if status != 200: report["error"] = parsed.get("error") or "token_http_rejected"
    except BootstrapError as exc: report["error"] = str(exc)
    except Exception: report["error"] = "local_io_or_network_failure"
    write_json(directory / "exchange-report.json", report)
    return report


def helper_path(value=None):
    path = Path(value) if value else Path(__file__).resolve().parents[1] / "build/RemoteNGCBootstrap/Phone Sign-in Research.app"
    require(path.is_absolute() and path.is_dir() and not path.is_symlink(), "native_bootstrap_helper_required")
    try:
        with (path / "Contents/Info.plist").open("rb") as stream: metadata = plistlib.load(stream)
    except Exception: raise BootstrapError("native_bootstrap_helper_required") from None
    require(metadata.get("CFBundleIdentifier") == "org.example.microsoftmfamac.RemoteNGCBootstrap", "native_bootstrap_helper_required")
    return path


def launch_helper(path, directory):
    # Paths only in argv. Authorization URL, account, PKCE and code remain in
    # protected files. LaunchServices preserves the helper's bundle identity.
    return subprocess.Popen(["/usr/bin/open", "-n", "-W", "-a", str(path), "--args",
        "--input", str(directory / "auth-input.json"), "--output", str(directory / "callback.json")],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)


def validate_native_input(path, directory):
    result = subprocess.run([str(path / "Contents/MacOS/RemoteNGCBootstrap"), "--validate-input",
        str(directory / "auth-input.json")], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=10, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 4096, "native_input_validation_failed")


def native_result(raw):
    value = safe_json(raw)
    required = {"v", "experiment", "status", "terminal", "session_started", "callback_received", "callback_saved",
                "callback_candidate_saved", "system_error_domain", "system_error_code"}
    require(set(value) == required and type(value["v"]) is int and value["v"] == 1
            and value["experiment"] == "NGC-B01", "invalid_native_result")
    for key in ("terminal", "session_started", "callback_received", "callback_saved", "callback_candidate_saved"):
        require(type(value[key]) is bool, "invalid_native_result")
    require(isinstance(value["status"], str) and value["status"] in (NATIVE_TERMINAL if value["terminal"] else NATIVE_NONTERMINAL),
            "invalid_native_result")
    require(value["system_error_domain"] in ("none", "authentication_services", "other")
            and (value["system_error_code"] is None or (type(value["system_error_code"]) is int
                 and -32768 <= value["system_error_code"] <= 32767)), "invalid_native_result")
    require(value["system_error_domain"] != "none" or value["system_error_code"] is None, "invalid_native_result")
    require(not value["callback_saved"] or (value["callback_received"] and value["callback_candidate_saved"] and value["session_started"]),
            "invalid_native_result")
    require(not value["callback_candidate_saved"] or value["callback_received"], "invalid_native_result")
    require(value["callback_saved"] == (value["status"] in ("callback_saved", "authorization_rejected")),
            "invalid_native_result")
    if value["status"] in ("callback_saved", "authorization_rejected"):
        require(value["terminal"] and value["callback_saved"] and value["system_error_domain"] == "none", "invalid_native_result")
    return value


def native_summary(value):
    return {"native_" + key: value[key] for key in ("status", "terminal", "session_started", "callback_received",
            "callback_saved", "callback_candidate_saved", "system_error_domain", "system_error_code")}


def inspect_command(directory):
    """Inspect only the inert candidate file; cannot submit a captured code."""
    directory = private_dir(directory)
    report = {"experiment": "NGC-B01", "stage": "callback_interpretation", "network_requests": 0,
              "interpretation_only": True, "candidate_file_present": False}
    state = safe_json(private_read(directory / "state.json"))
    try: raw = private_read(directory / "native-callback-candidate.json")
    except FileNotFoundError: return report
    report["candidate_file_present"] = True
    report["callback_diagnostic"] = callback_diagnosis(raw, state)
    return report


def live_command(directory, helper=None):
    """One coherent interactive transaction, with no discovery or enrollment."""
    directory = private_dir(directory)
    path = helper_path(helper)
    write_json(directory / "live-attempt.lock", {"experiment": "NGC-B01", "maximum_native_sessions": 1,
                                                "maximum_code_exchanges": 1})
    report = {"experiment": "NGC-B01", "stage": "interactive_bootstrap", "get_attempts": 0,
              "maximum_native_sessions": 1, "maximum_code_exchanges": 1, "post_attempts": 0,
              "automatic_retries": 0, "credential_registration_performed": False,
              "native_helper_launched": False, "error": None}
    process = None
    try:
        prepare_command(directory)
        validate_native_input(path, directory)
        state = safe_json(private_read(directory / "state.json"))
        deadline = time.monotonic() + max(0, state["expires_at"] - time.time()) + 2
        process = launch_helper(path, directory)
        report["native_helper_launched"] = True
        while time.monotonic() < deadline:
            if process.poll() is not None:
                report["native_process_exit_code"] = process.poll()
                try: receipt = native_result(private_read(directory / "native-result.json"))
                except FileNotFoundError: raise BootstrapError("native_result_missing") from None
                report.update(native_summary(receipt))
                require(receipt["terminal"], "native_result_incomplete")
                if receipt["status"] not in ("callback_saved", "authorization_rejected"):
                    raise BootstrapError("native_" + receipt["status"])
                require((directory / "callback.json").is_file(), "native_result_callback_missing")
                if receipt["status"] == "authorization_rejected":
                    # Parse only to obtain the fixed OAuth error. A receipt
                    # reporting rejection can never authorize a POST.
                    parse_callback(private_read(directory / "callback.json"), state)
                    raise BootstrapError("native_result_callback_mismatch")
                report.update(exchange_command(directory))
                break
            time.sleep(0.25)
        else: raise BootstrapError("bootstrap_session_expired")
    except KeyboardInterrupt: report["error"] = "bootstrap_cancelled_locally"
    except BootstrapError as exc: report["error"] = str(exc)
    except FileExistsError: report["error"] = "attempt_or_output_already_exists"
    except Exception: report["error"] = "local_io_or_network_failure"
    finally:
        # This terminates only the open -W waiter. The helper independently
        # cancels its ASWebAuthenticationSession at the exact input expiry.
        if process is not None and process.poll() is None:
            try: process.terminate()
            except OSError: pass
    if "native_status" not in report and (directory / "native-result.json").exists():
        try: report.update(native_summary(native_result(private_read(directory / "native-result.json"))))
        except Exception: report["native_result_read_error"] = "invalid_or_unavailable_native_result"
    # Candidates are diagnostic evidence only, including rejected/malformed
    # URLs. Never use this file as a fallback token-exchange input.
    if (directory / "native-callback-candidate.json").exists():
        try: report["callback_diagnostic"] = inspect_command(directory)["callback_diagnostic"]
        except Exception: report["callback_diagnostic"] = {"interpretation_only": True, "error": "candidate_interpretation_unavailable"}
    write_json(directory / "live-report.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Separate bounded OAuth compatibility diagnostic; never enrolls a credential.")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("discover", "stage", "prepare", "exchange", "live", "inspect"):
        part = sub.add_parser(command)
        part.add_argument("--directory", required=True)
        if command in ("discover", "exchange"): part.add_argument("--one-request", action="store_true", required=True)
        if command == "discover": part.add_argument("--research-root", required=True)
        if command == "stage": part.add_argument("--from-directory", required=True)
        if command == "live":
            part.add_argument("--one-session", action="store_true", required=True)
            part.add_argument("--helper", help="Path to separately built Phone Sign-in Research.app")
    args = parser.parse_args(argv)
    try:
        if args.command == "discover": report = discover_command(args.directory, args.research_root)
        elif args.command == "stage": report = stage_command(args.directory, args.from_directory)
        elif args.command == "prepare": report = prepare_command(args.directory)
        elif args.command == "live": report = live_command(args.directory, args.helper)
        elif args.command == "inspect": report = inspect_command(args.directory)
        else: report = exchange_command(args.directory)
    except FileExistsError: report = {"experiment": "NGC-B01", "error": "attempt_or_output_already_exists", "automatic_retries": 0}
    except BootstrapError as exc: report = {"experiment": "NGC-B01", "error": str(exc), "automatic_retries": 0}
    except Exception: report = {"experiment": "NGC-B01", "error": "local_prerequisite_failure", "automatic_retries": 0}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not report.get("error") else 1


if __name__ == "__main__": raise SystemExit(main())
