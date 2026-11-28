"""Classic-MFA number matching with explicit consent and truthful local state."""
import base64
from dataclasses import dataclass, replace
import json
import math
import re
import time
import xml.etree.ElementTree as ET

import auth_request
import enrollment_protocol as ep
import mfa_protocol as mfa
import push_protocol as p
import request_expiry as expiry
from research_runtime import require


def boolean(value):
    require(value in ("", "yes", "no", "true", "false", "1", "0"), "unknown_policy_boolean")
    return value in ("yes", "true", "1")


def message(data, schema):
    fields = p.decode_fields(data)
    require(all(n in schema and w == schema[n] for n, w, _ in fields.values), "unknown_policy_field")
    return {n: fields.one(n, w) for n, w, _ in fields.values}


def policy(encoded):
    result = dict(app_lock=False, approval_pin=False, app_context=False, location_context=False)
    if not encoded: return result
    require(isinstance(encoded, str) and len(encoded) <= 32768, "invalid_credential_policy")
    try: raw = base64.b64decode(encoded, validate=True)
    except ValueError: require(False, "invalid_credential_policy")
    top = message(raw, {1: 2, 2: 2, 3: 2, 4: 2, 5: 2})
    if 1 in top:
        metadata = message(top[1], {1: 2, 2: 2})  # Version and protobuf Timestamp.
        if 2 in metadata: message(metadata[2], {1: 0, 2: 0})
    if 3 in top: message(top[3], {1: 0, 2: 0})  # Reporting settings, not an approval proof.
    if 4 in top: message(top[4], {i: 0 for i in range(1, 9)})
    if 2 in top:
        phone = message(top[2], {i: 0 for i in range(1, 9)})
        require(all(v in (0, 1, 2) for k, v in phone.items() if k in (3, 4, 5, 6, 7, 8)), "unknown_policy_enum")
        # Mirrors UserCredentialPolicyStateKt:172 conservatively: enabled
        # phone-sign-in policy makes these requirements true even by default.
        enabled = phone.get(8, 0) == 0
        result.update(app_lock=enabled or phone.get(6) == 2,
                      app_context=enabled or phone.get(3) == 2,
                      location_context=enabled or phone.get(4) == 2)
    if 5 in top:
        platform = message(top[5], {1: 0})
        require(platform.get(1, 0) in (0, 1), "unknown_platform_policy_boolean")
        result["approval_pin"] = platform.get(1, 0) == 1
    return result


def context(fields):
    raw = fields.get("authDetails", "")
    if not raw: return {}
    require(len(raw) <= 16384, "rich_context_size_limit")
    try: obj = json.loads(raw, object_pairs_hook=p._object)
    except (ValueError, TypeError): require(False, "invalid_rich_context")
    require(isinstance(obj, dict), "invalid_rich_context")
    result = {}
    for key in ("ApplicationDisplayName", "CallerApplicationDisplayName"):
        if obj.get(key): result[key] = ep.scalar(obj[key], 1024)
    if "Latitude" in obj or "Longitude" in obj:
        for key, bound in (("Latitude", 90), ("Longitude", 180)):
            value = obj.get(key)
            require(type(value) in (int, float) and math.isfinite(value) and -bound <= value <= bound,
                    "invalid_rich_context_location")
            result[key] = value
    return result


def push_details(props, account):
    require(props.get("source") in ("SAS", "MFA Server") and props.get("type") == "auth",
            "unsupported_authentication_notification")
    require(props.get("deviceTokenChangeVersion") != "V2", "unsupported_token_rotation")
    require(props.get("groupKey") == account.group_key and props.get("phoneAppDetailId") == account.method_id,
            "notification_account_mismatch")
    require(props.get("interactive", "true").lower() in ("true", "yes", "1"), "noninteractive_request_rejected")
    ep.pad_destination(props.get("url", "")); ep.scalar(props.get("guid", ""), 1024)
    fields = {k: ep.scalar(v, 32768, empty=True) for k, v in props.items()
              if k in auth_request.FIELDS or k == "mode"}
    for key, expected in (("username", account.username), ("tenantId", account.tenant_id), ("azureObjectId", account.object_id)):
        require(not fields.get(key) or fields[key].casefold() == expected.casefold(), "push_identity_mismatch")
        fields[key] = expected
    return fields


def requirements(fields):
    require(all(fields.get(k) for k in ("firstEntropyChallenge", "secondEntropyChallenge", "thirdEntropyChallenge")),
            "number_matching_challenge_required")
    expiry.timestamp(fields.get("expiration", ""))
    require(not boolean(fields.get("pinChangeRequired", "")), "pin_change_not_supported")
    require(not boolean(fields.get("returnLocationData", "")), "device_location_proof_not_implemented")
    requirements = policy(fields.get("userCredentialPolicy", ""))
    requirements["app_lock"] |= boolean(fields.get("isAppLockRequired", ""))
    require(not requirements["approval_pin"], "organization_approval_pin_not_implemented")
    shown = context(fields)
    require(not requirements["app_context"] or bool(shown.get("ApplicationDisplayName")), "required_app_context_missing")
    require(not requirements["location_context"] or "Latitude" in shown, "required_location_context_missing")
    return requirements, shown


@dataclass(frozen=True, repr=False)
class Consent:
    guid: str
    number: str
    deadline: float
    app_lock_used: bool
    app_context_shown: bool
    location_context_shown: bool


def consent(fields, number, phrase, deadline, *, app_lock_used, app_context_shown, location_context_shown, now=None):
    require(phrase == "APPROVE", "approval_not_explicitly_confirmed")
    require(isinstance(number, str) and re.fullmatch(r"[0-9]{1,2}", number) is not None, "invalid_browser_number")
    require((time.monotonic() if now is None else now) < deadline, "approval_request_expired")
    req, _ = requirements(fields)
    require(not req["app_lock"] or app_lock_used, "local_user_verification_required")
    require(not req["app_context"] or app_context_shown, "required_app_context_not_shown")
    require(not req["location_context"] or location_context_shown, "required_location_context_not_shown")
    return Consent(ep.scalar(fields.get("guid", ""), 1024), str(int(number)), deadline,
                   bool(app_lock_used), bool(app_context_shown), bool(location_context_shown))


def app_state(approved):
    # Android/Authenticator are compatibility identifiers, not attestation.
    # The actual key store is a protected file; no RD proof is manufactured.
    raw = (p.field(1, "4") + p.field(2, 1) + p.field(3, 1) + p.field(4, ep.VERSION)
           + p.field(5, approved.number) + p.field(6, 2 if approved.app_context_shown else 1)
           + p.field(7, 2 if approved.location_context_shown else 1)
           + p.field(8, 2 if approved.app_lock_used else 1) + p.field(12, 16))
    return base64.b64encode(raw).decode()


def number_request(account, service, fields, approved, *, now=None, unix_time=None):
    require(type(approved) is Consent and approved.guid == fields.get("guid"), "approval_request_binding_failed")
    require((time.monotonic() if now is None else now) < approved.deadline, "approval_request_expired")
    unix = time.time() if unix_time is None else unix_time
    require(unix < expiry.timestamp(fields.get("expiration", "")), "approval_request_expired")
    requirements(fields)
    dest = ep.pad_destination(service)
    name = "phoneAppPinValidationRequest"; body = ET.Element(name)
    ctx = ET.SubElement(body, "phoneAppContext")
    for key, value in (("guid", approved.guid), ("oathCode", ""), ("needDosPreventer", "no"),
                       ("deviceToken", account.token), ("version", ep.VERSION), ("osVersion", ep.OS_VERSION)):
        mfa.add(ctx, key, value)
    mfa.add(body, "pin", "", {"stored": "no"})
    for key, value in (("authenticate", "yes"), ("oathCounter", str(int(unix) // 30)),
                       ("completedInteractively", "yes"), ("selectedEntropyNumber", approved.number),
                       ("isAppLockUsed", "yes" if approved.app_lock_used else "no"), ("appState", app_state(approved))):
        mfa.add(body, key, value)
    routed = replace(account, replication_scope=fields.get("replicationScope") or account.replication_scope,
                     routing_hint=fields.get("routingHint") or account.routing_hint,
                     country=fields.get("countryCode") or account.country)
    return p.Request("https://" + dest.host + dest.path, mfa.headers(routed, name), mfa.envelope(body))


def number_response(data):
    root = mfa.operation(data, "phoneAppPinValidationResponse")
    fields = ep.scalar_fields(root, ("validationResult", "rdPassed"))
    require(fields.get("validationResult") in tuple(str(i) for i in range(1, 12)), "unknown_number_validation_result")
    code = int(fields["validationResult"])
    return {"number_validation_result": code, "number_approval_accepted": code == 6,
            "root_detection_result_present": bool(fields.get("rdPassed"))}
