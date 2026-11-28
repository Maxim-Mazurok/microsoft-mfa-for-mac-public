"""Offline parsing of a classic-MFA push and request details. No approvals."""
import re

import enrollment_protocol as ep
import mfa_protocol as mfa
import request_expiry as expiry
from research_runtime import require


FIELDS = frozenset(("guid", "username", "groupKey", "tenantId", "azureObjectId", "phoneAppDetailId",
    "phoneAppAccountName", "expiration", "oathCounter", "pushNotificationDeviceToken", "dosPreventer",
    "replicationScope", "routingHint", "countryCode", "sasSessionId", "userCredentialPolicy", "endpointMapVersion",
    "isAppLockRequired", "returnLocationData", "pinChangeRequired", "pinRetries", "userCanChangePin",
    "oathTokenEnabled", "fraudAllowed", "fraudBlock", "firstEntropyChallenge", "secondEntropyChallenge",
    "thirdEntropyChallenge", "authDetails"))


def notification(properties, account):
    require(properties.get("source") in ("SAS", "MFA Server") and properties.get("type") == "auth",
            "unsupported_authentication_notification")
    require(properties.get("deviceTokenChangeVersion") != "V2", "unsupported_token_rotation")
    require(properties.get("groupKey") == account.group_key
            and properties.get("phoneAppDetailId") == account.method_id, "notification_account_mismatch")
    service = ep.scalar(properties.get("url", ""), 4096)
    ep.pad_destination(service)
    guid = ep.scalar(properties.get("guid", ""), 1024)
    counter = properties.get("oathCounter", "")
    require(re.fullmatch(r"[1-9][0-9]{0,18}", counter) is not None, "notification_oath_counter_required")
    mfa.oath_proof(account.secret, int(counter))
    return service, guid, int(counter)


def response(data, account):
    root = mfa.operation(data, "phoneAppAuthenticationResponse")
    fields = {}
    containers = set()
    # Android scans phoneAppContext/phoneAppInfo descendants. Keep the root
    # operation strict and reject duplicate containers or scalar fields.
    def walk(node, depth=0):
        require(depth <= 3, "authentication_response_depth")
        for child in node:
            if child.tag in ("phoneAppContext", "phoneAppInfo"):
                require(child.tag not in containers, "duplicate_authentication_container")
                containers.add(child.tag)
                if child.tag == "phoneAppInfo":
                    require(set(child.attrib) <= {"mode"}, "unknown_phone_app_info_attribute")
                    fields["mode"] = ep.scalar(child.get("mode", ""), 64, empty=True)
                else:
                    require(not child.attrib, "invalid_authentication_container")
                walk(child, depth + 1)
            else:
                require(child.tag in FIELDS and child.tag not in fields
                        and not child.attrib and not len(child), "unknown_or_duplicate_authentication_field")
                fields[child.tag] = ep.scalar(child.text or "", 32768, empty=True)
    walk(root)
    require(fields.get("username", "").casefold() == account.username.casefold()
            and fields.get("groupKey") == account.group_key
            and fields.get("phoneAppDetailId") == account.method_id, "retrieved_account_mismatch")
    for name, expected in (("tenantId", account.tenant_id), ("azureObjectId", account.object_id),
                           ("pushNotificationDeviceToken", account.token)):
        require(not fields.get(name) or fields[name] == expected, "retrieved_identity_mismatch")
    ep.scalar(fields.get("guid", ""), 1024)
    expiry.timestamp(fields.get("expiration", ""))
    return fields


def summary(fields):
    # Never report request GUID, number challenges, account, context, or policy.
    return {"retrieval_account_bound": True, "request_guid_present": bool(fields.get("guid")),
            "request_expiration_present": bool(fields.get("expiration")),
            "number_challenge_present": any(fields.get(k) for k in
                ("firstEntropyChallenge", "secondEntropyChallenge", "thirdEntropyChallenge")),
            "rich_context_present": bool(fields.get("authDetails")),
            "user_credential_policy_present": bool(fields.get("userCredentialPolicy")),
            "app_lock_requirement_present": bool(fields.get("isAppLockRequired")),
            "request_details_retrieved": True}
