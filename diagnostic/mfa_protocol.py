"""Offline classic-MFA discovery/retrieval codecs for the fresh E02B identity."""
import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import struct
import uuid
import xml.etree.ElementTree as ET

import e02
import enrollment_protocol as ep
import push_protocol as p
import research_runtime as rt

POLL_URL = "https://mobileappcommunicator.auth.microsoft.com/mac/MobileAppCommunicator.svc/"


@dataclass(frozen=True, repr=False)
class Account:
    token: str
    secret: str
    username: str
    tenant_id: str
    object_id: str
    group_key: str
    method_id: str
    dos_preventer: str
    replication_scope: str = ""
    routing_hint: str = ""
    country: str = ""


def load_account(root):
    _, _, token = e02.load_identity(root)
    lock = rt.private_json(root / ".secrets/push/e02b-attempt.lock")
    rt.require(isinstance(lock.get("run_id"), str) and re.fullmatch(r"[0-9a-f]{32}", lock["run_id"]),
               "invalid_enrollment_locator")
    directory = root / ".secrets/push" / lock["run_id"]
    report = rt.private_json(directory / "report.json")
    rt.require(report.get("experiment") == "E02B" and report.get("run_id") == lock["run_id"]
               and all(report.get(k) is True for k in ("bootstrap_accepted", "device_token_validated", "dos_preventer_present",
                                                       "confirmation_accepted", "enrollment_completed")),
               "confirmed_independent_enrollment_required")
    a = rt.private_json(directory / "activation.json")
    v = rt.private_json(directory / "validation.json")
    c = rt.private_json(directory / "confirmation.json")
    expected = rt.private_json(root / ".secrets/push/e02b-setup/input.json")["expected_account"]
    rt.require(a.get("Username", "").casefold() == expected.casefold()
               and (not v.get("username") or v["username"].casefold() == expected.casefold()), "unexpected_enrolled_account")
    account = Account(token, a["OathTokenSecretKey"], a["Username"], a["TenantId"], a["AzureObjectId"],
                      v["groupKey"], c["phoneAppDetailId"], v["dosPreventer"],
                      a.get("ReplicationScope", ""), a.get("RoutingHint", ""), a.get("CountryCode", ""))
    for key in ("token", "secret", "username", "tenant_id", "object_id", "group_key", "method_id", "dos_preventer"):
        ep.scalar(getattr(account, key))
    oath_proof(account.secret, 1)
    return account


def oath_proof(secret, counter):
    rt.require(isinstance(secret, str) and re.fullmatch(r"[A-Za-z2-7]{16,256}={0,6}", secret) is not None,
               "invalid_oath_secret_encoding")
    rt.require(type(counter) is int and 0 < counter < 2**63, "invalid_oath_counter")
    try:
        text = secret.upper().rstrip("=")
        key = base64.b32decode(text + "=" * ((-len(text)) % 8))
    except ValueError:
        rt.require(False, "invalid_oath_secret_encoding")
    rt.require(10 <= len(key) <= 128, "invalid_oath_key_length")
    return hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).hexdigest().upper()


def headers(account, action):
    result = {"Content-Type": "application/xml", "AppName": "Authenticator", "AppVersion": ep.VERSION,
              "DeviceType": "Android", "x-ms-mac-app-version": ep.VERSION, "x-ms-mac-os-version": ep.OS_VERSION,
              "x-ms-mac-flavor": "Authenticator", "x-ms-mac-os-platform": "Android",
              "x-ms-mac-device-token": hashlib.sha256(account.token.encode()).hexdigest(),
              "x-ms-mac-interactive": "true", "x-ms-mac-action": action}
    for name, value in (("x-ms-client-replication-scope", account.replication_scope),
                        ("x-ms-client-tenant-id", account.tenant_id), ("x-ms-routing-hint", account.routing_hint),
                        ("x-ms-client-tenant-country-code", account.country)):
        if value: result[name] = ep.scalar(value, 4096)
    return result


def envelope(body):
    root = ET.Element("pfpMessage", {"version": "1.6"})
    component = ET.SubElement(ET.SubElement(ET.SubElement(root, "header"), "source"), "component",
                              {"type": "pfsvc", "role": "master"})
    ET.SubElement(component, "host", {"ip": "", "hostname": "", "serverId": ""})
    request = ET.SubElement(root, "request", {"request-id": str(uuid.uuid4()), "async": "0",
                                              "response-url": "", "language": "en"})
    request.append(body)
    return ET.tostring(root, encoding="utf-8")


def add(parent, name, value, attributes=None):
    node = ET.SubElement(parent, name, attributes or {})
    node.text = ep.scalar(value, empty=True)
    return node


def poll(account):
    name = "phoneAppCheckForAuthenticationRequest"
    body = ET.Element(name)
    add(body, "dosPreventer", account.dos_preventer)
    add(body, "deviceToken", account.token, {"notificationType": "gcm"})
    add(body, "previousDeviceToken", "")
    add(body, "version", ep.VERSION); add(body, "osVersion", ep.OS_VERSION)
    add(body, "AuthenticatorFlavor", "Authenticator")
    return p.Request(POLL_URL, headers(account, name), envelope(body))


def operation(data, name):
    root = ep.xml(data)
    if root.tag == "pfpMessage":
        rt.require(all(n.tag in ("header", "response") for n in root)
                   and len(root.findall("header")) <= 1 and len(root.findall("response")) == 1,
                   "unexpected_mfa_envelope")
        response = root.find("response")
        matches = [n for n in response if n.tag == name]
        statuses = [n for n in response if n.tag == "status"]
        rt.require(len(matches) == 1 and len(statuses) <= 1 and len(response) == len(matches) + len(statuses),
                   "ambiguous_mfa_response")
        if statuses:
            status = statuses[0]
            rt.require(set(status.attrib) == {"disposition"}
                       and status.get("disposition") in ("success", "failure", "error")
                       and all(n.tag in ("error-id", "message") for n in status)
                       and len(status.findall("error-id")) == 1 and len(status.findall("message")) <= 1,
                       "invalid_mfa_status")
            code = status.find("error-id")
            rt.require(not len(code) and not code.attrib and re.fullmatch(r"-?[0-9]{1,10}", code.text or ""),
                       "invalid_mfa_status_code")
            rt.require(status.get("disposition") == "success" and code.text == "0", "mfa_status_rejected")
        return matches[0]
    rt.require(root.tag == name, "unexpected_mfa_operation")
    return root


def poll_response(data, account):
    root = operation(data, "phoneAppCheckForAuthenticationResponse")
    fields = ep.scalar_fields(root, ("checkForAuthenticationResult", "groupKey", "username", "oathCounter", "padUrl", "phoneAppDetailId"))
    result = fields.get("checkForAuthenticationResult", "")
    rt.require(result in ("1", "100", "101"), "unknown_poll_result")
    if result != "1":
        return {"result": int(result), "pending": False}, fields
    pending = bool(fields.get("padUrl"))
    if pending:
        rt.require(fields.get("username", "").casefold() == account.username.casefold()
                   and fields.get("groupKey") == account.group_key and fields.get("phoneAppDetailId") == account.method_id,
                   "pending_request_account_mismatch")
        ep.pad_destination(fields["padUrl"])
        rt.require(re.fullmatch(r"[1-9][0-9]{0,18}", fields.get("oathCounter", "")) is not None,
                   "invalid_pending_counter")
        oath_proof(account.secret, int(fields["oathCounter"]))
    else:
        rt.require(not any(fields.get(k) for k in ("groupKey", "username", "phoneAppDetailId")),
                   "partial_pending_response")
    return {"result": 1, "pending": pending}, fields


def retrieve(account, service, guid, counter):
    dest = ep.pad_destination(service)
    name = "phoneAppAuthenticationRequest"
    body = ET.Element(name); context = ET.SubElement(body, "phoneAppContext")
    for key, value in (("guid", guid), ("oathCode", oath_proof(account.secret, counter)), ("needDosPreventer", "no"),
                       ("deviceToken", account.token), ("version", ep.VERSION), ("osVersion", ep.OS_VERSION)):
        add(context, key, value)
    return p.Request("https://" + dest.host + dest.path, headers(account, name), envelope(body))
