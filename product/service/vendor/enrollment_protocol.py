"""Offline E02 codecs. No network, credential generation, or sign-in approval.

Historical binary evidence is not distributed; response assumptions remain experimental.
Original executed E01/P01/P02/P03 modules remain unchanged.
"""
from dataclasses import dataclass
import hashlib
import re
import time
import uuid
from urllib.parse import parse_qsl, urlsplit
import xml.etree.ElementTree as ET

import e01
from p01 import require
from push_protocol import Request

VERSION = "6.2610.7075"
DEVICE_NAME = "Mac E02 research"
OS_VERSION = "15"  # Explicit Android compatibility profile, not macOS attestation.
PRODUCTION_DOMAINS = ("mobileappcommunicator.auth.microsoft.com",
                      "adnotifications.windowsazure.com", "phonefactor.net")


def scalar(value, limit=8192, *, empty=False):
    require(isinstance(value, str) and (empty or bool(value)) and len(value) <= limit
            and all(ord(c) >= 32 and c not in "\x7f\ufffe\uffff" for c in value),
            "invalid_protocol_scalar")
    return value


def destination(base_url):
    result = e01.validate_destination(base_url)
    require(result.domain in PRODUCTION_DOMAINS, "e02_requires_production_cloud")
    return result


def pad_destination(notification_service):
    # MfaRegistrationUseCase:930–931 concatenates strings, including a routing
    # query when supplied. E02 observed /mac/<opaque route>?<routing parameters>.
    # Do not move /pad ahead of the query or drop opaque routing data.
    require(isinstance(notification_service, str) and len(notification_service) <= 8192,
            "invalid_notification_service_address")
    value = "https://" + notification_service
    e01._clean_uri(value)
    parts = urlsplit(value)
    require(parts.netloc == parts.hostname and not parts.fragment and "#" not in value,
            "invalid_notification_service_authority")
    dest = destination("https://" + parts.netloc)
    if parts.path:
        require(re.fullmatch(r"/mac/[A-Za-z0-9_.~-]+/?", parts.path) is not None
                and parts.path.rstrip("/").split("/")[-1] not in (".", ".."), "invalid_notification_route")
    if "?" in value:
        require(bool(parts.path) and bool(parts.query), "invalid_notification_query")
        try:
            pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True,
                              encoding="utf-8", errors="strict", max_num_fields=8)
        except (ValueError, UnicodeError):
            require(False, "invalid_notification_query")
        require(len({k for k, _ in pairs}) == len(pairs), "duplicate_notification_query")
        for key, val in pairs:
            require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", key) is not None,
                    "invalid_notification_query_key")
            scalar(val, 2048, empty=True)
        require(re.fullmatch(r"[A-Za-z0-9._~%+:/=&-]+", parts.query) is not None,
                "invalid_notification_query_encoding")
    path = parts.path + ("?" + parts.query if "?" in value else "") + "/pad"
    return e01.Destination(dest.host, path, dest.domain)


def validate_pad_request_url(value):
    require(isinstance(value, str) and value.startswith("https://") and value.endswith("/pad"),
            "invalid_validation_request_url")
    dest = pad_destination(value[8:-4])
    require(value == "https://" + dest.host + dest.path, "invalid_validation_request_url")
    return dest


def soap(operation, values):
    envelope = ET.Element("soap:Envelope", {
        "xmlns:soap": e01.SOAP, "xmlns:ns4": e01.PF,
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xmlns:xsd": "http://www.w3.org/2001/XMLSchema"})
    ET.SubElement(envelope, "soap:Header")
    op = ET.SubElement(ET.SubElement(envelope, "soap:Body"), "ns4:" + operation)
    parent = ET.SubElement(op, "ns4:activationParams") if operation == "ActivateNew" else op
    for key, value in values:
        ET.SubElement(parent, "ns4:" + key).text = scalar(value)
    return ET.tostring(envelope, encoding="utf-8")


def activate(enrollment, token, counter=None, *, device_name=DEVICE_NAME):
    dest = destination(enrollment.base_url)
    e01._validate_code(enrollment.code)
    counter = int(time.time()) // 30 if counter is None else counter
    require(type(counter) is int and 0 < counter < 2**63, "invalid_counter")
    body = soap("ActivateNew", (("ActivationCode", enrollment.code), ("DeviceToken", scalar(token)),
                ("DeviceName", scalar(device_name, 64)), ("OathCounter", str(counter)), ("Version", VERSION)))
    return Request("https://" + dest.host + dest.path,
                   {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": e01.ACTION}, body)


def confirm(enrollment, confirmation_code):
    dest = destination(enrollment.base_url)
    return Request("https://" + dest.host + dest.path,
                   {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": e01.PF + "/ConfirmActivation"},
                   soap("ConfirmActivation", (("confirmationCode", confirmation_code),)))


@dataclass(frozen=True, repr=False)
class ValidationNotification:
    guid: str
    destination: e01.Destination
    properties: dict


def validation_notification(properties):
    require(isinstance(properties, dict) and len(properties) <= 64, "invalid_notification")
    for key, value in properties.items():
        scalar(key, 128); scalar(value, empty=True)
    require(properties.get("source") in ("SAS", "MFA Server"), "unexpected_notification_source")
    require(properties.get("type") != "auth", "sign_in_requires_deliberate_approval")
    require(properties.get("type") == "validate", "unexpected_notification_type")
    require(not properties.get("deviceTokenChangeVersion"), "token_change_notification_requires_analysis")
    guid = scalar(properties.get("guid"), 128)
    # The SDK treats guid as an opaque string. Do not invent UUID-only proof.
    return ValidationNotification(guid, pad_destination(properties.get("url")), properties)


def validate(notification, token, request_id=None):
    dest = pad_destination(notification.properties.get("url"))
    require(dest == notification.destination, "notification_destination_mismatch")
    root = ET.Element("pfpMessage", {"version": "1.6"})
    component = ET.SubElement(ET.SubElement(ET.SubElement(root, "header"), "source"),
                              "component", {"type": "pfsvc", "role": "master"})
    ET.SubElement(component, "host", {"ip": "", "hostname": "", "serverId": ""})
    request_id = str(uuid.uuid4()) if request_id is None else str(uuid.UUID(request_id))
    request = ET.SubElement(root, "request", {"request-id": request_id, "async": "0",
                                              "response-url": "", "language": "en"})
    body = ET.SubElement(request, "phoneAppValidateDeviceTokenRequest")
    context = ET.SubElement(body, "phoneAppContext")
    for key, value in (("guid", notification.guid), ("oathCode", ""), ("deviceToken", scalar(token)),
                       ("version", VERSION), ("osVersion", OS_VERSION), ("needDosPreventer", "yes")):
        ET.SubElement(context, key).text = scalar(value, empty=True)
    ET.SubElement(body, "validationResult").text = "yes"
    ET.SubElement(body, "accounts")  # New client has no existing accounts/proofs to update.
    headers = {"Content-Type": "application/xml", "AppName": "Authenticator", "AppVersion": VERSION,
               "DeviceType": "Android", "x-ms-mac-app-version": VERSION, "x-ms-mac-os-version": OS_VERSION,
               "x-ms-mac-flavor": "Authenticator", "x-ms-mac-os-platform": "Android",
               "x-ms-mac-device-token": hashlib.sha256(token.encode()).hexdigest(),
               "x-ms-mac-interactive": "true", "x-ms-mac-action": "phoneAppValidateDeviceTokenRequest"}
    return Request("https://" + dest.host + dest.path, headers, ET.tostring(root, encoding="utf-8"))


def xml(data):
    require(isinstance(data, bytes) and 0 < len(data) <= e01.MAX_RESPONSE, "invalid_xml_size")
    try:
        text = data.decode("utf-8-sig")
        require(not re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I), "unsafe_xml_declaration")
        encoding = re.search(r"<\?xml\b[^?]*encoding\s*=\s*['\"]([^'\"]+)", text, re.I)
        require(not encoding or encoding[1].lower() in ("utf-8", "utf8"), "unsupported_xml_encoding")
        root = ET.fromstring(text)
    except (UnicodeError, ET.ParseError):
        raise e01.DiagnosticError("invalid_xml_response") from None
    stack, count = [(root, 0)], 0
    while stack:
        node, depth = stack.pop(); count += 1
        require(depth <= 32 and count <= 2048, "xml_structure_limit")
        stack.extend((child, depth + 1) for child in node)
    return root


def soap_response(data, operation):
    root = xml(data)
    require(root.tag == f"{{{e01.SOAP}}}Envelope", "unexpected_soap_envelope")
    require(all(n.tag in (f"{{{e01.SOAP}}}Header", f"{{{e01.SOAP}}}Body") for n in root)
            and len(root.findall(f"{{{e01.SOAP}}}Header")) <= 1, "unexpected_soap_envelope")
    bodies = root.findall(f"{{{e01.SOAP}}}Body")
    require(len(bodies) == 1, "unexpected_soap_envelope")
    responses, ids = [], []
    for node in bodies[0]:
        if node.tag in (f"{{{e01.PF}}}{operation}Response", f"{{{e01.SOAP}}}Fault"):
            responses.append(node)
        elif node.tag == f"{{{e01.SOAP}}}RequestId":
            ids.append(node)
        else:
            require(False, "unexpected_soap_operation")
    require(len(responses) == 1, "ambiguous_or_missing_soap_operation")
    require(len(ids) <= 1 and all(not len(n) and not n.attrib for n in ids), "invalid_soap_metadata")
    require(responses[0].tag != f"{{{e01.SOAP}}}Fault", "soap_fault")
    return responses[0]


def scalar_fields(root, names, namespace=""):
    result = {}
    for node in root.iter():
        local = node.tag.rsplit("}", 1)[-1]
        if local in names:
            expected = f"{{{namespace}}}{local}" if namespace else local
            require(node.tag == expected and local not in result and not len(node) and not node.attrib,
                    "ambiguous_or_invalid_response_field")
            result[local] = scalar(node.text or "", empty=True)
    return result


def activation_response(data):
    root = soap_response(data, "ActivateNew")
    scalar_fields(root, e01.PARSED_FIELDS, e01.PF)
    return e01.parse_response(data)


@dataclass(frozen=True, repr=False)
class ValidationResponse:
    fields: dict
    status_disposition: str | None
    status_error_id: int | None


def parse_validation_response(data):
    root = xml(data)
    status = None
    # V01 observed a status sibling before the response operation. Preserve
    # operation/namespace/uniqueness checks; never equate status with issuance.
    if root.tag == "pfpMessage":
        require(all(n.tag in ("header", "response") for n in root)
                and len(root.findall("header")) <= 1, "unexpected_validation_envelope")
        responses = root.findall("response")
        require(len(responses) == 1, "ambiguous_validation_response")
        operations, statuses = [], []
        for node in responses[0]:
            if node.tag == "phoneAppValidateDeviceTokenResponse":
                operations.append(node)
            elif node.tag == "status":
                statuses.append(node)
            else:
                require(False, "unexpected_validation_operation")
        require(len(operations) == 1 and len(statuses) <= 1, "ambiguous_validation_response")
        response = operations[0]
        status = statuses[0] if statuses else None
    else:
        response = root
    require(response.tag == "phoneAppValidateDeviceTokenResponse", "unexpected_validation_operation")
    fields = scalar_fields(response, ("groupKey", "username", "accountName", "dosPreventer"))
    require(not response.findall(".//accountValidationResult"), "unexpected_existing_account_result")
    disposition, error_id = None, None
    if status is not None:
        require(set(status.attrib) == {"disposition"} and status.get("disposition") in ("success", "failure", "error"),
                "invalid_validation_status")
        require(all(n.tag in ("error-id", "message") for n in status)
                and len(status.findall("error-id")) == 1 and len(status.findall("message")) <= 1,
                "ambiguous_validation_status")
        error = status.find("error-id")
        require(not len(error) and not error.attrib and re.fullmatch(r"-?[0-9]{1,10}", error.text or "") is not None,
                "invalid_validation_status_code")
        error_id = int(error.text)
        require(-(2**31) <= error_id < 2**31, "invalid_validation_status_code")
        for message in status.findall("message"):
            require(not len(message) and set(message.attrib) <= {"lang"}, "invalid_validation_status_message")
        disposition = status.get("disposition")
    return ValidationResponse(fields, disposition, error_id)


def validation_response(data):
    parsed = parse_validation_response(data)
    require(parsed.status_disposition is None or
            (parsed.status_disposition == "success" and parsed.status_error_id == 0), "validation_status_rejected")
    fields = parsed.fields
    require(all(fields.get(k) for k in ("groupKey", "accountName", "dosPreventer")),
            "validation_credentials_missing")
    return fields


def confirmation_response(data):
    root = soap_response(data, "ConfirmActivation")
    fields = scalar_fields(root, ("ConfirmActivationResult", "phoneAppDetailId", "Code", "Description"), e01.PF)
    require(fields.get("ConfirmActivationResult") in ("true", "false", "0", "1"),
            "invalid_confirmation_result")
    return fields
