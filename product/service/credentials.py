"""Private, read-only migration. No network, no credential logging."""
import bootstrap  # noqa: F401
from dataclasses import dataclass
from pathlib import Path
import os
import re

import e02
import enrollment_protocol as ep
import mfa_protocol as mfa
import push_protocol as p
import research_runtime as rt


@dataclass(repr=False, frozen=True)
class Credentials:
    account: mfa.Account
    checkin: p.CheckinCredentials
    sender_id: str
    package: str


def validate(bundle):
    rt.require(isinstance(bundle, dict) and type(bundle.get("version")) is int and bundle.get("version") == 1, "invalid_credentials")
    rt.require(set(bundle) <= {"version", "provider", "account", "installation"}, "invalid_credentials")
    provider, account = bundle.get("provider"), bundle.get("account")
    rt.require(isinstance(provider, dict) and isinstance(account, dict), "invalid_credentials")
    rt.require(set(provider) == {"android_id", "security_token", "token", "sender_id", "package"}, "invalid_credentials")
    mandatory = {"secret", "username", "tenant_id", "object_id", "group_key", "method_id", "dos_preventer"}
    rt.require(mandatory <= set(account) <= mandatory | {"replication_scope", "routing_hint", "country"}, "invalid_credentials")
    for key in ("android_id", "security_token"):
        rt.require(isinstance(provider[key], str) and re.fullmatch(r"[1-9][0-9]{0,19}", provider[key]), "invalid_credentials")
    checkin = p.CheckinCredentials(int(provider["android_id"]), int(provider["security_token"]))
    checkin.validate()
    for value in provider.values(): ep.scalar(value, 16384)
    for key, value in account.items(): ep.scalar(value, 16384, empty=key not in mandatory)
    rt.require(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", account["username"]), "invalid_credentials")
    # The product uses only the already traced AAD sender/package, never arbitrary registrations.
    rt.require(provider["sender_id"] == "275572744697" and provider["package"] == "com.azure.authenticator", "unsupported_provider_identity")
    obj = mfa.Account(token=provider["token"], **account)
    mfa.oath_proof(obj.secret, 1)
    return Credentials(obj, checkin, provider["sender_id"], provider["package"])


def _run(root, name):
    locator = rt.private_json(root / ".secrets/push" / (name + "-attempt.lock"))
    run_id = locator.get("run_id")
    rt.require(isinstance(run_id, str) and re.fullmatch(r"[0-9a-f]{32}", run_id), "invalid_import_provenance")
    directory = root / ".secrets/push" / run_id
    os.close(rt.private_directory(directory))
    report = rt.private_json(directory / "report.json")
    rt.require(report.get("experiment") == name.upper() and report.get("run_id") == run_id, "invalid_import_provenance")
    return directory, report


def export_research(root):
    """Return only the working registration; caller captures this into Keychain."""
    root = Path(root).absolute()
    config, checkin, token = e02.load_identity(root)
    directory, report = _run(root, "e05")
    rt.require(all(report.get(k) is True for k in ("enrollment_completed", "confirmation_accepted",
               "device_token_validated", "dos_preventer_present")), "working_enrollment_required")
    _, successful = _run(root, "e06")
    rt.require(successful.get("same_mac_sign_in_approved") is True
               and successful.get("browser_sign_in_success_user_reported") is True
               and successful.get("authentication_approvals_sent") == 1
               and successful.get("error") is None, "successful_e06_required")
    a, v, c = (rt.private_json(directory / name) for name in ("activation.json", "validation.json", "confirmation.json"))
    # E05 intentionally reused the designated account stored by E02/E02B.
    designated = rt.private_json(root / ".secrets/push/e02-setup/input.json")["expected_account"]
    rt.require(a.get("Username", "").casefold() == designated.casefold()
               and (not v.get("username") or v["username"].casefold() == designated.casefold())
               and c.get("ConfirmActivationResult") in ("true", "1"), "import_account_mismatch")
    bundle = {"version": 1, "provider": {"android_id": str(checkin.android_id),
              "security_token": str(checkin.security_token), "token": token,
              "sender_id": config.sender_id, "package": config.package},
              "account": {"secret": a["OathTokenSecretKey"], "username": a["Username"],
              "tenant_id": a["TenantId"], "object_id": a["AzureObjectId"], "group_key": v["groupKey"],
              "method_id": c["phoneAppDetailId"], "dos_preventer": v["dosPreventer"],
              "replication_scope": a.get("ReplicationScope", ""), "routing_hint": a.get("RoutingHint", ""),
              "country": a.get("CountryCode", "")}}
    validate(bundle)
    return bundle
