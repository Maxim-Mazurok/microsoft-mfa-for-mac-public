"""Fail-closed correlation between Safari challenges and issuer-authenticated pushes.

No number/account/application/time-only fallback. This module has no network or
credential access, and never chooses a number from a push. UUIDs and account
strings stay in memory; callers must not log event dictionaries or exceptions.
"""
from __future__ import annotations

import math
import re
import uuid

ALLOWED_ORIGINS = frozenset({
    "https://login.microsoftonline.com",
    "https://login.microsoft.com",
    "https://login.windows.net",
})
MAX_BROWSER_AGE = 90.0
MAX_REQUEST_AGE = 120.0
MAX_PAIR_GAP = 60.0
MAX_FUTURE_SKEW = 3.0
MAX_EVENTS = 32
MAX_REQUESTS = 64
FLOWS = frozenset({"classic_mfa", "remote_ngc"})


class CorrelationError(ValueError):
    """Only fixed identifiers may be raised; never interpolate untrusted input."""


def require(condition, code):
    if not condition:
        raise CorrelationError(code)


def text(value, limit=256, empty=False):
    require(isinstance(value, str) and len(value) <= limit and (empty or bool(value)), "invalid_correlation_text")
    require(all(ord(c) >= 32 and ord(c) != 127 for c in value), "invalid_correlation_text")
    return value


def local_id(value):
    value = text(value, 160)
    require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value) is not None, "invalid_local_identifier")
    return value


def shared_id(value):
    if value in (None, ""):
        return ""
    require(isinstance(value, str) and re.fullmatch(
        r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}", value) is not None,
        "invalid_shared_identifier")
    normalized = str(uuid.UUID(value))
    require(normalized != "00000000-0000-0000-0000-000000000000", "invalid_shared_identifier")
    return normalized


def account(value):
    value = text(value, 254).strip().casefold()
    # Exact UPN, no display-name parsing or guessed account selection.
    require(value.isascii() and re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", value) is not None,
            "invalid_browser_account")
    return value


def timestamp(value):
    require(type(value) in (int, float) and math.isfinite(value), "invalid_correlation_timestamp")
    return float(value)


def application(value):
    return text("" if value is None else value, 512, empty=True).strip().casefold()


def flow(value):
    require(isinstance(value, str) and value in FLOWS, "unsupported_authentication_flow")
    return value


def remote_hash(value):
    # A fingerprint of the opaque RemoteNGC SessionIdentifier, never that blob.
    require(isinstance(value, str) and (value == "" or re.fullmatch(r"[0-9a-f]{64}", value)),
            "invalid_remote_session_hash")
    return value


class CorrelationEngine:
    def __init__(self):
        self.browser_events: dict[tuple[str, str], dict] = {}
        self.requests: dict[str, dict] = {}
        self.locked = False
        # Retire old documents/events to prevent reordered messages resurrecting
        # a challenge after navigation/withdrawal. Memory is bounded per service.
        self._retired: dict[tuple[str, str], float] = {}
        self._retired_events: dict[str, float] = {}
        self._withdrawn_at: dict[tuple[str, str], float] = {}

    def _prune(self, now):
        now = timestamp(now)
        for key, value in list(self.browser_events.items()):
            if now - value["observed_at"] > MAX_BROWSER_AGE:
                self.browser_events.pop(key, None)
                self._retired_events[value["event_id"]] = now
        for key, value in list(self.requests.items()):
            if now >= value["expires_at"] or now - value["received_at"] > MAX_REQUEST_AGE:
                self.requests.pop(key, None)
        for mapping in (self._retired, self._retired_events, self._withdrawn_at):
            for key, retired_at in list(mapping.items()):
                if now - retired_at > 600:
                    mapping.pop(key, None)
            while len(mapping) > 256:
                mapping.pop(next(iter(mapping)))
        return now

    def add_browser(self, browser, now):
        now = self._prune(now)
        require(isinstance(browser, dict), "invalid_browser_event")
        allowed = {"version", "kind", "event_id", "tab_id", "document_id", "origin", "observed_at", "number",
                   "account", "application", "session_id", "request_id", "focused", "flow", "remote_session_hash"}
        require(set(browser) <= allowed and browser.get("version") == 1 and type(browser.get("version")) is int,
                "invalid_browser_schema")
        require(browser.get("kind") in ("challenge", "withdraw"), "invalid_browser_kind")
        kind = flow(browser.get("flow", "classic_mfa"))
        require(isinstance(browser.get("origin"), str) and browser["origin"] in ALLOWED_ORIGINS,
                "unsupported_browser_origin")
        tab, doc = local_id(browser.get("tab_id")), local_id(browser.get("document_id"))
        event_id = local_id(browser.get("event_id"))
        observed = timestamp(browser.get("observed_at"))
        require(-MAX_FUTURE_SKEW <= now - observed <= MAX_BROWSER_AGE, "stale_browser_event")
        key = tab, doc
        if browser["kind"] == "withdraw":
            # Withdrawal removes current evidence but allows the same document
            # to refocus only with a new event ID.
            current = self.browser_events.get(key)
            self._withdrawn_at[key] = max(observed, self._withdrawn_at.get(key, float("-inf")))
            if current and observed >= current["observed_at"]:
                self.browser_events.pop(key, None)
                self._retired_events[current["event_id"]] = now
            self._retired_events[event_id] = now
            return
        require(type(browser.get("focused")) is bool, "invalid_browser_focus")
        if not browser["focused"]:
            self.remove_browser(tab, doc)
            return
        require(not self.locked, "session_locked")
        require(key not in self._retired and event_id not in self._retired_events, "retired_browser_event")
        require(observed > self._withdrawn_at.get(key, float("-inf")), "withdrawn_browser_context")
        number = browser.get("number")
        require(isinstance(number, str) and re.fullmatch(r"[0-9]{1,2}", number) is not None, "invalid_browser_number")
        sid, rid = shared_id(browser.get("session_id")), shared_id(browser.get("request_id"))
        fingerprint = remote_hash(browser.get("remote_session_hash", ""))
        if kind == "classic_mfa":
            require(not fingerprint, "cross_flow_identifier")
            require(bool(sid or rid), "shared_session_identifier_required")
        else:
            require(not sid and not rid, "cross_flow_identifier")
            # An empty fingerprint permits detection-only reporting, never a match.
        value = {"event_id": event_id, "tab_id": tab, "document_id": doc, "origin": browser["origin"],
                 "observed_at": observed, "number": str(int(number)), "account": account(browser.get("account")),
                 "application": application(browser.get("application")), "session_id": sid, "request_id": rid,
                 "focused": True, "flow": kind, "remote_session_hash": fingerprint}
        for old_key, old in list(self.browser_events.items()):
            if old_key[0] == tab and old_key != key:
                require(observed >= old["observed_at"], "out_of_order_browser_event")
                self._retired[old_key] = now
                self._retired_events[old["event_id"]] = now
                self.browser_events.pop(old_key)
        current = self.browser_events.get(key)
        if current:
            require(observed >= current["observed_at"], "out_of_order_browser_event")
            if current["event_id"] == event_id:
                # Duplicate DOM updates cannot refresh evidence lifetime or
                # change its number/identity while retaining the same event ID.
                stable = ("number", "account", "application", "session_id", "request_id", "origin", "flow", "remote_session_hash")
                require(all(current[k] == value[k] for k in stable), "conflicting_browser_duplicate")
                return
            self._retired_events[current["event_id"]] = now
        require(key in self.browser_events or len(self.browser_events) < MAX_EVENTS, "browser_event_limit")
        self.browser_events[key] = value

    def remove_browser(self, tab_id, document_id):
        key = local_id(tab_id), local_id(document_id)
        old = self.browser_events.pop(key, None)
        if old:
            self._retired_events[old["event_id"]] = old["observed_at"]
            self._withdrawn_at[key] = max(old["observed_at"], self._withdrawn_at.get(key, float("-inf")))

    def add_request(self, request, now):
        now = self._prune(now)
        require(isinstance(request, dict), "invalid_request_context")
        key = local_id(request.get("request_id"))
        received = timestamp(request.get("received_at")); expires = timestamp(request.get("expires_at"))
        require(-MAX_FUTURE_SKEW <= now - received <= MAX_REQUEST_AGE and expires > now and expires > received,
                "expired_request_context")
        kind = flow(request.get("flow", "classic_mfa"))
        sid, rid = shared_id(request.get("session_id")), shared_id(request.get("server_request_id"))
        fingerprint = remote_hash(request.get("remote_session_hash", ""))
        if kind == "classic_mfa":
            require(not fingerprint, "cross_flow_identifier")
        else:
            require(not sid and not rid and bool(fingerprint), "remote_session_identifier_required")
        value = {"request_id": key, "account": account(request.get("account")),
                 "application": application(request.get("application")),
                 "session_id": sid, "server_request_id": rid,
                 "received_at": received, "expires_at": expires, "flow": kind, "remote_session_hash": fingerprint}
        if key in self.requests:
            require(self.requests[key] == value, "conflicting_request_duplicate")
            return
        require(len(self.requests) < MAX_REQUESTS, "pending_request_limit")
        self.requests[key] = value

    def remove_request(self, request_id):
        self.requests.pop(local_id(request_id), None)

    def clear_browser(self):
        for value in self.browser_events.values():
            self._retired_events[value["event_id"]] = value["observed_at"]
        self.browser_events.clear()

    def set_locked(self, locked):
        require(type(locked) is bool, "invalid_lock_state")
        self.locked = locked
        if locked:
            self.clear_browser()

    @staticmethod
    def _evidence(browser, request):
        if browser["flow"] != request["flow"]:
            return None
        if browser["account"] != request["account"]:
            return None
        if abs(browser["observed_at"] - request["received_at"]) > MAX_PAIR_GAP:
            return None
        if browser["application"] and request["application"] and browser["application"] != request["application"]:
            return None
        if browser["flow"] == "remote_ngc":
            return "exact_remote_session_hash" if (browser["remote_session_hash"]
                and browser["remote_session_hash"] == request["remote_session_hash"]) else None
        # If both sides expose a field, a conflicting value is disqualifying.
        pairs = (("session_id", "session_id"), ("request_id", "server_request_id"))
        for b, r in pairs:
            if browser[b] and request[r] and browser[b] != request[r]:
                return None
        if browser["session_id"] and browser["session_id"] == request["session_id"]:
            return "exact_session_id"
        if browser["request_id"] and browser["request_id"] == request["server_request_id"]:
            return "exact_request_id"
        return None

    def match(self, request_id, now):
        self._prune(now)
        if self.locked:
            return None
        request = self.requests.get(request_id)
        if not request:
            return None
        candidates = [(event, self._evidence(event, request)) for event in self.browser_events.values()]
        candidates = [(event, evidence) for event, evidence in candidates if evidence]
        if len(candidates) != 1:
            return None
        event, evidence = candidates[0]
        # One browser tab must not select between multiple genuine requests.
        if sum(self._evidence(event, other) is not None for other in self.requests.values()) != 1:
            return None
        return {key: event[key] for key in ("number", "event_id", "tab_id", "document_id")} | {"evidence": evidence}

    def diagnose(self, request_id, now):
        """Fixed local diagnostic only: never expose accounts, IDs or numbers."""
        self._prune(now)
        if self.locked:
            return "session_locked"
        request = self.requests.get(request_id)
        if not request:
            return "request_context_unavailable"
        events = list(self.browser_events.values())
        if not events:
            return "waiting_for_browser"
        events = [event for event in events if event["flow"] == request["flow"]]
        if not events:
            return "authentication_flow_mismatch"
        events = [event for event in events if event["account"] == request["account"]]
        if not events:
            return "account_mismatch"
        recent = [event for event in events if abs(event["observed_at"] - request["received_at"]) <= MAX_PAIR_GAP]
        if not recent:
            return "browser_context_not_fresh"
        if request["flow"] == "remote_ngc" and not any(event["remote_session_hash"] for event in recent):
            return "remote_session_binding_unavailable"
        candidates = [event for event in recent if self._evidence(event, request)]
        if not candidates:
            if any((event["session_id"] and event["session_id"] == request["session_id"])
                   or (event["request_id"] and event["request_id"] == request["server_request_id"]) for event in recent):
                return "browser_context_conflict"
            return "session_unmatched"
        if len(candidates) != 1:
            return "multiple_local_matches"
        if sum(self._evidence(candidates[0], other) is not None for other in self.requests.values()) != 1:
            return "multiple_request_matches"
        return "unique_local_match"
