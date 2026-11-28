"""Request lifecycle, narrow automatic authorization, and truthful policy reporting."""
import bootstrap  # noqa: F401
import asyncio
import json
import re
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

import approval_protocol as approval
import credentials as credential_store
import push_protocol as p
import request_expiry
import remotengc
from correlation import CorrelationEngine, CorrelationError
from state import StateStore
from transport import MCSConnection, TransportError, post_number


class ServiceError(ValueError):
    pass


def require(condition, code):
    if not condition: raise ServiceError(code)


def flag(command, name):
    value = command.get(name)
    require(type(value) is bool, "invalid_boolean")
    return value


@dataclass(repr=False)
class Pending:
    local_id: str
    fields: dict
    service: str
    digest: str
    expires_at: float
    deadline: float
    requirements: dict
    context: dict
    app_context_shown: bool = False
    location_context_shown: bool = False
    decision: dict | None = None
    ticket: str | None = None
    verified_at: float | None = None
    sending: bool = False
    claimed: bool = False
    auto_suppressed: bool = False
    context_requested: bool = False
    last_status: str | None = None


class Controller:
    def __init__(self, store, emit, *, synthetic=False, sender=post_number, connector=MCSConnection):
        self.store, self.emit = store, emit
        self.synthetic, self.sender, self.connector = synthetic, sender, connector
        self.credentials = None
        self.configured = False
        self.paused, self.locked, self.automatic = False, True, False
        self.connection = "offline"
        self.engine = CorrelationEngine()
        self.engine.set_locked(True)
        self.pending = {}
        self.seen = {}
        self.ngc_candidates = {}
        self.ngc_status = None
        self.connection_task = None
        self.approval_tasks = set()
        self.closed = False
        self.attempt_times = []
        self.last_tick = time.monotonic()
        self.last_wall = time.time()

    def output(self, event, **fields):
        self.emit({"version": 1, "event": event, **fields})

    def status(self, detail=""):
        self.output("state", connection=self.connection, paused=self.paused, locked=self.locked,
                    automatic=self.automatic, detail=detail)

    async def command(self, obj):
        require(isinstance(obj, dict) and type(obj.get("version")) is int and obj.get("version") == 1, "invalid_envelope")
        command = obj.get("command")
        if command == "configure":
            require(not self.configured, "already_configured")
            if self.synthetic:
                require(obj.get("credentials") is None, "synthetic_rejects_real_credentials")
            else:
                self.credentials = credential_store.validate(obj.get("credentials"))
            settings = obj.get("settings", {})
            require(isinstance(settings, dict), "invalid_settings")
            self.automatic = flag(settings, "automatic") if "automatic" in settings else False
            self.configured = True
            self.status("synthetic_ready" if self.synthetic else "credentials_loaded_from_keychain")
        elif command == "connect":
            require(self.configured, "import_required")
            if self.synthetic:
                self.connection = "connected"; self.status("synthetic_transport")
            elif not self.paused and not self.locked:
                if self.connection_task is None or self.connection_task.done():
                    self.connection_task = asyncio.create_task(self.connection_loop())
        elif command == "settings":
            self.automatic = flag(obj, "automatic")
            if not self.automatic: self.invalidate_decisions(automatic_only=True)
            self.status()
            await self.evaluate()
        elif command in ("pause", "session_lock"):
            value = flag(obj, "paused" if command == "pause" else "locked")
            if command == "pause": self.paused = value
            else: self.locked = value; self.engine.set_locked(value)
            if value:
                self.engine.clear_browser(); self.invalidate_decisions()
                await self.disconnect()
            self.status("paused" if self.paused else "session_locked" if self.locked else "ready_to_connect")
            if not self.paused and not self.locked and self.configured:
                await self.command({"version": 1, "command": "connect"})
        elif command == "browser_event":
            require(self.configured and not self.paused, "automatic_handling_paused")
            event = obj.get("browser")
            self.engine.add_browser(event, time.time())
            if event.get("kind") == "challenge" and event.get("flow") == "remote_ngc":
                # Detection is useful even without a current server session. It
                # never creates a classic Pending or permission to approve.
                self.ngc_capability("registration_required" if event.get("remote_session_hash")
                                    else "session_binding_unavailable")
            await self.evaluate()
        elif command == "browser_reset":
            # Native Safari termination/crash: revoke browser authorization only.
            # Keep MCS and deliberate manual handling available.
            self.engine.clear_browser(); self.invalidate_decisions(automatic_only=True)
            self.refresh_correlation_status()
        elif command == "context_shown":
            item = self.get_pending(obj)
            item.app_context_shown = flag(obj, "app_context_shown") and bool(item.context.get("ApplicationDisplayName"))
            item.location_context_shown = flag(obj, "location_context_shown") and "Latitude" in item.context
            await self.evaluate()
        elif command == "manual_approve":
            item = self.get_pending(obj)
            require(not item.sending and not item.claimed and not item.ticket, "request_already_in_progress")
            number = obj.get("number")
            require(isinstance(number, str) and re.fullmatch(r"[0-9]{1,2}", number), "invalid_browser_number")
            require(not self.paused and not self.locked, "approval_unavailable")
            item.decision = {"mode": "manual", "number": str(int(number))}
            await self.advance(item)
        elif command == "verification_result":
            item = self.get_pending(obj)
            require(item.ticket is not None and obj.get("ticket_id") == item.ticket, "verification_ticket_invalid")
            item.ticket = None  # Every result consumes the one-use ticket, including cancellation.
            if not flag(obj, "verified"):
                item.decision = None; item.verified_at = None
                item.auto_suppressed = True
                # A declined request remains declined across duplicate delivery/restart.
                if self.store.claim(item.digest): self.store.outcome(item.digest, "verification_cancelled")
                self.pending.pop(item.local_id, None); self.engine.remove_request(item.local_id)
                self.output("outcome", request_id=item.local_id, result="verification_cancelled")
                return
            self.preflight(item, require_verification=False)
            item.verified_at = time.monotonic()
            await self.advance(item)
        elif command == "wake":
            self.engine.clear_browser(); self.invalidate_decisions()
            await self.disconnect()
            self.status("fresh_browser_context_required")
            if self.configured and not self.paused and not self.locked:
                await self.command({"version": 1, "command": "connect"})
        elif command == "demo":
            require(self.synthetic and self.configured, "synthetic_mode_required")
            await self.demo(obj)
        elif command == "shutdown":
            self.closed = True
            await self.disconnect()
            for task in tuple(self.approval_tasks): task.cancel()
            if self.approval_tasks: await asyncio.gather(*self.approval_tasks, return_exceptions=True)
        else:
            raise ServiceError("unknown_command")

    def get_pending(self, obj):
        key = obj.get("request_id")
        require(isinstance(key, str) and key in self.pending, "unknown_request")
        item = self.pending[key]
        require(time.monotonic() < item.deadline and time.time() < item.expires_at, "request_expired")
        return item

    def invalidate_decisions(self, automatic_only=False):
        for item in self.pending.values():
            if not automatic_only or (item.decision and item.decision.get("mode") == "automatic"):
                item.ticket = item.decision = item.verified_at = None

    async def disconnect(self):
        if self.connection_task and not self.connection_task.done():
            self.connection_task.cancel()
            await asyncio.gather(self.connection_task, return_exceptions=True)
        self.connection_task = None
        self.connection = "offline"

    async def connection_loop(self):
        # Four consecutive failures: initial + 2/10/30-second reconnects. At most
        # eight connections in any rolling hour, even across repeated UI actions.
        failures = 0
        while not self.closed and not self.paused and not self.locked:
            now = time.monotonic()
            self.attempt_times = [t for t in self.attempt_times if now - t < 3600]
            if len(self.attempt_times) >= 8:
                self.connection = "attention"; self.status("connection_budget_exhausted"); return
            self.attempt_times.append(now)
            self.connection = "connecting"; self.status()
            connected_at = None
            async def connected():
                nonlocal connected_at
                connected_at = time.monotonic()
                self.connection = "connected"; self.status("push_ready")
            try:
                await self.connector(self.credentials, self.receive, connected).run()
                failures = 0  # Scheduled six-hour connection refresh, same identity.
                continue
            except asyncio.CancelledError:
                return
            except TransportError as exc:
                if str(exc) == "provider_credentials_rejected":
                    self.connection = "attention"; self.status("provider_credentials_rejected_no_rotation"); return
                if str(exc) not in ("heartbeat_timeout", "connection_receive_budget", "connection_frame_budget"):
                    self.connection = "attention"; self.status("provider_protocol_requires_attention"); return
            except (OSError, TimeoutError):
                pass  # Identified transport interruption; bounded retries only.
            except Exception:
                self.connection = "attention"; self.status("provider_protocol_requires_attention"); return
            if connected_at is not None and time.monotonic() - connected_at >= 300: failures = 0
            self.engine.clear_browser(); self.invalidate_decisions()
            if failures >= 3:
                self.connection = "attention"; self.status("connection_failed_retry_paused"); return
            delay = (2, 10, 30)[failures]; failures += 1
            self.connection = "reconnecting"; self.status("bounded_backoff")
            await asyncio.sleep(delay)

    async def receive(self, frame):
        try:
            data = p.parse_android_data(frame, sender_id=self.credentials.sender_id, package=self.credentials.package)
            props = data.properties
            if any(isinstance(props.get(k), str) and props[k].lower() == "ngc" for k in ("type", "sessiontype")):
                await self.receive_ngc(props)
                return
            if props.get("type") != "auth" or props.get("phoneAppDetailId") != self.credentials.account.method_id:
                return  # Validation/old-method/own-project control is never an approval.
            fields = approval.push_details(props, self.credentials.account)
            await self.add_request(fields, props["url"])
        except Exception:
            self.output("error", code="unsupported_or_invalid_push")

    def ngc_capability(self, status):
        require(status in ("registration_required", "session_binding_unavailable",
                           "registered_credential_unavailable"), "invalid_ngc_capability")
        if status != self.ngc_status:
            self.ngc_status = status
            self.output("capability", flow="remote_ngc", status=status)

    async def receive_ngc(self, props):
        """Validate and correlate only; the imported v1 credential is classic MFA.

        NGC needs its own issuer-registered asymmetric key. No classic OATH
        proof, number serializer, user-verification shortcut or enrollment here.
        """
        account = self.credentials.account
        try:
            session = remotengc.parse_notification(props, account=account.username,
                tenant_id=account.tenant_id, object_id=account.object_id)
        except remotengc.NgcError as exc:
            if str(exc) in ("ngc_account_mismatch", "ngc_tenant_mismatch"):
                return  # Never offer another account's request as a local action.
            raise
        now = time.time()
        fingerprint = session.session_hash
        if fingerprint not in self.ngc_candidates:
            require(len(self.ngc_candidates) < 32, "ngc_candidate_limit")
            local_id = "ngc-" + uuid.uuid4().hex
            expires = min(session.expiration_time, now + 120)
            self.engine.add_request({"request_id": local_id, "flow": "remote_ngc",
                "account": session.account, "application": session.context.get("ApplicationDisplayName", ""),
                "session_id": "", "server_request_id": "", "remote_session_hash": fingerprint,
                "received_at": now, "expires_at": expires}, now)
            self.ngc_candidates[fingerprint] = (local_id, expires)
        self.ngc_capability("registration_required")

    async def add_request(self, fields, service):
        require(fields.get("flow", "classic_mfa") == "classic_mfa"
                and not any(isinstance(fields.get(k), str) and fields[k].lower() == "ngc"
                            for k in ("type", "sessiontype")), "classic_flow_required")
        requirements, context = approval.requirements(fields)
        now, mono = time.time(), time.monotonic()
        expires = min(request_expiry.timestamp(fields["expiration"]), now + 120)
        deadline = request_expiry.deadline(fields["expiration"], mono)
        scope = "synthetic" if self.synthetic else self.credentials.account.method_id
        digest = StateStore.digest(scope, fields["guid"])
        if self.store.consumed(digest) or digest in self.seen: return
        require(len(self.pending) < 32, "pending_request_limit")
        key = uuid.uuid4().hex
        item = Pending(key, fields, service, digest, expires, deadline, requirements, context)
        self.pending[key] = item; self.seen[digest] = now
        try:
            self.engine.add_request({"request_id": key, "account": fields["username"],
                "application": context.get("ApplicationDisplayName", ""), "session_id": fields.get("sasSessionId", ""),
                "server_request_id": fields["guid"], "received_at": now, "expires_at": expires}, now)
        except CorrelationError:
            # Unsupported ID format remains manual-only; never infer an ID.
            pass
        self.pending_event(item, "waiting_for_browser")
        await self.evaluate()
        return item

    def pending_event(self, item, status):
        if item.last_status == status: return
        item.last_status = status
        context = item.context
        location = {"latitude": context["Latitude"], "longitude": context["Longitude"]} if "Latitude" in context else None
        self.output("pending", request_id=item.local_id, account=item.fields["username"],
                    application=context.get("ApplicationDisplayName", "Microsoft sign-in"), location=location,
                    expires_at=item.expires_at, status=status,
                    manual_available=not (item.decision and item.decision.get("mode") == "automatic"),
                    app_context_required=item.requirements["app_context"], location_context_required=item.requirements["location_context"],
                    verification_required=item.requirements["app_lock"])

    def refresh_correlation_status(self):
        allowed = {"waiting_for_browser", "account_mismatch", "session_unmatched", "multiple_local_matches",
                   "multiple_request_matches", "unique_local_match", "request_context_unavailable",
                   "browser_context_not_fresh", "browser_context_conflict", "session_locked"}
        for item in tuple(self.pending.values()):
            if item.claimed or item.decision: continue
            reason = self.engine.diagnose(item.local_id, time.time())
            self.pending_event(item, reason if reason in allowed else "no_unique_local_match")

    async def evaluate(self):
        if self.paused or self.locked: return
        for item in tuple(self.pending.values()):
            if item.sending or item.claimed: continue
            if item.decision and item.decision.get("mode") == "automatic":
                if self.engine.match(item.local_id, time.time()) != item.decision["match"]:
                    item.decision = item.ticket = item.verified_at = None
            if item.decision is None and self.automatic and not item.auto_suppressed:
                match = self.engine.match(item.local_id, time.time())
                if match: item.decision = {"mode": "automatic", "number": match["number"], "match": match}
            if item.decision:
                await self.advance(item)
        self.refresh_correlation_status()

    def preflight(self, item, *, require_verification=True):
        require(item.fields.get("flow", "classic_mfa") == "classic_mfa", "classic_flow_required")
        require(not self.closed and not self.paused and not self.locked, "approval_unavailable")
        require(item.local_id in self.pending and time.monotonic() < item.deadline
                and time.time() < item.expires_at, "request_expired")
        require(item.decision is not None, "approval_decision_missing")
        if item.decision["mode"] == "automatic":
            require(self.automatic and self.engine.match(item.local_id, time.time()) == item.decision["match"], "correlation_no_longer_unique")
        require(not item.requirements["app_context"] or item.app_context_shown, "required_context_not_shown")
        require(not item.requirements["location_context"] or item.location_context_shown, "required_context_not_shown")
        if require_verification and item.requirements["app_lock"]:
            require(item.verified_at is not None and 0 <= time.monotonic() - item.verified_at <= 30, "fresh_system_verification_required")

    async def advance(self, item):
        if item.sending or item.claimed or item.ticket: return
        if (item.requirements["app_context"] and not item.app_context_shown
                or item.requirements["location_context"] and not item.location_context_shown):
            if not item.context_requested:
                item.context_requested = True
                self.pending_event(item, "show_context")
            return
        self.preflight(item, require_verification=False)
        if item.requirements["app_lock"] and item.verified_at is None:
            item.ticket = uuid.uuid4().hex
            self.output("verification_required", request_id=item.local_id, ticket_id=item.ticket,
                        reason="Verify this Microsoft sign-in", mode=item.decision["mode"])
            return
        self.preflight(item)
        item.sending = True
        task = asyncio.create_task(self.submit(item))
        self.approval_tasks.add(task)
        task.add_done_callback(self.approval_tasks.discard)

    async def submit(self, item):
        result, service_code = "cancelled_before_send", None
        try:
            self.preflight(item)
            # This is product authorization, not fabricated typed research consent.
            consent = approval.Consent(item.fields["guid"], item.decision["number"], item.deadline,
                item.verified_at is not None, item.app_context_shown, item.location_context_shown)
            def claim():
                self.preflight(item)
                require(self.store.claim(item.digest), "request_already_consumed")
                item.claimed = True
            if self.synthetic:
                claim()
                result, service_code = "synthetic_accepted", 6
            else:
                request = approval.number_request(self.credentials.account, item.service, item.fields, consent)
                # The user confirmed the classic Safari automatic path live.
                # Only an actual manual decision or system authentication is interactive.
                interactive = item.decision["mode"] == "manual" or item.verified_at is not None
                if not interactive:
                    root = ET.fromstring(request.body)
                    for element in root.iter():
                        if element.tag.split("}")[-1] == "completedInteractively": element.text = "no"
                    request = p.Request(request.url, request.headers, ET.tostring(root, encoding="utf-8", xml_declaration=True))
                body = await self.sender(request, claim)
                parsed = approval.number_response(body)
                service_code = parsed["number_validation_result"]
                result = "accepted" if parsed["number_approval_accepted"] else "rejected"
        except asyncio.CancelledError:
            result = "unknown" if item.claimed else "cancelled_before_send"
        except Exception:
            result = "unknown" if item.claimed else "cancelled_before_send"
        finally:
            if item.claimed: self.store.outcome(item.digest, result if result in ("accepted", "rejected", "synthetic_accepted") else "unknown")
            self.pending.pop(item.local_id, None); self.engine.remove_request(item.local_id)
            self.output("outcome", request_id=item.local_id, result=result, service_code=service_code)

    async def tick(self):
        now, mono = time.time(), time.monotonic()
        # Detect suspend/clock discontinuity even if the host missed a wake signal.
        if abs((now - self.last_wall) - (mono - self.last_tick)) > 5 or mono - self.last_tick > 10:
            self.engine.clear_browser(); self.invalidate_decisions()
        self.last_wall, self.last_tick = now, mono
        for key, item in tuple(self.pending.items()):
            if (mono >= item.deadline or now >= item.expires_at) and not item.sending:
                self.pending.pop(key, None); self.engine.remove_request(key)
                self.output("outcome", request_id=key, result="expired")
        self.seen = {key: value for key, value in self.seen.items() if now - value < 600}
        for fingerprint, (local_id, expires) in tuple(self.ngc_candidates.items()):
            if now >= expires:
                self.engine.remove_request(local_id)
                self.ngc_candidates.pop(fingerprint, None)

    async def demo(self, obj):
        require(not self.locked and not self.paused, "demo_session_locked_or_paused")
        verify = flag(obj, "require_verification") if "require_verification" in obj else True
        ambiguous = flag(obj, "ambiguous") if "ambiguous" in obj else False
        session = str(uuid.uuid4())
        fields = {"guid": str(uuid.uuid4()), "username": "demo@example.test", "sasSessionId": session,
                  "expiration": str(int(time.time()) + 90), "firstEntropyChallenge": "10", "secondEntropyChallenge": "20",
                  "thirdEntropyChallenge": "30", "isAppLockRequired": "yes" if verify else "no",
                  "authDetails": json.dumps({"ApplicationDisplayName": "Synthetic Safari sign-in", "Latitude": 0, "Longitude": 0})}
        # Add before request so there is no momentarily unique match in ambiguous test.
        for index in range(2 if ambiguous else 1):
            browser = {"version": 1, "kind": "challenge", "event_id": uuid.uuid4().hex,
                "tab_id": "demo-tab-" + str(index), "document_id": uuid.uuid4().hex,
                "origin": "https://login.microsoftonline.com", "observed_at": time.time(), "number": "42",
                "account": fields["username"], "application": "Synthetic Safari sign-in", "session_id": session,
                "request_id": "", "focused": True}
            self.engine.add_browser(browser, time.time())
        return await self.add_request(fields, "https://example.invalid")
