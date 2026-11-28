"""No credentials, network or real sign-ins. Correlation failure cases matter."""
from pathlib import Path
import sys
import unittest
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service"))
from correlation import CorrelationEngine, CorrelationError

NOW = 1700000000.0
SID = "11111111-1111-4111-8111-111111111111"
RID = "22222222-2222-4222-8222-222222222222"
OTHER = "33333333-3333-4333-8333-333333333333"
BROWSER = {"version": 1, "kind": "challenge", "event_id": "event-1", "tab_id": "tab-1", "document_id": "document-1",
           "origin": "https://login.microsoftonline.com", "observed_at": NOW, "number": "42",
           "account": "synthetic@example.invalid", "application": "Synthetic app", "session_id": SID,
           "request_id": "", "focused": True}
REQUEST = {"request_id": "local-1", "account": "synthetic@example.invalid", "application": "Synthetic app",
           "session_id": SID, "server_request_id": RID, "received_at": NOW, "expires_at": NOW + 60}
REMOTE_HASH = hashlib.sha256(b"remote_ngc\0synthetic-opaque-session").hexdigest()
REMOTE_BROWSER = {**BROWSER, "flow": "remote_ngc", "session_id": "", "request_id": "", "remote_session_hash": REMOTE_HASH}
REMOTE_REQUEST = {**REQUEST, "flow": "remote_ngc", "session_id": "", "server_request_id": "", "remote_session_hash": REMOTE_HASH}


class Correlation(unittest.TestCase):
    def engine(self, browser=BROWSER, request=REQUEST):
        e = CorrelationEngine(); e.add_browser(browser, NOW); e.add_request(request, NOW)
        return e

    def test_exact_session_and_account_works_case_insensitively(self):
        e = self.engine({**BROWSER, "account": "Synthetic@Example.Invalid", "session_id": SID.upper()})
        self.assertEqual(e.match("local-1", NOW)["number"], "42")
        self.assertEqual(e.match("local-1", NOW)["evidence"], "exact_session_id")

    def test_number_and_account_without_shared_identifier_rejected(self):
        with self.assertRaisesRegex(CorrelationError, "shared_session_identifier_required"):
            self.engine({**BROWSER, "session_id": ""})
        e = self.engine({**BROWSER, "session_id": OTHER})
        self.assertIsNone(e.match("local-1", NOW))

    def test_other_account_or_application_never_matches(self):
        for changed in ({"account": "other@example.invalid"}, {"application": "Different app"}):
            with self.subTest(changed=changed): self.assertIsNone(self.engine({**BROWSER, **changed}).match("local-1", NOW))

    def test_exact_request_identifier_alternative_and_conflicting_ids(self):
        self.assertEqual(self.engine({**BROWSER, "session_id": "", "request_id": RID}).match("local-1", NOW)["evidence"], "exact_request_id")
        self.assertIsNone(self.engine({**BROWSER, "request_id": OTHER}).match("local-1", NOW))

    def test_multiple_tabs_are_ambiguous_even_with_same_number(self):
        e = self.engine(); e.add_browser({**BROWSER, "event_id": "event-2", "tab_id": "tab-2"}, NOW)
        self.assertIsNone(e.match("local-1", NOW))

    def test_multiple_requests_for_one_session_are_ambiguous(self):
        e = self.engine(); e.add_request({**REQUEST, "request_id": "local-2", "server_request_id": OTHER}, NOW)
        self.assertIsNone(e.match("local-1", NOW)); self.assertIsNone(e.match("local-2", NOW))

    def test_expired_requests_and_stale_browser_events(self):
        self.assertIsNone(self.engine().match("local-1", NOW + 60))
        with self.assertRaises(CorrelationError): self.engine({**BROWSER, "observed_at": NOW - 100})
        with self.assertRaises(CorrelationError): self.engine({**BROWSER, "observed_at": NOW + 5})
        e = self.engine({**BROWSER, "observed_at": NOW - 61})
        self.assertIsNone(e.match("local-1", NOW))

    def test_duplicate_updates_do_not_extend_lifetime(self):
        e = self.engine(); e.add_browser({**BROWSER, "observed_at": NOW + 50}, NOW + 50)
        self.assertEqual(e.browser_events[("tab-1", "document-1")]["observed_at"], NOW)
        with self.assertRaisesRegex(CorrelationError, "conflicting_browser_duplicate"):
            e.add_browser({**BROWSER, "number": "43", "observed_at": NOW + 50}, NOW + 50)

    def test_withdraw_and_document_reordering_prevent_resurrection(self):
        e = self.engine(); e.add_browser({**BROWSER, "kind": "withdraw", "observed_at": NOW + 1}, NOW + 1)
        self.assertIsNone(e.match("local-1", NOW + 1))
        with self.assertRaises(CorrelationError): e.add_browser(BROWSER, NOW + 1)
        e.add_browser({**BROWSER, "event_id": "event-2", "document_id": "document-2", "observed_at": NOW + 2}, NOW + 2)
        e.add_browser({**BROWSER, "event_id": "event-3", "document_id": "document-3", "observed_at": NOW + 3}, NOW + 3)
        with self.assertRaises(CorrelationError):
            e.add_browser({**BROWSER, "event_id": "event-4", "document_id": "document-2", "observed_at": NOW + 4}, NOW + 4)

    def test_lock_and_pause_clear_events_and_require_new_evidence(self):
        e = self.engine(); e.set_locked(True); self.assertIsNone(e.match("local-1", NOW))
        e.set_locked(False); self.assertIsNone(e.match("local-1", NOW))
        with self.assertRaises(CorrelationError): e.add_browser(BROWSER, NOW)
        e.add_browser({**BROWSER, "event_id": "after-unlock"}, NOW)
        self.assertIsNotNone(e.match("local-1", NOW))
        e.clear_browser(); self.assertIsNone(e.match("local-1", NOW))

    def test_withdrawal_arriving_before_challenge_still_invalidates_it(self):
        e = CorrelationEngine()
        e.add_browser({**BROWSER, "kind": "withdraw", "event_id": "withdraw-1", "observed_at": NOW + 1}, NOW + 1)
        with self.assertRaisesRegex(CorrelationError, "withdrawn_browser_context"):
            e.add_browser(BROWSER, NOW + 1)
        e.add_browser({**BROWSER, "event_id": "fresh-after-withdrawal", "observed_at": NOW + 2}, NOW + 2)
        e.add_request(REQUEST, NOW + 2)
        self.assertIsNotNone(e.match("local-1", NOW + 2))

    def test_origins_schemas_and_types_fail_closed(self):
        for changes in ({"origin": "http://login.microsoftonline.com"}, {"origin": "https://login.microsoftonline.com.evil.invalid"},
                        {"origin": "https://login.microsoftonline.com:443"}, {"origin": "https://login.microsoftonline.com/path"},
                        {"number": 42}, {"number": "100"}, {"focused": "true"}, {"observed_at": float('nan')},
                        {"observed_at": True}, {"session_id": "opaque-flow-token"}, {"flowToken": "forbidden"},
                        {"origin": []}, {"origin": {}}, {"application": False}, {"application": []}):
            with self.subTest(changes=changes), self.assertRaises(CorrelationError): self.engine({**BROWSER, **changes})

    def test_request_collision_never_replaces_identity(self):
        e = self.engine()
        with self.assertRaises(CorrelationError): e.add_request({**REQUEST, "account": "other@example.invalid"}, NOW)
        self.assertIsNotNone(e.match("local-1", NOW))

    def test_redacted_diagnostics_do_not_return_context(self):
        e = CorrelationEngine(); e.add_request(REQUEST, NOW)
        self.assertEqual(e.diagnose("local-1", NOW), "waiting_for_browser")
        for change, expected in (({"account": "other@example.invalid"}, "account_mismatch"),
                                 ({"session_id": OTHER}, "session_unmatched"),
                                 ({"application": "Other app"}, "browser_context_conflict"),
                                 ({}, "unique_local_match")):
            with self.subTest(expected=expected):
                self.assertEqual(self.engine({**BROWSER, **change}).diagnose("local-1", NOW), expected)
        e = self.engine(); e.add_browser({**BROWSER, "tab_id": "tab-2", "event_id": "event-2"}, NOW)
        self.assertEqual(e.diagnose("local-1", NOW), "multiple_local_matches")
        e = self.engine(); e.add_request({**REQUEST, "request_id": "local-2"}, NOW)
        self.assertEqual(e.diagnose("local-1", NOW), "multiple_request_matches")

    def test_limits_do_not_evict_valid_request_to_choose_new_one(self):
        e = CorrelationEngine()
        for i in range(32): e.add_browser({**BROWSER, "tab_id": f"tab-{i}", "event_id": f"event-{i}"}, NOW)
        with self.assertRaises(CorrelationError): e.add_browser({**BROWSER, "tab_id": "overflow"}, NOW)

    def test_remote_requires_exact_fingerprint_and_account(self):
        e = self.engine(REMOTE_BROWSER, REMOTE_REQUEST)
        self.assertEqual(e.match("local-1", NOW)["evidence"], "exact_remote_session_hash")
        for change in ({"remote_session_hash": "a" * 64}, {"remote_session_hash": ""}, {"account": "other@example.invalid"}):
            with self.subTest(change=change):
                self.assertIsNone(self.engine({**REMOTE_BROWSER, **change}, REMOTE_REQUEST).match("local-1", NOW))

    def test_similar_number_and_account_never_cross_authentication_flows(self):
        self.assertIsNone(self.engine(REMOTE_BROWSER, REQUEST).match("local-1", NOW))
        self.assertIsNone(self.engine(BROWSER, REMOTE_REQUEST).match("local-1", NOW))
        self.assertEqual(self.engine(REMOTE_BROWSER, REQUEST).diagnose("local-1", NOW), "authentication_flow_mismatch")

    def test_remote_cannot_substitute_classic_uuid_or_export_raw_blob(self):
        for change in ({"session_id": SID}, {"request_id": RID}, {"remote_session_hash": "raw-session"},
                       {"remote_session_hash": "A" * 64}, {"remote_session_id": "forbidden"}, {"flow": "unknown"}):
            with self.subTest(change=change), self.assertRaises(CorrelationError):
                self.engine({**REMOTE_BROWSER, **change}, REMOTE_REQUEST)
        with self.assertRaises(CorrelationError): self.engine({**BROWSER, "remote_session_hash": REMOTE_HASH})
        with self.assertRaises(CorrelationError): self.engine(REMOTE_BROWSER, {**REMOTE_REQUEST, "remote_session_hash": ""})

    def test_remote_detection_only_is_never_an_approval_match(self):
        e = self.engine({**REMOTE_BROWSER, "remote_session_hash": ""}, REMOTE_REQUEST)
        self.assertIsNone(e.match("local-1", NOW))
        self.assertEqual(e.diagnose("local-1", NOW), "remote_session_binding_unavailable")

    def test_remote_multiple_tabs_and_expiration_remain_guarded(self):
        e = self.engine(REMOTE_BROWSER, REMOTE_REQUEST)
        e.add_browser({**REMOTE_BROWSER, "event_id": "remote-2", "tab_id": "remote-2"}, NOW)
        self.assertIsNone(e.match("local-1", NOW))
        self.assertIsNone(self.engine(REMOTE_BROWSER, REMOTE_REQUEST).match("local-1", NOW + 60))

    def test_flow_changes_cannot_mutate_existing_browser_event(self):
        e = self.engine()
        with self.assertRaisesRegex(CorrelationError, "conflicting_browser_duplicate"):
            e.add_browser(REMOTE_BROWSER, NOW)


if __name__ == "__main__": unittest.main()
