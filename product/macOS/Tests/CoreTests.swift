import XCTest
@testable import MFANativeCore

final class CoreTests: XCTestCase {
    func testPartialAndMultipleLineFraming() throws {
        var framer = LineFramer()
        XCTAssertEqual(try framer.append(Data("{\"version\":1,".utf8)).count, 0)
        let lines = try framer.append(Data("\"event\":\"ready\"}\n{\"version\":1,\"event\":\"state\"}\n".utf8))
        XCTAssertEqual(lines.count, 2)
        XCTAssertEqual(try Wire.decode(lines[0])["event"] as? String, "ready")
    }
    func testOversizeChildOutputRejected() {
        var framer = LineFramer()
        XCTAssertThrowsError(try framer.append(Data(repeating: 65, count: Wire.maximumLineBytes)))
    }
    func testUnknownProtocolVersionOrEventRejected() {
        for text in ["{\"version\":2,\"event\":\"ready\"}", "{\"version\":true,\"event\":\"ready\"}", "{\"version\":1,\"event\":\"credentials\"}"] {
            XCTAssertThrowsError(try Wire.decode(Data(text.utf8)))
        }
    }
    func testRemotePhoneSignInCapabilityAllowsOnlyFixedStatuses() throws {
        for status in PhoneSignInCapability.Status.allCases {
            let value: [String: Any] = ["version": 1, "event": "capability", "flow": "remote_ngc", "status": status.rawValue]
            let decoded = try Wire.decode(JSONSerialization.data(withJSONObject: value))
            XCTAssertEqual(PhoneSignInCapability(decoded)?.status, status)
            XCTAssertNil(PendingRequest(decoded), "Capability information must not become an approvable pending request")
        }
    }
    func testRemotePhoneSignInCapabilityRejectsUnknownFlowStatusAndPrivateFields() throws {
        let valid: [String: Any] = ["version": 1, "event": "capability", "flow": "remote_ngc", "status": "registration_required"]
        for (key, value) in [("flow", "classic_mfa"), ("flow", "unknown"), ("status", "approved"), ("status", "https://invalid.example/private"), ("number", "42"), ("session_identifier", "synthetic-private-value")] {
            var invalid = valid; invalid[key] = value
            XCTAssertThrowsError(try Wire.decode(JSONSerialization.data(withJSONObject: invalid)))
        }
        var missing = valid; missing.removeValue(forKey: "status")
        XCTAssertThrowsError(try Wire.decode(JSONSerialization.data(withJSONObject: missing)))
    }
    func testClassicPendingEnvelopeRemainsUnchanged() throws {
        let value: [String: Any] = ["version": 1, "event": "pending", "request_id": "local-classic", "account": "synthetic@example.invalid", "application": "Classic MFA", "expires_at": Date().addingTimeInterval(60).timeIntervalSince1970, "manual_available": true]
        let decoded = try Wire.decode(JSONSerialization.data(withJSONObject: value))
        XCTAssertNotNil(PendingRequest(decoded))
        XCTAssertNil(PhoneSignInCapability(decoded))
    }
    func testPrivateErrorCannotBecomeHistoryCode() {
        XCTAssertEqual(Wire.safeCode("https://host.invalid/?token=private"), "operation_failed")
        XCTAssertEqual(Wire.safeCode("approval_accepted"), "approval_accepted")
    }
    func testContextInvalidCoordinatesOmitted() {
        let request: [String: Any] = ["request_id": "local-1", "account": "synthetic@example.invalid", "application": "Practice", "expires_at": Date().addingTimeInterval(60).timeIntervalSince1970, "location": ["latitude": 500, "longitude": 0], "manual_available": true]
        XCTAssertNotNil(PendingRequest(request))
        XCTAssertNil(PendingRequest(request)?.location)
    }
    func testMalformedPendingDoesNotReachUI() {
        XCTAssertNil(PendingRequest(["request_id": "local-1", "account": "synthetic@example.invalid", "application": "Practice", "expires_at": "invalid"]))
    }
    func testVerificationTicketExpiresAndCannotSurviveLockPauseOrRemoval() {
        let now = Date(timeIntervalSince1970: 100)
        let ticket = VerificationTicket(requestID: "local-1", ticketID: "ticket-1", started: now)
        XCTAssertTrue(ticket.canSubmit(now: now.addingTimeInterval(1), locked: false, paused: false, pendingIDs: ["local-1"]))
        XCTAssertFalse(ticket.canSubmit(now: now.addingTimeInterval(46), locked: false, paused: false, pendingIDs: ["local-1"]))
        XCTAssertFalse(ticket.canSubmit(now: now, locked: true, paused: false, pendingIDs: ["local-1"]))
        XCTAssertFalse(ticket.canSubmit(now: now, locked: false, paused: true, pendingIDs: ["local-1"]))
        XCTAssertFalse(ticket.canSubmit(now: now, locked: false, paused: false, pendingIDs: []))
    }
    func testOutcomeEncodingHasNoRequestOrAccount() throws {
        let data = try JSONEncoder().encode(RecentOutcome(result: "approval_accepted"))
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(json.keys), ["id", "date", "result"])
    }
    func testInboxRejectsSymlinkPublicModeAndOversizeFile() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("invented.json")
        try Data("invented".utf8).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        XCTAssertEqual(PrivateFiles.readOwnerOnlyRegular(file, maximumBytes: 100), Data("invented".utf8))
        XCTAssertNil(PrivateFiles.readOwnerOnlyRegular(file, maximumBytes: 2))
        let link = directory.appendingPathComponent("link.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        XCTAssertNil(PrivateFiles.readOwnerOnlyRegular(link, maximumBytes: 100))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        XCTAssertNil(PrivateFiles.readOwnerOnlyRegular(file, maximumBytes: 100))
        XCTAssertNil(PrivateFiles.readOwnerOnlyRegular(directory, maximumBytes: 100))
    }
}
