import Foundation
import Darwin

@main struct BridgeTests {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("mfa-bridge-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let now: Double = 1000
        var checks = 0
        func expect(_ result: Bool) { checks += 1; precondition(result, "Synthetic bridge check failed") }
        func heartbeat(_ time: Double) throws {
            let data = try JSONSerialization.data(withJSONObject: ["version": 1, "available": true, "updated_at": time])
            try data.write(to: root.appendingPathComponent("heartbeat.json"), options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: root.appendingPathComponent("heartbeat.json").path)
        }
        let bridge = BrowserBridge(container: root, now: { now })
        let modeBundleURL = root.appendingPathComponent("ModeProbe.bundle")
        try FileManager.default.createDirectory(at: modeBundleURL, withIntermediateDirectories: true)
        let modeInfo = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "org.example.synthetic.ModeProbe", "MFABridgeMode": "development"], format: .xml, options: 0)
        try modeInfo.write(to: modeBundleURL.appendingPathComponent("Info.plist"))
        let modeBundle = Bundle(url: modeBundleURL)!
        expect(BrowserBridge.configuredContainer(bundle: modeBundle)?.path.hasSuffix("Library/Application Support/org.example.microsoftmfamac/BrowserBridge") == true)
        expect(BrowserBridge.configuredContainer(bundle: .main) == nil)
        let status: [String: Any] = ["version": 1, "command": "status"]
        expect(bridge.handle(status)["status"] as? String == "app_unavailable")
        expect(BrowserBridge(container: nil).handle(status)["status"] as? String == "shared_container_unavailable")
        try heartbeat(now)
        expect(bridge.handle(status)["status"] as? String == "ready")
        let event: [String: Any] = ["version": 1, "kind": "challenge", "event_id": "event", "tab_id": "tab", "document_id": "doc", "origin": "https://login.microsoftonline.com", "observed_at": now, "number": "42", "account": "user@example.invalid", "application": "Synthetic", "session_id": "11111111-2222-4333-8444-555555555555", "request_id": "", "focused": true]
        expect(BrowserBridge.validate(event, now: now))
        let remote = event.merging(["flow": "remote_ngc", "session_id": "", "remote_session_hash": ""], uniquingKeysWith: { _, new in new })
        expect(BrowserBridge.validate(remote, now: now))
        expect(BrowserBridge.validate(remote.merging(["remote_session_hash": String(repeating: "a", count: 64)], uniquingKeysWith: { _, new in new }), now: now))
        for patch: [String: Any] in [["flow": "other"], ["flow": true], ["session_id": "11111111-2222-4333-8444-555555555555"], ["remote_session_hash": "opaque-raw-session"], ["remote_session_hash": String(repeating: "A", count: 64)], ["SessionIdentifier": "do-not-accept"]] {
            expect(!BrowserBridge.validate(remote.merging(patch, uniquingKeysWith: { _, new in new }), now: now))
        }
        expect(!BrowserBridge.validate(event.merging(["remote_session_hash": String(repeating: "a", count: 64)], uniquingKeysWith: { _, new in new }), now: now))
        for patch: [String: Any] in [["version": true], ["focused": 1], ["number": "142"], ["session_id": "fuzzy"], ["account": ""], ["flowToken": "synthetic-rejected"], ["origin": "https://evil.invalid"], ["observed_at": now - 121]] {
            expect(!BrowserBridge.validate(event.merging(patch, uniquingKeysWith: { _, new in new }), now: now))
        }
        expect(bridge.handle(["version": 1, "command": "browser_event", "browser": event])["status"] as? String == "delivered")
        let inbox = root.appendingPathComponent("BrowserEvents")
        let files = try FileManager.default.contentsOfDirectory(at: inbox, includingPropertiesForKeys: nil)
        expect(files.count == 1 && files[0].pathExtension == "json")
        let attrs = try FileManager.default.attributesOfItem(atPath: files[0].path)
        expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        expect(bridge.handle(["version": 1, "command": "manual_approve", "number": "42"])["status"] as? String == "invalid_message")
        try heartbeat(now - 16)
        expect(bridge.handle(status)["status"] as? String == "app_unavailable")
        try heartbeat(now + 3)
        expect(bridge.handle(status)["status"] as? String == "app_unavailable")
        try heartbeat(now)
        try FileManager.default.removeItem(at: inbox)
        try FileManager.default.createSymbolicLink(at: inbox, withDestinationURL: root)
        expect(bridge.handle(["version": 1, "command": "browser_event", "browser": event])["status"] as? String == "local_io_failure")
        print("Safari native bridge: \(checks) synthetic checks passed")
    }
}
