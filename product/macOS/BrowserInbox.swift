import Foundation
import Darwin

final class BrowserInbox {
    static let group = "group.org.example.microsoftmfamac"
    static var mode: String { Bundle.main.object(forInfoDictionaryKey: "MFABridgeMode") as? String ?? "unconfigured" }
    static func configuredContainer() -> URL? {
        switch mode {
        case "app-group": return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
        case "development":
            guard let home = getpwuid(getuid())?.pointee.pw_dir else { return nil }
            return URL(fileURLWithPath: String(cString: home), isDirectory: true)
                .appendingPathComponent("Library/Application Support/org.example.microsoftmfamac/BrowserBridge", isDirectory: true)
        default: return nil
        }
    }
    var onBrowser: (([String: Any]) -> Void)?
    var isAvailable: (() -> Bool)?
    var onStatus: ((Bool) -> Void)?
    private var timer: Timer?
    private var container: URL?
    private(set) var failureCode: String?
    private var lastStatus: Bool?
    private(set) var ready = false

    func start() {
        container = Self.configuredContainer()
        guard let container else { failureCode = "container_unavailable"; status(false); return }
        do {
            try FileManager.default.createDirectory(at: container, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let rootAttributes = try FileManager.default.attributesOfItem(atPath: container.path)
            guard rootAttributes[.type] as? FileAttributeType == .typeDirectory,
                  (rootAttributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
                  (rootAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700
            else { throw ProductError.unavailable }
            let inbox = container.appendingPathComponent("BrowserEvents", isDirectory: true)
            try FileManager.default.createDirectory(at: inbox, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let attributes = try FileManager.default.attributesOfItem(atPath: inbox.path)
            guard attributes[.type] as? FileAttributeType == .typeDirectory,
                  (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid()
            else { throw ProductError.unavailable }
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: inbox.path)
            status(true)
            tick()
            timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.tick() }
        } catch { failureCode = "inbox_setup_\((error as NSError).code)"; status(false) }
    }

    func stop() {
        timer?.invalidate(); timer = nil
        if let container { try? FileManager.default.removeItem(at: container.appendingPathComponent("heartbeat.json")) }
    }

    private func tick() {
        guard let container else { return }
        let available = isAvailable?() ?? false
        do {
            let heartbeat = try JSONSerialization.data(withJSONObject: ["version": 1, "updated_at": Date().timeIntervalSince1970, "available": available])
            let heartbeatURL = container.appendingPathComponent("heartbeat.json")
            try heartbeat.write(to: heartbeatURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: heartbeatURL.path)
            let inbox = container.appendingPathComponent("BrowserEvents")
            let files = try FileManager.default.contentsOfDirectory(at: inbox, includingPropertiesForKeys: nil)
                .filter { $0.pathExtension == "json" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
            var messages = [(String, [String: Any])]()
            for file in files.prefix(100) {
                defer { try? FileManager.default.removeItem(at: file) }
                guard available,
                      let data = PrivateFiles.readOwnerOnlyRegular(file, maximumBytes: 8192),
                      let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      payload["version"] as? Int == 1 else { continue }
                messages.append((file.lastPathComponent, payload))
            }
            messages.sort {
                let left = $0.1["observed_at"] as? Double ?? 0, right = $1.1["observed_at"] as? Double ?? 0
                if left != right { return left < right }
                let leftWithdraw = $0.1["kind"] as? String == "withdraw", rightWithdraw = $1.1["kind"] as? String == "withdraw"
                if leftWithdraw != rightWithdraw { return leftWithdraw }
                return $0.0 < $1.0
            }
            // The service revalidates schema/origin/freshness and tombstones withdrawals.
            for (_, payload) in messages { onBrowser?(payload) }
            failureCode = nil; status(true)
        } catch { failureCode = "inbox_poll_\((error as NSError).code)"; status(false) }
    }

    private func status(_ available: Bool) {
        ready = available
        if lastStatus != available { lastStatus = available; onStatus?(available) }
    }

}
