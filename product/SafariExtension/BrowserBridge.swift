import Foundation
import CoreFoundation
import Darwin

enum BrowserBridgeError: String, Error {
    case invalidMessage = "invalid_message"
    case unavailable = "app_unavailable"
    case containerUnavailable = "shared_container_unavailable"
    case queueFull = "queue_full"
    case localIO = "local_io_failure"
}

/// Browser data only. This component has no access to the product's Keychain credentials.
struct BrowserBridge {
    static let group = "group.org.example.microsoftmfamac"
    static let origins: Set<String> = ["https://login.microsoftonline.com", "https://login.microsoft.com", "https://login.windows.net"]
    private static let keys: Set<String> = ["version", "kind", "event_id", "tab_id", "document_id", "origin", "observed_at", "number", "account", "application", "session_id", "request_id", "focused", "flow", "remote_session_hash"]
    let container: URL?
    var now: () -> TimeInterval = { Date().timeIntervalSince1970 }

    static func configuredContainer(bundle: Bundle = .main) -> URL? {
        switch bundle.object(forInfoDictionaryKey: "MFABridgeMode") as? String {
        case "development":
            // Sandboxed Foundation home URLs point into the extension container.
            // The entitlement is scoped to this single real-user-home directory.
            guard let home = getpwuid(getuid())?.pointee.pw_dir else { return nil }
            return URL(fileURLWithPath: String(cString: home), isDirectory: true)
                .appendingPathComponent("Library/Application Support/org.example.microsoftmfamac/BrowserBridge", isDirectory: true)
        case "app-group":
            return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)
        default:
            return nil // Explicit build mode required; never silently change transport.
        }
    }

    init(container: URL? = configuredContainer(), now: @escaping () -> TimeInterval = { Date().timeIntervalSince1970 }) {
        self.container = container
        self.now = now
    }

    static func integer(_ value: Any?, equals expected: Int) -> Bool {
        guard let value = value as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID() else { return false }
        return value.doubleValue == Double(expected)
    }
    static func boolean(_ value: Any?) -> Bool? {
        guard let value = value as? NSNumber, CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
        return value.boolValue
    }
    static func matches(_ value: String, _ pattern: String) -> Bool { value.range(of: pattern, options: .regularExpression) != nil }

    static func validate(_ event: [String: Any], now: TimeInterval) -> Bool {
        guard Set(event.keys).isSubset(of: keys), integer(event["version"], equals: 1),
              let kind = event["kind"] as? String, ["challenge", "withdraw"].contains(kind),
              let origin = event["origin"] as? String, origins.contains(origin),
              let observed = event["observed_at"] as? NSNumber, CFGetTypeID(observed) != CFBooleanGetTypeID(),
              observed.doubleValue.isFinite, now - observed.doubleValue <= 120, observed.doubleValue - now <= 5,
              let focused = boolean(event["focused"]) else { return false }
        for key in ["event_id", "tab_id", "document_id"] {
            guard let value = event[key] as? String, matches(value, "^[a-zA-Z0-9_-]{1,80}$") else { return false }
        }
        if kind == "withdraw" { return !focused && event["number"] == nil && Set(event.keys).isSubset(of: ["version", "kind", "event_id", "tab_id", "document_id", "origin", "observed_at", "focused"]) }
        guard focused, let number = event["number"] as? String, matches(number, "^[0-9]{2}$"),
              let account = event["account"] as? String, account.count <= 254, account == account.lowercased(),
              matches(account, "^[^\\s<>@\\x00-\\x1f]+@[^\\s<>@\\x00-\\x1f]+\\.[^\\s<>@\\x00-\\x1f]+$"),
              let application = event["application"] as? String, application.count <= 160, !matches(application, "[\\x00-\\x1f<>]"),
              let session = event["session_id"] as? String, let request = event["request_id"] as? String else { return false }
        if event["flow"] != nil && !(event["flow"] is String) { return false }
        let flow = event["flow"] as? String ?? "classic_mfa"
        if flow == "remote_ngc" {
            guard session.isEmpty, request.isEmpty, let hash = event["remote_session_hash"] as? String else { return false }
            return hash.isEmpty || matches(hash, "^[a-f0-9]{64}$")
        }
        guard flow == "classic_mfa", !session.isEmpty || !request.isEmpty,
              event["remote_session_hash"] == nil || (event["remote_session_hash"] as? String) == "" else { return false }
        return [session, request].allSatisfy { $0.isEmpty || matches($0, "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") }
    }

    /// Opens an existing owner-controlled directory without following a final symlink.
    private func directory(_ url: URL) throws -> Int32 {
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw BrowserBridgeError.localIO }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), (info.st_mode & 0o022) == 0 else { close(fd); throw BrowserBridgeError.localIO }
        return fd
    }

    private func readHeartbeat(_ root: Int32) throws {
        let fd = openat(root, "heartbeat.json", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw BrowserBridgeError.unavailable }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), (info.st_mode & S_IFMT) == S_IFREG,
              (info.st_mode & 0o077) == 0, info.st_size > 0, info.st_size <= 1024 else { throw BrowserBridgeError.unavailable }
        var data = Data(count: Int(info.st_size))
        let count = data.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        guard count == data.count, let status = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Self.integer(status["version"], equals: 1), Self.boolean(status["available"]) == true,
              let timestamp = status["updated_at"] as? NSNumber, CFGetTypeID(timestamp) != CFBooleanGetTypeID(),
              timestamp.doubleValue.isFinite, now() - timestamp.doubleValue <= 15, timestamp.doubleValue - now() <= 2 else { throw BrowserBridgeError.unavailable }
    }

    func handle(_ message: Any) -> [String: Any] {
        do {
            guard let message = message as? [String: Any], Self.integer(message["version"], equals: 1),
                  let command = message["command"] as? String, ["status", "browser_event"].contains(command),
                  Set(message.keys) == (command == "status" ? ["version", "command"] : ["version", "command", "browser"]) else { throw BrowserBridgeError.invalidMessage }
            var browserEvent: [String: Any]?
            if command == "browser_event" {
                guard let event = message["browser"] as? [String: Any], Self.validate(event, now: now()) else { throw BrowserBridgeError.invalidMessage }
                browserEvent = event
            }
            guard let container else { throw BrowserBridgeError.containerUnavailable }
            let root = try directory(container); defer { close(root) }
            try readHeartbeat(root)
            guard let browserEvent else { return ["ok": true, "status": "ready"] }
            if mkdirat(root, "BrowserEvents", 0o700) != 0 && errno != EEXIST { throw BrowserBridgeError.localIO }
            let inboxURL = container.appendingPathComponent("BrowserEvents", isDirectory: true)
            let inbox = try directory(inboxURL); defer { close(inbox) }
            var inboxInfo = stat()
            guard fstat(inbox, &inboxInfo) == 0, (inboxInfo.st_mode & 0o077) == 0 else { throw BrowserBridgeError.localIO }
            let files = try FileManager.default.contentsOfDirectory(atPath: inboxURL.path)
            guard files.count < 100 else { throw BrowserBridgeError.queueFull }
            let data = try JSONSerialization.data(withJSONObject: browserEvent, options: [.sortedKeys])
            guard data.count <= 4096 else { throw BrowserBridgeError.invalidMessage }
            let identifier = UUID().uuidString
            let order = String(format: "%020lld", Int64(now() * 1_000_000))
            let temporary = ".\(identifier).tmp", final = "\(order)-\(identifier).json"
            let file = openat(inbox, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard file >= 0 else { throw BrowserBridgeError.localIO }
            defer { close(file); unlinkat(inbox, temporary, 0) }
            let written = data.withUnsafeBytes { write(file, $0.baseAddress, $0.count) }
            guard written == data.count, fsync(file) == 0, renameat(inbox, temporary, inbox, final) == 0 else { throw BrowserBridgeError.localIO }
            return ["ok": true, "status": "delivered"]
        } catch let error as BrowserBridgeError { return ["ok": false, "status": error.rawValue] }
        catch { return ["ok": false, "status": BrowserBridgeError.localIO.rawValue] }
    }
}
