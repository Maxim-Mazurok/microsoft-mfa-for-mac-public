import Foundation
import CoreFoundation
import Darwin

enum ProductError: Error { case invalidMessage, unavailable, alreadyImported, failed }

enum Wire {
    static let maximumLineBytes = 262_144

    static func encode(_ value: [String: Any]) throws -> Data {
        var envelope = value
        envelope["version"] = 1
        var data = try JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])
        guard data.count < maximumLineBytes else { throw ProductError.invalidMessage }
        data.append(10)
        return data
    }

    static func decode(_ data: Data) throws -> [String: Any] {
        guard data.count < maximumLineBytes,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let version = value["version"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(), version.intValue == 1, version.doubleValue == 1,
              let event = value["event"] as? String,
              ["ready", "state", "pending", "verification_required", "outcome", "error", "capability"].contains(event)
        else { throw ProductError.invalidMessage }
        if event == "capability", PhoneSignInCapability(value) == nil { throw ProductError.invalidMessage }
        return value
    }

    static func safeCode(_ value: Any?, fallback: String = "operation_failed") -> String {
        guard let code = value as? String, !code.isEmpty, code.count <= 96,
              code.range(of: "^[a-z0-9_]+$", options: .regularExpression) != nil else { return fallback }
        return code
    }
}

/// Capability information is deliberately separate from an approvable request.
/// No account, number, server identifier or credential enters this fixed message.
struct PhoneSignInCapability: Equatable {
    enum Status: String, CaseIterable {
        case registrationRequired = "registration_required"
        case sessionBindingUnavailable = "session_binding_unavailable"
        case registeredCredentialUnavailable = "registered_credential_unavailable"
    }
    let status: Status

    init?(_ value: [String: Any]) {
        guard Set(value.keys) == ["version", "event", "flow", "status"],
              value["event"] as? String == "capability", value["flow"] as? String == "remote_ngc",
              let text = value["status"] as? String, let status = Status(rawValue: text) else { return nil }
        self.status = status
    }

    var title: String {
        switch status {
        case .registrationRequired: return "Phone sign-in needs its own registration"
        case .sessionBindingUnavailable: return "Phone sign-in could not be matched"
        case .registeredCredentialUnavailable: return "Phone sign-in key unavailable"
        }
    }

    var explanation: String {
        switch status {
        case .registrationRequired:
            return "This page uses passwordless phone sign-in. Your existing Mac registration handles classic MFA; phone sign-in requires a separately registered key. Nothing was approved."
        case .sessionBindingUnavailable:
            return "The request context needed to identify this phone sign-in is unavailable. The displayed number alone is not enough to approve it safely. Nothing was approved."
        case .registeredCredentialUnavailable:
            return "This request requires a registered phone sign-in key that this app cannot use. Your classic MFA registration is unchanged. Nothing was approved."
        }
    }

    var nextStep: String { "In Safari, choose your password or another existing sign-in option. Classic MFA remains available." }
}

enum PrivateFiles {
    /// Open first, then validate that descriptor. No follow-symlink / metadata-read race.
    static func readOwnerOnlyRegular(_ url: URL, maximumBytes: Int) -> Data? {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_uid == getuid(),
              info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o777 == 0o600,
              info.st_size >= 0 && info.st_size <= maximumBytes else { return nil }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        var offset = 0
        while offset < bytes.count {
            let remaining = bytes.count - offset
            let count = bytes.withUnsafeMutableBytes { buffer in
                read(descriptor, buffer.baseAddress!.advanced(by: offset), remaining)
            }
            guard count > 0 else { return nil }
            offset += count
        }
        return Data(bytes)
    }
}

/// Bounded framing prevents a broken child from accumulating unbounded output.
struct LineFramer {
    private var buffer = Data()
    mutating func append(_ data: Data) throws -> [Data] {
        buffer.append(data)
        var lines = [Data]()
        while let end = buffer.firstIndex(of: 10) {
            guard end < Wire.maximumLineBytes else { buffer.removeAll(); throw ProductError.invalidMessage }
            lines.append(buffer.subdata(in: 0..<end))
            buffer.removeSubrange(0...end)
        }
        guard buffer.count < Wire.maximumLineBytes else { buffer.removeAll(); throw ProductError.invalidMessage }
        return lines
    }
}

struct PendingRequest: Identifiable {
    let id: String
    let account: String
    let application: String
    let expiresAt: Date
    var status: String
    let manualAvailable: Bool
    let applicationRequired: Bool
    let locationRequired: Bool
    let location: String?

    init?(_ value: [String: Any]) {
        guard let id = value["request_id"] as? String, !id.isEmpty, id.count <= 128,
              let account = value["account"] as? String, account.count <= 320,
              let application = value["application"] as? String, application.count <= 256 else { return nil }
        let expiry: Date
        if let seconds = value["expires_at"] as? Double { expiry = Date(timeIntervalSince1970: seconds) }
        else if let text = value["expires_at"] as? String,
                let parsed = ISO8601DateFormatter().date(from: text) { expiry = parsed }
        else { return nil }
        self.id = id
        self.account = account
        self.application = application
        self.expiresAt = expiry
        self.status = Wire.safeCode(value["status"], fallback: "waiting")
        self.manualAvailable = value["manual_available"] as? Bool ?? false
        self.applicationRequired = value["app_context_required"] as? Bool ?? false
        self.locationRequired = value["location_context_required"] as? Bool ?? false
        if let coordinates = value["location"] as? [String: Any],
           let latitude = coordinates["latitude"] as? Double,
           let longitude = coordinates["longitude"] as? Double,
           latitude.isFinite, longitude.isFinite,
           (-90...90).contains(latitude), (-180...180).contains(longitude) {
            self.location = String(format: "%.3f, %.3f", latitude, longitude)
        } else { self.location = nil }
    }
}

struct RecentOutcome: Identifiable, Codable {
    let id: UUID
    let date: Date
    let result: String
    init(result: String) { self.id = UUID(); self.date = Date(); self.result = Wire.safeCode(result) }
}

/// Local tickets are one-use and short-lived. System success alone never survives lock/pause.
struct VerificationTicket {
    let requestID: String
    let ticketID: String
    let started: Date
    func canSubmit(now: Date, locked: Bool, paused: Bool, pendingIDs: Set<String>) -> Bool {
        !locked && !paused && now.timeIntervalSince(started) >= 0 &&
        now.timeIntervalSince(started) < 45 && pendingIDs.contains(requestID)
    }
}
