import Foundation
import CoreFoundation
import Darwin

public enum BootstrapError: String, Error {
    case invalidInput = "invalid_input"
    case invalidDestination = "invalid_destination"
    case expiredInput = "expired_input"
    case invalidCallback = "invalid_callback"
    case privateStorageUnavailable = "private_storage_unavailable"
    case alreadyAttempted = "session_already_attempted"
    case outputExists = "output_already_exists"
    case callbackTooLarge = "callback_too_large"
    case callbackDestinationMismatch = "callback_destination_mismatch"
    case callbackPathMismatch = "callback_path_mismatch"
    case callbackDuplicateParameter = "callback_duplicate_parameter"
    case callbackStateMismatch = "callback_state_mismatch"
    case callbackFieldsUnsupported = "callback_fields_unsupported"
    case callbackPayloadInvalid = "callback_payload_invalid"
    case nativeReportExists = "native_report_already_exists"
    case nativeReportUnavailable = "native_report_unavailable"
}

public struct BootstrapInput {
    public static let scheme = "msauth"
    public static let host = "Microsoft.AAD.BrokerPlugin"
    public static let path = ""
    public static let redirect = scheme + "://" + host + path
    public static let clientID = "29d9ed98-a469-4536-ade2-f981bc1d605e"
    public static let maximumBytes = 65_536
    public let authorizeURL: URL
    public let state: String
    public let expiresAt: TimeInterval

    public init(data: Data, now: TimeInterval = Date().timeIntervalSince1970) throws {
        guard data.count <= Self.maximumBytes,
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(value.keys) == ["v", "experiment", "authorize_url", "authorize_endpoint", "tenant_id", "callback_scheme", "callback_host", "callback_path", "state", "expires_at"],
              let version = value["v"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), version.doubleValue == 1,
              value["experiment"] as? String == "WPJ-A01",
              value["callback_scheme"] as? String == Self.scheme,
              value["callback_host"] as? String == Self.host,
              value["callback_path"] as? String == Self.path,
              let state = value["state"] as? String, Self.matches(state, "^[A-Za-z0-9_-]{43}$"),
              let expiry = value["expires_at"] as? NSNumber, CFGetTypeID(expiry) != CFBooleanGetTypeID(), expiry.doubleValue.isFinite,
              expiry.doubleValue.rounded(.towardZero) == expiry.doubleValue,
              let tenant = value["tenant_id"] as? String, Self.isUUID(tenant),
              let endpoint = value["authorize_endpoint"] as? String,
              let source = value["authorize_url"] as? String, source.utf8.count <= Self.maximumBytes,
              let url = URL(string: source), let parts = URLComponents(url: url, resolvingAgainstBaseURL: false)
        else { throw BootstrapError.invalidInput }
        guard expiry.doubleValue > now, expiry.doubleValue <= now + 600 else { throw BootstrapError.expiredInput }
        guard parts.scheme == "https", ["login.microsoftonline.com", "login.windows.net", "login.microsoft.com"].contains(parts.host ?? ""),
              parts.user == nil, parts.password == nil, parts.port == nil, parts.fragment == nil,
              let endpointURL = URL(string: endpoint), let base = URLComponents(url: endpointURL, resolvingAgainstBaseURL: false),
              base.scheme == parts.scheme, base.host == parts.host, base.percentEncodedPath == parts.percentEncodedPath,
              base.query == nil, base.fragment == nil, base.user == nil, base.password == nil, base.port == nil
        else { throw BootstrapError.invalidDestination }
        let components = parts.percentEncodedPath.split(separator: "/", omittingEmptySubsequences: false)
        guard components.count == 5, components[0].isEmpty, components[2] == "oauth2", components[3] == "v2.0", components[4] == "authorize",
              [tenant.lowercased(), "common", "organizations"].contains(String(components[1]).lowercased()),
              let items = Self.formQueryItems(parts) else { throw BootstrapError.invalidDestination }
        let query = try Self.uniqueQuery(items, error: .invalidInput)
        guard Set(query.keys) == ["client_id", "redirect_uri", "response_type", "response_mode", "scope", "login_hint", "hsu", "state", "code_challenge", "code_challenge_method", "msafed"],
              query["client_id"] == Self.clientID, query["redirect_uri"] == Self.redirect,
              query["response_type"] == "code", query["response_mode"] == "query", query["state"] == state,
              query["code_challenge_method"] == "S256", Self.matches(query["code_challenge"] ?? "", "^[A-Za-z0-9_-]{43}$"),
              query["hsu"] == "1", query["msafed"] == "0",
              let hint = query["login_hint"], hint.count <= 320, Self.matches(hint, "^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$"),
              let scope = query["scope"], Self.validScopes(scope)
        else { throw BootstrapError.invalidInput }
        self.authorizeURL = url
        self.state = state
        self.expiresAt = expiry.doubleValue
    }

    public func callbackData(_ url: URL, now: TimeInterval = Date().timeIntervalSince1970) throws -> (Data, Bool) {
        guard now < expiresAt else { throw BootstrapError.expiredInput }
        guard url.absoluteString.utf8.count <= Self.maximumBytes else { throw BootstrapError.callbackTooLarge }
        guard let parts = URLComponents(url: url, resolvingAgainstBaseURL: false), parts.scheme == Self.scheme,
              parts.host?.lowercased() == Self.host.lowercased(), parts.user == nil, parts.password == nil, parts.port == nil, parts.fragment == nil
        else { throw BootstrapError.callbackDestinationMismatch }
        guard Self.callbackPathMatches(parts.percentEncodedPath) else { throw BootstrapError.callbackPathMismatch }
        guard let items = Self.formQueryItems(parts), items.count <= 16 else { throw BootstrapError.callbackPayloadInvalid }
        let values = try Self.uniqueQuery(items, error: .callbackDuplicateParameter)
        guard values["state"] == state else { throw BootstrapError.callbackStateMismatch }
        guard (values["code"] != nil) != (values["error"] != nil),
              values.keys.allSatisfy({ $0.utf8.count <= 32768 }),
              values.values.allSatisfy({ $0.utf8.count <= 32768 }),
              values["code"].map({ !$0.isEmpty && $0.utf8.count <= 16384 && $0.utf8.allSatisfy { (32...126).contains($0) } }) ?? true,
              values["error"].map({ !$0.isEmpty }) ?? true else { throw BootstrapError.callbackPayloadInvalid }
        // RFC 6749 section 4.1.2 requires ignoring unrecognized response fields.
        // Only state/code/error control acceptance; all other metadata is inert.
        let data = try JSONSerialization.data(withJSONObject: ["v": 1, "experiment": "WPJ-A01", "callback_url": url.absoluteString], options: [.sortedKeys])
        guard data.count <= Self.maximumBytes else { throw BootstrapError.invalidCallback }
        return (data, values["code"] != nil)
    }

    static func matches(_ value: String, _ pattern: String) -> Bool { value.range(of: pattern, options: .regularExpression) != nil }
    static func callbackPathMatches(_ encoded: String) -> Bool {
        // JoinActivity's BrokerPlugin redirect has no path. Even a trailing
        // slash is a different redirect and is not silently normalized.
        return encoded.isEmpty
    }
    static func formQueryItems(_ parts: URLComponents) -> [URLQueryItem]? {
        guard let raw = parts.percentEncodedQuery else { return nil }
        guard raw.range(of: "%(?![0-9A-Fa-f]{2})", options: .regularExpression) == nil else { return nil }
        var result: [URLQueryItem] = []
        for pair in raw.split(separator: "&", omittingEmptySubsequences: false) {
            let fields = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let first = fields.first,
                  let name = String(first).replacingOccurrences(of: "+", with: " ").removingPercentEncoding,
                  let value = (fields.count == 2 ? String(fields[1]) : "").replacingOccurrences(of: "+", with: " ").removingPercentEncoding
            else { return nil }
            result.append(URLQueryItem(name: name, value: value))
        }
        return result
    }
    static func isUUID(_ value: String) -> Bool { matches(value, "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$") }
    static func validResource(_ value: String) -> Bool {
        ["https://enterpriseregistration.windows.net/", "https://enterpriseregistration.windows.net", "urn:ms-drs:enterpriseregistration.windows.net"].contains(value)
    }
    static func validScopes(_ value: String) -> Bool {
        let scopes = value.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard scopes.count == 4, Set(scopes).count == 4,
              Set(["openid", "profile", "offline_access"]).isSubset(of: Set(scopes)),
              let resourceScope = scopes.first(where: { $0.hasSuffix("/.default") }) else { return false }
        // Match MSAL withResource exactly, including a discovered trailing slash.
        return validResource(String(resourceScope.dropLast("/.default".count)))
    }
    static func uniqueQuery(_ items: [URLQueryItem], error: BootstrapError) throws -> [String: String] {
        var result: [String: String] = [:]
        for item in items {
            guard result[item.name] == nil, let value = item.value else { throw error }
            result[item.name] = value
        }
        return result
    }
}

public struct NativeReport {
    public static let nonterminalStatuses: Set<String> = ["starting", "ready", "session_started", "callback_received"]
    public static let terminalStatuses: Set<String> = Set([
        "callback_saved", "authorization_rejected", "input_expired", "session_start_failed", "authentication_cancelled",
        "authentication_session_failed", "authentication_presentation_context_missing", "authentication_presentation_context_invalid",
        "callback_missing", "callback_before_session_start", "cancelled", "window_closed", "callback_save_failed", "callback_capture_failed", "native_operation_failed", "device_management_prompt_stopped"
    ] + [
        "invalid_input", "invalid_destination", "expired_input", "invalid_callback", "private_storage_unavailable",
        "session_already_attempted", "output_already_exists", "callback_too_large", "callback_destination_mismatch",
        "callback_path_mismatch", "callback_duplicate_parameter", "callback_state_mismatch", "callback_fields_unsupported",
        "callback_payload_invalid", "native_report_already_exists", "native_report_unavailable"
    ])
    public var sessionStarted = false
    public var callbackReceived = false
    public var callbackSaved = false
    public var callbackCandidateSaved = false
    public var systemErrorDomain = "none"
    public var systemErrorCode: Int? = nil

    public init() {}
    public func data(status: String, terminal: Bool) throws -> Data {
        guard (terminal ? Self.terminalStatuses : Self.nonterminalStatuses).contains(status),
              ["none", "authentication_services", "other"].contains(systemErrorDomain),
              systemErrorCode == nil || (-32768...32767).contains(systemErrorCode!),
              !callbackSaved || (callbackReceived && callbackCandidateSaved && sessionStarted),
              callbackSaved == ["callback_saved", "authorization_rejected"].contains(status),
              !callbackSaved || systemErrorDomain == "none",
              !callbackCandidateSaved || callbackReceived,
              (systemErrorDomain != "none" || systemErrorCode == nil)
        else { throw BootstrapError.nativeReportUnavailable }
        return try JSONSerialization.data(withJSONObject: [
            "v": 1, "experiment": "WPJ-A01", "status": status, "terminal": terminal,
            "session_started": sessionStarted, "callback_received": callbackReceived,
            "callback_saved": callbackSaved, "callback_candidate_saved": callbackCandidateSaved,
            "system_error_domain": systemErrorDomain, "system_error_code": systemErrorCode.map { $0 as Any } ?? NSNull()
        ], options: [.sortedKeys])
    }
}

/// All access is relative to a retained owner-only directory descriptor. No URL,
/// authorization code or token is returned through diagnostics or logs.
public final class PrivateAttempt {
    private let directory: Int32
    private let inputName: String
    private let outputName: String
    private let lockName = ".wpj-a01-native-session.lock"
    private let reportName = "native-result.json"
    private var reportInitialized = false

    public init(inputPath: String, outputPath: String) throws {
        let input = URL(fileURLWithPath: inputPath), output = URL(fileURLWithPath: outputPath)
        guard inputPath.hasPrefix("/"), outputPath.hasPrefix("/"),
              input.standardized.path == inputPath, output.standardized.path == outputPath,
              input.deletingLastPathComponent().path == output.deletingLastPathComponent().path,
              input.lastPathComponent != output.lastPathComponent,
              [input.lastPathComponent, output.lastPathComponent].allSatisfy({ BootstrapInput.matches($0, "^[A-Za-z0-9][A-Za-z0-9._-]{0,95}\\.json$") })
        else { throw BootstrapError.privateStorageUnavailable }
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw BootstrapError.privateStorageUnavailable }
        for component in input.deletingLastPathComponent().path.split(separator: "/") {
            let next = openat(descriptor, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            close(descriptor)
            guard next >= 0 else { throw BootstrapError.privateStorageUnavailable }
            descriptor = next
        }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else {
            close(descriptor); throw BootstrapError.privateStorageUnavailable
        }
        self.directory = descriptor
        self.inputName = input.lastPathComponent
        self.outputName = output.lastPathComponent
    }
    deinit { close(directory) }

    public func readInput() throws -> Data {
        let fd = openat(directory, inputName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw BootstrapError.privateStorageUnavailable }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o777 == 0o600, info.st_size > 0, info.st_size <= BootstrapInput.maximumBytes
        else { throw BootstrapError.privateStorageUnavailable }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size)), offset = 0
        while offset < bytes.count {
            let remaining = bytes.count - offset
            let count = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress!.advanced(by: offset), remaining) }
            guard count > 0 else { throw BootstrapError.privateStorageUnavailable }
            offset += count
        }
        return Data(bytes)
    }

    public func claimOneSession() throws {
        var info = stat()
        guard fstatat(directory, outputName, &info, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else { throw BootstrapError.outputExists }
        try writeExclusive(Data("{\"v\":1,\"experiment\":\"WPJ-A01\",\"session_claimed\":true}\n".utf8), name: lockName, exists: .alreadyAttempted)
    }

    public func saveCallback(_ data: Data) throws {
        guard data.count <= BootstrapInput.maximumBytes else { throw BootstrapError.invalidCallback }
        try writeExclusive(data, name: outputName, exists: .outputExists)
    }

    public func saveCallbackCandidate(_ url: URL) throws {
        guard url.absoluteString.utf8.count <= 131072 else { throw BootstrapError.callbackTooLarge }
        let data = try JSONSerialization.data(withJSONObject: ["v": 1, "experiment": "WPJ-A01", "callback_url": url.absoluteString], options: [.sortedKeys])
        guard data.count <= 131072 else { throw BootstrapError.callbackTooLarge }
        try writeExclusive(data, name: "native-callback-candidate.json", exists: .outputExists)
    }

    public func saveReport(_ data: Data) throws {
        guard data.count <= 4096 else { throw BootstrapError.nativeReportUnavailable }
        if !reportInitialized {
            try writeExclusive(data, name: reportName, exists: .nativeReportExists)
            reportInitialized = true
            return
        }
        var info = stat()
        guard fstatat(directory, reportName, &info, AT_SYMLINK_NOFOLLOW) == 0, info.st_uid == getuid(),
              info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o777 == 0o600 else { throw BootstrapError.nativeReportUnavailable }
        let temporary = ".native-result-" + UUID().uuidString + ".tmp"
        try writeExclusive(data, name: temporary, exists: .nativeReportUnavailable)
        guard renameat(directory, temporary, directory, reportName) == 0 else {
            unlinkat(directory, temporary, 0)
            throw BootstrapError.nativeReportUnavailable
        }
        guard fsync(directory) == 0 else { throw BootstrapError.nativeReportUnavailable }
    }

    private func writeExclusive(_ data: Data, name: String, exists: BootstrapError) throws {
        let fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw errno == EEXIST ? exists : BootstrapError.privateStorageUnavailable }
        defer { close(fd) }
        guard fchmod(fd, 0o600) == 0 else { throw BootstrapError.privateStorageUnavailable }
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
            guard count > 0 else { throw BootstrapError.privateStorageUnavailable }
            offset += count
        }
        guard fsync(fd) == 0 else { throw BootstrapError.privateStorageUnavailable }
    }
}

/// Testable local handoff state machine. It performs no browser or network work;
/// candidates are inert and accepted output is written only after validation.
public final class NativeSessionRecorder {
    private let attempt: PrivateAttempt
    private var report = NativeReport()
    public private(set) var status = "starting"
    public private(set) var terminal = false

    public init(attempt: PrivateAttempt) throws {
        self.attempt = attempt
        try persist(status: "starting", terminal: false)
    }
    public func ready() throws { guard !terminal else { return }; try persist(status: "ready", terminal: false) }
    public func sessionDidStart() throws {
        guard !terminal else { return }
        report.sessionStarted = true
        try persist(status: "session_started", terminal: false)
    }
    @discardableResult public func finish(_ code: String) throws -> String {
        guard !terminal else { return status }
        let known = NativeReport.terminalStatuses.contains(code) ? code : "native_operation_failed"
        // Set once even if the disk fails: later callbacks must never overwrite
        // a terminal decision or promote an already rejected callback.
        terminal = true
        try persist(status: known, terminal: true)
        return known
    }
    @discardableResult public func complete(input: BootstrapInput, url: URL?, systemErrorDomain: String? = nil, systemErrorCode: Int? = nil,
                                            now: TimeInterval = Date().timeIntervalSince1970) throws -> String {
        guard !terminal else { return status }
        if let systemErrorDomain {
            report.systemErrorDomain = systemErrorDomain == "authentication_services" ? "authentication_services" : "other"
            report.systemErrorCode = systemErrorCode.flatMap { (-32768...32767).contains($0) ? $0 : nil }
        }
        if let url {
            report.callbackReceived = true
            do { try attempt.saveCallbackCandidate(url); report.callbackCandidateSaved = true }
            catch { return try finish((error as? BootstrapError) == .callbackTooLarge ? "callback_too_large" : "callback_capture_failed") }
            try persist(status: "callback_received", terminal: false)
        }
        if let systemErrorDomain {
            let code: String
            switch (systemErrorDomain, systemErrorCode) {
            case ("authentication_services", 1): code = "authentication_cancelled"
            case ("authentication_services", 2): code = "authentication_presentation_context_missing"
            case ("authentication_services", 3): code = "authentication_presentation_context_invalid"
            default: code = "authentication_session_failed"
            }
            return try finish(code)
        }
        guard let url else { return try finish("callback_missing") }
        guard report.sessionStarted else { return try finish("callback_before_session_start") }
        let hasCode: Bool
        do {
            let (data, acceptedCode) = try input.callbackData(url, now: now)
            try attempt.saveCallback(data)
            report.callbackSaved = true
            hasCode = acceptedCode
        } catch {
            return try finish((error as? BootstrapError)?.rawValue ?? "callback_save_failed")
        }
        return try finish(hasCode ? "callback_saved" : "authorization_rejected")
    }
    private func persist(status: String, terminal: Bool) throws {
        self.status = status
        try attempt.saveReport(report.data(status: status, terminal: terminal))
    }
}
