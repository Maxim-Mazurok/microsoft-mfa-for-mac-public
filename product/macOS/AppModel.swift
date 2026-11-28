import AppKit
import Combine
import SafariServices
import ServiceManagement

@MainActor final class AppModel: ObservableObject {
    @Published var connection = "offline"
    @Published var detail = "Import the proven research registration to begin."
    @Published var account = ""
    @Published var paused = false
    @Published var locked = true
    @Published var automatic = UserDefaults.standard.object(forKey: "automatic") as? Bool ?? true
    @Published var allowRecentUnlock = UserDefaults.standard.object(forKey: "allowRecentUnlock") as? Bool ?? true
    @Published var pending = [PendingRequest]()
    @Published var phoneSignInCapability: PhoneSignInCapability?
    @Published var outcomes = [RecentOutcome]()
    @Published var hasImported = UserDefaults.standard.bool(forKey: "hasImportedRegistration")
    @Published var importing = false
    @Published var bridgeAvailable = false
    @Published var bridgeDetail = "not_started"
    @Published var loginStatus = "Off"
    @Published var verificationActive = false
    @Published var synthetic = false
    @Published var errorMessage: String?
    var showWindow: (() -> Void)?
    private let service = ProtocolProcess()
    private let keychain = KeychainStore()
    private let verifier = LocalVerification()
    private let session = SessionMonitor()
    private let inbox = BrowserInbox()
    private var configureCredentials: [String: Any]?
    private var awaitingReady = false
    private var shownContext = Set<String>()
    private var demoOnConnect = false
    private var running = false
    private var expiryTimer: Timer?
    private var verificationTicketIDs = Set<String>()
    private var currentVerificationMode: String?

    init() {
        if let saved = UserDefaults.standard.data(forKey: "recentOutcomes"),
           let decoded = try? JSONDecoder().decode([RecentOutcome].self, from: saved) {
            outcomes = decoded.filter { Wire.safeCode($0.result) == $0.result }.prefix(12).map { $0 }
        }
        service.onEvent = { [weak self] event in self?.receive(event) }
        service.onFailure = { [weak self] code in self?.failed(code) }
        session.onLockChange = { [weak self] locked in
            guard let self else { return }
            self.locked = locked
            if locked { self.verifier.cancel(); self.shownContext.removeAll() }
            if self.running { self.service.send(["command": "session_lock", "locked": locked]) }
        }
        session.onWake = { [weak self] in
            guard let self else { return }
            self.verifier.cancel(); self.shownContext.removeAll()
            if self.running { self.service.send(["command": "wake"]) }
        }
        session.onSafariQuit = { [weak self] in
            guard let self, self.running, !self.synthetic else { return }
            if self.currentVerificationMode != "manual" { self.verifier.cancel() }
            self.service.send(["command": "browser_reset"])
        }
        inbox.onStatus = { [weak self] available in
            guard let self else { return }
            self.bridgeAvailable = available
            self.bridgeDetail = self.inbox.failureCode ?? (available ? "ready" : "unavailable")
        }
        inbox.isAvailable = { [weak self] in
            guard let self else { return false }
            return self.running && !self.synthetic && !self.locked && !self.paused && self.connection == "connected"
        }
        inbox.onBrowser = { [weak self] browser in
            guard let self, !self.synthetic, !self.locked, !self.paused else { return }
            self.service.send(["command": "browser_event", "browser": browser])
        }
        if !CommandLine.arguments.contains("--self-test-native") {
            session.start(); locked = session.locked
            inbox.start()
            bridgeAvailable = inbox.ready
            bridgeDetail = inbox.failureCode ?? (inbox.ready ? "ready" : "unavailable")
        }
        loginStatus = Self.describeLoginStatus(SMAppService.mainApp.status)
        expiryTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.pending.removeAll { $0.expiresAt <= Date() } }
        }
        if hasImported { detail = "Registration saved in Keychain. Connect when ready." }
        if CommandLine.arguments.contains("--diagnose-inbox") {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                guard let self else { return }
                if let data = try? JSONSerialization.data(withJSONObject: self.redactedNativeStatus(), options: [.sortedKeys]),
                   let text = String(data: data, encoding: .utf8) { print(text) }
                self.shutdown(); NSApp.terminate(nil)
            }
        }
    }

    var connected: Bool { running }
    var bridgeName: String { BrowserInbox.mode == "development" ? "Local development bridge" : "App-group bridge" }
    var title: String {
        if synthetic { return "Practice mode" }
        if locked { return "Mac locked" }
        if paused { return "Paused" }
        switch connection {
        case "connected": return "Listening for sign-ins"
        case "connecting", "reconnecting", "backoff": return "Connecting…"
        default: return "Not connected"
        }
    }

    func importRegistration() {
        guard !running, !importing else { return }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true; panel.canChooseFiles = false; panel.allowsMultipleSelection = false
        panel.title = "Import existing research registration"
        panel.message = "Select the microsoft-mfa-for-mac folder. A separate copy goes into Keychain; research files and existing phone methods stay intact. This does not connect or enroll a method."
        panel.prompt = "Import to Keychain"
        guard panel.runModal() == .OK, let root = panel.url else { return }
        importing = true; errorMessage = nil
        ProtocolProcess.exportResearch(root: root) { [weak self] result in
            guard let self else { return }
            self.importing = false
            do {
                let data = try result.get()
                try self.keychain.importOnce(data)
                self.hasImported = true; UserDefaults.standard.set(true, forKey: "hasImportedRegistration")
                self.detail = "Imported into Keychain. Research registration preserved. Connect when ready."
            } catch ProductError.alreadyImported {
                self.hasImported = true; UserDefaults.standard.set(true, forKey: "hasImportedRegistration")
                self.errorMessage = "A product registration already exists in Keychain. It was preserved. Use Connect to open it."
            } catch { self.errorMessage = "Import failed. Select the original research folder with its private files and successful E05/E06 evidence. Nothing was replaced." }
        }
    }

    func connect() {
        guard !running else { return }
        do {
            let data = try keychain.load()
            guard let credentials = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  credentials["version"] as? Int == 1 else { throw ProductError.invalidMessage }
            configureCredentials = credentials
            account = (credentials["account"] as? [String: Any])?["username"] as? String ?? ""
            hasImported = true; synthetic = false; start()
        } catch { errorMessage = "The product registration could not be read from Keychain. Import the existing research registration first, or unlock Keychain." }
    }

    func startDemo() {
        disconnect(); synthetic = true; configureCredentials = nil; account = "demo@example.test"; demoOnConnect = true; start()
    }

    func addDemo(ambiguous: Bool = false) {
        guard synthetic, running else { return }
        service.send(["command": "demo", "require_verification": false, "ambiguous": ambiguous])
    }

    private func start() {
        errorMessage = nil; pending.removeAll(); shownContext.removeAll(); verificationTicketIDs.removeAll()
        phoneSignInCapability = nil
        connection = "connecting"; paused = false; awaitingReady = true
        do {
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("org.example.microsoftmfamac", isDirectory: true)
            // Fresh synthetic sessions never share dedupe claims or credentials with live state.
            let path = support.appendingPathComponent(synthetic ? "Synthetic/\(UUID().uuidString)" : "Live", isDirectory: true)
            try service.start(stateDirectory: path, synthetic: synthetic)
            running = true
        } catch { configureCredentials = nil; failed("runtime_unavailable") }
    }

    func disconnect() {
        verifier.cancel(); service.stop(); running = false; awaitingReady = false; configureCredentials = nil
        paused = false
        connection = "offline"; pending.removeAll(); shownContext.removeAll(); verificationTicketIDs.removeAll()
        phoneSignInCapability = nil
        account = ""; verificationActive = false; synthetic = false
        detail = hasImported ? "Registration stays in Keychain. Connect when ready." : "Import the proven research registration to begin."
    }

    func setPaused(_ value: Bool) {
        paused = value
        if value { verifier.cancel(); shownContext.removeAll() }
        if running { service.send(["command": "pause", "paused": value]) }
    }

    func setAutomatic(_ value: Bool) {
        if !value && currentVerificationMode != "manual" { verifier.cancel() }
        automatic = value; UserDefaults.standard.set(value, forKey: "automatic")
        if running { service.send(["command": "settings", "automatic": value]) }
    }

    func setReuse(_ value: Bool) {
        allowRecentUnlock = value; UserDefaults.standard.set(value, forKey: "allowRecentUnlock")
        verifier.cancel()
    }

    func contextVisible(for request: PendingRequest, actuallyVisible: Bool) {
        guard running, !locked, !paused, !shownContext.contains(request.id),
              actuallyVisible else { return }
        let applicationShown = !request.application.isEmpty
        let locationShown = request.location != nil
        if request.applicationRequired && !applicationShown { return }
        if request.locationRequired && !locationShown { return }
        shownContext.insert(request.id)
        service.send(["command": "context_shown", "request_id": request.id,
                      "app_context_shown": applicationShown, "location_context_shown": locationShown])
    }

    func manualApprove(_ request: PendingRequest, number: String) {
        guard running, !locked, !paused, request.expiresAt > Date(),
              number.range(of: "^[0-9]{1,2}$", options: .regularExpression) != nil else { return }
        service.send(["command": "manual_approve", "request_id": request.id, "number": number])
    }

    func openSafariSettings() {
        SFSafariApplication.showPreferencesForExtension(withIdentifier: "org.example.microsoftmfamac.SafariExtension") { [weak self] error in
            if error != nil { DispatchQueue.main.async { self?.errorMessage = "Open Safari Settings → Extensions and enable Microsoft MFA for Mac. For this local build, first enable Allow Unsigned Extensions in Safari Developer settings." } }
        }
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            loginStatus = Self.describeLoginStatus(SMAppService.mainApp.status)
        } catch { errorMessage = "Launch at login could not be changed. Move the app to Applications, then try again or review System Settings → General → Login Items." }
    }

    func shutdown() { disconnect(); inbox.stop() }

    func redactedNativeStatus() -> [String: Any] {
        ["bridge_available": bridgeAvailable, "bridge_detail": bridgeDetail, "bridge_mode": BrowserInbox.mode,
         "synthetic": synthetic, "connection": connection, "product_credentials_imported": hasImported]
    }

    private static func describeLoginStatus(_ status: SMAppService.Status) -> String {
        switch status { case .enabled: return "On"; case .requiresApproval: return "Approval needed in System Settings"; default: return "Off" }
    }

    private func receive(_ value: [String: Any]) {
        guard let event = value["event"] as? String else { return }
        switch event {
        case "ready":
            guard awaitingReady else { return }; awaitingReady = false
            service.send(["command": "configure", "credentials": configureCredentials as Any? ?? NSNull(),
                          "settings": ["automatic": automatic]])
            configureCredentials = nil
            service.send(["command": "session_lock", "locked": locked])
            service.send(["command": "connect"])
        case "state":
            connection = Wire.safeCode(value["connection"], fallback: "offline")
            paused = value["paused"] as? Bool ?? paused
            detail = humanDetail(Wire.safeCode(value["detail"], fallback: connection))
            if synthetic && demoOnConnect && connection == "connected" { demoOnConnect = false; addDemo() }
        case "pending":
            guard let request = PendingRequest(value), request.expiresAt > Date() else { return }
            if let index = pending.firstIndex(where: { $0.id == request.id }) { pending[index] = request }
            else { pending.append(request) }
            // A push can beat Safari's number page. Do not steal focus before capture.
            if request.status == "show_context" && !locked && !paused { showWindow?() }
        case "capability":
            guard let capability = PhoneSignInCapability(value) else { return }
            let changed = phoneSignInCapability != capability
            phoneSignInCapability = capability
            // Explain an unsupported flow once; it never becomes an approval request.
            if changed && !locked && !paused { showWindow?() }
        case "verification_required":
            guard let requestID = value["request_id"] as? String, let ticketID = value["ticket_id"] as? String,
                  ticketID.count <= 128, !verificationTicketIDs.contains(ticketID) else { return }
            verificationTicketIDs.insert(ticketID)
            let ticket = VerificationTicket(requestID: requestID, ticketID: ticketID, started: Date())
            guard ticket.canSubmit(now: Date(), locked: locked, paused: paused, pendingIDs: Set(pending.map(\.id))), !synthetic else {
                // Synthetic requests never manufacture system verification success.
                service.send(["command": "verification_result", "request_id": requestID, "ticket_id": ticketID, "verified": false]); return
            }
            verificationActive = true; showWindow?()
            currentVerificationMode = value["mode"] as? String
            verifier.verify(ticket: ticket, allowRecentUnlock: allowRecentUnlock) { [weak self] ticket, success in
                guard let self else { return }
                self.verificationActive = false
                self.currentVerificationMode = nil
                let verified = success && ticket.canSubmit(now: Date(), locked: self.locked, paused: self.paused, pendingIDs: Set(self.pending.map(\.id)))
                self.service.send(["command": "verification_result", "request_id": ticket.requestID, "ticket_id": ticket.ticketID, "verified": verified])
            }
        case "outcome":
            let result = Wire.safeCode(value["result"])
            outcomes.insert(RecentOutcome(result: synthetic && !result.hasPrefix("synthetic_") ? "synthetic_" + result : result), at: 0)
            outcomes = Array(outcomes.prefix(12))
            if !synthetic, let data = try? JSONEncoder().encode(outcomes.filter { !$0.result.hasPrefix("synthetic_") }) {
                UserDefaults.standard.set(data, forKey: "recentOutcomes")
            }
            if let id = value["request_id"] as? String { pending.removeAll { $0.id == id }; shownContext.remove(id) }
        case "error":
            let code = Wire.safeCode(value["code"])
            errorMessage = humanDetail(code)
        default: break
        }
    }

    private func failed(_ code: String) {
        running = false; awaitingReady = false; configureCredentials = nil; connection = "offline"
        verifier.cancel(); pending.removeAll(); errorMessage = humanDetail(code)
    }

    private func humanDetail(_ code: String) -> String {
        switch code {
        case "runtime_unavailable": return "The local Python runtime or bundled service is unavailable. Rebuild this development app using the documented build command."
        case "service_stopped", "service_write_failed", "service_message_invalid": return "The local service stopped safely. No uncertain approval is retried. Reconnect when ready."
        case "connected": return "Ready for a fresh, matching sign-in from Safari."
        case "paused": return "Automatic handling is paused."
        case "registration_required": return "Passwordless phone sign-in needs a separate registration. Classic MFA remains available."
        case "session_binding_unavailable": return "The phone sign-in context could not be matched safely. No approval was sent."
        case "registered_credential_unavailable": return "A usable registered phone sign-in key is unavailable. Classic MFA remains available."
        default: return code.replacingOccurrences(of: "_", with: " ").capitalized
        }
    }
}
