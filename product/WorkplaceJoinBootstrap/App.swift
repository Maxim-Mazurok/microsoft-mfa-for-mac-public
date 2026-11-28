import AppKit
import AuthenticationServices
import Foundation

@main
final class BootstrapApp: NSObject, NSApplicationDelegate, ASWebAuthenticationPresentationContextProviding {
    private var input: BootstrapInput?
    private var attempt: PrivateAttempt?
    private var recorder: NativeSessionRecorder?
    private var window: NSWindow!
    private var label: NSTextField!
    private var startButton: NSButton!
    private var cancelButton: NSButton!
    private var managementButton: NSButton!
    private var session: ASWebAuthenticationSession?
    private var timeout: Timer?
    private var finished = false
    private var started = false

    static func main() {
        let arguments = Array(CommandLine.arguments.dropFirst())
        if arguments.first == "--validate-input" {
            do {
                guard arguments.count == 2 else { throw BootstrapError.invalidInput }
                let output = URL(fileURLWithPath: arguments[1]).deletingLastPathComponent().appendingPathComponent("auth-callback.json").path
                let attempt = try PrivateAttempt(inputPath: arguments[1], outputPath: output)
                _ = try BootstrapInput(data: attempt.readInput())
                print("{\"experiment\":\"WPJ-A01\",\"native_status\":\"input_validated\"}")
                return
            } catch {
                let code = (error as? BootstrapError)?.rawValue ?? "input_unavailable"
                print("{\"experiment\":\"WPJ-A01\",\"native_status\":\"\(code)\"}")
                exit(1)
            }
        }
        let app = NSApplication.shared
        let delegate = BootstrapApp()
        app.setActivationPolicy(.regular)
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            guard arguments.count == 4, arguments[0] == "--input", arguments[2] == "--output" else { throw BootstrapError.invalidInput }
            let attempt = try PrivateAttempt(inputPath: arguments[1], outputPath: arguments[3])
            self.attempt = attempt
            recorder = try NativeSessionRecorder(attempt: attempt)
            let input = try BootstrapInput(data: attempt.readInput())
            self.input = input
            try recorder?.ready()
            makeWindow()
            timeout = Timer.scheduledTimer(withTimeInterval: max(0.1, input.expiresAt - Date().timeIntervalSince1970), repeats: false) { [weak self] _ in
                self?.finish(code: "input_expired", message: "The prepared sign-in expired. No retry was started.")
            }
        } catch {
            finish(code: (error as? BootstrapError)?.rawValue ?? "native_operation_failed", message: "The prepared input could not be safely opened. No sign-in was started.")
            NSApplication.shared.terminate(nil)
        }
    }

    private func makeWindow() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 590, height: 380), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Device registration authorization"
        let title = NSTextField(labelWithString: "Authorize a later registration experiment")
        title.font = .boldSystemFont(ofSize: 19)
        label = NSTextField(wrappingLabelWithString: "This step asks Microsoft for permission needed by a later device-registration experiment. This helper does not create a device, install a profile, enroll management, or approve an MFA request.\n\nUse only your designated account. Your existing phone may be needed to authenticate this sign-in; the Mac MFA app is not required.\n\nSTOP if asked to enable device management, install a profile, or satisfy device compliance. Cancel that prompt and use the stop button here. Your sign-in result stays private on this Mac.")
        label.font = .systemFont(ofSize: 13)
        startButton = NSButton(title: "Continue in browser", target: self, action: #selector(begin))
        startButton.bezelStyle = .rounded
        cancelButton = NSButton(title: "Cancel", target: self, action: #selector(cancel))
        cancelButton.bezelStyle = .rounded
        managementButton = NSButton(title: "Stop: device management prompt", target: self, action: #selector(stopForManagement))
        managementButton.bezelStyle = .rounded
        let buttons = NSStackView(views: [cancelButton, startButton]); buttons.orientation = .horizontal
        let stack = NSStackView(views: [title, label, managementButton, buttons]); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 20
        stack.translatesAutoresizingMaskIntoConstraints = false
        let view = window.contentView!; view.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 28), stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -28), stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 28)])
        window.center(); window.makeKeyAndOrderFront(nil); NSApplication.shared.activate(ignoringOtherApps: true)
    }

    @objc private func begin() {
        guard !started, !finished, let input, let attempt else { return }
        guard Date().timeIntervalSince1970 < input.expiresAt else { finish(code: "input_expired", message: "The prepared sign-in expired."); return }
        do { try attempt.claimOneSession() }
        catch { finish(code: (error as? BootstrapError)?.rawValue ?? "private_storage_unavailable", message: "This attempt cannot be started. No retry was made."); return }
        started = true; startButton.isEnabled = false
        let session = ASWebAuthenticationSession(url: input.authorizeURL, callback: .customScheme(BootstrapInput.scheme)) { [weak self] url, error in
            DispatchQueue.main.async { self?.completed(url: url, error: error) }
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = true
        self.session = session
        guard session.start() else { finish(code: "session_start_failed", message: "macOS could not start the sign-in session. No retry was made."); return }
        do { try recorder?.sessionDidStart() }
        catch { finish(code: "native_report_unavailable", message: "The private diagnostic record could not be saved. The session was stopped."); return }
        label.stringValue = "Complete only the sign-in for your designated account. If Microsoft requests MFA, your existing phone can approve the sign-in you just started. The Mac MFA app is not needed.\n\nSTOP at any device-management, profile-installation, or compliance prompt. Cancel it and use the stop button here.\n\nThis helper creates no device and enrolls no management. It will save the sign-in callback privately, then close."
        fixedOutput("session_started")
    }

    private func completed(url: URL?, error: Error?) {
        guard !finished, let input, let recorder else { return }
        do {
            let native = error as NSError?
            let domain = native.map { $0.domain == ASWebAuthenticationSessionErrorDomain ? "authentication_services" : "other" }
            let code = try recorder.complete(input: input, url: url, systemErrorDomain: domain, systemErrorCode: native?.code)
            let message: String
            switch code {
            case "callback_saved": message = "The sign-in callback was saved privately. This establishes neither token issuance nor device registration. No device was created."
            case "authorization_rejected": message = "Microsoft returned an authorization error. Its details were saved privately. Nothing was registered."
            case "authentication_cancelled": message = "Sign-in was cancelled. No retry was started."
            default: message = "The sign-in could not be safely completed. Private diagnostics were saved; no token exchange was started."
            }
            finish(code: code, message: message)
        } catch {
            finish(code: "native_report_unavailable", message: "The private diagnostic record could not be saved. No token exchange was started.")
        }
    }

    private func finish(code: String, message: String) {
        guard !finished else { return }
        finished = true; timeout?.invalidate(); timeout = nil
        session?.cancel(); session = nil
        var finalCode = code, finalMessage = message
        do { if let recorder, !recorder.terminal { finalCode = try recorder.finish(code) } }
        catch { finalCode = "native_report_unavailable"; finalMessage = "The local diagnostic record could not be saved. No token exchange was started." }
        label?.stringValue = finalMessage; startButton?.isEnabled = false; managementButton?.isEnabled = false; cancelButton?.title = "Close"
        fixedOutput(finalCode)
        // The bounded orchestrator waits for this helper to exit before it
        // considers one token exchange. Do not strand it behind a close button.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.75) { NSApplication.shared.terminate(nil) }
    }

    @objc private func cancel() {
        if !finished { finish(code: "cancelled", message: "Cancelled. No retry was started.") }
        NSApplication.shared.terminate(nil)
    }
    @objc private func stopForManagement() {
        finish(code: "device_management_prompt_stopped", message: "Stopped at a management, profile, or compliance prompt. No retry or device registration was started by this helper.")
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) {
        timeout?.invalidate()
        if !finished {
            finished = true
            do { _ = try recorder?.finish("window_closed"); fixedOutput("window_closed") }
            catch { fixedOutput("native_report_unavailable") }
        }
        session?.cancel()
    }
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { window }
    private func fixedOutput(_ code: String) { print("{\"experiment\":\"WPJ-A01\",\"native_status\":\"\(code)\"}") }
}
