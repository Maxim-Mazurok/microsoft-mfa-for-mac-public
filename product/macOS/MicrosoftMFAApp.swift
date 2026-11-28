import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    var onTerminate: (() -> Void)?
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        if CommandLine.arguments.contains("--self-test-native") {
            if let data = try? JSONSerialization.data(withJSONObject: NativeSelfTest.run(), options: [.sortedKeys]),
               let text = String(data: data, encoding: .utf8) { print(text) }
            NSApp.terminate(nil)
        }
    }
    func applicationWillTerminate(_ notification: Notification) { onTerminate?() }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

@main struct MicrosoftMFAApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        Window("Microsoft MFA for Mac", id: "main") {
            MainView(model: model)
                .onAppear { delegate.onTerminate = { model.shutdown() } }
                .frame(minWidth: 620, minHeight: 680)
        }
        .defaultSize(width: 690, height: 780)
        .windowResizability(.contentMinSize)
        MenuBarExtra("Microsoft MFA for Mac", systemImage: model.paused ? "shield.slash" : "checkmark.shield") {
            MenuContent(model: model)
        }
    }
}

private struct MenuContent: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text(model.title)
        if !model.pending.isEmpty { Text("\(model.pending.count) pending sign-in") }
        if model.phoneSignInCapability != nil { Text("Phone sign-in needs attention") }
        Divider()
        Button("Open Microsoft MFA for Mac") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
        if model.connected {
            Button(model.paused ? "Resume" : "Pause") { model.setPaused(!model.paused) }
            Button("Disconnect") { model.disconnect() }
        } else { Button("Connect") { model.connect() } }
        Divider()
        Button("Quit") { model.shutdown(); NSApp.terminate(nil) }
    }
}

private struct MainView: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @State private var launched = false
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(alignment: .top, spacing: 15) {
                    Image(systemName: "checkmark.shield.fill").font(.system(size: 36)).foregroundStyle(.blue)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Microsoft MFA for Mac").font(.title2.weight(.semibold))
                        Text("Your sign-in, on this Mac.").foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.synthetic { Text("PRACTICE").font(.caption.weight(.bold)).padding(.horizontal, 10).padding(.vertical, 6).background(.orange.opacity(0.15), in: Capsule()) }
                }
                statusCard
                if let capability = model.phoneSignInCapability {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(alignment: .top) {
                            Label("Phone sign-in", systemImage: "key.horizontal").font(.headline)
                            Spacer()
                            Button { model.phoneSignInCapability = nil } label: { Image(systemName: "xmark") }
                                .buttonStyle(.plain).accessibilityLabel("Dismiss phone sign-in notice")
                        }
                        Text(capability.title).font(.subheadline.weight(.semibold))
                        Text(capability.explanation).foregroundStyle(.secondary)
                        Text(capability.nextStep).font(.callout)
                    }.fixedSize(horizontal: false, vertical: true).card()
                }
                if let message = model.errorMessage {
                    HStack(alignment: .top) {
                        Image(systemName: "exclamationmark.circle").foregroundStyle(.orange)
                        Text(message).textSelection(.enabled)
                        Spacer()
                        Button { model.errorMessage = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain).accessibilityLabel("Dismiss message")
                    }.padding().background(.orange.opacity(0.09), in: RoundedRectangle(cornerRadius: 12))
                }
                if model.pending.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Ready when you sign in", systemImage: "safari").font(.headline)
                        Text(model.synthetic ? "Practice requests use invented data and cannot contact Microsoft or Google." : "Open a Microsoft sign-in in Safari. A fresh request with the same account and session can be approved automatically. Ambiguous requests stay manual.")
                            .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        if model.synthetic {
                            HStack {
                                Button("Matching practice request") { model.addDemo() }
                                Button("Ambiguous practice request") { model.addDemo(ambiguous: true) }
                            }.disabled(model.paused || model.locked || !model.connected)
                        }
                    }.card()
                } else {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Current sign-in").font(.headline)
                        ForEach(model.pending) { request in RequestCard(model: model, request: request) }
                    }
                }
                controls
                setup
                if !model.outcomes.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Recent activity").font(.headline)
                        ForEach(model.outcomes.prefix(6)) { outcome in
                            HStack {
                                Image(systemName: outcome.result.contains("accepted") || outcome.result.contains("approved") ? "checkmark.circle" : "circle")
                                    .foregroundStyle(.secondary)
                                Text(outcome.result.replacingOccurrences(of: "_", with: " ").capitalized)
                                Spacer()
                                Text(outcome.date, style: .time).foregroundStyle(.secondary).font(.caption)
                            }
                        }
                        Text("Activity stores outcomes and times only.").font(.caption).foregroundStyle(.secondary)
                    }.card()
                }
                Text("Independent research client · Not affiliated with Microsoft. Existing phone methods remain available.")
                    .font(.caption).foregroundStyle(.tertiary)
            }.padding(28)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .background(WindowIdentity())
        .onAppear {
            model.showWindow = { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
            if !launched {
                launched = true
                if CommandLine.arguments.contains("--demo") { model.startDemo() }
            }
        }
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Circle().fill(model.connection == "connected" && !model.paused && !model.locked ? Color.green : Color.secondary).frame(width: 8, height: 8)
                Text(model.title).font(.headline)
                Spacer()
                if model.connected {
                    Button(model.paused ? "Resume" : "Pause") { model.setPaused(!model.paused) }
                    Button("Disconnect") { model.disconnect() }
                } else {
                    Button("Connect") { model.connect() }.buttonStyle(.borderedProminent)
                        .disabled(!model.hasImported)
                }
            }
            if !model.account.isEmpty { Text(model.account).font(.subheadline).privacySensitive() }
            Text(model.detail).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if model.verificationActive { Label("Complete the macOS identity check", systemImage: "touchid").foregroundStyle(.blue) }
            if model.locked { Text("Automatic handling is suspended while this Mac is locked.").font(.caption).foregroundStyle(.secondary) }
        }.card()
    }

    private var controls: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Approval").font(.headline)
            Toggle(isOn: Binding(get: { model.automatic }, set: { model.setAutomatic($0) })) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Automatically approve matching Safari sign-ins")
                    Text("Requires an exact account and session match. A number alone never triggers approval.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Toggle(isOn: Binding(get: { model.allowRecentUnlock }, set: { model.setReuse($0) })) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Allow a recent Touch ID unlock")
                    Text("macOS may reuse a device-unlock match from the last 30 seconds. Microsoft can still require a system identity prompt.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }.toggleStyle(.switch).card()
    }

    private var setup: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Setup").font(.headline)
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(model.hasImported ? "Registration saved in Keychain" : "Import your existing registration")
                    Text("Copies the proven research identity. Does not create another method or change the original files.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button(model.importing ? "Importing…" : "Import…") { model.importRegistration() }.disabled(model.connected || model.importing)
            }
            Divider()
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Safari extension")
                    Text(model.bridgeAvailable ? "\(model.bridgeName) ready. Enable the extension in Safari and allow Microsoft sign-in sites." : "\(model.bridgeName) unavailable (\(model.bridgeDetail)). Review the local build and signing instructions.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Safari Settings…") { model.openSafariSettings() }
            }
            Divider()
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Launch at login")
                    Text(model.loginStatus + ". Starts disconnected; connect deliberately.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button(model.loginStatus == "On" ? "Turn off" : "Turn on") { model.setLaunchAtLogin(model.loginStatus != "On") }
            }
            Divider()
            HStack {
                Text("Explore without credentials or network access.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Practice mode") { model.startDemo() }
            }
        }.card()
    }

}

private struct RequestCard: View {
    @ObservedObject var model: AppModel
    let request: PendingRequest
    @State private var number = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 8) {
                Text(request.application.isEmpty ? "Microsoft sign-in" : request.application).font(.headline).privacySensitive()
                Text(request.account).privacySensitive()
                if let location = request.location { Label(location, systemImage: "location").font(.callout).privacySensitive() }
            }
            .background(VisibleContextProbe {
                model.contextVisible(for: request, actuallyVisible: true)
            })
            HStack {
                Text(request.status.replacingOccurrences(of: "_", with: " ").capitalized).foregroundStyle(.secondary)
                Spacer()
                Text(request.expiresAt, style: .relative).font(.caption).foregroundStyle(.secondary)
            }
            if request.manualAvailable && !model.verificationActive {
                Divider()
                Text("Only approve the sign-in you started. Enter the number visible in its browser page.")
                    .font(.caption).foregroundStyle(.secondary)
                HStack {
                    SecureField("Browser number", text: $number).frame(width: 150)
                        .onChange(of: number) { number = String(number.filter(\.isNumber).prefix(2)) }
                    Button("Approve this sign-in") { model.manualApprove(request, number: number); number = "" }
                        .disabled(number.isEmpty || model.locked || model.paused || model.verificationActive)
                }
            } else {
                Text("A matching local sign-in is handled automatically. macOS may ask you to verify your identity.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }.card()
    }
}

/// A policy flag means the actual context region was displayed, not merely that
/// SwiftUI constructed its model or that an offscreen ScrollView child exists.
private struct VisibleContextProbe: NSViewRepresentable {
    let visible: () -> Void
    func makeNSView(context: Context) -> ContextVisibilityView { ContextVisibilityView(visible: visible) }
    func updateNSView(_ view: ContextVisibilityView, context: Context) { view.visible = visible }
}

private final class ContextVisibilityView: NSView {
    var visible: () -> Void
    private var timer: Timer?
    init(visible: @escaping () -> Void) { self.visible = visible; super.init(frame: .zero) }
    required init?(coder: NSCoder) { fatalError("init(coder:) unsupported") }
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow(); timer?.invalidate(); timer = nil
        guard window != nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            guard let self, let window = self.window, window.isKeyWindow,
                  window.occlusionState.contains(.visible), !self.isHiddenOrHasHiddenAncestor,
                  self.bounds.width > 0, self.bounds.height > 0,
                  self.visibleRect.insetBy(dx: -0.5, dy: -0.5).contains(self.bounds) else { return }
            self.visible()
        }
    }
    deinit { timer?.invalidate() }
}

private struct WindowIdentity: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { let view = NSView(); DispatchQueue.main.async { view.window?.identifier = NSUserInterfaceItemIdentifier("main") }; return view }
    func updateNSView(_ nsView: NSView, context: Context) { DispatchQueue.main.async { nsView.window?.identifier = NSUserInterfaceItemIdentifier("main") } }
}

private extension View {
    func card() -> some View { padding(18).frame(maxWidth: .infinity, alignment: .leading).background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14)) }
}
