import AppKit
import ApplicationServices

final class SessionMonitor {
    var onLockChange: ((Bool) -> Void)?
    var onWake: (() -> Void)?
    var onSafariQuit: (() -> Void)?
    private(set) var locked = true
    private var observers = [NSObjectProtocol]()
    private var timer: Timer?
    private var sleeping = false

    func start() {
        let workspace = NSWorkspace.shared.notificationCenter
        observers.append(workspace.addObserver(forName: NSWorkspace.willSleepNotification, object: nil, queue: .main) { [weak self] _ in
            self?.sleeping = true; self?.update(true)
        })
        observers.append(workspace.addObserver(forName: NSWorkspace.didWakeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.sleeping = false; self?.update(true); self?.onWake?(); self?.refresh()
        })
        observers.append(workspace.addObserver(forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: .main) { [weak self] _ in self?.update(true) })
        observers.append(workspace.addObserver(forName: NSWorkspace.sessionDidBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in self?.refresh() })
        observers.append(workspace.addObserver(forName: NSWorkspace.didTerminateApplicationNotification, object: nil, queue: .main) { [weak self] notification in
            guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  ["com.apple.Safari", "com.apple.SafariTechnologyPreview"].contains(app.bundleIdentifier ?? "") else { return }
            self?.onSafariQuit?()
        })
        // macOS publishes these lock notifications; the polling check also closes missed-event gaps.
        let distributed = DistributedNotificationCenter.default()
        observers.append(distributed.addObserver(forName: NSNotification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in self?.update(true) })
        observers.append(distributed.addObserver(forName: NSNotification.Name("com.apple.screenIsUnlocked"), object: nil, queue: .main) { [weak self] _ in self?.refresh() })
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.refresh() }
        refresh()
    }

    func refresh() {
        guard !sleeping, let session = CGSessionCopyCurrentDictionary() as? [String: Any],
              session["kCGSSessionOnConsoleKey"] as? Bool == true,
              session["kCGSessionLoginDoneKey"] as? Bool == true else { update(true); return }
        update(session["CGSSessionScreenIsLocked"] as? Bool ?? false)
    }

    private func update(_ value: Bool) {
        guard value != locked else { return }
        locked = value; onLockChange?(value)
    }
}
