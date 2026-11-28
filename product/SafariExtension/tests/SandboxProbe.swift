import AppKit
import Foundation
import Darwin

/// LaunchServices-only synthetic sandbox permission probe; no credentials/network.
@main struct SandboxProbe {
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        guard CommandLine.arguments.count == 3,
              let identifier = UUID(uuidString: CommandLine.arguments[1]),
              let home = getpwuid(getuid())?.pointee.pw_dir else { exit(2) }
        let actualHome = URL(fileURLWithPath: String(cString: home), isDirectory: true)
        let product = actualHome.appendingPathComponent("Library/Application Support/org.example.microsoftmfamac", isDirectory: true)
        let allowed = product.appendingPathComponent("BrowserBridge", isDirectory: true)
        let suffix = "probe-denied-\(identifier.uuidString).txt"
        let denied = [product.appendingPathComponent(suffix), product.appendingPathComponent("Live").appendingPathComponent(suffix), URL(fileURLWithPath: CommandLine.arguments[2])]
        let blocked = denied.map { url -> Bool in
            let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            if fd >= 0 { close(fd); return false }
            return errno == EPERM || errno == EACCES
        }
        let receipt: [String: Any] = ["version": 1, "synthetic": true, "launch_services": true,
            "adjacent_product_denied": blocked[0], "adjacent_live_denied": blocked[1], "research_fixture_denied": blocked[2],
            "network_requests": 0, "credentials_read": false]
        do {
            let data = try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys])
            let output = allowed.appendingPathComponent("sandbox-probe-\(identifier.uuidString).json")
            let fd = open(output.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { exit(3) }
            defer { close(fd) }
            let written = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            guard written == data.count, fsync(fd) == 0 else { exit(4) }
            exit(blocked.allSatisfy { $0 } ? 0 : 5)
        } catch { exit(6) }
    }
}
