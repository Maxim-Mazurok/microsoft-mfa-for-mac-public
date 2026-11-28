import Foundation
import Security

enum NativeSelfTest {
    /// Runs only on explicit --self-test-native. No product/research item is read.
    static func run() -> [String: Any] {
        var report: [String: Any] = ["synthetic_only": true, "network_requests": 0,
                                     "product_credentials_accessed": false]
        let container = BrowserInbox.configuredContainer()
        report["bridge_mode"] = BrowserInbox.mode
        report["configured_bridge_directory_available"] = container != nil
        if let container {
            // Check real group IO without touching a live heartbeat or queued event.
            let probe = container.appendingPathComponent("synthetic-probe-" + UUID().uuidString)
            defer { try? FileManager.default.removeItem(at: probe) }
            do {
                try FileManager.default.createDirectory(at: container, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                let data = Data("synthetic-only".utf8)
                try data.write(to: probe, options: .withoutOverwriting)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: probe.path)
                report["configured_bridge_io_ready"] = PrivateFiles.readOwnerOnlyRegular(probe, maximumBytes: 100) == data
            } catch { report["configured_bridge_io_ready"] = false; report["configured_bridge_error_code"] = (error as NSError).code }
        }
        for dataProtection in [true, false] {
            let name = "org.example.microsoftmfamac.synthetic-smoke." + UUID().uuidString
            var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                       kSecAttrService as String: name, kSecAttrAccount as String: "invented"]
            if dataProtection { query[kSecUseDataProtectionKeychain as String] = true }
            var add = query
            add[kSecValueData as String] = Data("synthetic-only-not-a-credential".utf8)
            let prefix = dataProtection ? "data_protection" : "login_keychain"
            let status = SecItemAdd(add as CFDictionary, nil)
            report[prefix + "_add_status"] = Int(status)
            if status == errSecSuccess {
                var read = query; read[kSecReturnData as String] = true; read[kSecMatchLimit as String] = kSecMatchLimitOne
                var value: CFTypeRef?
                let readStatus = SecItemCopyMatching(read as CFDictionary, &value)
                report[prefix + "_roundtrip"] = readStatus == errSecSuccess && (value as? Data) == add[kSecValueData as String] as? Data
                report[prefix + "_cleanup_status"] = Int(SecItemDelete(query as CFDictionary))
            }
        }
        return report
    }
}
