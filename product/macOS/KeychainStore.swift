import Foundation
import Security

struct KeychainStore {
    private let service = "org.example.microsoftmfamac.registration"
    private let account = "product-registration-v1"

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    func load() throws -> Data {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { throw ProductError.unavailable }
        return data
    }

    /// Intentionally add-only: importing never silently replaces a working credential.
    func importOnce(_ data: Data) throws {
        guard data.count <= 262_144,
              let bundle = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              bundle["version"] as? Int == 1,
              bundle["provider"] is [String: Any], bundle["account"] is [String: Any]
        else { throw ProductError.invalidMessage }
        var request = query
        request[kSecValueData as String] = data
        request[kSecAttrLabel as String] = "Microsoft MFA for Mac — imported research registration"
        // This ad-hoc development app has no provisioned application identifier.
        // Its Data Protection Keychain probe returns errSecMissingEntitlement.
        // Use the local login Keychain explicitly, with its normal per-app ACL;
        // do not claim iOS-style accessibility classes or enable synchronization.
        let status = SecItemAdd(request as CFDictionary, nil)
        if status == errSecDuplicateItem { throw ProductError.alreadyImported }
        guard status == errSecSuccess else { throw ProductError.failed }
    }
}
