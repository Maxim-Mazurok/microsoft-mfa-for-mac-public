import Foundation
import CoreFoundation
import Security

public enum DeviceKeyError: String, Error {
    case invalidInput = "invalid_input"
    case keyNotFound = "research_key_not_found"
    case keyExists = "research_key_exists"
    case keychainUnavailable = "keychain_unavailable"
    case keyCreationFailed = "key_creation_failed"
    case keyProtectionUnverified = "key_protection_unverified"
    case publicKeyUnavailable = "public_key_unavailable"
    case signingFailed = "signing_failed"
    case cleanupFailed = "cleanup_failed"
}

public struct DeviceKeyRequest {
    public enum Action: String { case create, `public`, sign, delete }
    public enum Role: String { case device, transport }
    public static let maximumInputBytes = 1_048_576
    public static let maximumMessageBytes = 262_144
    public let action: Action
    public let namespace: String
    public let role: Role
    public let message: Data?
    public var tag: Data { Data(("org.example.microsoftmfamac.device-identity.research." + namespace + "." + role.rawValue).utf8) }

    public init(data: Data) throws {
        guard data.count <= Self.maximumInputBytes,
              let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let version = value["v"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), version.doubleValue == 1,
              let actionText = value["action"] as? String, let action = Action(rawValue: actionText),
              let namespace = value["namespace"] as? String,
              namespace.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", options: .regularExpression) != nil,
              UUID(uuidString: namespace) != nil,
              let roleText = value["role"] as? String, let role = Role(rawValue: roleText)
        else { throw DeviceKeyError.invalidInput }
        let keys: Set<String> = action == .sign ? ["v", "action", "namespace", "role", "data_base64"] : ["v", "action", "namespace", "role"]
        guard Set(value.keys) == keys else { throw DeviceKeyError.invalidInput }
        var message: Data?
        if action == .sign {
            guard let encoded = value["data_base64"] as? String, let decoded = Data(base64Encoded: encoded),
                  decoded.count <= Self.maximumMessageBytes, encoded == decoded.base64EncodedString() else { throw DeviceKeyError.invalidInput }
            message = decoded
        }
        self.action = action; self.namespace = namespace; self.role = role; self.message = message
    }
}

public enum RSAPublicEncoding {
    /// Apple exports RSA public keys as PKCS#1 RSAPublicKey. Wrap that public
    /// object in RFC 5280 SubjectPublicKeyInfo with rsaEncryption + NULL.
    public static func spki(pkcs1: Data) throws -> Data {
        guard pkcs1.count > 16, pkcs1.count <= 1024, pkcs1.first == 0x30 else { throw DeviceKeyError.publicKeyUnavailable }
        let algorithm = Data([0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00])
        let bitString = tlv(0x03, Data([0]) + pkcs1)
        return tlv(0x30, algorithm + bitString)
    }
    static func tlv(_ tag: UInt8, _ value: Data) -> Data {
        var length: [UInt8]
        if value.count < 128 { length = [UInt8(value.count)] }
        else {
            var count = value.count, bytes: [UInt8] = []
            while count > 0 { bytes.insert(UInt8(count & 255), at: 0); count >>= 8 }
            length = [0x80 | UInt8(bytes.count)] + bytes
        }
        return Data([tag] + length) + value
    }
}

public final class DeviceKeyStore {
    public init() {}
    private func query(_ request: DeviceKeyRequest) -> [String: Any] {
        [kSecClass as String: kSecClassKey, kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate, kSecAttrApplicationTag as String: request.tag,
         kSecUseDataProtectionKeychain as String: false]
    }
    private func lookup(_ request: DeviceKeyRequest) throws -> SecKey? {
        var lookup = query(request)
        lookup[kSecReturnRef as String] = true
        lookup[kSecReturnAttributes as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let values = result as? [String: Any],
              values[kSecAttrApplicationTag as String] as? Data == request.tag,
              let reference = values[kSecValueRef as String], CFGetTypeID(reference as CFTypeRef) == SecKeyGetTypeID()
        else { throw DeviceKeyError.keychainUnavailable }
        return (reference as! SecKey)
    }
    private func validate(_ key: SecKey) throws {
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeRSA as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 2048,
              attributes[kSecAttrIsExtractable as String] as? Bool == false
        else { throw DeviceKeyError.keyProtectionUnverified }
    }
    private func publicKey(_ key: SecKey) throws -> (SecKey, Data) {
        guard let publicKey = SecKeyCopyPublicKey(key) else { throw DeviceKeyError.publicKeyUnavailable }
        var error: Unmanaged<CFError>?
        guard let publicBytes = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else { throw DeviceKeyError.publicKeyUnavailable }
        return (publicKey, try RSAPublicEncoding.spki(pkcs1: publicBytes))
    }
    public func execute(_ request: DeviceKeyRequest) throws -> [String: Any] {
        var result: [String: Any] = ["v": 1, "ok": true, "action": request.action.rawValue, "namespace": request.namespace, "role": request.role.rawValue]
        if request.action == .delete {
            guard try lookup(request) != nil else { result["deleted"] = false; return result }
            let status = SecItemDelete(query(request) as CFDictionary)
            guard status == errSecSuccess, try lookup(request) == nil else { throw DeviceKeyError.cleanupFailed }
            result["deleted"] = true
            return result
        }
        let key: SecKey
        let publicKey: SecKey
        let spki: Data
        if request.action == .create {
            guard try lookup(request) == nil else { throw DeviceKeyError.keyExists }
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048,
                kSecUseDataProtectionKeychain as String: false,
                // On this legacy macOS provider the top-level flag is required;
                // the same flag only inside PrivateKeyAttrs was ignored.
                kSecAttrIsExtractable as String: false,
                kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true, kSecAttrIsExtractable as String: false,
                    kSecAttrApplicationTag as String: request.tag,
                    kSecAttrLabel as String: "Microsoft MFA for Mac research " + request.role.rawValue + " " + request.namespace]
            ]
            var error: Unmanaged<CFError>?
            guard let generated = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else { throw DeviceKeyError.keyCreationFailed }
            do {
                try validate(generated)
                guard try lookup(request) != nil else { throw DeviceKeyError.keyCreationFailed }
                (publicKey, spki) = try self.publicKey(generated)
                key = generated
            } catch {
                // Only this just-created exact namespace/role is eligible for
                // automatic rollback; no other Keychain query/delete is used.
                guard SecItemDelete(query(request) as CFDictionary) == errSecSuccess else { throw DeviceKeyError.cleanupFailed }
                throw error
            }
        } else {
            guard let existing = try lookup(request) else { throw DeviceKeyError.keyNotFound }
            key = existing
            try validate(key)
            (publicKey, spki) = try self.publicKey(key)
        }
        result.merge(["public_key_format": "spki_der", "public_key_base64": spki.base64EncodedString(), "key_type": "RSA", "key_size": 2048,
                      "storage": "login_keychain", "software_key": true, "private_exportable": false, "attestation": false]) { _, new in new }
        if request.action == .sign {
            guard let message = request.message, SecKeyIsAlgorithmSupported(key, .sign, .rsaSignatureMessagePKCS1v15SHA256) else { throw DeviceKeyError.signingFailed }
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, message as CFData, &error) as Data?,
                  SecKeyVerifySignature(publicKey, .rsaSignatureMessagePKCS1v15SHA256, message as CFData, signature as CFData, &error)
            else { throw DeviceKeyError.signingFailed }
            result["algorithm"] = "RS256"; result["signature_base64"] = signature.base64EncodedString()
        }
        return result
    }
}
