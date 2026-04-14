import Foundation
import Security
import LocalAuthentication
import CryptoKit

public enum KeyManagerError: Error {
    case generationFailed(String)
    case deletionFailed(OSStatus)
    case itemNotFound
    case unexpectedData
    case signingFailed(String)
}

open class KeyManager {
    public static let tagPrefix = "com.paprika.keys."
    
    public init() {}

    open func generateKey(name: String) throws -> SecKey {
        let tag = (Self.tagPrefix + name).data(using: .utf8)!
        
        // biometryCurrentSet (vs. biometryAny) invalidates the key if the
        // enrolled Touch ID fingerprint set changes after key creation.
        // This blocks the "attacker with brief physical access enrolls a
        // new fingerprint" attack, at the cost of requiring users to
        // re-generate keys after any Touch ID re-enrollment.
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        ) else {
            throw KeyManagerError.generationFailed("Could not create access control")
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: accessControl
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let err = error?.takeRetainedValue()
            throw KeyManagerError.generationFailed(err?.localizedDescription ?? "Unknown error")
        }
        return key
    }

    open func deleteKey(name: String) throws {
        let tag = (Self.tagPrefix + name).data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyManagerError.deletionFailed(status)
        }
    }
    
    open func getKey(name: String) throws -> SecKey? {
        let tag = (Self.tagPrefix + name).data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeyManagerError.itemNotFound
        }
        
        return (item as! SecKey)
    }

    open func listKeys() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
             return []
        }
        
        return items.compactMap { item in
            guard let tagData = item[kSecAttrApplicationTag as String] as? Data,
                  let tag = String(data: tagData, encoding: .utf8),
                  tag.hasPrefix(Self.tagPrefix) else {
                return nil
            }
            return String(tag.dropFirst(Self.tagPrefix.count))
        }
    }
    
    open func sign(data: Data, keyName: String) throws -> Data {
        let tag = (Self.tagPrefix + keyName).data(using: .utf8)!
        // Fresh LAContext per call — no cached authentication carries over,
        // so the Secure Enclave will demand Touch ID every time.
        let context = LAContext()
        context.localizedReason = "Paprika: authorize SSH signing"

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw KeyManagerError.signingFailed("Could not retrieve key '\(keyName)' for signing (OSStatus \(status))")
        }
        let key = item as! SecKey

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) else {
            throw KeyManagerError.signingFailed(error?.takeRetainedValue().localizedDescription ?? "Unknown error")
        }
        return signature as Data
    }
    
    open func getPublicKeyData(key: SecKey) -> Data? {
        guard let publicKey = SecKeyCopyPublicKey(key) else { return nil }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) else { return nil }
        return data as Data
    }

    open func getSSHPublicKey(key: SecKey) -> String? {
        guard let pubKeyData = getPublicKeyData(key: key) else { return nil }
        
        var blobWriter = SSHWriter()
        blobWriter.write("ecdsa-sha2-nistp256")
        blobWriter.write("nistp256")
        blobWriter.write(pubKeyData)
        
        return "ecdsa-sha2-nistp256 \(blobWriter.data.base64EncodedString())"
    }
}
