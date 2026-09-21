import Foundation
import Security

public protocol UnlockProvider: Sendable {
    func unlock() async throws -> Data
}

/// Keychain-backed app profile secret. Excluded from synchronization and backups.
public struct KeychainUnlockProvider: UnlockProvider {
    private let service: String
    private let account: String
    public init(service: String, account: String) {
        self.service = service
        self.account = account
    }
    public func unlock() async throws -> Data {
        try await Task.detached {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: false
            ]
            var result: CFTypeRef?
            var read = query
            read[kSecReturnData as String] = true
            read[kSecMatchLimit as String] = kSecMatchLimitOne
            let status = SecItemCopyMatching(read as CFDictionary, &result)
            if status == errSecSuccess, let data = result as? Data { return data }
            guard status == errSecItemNotFound else { throw GComsError.native("Keychain unlock unavailable") }
            var bytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw GComsError.unavailable }
            defer { bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            let secret = Data(Data(bytes).base64EncodedString().utf8)
            var create = query
            create[kSecValueData as String] = secret
            create[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let added = SecItemAdd(create as CFDictionary, nil)
            if added == errSecDuplicateItem {
                result = nil
                guard SecItemCopyMatching(read as CFDictionary, &result) == errSecSuccess,
                      let retained = result as? Data else { throw GComsError.unavailable }
                return retained
            }
            guard added == errSecSuccess else { throw GComsError.native("Keychain storage unavailable") }
            return secret
        }.value
    }
}
