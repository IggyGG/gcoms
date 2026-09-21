import Foundation
import Security
import GComs

public struct PushState: Codable, Sendable {
    public var reference: String?
    public var managementToken: String?
    public var expires: UInt64 = 0
    public var revision: UInt64 = 0
    public init() {}
}

public protocol PushStorage: Sendable {
    func load() async throws -> PushState
    func save(_ value: PushState) async throws
}

/// Use one gateway per profile. Registration tickets come from the app's server.
public actor PushGateway {
    private let origin: URL
    private let storage: any PushStorage
    private let session: URLSession
    private var busy = false
    public init(origin: URL, storage: any PushStorage) throws {
        guard origin.scheme == "https", origin.host != nil, origin.user == nil,
            origin.password == nil, origin.query == nil, origin.fragment == nil,
            ["", "/"].contains(origin.path) else { throw GComsError.invalidResponse }
        self.origin = origin
        self.storage = storage
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 10
        config.httpMaximumConnectionsPerHost = 1
        self.session = URLSession(configuration: config, delegate: NoRedirect(), delegateQueue: nil)
    }
    private func post(_ path: String, _ body: [String: Any]) async throws -> [String: Any] {
        let data = try JSONSerialization.data(withJSONObject: body)
        guard data.count <= 8192 else { throw GComsError.invalidResponse }
        var request = URLRequest(url: origin.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = data
        let (stream, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse, (200..<300).contains(response.statusCode) else {
            throw GComsError.native("Push gateway rejected request")
        }
        var received = Data()
        for try await byte in stream {
            guard received.count < 8192 else { throw GComsError.invalidResponse }
            received.append(byte)
        }
        guard let result = try JSONSerialization.jsonObject(with: received) as? [String: Any] else {
            throw GComsError.invalidResponse
        }
        return result
    }
    /// Call from didRegisterForRemoteNotificationsWithDeviceToken, with a fresh ticket.
    public func register(ticket: String, deviceToken: Data) async throws {
        guard !busy else { throw GComsError.unavailable }
        busy = true
        defer { busy = false }
        guard ticket.utf8.count <= 4096, !deviceToken.isEmpty, deviceToken.count <= 256 else {
            throw GComsError.invalidResponse
        }
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        let reply = try await post("v1/register", ["ticket": ticket, "platform": "apns", "token": token])
        guard let reference = reply["reference"] as? String, Self.valid(reference),
            let management = reply["management_token"] as? String, Self.valid(management),
            let expiry = reply["expires"] as? NSNumber else { throw GComsError.invalidResponse }
        var state = try await storage.load()
        state.reference = reference
        state.managementToken = management
        state.expires = expiry.uint64Value
        try await storage.save(state)
    }
    /// Persist a revision before binding; repeat after reopen and before suspension.
    public func bind(to sdk: GComs) async throws {
        guard !busy else { throw GComsError.unavailable }
        busy = true
        defer { busy = false }
        var state = try await storage.load()
        let reference = state.reference ?? String(repeating: "0", count: 64)
        guard Self.valid(reference), state.revision < UInt64.max else { throw GComsError.invalidResponse }
        let now = UInt64(Date().timeIntervalSince1970)
        let expiry = state.reference == nil ? now + 3600 : min(now + 23 * 3600, state.expires)
        guard expiry > now else { throw GComsError.native("Refresh expired push registration first") }
        state.revision += 1
        try await storage.save(state)
        let chars = Array(reference)
        let bytes = stride(from: 0, to: 64, by: 2).map { UInt8(String(chars[$0..<$0 + 2]), radix: 16)! }
        _ = try await sdk.request(JSONSerialization.data(withJSONObject: [
            "op": "bind_push", "reference": bytes, "revision": state.revision, "expires": expiry
        ]))
    }
    /// Disable gateway delivery, then call bind(to:) to remove current relay bindings.
    public func unregister() async throws {
        guard !busy else { throw GComsError.unavailable }
        busy = true
        defer { busy = false }
        var state = try await storage.load()
        if let reference = state.reference, let token = state.managementToken {
            _ = try await post("v1/unregister", ["reference": reference, "management_token": token])
        }
        state.reference = nil
        state.managementToken = nil
        state.expires = 0
        try await storage.save(state)
    }
    public nonisolated static func hintReference(_ userInfo: [AnyHashable: Any]) -> String? {
        guard userInfo["gcoms_activity"] as? String == "message",
            let reference = userInfo["gcoms_reference"] as? String, valid(reference),
            Set(userInfo.keys.compactMap { $0 as? String }) == Set(["aps", "gcoms_activity", "gcoms_reference"]) else { return nil }
        return reference
    }
    private nonisolated static func valid(_ value: String) -> Bool {
        value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
    }
}

private final class NoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

/// Non-synchronizing device-only storage. One instance per profile.
public actor KeychainPushStorage: PushStorage {
    private let account: String
    public init(profile: String) throws {
        guard profile.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil else {
            throw GComsError.invalidResponse
        }
        account = profile
    }
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "boo.gcoms.push",
         kSecAttrAccount as String: account, kSecAttrSynchronizable as String: false]
    }
    public func load() throws -> PushState {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return PushState() }
        guard status == errSecSuccess, let data = result as? Data, data.count <= 8192 else {
            throw GComsError.native("Push keychain is unavailable")
        }
        return try JSONDecoder().decode(PushState.self, from: data)
    }
    public func save(_ value: PushState) throws {
        let data = try JSONEncoder().encode(value)
        guard data.count <= 8192 else { throw GComsError.invalidResponse }
        let attributes: [String: Any] = [kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(attributes) { _, value in value } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw GComsError.native("Push keychain write failed") }
    }
}
