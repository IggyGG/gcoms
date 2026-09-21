import Foundation
import CGComs

public enum GComsError: Error {
    case unavailable
    case closed
    case native(String)
    case invalidResponse
}

/// Link either the client or relay XCFramework, never both.
public actor GComs {
    private var handle: UInt64
    public nonisolated let role: UInt32
    public init() throws {
        guard gcoms_mobile_abi_version() == 1 else { throw GComsError.unavailable }
        let value = gcoms_mobile_create()
        guard value != 0 else { throw GComsError.unavailable }
        handle = value
        role = gcoms_mobile_role()
    }

    /// Request/reply JSON uses the ABI v1 schema. Returns the complete {ok|error} envelope.
    /// A cancelled mutation may already have committed; reconcile before retrying it.
    public func request(_ input: Data) async throws -> Data {
        guard handle != 0 else { throw GComsError.closed }
        let session = handle
        let ticket = input.withUnsafeBytes {
            gcoms_mobile_submit(session, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
        }
        guard ticket != 0 else { throw GComsError.unavailable }
        defer { _ = gcoms_mobile_cancel(session, ticket) }
        while true {
            try Task.checkCancellation()
            let length = gcoms_mobile_take(session, ticket, nil, 0)
            guard length >= 0 && length <= 2 * 1024 * 1024 else { throw GComsError.unavailable }
            if length != 0 {
                var result = Data(count: length)
                let copied = result.withUnsafeMutableBytes {
                    gcoms_mobile_take(session, ticket, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
                }
                guard copied == length else { throw GComsError.unavailable }
                let envelope = try JSONSerialization.jsonObject(with: result) as? [String: Any]
                if let error = envelope?["error"] as? String { throw GComsError.native(error) }
                guard envelope?.keys.contains("ok") == true else { throw GComsError.invalidResponse }
                return result
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    public func open(configuration: Data) async throws -> Data {
        let config = try JSONSerialization.jsonObject(with: configuration)
        return try await request(JSONSerialization.data(withJSONObject: ["op": "open", "config": config]))
    }
    public func suspendProfile() async throws {
        _ = try await request(Data(#"{"op":"suspend"}"#.utf8))
    }
    /// Call on application suspension; resume with a freshly unlocked configuration.
    public func close() async throws {
        let session = handle
        handle = 0
        guard session != 0 else { return }
        let status: Int32 = await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                continuation.resume(returning: gcoms_mobile_destroy(session))
            }
        }
        guard status == 0 else { throw GComsError.native("Native shutdown failed") }
    }
    deinit {
        let session = handle
        if session != 0 {
            DispatchQueue.global(qos: .utility).async { _ = gcoms_mobile_destroy(session) }
        }
    }

    private func files(_ request: Any) async throws -> [String: Any] {
        let envelope = try await self.request(JSONSerialization.data(withJSONObject: ["op": "files", "request": request]))
        guard let object = try JSONSerialization.jsonObject(with: envelope) as? [String: Any],
              let reply = object["ok"] as? [String: Any] else { throw GComsError.invalidResponse }
        return reply
    }
    /// The caller opens/closes the stream and keeps any security-scoped URL access alive.
    public func importFile(scope: Data, name: String, size: UInt64, source: InputStream) async throws -> [UInt8] {
        guard size <= 10 * 1024 * 1024 * 1024 else { throw GComsError.invalidResponse }
        var id = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, id.count, &id) == errSecSuccess else { throw GComsError.unavailable }
        let scopeValue = try JSONSerialization.jsonObject(with: scope)
        _ = try await files(["Prepare": ["id": id, "scope": scopeValue, "name": name, "size_bytes": size]])
        do {
            var remaining = size
            var piece: UInt32 = 0
            var buffer = [UInt8](repeating: 0, count: 256 * 1024)
            defer { buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            while remaining != 0 {
                try Task.checkCancellation()
                let count = Int(min(remaining, UInt64(buffer.count)))
                var offset = 0
                while offset < count {
                    let received = buffer.withUnsafeMutableBufferPointer {
                        source.read($0.baseAddress!.advanced(by: offset), maxLength: count - offset)
                    }
                    guard received > 0 else { throw GComsError.native("Source ended before declared length") }
                    offset += received
                }
                _ = try await files(["WritePiece": ["id": id, "piece": piece, "bytes": Array(buffer.prefix(count))]])
                remaining -= UInt64(count)
                piece += 1
            }
            var extra: UInt8 = 0
            guard source.read(&extra, maxLength: 1) == 0 else { throw GComsError.native("Source exceeds declared length") }
            _ = try await files(["Commit": ["id": id]])
            return id
        } catch {
            // Cleanup is independent of the caller's cancellation state.
            let cleanup = Task { _ = try? await files(["Cancel": ["id": id]]) }
            await cleanup.value
            throw error
        }
    }
    public func exportFile(id: [UInt8], destination: OutputStream) async throws {
        let reply = try await files("List")
        guard let snapshot = reply["Snapshot"] as? [String: Any],
              let entries = snapshot["files"] as? [[String: Any]],
              let info = entries.first(where: { ($0["id"] as? [UInt8]) == id }),
              info["status"] as? String == "Complete",
              let size = info["size_bytes"] as? NSNumber else { throw GComsError.invalidResponse }
        var remaining = size.uint64Value
        var piece: UInt32 = 0
        while remaining != 0 {
            let reply = try await files(["ReadPiece": ["id": id, "piece": piece]])
            guard var bytes = reply["Piece"] as? [UInt8], bytes.count == Int(min(remaining, 256 * 1024)) else {
                throw GComsError.invalidResponse
            }
            defer { bytes.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
            var offset = 0
            while offset < bytes.count {
                try Task.checkCancellation()
                let written = bytes.withUnsafeBufferPointer {
                    destination.write($0.baseAddress!.advanced(by: offset), maxLength: bytes.count - offset)
                }
                guard written > 0 else { throw GComsError.native("Destination write failed") }
                offset += written
            }
            remaining -= UInt64(bytes.count)
            piece += 1
        }
    }
}
import Security
