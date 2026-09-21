import XCTest
@testable import GComs

final class RelayTests: XCTestCase {
    func testChannelsFilesAndProfileReopen() async throws {
        let session = try GComs()
        guard session.role == 2 else {
            try await session.close()
            throw XCTSkip("Relay fixture requires the relay distribution")
        }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let config = try JSONSerialization.data(withJSONObject: [
            "application": "mobile-smoke", "profile": root.appendingPathComponent("profile").path,
            "secret": "disposable-simulator-secret", "fixture": true
        ])
        do {
            let first = try await session.open(configuration: config)
            let channelReply = try await session.request(JSONSerialization.data(withJSONObject: [
                "op": "create_channel", "channel": "smoke", "display": "owner",
                "capacity": 8, "visibility": "Private"
            ]))
            let channelEnvelope = try XCTUnwrap(JSONSerialization.jsonObject(with: channelReply) as? [String: Any])
            let channel = try XCTUnwrap(channelEnvelope["ok"] as? [UInt8])
            let invitation = try await session.request(JSONSerialization.data(withJSONObject: [
                "op": "create_invitation", "channel": "smoke", "lifetime_secs": 3600
            ]))
            let invite = try XCTUnwrap(JSONSerialization.jsonObject(with: invitation) as? [String: Any])
            let link = try XCTUnwrap((invite["ok"] as? [String: Any])?["link"] as? String)
            XCTAssertFalse(link.isEmpty)
            let bytes = Data((0..<(256 * 1024 + 17)).map { UInt8($0 % 251) })
            let source = InputStream(data: bytes)
            source.open()
            defer { source.close() }
            let scope = try JSONSerialization.data(withJSONObject: ["channel": channel, "participants": []])
            let id = try await session.importFile(scope: scope, name: "smoke.bin",
                size: UInt64(bytes.count), source: source)
            try await session.suspendProfile()
            let second = try await session.open(configuration: config)
            let before = try XCTUnwrap(JSONSerialization.jsonObject(with: first) as? [String: Any])
            let after = try XCTUnwrap(JSONSerialization.jsonObject(with: second) as? [String: Any])
            let firstIdentity = try XCTUnwrap((before["ok"] as? [String: Any])?["safety_number"] as? String)
            let secondIdentity = try XCTUnwrap((after["ok"] as? [String: Any])?["safety_number"] as? String)
            XCTAssertEqual(firstIdentity, secondIdentity)
            let output = OutputStream.toMemory()
            output.open()
            defer { output.close() }
            try await session.exportFile(id: id, destination: output)
            XCTAssertEqual(output.property(forKey: .dataWrittenToMemoryStreamKey) as? Data, bytes)
            try await session.close()
        } catch {
            try? await session.close()
            throw error
        }
    }
}
