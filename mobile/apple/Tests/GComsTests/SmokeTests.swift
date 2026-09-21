import XCTest
@testable import GComs
final class SmokeTests: XCTestCase {
    func testDeviceOnlyUnlockReopens() async throws {
        let account = "test-" + UUID().uuidString
        let provider = KeychainUnlockProvider(service: "boo.gcoms.preview.tests", account: account)
        let original = try await provider.unlock()
        let reopened = KeychainUnlockProvider(service: "boo.gcoms.preview.tests", account: account)
        let restored = try await reopened.unlock()
        XCTAssertFalse(original.isEmpty)
        XCTAssertEqual(original, restored)
    }

    func testNativeOwnershipAndCancellation() async throws {
        let session = try GComs()
        XCTAssertTrue([1, 2].contains(session.role))
        do {
            _ = try await session.request(Data(#"{"op":"identity"}"#.utf8))
            XCTFail("suspended profile must reject identity")
        } catch GComsError.native { }
        try await session.suspendProfile()
        try await session.close()
        try await session.close()
    }
}
