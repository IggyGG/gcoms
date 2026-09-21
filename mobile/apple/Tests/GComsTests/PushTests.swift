#if GCOMS_PUSH
import XCTest
import GComsPush

final class PushTests: XCTestCase {
    func testGenericHintValidation() {
        var hint: [AnyHashable: Any] = ["aps": ["content-available": 1],
            "gcoms_activity": "message", "gcoms_reference": String(repeating: "a", count: 64)]
        XCTAssertNotNil(PushGateway.hintReference(hint))
        hint["message"] = "must not be forwarded"
        XCTAssertNil(PushGateway.hintReference(hint))
        hint.removeValue(forKey: "message")
        hint["gcoms_reference"] = "invalid"
        XCTAssertNil(PushGateway.hintReference(hint))
    }
    func testDeviceOnlyStateReopens() async throws {
        let storage = try KeychainPushStorage(profile: "test-" + UUID().uuidString)
        var state = PushState()
        state.revision = 12
        state.reference = String(repeating: "a", count: 64)
        try await storage.save(state)
        let restored = try await storage.load()
        XCTAssertEqual(restored.revision, 12)
        XCTAssertEqual(restored.reference, state.reference)
    }
}
#endif
