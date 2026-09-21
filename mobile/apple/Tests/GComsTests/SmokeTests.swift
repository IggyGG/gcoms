import XCTest
@testable import GComs
final class SmokeTests: XCTestCase {
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
