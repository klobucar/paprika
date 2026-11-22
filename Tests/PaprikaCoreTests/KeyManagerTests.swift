import XCTest
@testable import PaprikaCore

final class KeyManagerTests: XCTestCase {
    func testGenerateRefusesExistingName() {
        // MockKeyManager already has "test-key"; the check must fire before
        // anything reaches the Secure Enclave.
        XCTAssertThrowsError(try MockKeyManager().generateKey(name: "test-key")) { error in
            guard case KeyManagerError.alreadyExists("test-key") = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }
}
