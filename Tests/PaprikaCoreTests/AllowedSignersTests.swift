import XCTest
@testable import PaprikaCore

final class AllowedSignersTests: XCTestCase {
    let key = "ecdsa-sha2-nistp256 AAAAE2VjZHNh"

    func testPlainEmail() throws {
        XCTAssertEqual(try AllowedSigners.line(email: "me@example.com", publicKey: key),
                       "me@example.com \(key)\n")
    }

    func testRejectsInjectionAttempts() {
        for email in [
            "* ecdsa-sha2-nistp256 AAAAattacker",   // space: smuggles a second key
            "me@example.com\tcert-authority",        // tab: smuggles an option
            "me@example.com\nother@x ecdsa AAAA",    // newline: smuggles a line
            "*", "a@b,c@d", "a?b@c", "!a@b", "\"a\"@b", "#me@example.com", "",
            "me@exa\u{0}mple.com", "me@example.com\u{2028}",
        ] {
            XCTAssertThrowsError(try AllowedSigners.line(email: email, publicKey: key), "accepted \(email.debugDescription)")
        }
    }

    func testRejectsNewlineInKey() {
        XCTAssertThrowsError(try AllowedSigners.line(email: "me@example.com", publicKey: "\(key)\nx"))
    }
}
