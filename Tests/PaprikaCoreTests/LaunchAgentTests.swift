import XCTest
@testable import PaprikaCore

final class LaunchAgentTests: XCTestCase {
    func testPathWithXMLMetacharactersStaysOneArgument() throws {
        let path = "/Users/me/R&D <x></string><string>-c/Paprika.app/Contents/MacOS/paprika"
        let data = try LaunchAgent.plist(executablePath: path)
        let plist = try XCTUnwrap(
            PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        XCTAssertEqual(plist["Label"] as? String, "com.paprika.agent")
        XCTAssertEqual(plist["ProgramArguments"] as? [String], [path, "serve"])
        XCTAssertEqual(plist["ProcessType"] as? String, "Interactive")
        XCTAssertEqual(plist["RunAtLoad"] as? Bool, true)
        XCTAssertEqual(plist["KeepAlive"] as? [String: Bool], ["SuccessfulExit": false, "Crashed": true])
        XCTAssertEqual(plist["ThrottleInterval"] as? Int, 10)
    }
}
