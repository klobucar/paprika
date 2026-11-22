import XCTest
import CryptoKit
@testable import PaprikaCore

extension Data {
    init(hex: String) {
        var bytes = [UInt8]()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            bytes.append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
        self.init(bytes)
    }
}

final class RealPayloadTests: XCTestCase {
    /// Data-to-sign that `ssh-keygen -Y sign -n git` (OpenSSH 10.5) sent
    /// the agent for the message "paprika\n", captured off the socket.
    static let sshKeygenGitPayload = Data(hex:
        "5353485349470000000367697400000000000000067368613531320000004076" +
        "1be764dbb01717b39c7fc666ab1dfb4f7f1fd71947655ddf71329b822587925c" +
        "4aca8a320ee2bb9415cdc0976126477668146112da67b78d4f138a78e5e630")

    func testSSHKeygenGitPayloadGetsGitPrompt() {
        XCTAssertEqual(
            AgentServer.signContextDescription(for: Self.sshKeygenGitPayload),
            "Paprika: sign git commit or tag")
    }

    func testSSHKeygenPayloadMatchesProtocolLayout() {
        // PROTOCOL.sshsig signed data: no version field after the magic.
        var w = SSHWriter()
        w.writeRaw(Data("SSHSIG".utf8))
        w.write("git")
        w.write("")
        w.write("sha512")
        w.write(Data(SHA512.hash(data: Data("paprika\n".utf8))))
        XCTAssertEqual(w.data, Self.sshKeygenGitPayload)
    }

    func testHostboundAuthRequest() {
        // OpenSSH 8.9+ uses this method when the server advertises
        // publickey-hostbound@openssh.com; the server host key follows.
        var blob = SSHWriter()
        blob.write(Data(repeating: 0xAB, count: 32))
        blob.write(UInt8(50))
        blob.write("git")
        blob.write("ssh-connection")
        blob.write("publickey-hostbound-v00@openssh.com")
        blob.write(UInt8(1))
        blob.write("ecdsa-sha2-nistp256")
        blob.write(Data([0x04, 0x05]))
        var hostKey = SSHWriter()
        hostKey.write("ssh-ed25519")
        hostKey.write(Data(repeating: 0x11, count: 32))
        blob.write(hostKey.data)

        XCTAssertEqual(
            AgentServer.signContextDescription(for: blob.data),
            "Paprika: SSH auth as git (ssh-connection)")
    }

    func testNamespaceControlAndBidiCharactersAreNeutralized() {
        var blob = SSHWriter()
        blob.writeRaw(Data("SSHSIG".utf8))
        blob.write("evil\u{202E}\nApproved")
        blob.write("")
        blob.write("sha512")
        blob.write(Data([0x00]))
        XCTAssertEqual(
            AgentServer.signContextDescription(for: blob.data),
            "Paprika: sign evil??Approved")
    }

    func testUsernameControlAndBidiCharactersAreNeutralized() {
        var blob = SSHWriter()
        blob.write(Data(repeating: 0x01, count: 32))
        blob.write(UInt8(50))
        blob.write("root\u{202E}\u{2028}ok")
        blob.write("ssh-connection")
        blob.write("publickey")
        XCTAssertEqual(
            AgentServer.signContextDescription(for: blob.data),
            "Paprika: SSH auth as root??ok (ssh-connection)")
    }

    func testPromptSafeTruncatesAndKeepsOrdinaryUnicode() {
        XCTAssertEqual(AgentServer.promptSafe("José"), "José")
        XCTAssertEqual(AgentServer.promptSafe(String(repeating: "a", count: 100)),
                       String(repeating: "a", count: 64) + "…")
        XCTAssertEqual(AgentServer.promptSafe(String(repeating: "a", count: 64)),
                       String(repeating: "a", count: 64))
    }
}
