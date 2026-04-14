import XCTest
import CryptoKit
@testable import PaprikaCore
import Network
import Security

class MockKeyManager: KeyManager {
    // Keep a persistent key for the test session
    private var testKey: SecKey?
    
    override init() {
         super.init()
         let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        var error: Unmanaged<CFError>?
        testKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)
    }

    override func listKeys() throws -> [String] {
        return ["test-key"]
    }
    
    override func getKey(name: String) throws -> SecKey? {
        if name == "test-key" {
            return testKey
        }
        return nil
    }
    
    override func getPublicKeyData(key: SecKey) -> Data? {
        guard let publicKey = SecKeyCopyPublicKey(key) else { return nil }
        var error: Unmanaged<CFError>?
        return SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
    }
    
    override func sign(data: Data, keyName: String, reason: String = "") throws -> Data {
        guard let key = testKey else {
            throw KeyManagerError.signingFailed("No test key available")
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) else {
            throw KeyManagerError.signingFailed(error?.takeRetainedValue().localizedDescription ?? "Error")
        }
        return signature as Data
    }
}

final class AgentProtocolTests: XCTestCase {
    func testRequestIdentities() throws {
        let socketPath = "/tmp/ppk-\(UUID().uuidString.prefix(8)).sock"
        let keyManager = MockKeyManager()
        let server = AgentServer(socketPath: socketPath, keyManager: keyManager)
        
        try server.start()
        
        let expectation = self.expectation(description: "Identities Received")
        
        let connection = NWConnection(to: .unix(path: socketPath), using: .tcp)
        
        connection.stateUpdateHandler = { state in
            if case .ready = state {
                // Send SSH2_AGENTC_REQUEST_IDENTITIES (11)
                // Payload: [Byte 11]
                let payload = Data([11])
                
                // Packet: [UInt32 Length] [Payload]
                var packet = Data()
                var length = UInt32(payload.count).bigEndian
                withUnsafeBytes(of: &length) { packet.append(contentsOf: $0) }
                packet.append(payload)
                
                connection.send(content: packet, completion: .contentProcessed { _ in })
                
                // Read Response
                // First read length
                connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { content, _, _, _ in
                    guard let content = content else { return }
                    let len = content.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
                    
                    // Read Body
                    connection.receive(minimumIncompleteLength: Int(len), maximumLength: Int(len)) { body, _, _, _ in
                        guard let body = body else { return }
                        var reader = SSHReader(data: body)
                        
                        do {
                            let type = try reader.readByte()
                            XCTAssertEqual(type, 12) // SSH2_AGENT_IDENTITIES_ANSWER
                            
                            let count = try reader.readUInt32()
                            XCTAssertEqual(count, 1)
                            
                            let blob = try reader.readData()
                            XCTAssertFalse(blob.isEmpty)
                            
                            let comment = try reader.readString()
                            XCTAssertEqual(comment, "test-key")
                            
                            expectation.fulfill()
                        } catch {
                            XCTFail("Decoding failed: \(error)")
                        }
                    }
                }
            }
        }
        
        connection.start(queue: .global())
        
        waitForExpectations(timeout: 5, handler: nil)
        server.listener?.cancel()
    }
    
    func testSignRequest() throws {
        let socketPath = "/tmp/ppk-\(UUID().uuidString.prefix(8)).sock"
        let keyManager = MockKeyManager()
        let server = AgentServer(socketPath: socketPath, keyManager: keyManager)
        try server.start()
        
        let expectation = self.expectation(description: "Signature Received")
        
        let connection = NWConnection(to: .unix(path: socketPath), using: .tcp)
        connection.stateUpdateHandler = { state in
            if case .ready = state {
                self.getIdentity(connection: connection) { blob in
                    var writer = SSHWriter()
                    writer.write(UInt8(13)) // SSH2_AGENTC_SIGN_REQUEST
                    writer.write(blob)
                    writer.write("Hello World".data(using: .utf8)!)
                    writer.write(UInt32(0)) // Flags
                    
                    var packet = Data()
                    var length = UInt32(writer.data.count).bigEndian
                    withUnsafeBytes(of: &length) { packet.append(contentsOf: $0) }
                    packet.append(writer.data)
                    
                    connection.send(content: packet, completion: .contentProcessed { _ in })
                    
                    connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { content, _, _, _ in
                        guard let content = content else { return }
                        let len = content.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
                        connection.receive(minimumIncompleteLength: Int(len), maximumLength: Int(len)) { body, _, _, _ in
                            guard let body = body else { return }
                            var reader = SSHReader(data: body)
                            let type = try? reader.readByte()
                            XCTAssertEqual(type, 14, "Expected SSH2_AGENT_SIGN_RESPONSE")
                            
                            let sigBlob = try? reader.readData()
                            XCTAssertNotNil(sigBlob)
                            // Verify sigBlob structure? [string format] ...
                            if let sigBlob = sigBlob {
                                var sigReader = SSHReader(data: sigBlob)
                                let format = try? sigReader.readString()
                                XCTAssertEqual(format, "ecdsa-sha2-nistp256")
                            }
                            
                            expectation.fulfill()
                        }
                    }
                }
            }
        }
        connection.start(queue: .global())
        waitForExpectations(timeout: 5, handler: nil)
        server.listener?.cancel()
    }
    
    func getIdentity(connection: NWConnection, completion: @escaping (Data) -> Void) {
        var writer = SSHWriter()
        writer.write(UInt8(11))
        var packet = Data()
        var length = UInt32(writer.data.count).bigEndian
        withUnsafeBytes(of: &length) { packet.append(contentsOf: $0) }
        packet.append(writer.data)
        
        connection.send(content: packet, completion: .contentProcessed { _ in })
        
        connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { content, _, _, _ in
            guard let content = content else { return }
            let len = content.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            connection.receive(minimumIncompleteLength: Int(len), maximumLength: Int(len)) { body, _, _, _ in
                var reader = SSHReader(data: body!)
                _ = try? reader.readByte()
                _ = try? reader.readUInt32()
                if let blob = try? reader.readData() {
                    completion(blob)
                }
            }
        }
    }
}

final class AuditLogTests: XCTestCase {
    func testAppendAndChain() throws {
        let path = URL(fileURLWithPath: "/tmp/paprika-audit-\(UUID().uuidString.prefix(8)).log")
        defer { try? FileManager.default.removeItem(at: path) }

        let log = AuditLog(path: path)
        log.record(keyName: "test", data: Data("first".utf8), context: "ctx one")
        log.record(keyName: "test", data: Data("second".utf8), context: "ctx two")
        log.record(keyName: "test", data: Data("third".utf8), context: "ctx three")

        let entries = log.readAll()
        let rawLines = log.readRawLines()
        XCTAssertEqual(entries.count, 3)
        XCTAssertEqual(rawLines.count, 3)

        XCTAssertEqual(entries[0].key, "test")
        XCTAssertEqual(entries[0].context, "ctx one")
        XCTAssertEqual(entries[1].context, "ctx two")
        XCTAssertEqual(entries[2].context, "ctx three")

        // Verify the hash chain: each entry's prev_sha256 should equal
        // SHA256(previous line's raw bytes without the trailing \n).
        func sha256Hex(_ s: String) -> String {
            SHA256.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
        }

        XCTAssertEqual(entries[0].prev_sha256, sha256Hex(""),
                       "first entry should anchor to SHA256(empty)")
        XCTAssertEqual(entries[1].prev_sha256, sha256Hex(rawLines[0]),
                       "second entry should back-link to sha256 of line 1")
        XCTAssertEqual(entries[2].prev_sha256, sha256Hex(rawLines[1]),
                       "third entry should back-link to sha256 of line 2")
    }

    func testSpecialCharactersInContextRoundTrip() throws {
        let path = URL(fileURLWithPath: "/tmp/paprika-audit-\(UUID().uuidString.prefix(8)).log")
        defer { try? FileManager.default.removeItem(at: path) }

        let log = AuditLog(path: path)
        // JSON encoding handles tabs, newlines, quotes, backslashes,
        // and unicode natively — no sanitization needed on our side.
        // Round-trip must preserve the exact original context.
        let gnarly = "evil\tctx\nwith\"quotes\\and\r\nnewlines\u{1F600}"
        log.record(keyName: "k", data: Data("x".utf8), context: gnarly)

        let entries = log.readAll()
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].context, gnarly,
                       "JSON escaping should round-trip special characters losslessly")
    }

    func testRawLinesAreValidJSON() throws {
        let path = URL(fileURLWithPath: "/tmp/paprika-audit-\(UUID().uuidString.prefix(8)).log")
        defer { try? FileManager.default.removeItem(at: path) }

        let log = AuditLog(path: path)
        log.record(keyName: "k", data: Data("x".utf8), context: "c")

        let rawLines = log.readRawLines()
        XCTAssertEqual(rawLines.count, 1)
        // Should parse as JSON
        let parsed = try JSONSerialization.jsonObject(with: Data(rawLines[0].utf8))
        XCTAssertTrue(parsed is [String: Any])
    }
}

final class SignContextParserTests: XCTestCase {
    func testSSHSIGGitNamespace() {
        // SSHSIG magic + version(1) + namespace("git") + reserved("") + ...
        var blob = SSHWriter()
        blob.writeRaw(Data("SSHSIG".utf8))
        blob.write(UInt32(1))              // version
        blob.write("git")                  // namespace
        blob.write("")                     // reserved
        blob.write("sha512")               // hash algo
        blob.write(Data([0x01, 0x02]))     // H(message)

        let reason = AgentServer.signContextDescription(for: blob.data)
        XCTAssertEqual(reason, "Paprika: sign git commit or tag")
    }

    func testSSHSIGFileNamespace() {
        var blob = SSHWriter()
        blob.writeRaw(Data("SSHSIG".utf8))
        blob.write(UInt32(1))
        blob.write("file")
        blob.write("")
        blob.write("sha512")
        blob.write(Data([0x00]))

        XCTAssertEqual(
            AgentServer.signContextDescription(for: blob.data),
            "Paprika: sign file"
        )
    }

    func testSSHAuthRequest() {
        // Construct what ssh normally passes as data-to-sign for publickey auth:
        //   session_id, 50, username, service, "publickey", TRUE, algo, pubkey
        var blob = SSHWriter()
        blob.write(Data(repeating: 0xAB, count: 32))   // session id
        blob.write(UInt8(50))                          // SSH_MSG_USERAUTH_REQUEST
        blob.write("klobucar")                         // username
        blob.write("ssh-connection")                   // service
        blob.write("publickey")                        // method
        blob.write(UInt8(1))                           // has signature (TRUE)
        blob.write("ecdsa-sha2-nistp256")              // algo
        blob.write(Data([0x04, 0x05, 0x06]))           // public key blob

        let reason = AgentServer.signContextDescription(for: blob.data)
        XCTAssertEqual(reason, "Paprika: SSH auth as klobucar (ssh-connection)")
    }

    func testUnknownPayloadFallback() {
        let reason = AgentServer.signContextDescription(for: Data([0xFF, 0xFE, 0xFD]))
        XCTAssertEqual(reason, "Paprika: authorize SSH signing")
    }
}
