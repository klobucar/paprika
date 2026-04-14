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
    
    override func sign(data: Data, keyName: String) throws -> Data {
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
