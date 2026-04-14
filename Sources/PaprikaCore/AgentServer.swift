import Foundation
import Network
import CryptoKit
import Security

public class AgentServer {
    public let socketPath: String
    public let keyManager: KeyManager
    public var listener: NWListener?
    
    public init(socketPath: String, keyManager: KeyManager) {
        self.socketPath = socketPath
        self.keyManager = keyManager
    }
    
    public func start() throws {
        unlink(socketPath)
        
        // Configure for Unix Socket using TCP parameters (Stream)
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.unix(path: socketPath)
        
        listener = try NWListener(using: parameters)
        
        listener?.stateUpdateHandler = { state in
            switch state {
            case .ready:
                print("Agent listening on \(self.socketPath)")
            case .failed(let error):
                print("Agent listener failed: \(error)")
                exit(1)
            default: break
            }
        }
        
        listener?.newConnectionHandler = { connection in
            self.handleConnection(connection)
        }
        
        listener?.start(queue: .main)
    }
    
    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: .global(qos: .userInitiated))
        readLoop(connection)
    }
    
    private func readLoop(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 4, maximumLength: 4) { content, _, isComplete, error in
            if isComplete {
                 connection.cancel()
                 return
            }
            if let error = error {
                print("Connection error: \(error)")
                connection.cancel()
                return
            }
            
            guard let content = content, content.count == 4 else { return }
            let length = content.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            
            connection.receive(minimumIncompleteLength: Int(length), maximumLength: Int(length)) { body, _, _, error in
                if let error = error {
                    print("Read body error: \(error)")
                    connection.cancel()
                    return
                }
                
                guard let body = body, body.count == Int(length) else {
                    connection.cancel()
                    return
                }
                
                self.processMessage(body, connection: connection)
                self.readLoop(connection)
            }
        }
    }
    
    private func processMessage(_ data: Data, connection: NWConnection) {
        var reader = SSHReader(data: data)
        
        do {
            let msgType = try reader.readByte()
            
            switch msgType {
            case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
                try handleRequestIdentities(connection: connection)
            case 13: // SSH2_AGENTC_SIGN_REQUEST
                try handleSignRequest(reader: &reader, connection: connection)
            default:
                sendFailure(connection: connection)
            }
        } catch {
            print("Protocol error: \(error)")
            sendFailure(connection: connection)
        }
    }
    
    private func sendFailure(connection: NWConnection) {
        let data = Data([5])
        send(payload: data, connection: connection)
    }
    
    private func send(payload: Data, connection: NWConnection) {
        var writer = SSHWriter()
        writer.write(UInt32(payload.count))
        writer.writeRaw(payload)
        
        connection.send(content: writer.data, completion: .contentProcessed { error in
            if let error = error {
                print("Send error: \(error)")
            }
        })
    }
    
    // MARK: - Handlers
    
    private func handleRequestIdentities(connection: NWConnection) throws {
        let keys = try keyManager.listKeys()
        var writer = SSHWriter()
        writer.write(UInt8(12)) // SSH2_AGENT_IDENTITIES_ANSWER
        
        var identitiesBuffer = Data()
        var validKeyCount: UInt32 = 0
        
        for name in keys {
            if let key = try? keyManager.getKey(name: name),
               let pubKeyData = keyManager.getPublicKeyData(key: key) {
                
                // Construct Public Key Blob
                var blobWriter = SSHWriter()
                blobWriter.write("ecdsa-sha2-nistp256")
                blobWriter.write("nistp256")
                blobWriter.write(pubKeyData)
                
                var idWriter = SSHWriter()
                idWriter.write(blobWriter.data)
                idWriter.write(name)
                
                identitiesBuffer.append(idWriter.data)
                validKeyCount += 1
            }
        }
        
        writer.write(validKeyCount)
        writer.writeRaw(identitiesBuffer)
        
        send(payload: writer.data, connection: connection)
    }
    
    private func handleSignRequest(reader: inout SSHReader, connection: NWConnection) throws {
        let keyBlob = try reader.readData()
        let dataToSign = try reader.readData()
        let _ = try reader.readUInt32() // flags
        
        let keys = try keyManager.listKeys()
        var foundKeyName: String? = nil

        for name in keys {
            if let key = try? keyManager.getKey(name: name),
               let pubKeyData = keyManager.getPublicKeyData(key: key) {

                var blobWriter = SSHWriter()
                blobWriter.write("ecdsa-sha2-nistp256")
                blobWriter.write("nistp256")
                blobWriter.write(pubKeyData)

                if blobWriter.data == keyBlob {
                    foundKeyName = name
                    break
                }
            }
        }

        guard let keyName = foundKeyName else {
            sendFailure(connection: connection)
            return
        }

        let signature: Data
        do {
            signature = try keyManager.sign(data: dataToSign, keyName: keyName)
        } catch {
            print("Signing error: \(error)")
            sendFailure(connection: connection)
            return
        }
        
        let ecdsaSig = try P256.Signing.ECDSASignature(derRepresentation: signature)
        let raw = ecdsaSig.rawRepresentation
        let r = raw.subdata(in: 0..<32)
        let s = raw.subdata(in: 32..<64)
        
        var innerWriter = SSHWriter()
        writeMpint(r, to: &innerWriter)
        writeMpint(s, to: &innerWriter)
        
        var sigWriter = SSHWriter()
        sigWriter.write("ecdsa-sha2-nistp256")
        sigWriter.write(innerWriter.data)
        
        var responseWriter = SSHWriter()
        responseWriter.write(UInt8(14)) // SSH2_AGENT_SIGN_RESPONSE
        responseWriter.write(sigWriter.data)
        
        send(payload: responseWriter.data, connection: connection)
    }
    
    private func writeMpint(_ value: Data, to writer: inout SSHWriter) {
        var data = value
        while data.first == 0 && data.count > 1 {
            data = data.dropFirst()
        }
        
        if let first = data.first, (first & 0x80) != 0 {
            data.insert(0, at: 0)
        }
        
        writer.write(data)
    }
}
