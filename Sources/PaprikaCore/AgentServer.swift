import Foundation
import Network
import CryptoKit
import Security
import os

// All daemon diagnostics flow through the macOS unified log system.
// Rotation, redaction, and subsystem-level filtering are handled by the
// OS; users can tail the log with:
//   log stream --predicate 'subsystem == "com.paprika.agent"'
// or query historical events with:
//   log show --predicate 'subsystem == "com.paprika.agent"' --last 1h
private let logger = Logger(subsystem: "com.paprika.agent", category: "server")

public class AgentServer {
    // SSH agent protocol caps messages around 256 KB. Anything larger is
    // spec-violating and, left unbounded, lets a local client force the
    // network stack to buffer gigabytes before delivery — a trivial DoS.
    public static let maxMessageLength: UInt32 = 256 * 1024

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
                // Restrict the socket to owner-only. File system permissions
                // are our peer-auth fence: only the process owner can
                // connect(2) to a 0600 Unix socket.
                if chmod(self.socketPath, 0o600) != 0 {
                    let err = String(cString: strerror(errno))
                    logger.warning("could not chmod socket to 0600: \(err, privacy: .public)")
                }
                logger.info("agent listening on \(self.socketPath, privacy: .public)")
            case .failed(let error):
                logger.error("listener failed: \(error.localizedDescription, privacy: .public)")
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
                logger.error("connection error: \(error.localizedDescription, privacy: .public)")
                connection.cancel()
                return
            }

            guard let content = content, content.count == 4 else { return }
            let length = content.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

            guard length > 0 && length <= AgentServer.maxMessageLength else {
                logger.warning("rejecting oversized agent message: \(length) bytes (max \(AgentServer.maxMessageLength))")
                connection.cancel()
                return
            }

            connection.receive(minimumIncompleteLength: Int(length), maximumLength: Int(length)) { body, _, _, error in
                if let error = error {
                    logger.error("read body error: \(error.localizedDescription, privacy: .public)")
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
            logger.error("protocol error: \(error.localizedDescription, privacy: .public)")
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
                logger.error("send error: \(error.localizedDescription, privacy: .public)")
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
            logger.error("signing error: \(error.localizedDescription, privacy: .public)")
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
