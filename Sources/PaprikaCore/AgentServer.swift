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

    /// Most clients connected at once. launchd gives agents a soft
    /// RLIMIT_NOFILE of 256, and every client holds a descriptor, so an
    /// unbounded pile of idle connections (say, from a malicious host over
    /// agent forwarding) would stop the agent from accepting anyone. At
    /// the cap, the longest-idle client is dropped to make room.
    public static let maxClients = 128

    /// Most sign requests waiting for (or showing) Touch ID at once. Past
    /// this, a new sign request fails immediately instead of lining up
    /// yet another prompt behind the others.
    public static let maxPendingSigns = 8

    /// Most requests one client may have queued. Agent clients wait for
    /// each reply before sending the next request; a deep pipeline is abuse.
    static let maxQueuedPerClient = 4

    /// A client that sends part of a message and then stalls is dropped
    /// after this long, so it can't hold a connection slot forever.
    static let partialMessageTimeout: TimeInterval = 10

    public let socketPath: String
    public let keyManager: KeyManager
    public var listener: NWListener?

    // Sign operations run on a dedicated serial queue so concurrent
    // client connections cannot interleave Touch ID dialogs. Without
    // this, two clients racing to sign at the same moment would produce
    // two overlapping system prompts and the user would have no way to
    // tell which one they're approving. All signing goes through here.
    private let signQueue = DispatchQueue(label: "com.paprika.agent.sign")

    /// Append-only audit log, ~/Library/Logs/paprika/signatures.log by
    /// default. Records every successful sign.
    private let auditLog: AuditLog

    private let lock = NSLock()
    private var clients: [ObjectIdentifier: Client] = [:]  // guarded by lock
    private var pendingSigns = 0                            // guarded by lock

    /// One connected agent client.
    private final class Client {
        let connection: NWConnection
        /// Network callbacks and message framing.
        let io = DispatchQueue(label: "com.paprika.agent.client.io")
        /// Requests run here one at a time, so replies go out in request
        /// order even while a sign is waiting on Touch ID.
        let work = DispatchQueue(label: "com.paprika.agent.client.work")
        var buffer = Data()           // io queue only
        var partialSince: Date?       // io queue only
        var lastActivity = Date()     // guarded by server lock
        var queued = 0                // guarded by server lock
        /// The peer has closed. Its queued sign requests are dropped:
        /// nobody is waiting for those Touch ID prompts any more.
        var gone = false              // guarded by server lock

        init(_ connection: NWConnection) { self.connection = connection }
    }

    enum FrameError: Error, CustomStringConvertible {
        case badLength(UInt32)
        var description: String {
            switch self {
            case .badLength(let n): return "message length \(n) outside 1...\(AgentServer.maxMessageLength)"
            }
        }
    }

    public init(socketPath: String, keyManager: KeyManager, auditLog: AuditLog = .default()) {
        self.socketPath = socketPath
        self.keyManager = keyManager
        self.auditLog = auditLog
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

    // MARK: - Connections

    private func handleConnection(_ connection: NWConnection) {
        let client = Client(connection)
        var evicted: Client?
        let admitted: Bool = lock.withLock {
            if clients.count >= Self.maxClients,
               let idlest = clients.values.filter({ $0.queued == 0 }).min(by: { $0.lastActivity < $1.lastActivity }) {
                idlest.gone = true
                clients[ObjectIdentifier(idlest)] = nil
                evicted = idlest
            }
            guard clients.count < Self.maxClients else { return false }
            clients[ObjectIdentifier(client)] = client
            return true
        }
        if let evicted {
            logger.warning("client limit (\(Self.maxClients)) reached; dropping the longest-idle client")
            evicted.connection.cancel()
        }
        guard admitted else {
            logger.warning("client limit (\(Self.maxClients)) reached and every client is busy; refusing connection")
            connection.cancel()
            return
        }

        // Network.framework releases these handlers once the connection is
        // cancelled, which breaks the client <-> connection reference cycle.
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed:
                self?.forget(client)
                connection.cancel()
            case .cancelled:
                self?.forget(client)
            default:
                break
            }
        }
        connection.start(queue: client.io)
        receive(client)
    }

    private func forget(_ client: Client) {
        lock.withLock {
            client.gone = true
            clients[ObjectIdentifier(client)] = nil
        }
    }

    private func receive(_ client: Client) {
        client.connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] content, _, isComplete, error in
            guard let self else { return }
            if let content { client.buffer.append(content) }

            do {
                while let frame = try Self.nextFrame(from: &client.buffer) {
                    guard self.enqueue(frame, for: client) else {
                        logger.warning("client queued more than \(Self.maxQueuedPerClient) requests; disconnecting")
                        client.connection.cancel()
                        return
                    }
                }
            } catch {
                logger.warning("rejecting agent message: \(String(describing: error), privacy: .public)")
                client.connection.cancel()
                return
            }

            if let error {
                logger.error("connection error: \(error.localizedDescription, privacy: .public)")
                client.connection.cancel()
                return
            }
            if isComplete {
                // The peer closed its end. Still answer what it already sent
                // (`printf ... | nc -U` style clients rely on that), then
                // close once the work queue has drained. Its sign requests
                // are skipped rather than prompted: see performSign.
                self.lock.withLock { client.gone = true }
                client.work.async {
                    client.connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                                           completion: .contentProcessed { _ in client.connection.cancel() })
                }
                return
            }

            self.armPartialMessageTimer(client)
            self.receive(client)
        }
    }

    /// Pops one complete length-prefixed message off the front of
    /// `buffer`. Returns nil until the whole message has arrived; throws
    /// on a zero or oversized length so the caller can drop the client.
    static func nextFrame(from buffer: inout Data) throws -> Data? {
        guard buffer.count >= 4 else { return nil }
        let start = buffer.startIndex
        let length = buffer[start..<start + 4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard length > 0, length <= maxMessageLength else { throw FrameError.badLength(length) }
        let end = start + 4 + Int(length)
        guard buffer.endIndex >= end else { return nil }
        let frame = Data(buffer[(start + 4)..<end])
        buffer = Data(buffer[end...])
        return frame
    }

    /// Drop the client if a partly received message doesn't complete in
    /// time. Runs on the client's io queue.
    private func armPartialMessageTimer(_ client: Client) {
        guard !client.buffer.isEmpty else {
            client.partialSince = nil
            return
        }
        guard client.partialSince == nil else { return }
        let started = Date()
        client.partialSince = started
        client.io.asyncAfter(deadline: .now() + Self.partialMessageTimeout) {
            guard client.partialSince == started else { return }
            logger.warning("dropping client: message incomplete after \(Int(Self.partialMessageTimeout))s")
            client.connection.cancel()
        }
    }

    /// Queue one request on the client's work queue. Returns false if the
    /// client already has too many requests queued.
    private func enqueue(_ message: Data, for client: Client) -> Bool {
        let isSign = message.first == 13
        var admitted = false
        var holdsSignSlot = false
        lock.withLock {
            client.lastActivity = Date()
            guard client.queued < Self.maxQueuedPerClient else { return }
            admitted = true
            client.queued += 1
            if isSign && pendingSigns < Self.maxPendingSigns {
                pendingSigns += 1
                holdsSignSlot = true
            }
        }
        guard admitted else { return false }

        client.work.async { [self] in
            defer {
                lock.withLock {
                    client.queued -= 1
                    if holdsSignSlot { pendingSigns -= 1 }
                }
            }
            if isSign && !holdsSignSlot {
                logger.warning("\(Self.maxPendingSigns) sign requests already pending; refusing another")
                sendFailure(connection: client.connection)
                return
            }
            processMessage(message, client: client)
        }
        return true
    }

    // MARK: - Messages

    private func processMessage(_ data: Data, client: Client) {
        var reader = SSHReader(data: data)

        do {
            let msgType = try reader.readByte()

            switch msgType {
            case 11: // SSH2_AGENTC_REQUEST_IDENTITIES
                try handleRequestIdentities(connection: client.connection)
            case 13: // SSH2_AGENTC_SIGN_REQUEST
                try handleSignRequest(reader: &reader, client: client)
            default:
                sendFailure(connection: client.connection)
            }
        } catch {
            logger.error("protocol error: \(error.localizedDescription, privacy: .public)")
            sendFailure(connection: client.connection)
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

    private func handleSignRequest(reader: inout SSHReader, client: Client) throws {
        let keyBlob = try reader.readData()
        let dataToSign = try reader.readData()
        let _ = try reader.readUInt32() // flags

        // signQueue serializes Touch ID dialogs across clients. sync keeps
        // this client's later requests waiting until this reply is sent.
        signQueue.sync {
            performSign(keyBlob: keyBlob, dataToSign: dataToSign, client: client)
        }
    }

    private func performSign(keyBlob: Data, dataToSign: Data, client: Client) {
        let connection = client.connection
        if lock.withLock({ client.gone }) {
            logger.info("dropping sign request: client disconnected before its turn")
            return
        }

        let keys: [String]
        do {
            keys = try keyManager.listKeys()
        } catch {
            logger.error("listKeys failed: \(error.localizedDescription, privacy: .public)")
            sendFailure(connection: connection)
            return
        }

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

        let reason = AgentServer.signContextDescription(for: dataToSign)
        logger.info("signing: \(reason, privacy: .public) with key \(keyName, privacy: .public)")

        let signature: Data
        do {
            signature = try keyManager.sign(data: dataToSign, keyName: keyName, reason: reason)
        } catch {
            logger.error("signing error: \(error.localizedDescription, privacy: .public)")
            sendFailure(connection: connection)
            return
        }

        // Only audit on success — a denied Touch ID prompt throws above
        // and we don't want to record "something tried to sign X."
        auditLog.record(keyName: keyName, data: dataToSign, context: reason)

        guard let ecdsaSig = try? P256.Signing.ECDSASignature(derRepresentation: signature) else {
            logger.error("failed to parse ECDSA signature")
            sendFailure(connection: connection)
            return
        }
        let raw = ecdsaSig.rawRepresentation
        let r = raw.subdata(in: 0..<32)
        let s = raw.subdata(in: 32..<64)

        var innerWriter = SSHWriter()
        AgentServer.writeMpint(r, to: &innerWriter)
        AgentServer.writeMpint(s, to: &innerWriter)

        var sigWriter = SSHWriter()
        sigWriter.write("ecdsa-sha2-nistp256")
        sigWriter.write(innerWriter.data)

        var responseWriter = SSHWriter()
        responseWriter.write(UInt8(14)) // SSH2_AGENT_SIGN_RESPONSE
        responseWriter.write(sigWriter.data)

        send(payload: responseWriter.data, connection: connection)
    }

    // MARK: - Context extraction

    /// Best-effort decode of an SSH sign request's data-to-sign blob
    /// into a human-readable description for the Touch ID dialog.
    ///
    /// Two payload shapes are recognized:
    ///
    ///   * **SSHSIG** (OpenSSH PROTOCOL.sshsig, used by `ssh-keygen -Y
    ///     sign` and therefore by `git commit -S`). The signed data is
    ///     the ASCII magic `SSHSIG` followed by length-prefixed namespace,
    ///     reserved, hash algorithm, and message hash strings. There is
    ///     no version field: that only appears in the armored signature
    ///     file. We extract the namespace (`git`, `file`, etc.).
    ///
    ///   * **SSH publickey auth request** (RFC 4252 §7). The signed
    ///     blob starts with a length-prefixed session identifier, then
    ///     a single byte equal to 50 (`SSH_MSG_USERAUTH_REQUEST`),
    ///     then length-prefixed username, service, method strings.
    ///     OpenSSH 8.9+ sends method `publickey-hostbound-v00@openssh.com`
    ///     instead of `publickey` whenever the server supports it; the
    ///     leading fields are the same. We extract username + service.
    ///
    /// Client-supplied strings pass through `promptSafe` before they reach
    /// the dialog. Any parse failure falls back to a generic description.
    /// Never throws — a prompt that says "authorize SSH signing" is a bad
    /// UX, not a security failure.
    internal static func signContextDescription(for data: Data) -> String {
        // SSHSIG path
        let sigMagic = Data("SSHSIG".utf8)
        if data.count >= 6, data.prefix(6) == sigMagic {
            // Wrap in fresh Data so the slice has 0-based indices —
            // SSHReader does subdata(in: 0..<N) which would otherwise
            // trap on a Data.SubSequence whose startIndex is 6.
            var reader = SSHReader(data: Data(data.dropFirst(6)))
            if let namespace = try? reader.readString(), !namespace.isEmpty {
                switch namespace {
                case "git":
                    return "Paprika: sign git commit or tag"
                case "file":
                    return "Paprika: sign file"
                default:
                    return "Paprika: sign \(promptSafe(namespace))"
                }
            }
            return "Paprika: sign SSHSIG request"
        }

        // SSH auth request path
        var reader = SSHReader(data: data)
        if (try? reader.readData()) != nil,                          // session_id
           let msgType = try? reader.readByte(), msgType == 50,      // USERAUTH_REQUEST
           let user = try? reader.readString(),
           let service = try? reader.readString(),
           let method = try? reader.readString(),
           method == "publickey" || method == "publickey-hostbound-v00@openssh.com" {
            return "Paprika: SSH auth as \(promptSafe(user)) (\(promptSafe(service)))"
        }

        return "Paprika: authorize SSH signing"
    }

    /// Make client-supplied text safe to show in the Touch ID dialog.
    /// Control, format (bidi overrides, zero-width), and line/paragraph
    /// separator characters become "?", and long text is cut short, so a
    /// sign request can't reorder the prompt or push the real context
    /// out of view.
    internal static func promptSafe(_ text: String, limit: Int = 64) -> String {
        var out = String.UnicodeScalarView()
        for (i, scalar) in text.unicodeScalars.enumerated() {
            if i == limit {
                out.append("…")
                break
            }
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator,
                 .surrogate, .privateUse, .unassigned:
                out.append("?")
            default:
                out.append(scalar)
            }
        }
        return String(out)
    }

    /// RFC 4251 §5 mpint from an unsigned big-endian magnitude: no
    /// leading zero bytes, a single 0x00 prefix when the top bit is set,
    /// and zero encoded as the empty string.
    internal static func writeMpint(_ value: Data, to writer: inout SSHWriter) {
        // Rebase into a fresh Data: drop(while:) returns a slice whose
        // startIndex isn't 0, and insert(_:at: 0) on that slice traps.
        var data = Data(value.drop(while: { $0 == 0 }))
        if let first = data.first, (first & 0x80) != 0 {
            data.insert(0, at: 0)
        }
        writer.write(data)
    }
}
