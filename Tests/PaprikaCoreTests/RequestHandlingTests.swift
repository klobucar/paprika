import XCTest
import Darwin
@testable import PaprikaCore

func agentFrame(_ payload: Data) -> Data {
    var w = SSHWriter()
    w.write(UInt32(payload.count))
    w.writeRaw(payload)
    return w.data
}

/// Blocking Unix-socket client, for tests that need exact control over
/// the bytes on the wire (pipelining, disconnecting mid-request).
final class RawAgentClient {
    private var fd: Int32 = -1

    /// Connects, retrying while the server's listener comes up.
    init(path: String) throws {
        for _ in 0..<100 {
            fd = socket(AF_UNIX, SOCK_STREAM, 0)
            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8)) }
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if rc == 0 {
                var tv = timeval(tv_sec: 5, tv_usec: 0)
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                return
            }
            Darwin.close(fd)
            usleep(20_000)
        }
        throw POSIXError(.ECONNREFUSED)
    }

    func send(_ data: Data) {
        data.withUnsafeBytes { _ = Darwin.write(fd, $0.baseAddress, $0.count) }
    }

    func readFrame() -> Data? {
        guard let header = readExactly(4) else { return nil }
        return readExactly(header.reduce(0) { $0 << 8 | Int($1) })
    }

    /// Done writing, still reading.
    func shutdownWrite() {
        Darwin.shutdown(fd, SHUT_WR)
    }

    func close() {
        if fd >= 0 { Darwin.close(fd); fd = -1 }
    }

    private func readExactly(_ n: Int) -> Data? {
        var out = Data()
        var buf = [UInt8](repeating: 0, count: max(n, 1))
        while out.count < n {
            let got = Darwin.read(fd, &buf, n - out.count)
            if got <= 0 { return nil }
            out.append(contentsOf: buf[0..<got])
        }
        return out
    }

    deinit { close() }
}

extension XCTestCase {
    /// Run blocking socket code off the main thread. AgentServer's listener
    /// delivers new connections on the main queue, which has to keep
    /// spinning (wait(for:) does that) for the server to accept anyone.
    func offMain(timeout: TimeInterval = 15, _ body: @escaping () throws -> Void) {
        let done = expectation(description: "client finished")
        DispatchQueue.global().async {
            do { try body() } catch { XCTFail("\(error)") }
            done.fulfill()
        }
        wait(for: [done], timeout: timeout)
    }
}

/// MockKeyManager whose sign takes a while, like a user reaching for Touch ID.
final class SlowMockKeyManager: MockKeyManager {
    private let lock = NSLock()
    private var calls = 0
    var signCalls: Int { lock.withLock { calls } }

    override func sign(data: Data, keyName: String, reason: String = "") throws -> Data {
        lock.withLock { calls += 1 }
        usleep(300_000)
        return try super.sign(data: data, keyName: keyName, reason: reason)
    }
}

func signRequest(for keyManager: KeyManager, data: Data) throws -> Data {
    let key = try XCTUnwrap(keyManager.getKey(name: "test-key"))
    var blob = SSHWriter()
    blob.write("ecdsa-sha2-nistp256")
    blob.write("nistp256")
    blob.write(try XCTUnwrap(keyManager.getPublicKeyData(key: key)))
    var req = SSHWriter()
    req.write(UInt8(13))
    req.write(blob.data)
    req.write(data)
    req.write(UInt32(0))
    return req.data
}

final class FramingTests: XCTestCase {
    func testWaitsForCompleteMessage() throws {
        var buffer = Data([0, 0, 0, 5, 11])
        XCTAssertNil(try AgentServer.nextFrame(from: &buffer))
        XCTAssertEqual(buffer, Data([0, 0, 0, 5, 11]))
    }

    func testSplitsPipelinedMessages() throws {
        var buffer = agentFrame(Data([11])) + agentFrame(Data([99, 1, 2]))
        XCTAssertEqual(try AgentServer.nextFrame(from: &buffer), Data([11]))
        XCTAssertEqual(try AgentServer.nextFrame(from: &buffer), Data([99, 1, 2]))
        XCTAssertNil(try AgentServer.nextFrame(from: &buffer))
        XCTAssertTrue(buffer.isEmpty)
    }

    func testRejectsZeroAndOversizedLengths() {
        var zero = Data([0, 0, 0, 0])
        XCTAssertThrowsError(try AgentServer.nextFrame(from: &zero))
        var huge = Data([0xFF, 0xFF, 0xFF, 0xFF])
        XCTAssertThrowsError(try AgentServer.nextFrame(from: &huge))
    }

    func testAcceptsSliceBuffer() throws {
        var buffer = (Data([0xEE]) + agentFrame(Data([11]))).dropFirst()
        XCTAssertEqual(try AgentServer.nextFrame(from: &buffer), Data([11]))
    }
}

final class RequestHandlingTests: XCTestCase {
    func testPipelinedRepliesKeepRequestOrder() throws {
        let socketPath = "/tmp/ppk-\(UUID().uuidString.prefix(8)).sock"
        let keyManager = SlowMockKeyManager()
        let server = AgentServer(socketPath: socketPath, keyManager: keyManager, auditLog: scratchAuditLog())
        try server.start()
        defer { server.listener?.cancel(); unlink(socketPath) }

        let request = try signRequest(for: keyManager, data: Data("order".utf8))
        offMain {
            let client = try RawAgentClient(path: socketPath)
            // A sign (slow) and an unknown message (instant) in one write.
            client.send(agentFrame(request) + agentFrame(Data([99])))
            XCTAssertEqual(client.readFrame()?.first, 14, "sign reply must come first")
            XCTAssertEqual(client.readFrame()?.first, 5)
        }
    }

    func testDisconnectedClientsGetNoTouchIDPrompt() throws {
        let socketPath = "/tmp/ppk-\(UUID().uuidString.prefix(8)).sock"
        let keyManager = SlowMockKeyManager()
        let server = AgentServer(socketPath: socketPath, keyManager: keyManager, auditLog: scratchAuditLog())
        try server.start()
        defer { server.listener?.cancel(); unlink(socketPath) }

        let request = try signRequest(for: keyManager, data: Data("sign me".utf8))
        offMain {
            // One client holds the sign queue for 300ms...
            let waiting = try RawAgentClient(path: socketPath)
            waiting.send(agentFrame(request))
            // ...while three more queue sign requests behind it and give up.
            for _ in 0..<3 {
                let quitter = try RawAgentClient(path: socketPath)
                quitter.send(agentFrame(request))
                quitter.close()
            }
            XCTAssertEqual(waiting.readFrame()?.first, 14)
            usleep(500_000)
        }
        XCTAssertEqual(keyManager.signCalls, 1, "requests from closed clients must not reach Touch ID")
    }

    func testHalfClosedClientStillGetsItsAnswer() throws {
        let socketPath = "/tmp/ppk-\(UUID().uuidString.prefix(8)).sock"
        let server = AgentServer(socketPath: socketPath, keyManager: MockKeyManager(), auditLog: scratchAuditLog())
        try server.start()
        defer { server.listener?.cancel(); unlink(socketPath) }

        offMain {
            let client = try RawAgentClient(path: socketPath)
            client.send(agentFrame(Data([11])))
            client.shutdownWrite()   // like `printf ... | nc -U`
            XCTAssertEqual(client.readFrame()?.first, 12)
        }
    }
}
