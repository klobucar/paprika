import Foundation
import CryptoKit
import os

/// Append-only, tamper-evident audit log of every sign operation the
/// agent performs. Uses JSON Lines (JSONL) format: one JSON object per
/// line, structured fields, standard escaping for special characters.
///
/// This file is deliberately separate from the macOS unified log:
///
///   * Unified log (os.Logger) is for diagnostics. The OS can rotate,
///     compress, or drop entries at its own discretion, and users can
///     `log erase` it. That's fine for "what did the daemon log at
///     startup?" but wrong for "what signatures did Paprika issue on
///     my behalf?" which must be retained indefinitely.
///
///   * This log is a plain UTF-8 file under the user's control at
///     ~/Library/Logs/paprika/signatures.log. It contains one JSON
///     object per sign, in the order they happened, and nobody
///     (including paprika itself) ever rewrites existing lines. To
///     rotate, the user moves the file aside; a new chain starts.
///
/// Per-line JSON schema:
///     {
///       "ts":          "2026-04-14T16:30:00Z",
///       "key":         "paprika-laptop",
///       "data_sha256": "abcd...",
///       "context":     "Paprika: sign git commit or tag",
///       "prev_sha256": "ef01..."   // SHA256 of the previous line bytes
///     }
///
/// `prev_sha256` for the first entry is SHA256("") as a fixed anchor.
/// For every subsequent entry it is SHA256 of the previous line's
/// exact bytes (not including its trailing '\n'). This makes historical
/// modification detectable by recomputing the chain — delete or edit
/// any entry and every subsequent `prev_sha256` becomes wrong.
///
/// **What this log does NOT contain:** key material (obviously), the
/// data-to-sign itself (only its hash), the signature produced, or any
/// identifying info about the requesting process beyond what the agent
/// already knows. The intent is "prove to yourself that a signing
/// operation happened at time T for context C," not "reconstruct the
/// exact contents of what was signed."
public final class AuditLog {
    public struct Entry: Codable {
        public let ts: String
        public let key: String
        public let data_sha256: String
        public let context: String
        public let prev_sha256: String
    }

    private static let logger = Logger(subsystem: "com.paprika.agent", category: "audit")
    private static let iso = ISO8601DateFormatter()

    private let path: URL
    private let queue = DispatchQueue(label: "com.paprika.audit")

    /// Default location. Creates `~/Library/Logs/paprika/` if missing.
    public static func `default`() -> AuditLog {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs/paprika")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return AuditLog(path: dir.appendingPathComponent("signatures.log"))
    }

    public init(path: URL) {
        self.path = path
    }

    /// Append a new entry. Runs synchronously on an internal serial
    /// queue so multiple concurrent callers produce a well-ordered log
    /// with no interleaved writes or missed back-link hashes.
    public func record(keyName: String, data: Data, context: String) {
        queue.sync { [self] in
            // Ensure file exists with owner-only permissions
            if !FileManager.default.fileExists(atPath: path.path) {
                FileManager.default.createFile(atPath: path.path, contents: nil)
                try? FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: path.path)
            }

            let entry = Entry(
                ts: AuditLog.iso.string(from: Date()),
                key: keyName,
                data_sha256: AuditLog.hex(SHA256.hash(data: data)),
                context: context,
                prev_sha256: lastLineHash()
            )

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.withoutEscapingSlashes]
            guard let jsonData = try? encoder.encode(entry) else {
                AuditLog.logger.error("could not encode audit entry to JSON")
                return
            }

            guard let handle = try? FileHandle(forWritingTo: path) else {
                AuditLog.logger.error("could not open audit log at \(self.path.path, privacy: .public)")
                return
            }
            defer { try? handle.close() }

            do {
                try handle.seekToEnd()
                try handle.write(contentsOf: jsonData)
                try handle.write(contentsOf: Data([0x0A])) // newline
            } catch {
                AuditLog.logger.error("audit log write failed: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Read the full audit log as decoded entries. Useful for
    /// `paprika status` to show recent signs and for a future
    /// `verify-log` subcommand that recomputes the hash chain.
    public func readAll() -> [Entry] {
        guard let content = try? String(contentsOf: path, encoding: .utf8) else {
            return []
        }
        let decoder = JSONDecoder()
        return content
            .split(separator: "\n", omittingEmptySubsequences: true)
            .compactMap { line in
                try? decoder.decode(Entry.self, from: Data(line.utf8))
            }
    }

    /// Read the raw JSON lines as strings (useful if you want to
    /// pipe them into `jq` without first decoding through Codable).
    public func readRawLines() -> [String] {
        guard let content = try? String(contentsOf: path, encoding: .utf8) else {
            return []
        }
        return content.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    }

    // MARK: - Internals

    private func lastLineHash() -> String {
        guard let content = try? String(contentsOf: path, encoding: .utf8),
              let lastLine = content.split(separator: "\n", omittingEmptySubsequences: true).last else {
            // First entry: back-link is SHA256 of empty string
            return AuditLog.hex(SHA256.hash(data: Data()))
        }
        return AuditLog.hex(SHA256.hash(data: Data(lastLine.utf8)))
    }

    private static func hex(_ digest: SHA256.Digest) -> String {
        digest.map { String(format: "%02x", $0) }.joined()
    }
}
