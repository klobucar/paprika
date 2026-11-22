import Foundation

/// Lines for git's SSH `allowed_signers` trust file.
public enum AllowedSigners {
    public struct UnsafeEntry: Error, CustomStringConvertible {
        public let description: String
    }

    /// One `allowed_signers` line trusting `publicKey` for `email`.
    ///
    /// Each line is "principals [options] keytype key", split on
    /// whitespace. An email containing a space (say, from a hostile local
    /// git config) could add options or a different key: an email of
    /// "* ecdsa-sha2-nistp256 AAAA<attacker>" would trust the attacker's
    /// key for every signer. Newlines would add whole lines, a leading #
    /// comments the line out, and , * ? ! are principal-pattern syntax.
    public static func line(email: String, publicKey: String) throws -> String {
        guard isPlainPrincipal(email) else {
            throw UnsafeEntry(description: """
                git user.email contains whitespace, control, or pattern characters \
                (, * ? ! "); refusing to write it to allowed_signers
                """)
        }
        guard !publicKey.contains(where: { $0.isNewline }) else {
            throw UnsafeEntry(description: "public key string contains a newline; refusing to write it to allowed_signers")
        }
        return "\(email) \(publicKey)\n"
    }

    /// True if `email` can stand alone as a single principal.
    static func isPlainPrincipal(_ email: String) -> Bool {
        guard !email.isEmpty, !email.hasPrefix("#") else { return false }
        return email.unicodeScalars.allSatisfy { scalar in
            !scalar.properties.isWhitespace
                && scalar.properties.generalCategory != .control
                && !",*?!\"".unicodeScalars.contains(scalar)
        }
    }
}
