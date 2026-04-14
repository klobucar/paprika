import Foundation
import Security

/// Defense-in-depth check that the running binary carries a proper
/// code-signing team identifier. Ad-hoc signed binaries (`codesign
/// --sign -`) have no team ID, and the Secure Enclave will refuse
/// to create or access keys for them with `errSecMissingEntitlement`
/// (-34018) — a cryptic error deep in the sign path. Failing fast at
/// startup with a clear message beats that by a wide margin.
public enum CodeSignatureCheck {
    public enum Problem: Error, CustomStringConvertible {
        case selfInspectionFailed(OSStatus)
        case signingInfoFailed(OSStatus)
        case missingTeamIdentifier

        public var description: String {
            switch self {
            case .selfInspectionFailed(let s):
                return "SecCodeCopySelf failed (OSStatus \(s))"
            case .signingInfoFailed(let s):
                return "SecCodeCopySigningInformation failed (OSStatus \(s))"
            case .missingTeamIdentifier:
                return """
                    This paprika binary has no code-signing team identifier.
                    Secure Enclave operations require a binary signed with a
                    proper Apple Development or Developer ID certificate — an
                    ad-hoc signature (`codesign --sign -`) will not work.

                    Build and sign with scripts/codesign.sh, then run paprika
                    from the resulting .app bundle:
                        .build/release/Paprika.app/Contents/MacOS/paprika
                    """
            }
        }
    }

    /// Returns the current process's team identifier, or throws a
    /// Problem describing why it couldn't be determined / is missing.
    @discardableResult
    public static func requireTeamIdentifier() throws -> String {
        var codeRef: SecCode?
        let copyStatus = SecCodeCopySelf([], &codeRef)
        guard copyStatus == errSecSuccess, let code = codeRef else {
            throw Problem.selfInspectionFailed(copyStatus)
        }

        // SecCodeCopySigningInformation takes SecStaticCode, which
        // SecCode is a refinement of. Unsafe-cast across the CF type
        // hierarchy is the idiomatic way to bridge.
        let staticCode = unsafeBitCast(code, to: SecStaticCode.self)
        var infoRef: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &infoRef)
        guard infoStatus == errSecSuccess, let info = infoRef as? [String: Any] else {
            throw Problem.signingInfoFailed(infoStatus)
        }

        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        guard let team = teamID, !team.isEmpty else {
            throw Problem.missingTeamIdentifier
        }
        return team
    }
}
