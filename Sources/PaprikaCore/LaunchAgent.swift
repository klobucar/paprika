import Foundation

/// The launchd agent definition `paprika install` writes.
public enum LaunchAgent {
    public static let label = "com.paprika.agent"

    /// XML plist for ~/Library/LaunchAgents. Built with
    /// PropertyListSerialization rather than string interpolation so an
    /// install path containing `&`, `<`, or `</string>` stays one
    /// well-formed argument.
    public static func plist(executablePath: String) throws -> Data {
        let agent: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executablePath, "serve"],
            "ProcessType": "Interactive",
            "RunAtLoad": true,
            // Restart only on crash, at most every 10s.
            "KeepAlive": ["SuccessfulExit": false, "Crashed": true],
            "ThrottleInterval": 10,
        ]
        return try PropertyListSerialization.data(fromPropertyList: agent, format: .xml, options: 0)
    }
}
