import PaprikaCore
import ArgumentParser
import Foundation
import CryptoKit
import Security
import Darwin

@main
struct Paprika: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Secure Enclave SSH Agent",
        subcommands: [Generate.self, Delete.self, Serve.self, Install.self, Uninstall.self, Status.self, Show.self, GitSetup.self]
    )
}

struct RuntimeError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

// Returns the absolute path of the currently running binary, resolving
// symlinks so launchd records a stable location.
// Bundle.main.executableURL is always nil for SPM CLI binaries, so we
// use _NSGetExecutablePath — the canonical Darwin syscall for this.
private func currentExecutablePath() -> String {
    var size: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &size)
    var buffer = [CChar](repeating: 0, count: Int(size))
    guard _NSGetExecutablePath(&buffer, &size) == 0 else {
        return CommandLine.arguments[0]
    }
    let raw = String(cString: buffer)
    return (try? FileManager.default.destinationOfSymbolicLink(atPath: raw)) ?? raw
}

struct Generate: ParsableCommand {
    @Argument(help: "Name of the key")
    var name: String

    func run() throws {
        try CodeSignatureCheck.requireTeamIdentifier()
        let keyManager = KeyManager()
        _ = try keyManager.generateKey(name: name)
        print("Key '\(name)' generated successfully.")
    }
}

struct Delete: ParsableCommand {
    @Argument(help: "Name of the key")
    var name: String

    func run() throws {
        try CodeSignatureCheck.requireTeamIdentifier()
        let keyManager = KeyManager()
        try keyManager.deleteKey(name: name)
        print("Key '\(name)' deleted.")
    }
}

struct Serve: ParsableCommand {
    func run() throws {
        try CodeSignatureCheck.requireTeamIdentifier()

        let socketDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".paprika")

        // Ensure directory exists
        if !FileManager.default.fileExists(atPath: socketDir.path) {
            try FileManager.default.createDirectory(at: socketDir, withIntermediateDirectories: true, attributes: [FileAttributeKey.posixPermissions: 0o700])
        }

        // Always re-enforce owner-only perms. A stale ~/.paprika from an
        // earlier install (or a hostile drop) could be world-readable,
        // which would expose the socket to every local user.
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: socketDir.path)

        // Refuse to run if ~/.paprika is not owned by the current user.
        let attrs = try FileManager.default.attributesOfItem(atPath: socketDir.path)
        let ownerID = attrs[.ownerAccountID] as? UInt ?? 0
        guard ownerID == UInt(getuid()) else {
            throw RuntimeError("\(socketDir.path) is not owned by uid \(getuid()); refusing to start")
        }

        let socketPath = socketDir.appendingPathComponent("agent.sock").path

        let keyManager = KeyManager()
        let server = AgentServer(socketPath: socketPath, keyManager: keyManager)

        try server.start()

        // Graceful shutdown: unlink the socket on SIGTERM (launchd stop)
        // and SIGINT (Ctrl-C in a terminal). DispatchSource handlers run
        // on a normal dispatch queue, so unlink + exit are safe here —
        // unlike raw signal() handlers which are restricted to
        // async-signal-safe calls.
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT,  SIG_IGN)

        let shutdown: @Sendable () -> Void = {
            unlink(socketPath)
            Darwin.exit(0)
        }
        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        termSource.setEventHandler(handler: shutdown)
        termSource.resume()
        let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        intSource.setEventHandler(handler: shutdown)
        intSource.resume()

        withExtendedLifetime((termSource, intSource)) {
            dispatchMain()
        }
    }
}

struct Install: ParsableCommand {
    func run() throws {
        let label = "com.paprika.agent"
        let home = FileManager.default.homeDirectoryForCurrentUser
        let plistCacheURL = home
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")

        let executablePath = currentExecutablePath()

        // The launchd plist is only useful if the binary it points at is
        // runnable under AMFI. Bare CLI Mach-O binaries signed without an
        // embedded provisioning profile get SIGKILLed at exec, so pointing
        // launchd at one would produce a crash/respawn loop forever.
        // Require the installing binary to live inside a .app bundle.
        guard executablePath.contains(".app/Contents/MacOS/") else {
            throw RuntimeError("""
                paprika install must be run from a signed .app bundle.

                Current executable:
                  \(executablePath)

                Expected layout:
                  <some-path>/Paprika.app/Contents/MacOS/paprika

                Build and sign the bundle first, then run install from inside it:
                  swift build -c release
                  ./scripts/codesign.sh
                  .build/release/Paprika.app/Contents/MacOS/paprika install
                """)
        }

        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(executablePath)</string>
                <string>serve</string>
            </array>
            <key>ProcessType</key>
            <string>Interactive</string>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <dict>
                <key>SuccessfulExit</key>
                <false/>
                <key>Crashed</key>
                <true/>
            </dict>
            <key>ThrottleInterval</key>
            <integer>10</integer>
        </dict>
        </plist>
        """

        try plist.write(to: plistCacheURL, atomically: true, encoding: .utf8)
        print("Installed launchd agent to \(plistCacheURL.path)")
        print("Executable path: \(executablePath)")
        print("")
        print("Load the agent (this session and every login):")
        print("  launchctl bootstrap gui/$UID \(plistCacheURL.path)")
        print("")
        print("Tail the daemon log:")
        print("  log stream --predicate 'subsystem == \"com.paprika.agent\"'")
        print("")
        print("Stop and remove:")
        print("  paprika uninstall")
    }
}

struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show paprika agent, socket, key, and audit log state",
        discussion: """
            By default, status output is safe to paste into a bug report or a
            shared Slack thread: counts and system state only, no identifying
            details.

            Opt in to sensitive sections explicitly:

              --keys     show key names, fingerprints, and public keys
              --audit    show recent audit log entries (time + context of
                         signing operations — reveals who/what you signed for)
              --tail N   with --audit, limit to N most recent entries (default 5)
            """
    )

    @Flag(name: .shortAndLong, help: "Show key names, fingerprints, and public keys")
    var keys: Bool = false

    @Flag(name: .shortAndLong, help: "Show recent audit log entries")
    var audit: Bool = false

    @Option(name: .long, help: "With --audit, number of recent entries to show")
    var tail: Int = 5

    func run() throws {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let socketPath = home.appendingPathComponent(".paprika/agent.sock")
        let plistPath = home.appendingPathComponent("Library/LaunchAgents/com.paprika.agent.plist")
        let auditPath = home.appendingPathComponent("Library/Logs/paprika/signatures.log")

        // --- binary identity ---
        print("=== binary ===")
        if let team = try? CodeSignatureCheck.requireTeamIdentifier() {
            print("  code signature: valid, team \(team)")
        } else {
            print("  code signature: ad-hoc or invalid (SE access will fail)")
        }

        // --- launchd ---
        print("")
        print("=== launchd ===")
        if FileManager.default.fileExists(atPath: plistPath.path) {
            print("  plist:        installed")
            let uid = getuid()
            let loaded = launchctlPrint(target: "gui/\(uid)/com.paprika.agent")
            if loaded.pid != nil {
                print("  state:        loaded")
            } else {
                print("  state:        plist present but not loaded")
                print("  load with:    launchctl bootstrap gui/$UID \(plistPath.path)")
            }
        } else {
            print("  plist:        not installed")
            print("  install with: paprika install")
        }

        // --- socket ---
        print("")
        print("=== socket ===")
        if let attrs = try? FileManager.default.attributesOfItem(atPath: socketPath.path) {
            let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
            print("  state:   listening, mode \(String(format: "0%o", perms))")
            if !keys {
                print("  (run 'paprika status --keys' to see key fingerprints)")
            }
        } else {
            print("  state:   missing — paprika serve is not running")
        }

        // --- keys ---
        print("")
        print("=== keys ===")
        let keyManager = KeyManager()
        let keyList = (try? keyManager.listKeys()) ?? []
        if keyList.isEmpty {
            print("  (none) — generate one with: paprika generate <name>")
        } else if !keys {
            print("  \(keyList.count) key\(keyList.count == 1 ? "" : "s") present")
            print("  (run 'paprika status --keys' to show names and fingerprints)")
        } else {
            for name in keyList {
                if let key = try? keyManager.getKey(name: name),
                   let pub = keyManager.getSSHPublicKey(key: key),
                   let pubData = keyManager.getPublicKeyData(key: key) {
                    var blob = SSHWriter()
                    blob.write("ecdsa-sha2-nistp256")
                    blob.write("nistp256")
                    blob.write(pubData)
                    let digest = SHA256.hash(data: blob.data)
                    let fp = Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
                    print("  \(name)")
                    print("    SHA256:\(fp)")
                    print("    \(pub.prefix(70))...")
                } else {
                    print("  \(name)  (inaccessible)")
                }
            }
        }

        // --- local git signing config ---
        print("")
        print("=== git signing (this repo) ===")
        let gpgFormat = gitConfigValue("gpg.format") ?? "(unset)"
        let commitSign = gitConfigValue("commit.gpgSign") ?? "(unset)"
        let signingKeyRaw = gitConfigValue("user.signingkey")
        let allowedSigners = gitConfigValue("gpg.ssh.allowedSignersFile") ?? "(unset)"
        print("  gpg.format:                  \(gpgFormat)")
        print("  commit.gpgSign:              \(commitSign)")
        if keys, let raw = signingKeyRaw {
            print("  user.signingkey:             \(raw.prefix(70))\(raw.count > 70 ? "..." : "")")
        } else {
            print("  user.signingkey:             \(signingKeyRaw == nil ? "(unset)" : "(set, --keys to show)")")
        }
        print("  gpg.ssh.allowedSignersFile:  \(allowedSigners)")

        // --- audit log ---
        print("")
        print("=== audit log ===")
        let log = AuditLog(path: auditPath)
        let entries = log.readAll()
        if entries.isEmpty {
            print("  (no entries yet)")
        } else if !audit {
            print("  \(entries.count) entries recorded")
            print("  (run 'paprika status --audit' to show recent entries; may reveal")
            print("   usernames, hostnames, and signing times)")
        } else {
            let recent = Array(entries.suffix(tail))
            for entry in recent {
                print("  \(entry.ts)  \(entry.key)  \(entry.context)")
            }
            print("")
            print("  showing last \(recent.count) of \(entries.count) entries")
            print("  log file: \(auditPath.path)")
        }
    }

    private func launchctlPrint(target: String) -> (pid: Int?, state: String?) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", target]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        try? process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return (nil, nil) }

        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        var pid: Int?
        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("pid =") {
                pid = Int(trimmed.replacingOccurrences(of: "pid =", with: "").trimmingCharacters(in: .whitespaces))
            }
        }
        return (pid, "loaded")
    }

    private func gitConfigValue(_ key: String) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["config", "--local", "--get", key]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        try? process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        let value = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (value?.isEmpty ?? true) ? nil : value
    }
}

struct Uninstall: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Stop the launchd agent and remove its plist"
    )

    func run() throws {
        let label = "com.paprika.agent"
        let plistURL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")

        // Bootout the service if it's currently loaded. We ignore any
        // error here because a common case is "plist exists on disk but
        // isn't loaded in launchd" — bootout returns non-zero for that,
        // but we still want to clean up the plist file.
        let uid = getuid()
        let target = "gui/\(uid)/\(label)"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["bootout", target]
        process.standardError = Pipe()  // swallow "Service not found" noise
        process.standardOutput = Pipe()
        try? process.run()
        process.waitUntilExit()
        if process.terminationStatus == 0 {
            print("Stopped \(target)")
        }

        if FileManager.default.fileExists(atPath: plistURL.path) {
            try FileManager.default.removeItem(at: plistURL)
            print("Removed \(plistURL.path)")
        } else {
            print("No plist at \(plistURL.path) (already uninstalled?)")
        }

        print("")
        print("Note: Secure Enclave keys are NOT deleted by uninstall.")
        print("To destroy a key permanently, use:  paprika delete <name>")
    }
}

struct Show: ParsableCommand {
    @Argument(help: "Name of the key (optional)")
    var name: String?
    
    @Flag(name: .shortAndLong, help: "Show SHA256 fingerprint")
    var fingerprint: Bool = false
    
    func run() throws {
        let keyManager = KeyManager()
        
        if let name = name {
            printKey(name: name, keyManager: keyManager)
        } else {
            let keys = try keyManager.listKeys()
            if keys.isEmpty {
                // Do nothing or print message? User request says: "If multiple keys... print list... If only 1 key... automatically print that key's public string"
                // It also implies if NO keys, what happens? "If <key-name> is omitted: Check the KeyStore."
                // I'll print nothing if empty to be clean, or "No keys".
                print("No keys found.")
            } else if keys.count == 1 {
                printKey(name: keys[0], keyManager: keyManager)
            } else {
                for keyName in keys {
                    print(keyName)
                }
            }
        }
    }
    
    func printKey(name: String, keyManager: KeyManager) {
        do {
            guard let key = try keyManager.getKey(name: name) else {
                print("Key '\(name)' not found.")
                return
            }
            
            if fingerprint {
                guard let pubData = keyManager.getPublicKeyData(key: key) else { return }
                var blobWriter = SSHWriter()
                blobWriter.write("ecdsa-sha2-nistp256")
                blobWriter.write("nistp256")
                blobWriter.write(pubData)
                
                let digest = SHA256.hash(data: blobWriter.data)
                let digestBase64 = Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
                print("SHA256:\(digestBase64) \(name)")
            } else {
                guard let pubKeyString = keyManager.getSSHPublicKey(key: key) else {
                    print("Failed to get public key string.")
                    return
                }
                print("\(pubKeyString) \(name)")
            }
        } catch {
            print("Error retrieving key: \(error)")
        }
    }
}

struct GitSetup: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "git-setup",
        abstract: "Configure Git to use Paprika for commit signing"
    )

    @Argument(help: "Name of the key to use (optional if only one exists)")
    var name: String?

    @Flag(name: .shortAndLong, help: "Configure Git globally")
    var global: Bool = false

    @Flag(name: .long, help: "Add key to ~/.ssh/allowed_signers")
    var addToAllowed: Bool = false

    func run() throws {
        let keyManager = KeyManager()
        let keys = try keyManager.listKeys()

        let selectedName: String
        if let name = name {
            selectedName = name
        } else if keys.count == 1 {
            selectedName = keys[0]
        } else if keys.isEmpty {
            print("No keys found. Generate one first with 'paprika generate <name>'.")
            return
        } else {
            print("Multiple keys found. Please specify which one to use:")
            for k in keys {
                print("  \(k)")
            }
            return
        }

        guard let key = try keyManager.getKey(name: selectedName),
              let pubKeyString = keyManager.getSSHPublicKey(key: key) else {
            print("Could not retrieve key '\(selectedName)'.")
            return
        }

        let configScope = global ? ["--global"] : []
        
        print("Configuring Git...")
        try runGit(args: configScope + ["config", "gpg.format", "ssh"])
        // Modern git treats user.signingkey as a filesystem path unless
        // it's prefixed with key::, in which case the remainder is read
        // as a literal SSH public key line. Paprika keys live inside the
        // Secure Enclave and have no on-disk .pub file, so the literal
        // form is the only one that works.
        try runGit(args: configScope + ["config", "user.signingkey", "key::\(pubKeyString)"])

        if addToAllowed {
            try setupAllowedSigners(pubKeyString: pubKeyString)
        }

        print("\n✅ Git configured to use key '\(selectedName)' for signing.")
        if global {
            print("Scope: Global")
        } else {
            print("Scope: Local repository")
        }
        
        let socketPath = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".paprika/agent.sock").path
        print("\nReminder: Ensure your SSH_AUTH_SOCK is set in your shell profile:")
        print("export SSH_AUTH_SOCK=\"\(socketPath)\"")
    }

    private func runGit(args: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = args
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw RuntimeError("git \(args.joined(separator: " ")) failed (exit \(process.terminationStatus))")
        }
    }

    private func setupAllowedSigners(pubKeyString: String) throws {
        let gitEmail = getGitEmail() ?? "your-email@example.com"

        // Refuse any embedded CR/LF. The allowed_signers file is a
        // line-based format; an email like "foo@bar\nALL_SIGNERS_BYPASS ..."
        // from a hostile local git config could inject extra trust entries.
        // Same for the public key string — paranoia costs nothing.
        guard !gitEmail.contains(where: { $0 == "\n" || $0 == "\r" }) else {
            throw RuntimeError("git user.email contains a newline character; refusing to write it to allowed_signers")
        }
        guard !pubKeyString.contains(where: { $0 == "\n" || $0 == "\r" }) else {
            throw RuntimeError("public key string contains a newline character; refusing to write it to allowed_signers")
        }

        let allowedSignersPath = try allowedSignersLocation()

        let entry = "\(gitEmail) \(pubKeyString)\n"

        // Parent dir is guaranteed by allowedSignersLocation(); create the
        // file if it doesn't exist yet.
        if !FileManager.default.fileExists(atPath: allowedSignersPath.path) {
            try "".write(to: allowedSignersPath, atomically: true, encoding: .utf8)
        }

        let fileHandle = try FileHandle(forWritingTo: allowedSignersPath)
        fileHandle.seekToEndOfFile()
        fileHandle.write(entry.data(using: .utf8)!)
        fileHandle.closeFile()

        print("Added key to \(allowedSignersPath.path)")

        // Also configure git to use this file
        let configScope = global ? ["--global"] : []
        try runGit(args: configScope + ["config", "gpg.ssh.allowedSignersFile", allowedSignersPath.path])
    }

    /// Decide where to write / append the allowed_signers file.
    ///
    /// The file is semantically a **git** trust store (it's consumed by
    /// `git` via `gpg.ssh.allowedSignersFile`, not by `ssh` itself), so
    /// the XDG-compliant location under `~/.config/git/` is the correct
    /// default for greenfield setups.
    ///
    /// For backward compatibility, if the user already has a populated
    /// `~/.ssh/allowed_signers`, we append there instead so we don't
    /// split their trust store across two files.
    private func allowedSignersLocation() throws -> URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let legacyPath = home.appendingPathComponent(".ssh/allowed_signers")

        // Respect an existing legacy file if it has any content — don't
        // fragment the user's trust store.
        if let data = try? Data(contentsOf: legacyPath), !data.isEmpty {
            return legacyPath
        }

        // Default: XDG config location for git.
        let xdgGitDir = home.appendingPathComponent(".config/git")
        if !FileManager.default.fileExists(atPath: xdgGitDir.path) {
            try FileManager.default.createDirectory(
                at: xdgGitDir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
        }
        return xdgGitDir.appendingPathComponent("allowed_signers")
    }

    private func getGitEmail() -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = ["config", "user.email"]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let email = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
        return (email?.isEmpty ?? true) ? nil : email
    }
}
