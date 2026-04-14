# Paprika

A Secure Enclave SSH agent for macOS that lives entirely in your terminal.

Paprika stores SSH keys inside the Secure Enclave — they are generated there, they never leave, and every signing operation requires a fresh Touch ID authentication. It speaks the standard SSH agent protocol, so any SSH client that respects `SSH_AUTH_SOCK` works with it out of the box.

---

## Why Paprika instead of Secretive?

[Secretive](https://github.com/maxgoedjen/secretive) is excellent and the right tool for most people. Paprika is for a different workflow:

| | Paprika | Secretive |
|---|---|---|
| Interface | CLI daemon | GUI menu bar app |
| Requires display session | No | Yes |
| Scripting / dotfiles | `paprika generate mykey` | Manual |
| Git signing setup | `paprika git-setup --global` | Manual |
| Codebase size | ~600 lines | Much larger |
| Runs on headless Mac | Yes | No |

**Choose Paprika if** you live in the terminal, manage Macs with Ansible or bootstrap scripts, or run a headless Mac mini that you SSH into. Paprika is a `launchd` agent with no GUI dependencies — it starts before you log in and cleans up after itself.

**Choose Secretive if** you want a polished GUI with a dedicated Touch ID dialog that names the requesting application. Secretive has years of production use and a much larger user base.

---

## Requirements

- macOS 14+
- A Mac with Secure Enclave (any Apple Silicon or Intel Mac with T2 chip)
- A paid Apple Developer account for code signing (required to access the Secure Enclave)

---

## Installation

### Build from source

```bash
git clone https://github.com/klobucar/paprika.git
cd paprika
swift build -c release
```

After building, sign the binary with the provided entitlements. The Secure Enclave is inaccessible without this step:

```bash
codesign --force --sign - --entitlements entitlements.plist .build/release/paprika
```

For production use, sign with your Developer ID instead of `-` (ad-hoc):

```bash
codesign --force --sign "Developer ID Application: Your Name (TEAMID)" \
  --entitlements entitlements.plist \
  .build/release/paprika
```

### Install as a background agent

```bash
# Copy binary to a permanent location first, then:
.build/release/paprika install

# Load immediately (also runs at login via launchd)
launchctl load ~/Library/LaunchAgents/com.paprika.agent.plist
```

Add to your shell profile (`.zshrc`, `.bashrc`, etc.):

```bash
export SSH_AUTH_SOCK="$HOME/.paprika/agent.sock"
```

---

## Usage

### Generate a key

```bash
paprika generate github
paprika generate work-server
```

You will be prompted for Touch ID. The key is created inside the Secure Enclave and is permanently non-extractable.

### Show public keys

```bash
# If you have one key, prints it directly:
paprika show

# Specify by name:
paprika show github

# SHA256 fingerprint for GitHub/GitLab verification:
paprika show github --fingerprint
```

### Delete a key

```bash
paprika delete github
```

This permanently destroys the key. There is no recovery.

### Configure Git commit signing

```bash
# Auto-detects your key if you only have one:
paprika git-setup --global

# Specify a key:
paprika git-setup --global github

# Also add to ~/.ssh/allowed_signers (needed for git log --show-signature):
paprika git-setup --global --add-to-allowed
```

---

## Security model

- **Non-extractable keys**: Keys are `kSecAttrIsExtractable: false`. The private key material never exists outside the Secure Enclave, including in memory.
- **Touch ID on every signing operation**: Paprika creates a fresh `LAContext` per signing request. There is no authentication caching — each SSH or Git operation requires physical presence.
- **No network access**: Paprika communicates only over a Unix domain socket at `~/.paprika/agent.sock` with permissions `0700`.
- **Protocol**: Implements `SSH2_AGENTC_REQUEST_IDENTITIES` (11) and `SSH2_AGENTC_SIGN_REQUEST` (13) from the [SSH agent protocol](https://www.ietf.org/archive/id/draft-miller-ssh-agent-04.txt). Signatures are ECDSA P-256 (`ecdsa-sha2-nistp256`).
- **Crypto**: `CryptoKit` and the `Security` framework. No third-party crypto dependencies.

### Threat model

Paprika protects your SSH private keys from:
- Exfiltration by malware with user-level access
- SSH agent hijacking (the socket is owner-only)
- Silent signing (every operation requires biometric confirmation)

Paprika does **not** protect against:
- An attacker who can present your finger to the sensor
- A compromised OS kernel or Secure Enclave firmware
- An attacker present at your machine while your session is unlocked and you are authenticated

---

## Logs

```
/tmp/paprika.log   # stdout
/tmp/paprika.err   # stderr
```

---

## License

MIT
