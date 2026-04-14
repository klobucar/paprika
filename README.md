<p align="center">
  <img src="assets/paprika.png" width="320" alt="Paprika SSH Agent">
</p>

# Paprika

A Secure Enclave SSH agent for macOS that lives entirely in your terminal.

Paprika is an **SSH key manager** first and foremost. It generates SSH keys inside the Secure Enclave (they never leave, not even into RAM), manages them through the standard `ssh-agent` protocol, and requires a fresh Touch ID authentication for every single signing operation. Any tool that respects `SSH_AUTH_SOCK` — `ssh`, `git`, `scp`, `rsync`, `mosh`, Ansible, Terraform, anything — gets hardware-backed keys for free, without changing its configuration.

Git commit signing is an excellent side benefit: because Paprika serves the same keys over the agent protocol, `git commit -S` and `git log --show-signature` work against Secure Enclave keys with no extra plumbing. The signing is hardware-bound, Touch ID-gated, and — to our knowledge — as strong as anything a macOS command-line tool can offer.

---

## Why Paprika instead of Secretive?

[Secretive](https://github.com/maxgoedjen/secretive) is excellent and the right tool for most people. Paprika is for a different workflow:

| | Paprika | Secretive |
|---|---|---|
| Interface | CLI daemon | GUI menu bar app |
| Requires display session | No | Yes |
| Runs on headless Mac | Yes | No |
| Scripting / dotfiles | `paprika generate mykey` | Manual clicks |
| Codebase size | ~600 lines of Swift | Much larger |
| One-line Git signing setup | `paprika git-setup --global` | Manual |

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

The primary workflow is: generate a key, copy the public half somewhere that accepts SSH keys (a server's `authorized_keys`, GitHub, GitLab, a Git host, a cloud instance), then use `ssh` / `git` / `scp` / `rsync` normally. Paprika handles the rest.

### 1. Generate a key

```bash
paprika generate github
paprika generate prod-bastion
paprika generate work-laptop
```

Touch ID will prompt once. The private key is created inside the Secure Enclave and is permanently non-extractable — it cannot be copied, backed up, or exported.

### 2. Copy the public key somewhere useful

```bash
# Print in ssh-keygen format:
paprika show github

# Pipe straight into a remote authorized_keys:
paprika show prod-bastion | ssh bastion 'cat >> ~/.ssh/authorized_keys'

# Or copy to clipboard for pasting into GitHub/GitLab:
paprika show github | pbcopy

# SHA256 fingerprint (for GitHub/GitLab key verification pages):
paprika show github --fingerprint
```

### 3. Use it

No SSH config changes needed. As long as `SSH_AUTH_SOCK` points at Paprika (see Installation above), every tool that uses SSH authentication will route through Paprika:

```bash
ssh prod-bastion            # Touch ID prompts, then you're in
git push origin main        # Touch ID prompts, then pushes
scp ./file bastion:~/       # Touch ID prompts, then transfers
rsync -av src/ bastion:dst/ # Touch ID prompts, then syncs
```

You'll see a Touch ID prompt the first time in a session and on every signing operation — there is no authentication caching.

### Deleting a key

```bash
paprika delete github
```

This destroys the key in the Secure Enclave. **There is no recovery** — the private key no longer exists anywhere in the universe.

### Bonus: Git commit signing

Because the same SSH keys are served over the agent protocol, Git can use them to sign commits with zero extra setup:

```bash
# Auto-detects your key if you only have one:
paprika git-setup --global

# Specify a key by name:
paprika git-setup --global github

# Also add to ~/.ssh/allowed_signers (so `git log --show-signature` verifies):
paprika git-setup --global --add-to-allowed
```

Every `git commit -S` will now prompt Touch ID and produce a hardware-bound, Secure Enclave-backed signature. Your Git history becomes provably authored by someone with physical presence at your Mac.

---

## Security model

- **Non-extractable keys**: Keys are `kSecAttrIsExtractable: false` and generated directly inside the Secure Enclave. The private key material never exists outside the SE, not even in RAM.
- **Touch ID on every signing operation**: Paprika creates a fresh `LAContext` per signing request. There is no authentication caching — each SSH, Git, scp, or rsync operation requires fresh physical presence.
- **Current-biometry binding**: Keys are generated with `.biometryCurrentSet`, so enrolling a new fingerprint after key creation invalidates the key. An attacker with brief physical access to an unlocked Mac cannot silently gain persistent signing authority.
- **File-system peer authentication**: The Unix socket at `~/.paprika/agent.sock` is `0600` under a `0700` directory, both re-enforced on every start. Only the process owner can `connect(2)` — no other local user can reach the agent.
- **Bounded message handling**: Incoming agent messages are capped at 256 KB. A malicious local client cannot force unbounded memory allocation by claiming a gigabyte-sized frame.
- **No network access**: Paprika listens only on a Unix domain socket. It never opens a TCP/UDP port.
- **Protocol**: Implements `SSH2_AGENTC_REQUEST_IDENTITIES` (11) and `SSH2_AGENTC_SIGN_REQUEST` (13) from the [SSH agent protocol](https://www.ietf.org/archive/id/draft-miller-ssh-agent-04.txt). Signatures are ECDSA P-256 (`ecdsa-sha2-nistp256`).
- **Crypto**: `CryptoKit` and the `Security` framework. No third-party crypto dependencies.

### Threat model

Paprika protects your SSH private keys from:

- Exfiltration by malware with user-level access (keys never leave the Secure Enclave)
- SSH agent hijacking by another local user (socket is 0600; parent dir is 0700; ownership verified at startup)
- Silent signing — every operation requires a fresh Touch ID authentication
- Attackers who briefly touch an unlocked machine to enroll a new fingerprint (keys become invalid on biometry set change)
- Memory exhaustion via oversized agent frames

Paprika does **not** protect against:

- An attacker who can present *your* finger to the sensor
- A compromised OS kernel or Secure Enclave firmware
- An attacker already executing code as your user while your session is unlocked and actively authenticated (they will still need Touch ID for each signature, so they cannot sign silently — but they can prompt you and hope you approve)
- An ad-hoc signed binary: keychain access group isolation depends on a proper Developer ID. For production use, sign the release binary with your team ID.

---

## Logs

```
~/Library/Logs/paprika/paprika.log   # stdout
~/Library/Logs/paprika/paprika.err   # stderr
```

---

## AI Honesty

Parts of Paprika were written with [Claude](https://claude.com/claude-code) as a pair-programmer — design discussions, SSH agent protocol wiring, Secure Enclave access control, test scaffolding, and this README itself. Every line was reviewed, tested, and accepted by a human before landing. This note exists because attribution belongs somewhere readers can see it, not buried in commit trailers.

## License

MIT
