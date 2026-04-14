# Security Policy

Paprika guards SSH private keys with the Apple Secure Enclave, so security issues here matter more than in most projects. If you find one, please report it privately.

## Supported Versions

During pre-1.0 development, only the `main` branch is supported. Fixes will be merged there.

| Version | Supported |
|---------|-----------|
| `main`  | Yes       |
| Tagged releases | On a best-effort basis |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private vulnerability reporting for this repository:

1. Go to the repository's **Security** tab
2. Click **Report a vulnerability**
3. Fill in the form with the details below

If private reporting is unavailable, contact the maintainer directly via the email listed on their GitHub profile.

## What to Include

A good report includes:

- **Affected version / commit SHA** — `git rev-parse HEAD` at the time you observed the issue
- **Reproduction steps** — minimal commands or code that trigger the issue
- **Impact assessment** — what an attacker could do (key exfiltration, signing bypass, DoS, etc.)
- **Environment** — macOS version, Mac model, whether you built the binary yourself and what signing identity was used
- **Suggested fix** (optional) — if you see one

## Scope

In scope:

- Key material leaving the Secure Enclave through any code path in this repository
- Signing operations succeeding without a fresh Touch ID authentication
- Socket protocol bugs that could let an unprivileged local process impersonate a signed identity
- Denial of service against the agent via malformed SSH agent protocol frames

Out of scope:

- Issues with Apple's Secure Enclave firmware, `CryptoKit`, or the `Security` framework — report those to Apple
- Attacks that require an attacker to already control your user account or present your biometry to the sensor
- Missing CI/CD security hardening (these are tracked as normal issues)

See the **Threat model** section of the README for the full model.

## Disclosure Timeline

- **Acknowledgement**: within 72 hours of receipt
- **Triage and fix target**: within 30 days for critical issues, 90 days for lower-severity
- **Public disclosure**: coordinated — we will agree on a disclosure date with the reporter once a fix is available

Credit will be given in release notes unless you request otherwise.
