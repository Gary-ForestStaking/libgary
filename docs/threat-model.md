# v0 threat model

This document is **non-normative** for byte layouts (see [v0-protocol.md](v0-protocol.md)) but **normative for security claims**: what libgary v0 is intended to defend against, and what remains out of scope.

## In scope — mitigations v0 targets

| Threat | Mitigation (design intent) |
|--------|----------------------------|
| **Passive network interception** | QUIC/TLS to server; E2E payloads encrypted with ratchet + AEAD; attachment ciphertext opaque on relay. |
| **Malicious or compromised relay (honest-but-curious server)** | Server sees timing, sizes, routing metadata; **must not** derive message plaintext or CEKs without breaking AEAD or stealing client keys. Keys derived only on clients. |
| **Stored ciphertext at rest (DB / blob store)** | Confidentiality under assumption that long-term **identity** secrets and **ratchet state** are not recovered; forward secrecy limits impact of later key compromise for deleted chain keys. |
| **Replay at protocol layer** | Counter + epoch rules per session (see v0-protocol). |
| **Tampering on the wire** | AEAD authentication tags; handshake transcript binding. |

## Explicitly out of scope — v0 does **not** guarantee

| Threat | Notes |
|--------|--------|
| **Compromised device** (malware, rooted/jailbroken OS, debugger) | Attacker can read keys, plaintext, memory; FS/PCS claims do not hold on that device. |
| **Screen capture, accessibility malware, malicious keyboard** | UI/data exfiltration; not addressed by wire crypto. |
| **Plaintext OS backups** (iCloud unencrypted backup, desktop sync, disk images) | Restores old keys and ciphertext; breaks practical FS unless backup encryption is designed separately. |
| **Physical seizure unlocked phone** | Same as device compromise while unlocked. |
| **Supply-chain compromise** of client binaries | Requires reproducible builds / code signing policies outside this spec. |
| **Metadata analysis** | Observing who talks when, blob sizes, IP correlation—partially mitigated only by product/network choices not fully specified in v0. |
| **Social engineering / impersonation** without key verification | Users must verify identity keys out-of-band if human assurance is required; v0 binds cryptography to keys, not to legal names. |

## Deployment assumptions

- Clients use an **OS CSPRNG** for all random values.
- TLS/QUIC endpoint authentication is configured correctly (valid server identity).
- Server follows **v0-protocol** API contracts (no plaintext transcoding of attachments).

## Relation to protocol goals

Claims of **forward secrecy** and **post-compromise security** apply **per pairwise session** under honest participant devices and correct implementation of ratchet rules in [v0-protocol.md](v0-protocol.md). They do **not** extend to backups, screenshots, or indefinite retention of decrypted plaintext.

Product-level metadata minimization (invite-only discovery, wake-only push, log retention) is described in [privacy-architecture.md](privacy-architecture.md); those controls affect **real-world** privacy even when wire crypto is correct.
