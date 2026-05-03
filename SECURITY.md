# Security policy

## Reporting a vulnerability

Please report security issues **privately** — do **not** open a public GitHub issue for undisclosed vulnerabilities.

- Prefer encrypted contact where possible (Signal / age / PGP — publish a key or inbox when ready).
- Include enough detail to reproduce or understand impact (component, version/commit, scenario).

We aim to acknowledge receipt within **7 days**. Coordinated disclosure timelines (e.g. fix window before public detail) can be agreed per report.

## Scope

This policy applies to the **libgary** reference implementation and protocol documents in this repository (Rust crates under `crates/`, wire format, persistence WAL). Out-of-scope items (third-party apps, deployment configs) may be redirected.

## Status

libgary v0 is **pre-production**. Independent cryptographic and protocol review is expected before production use; passing CI (tests, advisories, vector sync) does not replace a dedicated audit.
