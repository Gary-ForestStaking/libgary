# LibGaryShell — local peer (FFI + MultipeerConnectivity)

Single-screen SwiftUI: **MultipeerConnectivity** on the LAN (Bonjour `lgry-peer-v1`). Payloads are **`gary_send_utf8_data_outer`** records; receive uses **`gary_ingest_outer`** → **`gary_last_inbound_utf8`**. Segmented **Alice / Bob**: initiator vs responder from the same doc handshake fixture (`gary_session_new_initiator` / `gary_session_new`). Not internet routing.

Rebuild Rust static library after FFI changes: `./scripts/build-libgary-ios-sim.sh`; ABI check expects **10** `gary_*` exports (includes relay wire prepare/process — use these for TLS/WebSocket relays; MCP demo still uses raw `OuterRecord` helpers).

Rust engine: `libgary-core`; C ABI: `crates/libgary-ffi/include/libgary.h` (see header for exported `gary_*` list).

## Prerequisites

- **Full Xcode.app** (not only Command Line Tools): `xcode-select -p` under `…/Xcode.app/…`, or the build script sets `DEVELOPER_DIR` when `/Applications/Xcode.app` exists.
- Xcode 15+ (iOS 17 SDK).
- **rustup** + `aarch64-apple-ios-sim`:

```bash
rustup target add aarch64-apple-ios-sim
```

## Build Rust archive + verify public ABI

From repo root:

```bash
./scripts/build-libgary-ios-sim.sh
./scripts/verify-libgary-ffi-abi.sh
```

Expect **exactly ten** `_gary_*` text symbols in the `.a` (per `verify-libgary-ffi-abi.sh`). Rust `__ZN…` names inside the archive are normal static-lib internals, not the C contract.

## Xcode

1. Open `examples/ios/LibGaryShell/LibGaryShell.xcodeproj`.
2. Signing / Simulator as usual.
3. Run — grant **Local Network** when prompted; two devices pick **Alice** / **Bob**, then Host / Browse.

The Xcode target sets **`EXCLUDED_ARCHS[sdk=iphonesimulator*] = x86_64`** so simulator builds match **`liblibgary_ffi.a`** from `./scripts/build-libgary-ios-sim.sh` (arm64 simulator only). Without that, Xcode links an x86_64 simulator slice too and you get many **`Undefined symbols for architecture x86_64`** (`_gary_*`). On an Intel Mac you would remove that exclusion and build the Rust library for the x86_64 iOS simulator target instead.

## Files

| Path | Role |
|------|------|
| `../../../crates/libgary-ffi/include/libgary.h` | C ABI |
| `LibGaryShell/LibGaryShell-Bridging-Header.h` | `#include "libgary.h"` |
| `LibGaryShell/LibGaryFFI.swift` | `gary_*` session wrapper |
| `LibGaryShell/GaryPeerTransport.swift` | MultipeerConnectivity |
| `LibGaryShell/PeerChatView.swift` | Chat UI |

See `docs/session-handle-boundary.md`.
