# v0 session state machine

Non-normative diagram for implementers; framing in [v0-protocol.md](v0-protocol.md); handshake replay & duplicate `INIT`/`INIT_ACK` rules in [v0-handshake.md](v0-handshake.md) §8; catastrophic **`RESET_*`** flow in [v0-reset.md](v0-reset.md).

## States

| State | Description |
|-------|-------------|
| **NONE** | No session with peer; may have directory/prekey fetch cached. |
| **INIT_SENT** | Initiator sent `INIT`; awaiting `INIT_ACK`. |
| **INIT_RECV** | Responder received valid `INIT`; sent `INIT_ACK` or preparing to send. |
| **ACTIVE** | Double Ratchet operational; `DATA` / `REKEY` / attachments allowed. |
| **DRAINING** | Optional: user initiated close; flush outbound then send `CLOSE`. |
| **CLOSED** | Session terminated; must use new handshake (`epoch` bump + new `session_id`) for new cryptographic epoch. |

## Transitions (logical)

```
NONE --(send INIT)--> INIT_SENT
NONE --(recv INIT)--> INIT_RECV --(send INIT_ACK)--> ACTIVE

INIT_SENT --(recv INIT_ACK)--> ACTIVE

ACTIVE --(recv REKEY / local policy)--> ACTIVE   [ratchet advance, same session_id rules per spec]
ACTIVE --(RESET_INIT / RESET_ACK complete)--> ACTIVE   [new session_id, epoch++, tombstone prior session — [v0-reset.md](v0-reset.md)]
ACTIVE --(send CLOSE / recv CLOSE)--> CLOSED
ACTIVE --(recovery: explicit reset)--> NONE / INIT_SENT   [new prekeys, new session_id, epoch++]

CLOSED --(new handshake)--> INIT_SENT | INIT_RECV --> ACTIVE
```

## Implementation notes

- Handshake duplicates (`INIT`, `INIT_ACK`) — see [v0-handshake.md](v0-handshake.md) §8 (distinct from DATA replay §9 [v0-protocol.md](v0-protocol.md)).  
- **Replay window** and **skipped keys** in **ACTIVE** follow ratchet §8–§9 [v0-protocol.md](v0-protocol.md).
- **Concurrent INIT** from both sides should be resolved deterministically (e.g. lexicographic compare of `account_id`); normative tie-break belongs in server/client policy—document your chosen rule in the deployment guide.
- After **CLOSE**, implementations **must zeroize** ratchet secrets unless explicitly implementing lazy deletion policy—document retention.
