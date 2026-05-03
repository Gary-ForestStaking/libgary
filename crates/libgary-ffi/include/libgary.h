/**
 * Stable C ABI for libgary session runtime (`crates/libgary-ffi`).
 *
 * ABI — public exports (verify with `./scripts/verify-libgary-ffi-abi.sh`, expect **10** symbols):
 *   gary_session_new, gary_session_new_initiator, gary_session_free,
 *   gary_ingest_outer, gary_process_relay_inbound,
 *   gary_get_digest, gary_last_error,
 *   gary_send_utf8_data_outer, gary_prepare_relay_outbound_utf8, gary_last_inbound_utf8
 *
 * **Transport rule:** Embeddings should treat protocol bytes as opaque. Prefer relay wire
 * ([`gary_prepare_relay_outbound_utf8`] / [`gary_process_relay_inbound`]) for TLS/WebSocket relays.
 * [`gary_send_utf8_data_outer`] + [`gary_ingest_outer`] are raw `OuterRecord` bytes (e.g. LAN demos);
 * Swift must not implement relay framing or `PAD()` locally.
 *
 * Opaque `SessionHandle` only — not thread-safe across concurrent mutating calls on one handle.
 */

#ifndef LIBGARY_H
#define LIBGARY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct SessionHandle {
	unsigned char _opaque;
};
typedef struct SessionHandle SessionHandle;

/** Minimum recommended `out_cap` for [`gary_send_utf8_data_outer`] (serialized `OuterRecord` only). */
#define GARY_SEND_OUTER_CAP 8192
/** Maximum padded relay wire §6.5 bucket (`docs/v0-protocol.md`); use for [`gary_prepare_relay_outbound_utf8`]. */
#define GARY_RELAY_WIRE_CAP 32768

#define GARY_CODE_OK 0
#define GARY_CODE_NULL_POINTER 1
#define GARY_CODE_PANIC 2

#define GARY_CODE_WIRE_TRUNCATED 10
#define GARY_CODE_WIRE_RECORD_LENGTH_MISMATCH 11
#define GARY_CODE_WIRE_RECORD_TOO_LARGE 12
#define GARY_CODE_WIRE_INVALID_HEADER_VERSION 13
#define GARY_CODE_WIRE_INVALID_HEADER_TYPE 14
#define GARY_CODE_WIRE_INVALID_HEADER_FLAGS 15
#define GARY_CODE_WIRE_OTHER 19

#define GARY_CODE_CONTENT_TOO_LARGE 20
#define GARY_CODE_BUFFER_TOO_SMALL 21

#define GARY_CODE_SESSION_REPLAY_REJECTED 100
#define GARY_CODE_SESSION_STALE_EPOCH 101
#define GARY_CODE_SESSION_DECRYPTION_FAILED 102
#define GARY_CODE_SESSION_MAX_SKIP_EXCEEDED 103
#define GARY_CODE_SESSION_INVALID_HEADER 104
#define GARY_CODE_SESSION_UNKNOWN_SESSION 105
#define GARY_CODE_SESSION_STATE_INTEGRITY 106
#define GARY_CODE_SESSION_RESET_REQUIRED 107
#define GARY_CODE_SESSION_LATE_DATA_AFTER_RESET 108
#define GARY_CODE_SESSION_FUTURE_EPOCH 109

SessionHandle *gary_session_new(void);
SessionHandle *gary_session_new_initiator(void);
void gary_session_free(SessionHandle *session);

/** Raw serialized `OuterRecord` ingress (no relay envelope). Prefer [`gary_process_relay_inbound`] from relays. */
int32_t gary_ingest_outer(SessionHandle *session, const uint8_t *buf, size_t len);

/** Relay ingress: padded §6.1 relay wire → unwrap opaque → same decrypt path as [`gary_ingest_outer`]. */
int32_t gary_process_relay_inbound(SessionHandle *session, const uint8_t *buf, size_t len);

void gary_get_digest(const SessionHandle *session, uint8_t *out_digest32);
const char *gary_last_error(const SessionHandle *session);

/** Raw DATA `OuterRecord` only (no relay wrap). Prefer [`gary_prepare_relay_outbound_utf8`] for internet relays. */
int32_t gary_send_utf8_data_outer(SessionHandle *session, const uint8_t *utf8, size_t utf8_len,
				  uint8_t *out_buf, size_t out_cap, size_t *out_written);

/**
 * Full relay §6.1 wire: UTF‑8 DATA → `OuterRecord` → `RelayOuterEnvelope` → §6.5 `PAD`.
 * On OK, send `out_buf[..*out_written]` as one opaque WebSocket/TLS message.
 */
int32_t gary_prepare_relay_outbound_utf8(SessionHandle *session, const uint8_t *route_token,
					 size_t route_token_len, const uint8_t *utf8, size_t utf8_len,
					 uint8_t *out_buf, size_t out_cap, size_t *out_written);

/** After DATA decrypt OK ([`gary_ingest_outer`] or [`gary_process_relay_inbound`]). */
const char *gary_last_inbound_utf8(const SessionHandle *session);

#ifdef __cplusplus
}
#endif

#endif /* LIBGARY_H */
