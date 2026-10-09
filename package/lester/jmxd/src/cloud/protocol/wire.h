// SPDX-License-Identifier: GPL-2.0-or-later
//
// cloud-web-v1 wire framing. This is the *shared* binary frame layer that both
// the cloud gateway (dreamingrelay/cloud-web) and the device agent
// (jmxd/src/cloud) speak over an already-TLS-secured, authenticated long-lived
// connection. It is deliberately independent of the legacy App E2EE 64 KiB JSON
// channel (jmxd/src/cloud/cloud_tunnel.c): browser traffic never shares that
// channel, its message types, or its business permissions.
//
// This header defines only framing (header + opaque payload + bounds). Payload
// interpretation (JSON for control ops, raw bytes for data ops) is layered
// above; keeping the codec dependency-free lets device and cloud compile the
// exact same object and lets it be fuzzed/tested in isolation.
#ifndef DREAMINGOS_CLOUD_WEB_WIRE_H
#define DREAMINGOS_CLOUD_WEB_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define CW_WIRE_VERSION        1u
#define CW_WIRE_HDR            12u          /* fixed header size in bytes */
#define CW_WIRE_FRAME_MAX      65536u       /* max payload bytes in one frame */
#define CW_WIRE_MSG_MAX       (CW_WIRE_HDR + CW_WIRE_FRAME_MAX)
#define CW_WIRE_MAX_STREAMS   128u          /* concurrent streams per session */
#define CW_WIRE_STREAM_WINDOW 262144u       /* initial per-stream flow window */
#define CW_WIRE_CONN_WINDOW   4194304u      /* initial per-device flow window */
#define CW_WIRE_WINDOW_MAX    0x7fffffffu   /* window ceiling (stays below 2^31) */
#define CW_WIRE_PING_INTERVAL 20            /* seconds between PING */
#define CW_WIRE_PING_TIMEOUT  60            /* seconds with no PONG => drop */
#define CW_WIRE_BACKOFF_BASE_MS 1000u       /* reconnect backoff base */
#define CW_WIRE_BACKOFF_CAP_MS  30000u      /* reconnect backoff ceiling */

/* Frame opcodes. Control ops require stream_id==0; data ops require a non-zero
 * stream_id. WINDOW is the sole exception: stream_id 0 = connection-level. */
enum cw_wire_op {
    CW_OP_HELLO      = 0x01, /* device->cloud: {proto,relay_router_id,generation} */
    CW_OP_WELCOME    = 0x02, /* cloud->device: {session_id,heartbeat,limits{...}} */
    CW_OP_PING       = 0x03, /* either: opaque token echoed in PONG */
    CW_OP_PONG       = 0x04, /* either: echoes the PING token */
    CW_OP_SERVICES   = 0x05, /* signed service manifest {revision,services,sig} */
    CW_OP_GENERATION = 0x06, /* cloud->device: {generation,action:enable|revoke} */
    CW_OP_GOAWAY     = 0x07, /* graceful close {code,last_stream_id,reason} */
    CW_OP_AUTH_CHALLENGE = 0x08, /* cloud->device: {nonce} transport-key challenge (§20) */
    CW_OP_AUTH_RESPONSE  = 0x09, /* device->cloud: {sign_pub,kex_pub,signature} (§20) */

    CW_OP_OPEN       = 0x10, /* open stream: request head incl. registered service_id */
    CW_OP_RESP       = 0x11, /* response head {status,headers} (once per stream) */
    CW_OP_DATA       = 0x12, /* raw body chunk (either direction) */
    CW_OP_FIN        = 0x13, /* half-close: no more body from sender (len==0) */
    CW_OP_RESET      = 0x14, /* abort stream, payload = u32 cw_wire_err (len==4) */
    CW_OP_WINDOW     = 0x15, /* flow credit, payload = u32 bytes (len==4) */
};

/* Frame flags (u16 bitfield). */
#define CW_FLAG_FIN      0x0001u /* with DATA/RESP: end-of-body in this direction */
#define CW_FLAG_END_HEAD 0x0002u /* with OPEN/RESP: request/response head complete */

/* Decode outcome. */
enum cw_wire_status {
    CW_WIRE_OK        = 0,  /* one full frame decoded */
    CW_WIRE_NEED_MORE = 1,  /* header/payload not fully buffered yet */
    CW_WIRE_ERROR     = -1, /* protocol violation; caller MUST close the link */
};

/* GOAWAY / RESET error codes. */
enum cw_wire_err {
    CW_ERR_NONE          = 0,
    CW_ERR_PROTOCOL      = 1,  /* malformed frame or rule violation */
    CW_ERR_FRAME_TOO_BIG = 2,  /* length exceeded CW_WIRE_FRAME_MAX */
    CW_ERR_FLOW_CONTROL  = 3,  /* peer overran its granted window */
    CW_ERR_STREAM_LIMIT  = 4,  /* too many concurrent streams */
    CW_ERR_GENERATION    = 5,  /* session superseded by a newer generation */
    CW_ERR_REVOKED       = 6,  /* access grant revoked */
    CW_ERR_SERVICE       = 7,  /* OPEN named an unknown/disabled service_id */
    CW_ERR_UPSTREAM      = 8,  /* device could not reach the target service */
    CW_ERR_CANCEL        = 9,  /* caller cancelled the request */
    CW_ERR_INTERNAL      = 10,
};

struct cw_frame {
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t length;         /* payload byte count (<= CW_WIRE_FRAME_MAX) */
    const uint8_t *payload;  /* points into the caller's input buffer, or NULL */
};

/* Serialize header+payload into out[0..cap). Returns total bytes written
 * (CW_WIRE_HDR+length) or -1 on: unknown opcode, length>max, cap too small,
 * NULL payload with length>0, or a stream_id that violates the op's rule. */
long cw_wire_encode(uint8_t *out, size_t cap, uint8_t type, uint16_t flags,
                    uint32_t stream_id, const uint8_t *payload, uint32_t length);

/* Decode one frame from in[0..len). CW_WIRE_OK: *frame filled (payload aliases
 * `in`), *consumed = whole-frame size. CW_WIRE_NEED_MORE: *consumed = 0.
 * CW_WIRE_ERROR: *err set to a cw_wire_err. Enforces version, opcode validity,
 * the control/data stream_id rule, fixed-size op lengths, and length<=max. */
int cw_wire_decode(const uint8_t *in, size_t len, struct cw_frame *frame,
                   size_t *consumed, int *err);

int cw_wire_is_control(uint8_t type); /* known control op (stream_id must be 0) */
int cw_wire_is_data(uint8_t type);    /* known data op (stream_id must be != 0) */

uint32_t cw_wire_read_u32(const uint8_t *p); /* big-endian u32 (RESET/WINDOW body) */

/* Reconnect backoff in ms for 0-based `attempt`: full = min(cap, base<<attempt),
 * result = full/2 + rnd*(full-full/2), i.e. equal jitter in [full/2, full).
 * `rnd` in [0,1) is supplied by the caller so the function stays pure. */
uint32_t cw_wire_backoff_ms(unsigned attempt, double rnd);

/* Flow-control accounting. add: grant credit, -1 if it would pass WINDOW_MAX.
 * take: consume n bytes, -1 if n>window (peer overran => CW_ERR_FLOW_CONTROL). */
int cw_wire_window_add(uint32_t *window, uint32_t credit);
int cw_wire_window_take(uint32_t *window, uint32_t n);

#endif
