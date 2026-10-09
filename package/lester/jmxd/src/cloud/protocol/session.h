// SPDX-License-Identifier: GPL-2.0-or-later
//
// cloud-web-v1 tunnel-session data-plane enforcement (CLOUD side). This is the
// runtime that the cloud gateway applies to the frames decoded by wire.c on one
// authenticated device tunnel: it is the "OPEN service_id registry + STREAM_LIMIT
// enforcement point" and the flow-control / lifecycle / revoke-close machine
// required by PM-to-Backend §3.2 and §7.
//
// It enforces the SHARED rules already frozen in docs/cloud-web-v1-wire.md
// (§5 stream lifecycle, §6 credit windows, §7 limits, §10 generation, §11
// revoke) but is NOT itself a byte-level wire contract: the device agent keeps
// its own equivalent bookkeeping. Kept dependency-free apart from wire.h
// (framing constants, error codes, and the window primitives) so it compiles and
// fuzzes in isolation, exactly like wire.c/control.c/webframe.c. No json-c, no
// sqlite3, no I/O: pure state, fed pre-decoded frame events by the caller.
//
// Perspective: the gateway is the OPEN initiator (caller) on behalf of a browser.
//   CW_DIR_UP   = gateway -> device (request body).
//   CW_DIR_DOWN = device -> gateway (response body).
// A window in a direction is credit the SENDER of that direction may still spend;
// the receiver replenishes it with WINDOW frames. Every mutator returns 0 on
// success or a positive enum cw_wire_err telling the caller which RESET/GOAWAY
// code to emit; -1 is reserved for a NULL/usage error.
#ifndef DREAMINGOS_CLOUD_WEB_SESSION_H
#define DREAMINGOS_CLOUD_WEB_SESSION_H

#include "wire.h"

#define CW_SESS_MAX_SERVICES   64  /* registered service_ids per signed manifest */
#define CW_SESS_SERVICE_ID_MAX 63  /* matches webframe service_id length cap */

enum cw_dir { CW_DIR_UP = 0, CW_DIR_DOWN = 1 };

/* One active stream slot. id==0 means the slot is free. */
struct cw_stream {
    uint32_t id;
    uint32_t win[2];      /* remaining credit the sender of each dir may spend */
    uint8_t  in_use;
    uint8_t  resp_seen;   /* RESP head observed (once per stream) */
    uint8_t  fin[2];      /* half-close seen for each direction */
};

struct cw_session {
    uint32_t generation;          /* current session generation (>=1) */
    uint32_t max_streams;         /* concurrency cap (1..CW_WIRE_MAX_STREAMS) */
    uint32_t init_stream_window;  /* per-stream initial window for new OPENs */
    uint32_t conn_win[2];         /* connection-level credit per direction */
    int      revoked;             /* access revoked: OPEN => CW_ERR_REVOKED */
    int      superseded;          /* newer generation took over: => CW_ERR_GENERATION */
    int      n_active;            /* active streams (0..max_streams) */
    int      n_services;          /* registered service_ids */
    char     services[CW_SESS_MAX_SERVICES][CW_SESS_SERVICE_ID_MAX + 1];
    struct cw_stream streams[CW_WIRE_MAX_STREAMS];
};

/* Initialize a session. max_streams is clamped to [1,CW_WIRE_MAX_STREAMS];
 * stream/conn windows to [1,CW_WIRE_WINDOW_MAX] with conn>=stream. generation
 * is forced to >=1. Clears the service registry and all streams. */
void cw_session_init(struct cw_session *s, uint32_t generation,
                     uint32_t max_streams, uint32_t stream_window,
                     uint32_t conn_window);

/* Replace the registered service set from a freshly applied signed manifest.
 * `ids` are service_ids the caller has already validated (webframe shape). A
 * bad-shaped id, a duplicate, or more than CW_SESS_MAX_SERVICES => -1 and the
 * registry is left cleared (fail-closed). Returns 0 on success. */
int  cw_session_set_services(struct cw_session *s, const char *const *ids, int n);
int  cw_session_has_service(const struct cw_session *s, const char *service_id);

/* Data-plane events. Return 0 or a positive enum cw_wire_err (see header note). */
int  cw_session_open(struct cw_session *s, uint32_t stream_id, const char *service_id);
int  cw_session_on_resp(struct cw_session *s, uint32_t stream_id);
int  cw_session_on_data(struct cw_session *s, uint32_t stream_id, int dir,
                        uint32_t n, int fin);
int  cw_session_on_fin(struct cw_session *s, uint32_t stream_id, int dir);
int  cw_session_on_reset(struct cw_session *s, uint32_t stream_id);
int  cw_session_on_window(struct cw_session *s, uint32_t stream_id, int dir,
                          uint32_t credit);

/* generation supersede: new_generation must be strictly greater (else
 * CW_ERR_PROTOCOL). Marks the session superseded and closes every active
 * stream. Returns 0 on success. */
int  cw_session_supersede(struct cw_session *s, uint32_t new_generation);
/* Revoke access: mark revoked and close every active stream. Returns the number
 * of streams closed (>=0). */
int  cw_session_revoke(struct cw_session *s);

/* Introspection (for callers/tests). */
int  cw_session_active_streams(const struct cw_session *s);
const struct cw_stream *cw_session_find(const struct cw_session *s, uint32_t stream_id);

#endif
