// SPDX-License-Identifier: GPL-2.0-or-later
//
// cloud-web-v1 CONTROL-frame JSON schema. This is the field-level payload layer
// carried inside the CONTROL opcodes framed by wire.h/wire.c
// (HELLO/WELCOME/SERVICES/GENERATION/GOAWAY). wire.c freezes only the 12-byte
// framing + bounds; this header + control.c freeze the *field-level* JSON schema
// of the five control payloads, with strict validation and byte-stable encoders.
//
// Shared contract between the cloud gateway (dreamingrelay/cloud-web) and the
// device agent (jmxd/src/cloud): the SCHEMA and the golden vectors in
// tests/test_cloud_web_control.c are authoritative. This json-c implementation
// is cloud-web's; the device side must reproduce the same schema and golden
// bytes (it may use its own JSON library). Kept dependency-free apart from
// wire.h (constants) + json-c so it compiles/fuzzes in isolation, exactly like
// the wire codec.
//
// NOT frozen here (deliberately): OPEN/RESP data-frame heads, and the SERVICES
// manifest ELEMENT schema (a service object's internal fields) -- those belong
// to B2 (intranet-service publish). SERVICES freezes only its ENVELOPE
// {revision, services[], sig}; each element stays opaque.
#ifndef DREAMINGOS_CLOUD_WEB_CONTROL_H
#define DREAMINGOS_CLOUD_WEB_CONTROL_H

#include <stddef.h>
#include <stdint.h>

/* relay_router_id = "router-" + 32 lowercase hex = 39 chars (+NUL). Mirrors
 * cw_derive_router_id() in device.c. */
#define CW_CTL_ROUTER_ID_LEN  39
#define CW_CTL_SESSION_ID_LEN 32     /* tunnel session id: 128-bit lowercase hex */
#define CW_CTL_REASON_MAX     256    /* GOAWAY human reason cap */
#define CW_CTL_SIG_MAX        128    /* SERVICES manifest signature (base64) cap */
#define CW_CTL_NONCE_LEN      32     /* AUTH nonce: 128-bit lowercase hex (§20) */
#define CW_CTL_PUBKEY_B64     44     /* base64 of a 32-byte x25519/ed25519 pubkey */
#define CW_CTL_SIG_B64        88     /* base64 of a 64-byte ed25519 signature */

/* GENERATION.action enum (wire.h: enable|revoke; wire doc §10: supersede). */
enum cw_ctl_gen_action {
    CW_CTL_GEN_ENABLE    = 1,
    CW_CTL_GEN_REVOKE    = 2,
    CW_CTL_GEN_SUPERSEDE = 3,
};

struct cw_ctl_hello {                /* device -> cloud */
    uint32_t proto;                  /* must == CW_WIRE_VERSION */
    char     relay_router_id[CW_CTL_ROUTER_ID_LEN + 1];
    uint32_t generation;             /* device's last known generation, >= 1 */
};

struct cw_ctl_limits {               /* WELCOME.limits, bounded by wire.h */
    uint32_t max_streams;            /* 1 .. CW_WIRE_MAX_STREAMS */
    uint32_t stream_window;          /* 1 .. CW_WIRE_WINDOW_MAX */
    uint32_t conn_window;            /* stream_window .. CW_WIRE_WINDOW_MAX */
};

struct cw_ctl_welcome {              /* cloud -> device */
    char     session_id[CW_CTL_SESSION_ID_LEN + 1];
    uint32_t generation;             /* session generation, >= 1 */
    uint32_t heartbeat;              /* PING cadence secs, 1 .. CW_WIRE_PING_TIMEOUT */
    struct cw_ctl_limits limits;
};

struct cw_ctl_generation {           /* cloud -> device */
    uint32_t generation;             /* >= 1 */
    int      action;                 /* enum cw_ctl_gen_action */
};

struct cw_ctl_goaway {               /* either direction */
    int      code;                   /* enum cw_wire_err, 0 .. CW_ERR_INTERNAL */
    uint32_t last_stream_id;         /* highest stream the sender processed; 0 ok */
    char     reason[CW_CTL_REASON_MAX + 1]; /* optional; "" when absent */
};

struct cw_ctl_services {             /* cloud -> device; ENVELOPE only */
    int64_t revision;                /* monotonic, >= 1 (same source as generation) */
    int     n_services;              /* element count; elements stay opaque (B2) */
    char    sig[CW_CTL_SIG_MAX + 1]; /* base64 manifest signature, non-empty */
};

/* AUTH_CHALLENGE / AUTH_RESPONSE (§20): in-band ed25519 transport-key possession
 * proof, exchanged BETWEEN HELLO and WELCOME so a reconnecting device proves it
 * still holds the private keys behind its relay_router_id against a fresh,
 * server-chosen nonce (the durable, per-connection form of the B0 device
 * key-possession challenge; it does not depend on the ephemeral web_challenges
 * row). This header freezes only the JSON SHAPE + charset/length of each field;
 * re-deriving the router_id and verifying the signature is cloud-internal
 * enforcement (device.c/tunnel_server.c), not part of this shared codec. */
struct cw_ctl_auth_challenge {       /* cloud -> device */
    char nonce[CW_CTL_NONCE_LEN + 1];      /* 32 lowercase hex (128-bit) */
};

struct cw_ctl_auth_response {        /* device -> cloud */
    char sign_pub[CW_CTL_PUBKEY_B64 + 1];  /* base64(ed25519 pubkey, 32B) */
    char kex_pub[CW_CTL_PUBKEY_B64 + 1];   /* base64(x25519 pubkey, 32B) */
    char signature[CW_CTL_SIG_B64 + 1];    /* base64(ed25519 sig, 64B) */
};

/* Encoders: write a compact, byte-stable JSON payload into out[0..cap) and
 * return the length written (excluding the NUL), or -1 on a schema violation or
 * insufficient cap. Key order is fixed (see control.c) so the output matches the
 * golden vectors byte-for-byte. */
long cw_ctl_hello_encode(const struct cw_ctl_hello *h, char *out, size_t cap);
long cw_ctl_welcome_encode(const struct cw_ctl_welcome *w, char *out, size_t cap);
long cw_ctl_generation_encode(const struct cw_ctl_generation *g, char *out, size_t cap);
long cw_ctl_goaway_encode(const struct cw_ctl_goaway *g, char *out, size_t cap);
/* SERVICES: services_array_json is a pre-serialized JSON array of opaque service
 * objects (element schema is B2). Validated as a JSON array and embedded
 * verbatim. Pass "[]" for an empty manifest. */
long cw_ctl_services_encode(int64_t revision, const char *services_array_json,
                            const char *sig, char *out, size_t cap);
/* AUTH frames (§20): challenge carries the server nonce; response carries the
 * device's presented public keys + signature. Field charset/length enforced;
 * key order fixed for byte-stable goldens. */
long cw_ctl_auth_challenge_encode(const struct cw_ctl_auth_challenge *c,
                                  char *out, size_t cap);
long cw_ctl_auth_response_encode(const struct cw_ctl_auth_response *r,
                                 char *out, size_t cap);

/* Decoders: parse json[0..len), enforce the full field-level schema (required
 * keys, types, ranges, and NO unknown top-level keys), fill *out, and return 0;
 * return -1 on malformed JSON or any schema violation. */
int cw_ctl_hello_decode(const char *json, size_t len, struct cw_ctl_hello *out);
int cw_ctl_welcome_decode(const char *json, size_t len, struct cw_ctl_welcome *out);
int cw_ctl_generation_decode(const char *json, size_t len, struct cw_ctl_generation *out);
int cw_ctl_goaway_decode(const char *json, size_t len, struct cw_ctl_goaway *out);
int cw_ctl_services_decode(const char *json, size_t len, struct cw_ctl_services *out);
int cw_ctl_auth_challenge_decode(const char *json, size_t len,
                                 struct cw_ctl_auth_challenge *out);
int cw_ctl_auth_response_decode(const char *json, size_t len,
                                struct cw_ctl_auth_response *out);

/* Map a GENERATION.action string <-> enum (exposed for the test + callers). */
int         cw_ctl_action_from_str(const char *s);   /* -1 if unknown */
const char *cw_ctl_action_str(int action);           /* NULL if out of range */

#endif
