// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AC_INTERNAL_H
#define DREAMINGWRT_AC_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#define AC_PAIRING_TOKEN_ID_LEN 36
#define AC_PAIRING_TOKEN_LEN 43
#define AC_PAIRING_SITE_ID_LEN 64
#define AC_PAIRING_HARDWARE_DIGEST_LEN 71
#define AC_ENROLLMENT_ID_LEN 36
#define AC_ENROLLMENT_KEY_ID_LEN 71
#define AC_ENROLLMENT_PUBLIC_KEY_LEN 32
#define AC_ENROLLMENT_NONCE_LEN 32
#define AC_ENROLLMENT_SIGNATURE_LEN 64
#define AC_ENROLLMENT_CSR_MAX 8192
#define AC_ENROLLMENT_CERT_MAX 16384

enum ac_pairing_redeem_result {
    AC_PAIRING_REDEEM_ERROR = -1,
    AC_PAIRING_REDEEM_OK = 0,
    AC_PAIRING_REDEEM_INVALID = 1,
    AC_PAIRING_REDEEM_EXPIRED = 2,
    AC_PAIRING_REDEEM_REVOKED = 3,
    AC_PAIRING_REDEEM_CONSUMED = 4,
    AC_PAIRING_REDEEM_EXHAUSTED = 5,
};

enum ac_enrollment_result {
    AC_ENROLLMENT_ERROR = -1,
    AC_ENROLLMENT_OK = 0,
    AC_ENROLLMENT_INVALID = 1,
    AC_ENROLLMENT_EXPIRED = 2,
    AC_ENROLLMENT_REVOKED = 3,
    AC_ENROLLMENT_CONFLICT = 4,
    AC_ENROLLMENT_EXHAUSTED = 5,
    AC_ENROLLMENT_IDEMPOTENT = 6,
};

struct ac_pairing_token_secret {
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char token[AC_PAIRING_TOKEN_LEN + 1];
    int64_t created_at;
    int64_t expires_at;
    int max_attempts;
};

struct ac_pairing_token_status {
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char site_id[AC_PAIRING_SITE_ID_LEN + 1];
    int hardware_bound;
    int attempts;
    int max_attempts;
    int64_t created_at;
    int64_t expires_at;
    int64_t consumed_at;
    int64_t revoked_at;
    int64_t claimed_at;
    char state[16];
};

typedef int (*ac_pairing_token_visit_fn)(
    const struct ac_pairing_token_status *status, void *opaque);

struct ac_enrollment_challenge {
    char challenge_id[AC_ENROLLMENT_ID_LEN + 1];
    unsigned char server_nonce[AC_ENROLLMENT_NONCE_LEN];
    int64_t created_at;
    int64_t expires_at;
};

struct ac_enrollment_claim {
    char challenge_id[AC_ENROLLMENT_ID_LEN + 1];
    unsigned char server_nonce[AC_ENROLLMENT_NONCE_LEN];
    unsigned char client_nonce[AC_ENROLLMENT_NONCE_LEN];
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    const char *token;
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    unsigned char public_key[AC_ENROLLMENT_PUBLIC_KEY_LEN];
    char site_id[AC_PAIRING_SITE_ID_LEN + 1];
    char hardware_digest[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    const unsigned char *csr_der;
    size_t csr_der_len;
    unsigned char csr_sha256[32];
    int64_t challenge_expires_at;
};

struct ac_enrollment_signed_request {
    struct ac_enrollment_claim claim;
    unsigned char signature[AC_ENROLLMENT_SIGNATURE_LEN];
};

struct ac_enrollment_record {
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char site_id[AC_PAIRING_SITE_ID_LEN + 1];
    char key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    char certificate_id[AC_ENROLLMENT_ID_LEN + 1];
    char state[32];
    int64_t claim_expires_at;
    int64_t created_at;
    int64_t updated_at;
    int64_t adopted_at;
};

struct ac_enrollment_certificate {
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    char certificate_id[AC_ENROLLMENT_ID_LEN + 1];
    char serial[129];
    char issuer_key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    const unsigned char *certificate_der;
    size_t certificate_der_len;
    unsigned char fingerprint_sha256[32];
    int64_t not_before;
    int64_t not_after;
};

int ac_db_init(void);
void ac_db_close(void);
int ac_db_pairing_token_create(int64_t ttl_seconds, int max_attempts,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_secret *out);
int ac_db_enrollment_challenge_create(
    int64_t ttl_seconds, struct ac_enrollment_challenge *out);
int ac_db_enrollment_claim(const struct ac_enrollment_claim *claim,
                           struct ac_enrollment_record *out);
int ac_db_enrollment_certificate_commit(
    const struct ac_enrollment_certificate *certificate,
    struct ac_enrollment_record *out);
int ac_db_enrollment_certificate_get(
    const char *enrollment_id, struct ac_enrollment_certificate *out,
    unsigned char **owned_der);
int ac_db_certificate_peer_authorize(
    const char *certificate_id, const char *ap_id,
    const unsigned char fingerprint_sha256[32], int require_active);
int ac_db_enrollment_activation_begin(
    const char *enrollment_id, const char *certificate_id,
    unsigned char challenge[AC_ENROLLMENT_NONCE_LEN]);
int ac_db_enrollment_activate(
    const char *enrollment_id, const char *certificate_id,
    const unsigned char peer_fingerprint_sha256[32],
    const unsigned char *challenge, size_t challenge_len,
    struct ac_enrollment_record *out);
int ac_enrollment_verify_and_claim(
    const struct ac_enrollment_signed_request *request,
    struct ac_enrollment_record *out);
int ac_enrollment_transcript_build(
    const struct ac_enrollment_claim *claim,
    unsigned char **out, size_t *out_len);

#endif
