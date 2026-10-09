// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DWRT_AC_CERTIFICATE_LIFECYCLE_H
#define DWRT_AC_CERTIFICATE_LIFECYCLE_H
#include <stddef.h>
#include <stdint.h>
#include <openssl/types.h>
#include <sqlite3.h>
struct json_object;
struct ac_pki;
struct ac_pki_issued_certificate;
int ac_pki_init(struct ac_pki **out);
void ac_pki_free(struct ac_pki *pki);
const char *ac_pki_last_reason(void);
const char *ac_pki_controller_id(const struct ac_pki *pki);
X509 *ac_pki_server_certificate_dup(const struct ac_pki *pki);
X509 *ac_pki_ca_certificate_dup(const struct ac_pki *pki);
EVP_PKEY *ac_pki_server_private_key_dup(const struct ac_pki *pki);
int ac_pki_issue_ap_certificate(const struct ac_pki *, const char *, const unsigned char[32],
    const unsigned char *, size_t, struct ac_pki_issued_certificate **);
void ac_pki_issued_certificate_free(struct ac_pki_issued_certificate *);
const unsigned char *ac_pki_issued_certificate_der(const struct ac_pki_issued_certificate *, size_t *);
const char *ac_pki_issued_certificate_serial(const struct ac_pki_issued_certificate *);
const char *ac_pki_issued_certificate_issuer_key_id(const struct ac_pki_issued_certificate *);
const unsigned char *ac_pki_issued_certificate_fingerprint_sha256(const struct ac_pki_issued_certificate *);
int64_t ac_pki_issued_certificate_not_before(const struct ac_pki_issued_certificate *);
int64_t ac_pki_issued_certificate_not_after(const struct ac_pki_issued_certificate *);

int ac_pki_certificate_window(const char *kind, int64_t *not_before, int64_t *not_after);
const char *ac_pki_generation(const struct ac_pki *pki);
X509 *ac_pki_alternate_ca_dup(const struct ac_pki *pki);
int ac_pki_generation_prepare(const char *id, int rotate_ca, struct ac_pki **out);
int ac_pki_generation_open(const char *id, struct ac_pki **out);
int ac_pki_generation_activate(const char *id);
int ac_pki_generation_retire(const char *id);
int ac_pki_trust_pem(const struct ac_pki *pki, unsigned char **out, size_t *length);
int ac_certificate_lifecycle_init(sqlite3 *db);
int ac_certificate_lifecycle_ready(sqlite3 *db);
struct json_object *ac_certificate_lifecycle_request(sqlite3 *db, struct json_object *request);
struct json_object *ac_certificate_lifecycle_poll(sqlite3 *db, const char *ap_id,
    const char *certificate_id, const unsigned char peer_fingerprint[32],
    const unsigned char server_fingerprint[32], const unsigned char trust_fingerprint[32],
    const unsigned char *csr, size_t csr_len);
int ac_certificate_lifecycle_enrollment_allowed(sqlite3 *db);
int ac_certificate_lifecycle_tick(sqlite3 *db);
int ac_transport_certificate_reload(void);
#endif
