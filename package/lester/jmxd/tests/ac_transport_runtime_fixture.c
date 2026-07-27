// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_enrollment_fixture.h"

#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define FIXTURE_CONTROLLER_ID "11111111-1111-5111-8111-111111111111"
#define FIXTURE_AP_ID "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define AC_SERVICE_NAME "dreamingwrt-ac-test"
#define AC_TRANSPORT_DEFAULT_PORT 18443
#define AC_TRANSPORT_WORKERS_MAX 8

struct ac_pki;
struct ac_pki_issued_certificate;
void ac_pki_free(struct ac_pki *pki);
int ac_transport_start(void);
void ac_transport_stop(void);
int ac_transport_listening(void);
const char *ac_transport_reason(void);
int ac_transport_port(void);
const char *ac_transport_controller_id(void);
int ac_pki_init(struct ac_pki **out);
const char *ac_pki_controller_id(const struct ac_pki *pki);
const unsigned char *ac_pki_ca_fingerprint_sha256(const struct ac_pki *pki);
X509 *ac_pki_ca_certificate_dup(const struct ac_pki *pki);
X509 *ac_pki_server_certificate_dup(const struct ac_pki *pki);
EVP_PKEY *ac_pki_server_private_key_dup(const struct ac_pki *pki);
int ac_pki_issue_ap_certificate(const struct ac_pki *pki, const char *ap_id,
    const unsigned char public_key[32], const unsigned char *csr_der,
    size_t csr_der_len, struct ac_pki_issued_certificate **out);
void ac_pki_issued_certificate_free(struct ac_pki_issued_certificate *value);
const unsigned char *ac_pki_issued_certificate_der(
    const struct ac_pki_issued_certificate *value, size_t *length);
const char *ac_pki_issued_certificate_serial(
    const struct ac_pki_issued_certificate *value);
const char *ac_pki_issued_certificate_issuer_key_id(
    const struct ac_pki_issued_certificate *value);
const unsigned char *ac_pki_issued_certificate_fingerprint_sha256(
    const struct ac_pki_issued_certificate *value);
int64_t ac_pki_issued_certificate_not_before(
    const struct ac_pki_issued_certificate *value);
int64_t ac_pki_issued_certificate_not_after(
    const struct ac_pki_issued_certificate *value);
int64_t ac_now_s(void);
int ac_db_enrollment_challenge_create(
    int64_t ttl, struct ac_enrollment_challenge *out);
int ac_enrollment_verify_and_claim(
    const struct ac_enrollment_signed_request *request,
    struct ac_enrollment_record *out);
int ac_db_enrollment_certificate_commit(
    const struct ac_enrollment_certificate *certificate,
    struct ac_enrollment_record *out);
int ac_db_enrollment_certificate_get(
    const char *enrollment_id, struct ac_enrollment_certificate *out,
    unsigned char **owned_der);
int ac_db_certificate_peer_authorize(const char *certificate_id,
    const char *ap_id, const unsigned char fingerprint[32], int active);
int ac_db_enrollment_activation_begin(const char *enrollment_id,
    const char *certificate_id, unsigned char challenge[32]);
int ac_db_enrollment_activate(const char *enrollment_id,
    const char *certificate_id, const unsigned char fingerprint[32],
    const unsigned char *challenge, size_t challenge_len,
    struct ac_enrollment_record *out);

struct ac_pki {
    X509 *ca;
    EVP_PKEY *ca_key;
    X509 *server;
    EVP_PKEY *server_key;
    X509 *client;
    EVP_PKEY *client_key;
    unsigned char client_fingerprint[SHA256_DIGEST_LENGTH];
    unsigned char ca_fingerprint[SHA256_DIGEST_LENGTH];
};

static struct ac_pki *fixture_active_pki;
static int fixture_adopted;
static int fixture_heartbeat_count;
static int fixture_session_protocol_version;
char fixture_current_session_epoch[AC_RADIO_JOB_SESSION_EPOCH_MAX + 1];
static char fixture_certificate_id[37];
static char fixture_enrollment_id[37];

struct ac_pki_issued_certificate {
    unsigned char *der;
    size_t der_len;
    unsigned char fingerprint[SHA256_DIGEST_LENGTH];
    char serial[41];
    int64_t not_before;
    int64_t not_after;
};

static volatile sig_atomic_t fixture_stop;
static int fixture_write_activation_marker(void);

static int fixture_extension(X509 *certificate, X509 *issuer, int nid,
                             const char *value)
{
    X509V3_CTX context;
    X509_EXTENSION *extension;
    int rc = -1;

    X509V3_set_ctx(&context, issuer, certificate, NULL, NULL, 0);
    extension = X509V3_EXT_conf_nid(NULL, &context, nid, (char *)value);
    if (extension && X509_add_ext(certificate, extension, -1) == 1)
        rc = 0;
    X509_EXTENSION_free(extension);
    return rc;
}

static EVP_PKEY *fixture_key(void)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *key = NULL;

    if (!context || EVP_PKEY_keygen_init(context) != 1 ||
        EVP_PKEY_keygen(context, &key) != 1) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static int fixture_name(X509_NAME *name, const char *text)
{
    return X509_NAME_add_entry_by_NID(
        name, NID_commonName, MBSTRING_ASC,
        (const unsigned char *)text, -1, -1, 0) == 1 ? 0 : -1;
}

static X509 *fixture_ca(EVP_PKEY *key)
{
    X509 *certificate = X509_new();
    X509_NAME *subject;

    if (!certificate || X509_set_version(certificate, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(certificate), -60) ||
        !X509_gmtime_adj(X509_getm_notAfter(certificate), 86400) ||
        X509_set_pubkey(certificate, key) != 1 ||
        !(subject = X509_get_subject_name(certificate)) ||
        fixture_name(subject, "DreamingWrt transport test CA") != 0 ||
        X509_set_issuer_name(certificate, subject) != 1 ||
        fixture_extension(certificate, certificate, NID_basic_constraints,
                          "critical,CA:TRUE,pathlen:0") != 0 ||
        fixture_extension(certificate, certificate, NID_key_usage,
                          "critical,keyCertSign,cRLSign") != 0 ||
        X509_sign(certificate, key, NULL) <= 0)
        goto fail;
    return certificate;
fail:
    X509_free(certificate);
    return NULL;
}

static X509 *fixture_server(EVP_PKEY *key, EVP_PKEY *ca_key, X509 *ca)
{
    X509 *certificate = X509_new();
    X509_NAME *subject;

    if (!certificate || X509_set_version(certificate, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), 2) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(certificate), -60) ||
        !X509_gmtime_adj(X509_getm_notAfter(certificate), 86400) ||
        X509_set_pubkey(certificate, key) != 1 ||
        !(subject = X509_get_subject_name(certificate)) ||
        fixture_name(subject, "DreamingWrt AC transport test") != 0 ||
        X509_set_issuer_name(certificate, X509_get_subject_name(ca)) != 1 ||
        fixture_extension(certificate, ca, NID_basic_constraints,
                          "critical,CA:FALSE") != 0 ||
        fixture_extension(certificate, ca, NID_key_usage,
                          "critical,digitalSignature") != 0 ||
        fixture_extension(certificate, ca, NID_ext_key_usage,
                          "serverAuth") != 0 ||
        fixture_extension(certificate, ca, NID_subject_alt_name,
                          "IP:127.0.0.1") != 0 ||
        X509_sign(certificate, ca_key, NULL) <= 0)
        goto fail;
    return certificate;
fail:
    X509_free(certificate);
    return NULL;
}

static X509 *fixture_client(EVP_PKEY *key, EVP_PKEY *ca_key, X509 *ca)
{
    X509 *certificate = X509_new();
    X509_NAME *subject;
    char san[128];

    if (!certificate || X509_set_version(certificate, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), 3) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(certificate), -60) ||
        !X509_gmtime_adj(X509_getm_notAfter(certificate), 86400) ||
        X509_set_pubkey(certificate, key) != 1 ||
        !(subject = X509_get_subject_name(certificate)) ||
        fixture_name(subject, "DreamingWrt AP transport test") != 0 ||
        X509_set_issuer_name(certificate, X509_get_subject_name(ca)) != 1 ||
        snprintf(san, sizeof(san), "URI:urn:dreamingwrt:ap:%s",
                 FIXTURE_AP_ID) >= (int)sizeof(san) ||
        fixture_extension(certificate, ca, NID_basic_constraints,
                          "critical,CA:FALSE") != 0 ||
        fixture_extension(certificate, ca, NID_key_usage,
                          "critical,digitalSignature") != 0 ||
        fixture_extension(certificate, ca, NID_ext_key_usage,
                          "clientAuth") != 0 ||
        fixture_extension(certificate, ca, NID_subject_alt_name, san) != 0 ||
        X509_sign(certificate, ca_key, NULL) <= 0)
        goto fail;
    return certificate;
fail:
    X509_free(certificate);
    return NULL;
}

static int fixture_fingerprint(X509 *certificate,
                               unsigned char out[SHA256_DIGEST_LENGTH])
{
    unsigned char *der = NULL;
    unsigned char *cursor;
    int length = i2d_X509(certificate, NULL);
    int rc = -1;

    if (length <= 0 || !(der = OPENSSL_malloc((size_t)length)))
        return -1;
    cursor = der;
    if (i2d_X509(certificate, &cursor) == length &&
        SHA256(der, (size_t)length, out))
        rc = 0;
    OPENSSL_cleanse(der, (size_t)length);
    OPENSSL_free(der);
    return rc;
}

int ac_pki_init(struct ac_pki **out)
{
    struct ac_pki *pki = calloc(1, sizeof(*pki));

    if (!pki || !(pki->ca_key = fixture_key()) ||
        !(pki->server_key = fixture_key()) ||
        !(pki->client_key = fixture_key()) ||
        !(pki->ca = fixture_ca(pki->ca_key)) ||
        !(pki->server = fixture_server(pki->server_key, pki->ca_key,
                                       pki->ca)) ||
        !(pki->client = fixture_client(pki->client_key, pki->ca_key,
                                       pki->ca)) ||
        fixture_fingerprint(pki->ca, pki->ca_fingerprint) != 0 ||
        fixture_fingerprint(pki->client, pki->client_fingerprint) != 0) {
        ac_pki_free(pki);
        return -1;
    }
    fixture_active_pki = pki;
    *out = pki;
    return 0;
}

void ac_pki_free(struct ac_pki *pki)
{
    if (!pki)
        return;
    X509_free(pki->server);
    X509_free(pki->client);
    X509_free(pki->ca);
    EVP_PKEY_free(pki->server_key);
    EVP_PKEY_free(pki->client_key);
    EVP_PKEY_free(pki->ca_key);
    if (fixture_active_pki == pki)
        fixture_active_pki = NULL;
    OPENSSL_cleanse(pki, sizeof(*pki));
    free(pki);
}

const char *ac_pki_controller_id(const struct ac_pki *pki)
{
    return pki ? FIXTURE_CONTROLLER_ID : NULL;
}

const unsigned char *ac_pki_ca_fingerprint_sha256(const struct ac_pki *pki)
{
    return pki ? pki->ca_fingerprint : NULL;
}

X509 *ac_pki_ca_certificate_dup(const struct ac_pki *pki)
{
    if (!pki || X509_up_ref(pki->ca) != 1)
        return NULL;
    return pki->ca;
}

X509 *ac_pki_server_certificate_dup(const struct ac_pki *pki)
{
    if (!pki || X509_up_ref(pki->server) != 1)
        return NULL;
    return pki->server;
}

EVP_PKEY *ac_pki_server_private_key_dup(const struct ac_pki *pki)
{
    if (!pki || EVP_PKEY_up_ref(pki->server_key) != 1)
        return NULL;
    return pki->server_key;
}

int ac_pki_issue_ap_certificate(const struct ac_pki *pki, const char *ap_id,
    const unsigned char public_key[32], const unsigned char *csr_der,
    size_t csr_der_len, struct ac_pki_issued_certificate **out)
{
    struct ac_pki_issued_certificate *issued = NULL;
    static const unsigned char der[] = {0x30, 0x03, 0x02, 0x01, 0x01};

    if (!pki || !ap_id || !public_key || !csr_der || !csr_der_len || !out ||
        strcmp(ap_id, FIXTURE_AP_ID) != 0 ||
        !(issued = calloc(1, sizeof(*issued))) ||
        !(issued->der = OPENSSL_malloc(sizeof(der)))) {
        free(issued);
        return -1;
    }
    memcpy(issued->der, der, sizeof(der));
    issued->der_len = sizeof(der);
    SHA256(der, sizeof(der), issued->fingerprint);
    snprintf(issued->serial, sizeof(issued->serial),
             "%s", "0123456789abcdef0123456789abcdef01234567");
    issued->not_before = ac_now_s() - 1;
    issued->not_after = ac_now_s() + 3600;
    *out = issued;
    return 0;
}

void ac_pki_issued_certificate_free(struct ac_pki_issued_certificate *value)
{
    if (!value)
        return;
    OPENSSL_free(value->der);
    OPENSSL_cleanse(value, sizeof(*value));
    free(value);
}

const unsigned char *ac_pki_issued_certificate_der(
    const struct ac_pki_issued_certificate *value, size_t *length)
{
    if (!value || !length)
        return NULL;
    *length = value->der_len;
    return value->der;
}

const char *ac_pki_issued_certificate_serial(
    const struct ac_pki_issued_certificate *value)
{
    return value ? value->serial : NULL;
}

const char *ac_pki_issued_certificate_issuer_key_id(
    const struct ac_pki_issued_certificate *value)
{
    (void)value;
    return "sha256:0000000000000000000000000000000000000000000000000000000000000000";
}

const unsigned char *ac_pki_issued_certificate_fingerprint_sha256(
    const struct ac_pki_issued_certificate *value)
{
    return value ? value->fingerprint : NULL;
}

int64_t ac_pki_issued_certificate_not_before(
    const struct ac_pki_issued_certificate *value)
{
    return value ? value->not_before : 0;
}

int64_t ac_pki_issued_certificate_not_after(
    const struct ac_pki_issued_certificate *value)
{
    return value ? value->not_after : 0;
}

int64_t ac_now_s(void)
{
    return (int64_t)time(NULL);
}

int ac_db_enrollment_challenge_create(
    int64_t ttl, struct ac_enrollment_challenge *out)
{
    (void)ttl;
    memset(out, 0, sizeof(*out));
    snprintf(out->challenge_id, sizeof(out->challenge_id),
             "%s", "22222222-2222-4222-8222-222222222222");
    memset(out->server_nonce, 0x22, sizeof(out->server_nonce));
    out->created_at = ac_now_s();
    out->expires_at = out->created_at + 120;
    return 0;
}

int ac_enrollment_verify_and_claim(
    const struct ac_enrollment_signed_request *request,
    struct ac_enrollment_record *out)
{
    if (!request || !out || strcmp(request->claim.ap_id, FIXTURE_AP_ID) != 0 ||
        strcmp(request->claim.token,
               "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS") != 0)
        return AC_ENROLLMENT_INVALID;
    memset(out, 0, sizeof(*out));
    snprintf(out->enrollment_id, sizeof(out->enrollment_id), "%s",
             request->claim.enrollment_id);
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", request->claim.ap_id);
    snprintf(out->state, sizeof(out->state), "%s", "claimed");
    return AC_ENROLLMENT_OK;
}

int ac_db_enrollment_certificate_commit(
    const struct ac_enrollment_certificate *certificate,
    struct ac_enrollment_record *out)
{
    if (!certificate || !out)
        return AC_ENROLLMENT_ERROR;
    memset(out, 0, sizeof(*out));
    snprintf(out->enrollment_id, sizeof(out->enrollment_id), "%s",
             certificate->enrollment_id);
    snprintf(out->certificate_id, sizeof(out->certificate_id), "%s",
             certificate->certificate_id);
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", FIXTURE_AP_ID);
    snprintf(out->state, sizeof(out->state), "%s", "mtls_pending");
    snprintf(fixture_certificate_id, sizeof(fixture_certificate_id), "%s",
             certificate->certificate_id);
    snprintf(fixture_enrollment_id, sizeof(fixture_enrollment_id), "%s",
             certificate->enrollment_id);
    return AC_ENROLLMENT_OK;
}

int ac_db_enrollment_certificate_get(
    const char *enrollment_id, struct ac_enrollment_certificate *out,
    unsigned char **owned_der)
{
    static const unsigned char der[] = {0x30, 0x03, 0x02, 0x01, 0x01};

    if (!fixture_adopted || !enrollment_id || !out || !owned_der ||
        strcmp(enrollment_id, fixture_enrollment_id) != 0 ||
        !(*owned_der = malloc(sizeof(der))))
        return -1;
    memcpy(*owned_der, der, sizeof(der));
    memset(out, 0, sizeof(*out));
    snprintf(out->enrollment_id, sizeof(out->enrollment_id), "%s",
             enrollment_id);
    snprintf(out->certificate_id, sizeof(out->certificate_id), "%s",
             fixture_certificate_id);
    out->certificate_der = *owned_der;
    out->certificate_der_len = sizeof(der);
    memcpy(out->fingerprint_sha256,
           fixture_active_pki->client_fingerprint, SHA256_DIGEST_LENGTH);
    return 0;
}

int ac_db_certificate_peer_authorize(const char *certificate_id,
    const char *ap_id, const unsigned char fingerprint[32], int active)
{
    (void)active;
    return fixture_active_pki && certificate_id && ap_id && fingerprint &&
        (active ? fixture_adopted : !fixture_adopted) &&
        strcmp(certificate_id, fixture_certificate_id) == 0 &&
        strcmp(ap_id, FIXTURE_AP_ID) == 0 &&
        CRYPTO_memcmp(fingerprint, fixture_active_pki->client_fingerprint,
                      SHA256_DIGEST_LENGTH) == 0;
}

int ac_db_enrollment_activation_begin(const char *enrollment_id,
    const char *certificate_id, unsigned char challenge[32])
{
    if (fixture_adopted || !enrollment_id || !certificate_id || !challenge ||
        strcmp(enrollment_id, fixture_enrollment_id) != 0 ||
        strcmp(certificate_id, fixture_certificate_id) != 0)
        return -1;
    memset(challenge, 0x55, 32);
    return 0;
}

int ac_db_enrollment_activate(const char *enrollment_id,
    const char *certificate_id, const unsigned char fingerprint[32],
    const unsigned char *challenge, size_t challenge_len,
    struct ac_enrollment_record *out)
{
    static const unsigned char expected[32] = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    };

    if (fixture_adopted || !enrollment_id || !certificate_id || !fingerprint ||
        !challenge || challenge_len != 32 || !out ||
        strcmp(enrollment_id, fixture_enrollment_id) != 0 ||
        strcmp(certificate_id, fixture_certificate_id) != 0 ||
        CRYPTO_memcmp(challenge, expected, 32) != 0)
        return AC_ENROLLMENT_INVALID;
    fixture_adopted = 1;
    if (fixture_write_activation_marker() != 0) {
        fixture_adopted = 0;
        return AC_ENROLLMENT_ERROR;
    }
    memset(out, 0, sizeof(*out));
    snprintf(out->enrollment_id, sizeof(out->enrollment_id), "%s",
             enrollment_id);
    snprintf(out->certificate_id, sizeof(out->certificate_id), "%s",
             certificate_id);
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", FIXTURE_AP_ID);
    snprintf(out->state, sizeof(out->state), "%s", "adopted");
    return AC_ENROLLMENT_OK;
}

int ac_db_ap_session_begin(const char *ap_id, const char *session_epoch,
                           int protocol_version, int64_t received_at)
{
    if (!fixture_adopted || !ap_id || strcmp(ap_id, FIXTURE_AP_ID) != 0 ||
        !session_epoch || strlen(session_epoch) != 64 ||
        (protocol_version != 1 && protocol_version != 2) || received_at <= 0)
        return -1;
    snprintf(fixture_current_session_epoch,
             sizeof(fixture_current_session_epoch), "%s", session_epoch);
    fixture_radio_jobs_reset(session_epoch);
    fixture_session_protocol_version = protocol_version;
    return 0;
}

int ac_db_ap_session_end(const char *ap_id, const char *session_epoch)
{
    if (!ap_id || !session_epoch || strcmp(ap_id, FIXTURE_AP_ID) != 0)
        return -1;
    if (!strcmp(session_epoch, fixture_current_session_epoch))
        fixture_session_protocol_version = 0;
    return 0;
}

int ac_db_ap_heartbeat(const char *ap_id, const char *session_epoch,
                       int64_t received_at)
{
    if (!fixture_adopted || !ap_id || strcmp(ap_id, FIXTURE_AP_ID) != 0 ||
        !session_epoch || strlen(session_epoch) != 64 ||
        strcmp(session_epoch, fixture_current_session_epoch) != 0 ||
        received_at <= 0)
        return -1;
    fixture_heartbeat_count++;
    return 0;
}

static void fixture_signal(int signo)
{
    (void)signo;
    fixture_stop = 1;
}

static int fixture_write_pem(const char *path, X509 *certificate,
                             EVP_PKEY *key)
{
    FILE *file = fopen(path, "w");
    int rc = -1;

    if (file && chmod(path, 0600) == 0 &&
        ((certificate && PEM_write_X509(file, certificate) == 1) ||
         (key && PEM_write_PrivateKey(file, key, NULL, NULL, 0,
                                      NULL, NULL) == 1)) &&
        fflush(file) == 0 && fsync(fileno(file)) == 0)
        rc = 0;
    if (file && fclose(file) != 0)
        rc = -1;
    return rc;
}

static int fixture_write_activation_marker(void)
{
    const char *directory = getenv("AC_TRANSPORT_TEST_OUTPUT");
    char path[1024];
    FILE *file;
    int rc = -1;

    if (!directory || !directory[0] ||
        snprintf(path, sizeof(path), "%s/activation.committed", directory) >=
            (int)sizeof(path))
        return -1;
    file = fopen(path, "w");
    if (file && fputs("adopted\n", file) >= 0 && fflush(file) == 0 &&
        fsync(fileno(file)) == 0)
        rc = 0;
    if (file && fclose(file) != 0)
        rc = -1;
    return rc;
}

static int fixture_export(void)
{
    const char *directory = getenv("AC_TRANSPORT_TEST_OUTPUT");
    char path[1024];

    if (!directory || !directory[0] || !fixture_active_pki)
        return -1;
    if (snprintf(path, sizeof(path), "%s/ca.pem", directory) >=
            (int)sizeof(path) ||
        fixture_write_pem(path, fixture_active_pki->ca, NULL) != 0 ||
        snprintf(path, sizeof(path), "%s/client.pem", directory) >=
            (int)sizeof(path) ||
        fixture_write_pem(path, fixture_active_pki->client, NULL) != 0 ||
        snprintf(path, sizeof(path), "%s/client.key", directory) >=
            (int)sizeof(path) ||
        fixture_write_pem(path, NULL, fixture_active_pki->client_key) != 0)
        return -1;
    return 0;
}

int main(void)
{
    const char *controller_id;

    signal(SIGINT, fixture_signal);
    signal(SIGTERM, fixture_signal);
    if (ac_transport_start() != 0 || fixture_export() != 0) {
        ac_transport_stop();
        return 2;
    }
    controller_id = ac_transport_controller_id();
    printf("port=%d\nreason=%s\ncontroller_id=%s\n", ac_transport_port(),
           ac_transport_reason(), controller_id);
    fflush(stdout);
    while (!fixture_stop)
        usleep(10000);
    ac_transport_stop();
    printf("stopped=%d\nreason=%s\ncontroller_after_stop=%s\nheartbeats=%d\n",
           !ac_transport_listening(), ac_transport_reason(),
           ac_transport_controller_id(), fixture_heartbeat_count);
    fflush(stdout);
    return 0;
}
