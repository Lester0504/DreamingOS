// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_enrollment_fixture.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define BUNDLE_MAGIC "ACENROLLMENTV1"

struct enrollment_bundle {
    char magic[16];
    char challenge_id[AC_ENROLLMENT_ID_LEN + 1];
    unsigned char server_nonce[AC_ENROLLMENT_NONCE_LEN];
    unsigned char client_nonce[AC_ENROLLMENT_NONCE_LEN];
    char enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char token[AC_PAIRING_TOKEN_LEN + 1];
    char ap_id[AC_ENROLLMENT_ID_LEN + 1];
    char key_id[AC_ENROLLMENT_KEY_ID_LEN + 1];
    unsigned char private_key[AC_ENROLLMENT_PUBLIC_KEY_LEN];
    unsigned char public_key[AC_ENROLLMENT_PUBLIC_KEY_LEN];
    char site_id[AC_PAIRING_SITE_ID_LEN + 1];
    char hardware_digest[AC_PAIRING_HARDWARE_DIGEST_LEN + 1];
    int64_t challenge_expires_at;
    size_t csr_der_len;
    unsigned char csr_der[AC_ENROLLMENT_CSR_MAX];
    unsigned char csr_sha256[SHA256_DIGEST_LENGTH];
    char certificate_id[AC_ENROLLMENT_ID_LEN + 1];
    unsigned char certificate_der[256];
    size_t certificate_der_len;
    unsigned char certificate_fingerprint[SHA256_DIGEST_LENGTH];
    unsigned char activation_challenge[AC_ENROLLMENT_NONCE_LEN];
};

static int generate_uuid(char out[AC_ENROLLMENT_ID_LEN + 1])
{
    unsigned char raw[16];

    if (RAND_bytes(raw, sizeof(raw)) != 1)
        return -1;
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    snprintf(out, AC_ENROLLMENT_ID_LEN + 1,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
             raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
    OPENSSL_cleanse(raw, sizeof(raw));
    return 0;
}

static void hex(char *out, const unsigned char *data, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < length; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 15];
    }
    out[length * 2] = '\0';
}

static int generate_identity_and_csr(struct enrollment_bundle *bundle)
{
    EVP_PKEY_CTX *key_context = NULL;
    EVP_PKEY *key = NULL;
    X509_REQ *request = NULL;
    X509_EXTENSION *san = NULL;
    STACK_OF(X509_EXTENSION) *extensions = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char *cursor;
    char digest_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    char san_value[96];
    size_t private_len = sizeof(bundle->private_key);
    size_t public_len = sizeof(bundle->public_key);
    int der_len;
    int rc = -1;

    key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!key_context || EVP_PKEY_keygen_init(key_context) != 1 ||
        EVP_PKEY_keygen(key_context, &key) != 1 ||
        EVP_PKEY_get_raw_private_key(key, bundle->private_key, &private_len) != 1 ||
        EVP_PKEY_get_raw_public_key(key, bundle->public_key, &public_len) != 1 ||
        private_len != sizeof(bundle->private_key) ||
        public_len != sizeof(bundle->public_key) ||
        !SHA256(bundle->public_key, sizeof(bundle->public_key), digest))
        goto done;
    hex(digest_hex, digest, sizeof(digest));
    snprintf(bundle->key_id, sizeof(bundle->key_id), "sha256:%s", digest_hex);
    if (generate_uuid(bundle->ap_id) != 0 ||
        snprintf(san_value, sizeof(san_value), "URI:urn:dreamingwrt:ap:%s",
                 bundle->ap_id) >= (int)sizeof(san_value) ||
        !(request = X509_REQ_new()) || X509_REQ_set_version(request, 0) != 1 ||
        X509_REQ_set_pubkey(request, key) != 1 ||
        !(extensions = sk_X509_EXTENSION_new_null()) ||
        !(san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
                                    san_value)) ||
        !sk_X509_EXTENSION_push(extensions, san))
        goto done;
    san = NULL;
    if (X509_REQ_add_extensions(request, extensions) != 1 ||
        X509_REQ_sign(request, key, NULL) <= 0 ||
        (der_len = i2d_X509_REQ(request, NULL)) <= 0 ||
        der_len > (int)sizeof(bundle->csr_der))
        goto done;
    cursor = bundle->csr_der;
    if (i2d_X509_REQ(request, &cursor) != der_len ||
        !SHA256(bundle->csr_der, (size_t)der_len, bundle->csr_sha256))
        goto done;
    bundle->csr_der_len = (size_t)der_len;
    rc = 0;
done:
    X509_EXTENSION_free(san);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    X509_REQ_free(request);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_context);
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(digest_hex, sizeof(digest_hex));
    return rc;
}

static int bundle_write(const char *path, const struct enrollment_bundle *bundle)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    const unsigned char *cursor = (const unsigned char *)bundle;
    size_t left = sizeof(*bundle);

    if (fd < 0 || fchmod(fd, 0600) != 0)
        goto fail;
    while (left) {
        ssize_t written = write(fd, cursor, left);
        if (written <= 0)
            goto fail;
        cursor += written;
        left -= (size_t)written;
    }
    if (fsync(fd) != 0 || close(fd) != 0)
        return -1;
    return 0;
fail:
    if (fd >= 0)
        close(fd);
    return -1;
}

static int bundle_read(const char *path, struct enrollment_bundle *bundle)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    unsigned char *cursor = (unsigned char *)bundle;
    size_t left = sizeof(*bundle);

    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_nlink != 1 || (st.st_mode & 0777) != 0600 ||
        st.st_size != (off_t)sizeof(*bundle))
        goto fail;
    while (left) {
        ssize_t got = read(fd, cursor, left);
        if (got <= 0)
            goto fail;
        cursor += got;
        left -= (size_t)got;
    }
    close(fd);
    if (memcmp(bundle->magic, BUNDLE_MAGIC, sizeof(BUNDLE_MAGIC)) != 0 ||
        bundle->csr_der_len == 0 || bundle->csr_der_len > sizeof(bundle->csr_der))
        return -1;
    return 0;
fail:
    if (fd >= 0)
        close(fd);
    return -1;
}

static int certificate_readback(const char *path)
{
    struct enrollment_bundle bundle;
    struct ac_enrollment_certificate certificate;
    unsigned char *owned_der = NULL;
    int pending_ok;
    int active_ok;
    int rc = 1;

    memset(&bundle, 0, sizeof(bundle));
    memset(&certificate, 0, sizeof(certificate));
    if (bundle_read(path, &bundle) != 0 ||
        ac_db_enrollment_certificate_get(bundle.enrollment_id, &certificate,
                                         &owned_der) != 0)
        goto done;
    pending_ok = ac_db_certificate_peer_authorize(
        certificate.certificate_id, bundle.ap_id,
        certificate.fingerprint_sha256, 0);
    active_ok = ac_db_certificate_peer_authorize(
        certificate.certificate_id, bundle.ap_id,
        certificate.fingerprint_sha256, 1);
    printf("certificate_id=%s length=%zu same=%d pending=%d active=%d\n",
           certificate.certificate_id, certificate.certificate_der_len,
           certificate.certificate_der_len == bundle.certificate_der_len &&
           CRYPTO_memcmp(certificate.certificate_der, bundle.certificate_der,
                         bundle.certificate_der_len) == 0,
           pending_ok, active_ok);
    rc = 0;
done:
    if (owned_der) {
        OPENSSL_cleanse(owned_der, certificate.certificate_der_len);
        free(owned_der);
    }
    OPENSSL_cleanse(&bundle, sizeof(bundle));
    OPENSSL_cleanse(&certificate, sizeof(certificate));
    return rc;
}

static void claim_from_bundle(struct ac_enrollment_claim *claim,
                              struct enrollment_bundle *bundle)
{
    memset(claim, 0, sizeof(*claim));
    snprintf(claim->challenge_id, sizeof(claim->challenge_id), "%s",
             bundle->challenge_id);
    memcpy(claim->server_nonce, bundle->server_nonce,
           sizeof(claim->server_nonce));
    memcpy(claim->client_nonce, bundle->client_nonce,
           sizeof(claim->client_nonce));
    snprintf(claim->enrollment_id, sizeof(claim->enrollment_id), "%s",
             bundle->enrollment_id);
    snprintf(claim->token_id, sizeof(claim->token_id), "%s", bundle->token_id);
    claim->token = bundle->token;
    snprintf(claim->ap_id, sizeof(claim->ap_id), "%s", bundle->ap_id);
    snprintf(claim->key_id, sizeof(claim->key_id), "%s", bundle->key_id);
    memcpy(claim->public_key, bundle->public_key, sizeof(claim->public_key));
    snprintf(claim->site_id, sizeof(claim->site_id), "%s", bundle->site_id);
    snprintf(claim->hardware_digest, sizeof(claim->hardware_digest), "%s",
             bundle->hardware_digest);
    claim->csr_der = bundle->csr_der;
    claim->csr_der_len = bundle->csr_der_len;
    memcpy(claim->csr_sha256, bundle->csr_sha256, sizeof(claim->csr_sha256));
    claim->challenge_expires_at = bundle->challenge_expires_at;
}

static int sign_request(struct ac_enrollment_signed_request *request,
                        struct enrollment_bundle *bundle)
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *context = NULL;
    unsigned char *transcript = NULL;
    size_t transcript_len = 0;
    size_t signature_len = sizeof(request->signature);
    int rc = -1;

    memset(request, 0, sizeof(*request));
    claim_from_bundle(&request->claim, bundle);
    if (ac_enrollment_transcript_build(&request->claim, &transcript,
                                       &transcript_len) != 0 ||
        !(key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                             bundle->private_key,
                                             sizeof(bundle->private_key))) ||
        !(context = EVP_MD_CTX_new()) ||
        EVP_DigestSignInit(context, NULL, NULL, NULL, key) != 1 ||
        EVP_DigestSign(context, request->signature, &signature_len,
                       transcript, transcript_len) != 1 ||
        signature_len != sizeof(request->signature))
        goto done;
    rc = 0;
done:
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    if (transcript) {
        OPENSSL_cleanse(transcript, transcript_len);
        OPENSSL_free(transcript);
    }
    return rc;
}

static int prepare_bundle(const char *path)
{
    struct enrollment_bundle bundle;
    struct ac_pairing_token_secret token;
    struct ac_enrollment_challenge challenge;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int rc = -1;

    memset(&bundle, 0, sizeof(bundle));
    memset(&token, 0, sizeof(token));
    memset(&challenge, 0, sizeof(challenge));
    memcpy(bundle.magic, BUNDLE_MAGIC, sizeof(BUNDLE_MAGIC));
    snprintf(bundle.site_id, sizeof(bundle.site_id), "site-a");
    SHA256((const unsigned char *)"fixture-hardware", 16, digest);
    memcpy(bundle.hardware_digest, "sha256:", 7);
    hex(bundle.hardware_digest + 7, digest, sizeof(digest));
    if (ac_db_pairing_token_create(600, 5, bundle.site_id,
                                   bundle.hardware_digest, &token) != 0 ||
        ac_db_enrollment_challenge_create(120, &challenge) != 0 ||
        generate_uuid(bundle.enrollment_id) != 0 ||
        generate_identity_and_csr(&bundle) != 0 ||
        RAND_bytes(bundle.client_nonce, sizeof(bundle.client_nonce)) != 1)
        goto done;
    snprintf(bundle.challenge_id, sizeof(bundle.challenge_id), "%s",
             challenge.challenge_id);
    memcpy(bundle.server_nonce, challenge.server_nonce,
           sizeof(bundle.server_nonce));
    bundle.challenge_expires_at = challenge.expires_at;
    snprintf(bundle.token_id, sizeof(bundle.token_id), "%s", token.token_id);
    snprintf(bundle.token, sizeof(bundle.token), "%s", token.token);
    if (generate_uuid(bundle.certificate_id) != 0)
        goto done;
    bundle.certificate_der_len = sizeof(bundle.certificate_der);
    if (RAND_bytes(bundle.certificate_der,
                   (int)bundle.certificate_der_len) != 1 ||
        !SHA256(bundle.certificate_der, bundle.certificate_der_len,
                bundle.certificate_fingerprint) ||
        bundle_write(path, &bundle) != 0)
        goto done;
    printf("token_id=%s enrollment_id=%s ap_id=%s\n", bundle.token_id,
           bundle.enrollment_id, bundle.ap_id);
    rc = 0;
done:
    OPENSSL_cleanse(&token, sizeof(token));
    OPENSSL_cleanse(&bundle, sizeof(bundle));
    OPENSSL_cleanse(digest, sizeof(digest));
    return rc;
}

static int claim_bundle(const char *path, int tamper, int commit_failure)
{
    struct enrollment_bundle bundle;
    struct ac_enrollment_signed_request request;
    struct ac_enrollment_record record;
    int result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&request, 0, sizeof(request));
    memset(&record, 0, sizeof(record));
    if (bundle_read(path, &bundle) != 0 || sign_request(&request, &bundle) != 0)
        return 1;
    if (tamper == 1)
        request.signature[0] ^= 1;
    else if (tamper == 2)
        ((unsigned char *)request.claim.csr_der)[0] ^= 1;
    else if (tamper == 3)
        request.claim.server_nonce[0] ^= 1;
    if (commit_failure)
        setenv("AC_DB_TEST_FAIL_COMMIT_ONCE", "1", 1);
    result = ac_enrollment_verify_and_claim(&request, &record);
    printf("result=%d state=%s enrollment_id=%s\n", result, record.state,
           record.enrollment_id);
    OPENSSL_cleanse(&request, sizeof(request));
    OPENSSL_cleanse(&bundle, sizeof(bundle));
    return result == AC_ENROLLMENT_ERROR ? 1 : 0;
}

static int recover_claim_bundle(const char *path)
{
    struct enrollment_bundle bundle;
    struct ac_enrollment_challenge challenge;
    struct ac_enrollment_signed_request request;
    struct ac_enrollment_record record;
    char original_enrollment_id[AC_ENROLLMENT_ID_LEN + 1];
    int result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&challenge, 0, sizeof(challenge));
    memset(&request, 0, sizeof(request));
    memset(&record, 0, sizeof(record));
    memset(original_enrollment_id, 0, sizeof(original_enrollment_id));
    if (bundle_read(path, &bundle) != 0)
        return 1;
    snprintf(original_enrollment_id, sizeof(original_enrollment_id), "%s",
             bundle.enrollment_id);
    if (ac_db_enrollment_challenge_create(120, &challenge) != 0 ||
        generate_uuid(bundle.enrollment_id) != 0 ||
        RAND_bytes(bundle.client_nonce, sizeof(bundle.client_nonce)) != 1)
        goto fail;
    snprintf(bundle.challenge_id, sizeof(bundle.challenge_id), "%s",
             challenge.challenge_id);
    memcpy(bundle.server_nonce, challenge.server_nonce,
           sizeof(bundle.server_nonce));
    bundle.challenge_expires_at = challenge.expires_at;
    if (sign_request(&request, &bundle) != 0)
        goto fail;
    result = ac_enrollment_verify_and_claim(&request, &record);
    printf("result=%d requested_enrollment_id=%s recovered_enrollment_id=%s\n",
           result, bundle.enrollment_id, record.enrollment_id);
    OPENSSL_cleanse(&request, sizeof(request));
    OPENSSL_cleanse(&bundle, sizeof(bundle));
    OPENSSL_cleanse(&challenge, sizeof(challenge));
    return result == AC_ENROLLMENT_IDEMPOTENT &&
           strcmp(record.enrollment_id, original_enrollment_id) == 0 ? 0 : 1;
fail:
    OPENSSL_cleanse(&request, sizeof(request));
    OPENSSL_cleanse(&bundle, sizeof(bundle));
    OPENSSL_cleanse(&challenge, sizeof(challenge));
    return 1;
}

static int certificate_bundle(const char *path, int commit_failure)
{
    struct enrollment_bundle bundle;
    struct ac_enrollment_certificate certificate;
    struct ac_enrollment_record record;
    int result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&certificate, 0, sizeof(certificate));
    memset(&record, 0, sizeof(record));
    if (bundle_read(path, &bundle) != 0)
        return 1;
    snprintf(certificate.enrollment_id, sizeof(certificate.enrollment_id), "%s",
             bundle.enrollment_id);
    snprintf(certificate.certificate_id, sizeof(certificate.certificate_id), "%s",
             bundle.certificate_id);
    snprintf(certificate.serial, sizeof(certificate.serial), "0011223344556677");
    memset(certificate.issuer_key_id, 'a', sizeof(certificate.issuer_key_id) - 1);
    memcpy(certificate.issuer_key_id, "sha256:", 7);
    certificate.certificate_der = bundle.certificate_der;
    certificate.certificate_der_len = bundle.certificate_der_len;
    memcpy(certificate.fingerprint_sha256, bundle.certificate_fingerprint,
           sizeof(certificate.fingerprint_sha256));
    certificate.not_before = (int64_t)time(NULL) - 1;
    certificate.not_after = (int64_t)time(NULL) + 3600;
    if (commit_failure)
        setenv("AC_DB_TEST_FAIL_COMMIT_ONCE", "1", 1);
    result = ac_db_enrollment_certificate_commit(&certificate, &record);
    printf("result=%d state=%s certificate_id=%s\n", result, record.state,
           record.certificate_id);
    OPENSSL_cleanse(&bundle, sizeof(bundle));
    return result == AC_ENROLLMENT_ERROR ? 1 : 0;
}

static int activation_begin(const char *path)
{
    struct enrollment_bundle bundle;

    memset(&bundle, 0, sizeof(bundle));
    if (bundle_read(path, &bundle) != 0 ||
        ac_db_enrollment_activation_begin(bundle.enrollment_id,
            bundle.certificate_id, bundle.activation_challenge) != 0 ||
        bundle_write(path, &bundle) != 0)
        return 1;
    printf("challenge_created=1\n");
    OPENSSL_cleanse(&bundle, sizeof(bundle));
    return 0;
}

static int activate_bundle(const char *path, int wrong_challenge,
                           int wrong_fingerprint)
{
    struct enrollment_bundle bundle;
    struct ac_enrollment_record record;
    unsigned char challenge[AC_ENROLLMENT_NONCE_LEN];
    unsigned char fingerprint[SHA256_DIGEST_LENGTH];
    int result;

    memset(&bundle, 0, sizeof(bundle));
    memset(&record, 0, sizeof(record));
    if (bundle_read(path, &bundle) != 0)
        return 1;
    memcpy(challenge, bundle.activation_challenge, sizeof(challenge));
    memcpy(fingerprint, bundle.certificate_fingerprint, sizeof(fingerprint));
    if (wrong_challenge)
        challenge[0] ^= 1;
    if (wrong_fingerprint)
        fingerprint[0] ^= 1;
    result = ac_db_enrollment_activate(bundle.enrollment_id,
        bundle.certificate_id, fingerprint, challenge, sizeof(challenge), &record);
    printf("result=%d state=%s adopted_at=%lld\n", result, record.state,
           (long long)record.adopted_at);
    OPENSSL_cleanse(&bundle, sizeof(bundle));
    OPENSSL_cleanse(challenge, sizeof(challenge));
    OPENSSL_cleanse(fingerprint, sizeof(fingerprint));
    return result == AC_ENROLLMENT_ERROR ? 1 : 0;
}

int main(int argc, char **argv)
{
    int rc = 1;

    if (argc < 2 || ac_db_init() != 0)
        return 2;
    if (strcmp(argv[1], "prepare") == 0 && argc == 3)
        rc = prepare_bundle(argv[2]);
    else if (strcmp(argv[1], "claim") == 0 && argc == 3)
        rc = claim_bundle(argv[2], 0, 0);
    else if (strcmp(argv[1], "claim-bad-signature") == 0 && argc == 3)
        rc = claim_bundle(argv[2], 1, 0);
    else if (strcmp(argv[1], "claim-bad-csr") == 0 && argc == 3)
        rc = claim_bundle(argv[2], 2, 0);
    else if (strcmp(argv[1], "claim-bad-nonce") == 0 && argc == 3)
        rc = claim_bundle(argv[2], 3, 0);
    else if (strcmp(argv[1], "claim-commit-failure") == 0 && argc == 3)
        rc = claim_bundle(argv[2], 0, 1);
    else if (strcmp(argv[1], "certificate") == 0 && argc == 3)
        rc = certificate_bundle(argv[2], 0);
    else if (strcmp(argv[1], "certificate-commit-failure") == 0 && argc == 3)
        rc = certificate_bundle(argv[2], 1);
    else if (strcmp(argv[1], "recover-claim") == 0 && argc == 3)
        rc = recover_claim_bundle(argv[2]);
    else if (strcmp(argv[1], "activation-begin") == 0 && argc == 3)
        rc = activation_begin(argv[2]);
    else if (strcmp(argv[1], "activate") == 0 && argc == 3)
        rc = activate_bundle(argv[2], 0, 0);
    else if (strcmp(argv[1], "activate-wrong") == 0 && argc == 3)
        rc = activate_bundle(argv[2], 1, 0);
    else if (strcmp(argv[1], "activate-wrong-certificate") == 0 && argc == 3)
        rc = activate_bundle(argv[2], 0, 1);
    else if (strcmp(argv[1], "certificate-readback") == 0 && argc == 3)
        rc = certificate_readback(argv[2]);
    ac_db_close();
    return rc;
}
