// SPDX-License-Identifier: GPL-2.0-or-later
#ifdef APD_ENROLLMENT_TEST_STANDALONE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#define APD_AP_ID_LEN 36
#define APD_ED25519_KEY_LEN 32
#define APD_ED25519_SIGNATURE_LEN 64
#define APD_KEY_ID_LEN 71
#define APD_ENROLLMENT_CHALLENGE_ID_MAX 36
#define APD_ENROLLMENT_ID_MAX 36
#define APD_ENROLLMENT_TOKEN_ID_MAX 36
#define APD_ENROLLMENT_TOKEN_LEN 43
#define APD_ENROLLMENT_SITE_ID_MAX 64
#define APD_ENROLLMENT_HARDWARE_DIGEST_MAX 71
#define APD_ENROLLMENT_TRANSCRIPT_MAX 1024
#define APD_ENROLLMENT_CSR_DER_MAX 2048
struct apd_node_identity {
    char ap_id[APD_AP_ID_LEN + 1];
    char key_id[APD_KEY_ID_LEN + 1];
    unsigned char public_key[APD_ED25519_KEY_LEN];
    int64_t created_at;
};
struct apd_enrollment_field {
    const unsigned char *data;
    size_t len;
};
struct apd_enrollment_transcript_v1 {
    struct apd_enrollment_field challenge_id;
    unsigned char server_nonce[32];
    unsigned char client_nonce[32];
    struct apd_enrollment_field enrollment_id;
    struct apd_enrollment_field token_id;
    struct apd_enrollment_field token;
    struct apd_enrollment_field ap_id;
    struct apd_enrollment_field key_id;
    unsigned char public_key[APD_ED25519_KEY_LEN];
    struct apd_enrollment_field site_id;
    struct apd_enrollment_field hardware_digest;
    unsigned char csr_sha256[SHA256_DIGEST_LENGTH];
    uint64_t challenge_expires_at;
};
int64_t apd_now_s(void);
int apd_db_identity_get(struct apd_node_identity *out);
EVP_PKEY *apd_identity_key_open(void);
#else
#include "apd_internal.h"
#include <openssl/x509v3.h>
#endif

#define APD_ENROLLMENT_DOMAIN "dreamingwrt-ap-enrollment-v1"

static int apd_enrollment_ascii(const struct apd_enrollment_field *field,
                                size_t minimum, size_t maximum)
{
    size_t i;

    if (!field || !field->data || field->len < minimum || field->len > maximum)
        return 0;
    for (i = 0; i < field->len; i++)
        if (field->data[i] < 0x21 || field->data[i] > 0x7e)
            return 0;
    return 1;
}

static int apd_enrollment_uuid(const struct apd_enrollment_field *field)
{
    static const size_t hyphens[] = {8, 13, 18, 23};
    size_t i;
    size_t h = 0;

    if (!apd_enrollment_ascii(field, APD_AP_ID_LEN, APD_AP_ID_LEN) ||
        field->data[14] != '4' ||
        (field->data[19] != '8' && field->data[19] != '9' &&
         field->data[19] != 'a' && field->data[19] != 'b'))
        return 0;
    for (i = 0; i < field->len; i++) {
        if (h < sizeof(hyphens) / sizeof(hyphens[0]) && i == hyphens[h]) {
            if (field->data[i] != '-')
                return 0;
            h++;
        } else if (!((field->data[i] >= '0' && field->data[i] <= '9') ||
                     (field->data[i] >= 'a' && field->data[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int apd_enrollment_digest_id(const struct apd_enrollment_field *field,
                                    int allow_empty)
{
    size_t i;

    if (allow_empty && field && field->len == 0)
        return 1;
    if (!apd_enrollment_ascii(field, APD_KEY_ID_LEN, APD_KEY_ID_LEN) ||
        memcmp(field->data, "sha256:", 7) != 0)
        return 0;
    for (i = 7; i < field->len; i++)
        if (!((field->data[i] >= '0' && field->data[i] <= '9') ||
              (field->data[i] >= 'a' && field->data[i] <= 'f')))
            return 0;
    return 1;
}

static int apd_enrollment_token_valid(const struct apd_enrollment_field *field)
{
    size_t i;

    if (!field || !field->data || field->len != APD_ENROLLMENT_TOKEN_LEN)
        return 0;
    for (i = 0; i < field->len; i++)
        if (!((field->data[i] >= 'A' && field->data[i] <= 'Z') ||
              (field->data[i] >= 'a' && field->data[i] <= 'z') ||
              (field->data[i] >= '0' && field->data[i] <= '9') ||
              field->data[i] == '-' || field->data[i] == '_'))
            return 0;
    return 1;
}

static int apd_enrollment_input_valid(
    const struct apd_enrollment_transcript_v1 *input)
{
    if (!input ||
        !apd_enrollment_uuid(&input->challenge_id) ||
        !apd_enrollment_uuid(&input->enrollment_id) ||
        !apd_enrollment_uuid(&input->token_id) ||
        !apd_enrollment_token_valid(&input->token) ||
        !apd_enrollment_uuid(&input->ap_id) ||
        !apd_enrollment_digest_id(&input->key_id, 0) ||
        !apd_enrollment_digest_id(&input->hardware_digest, 1) ||
        input->site_id.len > APD_ENROLLMENT_SITE_ID_MAX ||
        (input->site_id.len > 0 &&
         !apd_enrollment_ascii(&input->site_id, 1, APD_ENROLLMENT_SITE_ID_MAX)) ||
        input->challenge_expires_at == 0)
        return 0;
    return 1;
}

static int apd_enrollment_append(unsigned char *out, size_t out_size,
                                 size_t *offset, const unsigned char *data,
                                 size_t len)
{
    if (!out || !offset || len > UINT16_MAX ||
        (len > 0 && !data) || *offset > out_size ||
        out_size - *offset < len + 2)
        return -1;
    out[(*offset)++] = (unsigned char)(len >> 8);
    out[(*offset)++] = (unsigned char)len;
    if (len > 0) {
        memcpy(out + *offset, data, len);
        *offset += len;
    }
    return 0;
}

int apd_enrollment_transcript_encode_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char *out, size_t out_size, size_t *out_len)
{
    static const unsigned char domain[] = APD_ENROLLMENT_DOMAIN;
    size_t offset = 0;
    int shift;

    if (!out || !out_len)
        return -1;
    *out_len = 0;
    if (!apd_enrollment_input_valid(input) ||
        out_size < sizeof(domain) - 1)
        return -1;
    if (out_size > APD_ENROLLMENT_TRANSCRIPT_MAX)
        out_size = APD_ENROLLMENT_TRANSCRIPT_MAX;
    memcpy(out, domain, sizeof(domain) - 1);
    offset = sizeof(domain) - 1;
#define APD_APPEND_FIELD(data_, len_) do { \
    if (apd_enrollment_append(out, out_size, &offset, (data_), (len_)) != 0) \
        goto fail; \
} while (0)
    APD_APPEND_FIELD(input->challenge_id.data, input->challenge_id.len);
    APD_APPEND_FIELD(input->server_nonce, sizeof(input->server_nonce));
    APD_APPEND_FIELD(input->client_nonce, sizeof(input->client_nonce));
    APD_APPEND_FIELD(input->enrollment_id.data, input->enrollment_id.len);
    APD_APPEND_FIELD(input->token_id.data, input->token_id.len);
    APD_APPEND_FIELD(input->token.data, input->token.len);
    APD_APPEND_FIELD(input->ap_id.data, input->ap_id.len);
    APD_APPEND_FIELD(input->key_id.data, input->key_id.len);
    APD_APPEND_FIELD(input->public_key, sizeof(input->public_key));
    APD_APPEND_FIELD(input->site_id.data, input->site_id.len);
    APD_APPEND_FIELD(input->hardware_digest.data, input->hardware_digest.len);
    APD_APPEND_FIELD(input->csr_sha256, sizeof(input->csr_sha256));
#undef APD_APPEND_FIELD
    if (offset > out_size || out_size - offset < 8)
        goto fail;
    for (shift = 56; shift >= 0; shift -= 8)
        out[offset++] = (unsigned char)(input->challenge_expires_at >> shift);
    *out_len = offset;
    return 0;
fail:
    OPENSSL_cleanse(out, out_size);
    *out_len = 0;
    return -1;
}

static EVP_PKEY *apd_enrollment_identity_key(struct apd_node_identity *identity)
{
    unsigned char derived[APD_ED25519_KEY_LEN] = {0};
    EVP_PKEY *key = NULL;
    size_t derived_len = sizeof(derived);

    if (!identity || apd_db_identity_get(identity) != 0)
        goto done;
    key = apd_identity_key_open();
    if (!key || EVP_PKEY_get_raw_public_key(key, derived, &derived_len) <= 0 ||
        derived_len != sizeof(derived) ||
        CRYPTO_memcmp(derived, identity->public_key, sizeof(derived)) != 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
done:
    OPENSSL_cleanse(derived, sizeof(derived));
    return key;
}

int apd_enrollment_csr_create(unsigned char *csr_der, size_t csr_der_size,
                              size_t *csr_der_len,
                              unsigned char csr_sha256[SHA256_DIGEST_LENGTH])
{
    struct apd_node_identity identity;
    EVP_PKEY *key = NULL;
    X509_REQ *request = NULL;
    X509_NAME *subject = NULL;
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name = NULL;
    X509_EXTENSION *extension = NULL;
    STACK_OF(X509_EXTENSION) *extensions = NULL;
    char uri[sizeof("urn:dreamingwrt:ap:") + APD_AP_ID_LEN] = {0};
    unsigned char *cursor;
    int der_len;
    int rc = -1;

    if (!csr_der || !csr_der_len || !csr_sha256 ||
        csr_der_size == 0 || csr_der_size > APD_ENROLLMENT_CSR_DER_MAX)
        return -1;
    *csr_der_len = 0;
    memset(csr_sha256, 0, SHA256_DIGEST_LENGTH);
    memset(&identity, 0, sizeof(identity));
    key = apd_enrollment_identity_key(&identity);
    request = X509_REQ_new();
    subject = X509_NAME_new();
    names = sk_GENERAL_NAME_new_null();
    name = GENERAL_NAME_new();
    extensions = sk_X509_EXTENSION_new_null();
    if (!key || !request || !subject || !names || !name || !extensions ||
        snprintf(uri, sizeof(uri), "urn:dreamingwrt:ap:%s", identity.ap_id) >=
            (int)sizeof(uri) ||
        X509_REQ_set_version(request, 0L) != 1 ||
        X509_REQ_set_subject_name(request, subject) != 1 ||
        X509_REQ_set_pubkey(request, key) != 1)
        goto done;
    GENERAL_NAME_set0_value(name, GEN_URI,
                            ASN1_IA5STRING_new());
    if (!name->d.uniformResourceIdentifier ||
        ASN1_STRING_set(name->d.uniformResourceIdentifier, uri, -1) != 1)
        goto done;
    if (!sk_GENERAL_NAME_push(names, name))
        goto done;
    name = NULL;
    extension = X509V3_EXT_i2d(NID_subject_alt_name, 0, names);
    if (!extension || !sk_X509_EXTENSION_push(extensions, extension))
        goto done;
    extension = NULL;
    if (X509_REQ_add_extensions(request, extensions) != 1 ||
        X509_REQ_sign(request, key, NULL) <= 0)
        goto done;
    der_len = i2d_X509_REQ(request, NULL);
    if (der_len <= 0 || (size_t)der_len > csr_der_size ||
        der_len > APD_ENROLLMENT_CSR_DER_MAX)
        goto done;
    cursor = csr_der;
    if (i2d_X509_REQ(request, &cursor) != der_len ||
        !SHA256(csr_der, (size_t)der_len, csr_sha256))
        goto done;
    *csr_der_len = (size_t)der_len;
    rc = 0;
done:
    GENERAL_NAME_free(name);
    X509_EXTENSION_free(extension);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    GENERAL_NAMES_free(names);
    X509_NAME_free(subject);
    X509_REQ_free(request);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(uri, sizeof(uri));
    OPENSSL_cleanse(&identity, sizeof(identity));
    if (rc != 0) {
        OPENSSL_cleanse(csr_der, csr_der_size);
        OPENSSL_cleanse(csr_sha256, SHA256_DIGEST_LENGTH);
        *csr_der_len = 0;
    }
    return rc;
}

int apd_enrollment_transcript_sign_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char signature[APD_ED25519_SIGNATURE_LEN])
{
    struct apd_node_identity identity;
    unsigned char transcript[APD_ENROLLMENT_TRANSCRIPT_MAX] = {0};
    EVP_MD_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    size_t transcript_len = 0;
    size_t signature_len = APD_ED25519_SIGNATURE_LEN;
    uint64_t now = (uint64_t)apd_now_s();
    int rc = -1;

    if (!signature)
        return -1;
    memset(signature, 0, APD_ED25519_SIGNATURE_LEN);
    if (!input || !apd_enrollment_input_valid(input) ||
        input->challenge_expires_at <= now ||
        input->challenge_expires_at > now + 600)
        return -1;
    memset(&identity, 0, sizeof(identity));
    key = apd_enrollment_identity_key(&identity);
    if (!key || input->ap_id.len != strlen(identity.ap_id) ||
        CRYPTO_memcmp(input->ap_id.data, identity.ap_id, input->ap_id.len) != 0 ||
        input->key_id.len != strlen(identity.key_id) ||
        CRYPTO_memcmp(input->key_id.data, identity.key_id, input->key_id.len) != 0 ||
        CRYPTO_memcmp(input->public_key, identity.public_key,
                      sizeof(identity.public_key)) != 0 ||
        apd_enrollment_transcript_encode_v1(input, transcript,
                                             sizeof(transcript),
                                             &transcript_len) != 0)
        goto done;
    context = EVP_MD_CTX_new();
    if (!context || EVP_DigestSignInit(context, NULL, NULL, NULL, key) <= 0 ||
        EVP_DigestSign(context, signature, &signature_len,
                       transcript, transcript_len) <= 0 ||
        signature_len != APD_ED25519_SIGNATURE_LEN)
        goto done;
    rc = 0;
done:
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(transcript, sizeof(transcript));
    OPENSSL_cleanse(&identity, sizeof(identity));
    if (rc != 0)
        OPENSSL_cleanse(signature, APD_ED25519_SIGNATURE_LEN);
    return rc;
}
