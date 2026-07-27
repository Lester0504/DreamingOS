// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_internal.h"

#include <limits.h>

#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define AC_ENROLLMENT_TRANSCRIPT_DOMAIN "dreamingwrt-ap-enrollment-v1"

struct ac_transcript_writer {
    unsigned char *data;
    size_t length;
    size_t capacity;
};

static int ac_transcript_field(struct ac_transcript_writer *writer,
                               const void *data, size_t length)
{
    if (!writer || !data || length > UINT16_MAX ||
        writer->length > writer->capacity ||
        writer->capacity - writer->length < 2 ||
        length > writer->capacity - writer->length - 2)
        return -1;
    writer->data[writer->length++] = (unsigned char)(length >> 8);
    writer->data[writer->length++] = (unsigned char)length;
    memcpy(writer->data + writer->length, data, length);
    writer->length += length;
    return 0;
}

static int ac_enrollment_claim_lengths_valid(
    const struct ac_enrollment_claim *claim)
{
    return claim && claim->token && claim->csr_der &&
        strlen(claim->challenge_id) == AC_ENROLLMENT_ID_LEN &&
        strlen(claim->enrollment_id) == AC_ENROLLMENT_ID_LEN &&
        strlen(claim->token_id) == AC_PAIRING_TOKEN_ID_LEN &&
        strlen(claim->token) == AC_PAIRING_TOKEN_LEN &&
        strlen(claim->ap_id) == AC_ENROLLMENT_ID_LEN &&
        strlen(claim->key_id) == AC_ENROLLMENT_KEY_ID_LEN &&
        strlen(claim->site_id) <= AC_PAIRING_SITE_ID_LEN &&
        strlen(claim->hardware_digest) <= AC_PAIRING_HARDWARE_DIGEST_LEN &&
        claim->csr_der_len > 0 && claim->csr_der_len <= AC_ENROLLMENT_CSR_MAX &&
        claim->challenge_expires_at > 0;
}

int ac_enrollment_transcript_build(
    const struct ac_enrollment_claim *claim,
    unsigned char **out, size_t *out_len)
{
    struct ac_transcript_writer writer;
    unsigned char expires[8];
    static const char domain[] = AC_ENROLLMENT_TRANSCRIPT_DOMAIN;
    size_t capacity;
    size_t i;

    if (!out || !out_len || !ac_enrollment_claim_lengths_valid(claim))
        return -1;
    *out = NULL;
    *out_len = 0;
    capacity = sizeof(domain) - 1 + 12 * 2 +
        strlen(claim->challenge_id) + sizeof(claim->server_nonce) +
        sizeof(claim->client_nonce) + strlen(claim->enrollment_id) +
        strlen(claim->token_id) + strlen(claim->token) +
        strlen(claim->ap_id) + strlen(claim->key_id) +
        sizeof(claim->public_key) + strlen(claim->site_id) +
        strlen(claim->hardware_digest) + sizeof(claim->csr_sha256) +
        sizeof(expires);
    writer.data = OPENSSL_malloc(capacity);
    if (!writer.data)
        return -1;
    writer.length = 0;
    writer.capacity = capacity;
    memcpy(writer.data, domain, sizeof(domain) - 1);
    writer.length = sizeof(domain) - 1;
    for (i = 0; i < sizeof(expires); i++)
        expires[sizeof(expires) - 1 - i] =
            (unsigned char)((uint64_t)claim->challenge_expires_at >> (i * 8));
    if (ac_transcript_field(&writer, claim->challenge_id,
                            strlen(claim->challenge_id)) != 0 ||
        ac_transcript_field(&writer, claim->server_nonce,
                            sizeof(claim->server_nonce)) != 0 ||
        ac_transcript_field(&writer, claim->client_nonce,
                            sizeof(claim->client_nonce)) != 0 ||
        ac_transcript_field(&writer, claim->enrollment_id,
                            strlen(claim->enrollment_id)) != 0 ||
        ac_transcript_field(&writer, claim->token_id,
                            strlen(claim->token_id)) != 0 ||
        ac_transcript_field(&writer, claim->token,
                            strlen(claim->token)) != 0 ||
        ac_transcript_field(&writer, claim->ap_id,
                            strlen(claim->ap_id)) != 0 ||
        ac_transcript_field(&writer, claim->key_id,
                            strlen(claim->key_id)) != 0 ||
        ac_transcript_field(&writer, claim->public_key,
                            sizeof(claim->public_key)) != 0 ||
        ac_transcript_field(&writer, claim->site_id,
                            strlen(claim->site_id)) != 0 ||
        ac_transcript_field(&writer, claim->hardware_digest,
                            strlen(claim->hardware_digest)) != 0 ||
        ac_transcript_field(&writer, claim->csr_sha256,
                            sizeof(claim->csr_sha256)) != 0 ||
        writer.length > writer.capacity ||
        sizeof(expires) > writer.capacity - writer.length) {
        OPENSSL_cleanse(writer.data, writer.capacity);
        OPENSSL_free(writer.data);
        OPENSSL_cleanse(expires, sizeof(expires));
        return -1;
    }
    memcpy(writer.data + writer.length, expires, sizeof(expires));
    writer.length += sizeof(expires);
    *out = writer.data;
    *out_len = writer.length;
    OPENSSL_cleanse(expires, sizeof(expires));
    return 0;
}

static int ac_enrollment_csr_valid(const struct ac_enrollment_claim *claim)
{
    const unsigned char *cursor = claim->csr_der;
    const unsigned char *uri;
    EVP_PKEY *key = NULL;
    X509_REQ *request = NULL;
    STACK_OF(X509_EXTENSION) *extensions = NULL;
    GENERAL_NAMES *names = NULL;
    GENERAL_NAME *name;
    unsigned char raw_public[AC_ENROLLMENT_PUBLIC_KEY_LEN];
    char expected_uri[64 + AC_ENROLLMENT_ID_LEN];
    size_t raw_public_len = sizeof(raw_public);
    int san_extensions = 0;
    int valid = 0;
    int i;

    memset(raw_public, 0, sizeof(raw_public));
    if (claim->csr_der_len > LONG_MAX ||
        !(request = d2i_X509_REQ(NULL, &cursor, (long)claim->csr_der_len)) ||
        cursor != claim->csr_der + claim->csr_der_len ||
        !(key = X509_REQ_get_pubkey(request)) ||
        EVP_PKEY_base_id(key) != EVP_PKEY_ED25519 ||
        X509_REQ_verify(request, key) != 1 ||
        EVP_PKEY_get_raw_public_key(key, raw_public, &raw_public_len) != 1 ||
        raw_public_len != sizeof(raw_public) ||
        CRYPTO_memcmp(raw_public, claim->public_key,
                      sizeof(raw_public)) != 0 ||
        snprintf(expected_uri, sizeof(expected_uri),
                 "urn:dreamingwrt:ap:%s", claim->ap_id) >=
            (int)sizeof(expected_uri) ||
        !(extensions = X509_REQ_get_extensions(request)))
        goto done;
    for (i = 0; i < sk_X509_EXTENSION_num(extensions); i++) {
        X509_EXTENSION *extension = sk_X509_EXTENSION_value(extensions, i);

        if (OBJ_obj2nid(X509_EXTENSION_get_object(extension)) !=
            NID_subject_alt_name)
            continue;
        san_extensions++;
        if (san_extensions > 1 ||
            !(names = X509V3_EXT_d2i(extension)) ||
            sk_GENERAL_NAME_num(names) != 1)
            goto done;
        name = sk_GENERAL_NAME_value(names, 0);
        if (!name || name->type != GEN_URI || !name->d.uniformResourceIdentifier)
            goto done;
        uri = ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
        if (!uri || ASN1_STRING_length(name->d.uniformResourceIdentifier) !=
                        (int)strlen(expected_uri) ||
            CRYPTO_memcmp(uri, expected_uri, strlen(expected_uri)) != 0)
            goto done;
        GENERAL_NAMES_free(names);
        names = NULL;
    }
    valid = san_extensions == 1;
done:
    GENERAL_NAMES_free(names);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    X509_REQ_free(request);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(raw_public, sizeof(raw_public));
    OPENSSL_cleanse(expected_uri, sizeof(expected_uri));
    return valid;
}

static int ac_enrollment_signature_valid(
    const struct ac_enrollment_signed_request *request)
{
    EVP_MD_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *transcript = NULL;
    size_t transcript_len = 0;
    int valid = 0;

    if (ac_enrollment_transcript_build(&request->claim, &transcript,
                                       &transcript_len) != 0)
        return 0;
    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                      request->claim.public_key,
                                      sizeof(request->claim.public_key));
    context = EVP_MD_CTX_new();
    if (key && context && EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(context, request->signature, sizeof(request->signature),
                         transcript, transcript_len) == 1)
        valid = 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(transcript, transcript_len);
    OPENSSL_free(transcript);
    return valid;
}

int ac_enrollment_verify_and_claim(
    const struct ac_enrollment_signed_request *request,
    struct ac_enrollment_record *out)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int result = AC_ENROLLMENT_INVALID;

    memset(digest, 0, sizeof(digest));
    if (!request || !out ||
        !SHA256(request->claim.csr_der, request->claim.csr_der_len, digest) ||
        CRYPTO_memcmp(digest, request->claim.csr_sha256,
                      sizeof(digest)) != 0 ||
        !ac_enrollment_csr_valid(&request->claim) ||
        !ac_enrollment_signature_valid(request))
        goto done;
    result = ac_db_enrollment_claim(&request->claim, out);
done:
    OPENSSL_cleanse(digest, sizeof(digest));
    return result;
}
