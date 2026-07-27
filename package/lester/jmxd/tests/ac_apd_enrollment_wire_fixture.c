// SPDX-License-Identifier: GPL-2.0-or-later
#include "ac_enrollment_fixture.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define APD_ED25519_KEY_LEN 32
#define APD_ED25519_SIGNATURE_LEN 64
#define APD_AP_ID_LEN 36
#define APD_KEY_ID_LEN 71

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

int apd_enrollment_transcript_encode_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char *out, size_t out_size, size_t *out_len);
int apd_enrollment_transcript_sign_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char signature[APD_ED25519_SIGNATURE_LEN]);

static const unsigned char fixture_private_key[APD_ED25519_KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

static struct apd_node_identity fixture_identity;

static void hex_encode(char *out, const unsigned char *data, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < length; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    out[length * 2] = '\0';
}

int64_t apd_now_s(void)
{
    return (int64_t)time(NULL);
}

int apd_db_identity_get(struct apd_node_identity *out)
{
    if (!out)
        return -1;
    *out = fixture_identity;
    return 0;
}

EVP_PKEY *apd_identity_key_open(void)
{
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                         fixture_private_key,
                                         sizeof(fixture_private_key));
}

int ac_db_enrollment_claim(const struct ac_enrollment_claim *claim,
                           struct ac_enrollment_record *out)
{
    (void)claim;
    (void)out;
    return AC_ENROLLMENT_ERROR;
}

static int identity_init(void)
{
    EVP_PKEY *key = apd_identity_key_open();
    unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
    size_t public_len = sizeof(fixture_identity.public_key);
    int rc = -1;

    memset(&fixture_identity, 0, sizeof(fixture_identity));
    snprintf(fixture_identity.ap_id, sizeof(fixture_identity.ap_id),
             "44444444-4444-4444-8444-444444444444");
    if (!key ||
        EVP_PKEY_get_raw_public_key(key, fixture_identity.public_key,
                                    &public_len) != 1 ||
        public_len != sizeof(fixture_identity.public_key) ||
        !SHA256(fixture_identity.public_key,
                sizeof(fixture_identity.public_key), digest))
        goto done;
    memcpy(fixture_identity.key_id, "sha256:", 7);
    hex_encode(fixture_identity.key_id + 7, digest, sizeof(digest));
    fixture_identity.created_at = 1;
    rc = 0;
done:
    EVP_PKEY_free(key);
    OPENSSL_cleanse(digest, sizeof(digest));
    return rc;
}

static int signature_valid(const unsigned char *message, size_t message_len,
                           const unsigned char signature[64])
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *context = NULL;
    int valid = 0;

    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                      fixture_identity.public_key,
                                      sizeof(fixture_identity.public_key));
    context = EVP_MD_CTX_new();
    if (key && context &&
        EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestVerify(context, signature, 64,
                         message, message_len) == 1)
        valid = 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return valid;
}

int main(void)
{
    static const unsigned char challenge_id[] =
        "33333333-3333-4333-8333-333333333333";
    static const unsigned char enrollment_id[] =
        "11111111-1111-4111-8111-111111111111";
    static const unsigned char token_id[] =
        "22222222-2222-4222-8222-222222222222";
    static const unsigned char token[] =
        "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";
    struct apd_enrollment_transcript_v1 apd;
    struct ac_enrollment_claim ac;
    unsigned char apd_wire[1024] = {0};
    unsigned char signature[64] = {0};
    unsigned char *ac_wire = NULL;
    size_t apd_wire_len = 0;
    size_t ac_wire_len = 0;
    size_t i;
    int rc = 1;

    if (identity_init() != 0 || sizeof(token) - 1 != AC_PAIRING_TOKEN_LEN)
        goto done;
    memset(&apd, 0, sizeof(apd));
    memset(&ac, 0, sizeof(ac));
    apd.challenge_id = (struct apd_enrollment_field){
        challenge_id, sizeof(challenge_id) - 1};
    apd.enrollment_id = (struct apd_enrollment_field){
        enrollment_id, sizeof(enrollment_id) - 1};
    apd.token_id = (struct apd_enrollment_field){token_id, sizeof(token_id) - 1};
    apd.token = (struct apd_enrollment_field){token, sizeof(token) - 1};
    apd.ap_id = (struct apd_enrollment_field){
        (const unsigned char *)fixture_identity.ap_id,
        strlen(fixture_identity.ap_id)};
    apd.key_id = (struct apd_enrollment_field){
        (const unsigned char *)fixture_identity.key_id,
        strlen(fixture_identity.key_id)};
    apd.site_id = (struct apd_enrollment_field){NULL, 0};
    apd.hardware_digest = (struct apd_enrollment_field){NULL, 0};
    for (i = 0; i < 32; i++) {
        apd.server_nonce[i] = (unsigned char)i;
        apd.client_nonce[i] = (unsigned char)(i + 32);
        apd.csr_sha256[i] = (unsigned char)(0xa0 + i);
    }
    memcpy(apd.public_key, fixture_identity.public_key,
           sizeof(apd.public_key));
    apd.challenge_expires_at = (uint64_t)time(NULL) + 120;

    snprintf(ac.challenge_id, sizeof(ac.challenge_id), "%s", challenge_id);
    memcpy(ac.server_nonce, apd.server_nonce, sizeof(ac.server_nonce));
    memcpy(ac.client_nonce, apd.client_nonce, sizeof(ac.client_nonce));
    snprintf(ac.enrollment_id, sizeof(ac.enrollment_id), "%s", enrollment_id);
    snprintf(ac.token_id, sizeof(ac.token_id), "%s", token_id);
    ac.token = (const char *)token;
    snprintf(ac.ap_id, sizeof(ac.ap_id), "%s", fixture_identity.ap_id);
    snprintf(ac.key_id, sizeof(ac.key_id), "%s", fixture_identity.key_id);
    memcpy(ac.public_key, apd.public_key, sizeof(ac.public_key));
    ac.site_id[0] = '\0';
    ac.hardware_digest[0] = '\0';
    ac.csr_der = (const unsigned char *)"x";
    ac.csr_der_len = 1;
    memcpy(ac.csr_sha256, apd.csr_sha256, sizeof(ac.csr_sha256));
    ac.challenge_expires_at = (int64_t)apd.challenge_expires_at;

    if (apd_enrollment_transcript_encode_v1(&apd, apd_wire,
                                             sizeof(apd_wire),
                                             &apd_wire_len) != 0 ||
        apd_enrollment_transcript_sign_v1(&apd, signature) != 0 ||
        ac_enrollment_transcript_build(&ac, &ac_wire, &ac_wire_len) != 0 ||
        apd_wire_len != ac_wire_len ||
        CRYPTO_memcmp(apd_wire, ac_wire, apd_wire_len) != 0 ||
        !signature_valid(ac_wire, ac_wire_len, signature))
        goto done;
    ac_wire[ac_wire_len - 1] ^= 1;
    if (signature_valid(ac_wire, ac_wire_len, signature))
        goto done;
    printf("ok: APD binary-v1 bytes and signature verify on the AC side\n");
    rc = 0;
done:
    if (ac_wire) {
        OPENSSL_cleanse(ac_wire, ac_wire_len);
        OPENSSL_free(ac_wire);
    }
    OPENSSL_cleanse(apd_wire, sizeof(apd_wire));
    OPENSSL_cleanse(signature, sizeof(signature));
    OPENSSL_cleanse(&apd, sizeof(apd));
    OPENSSL_cleanse(&ac, sizeof(ac));
    OPENSSL_cleanse(&fixture_identity, sizeof(fixture_identity));
    return rc;
}
