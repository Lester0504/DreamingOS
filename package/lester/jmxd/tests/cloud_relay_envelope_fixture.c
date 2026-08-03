// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Cross-language known-answer test for the relay end-to-end encryption chain.
 *
 * The iOS App seals requests with CryptoKit and the router opens them with
 * OpenSSL. A bug in either direction shows up as "remote access silently does
 * not work", which is expensive to debug on live hardware, so the byte-exact
 * contract is pinned here instead.
 *
 * Vectors in cloud_relay_kat_vectors.h come from a from-scratch RFC
 * implementation (tests/cloud_relay_kat_reference.py) that self-checks against
 * the published RFC 7748 / 5869 / 8439 / 8032 vectors. Verifying OpenSSL
 * against OpenSSL would prove nothing; this proves the router agrees with an
 * independent reading of the same spec the App implements.
 *
 * cloud_identity() is provided here rather than linked from cloud_identity.c so
 * the fixture can pin the router keypair without touching /etc or generating a
 * random key at run time.
 */
#include "cloud_internal.h"
#include "cloud_relay_kat_vectors.h"

#include <assert.h>
#include <stdio.h>

static struct cloud_identity kat_identity;

const struct cloud_identity *cloud_identity(void)
{
    return &kat_identity;
}

static void identity_init(void)
{
    memcpy(kat_identity.private_key, kat_router_private,
           sizeof(kat_identity.private_key));
    memcpy(kat_identity.public_key, kat_router_public,
           sizeof(kat_identity.public_key));
    snprintf(kat_identity.router_id, sizeof(kat_identity.router_id), "%s",
             KAT_ROUTER_ID);
}

/* The derived traffic key must match the reference byte for byte; anything else
 * means the HKDF salt or info layout drifted from what the App builds. */
static void test_key_derivation(unsigned char *traffic_key)
{
    unsigned char other[CLOUD_TRAFFIC_KEY_LEN];

    assert(cloud_envelope_derive_key(kat_ephemeral_public, KAT_REQUEST_ID,
                                     traffic_key) == 0);
    assert(memcmp(traffic_key, kat_traffic_key, CLOUD_TRAFFIC_KEY_LEN) == 0);

    /* A different request_id changes the salt, so the key must change too.
     * Without this the replay guard would be the only thing standing between a
     * captured frame and a successful replay. */
    assert(cloud_envelope_derive_key(kat_ephemeral_public,
                                     "00000000-0000-4000-8000-000000000000",
                                     other) == 0);
    assert(memcmp(other, kat_traffic_key, CLOUD_TRAFFIC_KEY_LEN) != 0);

    assert(cloud_envelope_derive_key(NULL, KAT_REQUEST_ID, other) == -1);
    assert(cloud_envelope_derive_key(kat_ephemeral_public, NULL, other) == -1);
    assert(cloud_envelope_derive_key(kat_ephemeral_public, KAT_REQUEST_ID,
                                     NULL) == -1);
}

static void test_signature(void)
{
    unsigned char tampered[sizeof(kat_signature)];
    unsigned char wrong_key[sizeof(kat_signing_public)];

    assert(cloud_envelope_verify_signature(
               KAT_ROUTER_ID, KAT_REQUEST_ID, kat_ephemeral_public,
               kat_ciphertext, sizeof(kat_ciphertext), kat_signature,
               kat_signing_public) == 0);

    /* Each transcript field is covered: flipping any of them has to break the
     * signature, otherwise a relay could redirect a signed request. */
    assert(cloud_envelope_verify_signature(
               "DR-KAT-0002", KAT_REQUEST_ID, kat_ephemeral_public,
               kat_ciphertext, sizeof(kat_ciphertext), kat_signature,
               kat_signing_public) != 0);
    assert(cloud_envelope_verify_signature(
               KAT_ROUTER_ID, "00000000-0000-4000-8000-000000000000",
               kat_ephemeral_public, kat_ciphertext, sizeof(kat_ciphertext),
               kat_signature, kat_signing_public) != 0);
    assert(cloud_envelope_verify_signature(
               KAT_ROUTER_ID, KAT_REQUEST_ID, kat_router_public,
               kat_ciphertext, sizeof(kat_ciphertext), kat_signature,
               kat_signing_public) != 0);
    assert(cloud_envelope_verify_signature(
               KAT_ROUTER_ID, KAT_REQUEST_ID, kat_ephemeral_public,
               kat_ciphertext, sizeof(kat_ciphertext) - 1, kat_signature,
               kat_signing_public) != 0);

    memcpy(tampered, kat_signature, sizeof(tampered));
    tampered[0] ^= 0x01;
    assert(cloud_envelope_verify_signature(
               KAT_ROUTER_ID, KAT_REQUEST_ID, kat_ephemeral_public,
               kat_ciphertext, sizeof(kat_ciphertext), tampered,
               kat_signing_public) != 0);

    /* An unregistered signing key must be rejected: this is what stops a
     * stranger who knows a router_id from driving the router. */
    memcpy(wrong_key, kat_signing_public, sizeof(wrong_key));
    wrong_key[0] ^= 0x01;
    assert(cloud_envelope_verify_signature(
               KAT_ROUTER_ID, KAT_REQUEST_ID, kat_ephemeral_public,
               kat_ciphertext, sizeof(kat_ciphertext), kat_signature,
               wrong_key) != 0);

    assert(cloud_envelope_verify_signature(
               NULL, KAT_REQUEST_ID, kat_ephemeral_public, kat_ciphertext,
               sizeof(kat_ciphertext), kat_signature, kat_signing_public) != 0);
}

static void test_open_and_parse(const unsigned char *traffic_key)
{
    struct cloud_inner_request request;
    unsigned char *plaintext = NULL;
    unsigned char *tampered = NULL;
    unsigned char wrong_key[CLOUD_TRAFFIC_KEY_LEN];
    size_t plaintext_length = 0;

    assert(cloud_envelope_open(traffic_key, kat_ciphertext,
                               sizeof(kat_ciphertext), &plaintext,
                               &plaintext_length) == 0);
    assert(plaintext_length == sizeof(kat_inner_plaintext));
    assert(memcmp(plaintext, kat_inner_plaintext, plaintext_length) == 0);

    assert(cloud_envelope_parse_inner(plaintext, plaintext_length,
                                      &request) == 0);
    assert(strcmp(request.method, "GET") == 0);
    assert(strcmp(request.path, "/api/v1/status") == 0);
    assert(strcmp(request.request_id, KAT_REQUEST_ID) == 0);
    assert(request.issued_at == 1767225600);
    assert(request.access_token && strcmp(request.access_token,
                                         "kat-access-token") == 0);
    assert(request.body_length == 0);
    cloud_inner_request_free(&request);

    /* Tag rejection: a single flipped ciphertext byte must fail to open rather
     * than yield garbage plaintext that later code tries to interpret. */
    tampered = malloc(sizeof(kat_ciphertext));
    assert(tampered != NULL);
    memcpy(tampered, kat_ciphertext, sizeof(kat_ciphertext));
    tampered[CLOUD_CHACHA_NONCE_LEN] ^= 0x01;
    {
        unsigned char *out = NULL;
        size_t out_length = 0;

        assert(cloud_envelope_open(traffic_key, tampered,
                                   sizeof(kat_ciphertext), &out,
                                   &out_length) != 0);
        assert(out == NULL || out_length == 0);
    }
    free(tampered);

    memcpy(wrong_key, traffic_key, sizeof(wrong_key));
    wrong_key[0] ^= 0x01;
    {
        unsigned char *out = NULL;
        size_t out_length = 0;

        assert(cloud_envelope_open(wrong_key, kat_ciphertext,
                                   sizeof(kat_ciphertext), &out,
                                   &out_length) != 0);
    }

    /* A frame too short to hold nonce plus tag must be refused before any
     * pointer arithmetic runs off the end of the buffer. */
    {
        unsigned char *out = NULL;
        size_t out_length = 0;

        assert(cloud_envelope_open(traffic_key, kat_ciphertext,
                                   CLOUD_CHACHA_NONCE_LEN +
                                       CLOUD_CHACHA_TAG_LEN,
                                   &out, &out_length) != 0);
    }

    free(plaintext);
}

static void test_inner_rejects_malformed(void)
{
    static const char *const bad[] = {
        "{}",
        "[]",
        "not json",
        /* missing request_id */
        "{\"method\":\"GET\",\"path\":\"/x\",\"issued_at\":1}",
        /* missing issued_at */
        "{\"method\":\"GET\",\"path\":\"/x\",\"request_id\":\"a\"}",
        /* issued_at must be an integer, not a string */
        "{\"method\":\"GET\",\"path\":\"/x\",\"request_id\":\"a\","
        "\"issued_at\":\"1\"}",
        /* wrong types for the string fields */
        "{\"method\":1,\"path\":\"/x\",\"request_id\":\"a\",\"issued_at\":1}",
        /* access_token present but not a string */
        "{\"method\":\"GET\",\"path\":\"/x\",\"request_id\":\"a\","
        "\"issued_at\":1,\"access_token\":5}",
        /* body present but not valid base64 */
        "{\"method\":\"GET\",\"path\":\"/x\",\"request_id\":\"a\","
        "\"issued_at\":1,\"body\":\"!!!\"}",
    };
    struct cloud_inner_request request;
    char oversized[512];
    unsigned int i;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        assert(cloud_envelope_parse_inner((const unsigned char *)bad[i],
                                          strlen(bad[i]), &request) != 0);
    }

    /* An over-long method would otherwise be truncated into the fixed buffer
     * and silently change which verb the local replay uses. */
    snprintf(oversized, sizeof(oversized),
             "{\"method\":\"%s\",\"path\":\"/x\",\"request_id\":\"a\","
             "\"issued_at\":1}",
             "GETGETGETGETGETGETGETGETGETGETGET");
    assert(cloud_envelope_parse_inner((const unsigned char *)oversized,
                                      strlen(oversized), &request) != 0);

    assert(cloud_envelope_parse_inner(NULL, 0, &request) != 0);
}

/*
 * The response has to be sealed with the same traffic key and echo the request
 * id, because the App treats a mismatched id as a replay and drops the reply.
 */
static void test_response_round_trip(const unsigned char *traffic_key)
{
    unsigned char *sealed = NULL;
    unsigned char *reopened = NULL;
    unsigned char *response = NULL;
    size_t sealed_length = 0, reopened_length = 0, response_length = 0;
    struct json_object *root, *value = NULL;

    assert(cloud_envelope_build_response(200, KAT_REQUEST_ID, NULL, 0,
                                         &response, &response_length) == 0);
    root = json_tokener_parse((const char *)response);
    assert(root && json_object_is_type(root, json_type_object));
    assert(json_object_object_get_ex(root, "status", &value) &&
           json_object_get_int(value) == 200);
    assert(json_object_object_get_ex(root, "request_id", &value) &&
           strcmp(json_object_get_string(value), KAT_REQUEST_ID) == 0);
    assert(json_object_object_get_ex(root, "body", &value));
    json_object_put(root);

    /* Seal/open is a round trip rather than a fixed vector because the nonce is
     * random by design; the reference vector covers the byte layout. */
    assert(cloud_envelope_seal(traffic_key, response, response_length, &sealed,
                              &sealed_length) == 0);
    assert(sealed_length == response_length + CLOUD_CHACHA_NONCE_LEN +
                                CLOUD_CHACHA_TAG_LEN);
    assert(cloud_envelope_open(traffic_key, sealed, sealed_length, &reopened,
                               &reopened_length) == 0);
    assert(reopened_length == response_length);
    assert(memcmp(reopened, response, response_length) == 0);

    free(reopened);
    free(sealed);
    free(response);
}

/*
 * The reference implementation also sealed a response with a fixed nonce, so
 * the router's opener is checked against a response it did not produce itself.
 */
static void test_reference_response(const unsigned char *traffic_key)
{
    unsigned char *plaintext = NULL;
    size_t plaintext_length = 0;

    assert(cloud_envelope_open(traffic_key, kat_response_ciphertext,
                               sizeof(kat_response_ciphertext), &plaintext,
                               &plaintext_length) == 0);
    assert(plaintext_length == sizeof(kat_response_plaintext));
    assert(memcmp(plaintext, kat_response_plaintext, plaintext_length) == 0);
    free(plaintext);
}

static void test_replay_guard(void)
{
    int64_t now = 1767225600;

    cloud_replay_reset();
    assert(cloud_replay_seen(KAT_REQUEST_ID, now) == 0);
    /* Same id inside the window is a replay. */
    assert(cloud_replay_seen(KAT_REQUEST_ID, now) != 0);
    assert(cloud_replay_seen(KAT_REQUEST_ID, now + 1) != 0);
    /* A different id in the same second is fine. */
    assert(cloud_replay_seen("00000000-0000-4000-8000-000000000000", now) == 0);
    cloud_replay_reset();
}

static void test_base64_helpers(void)
{
    unsigned char fixed[CLOUD_X25519_KEY_LEN];
    unsigned char *decoded = NULL;
    size_t decoded_length = 0;
    char *encoded = NULL;

    assert(cloud_base64_encode(kat_router_public, sizeof(kat_router_public),
                               &encoded) == 0);
    assert(cloud_base64_decode_fixed(encoded, fixed, sizeof(fixed)) == 0);
    assert(memcmp(fixed, kat_router_public, sizeof(fixed)) == 0);
    /* A key of the wrong length must not be accepted as a 32-byte key. */
    assert(cloud_base64_decode_fixed(encoded, fixed, sizeof(fixed) - 1) != 0);
    assert(cloud_base64_decode(encoded, &decoded, &decoded_length) == 0);
    assert(decoded_length == sizeof(kat_router_public));
    free(decoded);
    free(encoded);

    assert(cloud_base64_decode_fixed("!!!!", fixed, sizeof(fixed)) != 0);
    assert(cloud_base64_decode_fixed("", fixed, sizeof(fixed)) != 0);
    assert(cloud_base64_decode_fixed(NULL, fixed, sizeof(fixed)) != 0);
}

/*
 * The authorized_apps declaration crosses into Go, which decodes with
 * base64.StdEncoding: standard alphabet, padding required. A variant mismatch
 * would make the relay silently skip every key and refuse all presence queries,
 * so the exact expected strings are pinned here.
 */
static void test_base64_matches_go_stdencoding(void)
{
    /* Lengths 1..3 cover both padding cases plus the unpadded one. */
    static const struct {
        unsigned char raw[3];
        size_t length;
        const char *expected;
    } cases[] = {
        {{0xff, 0x00, 0x00}, 1, "/w=="},
        {{0xfb, 0xf0, 0x00}, 2, "+/A="},
        {{0xfb, 0xff, 0xbf}, 3, "+/+/"},
    };
    char *encoded = NULL;
    unsigned int i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        assert(cloud_base64_encode(cases[i].raw, cases[i].length,
                                   &encoded) == 0);
        assert(!strcmp(encoded, cases[i].expected));
        free(encoded);
        encoded = NULL;
    }

    /* A 32-byte key encodes to 44 characters ending in one '=', which is the
     * shape the relay's length check expects for an Ed25519 key. */
    assert(cloud_base64_encode(kat_signing_public,
                               sizeof(kat_signing_public), &encoded) == 0);
    assert(strlen(encoded) == 44 && encoded[43] == '=');
    free(encoded);
}

/*
 * The App database path has to be the one webd actually writes.
 *
 * This is not a hypothetical: the first version of this daemon pointed at
 * /etc/dreamingwrt/app_api.db while webd uses apid.db, so every signing-key
 * lookup would have found no rows and refused all remote access with
 * app_not_authorized. Nothing else in the build would have complained.
 */
static void test_app_db_path_matches_webd(void)
{
    assert(!strcmp(CLOUD_APP_DB_PATH, "/etc/dreamingwrt/apid.db"));
    /* Local replay must target webd's listener, not some other component. */
    assert(CLOUD_LOCAL_PORT == 12517);
    assert(!strcmp(CLOUD_LOCAL_HOST, "127.0.0.1"));
}

int main(void)
{
    unsigned char traffic_key[CLOUD_TRAFFIC_KEY_LEN];

    identity_init();
    test_key_derivation(traffic_key);
    test_signature();
    test_open_and_parse(traffic_key);
    test_inner_rejects_malformed();
    test_response_round_trip(traffic_key);
    test_reference_response(traffic_key);
    test_replay_guard();
    test_base64_helpers();
    test_base64_matches_go_stdencoding();
    test_app_db_path_matches_webd();
    OPENSSL_cleanse(traffic_key, sizeof(traffic_key));
    puts("ok: relay envelope KAT matches the independent RFC reference, "
         "signature/tag/replay rejection holds");
    return 0;
}
