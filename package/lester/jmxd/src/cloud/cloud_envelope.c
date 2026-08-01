// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Request/response envelope crypto.
 *
 * Every construction here has to agree with the App byte for byte, so the
 * layout is spelled out rather than abstracted:
 *
 *   traffic key : HKDF-SHA256(X25519(router_priv, eph_pub),
 *                             salt = SHA256(request_id),
 *                             info = CONTEXT || eph_pub || router_pub, 32)
 *   ciphertext  : ChaCha20-Poly1305 "combined" == nonce(12) || ct || tag(16)
 *   transcript  : CONTEXT || router_id || request_id || eph_pub || ciphertext
 *
 * CryptoKit's ChaChaPoly.combined puts the nonce first, which is why the
 * combined layout is split the way it is below.
 */
#include "cloud_internal.h"

#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

/* ── base64 ───────────────────────────────────────────────────────── */

static int cloud_base64_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/*
 * Strict standard-alphabet base64. Written by hand rather than using
 * EVP_DecodeBlock because that helper silently skips invalid characters and
 * cannot report the exact output length when padding is present, and both of
 * those matter for values that feed straight into crypto.
 */
int cloud_base64_decode(const char *text, unsigned char **out, size_t *out_length)
{
    size_t length, i, produced = 0;
    unsigned char *buffer;
    uint32_t accumulator = 0;
    int bits = 0, padding = 0;

    if (!text || !out || !out_length)
        return -1;
    length = strlen(text);
    if (!length || length % 4 || length > CLOUD_FRAME_MAX)
        return -1;

    buffer = malloc(length / 4 * 3 + 1);
    if (!buffer)
        return -1;

    for (i = 0; i < length; i++) {
        char c = text[i];
        int value;

        if (c == '=') {
            /* Padding is only legal in the final quantum. */
            if (i + 2 < length || ++padding > 2)
                goto fail;
            continue;
        }
        if (padding)
            goto fail;
        value = cloud_base64_value(c);
        if (value < 0)
            goto fail;
        accumulator = (accumulator << 6) | (uint32_t)value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buffer[produced++] = (unsigned char)((accumulator >> bits) & 0xff);
        }
    }
    *out = buffer;
    *out_length = produced;
    return 0;
fail:
    free(buffer);
    return -1;
}

int cloud_base64_decode_fixed(const char *text, unsigned char *out, size_t expected)
{
    unsigned char *decoded = NULL;
    size_t length = 0;

    if (cloud_base64_decode(text, &decoded, &length) != 0)
        return -1;
    if (length != expected) {
        OPENSSL_cleanse(decoded, length);
        free(decoded);
        return -1;
    }
    memcpy(out, decoded, expected);
    OPENSSL_cleanse(decoded, length);
    free(decoded);
    return 0;
}

int cloud_base64_encode(const unsigned char *data, size_t length, char **out)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, o = 0, encoded_length;
    char *buffer;

    if (!out || (length && !data))
        return -1;
    encoded_length = (length + 2) / 3 * 4;
    buffer = malloc(encoded_length + 1);
    if (!buffer)
        return -1;

    for (i = 0; i < length; i += 3) {
        uint32_t chunk = (uint32_t)data[i] << 16;
        size_t remaining = length - i;

        if (remaining > 1)
            chunk |= (uint32_t)data[i + 1] << 8;
        if (remaining > 2)
            chunk |= (uint32_t)data[i + 2];
        buffer[o++] = alphabet[(chunk >> 18) & 0x3f];
        buffer[o++] = alphabet[(chunk >> 12) & 0x3f];
        buffer[o++] = remaining > 1 ? alphabet[(chunk >> 6) & 0x3f] : '=';
        buffer[o++] = remaining > 2 ? alphabet[chunk & 0x3f] : '=';
    }
    buffer[o] = '\0';
    *out = buffer;
    return 0;
}

/* ── key agreement and derivation ────────────────────────────────── */

static int cloud_x25519_shared(const unsigned char *private_key,
                               const unsigned char *peer_public,
                               unsigned char *out_shared)
{
    EVP_PKEY *own = NULL, *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t length = CLOUD_X25519_KEY_LEN;
    int rc = -1;

    own = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key,
                                       CLOUD_X25519_KEY_LEN);
    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public,
                                       CLOUD_X25519_KEY_LEN);
    if (!own || !peer)
        goto done;
    ctx = EVP_PKEY_CTX_new(own, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) != 1 ||
        EVP_PKEY_derive_set_peer(ctx, peer) != 1 ||
        EVP_PKEY_derive(ctx, out_shared, &length) != 1 ||
        length != CLOUD_X25519_KEY_LEN)
        goto done;
    rc = 0;
done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(own);
    return rc;
}

static int cloud_hkdf_sha256(const unsigned char *secret, size_t secret_length,
                             const unsigned char *salt, size_t salt_length,
                             const unsigned char *info, size_t info_length,
                             unsigned char *out, size_t out_length)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[5];
    size_t index = 0;
    int rc = -1;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        return -1;
    ctx = EVP_KDF_CTX_new(kdf);
    if (!ctx)
        goto done;

    params[index++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, (void *)secret, secret_length);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, (void *)salt, salt_length);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, (void *)info, info_length);
    params[index] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(ctx, out, out_length, params) == 1)
        rc = 0;
done:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return rc;
}

int cloud_envelope_derive_key(const unsigned char *ephemeral_public,
                              const char *request_id,
                              unsigned char *out_key)
{
    const struct cloud_identity *identity = cloud_identity();
    unsigned char shared[CLOUD_X25519_KEY_LEN];
    unsigned char salt[SHA256_DIGEST_LENGTH];
    unsigned char info[sizeof(CLOUD_E2EE_CONTEXT) - 1 + 2 * CLOUD_X25519_KEY_LEN];
    size_t context_length = sizeof(CLOUD_E2EE_CONTEXT) - 1;
    int rc;

    if (!identity || !ephemeral_public || !request_id || !out_key)
        return -1;
    if (!SHA256((const unsigned char *)request_id, strlen(request_id), salt))
        return -1;
    if (cloud_x25519_shared(identity->private_key, ephemeral_public, shared) != 0)
        return -1;

    memcpy(info, CLOUD_E2EE_CONTEXT, context_length);
    memcpy(info + context_length, ephemeral_public, CLOUD_X25519_KEY_LEN);
    memcpy(info + context_length + CLOUD_X25519_KEY_LEN, identity->public_key,
           CLOUD_X25519_KEY_LEN);

    rc = cloud_hkdf_sha256(shared, sizeof(shared), salt, sizeof(salt),
                           info, sizeof(info), out_key, CLOUD_TRAFFIC_KEY_LEN);
    OPENSSL_cleanse(shared, sizeof(shared));
    return rc;
}

/* ── signature verification ──────────────────────────────────────── */

int cloud_envelope_verify_signature(const char *router_id,
                                    const char *request_id,
                                    const unsigned char *ephemeral_public,
                                    const unsigned char *ciphertext,
                                    size_t ciphertext_length,
                                    const unsigned char *signature,
                                    const unsigned char *signing_key)
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *transcript = NULL;
    size_t context_length = sizeof(CLOUD_E2EE_CONTEXT) - 1;
    size_t router_length, request_length, total, offset = 0;
    int rc = -1;

    if (!router_id || !request_id || !ephemeral_public || !ciphertext ||
        !signature || !signing_key)
        return -1;
    router_length = strlen(router_id);
    request_length = strlen(request_id);
    total = context_length + router_length + request_length +
            CLOUD_X25519_KEY_LEN + ciphertext_length;

    transcript = malloc(total);
    if (!transcript)
        return -1;
    memcpy(transcript + offset, CLOUD_E2EE_CONTEXT, context_length);
    offset += context_length;
    memcpy(transcript + offset, router_id, router_length);
    offset += router_length;
    memcpy(transcript + offset, request_id, request_length);
    offset += request_length;
    memcpy(transcript + offset, ephemeral_public, CLOUD_X25519_KEY_LEN);
    offset += CLOUD_X25519_KEY_LEN;
    memcpy(transcript + offset, ciphertext, ciphertext_length);

    key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, signing_key,
                                      CLOUD_ED25519_KEY_LEN);
    ctx = EVP_MD_CTX_new();
    if (!key || !ctx)
        goto done;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) != 1)
        goto done;
    if (EVP_DigestVerify(ctx, signature, CLOUD_ED25519_SIG_LEN,
                         transcript, total) == 1)
        rc = 0;
done:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    free(transcript);
    return rc;
}

/* ── AEAD ────────────────────────────────────────────────────────── */

int cloud_envelope_open(const unsigned char *key,
                        const unsigned char *ciphertext,
                        size_t ciphertext_length,
                        unsigned char **out, size_t *out_length)
{
    EVP_CIPHER_CTX *ctx = NULL;
    const unsigned char *nonce, *payload, *tag;
    size_t payload_length;
    unsigned char *plaintext = NULL;
    int written = 0, final = 0;
    int rc = -1;

    if (!key || !ciphertext || !out || !out_length)
        return -1;
    /* combined = nonce(12) || ciphertext || tag(16) */
    if (ciphertext_length <= CLOUD_CHACHA_NONCE_LEN + CLOUD_CHACHA_TAG_LEN)
        return -1;

    nonce = ciphertext;
    payload = ciphertext + CLOUD_CHACHA_NONCE_LEN;
    payload_length = ciphertext_length - CLOUD_CHACHA_NONCE_LEN -
                     CLOUD_CHACHA_TAG_LEN;
    tag = ciphertext + CLOUD_CHACHA_NONCE_LEN + payload_length;

    plaintext = malloc(payload_length + 1);
    ctx = EVP_CIPHER_CTX_new();
    if (!plaintext || !ctx)
        goto done;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            CLOUD_CHACHA_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, &written, payload,
                          (int)payload_length) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, CLOUD_CHACHA_TAG_LEN,
                            (void *)tag) != 1)
        goto done;
    /* A failure here is tag rejection: forged or tampered ciphertext. */
    if (EVP_DecryptFinal_ex(ctx, plaintext + written, &final) != 1)
        goto done;

    plaintext[written + final] = '\0';
    *out = plaintext;
    *out_length = (size_t)(written + final);
    plaintext = NULL;
    rc = 0;
done:
    if (plaintext) {
        OPENSSL_cleanse(plaintext, payload_length);
        free(plaintext);
    }
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int cloud_envelope_seal(const unsigned char *key,
                        const unsigned char *plaintext,
                        size_t plaintext_length,
                        unsigned char **out, size_t *out_length)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *combined = NULL;
    unsigned char nonce[CLOUD_CHACHA_NONCE_LEN];
    int written = 0, final = 0;
    int rc = -1;

    if (!key || !plaintext || !out || !out_length)
        return -1;
    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        return -1;

    combined = malloc(CLOUD_CHACHA_NONCE_LEN + plaintext_length +
                      CLOUD_CHACHA_TAG_LEN);
    ctx = EVP_CIPHER_CTX_new();
    if (!combined || !ctx)
        goto done;
    memcpy(combined, nonce, CLOUD_CHACHA_NONCE_LEN);

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            CLOUD_CHACHA_NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, combined + CLOUD_CHACHA_NONCE_LEN, &written,
                          plaintext, (int)plaintext_length) != 1 ||
        EVP_EncryptFinal_ex(ctx, combined + CLOUD_CHACHA_NONCE_LEN + written,
                            &final) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, CLOUD_CHACHA_TAG_LEN,
                            combined + CLOUD_CHACHA_NONCE_LEN + written +
                            final) != 1)
        goto done;

    *out = combined;
    *out_length = CLOUD_CHACHA_NONCE_LEN + (size_t)(written + final) +
                  CLOUD_CHACHA_TAG_LEN;
    combined = NULL;
    rc = 0;
done:
    free(combined);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return rc;
}

/* ── inner payload ───────────────────────────────────────────────── */

void cloud_inner_request_free(struct cloud_inner_request *request)
{
    if (!request)
        return;
    free(request->path);
    if (request->access_token) {
        /* The access token is a bearer credential; do not leave it in freed
         * heap for the next allocation to expose. */
        OPENSSL_cleanse(request->access_token, strlen(request->access_token));
        free(request->access_token);
    }
    if (request->body) {
        OPENSSL_cleanse(request->body, request->body_length);
        free(request->body);
    }
    memset(request, 0, sizeof(*request));
}

static int cloud_json_string_field(struct json_object *object, const char *name,
                                   const char **out)
{
    struct json_object *value = NULL;

    if (!json_object_object_get_ex(object, name, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return -1;
    *out = json_object_get_string(value);
    return 0;
}

int cloud_envelope_parse_inner(const unsigned char *plaintext,
                               size_t plaintext_length,
                               struct cloud_inner_request *out)
{
    struct json_object *root = NULL;
    struct json_object *value = NULL;
    const char *method = NULL, *path = NULL, *request_id = NULL;
    const char *token = NULL, *body = NULL;
    int rc = -1;

    if (!plaintext || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (plaintext_length > CLOUD_FRAME_MAX)
        return -1;

    root = json_tokener_parse((const char *)plaintext);
    if (!root || !json_object_is_type(root, json_type_object))
        goto done;

    if (cloud_json_string_field(root, "method", &method) != 0 ||
        cloud_json_string_field(root, "path", &path) != 0 ||
        cloud_json_string_field(root, "request_id", &request_id) != 0)
        goto done;
    if (strlen(method) >= sizeof(out->method) ||
        strlen(request_id) > CLOUD_REQUEST_ID_MAX)
        goto done;

    if (!json_object_object_get_ex(root, "issued_at", &value) || !value ||
        !json_object_is_type(value, json_type_int))
        goto done;
    out->issued_at = json_object_get_int64(value);

    snprintf(out->method, sizeof(out->method), "%s", method);
    snprintf(out->request_id, sizeof(out->request_id), "%s", request_id);
    out->path = strdup(path);
    if (!out->path)
        goto done;

    /* access_token and body are optional and may legitimately be empty. */
    if (json_object_object_get_ex(root, "access_token", &value)) {
        if (!value || !json_object_is_type(value, json_type_string))
            goto done;
        token = json_object_get_string(value);
        if (token && token[0]) {
            out->access_token = strdup(token);
            if (!out->access_token)
                goto done;
        }
    }
    if (json_object_object_get_ex(root, "body", &value)) {
        if (!value || !json_object_is_type(value, json_type_string))
            goto done;
        body = json_object_get_string(value);
        if (body && body[0] &&
            cloud_base64_decode(body, &out->body, &out->body_length) != 0)
            goto done;
    }
    rc = 0;
done:
    if (root)
        json_object_put(root);
    if (rc != 0)
        cloud_inner_request_free(out);
    return rc;
}

int cloud_envelope_build_response(int status, const char *request_id,
                                  const unsigned char *body,
                                  size_t body_length,
                                  unsigned char **out, size_t *out_length)
{
    struct json_object *root;
    char *encoded = NULL;
    const char *text;
    size_t text_length;
    unsigned char *copy;

    if (!request_id || !out || !out_length)
        return -1;
    if (cloud_base64_encode(body, body_length, &encoded) != 0)
        return -1;

    root = json_object_new_object();
    if (!root) {
        free(encoded);
        return -1;
    }
    json_object_object_add(root, "status", json_object_new_int(status));
    /* The App drops any response whose inner request_id does not match, which
     * is what makes a replayed response detectable. */
    json_object_object_add(root, "request_id", json_object_new_string(request_id));
    json_object_object_add(root, "body", json_object_new_string(encoded));

    text = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    if (!text) {
        json_object_put(root);
        free(encoded);
        return -1;
    }
    text_length = strlen(text);
    copy = malloc(text_length);
    if (!copy) {
        json_object_put(root);
        free(encoded);
        return -1;
    }
    memcpy(copy, text, text_length);
    json_object_put(root);
    free(encoded);

    *out = copy;
    *out_length = text_length;
    return 0;
}
