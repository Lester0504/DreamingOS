// SPDX-License-Identifier: GPL-2.0-or-later
/* BLE bootstrap crypto and authenticated fragment framing. */
#include "apd_ble.h"

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define APD_BLE_FRAME_MAGIC "DWBL"
#define APD_BLE_FRAME_VERSION 1U

static void put_u16(unsigned char *p, uint16_t value)
{
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}

static void put_u64(unsigned char *p, uint64_t value)
{
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = (unsigned char)value;
        value >>= 8;
    }
}

static uint16_t get_u16(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint64_t get_u64(const unsigned char *p)
{
    uint64_t value = 0;
    int i;

    for (i = 0; i < 8; i++)
        value = (value << 8) | p[i];
    return value;
}

static int x25519_shared(const unsigned char private_key[APD_BLE_X25519_KEY_LEN],
                         const unsigned char peer_public[APD_BLE_X25519_KEY_LEN],
                         unsigned char shared[APD_BLE_X25519_KEY_LEN])
{
    EVP_PKEY *own = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *context = NULL;
    size_t length = APD_BLE_X25519_KEY_LEN;
    int rc = -1;

    own = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key,
                                       APD_BLE_X25519_KEY_LEN);
    peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_public,
                                       APD_BLE_X25519_KEY_LEN);
    if (!own || !peer)
        goto done;
    context = EVP_PKEY_CTX_new(own, NULL);
    if (!context || EVP_PKEY_derive_init(context) != 1 ||
        EVP_PKEY_derive_set_peer(context, peer) != 1 ||
        EVP_PKEY_derive(context, shared, &length) != 1 ||
        length != APD_BLE_X25519_KEY_LEN)
        goto done;
    rc = 0;
done:
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(own);
    return rc;
}

int apd_ble_x25519_keypair(unsigned char private_key[APD_BLE_X25519_KEY_LEN],
                           unsigned char public_key[APD_BLE_X25519_KEY_LEN])
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    size_t private_len = APD_BLE_X25519_KEY_LEN;
    size_t public_len = APD_BLE_X25519_KEY_LEN;
    int rc = -1;

    if (!private_key || !public_key)
        return APD_BLE_ERR_ARGUMENT;
    context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!context || EVP_PKEY_keygen_init(context) != 1 ||
        EVP_PKEY_keygen(context, &key) != 1 ||
        EVP_PKEY_get_raw_private_key(key, private_key, &private_len) != 1 ||
        EVP_PKEY_get_raw_public_key(key, public_key, &public_len) != 1 ||
        private_len != APD_BLE_X25519_KEY_LEN ||
        public_len != APD_BLE_X25519_KEY_LEN)
        goto done;
    rc = APD_BLE_OK;
done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    if (rc != APD_BLE_OK) {
        OPENSSL_cleanse(private_key, APD_BLE_X25519_KEY_LEN);
        OPENSSL_cleanse(public_key, APD_BLE_X25519_KEY_LEN);
    }
    return rc;
}

static int hkdf_sha256(const unsigned char *secret, size_t secret_len,
                       const unsigned char *salt, size_t salt_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *out, size_t out_len)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *context = NULL;
    OSSL_PARAM params[5];
    size_t index = 0;
    int rc = -1;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        return -1;
    context = EVP_KDF_CTX_new(kdf);
    if (!context)
        goto done;
    params[index++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, (void *)secret, secret_len);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    params[index++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    params[index] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(context, out, out_len, params) == 1)
        rc = 0;
done:
    EVP_KDF_CTX_free(context);
    EVP_KDF_free(kdf);
    return rc;
}

int apd_ble_derive_key(const unsigned char private_key[APD_BLE_X25519_KEY_LEN],
                       const unsigned char peer_public[APD_BLE_X25519_KEY_LEN],
                       const char *bootstrap_id,
                       const unsigned char bootstrap_nonce[APD_BLE_BOOTSTRAP_NONCE_LEN],
                       unsigned char out_key[APD_BLE_KEY_LEN])
{
    static const unsigned char domain[] = "dreamingwrt-ble-bootstrap-v1";
    unsigned char own_public[APD_BLE_X25519_KEY_LEN];
    unsigned char shared[APD_BLE_X25519_KEY_LEN];
    unsigned char salt_input[sizeof(domain) - 1 + 64 + APD_BLE_BOOTSTRAP_NONCE_LEN +
                             APD_BLE_X25519_KEY_LEN * 2];
    unsigned char salt[SHA256_DIGEST_LENGTH];
    unsigned char info[sizeof(domain) - 1 + 4 + 64];
    size_t bootstrap_len;
    size_t salt_len;
    size_t info_len;
    int rc = APD_BLE_ERR_CRYPTO;

    if (!private_key || !peer_public || !bootstrap_id ||
        !bootstrap_nonce || !out_key)
        return APD_BLE_ERR_ARGUMENT;
    bootstrap_len = strlen(bootstrap_id);
    if (bootstrap_len == 0 || bootstrap_len > 64)
        return APD_BLE_ERR_ARGUMENT;
    if (x25519_shared(private_key, peer_public, shared) != 0)
        goto done;
    {
        EVP_PKEY *own = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                      private_key,
                                                      APD_BLE_X25519_KEY_LEN);
        size_t own_len = sizeof(own_public);
        if (!own || EVP_PKEY_get_raw_public_key(own, own_public, &own_len) != 1 ||
            own_len != sizeof(own_public)) {
            EVP_PKEY_free(own);
            goto done;
        }
        EVP_PKEY_free(own);
    }
    /* Sort the public keys so both peers derive the same transcript while
     * retaining both ephemeral keys in the binding. */
    const unsigned char *first = own_public;
    const unsigned char *second = peer_public;
    if (memcmp(first, second, APD_BLE_X25519_KEY_LEN) > 0) {
        first = peer_public;
        second = own_public;
    }
    memcpy(salt_input, domain, sizeof(domain) - 1);
    salt_len = sizeof(domain) - 1;
    memcpy(salt_input + salt_len, bootstrap_id, bootstrap_len);
    salt_len += bootstrap_len;
    memcpy(salt_input + salt_len, bootstrap_nonce, APD_BLE_BOOTSTRAP_NONCE_LEN);
    salt_len += APD_BLE_BOOTSTRAP_NONCE_LEN;
    memcpy(salt_input + salt_len, first, APD_BLE_X25519_KEY_LEN);
    salt_len += APD_BLE_X25519_KEY_LEN;
    memcpy(salt_input + salt_len, second, APD_BLE_X25519_KEY_LEN);
    salt_len += APD_BLE_X25519_KEY_LEN;
    if (!SHA256(salt_input, salt_len, salt))
        goto done;
    memcpy(info, domain, sizeof(domain) - 1);
    info_len = sizeof(domain) - 1;
    info[info_len++] = 0;
    info[info_len++] = 0;
    info[info_len++] = 0;
    info[info_len++] = APD_BLE_PROTOCOL_VERSION;
    memcpy(info + info_len, bootstrap_id, bootstrap_len);
    info_len += bootstrap_len;
    if (hkdf_sha256(shared, sizeof(shared), salt, sizeof(salt), info, info_len,
                    out_key, APD_BLE_KEY_LEN) != 0)
        goto done;
    rc = APD_BLE_OK;
done:
    OPENSSL_cleanse(own_public, sizeof(own_public));
    OPENSSL_cleanse(shared, sizeof(shared));
    OPENSSL_cleanse(salt_input, sizeof(salt_input));
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(info, sizeof(info));
    if (rc != APD_BLE_OK)
        OPENSSL_cleanse(out_key, APD_BLE_KEY_LEN);
    return rc;
}

int apd_ble_uuid_parse(const char *text,
                       unsigned char out[APD_BLE_REQUEST_ID_LEN])
{
    size_t i;
    size_t written = 0;
    int high = -1;

    if (!text || !out)
        return APD_BLE_ERR_ARGUMENT;
    if (strlen(text) != 36 || text[8] != '-' || text[13] != '-' ||
        text[18] != '-' || text[23] != '-')
        return APD_BLE_ERR_ARGUMENT;
    for (i = 0; text[i]; i++) {
        int value;
        char c = text[i];

        if (c == '-')
            continue;
        if (c >= '0' && c <= '9')
            value = c - '0';
        else if (c >= 'a' && c <= 'f')
            value = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            value = c - 'A' + 10;
        else
            return APD_BLE_ERR_ARGUMENT;
        if (high < 0)
            high = value;
        else {
            if (written >= APD_BLE_REQUEST_ID_LEN)
                return APD_BLE_ERR_ARGUMENT;
            out[written++] = (unsigned char)((high << 4) | value);
            high = -1;
        }
    }
    return written == APD_BLE_REQUEST_ID_LEN && high < 0 ?
           APD_BLE_OK : APD_BLE_ERR_ARGUMENT;
}

void apd_ble_hex(const unsigned char *data, size_t len, char *out,
                 size_t out_size)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if (!out || out_size < len * 2 + 1)
        return;
    for (i = 0; i < len; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

int apd_ble_hex_decode(const char *text, unsigned char *out, size_t out_size,
                       size_t *written)
{
    size_t len;
    size_t i;

    if (!text || !out || !written)
        return APD_BLE_ERR_ARGUMENT;
    len = strlen(text);
    if ((len & 1U) || len / 2 > out_size)
        return APD_BLE_ERR_ARGUMENT;
    for (i = 0; i < len / 2; i++) {
        int high, low;
        char a = text[i * 2];
        char b = text[i * 2 + 1];
        high = a >= '0' && a <= '9' ? a - '0' :
               a >= 'a' && a <= 'f' ? a - 'a' + 10 :
               a >= 'A' && a <= 'F' ? a - 'A' + 10 : -1;
        low = b >= '0' && b <= '9' ? b - '0' :
              b >= 'a' && b <= 'f' ? b - 'a' + 10 :
              b >= 'A' && b <= 'F' ? b - 'A' + 10 : -1;
        if (high < 0 || low < 0)
            return APD_BLE_ERR_ARGUMENT;
        out[i] = (unsigned char)((high << 4) | low);
    }
    *written = len / 2;
    return APD_BLE_OK;
}

size_t apd_ble_fragment_count(size_t plaintext_len)
{
    if (!plaintext_len || plaintext_len > APD_BLE_MAX_REQUEST)
        return 0;
    return (plaintext_len + APD_BLE_MAX_FRAGMENT_PLAINTEXT - 1U) /
           APD_BLE_MAX_FRAGMENT_PLAINTEXT;
}

static int aead_crypt(int decrypt, const unsigned char key[APD_BLE_KEY_LEN],
                      const unsigned char nonce[APD_BLE_NONCE_LEN],
                      const unsigned char *aad, size_t aad_len,
                      const unsigned char *input, size_t input_len,
                      const unsigned char *tag, unsigned char *output,
                      unsigned char output_tag[APD_BLE_TAG_LEN])
{
    EVP_CIPHER_CTX *context = NULL;
    int written = 0;
    int final = 0;
    int rc = -1;

    context = EVP_CIPHER_CTX_new();
    if (!context)
        return -1;
    if (decrypt) {
        if (EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), NULL, NULL,
                               NULL) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
                                APD_BLE_NONCE_LEN, NULL) != 1 ||
            EVP_DecryptInit_ex(context, NULL, NULL, key, nonce) != 1 ||
            EVP_DecryptUpdate(context, NULL, &written, aad, (int)aad_len) != 1 ||
            EVP_DecryptUpdate(context, output, &written, input, (int)input_len) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG,
                                APD_BLE_TAG_LEN, (void *)tag) != 1 ||
            EVP_DecryptFinal_ex(context, output + written, &final) != 1)
            goto done;
    } else {
        if (EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), NULL, NULL,
                               NULL) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN,
                                APD_BLE_NONCE_LEN, NULL) != 1 ||
            EVP_EncryptInit_ex(context, NULL, NULL, key, nonce) != 1 ||
            EVP_EncryptUpdate(context, NULL, &written, aad, (int)aad_len) != 1 ||
            EVP_EncryptUpdate(context, output, &written, input, (int)input_len) != 1 ||
            EVP_EncryptFinal_ex(context, output + written, &final) != 1 ||
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG,
                                APD_BLE_TAG_LEN, output_tag) != 1)
            goto done;
    }
    rc = written + final;
done:
    EVP_CIPHER_CTX_free(context);
    return rc;
}

int apd_ble_seal_fragment(const unsigned char key[APD_BLE_KEY_LEN],
                          const unsigned char session_id[APD_BLE_SESSION_ID_LEN],
                          const unsigned char request_id[APD_BLE_REQUEST_ID_LEN],
                          uint64_t sequence, uint8_t direction,
                          uint16_t fragment_index, uint16_t fragment_count,
                          const unsigned char *plaintext, size_t plaintext_len,
                          unsigned char *out, size_t out_size, size_t *out_len)
{
    unsigned char *ciphertext;
    unsigned char *tag;
    size_t total;
    int encrypted;

    if (!key || !session_id || !request_id || !plaintext || !out || !out_len ||
        direction > 1 || !fragment_count || fragment_index >= fragment_count ||
        plaintext_len > APD_BLE_MAX_FRAGMENT_PLAINTEXT ||
        out_size < APD_BLE_FRAME_HEADER_LEN + plaintext_len + APD_BLE_TAG_LEN)
        return APD_BLE_ERR_ARGUMENT;
    total = APD_BLE_FRAME_HEADER_LEN + plaintext_len + APD_BLE_TAG_LEN;
    memset(out, 0, APD_BLE_FRAME_HEADER_LEN);
    memcpy(out, APD_BLE_FRAME_MAGIC, 4);
    out[4] = APD_BLE_FRAME_VERSION;
    out[5] = direction;
    out[6] = 0;
    memcpy(out + 8, session_id, APD_BLE_SESSION_ID_LEN);
    memcpy(out + 24, request_id, APD_BLE_REQUEST_ID_LEN);
    put_u64(out + 40, sequence);
    put_u16(out + 48, fragment_index);
    put_u16(out + 50, fragment_count);
    put_u16(out + 52, (uint16_t)plaintext_len);
    if (RAND_bytes(out + 54, APD_BLE_NONCE_LEN) != 1)
        return APD_BLE_ERR_CRYPTO;
    ciphertext = out + APD_BLE_FRAME_HEADER_LEN;
    tag = ciphertext + plaintext_len;
    encrypted = aead_crypt(0, key, out + 54, out, APD_BLE_FRAME_HEADER_LEN,
                           plaintext, plaintext_len, NULL, ciphertext, tag);
    if (encrypted != (int)plaintext_len)
        return APD_BLE_ERR_CRYPTO;
    *out_len = total;
    return APD_BLE_OK;
}

int apd_ble_open_fragment(const unsigned char key[APD_BLE_KEY_LEN],
                          const unsigned char expected_session_id[APD_BLE_SESSION_ID_LEN],
                          uint8_t expected_direction, uint64_t *last_sequence,
                          const unsigned char *frame, size_t frame_len,
                          unsigned char *plaintext, size_t plaintext_size,
                          size_t *plaintext_len,
                          unsigned char request_id[APD_BLE_REQUEST_ID_LEN],
                          uint16_t *fragment_index, uint16_t *fragment_count)
{
    uint16_t length;
    uint16_t count;
    uint64_t sequence;
    const unsigned char *ciphertext;
    const unsigned char *tag;
    int decrypted;

    if (!key || !expected_session_id || !last_sequence || !frame ||
        !plaintext || !plaintext_len || !request_id || !fragment_index ||
        !fragment_count || expected_direction > 1 ||
        frame_len < APD_BLE_FRAME_HEADER_LEN + APD_BLE_TAG_LEN ||
        frame_len > APD_BLE_MAX_FRAME ||
        memcmp(frame, APD_BLE_FRAME_MAGIC, 4) != 0 ||
        frame[4] != APD_BLE_FRAME_VERSION || frame[5] != expected_direction ||
        memcmp(frame + 8, expected_session_id, APD_BLE_SESSION_ID_LEN) != 0)
        return APD_BLE_ERR_FRAME;
    sequence = get_u64(frame + 40);
    if (sequence == 0 || sequence <= *last_sequence)
        return APD_BLE_ERR_REPLAY;
    *fragment_index = get_u16(frame + 48);
    count = get_u16(frame + 50);
    length = get_u16(frame + 52);
    if (!count || *fragment_index >= count || count > APD_BLE_MAX_FRAGMENTS ||
        length > APD_BLE_MAX_FRAGMENT_PLAINTEXT ||
        frame_len != APD_BLE_FRAME_HEADER_LEN + length + APD_BLE_TAG_LEN ||
        plaintext_size < length)
        return APD_BLE_ERR_FRAME;
    ciphertext = frame + APD_BLE_FRAME_HEADER_LEN;
    tag = ciphertext + length;
    decrypted = aead_crypt(1, key, frame + 54, frame, APD_BLE_FRAME_HEADER_LEN,
                           ciphertext, length, tag, plaintext, NULL);
    if (decrypted != (int)length)
        return APD_BLE_ERR_AUTH;
    memcpy(request_id, frame + 24, APD_BLE_REQUEST_ID_LEN);
    *fragment_count = count;
    *plaintext_len = length;
    *last_sequence = sequence;
    return APD_BLE_OK;
}
