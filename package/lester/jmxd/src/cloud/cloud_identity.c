// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Router identity for the relay path.
 *
 * The X25519 static key is the anchor of the whole design: the App pins its
 * public half during LAN pairing, so losing or rotating it forces every paired
 * App to pair again. That makes durability the priority here, hence the temp
 * file plus rename and the refusal to overwrite an existing key.
 *
 * router_id is generated locally and never accepted from the relay. If the
 * relay could assign it, a relay operator could point a stored App profile at a
 * different router.
 */
#include "cloud_internal.h"

static struct cloud_identity g_identity;
static int g_identity_loaded;

int cloud_identity_fingerprint(const unsigned char *public_key,
                               char *out, size_t out_size)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    static const char hex[] = "0123456789ABCDEF";
    size_t i, o = 0;

    if (!public_key || !out || out_size < 20)
        return -1;
    if (!SHA256(public_key, CLOUD_X25519_KEY_LEN, digest))
        return -1;

    /* First 8 bytes, uppercase hex, grouped in fours: A1B2-C3D4-E5F6-0718.
     * The App computes the same value so a user can compare them by eye. */
    for (i = 0; i < 8; i++) {
        if (i && i % 2 == 0)
            out[o++] = '-';
        out[o++] = hex[(digest[i] >> 4) & 0x0f];
        out[o++] = hex[digest[i] & 0x0f];
    }
    out[o] = '\0';
    return 0;
}

static int cloud_identity_dir_ready(void)
{
    struct stat st;

    if (stat(CLOUD_STATE_DIR, &st) == 0)
        return S_ISDIR(st.st_mode) ? 0 : -1;
    if (mkdir(CLOUD_STATE_DIR, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* Writes through a temp file so an interrupted write cannot truncate a live
 * key. Callers treat a missing file as "generate", and a truncated file would
 * otherwise be indistinguishable from a valid short read. */
static int cloud_identity_write_secret(const char *path,
                                       const unsigned char *data, size_t length,
                                       mode_t mode)
{
    char temp[512];
    int fd;
    ssize_t written;

    if (snprintf(temp, sizeof(temp), "%s.tmp", path) >= (int)sizeof(temp))
        return -1;
    fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return -1;
    written = write(fd, data, length);
    if (written < 0 || (size_t)written != length || fsync(fd) != 0) {
        close(fd);
        unlink(temp);
        return -1;
    }
    if (close(fd) != 0) {
        unlink(temp);
        return -1;
    }
    if (rename(temp, path) != 0) {
        unlink(temp);
        return -1;
    }
    return 0;
}

static int cloud_identity_read_file(const char *path, unsigned char *out,
                                    size_t expected)
{
    struct stat st;
    ssize_t got;
    int fd;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (size_t)st.st_size != expected) {
        close(fd);
        return -1;
    }
    got = read(fd, out, expected);
    close(fd);
    return (got >= 0 && (size_t)got == expected) ? 0 : -1;
}

static int cloud_identity_derive_public(const unsigned char *private_key,
                                        unsigned char *public_key)
{
    EVP_PKEY *key;
    size_t length = CLOUD_X25519_KEY_LEN;
    int rc = -1;

    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key,
                                       CLOUD_X25519_KEY_LEN);
    if (!key)
        return -1;
    if (EVP_PKEY_get_raw_public_key(key, public_key, &length) == 1 &&
        length == CLOUD_X25519_KEY_LEN)
        rc = 0;
    EVP_PKEY_free(key);
    return rc;
}

static int cloud_identity_generate(unsigned char *private_key)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    size_t length = CLOUD_X25519_KEY_LEN;
    int rc = -1;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx)
        return -1;
    if (EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1 &&
        EVP_PKEY_get_raw_private_key(key, private_key, &length) == 1 &&
        length == CLOUD_X25519_KEY_LEN)
        rc = 0;
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

/* Ed25519 keygen and public-key derivation. Kept separate from the X25519
 * helpers rather than parameterised: the two key types are persisted to
 * different files and a mix-up would be silent until enrollment failed. */
static int cloud_identity_generate_signing(unsigned char *private_key)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    size_t length = CLOUD_ED25519_KEY_LEN;
    int rc = -1;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx)
        return -1;
    if (EVP_PKEY_keygen_init(ctx) == 1 && EVP_PKEY_keygen(ctx, &key) == 1 &&
        EVP_PKEY_get_raw_private_key(key, private_key, &length) == 1 &&
        length == CLOUD_ED25519_KEY_LEN)
        rc = 0;
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int cloud_identity_derive_signing_public(const unsigned char *private_key,
                                                unsigned char *public_key)
{
    EVP_PKEY *key;
    size_t length = CLOUD_ED25519_KEY_LEN;
    int rc = -1;

    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key,
                                       CLOUD_ED25519_KEY_LEN);
    if (!key)
        return -1;
    if (EVP_PKEY_get_raw_public_key(key, public_key, &length) == 1 &&
        length == CLOUD_ED25519_KEY_LEN)
        rc = 0;
    EVP_PKEY_free(key);
    return rc;
}

/*
 * ROUTER_AGENT_CONTRACT.md section 2. The relay records this id but never
 * assigns it: if it could, a relay operator would be able to point a stored App
 * profile at a different router, which is the one way to bypass the end-to-end
 * encryption. Deriving it from both public keys makes claiming someone else's id
 * equivalent to a second-preimage attack on 128-bit truncated SHA-256.
 */
int cloud_identity_derive_router_id(const unsigned char *kex_public_key,
                                    const unsigned char *signing_public_key,
                                    char *out, size_t out_size)
{
    unsigned char material[CLOUD_X25519_KEY_LEN + CLOUD_ED25519_KEY_LEN];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";
    size_t i, o;

    /* "router-" + 32 hex chars + NUL */
    if (!kex_public_key || !signing_public_key || !out || out_size < 40)
        return -1;
    memcpy(material, kex_public_key, CLOUD_X25519_KEY_LEN);
    memcpy(material + CLOUD_X25519_KEY_LEN, signing_public_key,
           CLOUD_ED25519_KEY_LEN);
    if (!SHA256(material, sizeof(material), digest))
        return -1;
    memcpy(out, "router-", 7);
    o = 7;
    for (i = 0; i < 16; i++) {
        out[o++] = hex[(digest[i] >> 4) & 0x0f];
        out[o++] = hex[digest[i] & 0x0f];
    }
    out[o] = '\0';
    return 0;
}

int cloud_identity_sign(const unsigned char *message, size_t message_len,
                        unsigned char *out, size_t out_size)
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t signature_len = 64;
    int rc = -1;

    if (!out || out_size < 64)
        return -1;
    if (cloud_identity_load(NULL) != 0)
        return -1;
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                       g_identity.signing_private_key,
                                       CLOUD_ED25519_KEY_LEN);
    if (!key)
        return -1;
    ctx = EVP_MD_CTX_new();
    if (ctx &&
        EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1 &&
        EVP_DigestSign(ctx, out, &signature_len, message, message_len) == 1 &&
        signature_len == 64)
        rc = 0;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}

/*
 * Accepts both id shapes that exist in the field.
 *
 * The contract form is the fingerprint of both public keys. The UUID form was
 * minted by earlier builds of this daemon; per contract section 2 it still works
 * for static registration in the relay's config.json but cannot self enroll,
 * because no signature can produce a matching fingerprint. Rewriting one to the
 * other would change the identity every paired App has pinned, so an existing id
 * is kept as-is and only its capability is downgraded.
 */
static int cloud_identity_router_id_is_uuid(const char *value)
{
    size_t i;

    if (!value || strlen(value) != CLOUD_UUID_LEN)
        return 0;
    for (i = 0; i < CLOUD_UUID_LEN; i++) {
        char c = value[i];

        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return 0;
            continue;
        }
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/* "router-" + exactly 32 lowercase hex characters. */
static int cloud_identity_router_id_is_fingerprint(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 7 + 32 || strncmp(value, "router-", 7))
        return 0;
    for (i = 7; i < 7 + 32; i++) {
        char c = value[i];

        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

static int cloud_identity_router_id_valid(const char *value)
{
    return cloud_identity_router_id_is_fingerprint(value) ||
           cloud_identity_router_id_is_uuid(value);
}

/*
 * Loads the persisted router_id, deriving and persisting the contract form on
 * first run. `key_derived` reports whether the effective id is the fingerprint
 * of the two public keys, which is what decides whether self enrollment is even
 * possible.
 */
static int cloud_identity_load_router_id(const unsigned char *kex_public_key,
                                        const unsigned char *signing_public_key,
                                        char *out, size_t out_size,
                                        int *key_derived)
{
    char buffer[CLOUD_ROUTER_ID_MAX + 2] = {0};
    char derived[64];
    FILE *fp;

    if (key_derived)
        *key_derived = 0;
    if (cloud_identity_derive_router_id(kex_public_key, signing_public_key,
                                        derived, sizeof(derived)) != 0)
        return -1;

    fp = fopen(CLOUD_ROUTER_ID_PATH, "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            size_t length = strlen(buffer);

            while (length && (buffer[length - 1] == '\n' ||
                              buffer[length - 1] == '\r'))
                buffer[--length] = '\0';
        }
        fclose(fp);
        if (cloud_identity_router_id_valid(buffer)) {
            snprintf(out, out_size, "%s", buffer);
            if (key_derived)
                *key_derived = !strcmp(buffer, derived);
            /*
             * A stored fingerprint that does not match the current keys means
             * the id and the key files have drifted apart. Reported, not
             * silently corrected: the App pinned the stored value, and the
             * honest answer is that this router can no longer prove that id.
             */
            if (cloud_identity_router_id_is_fingerprint(buffer) &&
                strcmp(buffer, derived))
                fprintf(stderr,
                        "[%s] router_id does not match the current keys "
                        "stored=%s derived=%s\n",
                        CLOUD_SERVICE_NAME, buffer, derived);
            return 0;
        }
        /* A corrupt id is reported rather than silently replaced: replacing it
         * would strand every App that already pinned the old one. */
        if (buffer[0])
            return -1;
    }

    snprintf(out, out_size, "%s", derived);
    if (cloud_identity_write_secret(CLOUD_ROUTER_ID_PATH,
                                    (const unsigned char *)out, strlen(out),
                                    0644) != 0)
        return -1;
    if (key_derived)
        *key_derived = 1;
    return 0;
}

int cloud_identity_load(struct cloud_identity *out)
{
    struct cloud_identity identity;

    if (g_identity_loaded) {
        if (out)
            *out = g_identity;
        return 0;
    }
    memset(&identity, 0, sizeof(identity));
    if (cloud_identity_dir_ready() != 0)
        return -1;

    if (cloud_identity_read_file(CLOUD_IDENTITY_PATH, identity.private_key,
                                 CLOUD_X25519_KEY_LEN) != 0) {
        struct stat st;

        /* Only generate when the file is genuinely absent. If it exists but did
         * not read back cleanly, failing loudly is better than minting a new
         * key and silently breaking every paired App. */
        if (stat(CLOUD_IDENTITY_PATH, &st) == 0) {
            fprintf(stderr,
                    "[%s] identity key present but unreadable path=%s\n",
                    CLOUD_SERVICE_NAME, CLOUD_IDENTITY_PATH);
            return -1;
        }
        if (cloud_identity_generate(identity.private_key) != 0)
            return -1;
        if (cloud_identity_write_secret(CLOUD_IDENTITY_PATH,
                                        identity.private_key,
                                        CLOUD_X25519_KEY_LEN, 0600) != 0) {
            OPENSSL_cleanse(identity.private_key, sizeof(identity.private_key));
            return -1;
        }
        fprintf(stderr, "[%s] generated new relay identity\n",
                CLOUD_SERVICE_NAME);
    }

    /*
     * The signing key is generated on demand, including for routers installed
     * before it existed. It is a separate file so an upgrade adds the signing
     * ability without touching the X25519 key the Apps already pinned.
     */
    if (cloud_identity_read_file(CLOUD_SIGNING_KEY_PATH,
                                 identity.signing_private_key,
                                 CLOUD_ED25519_KEY_LEN) != 0) {
        struct stat st;

        if (stat(CLOUD_SIGNING_KEY_PATH, &st) == 0) {
            fprintf(stderr,
                    "[%s] signing key present but unreadable path=%s\n",
                    CLOUD_SERVICE_NAME, CLOUD_SIGNING_KEY_PATH);
            OPENSSL_cleanse(identity.private_key, sizeof(identity.private_key));
            return -1;
        }
        if (cloud_identity_generate_signing(identity.signing_private_key) != 0 ||
            cloud_identity_write_secret(CLOUD_SIGNING_KEY_PATH,
                                        identity.signing_private_key,
                                        CLOUD_ED25519_KEY_LEN, 0600) != 0) {
            OPENSSL_cleanse(identity.private_key, sizeof(identity.private_key));
            OPENSSL_cleanse(identity.signing_private_key,
                            sizeof(identity.signing_private_key));
            return -1;
        }
        fprintf(stderr, "[%s] generated new relay signing key\n",
                CLOUD_SERVICE_NAME);
    }

    if (cloud_identity_derive_public(identity.private_key,
                                     identity.public_key) != 0 ||
        cloud_identity_derive_signing_public(identity.signing_private_key,
                                             identity.signing_public_key) != 0 ||
        cloud_identity_load_router_id(identity.public_key,
                                      identity.signing_public_key,
                                      identity.router_id,
                                      sizeof(identity.router_id),
                                      &identity.router_id_is_key_derived) != 0 ||
        cloud_identity_fingerprint(identity.public_key, identity.fingerprint,
                                   sizeof(identity.fingerprint)) != 0) {
        OPENSSL_cleanse(identity.private_key, sizeof(identity.private_key));
        OPENSSL_cleanse(identity.signing_private_key,
                        sizeof(identity.signing_private_key));
        return -1;
    }

    g_identity = identity;
    g_identity_loaded = 1;
    OPENSSL_cleanse(identity.private_key, sizeof(identity.private_key));
    OPENSSL_cleanse(identity.signing_private_key,
                    sizeof(identity.signing_private_key));
    if (out)
        *out = g_identity;
    return 0;
}

const struct cloud_identity *cloud_identity(void)
{
    return g_identity_loaded ? &g_identity : NULL;
}
