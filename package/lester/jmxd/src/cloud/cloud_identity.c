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

/* router_id is a UUID v4. It is public, non-secret routing metadata. */
static int cloud_identity_generate_router_id(char *out, size_t out_size)
{
    unsigned char raw[16];

    if (out_size < CLOUD_UUID_LEN + 1)
        return -1;
    if (RAND_bytes(raw, sizeof(raw)) != 1)
        return -1;
    raw[6] = (unsigned char)((raw[6] & 0x0f) | 0x40);
    raw[8] = (unsigned char)((raw[8] & 0x3f) | 0x80);
    snprintf(out, out_size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
             raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14],
             raw[15]);
    return 0;
}

static int cloud_identity_router_id_valid(const char *value)
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

static int cloud_identity_load_router_id(char *out, size_t out_size)
{
    char buffer[CLOUD_UUID_LEN + 2] = {0};
    FILE *fp;

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
            return 0;
        }
        /* A corrupt id is reported rather than silently replaced: replacing it
         * would strand every App that already pinned the old one. */
        if (buffer[0])
            return -1;
    }
    if (cloud_identity_generate_router_id(out, out_size) != 0)
        return -1;
    if (cloud_identity_write_secret(CLOUD_ROUTER_ID_PATH,
                                    (const unsigned char *)out, strlen(out),
                                    0644) != 0)
        return -1;
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

    if (cloud_identity_derive_public(identity.private_key,
                                     identity.public_key) != 0 ||
        cloud_identity_load_router_id(identity.router_id,
                                      sizeof(identity.router_id)) != 0 ||
        cloud_identity_fingerprint(identity.public_key, identity.fingerprint,
                                   sizeof(identity.fingerprint)) != 0) {
        OPENSSL_cleanse(identity.private_key, sizeof(identity.private_key));
        return -1;
    }

    g_identity = identity;
    g_identity_loaded = 1;
    OPENSSL_cleanse(identity.private_key, sizeof(identity.private_key));
    if (out)
        *out = g_identity;
    return 0;
}

const struct cloud_identity *cloud_identity(void)
{
    return g_identity_loaded ? &g_identity : NULL;
}
