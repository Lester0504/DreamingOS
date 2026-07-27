// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#define APD_AP_ID_LEN 36
#define APD_ED25519_KEY_LEN 32
#define APD_ED25519_SIGNATURE_LEN 64
#define APD_KEY_ID_LEN 71
#define APD_ENROLLMENT_CHALLENGE_ID_MAX 36
#define APD_ENROLLMENT_TOKEN_LEN 43

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

const char *apd_db_path(void);
int apd_db_init(void);
void apd_db_close(void);
int apd_db_identity_get(struct apd_node_identity *out);
int apd_enrollment_csr_create(unsigned char *csr_der, size_t csr_der_size,
                              size_t *csr_der_len,
                              unsigned char csr_sha256[SHA256_DIGEST_LENGTH]);
int apd_enrollment_transcript_encode_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char *out, size_t out_size, size_t *out_len);
int apd_enrollment_transcript_sign_v1(
    const struct apd_enrollment_transcript_v1 *input,
    unsigned char signature[APD_ED25519_SIGNATURE_LEN]);

static void fixture_hex(char *out, size_t out_size,
                        const unsigned char *data, size_t data_len)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if (out_size < data_len * 2 + 1)
        return;
    for (i = 0; i < data_len; i++) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 15];
    }
    out[data_len * 2] = '\0';
}

static int fixture_write(const char *path, const unsigned char *data, size_t len)
{
    size_t offset = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0)
        return -1;
    while (offset < len) {
        ssize_t count = write(fd, data + offset, len - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            close(fd);
            unlink(path);
            return -1;
        }
        offset += (size_t)count;
    }
    if (fsync(fd) != 0 || close(fd) != 0) {
        unlink(path);
        return -1;
    }
    return 0;
}

static int fixture_seed_v2(void)
{
    static const char ap_id[] = "01234567-89ab-4cde-8fab-0123456789ab";
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    EVP_PKEY *key = NULL;
    unsigned char private_key[APD_ED25519_KEY_LEN];
    unsigned char public_key[APD_ED25519_KEY_LEN];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char key_id[APD_KEY_ID_LEN + 1] = "sha256:";
    size_t public_len = sizeof(public_key);
    int rc = -1;
    size_t i;

    for (i = 0; i < sizeof(private_key); i++)
        private_key[i] = (unsigned char)(i + 1);
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                       private_key, sizeof(private_key));
    if (!key || EVP_PKEY_get_raw_public_key(key, public_key, &public_len) <= 0 ||
        public_len != sizeof(public_key) || !SHA256(public_key, sizeof(public_key), digest))
        goto done;
    fixture_hex(key_id + 7, sizeof(key_id) - 7, digest, sizeof(digest));
    if (sqlite3_open(apd_db_path(), &db) != SQLITE_OK ||
        sqlite3_exec(db,
            "CREATE TABLE apd_schema_meta(singleton INTEGER PRIMARY KEY,version INTEGER NOT NULL,"
            "owner TEXT NOT NULL,migrated_at INTEGER NOT NULL);"
            "INSERT INTO apd_schema_meta VALUES(1,2,'dreamingwrt-apd',1);"
            "CREATE TABLE apd_node_identity_v2(singleton INTEGER PRIMARY KEY,ap_id TEXT NOT NULL UNIQUE,"
            "private_key BLOB NOT NULL,public_key BLOB NOT NULL,key_id TEXT NOT NULL UNIQUE,"
            "algorithm TEXT NOT NULL,created_at INTEGER NOT NULL);",
            NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
            "INSERT INTO apd_node_identity_v2 VALUES(1,?1,?2,?3,?4,'Ed25519',123456789)",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_text(st, 1, ap_id, -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, private_key, sizeof(private_key), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, public_key, sizeof(public_key), SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, key_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE)
        goto done;
    if (chmod(apd_db_path(), 0600) != 0)
        goto done;
    rc = 0;
done:
    sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(key_id, sizeof(key_id));
    return rc;
}

static int fixture_identity(void)
{
    struct apd_node_identity identity;
    char public_hex[APD_ED25519_KEY_LEN * 2 + 1] = {0};

    memset(&identity, 0, sizeof(identity));
    if (apd_db_identity_get(&identity) != 0)
        return -1;
    fixture_hex(public_hex, sizeof(public_hex), identity.public_key,
                sizeof(identity.public_key));
    printf("ap_id=%s\nkey_id=%s\npublic_key=%s\ncreated_at=%lld\n",
           identity.ap_id, identity.key_id, public_hex,
           (long long)identity.created_at);
    OPENSSL_cleanse(&identity, sizeof(identity));
    OPENSSL_cleanse(public_hex, sizeof(public_hex));
    return 0;
}

static int fixture_build_input(struct apd_enrollment_transcript_v1 *input,
                               struct apd_node_identity *identity,
                               const unsigned char csr_sha256[SHA256_DIGEST_LENGTH],
                               uint64_t expires_at)
{
    static const unsigned char challenge_id[] =
        "33333333-3333-4333-8333-333333333333";
    static const unsigned char enrollment_id[] =
        "11111111-1111-4111-8111-111111111111";
    static const unsigned char token_id[] =
        "22222222-2222-4222-8222-222222222222";
    static const unsigned char token[] =
        "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT";
    static const unsigned char site_id[] = "site-fixture";
    static const unsigned char hardware_digest[] =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    size_t i;

    if (sizeof(token) - 1 != APD_ENROLLMENT_TOKEN_LEN)
        return -1;
    memset(input, 0, sizeof(*input));
    input->challenge_id = (struct apd_enrollment_field){challenge_id,
                                                        sizeof(challenge_id) - 1};
    input->enrollment_id = (struct apd_enrollment_field){enrollment_id,
                                                         sizeof(enrollment_id) - 1};
    input->token_id = (struct apd_enrollment_field){token_id, sizeof(token_id) - 1};
    input->token = (struct apd_enrollment_field){token, sizeof(token) - 1};
    input->ap_id = (struct apd_enrollment_field){
        (const unsigned char *)identity->ap_id, strlen(identity->ap_id)};
    input->key_id = (struct apd_enrollment_field){
        (const unsigned char *)identity->key_id, strlen(identity->key_id)};
    input->site_id = (struct apd_enrollment_field){site_id, sizeof(site_id) - 1};
    input->hardware_digest = (struct apd_enrollment_field){
        hardware_digest, sizeof(hardware_digest) - 1};
    for (i = 0; i < 32; i++) {
        input->server_nonce[i] = (unsigned char)i;
        input->client_nonce[i] = (unsigned char)(i + 32);
    }
    memcpy(input->public_key, identity->public_key, sizeof(input->public_key));
    memcpy(input->csr_sha256, csr_sha256, sizeof(input->csr_sha256));
    input->challenge_expires_at = expires_at;
    return 0;
}

static int fixture_enrollment(const char *transcript_path,
                              const char *signature_path,
                              const char *csr_path)
{
    struct apd_node_identity identity;
    struct apd_enrollment_transcript_v1 input;
    unsigned char transcript[1024] = {0};
    unsigned char signature[APD_ED25519_SIGNATURE_LEN] = {0};
    unsigned char csr[2048] = {0};
    unsigned char csr_sha256[SHA256_DIGEST_LENGTH] = {0};
    size_t transcript_len = 0;
    size_t csr_len = 0;
    uint64_t expires_at = (uint64_t)time(NULL) + 300;
    int rc = -1;

    memset(&identity, 0, sizeof(identity));
    if (apd_db_identity_get(&identity) != 0 ||
        apd_enrollment_csr_create(csr, sizeof(csr), &csr_len, csr_sha256) != 0 ||
        fixture_build_input(&input, &identity, csr_sha256, expires_at) != 0 ||
        apd_enrollment_transcript_encode_v1(&input, transcript,
                                             sizeof(transcript),
                                             &transcript_len) != 0 ||
        apd_enrollment_transcript_sign_v1(&input, signature) != 0 ||
        fixture_write(transcript_path, transcript, transcript_len) != 0 ||
        fixture_write(signature_path, signature, sizeof(signature)) != 0 ||
        fixture_write(csr_path, csr, csr_len) != 0)
        goto done;
    printf("expires_at=%llu\n", (unsigned long long)expires_at);
    rc = 0;
done:
    OPENSSL_cleanse(&identity, sizeof(identity));
    OPENSSL_cleanse(&input, sizeof(input));
    OPENSSL_cleanse(transcript, sizeof(transcript));
    OPENSSL_cleanse(signature, sizeof(signature));
    OPENSSL_cleanse(csr, sizeof(csr));
    OPENSSL_cleanse(csr_sha256, sizeof(csr_sha256));
    return rc;
}

static int fixture_negative(void)
{
    struct apd_node_identity identity;
    struct apd_enrollment_transcript_v1 input;
    unsigned char csr[2048] = {0};
    unsigned char csr_sha256[SHA256_DIGEST_LENGTH] = {0};
    unsigned char transcript[1024] = {0};
    unsigned char signature[APD_ED25519_SIGNATURE_LEN] = {0};
    unsigned char oversized[APD_ENROLLMENT_CHALLENGE_ID_MAX + 1];
    size_t csr_len = 0;
    size_t transcript_len = 0;
    int rejected = 0;

    memset(&identity, 0, sizeof(identity));
    memset(oversized, 'x', sizeof(oversized));
    if (apd_db_identity_get(&identity) != 0 ||
        apd_enrollment_csr_create(csr, sizeof(csr), &csr_len, csr_sha256) != 0 ||
        fixture_build_input(&input, &identity, csr_sha256,
                            (uint64_t)time(NULL) + 300) != 0)
        return -1;
    input.token.len--;
    rejected += apd_enrollment_transcript_encode_v1(&input, transcript,
                                                     sizeof(transcript),
                                                     &transcript_len) != 0;
    input.token.len++;
    input.challenge_id = (struct apd_enrollment_field){oversized, sizeof(oversized)};
    rejected += apd_enrollment_transcript_encode_v1(&input, transcript,
                                                     sizeof(transcript),
                                                     &transcript_len) != 0;
    fixture_build_input(&input, &identity, csr_sha256, (uint64_t)time(NULL) + 601);
    rejected += apd_enrollment_transcript_sign_v1(&input, signature) != 0;
    fixture_build_input(&input, &identity, csr_sha256, (uint64_t)time(NULL) + 300);
    input.public_key[0] ^= 0xff;
    rejected += apd_enrollment_transcript_sign_v1(&input, signature) != 0;
    fixture_build_input(&input, &identity, csr_sha256, (uint64_t)time(NULL) - 1);
    rejected += apd_enrollment_transcript_sign_v1(&input, signature) != 0;
    fixture_build_input(&input, &identity, csr_sha256, (uint64_t)time(NULL) + 300);
    input.ap_id.data = NULL;
    rejected += apd_enrollment_transcript_sign_v1(&input, signature) != 0;
    OPENSSL_cleanse(&identity, sizeof(identity));
    OPENSSL_cleanse(&input, sizeof(input));
    OPENSSL_cleanse(csr, sizeof(csr));
    OPENSSL_cleanse(csr_sha256, sizeof(csr_sha256));
    OPENSSL_cleanse(transcript, sizeof(transcript));
    OPENSSL_cleanse(signature, sizeof(signature));
    OPENSSL_cleanse(oversized, sizeof(oversized));
    printf("rejected=%d\n", rejected);
    return rejected == 6 ? 0 : -1;
}

int main(int argc, char **argv)
{
    const char *command = argc > 1 ? argv[1] : "identity";
    int rc;

    if (strcmp(command, "seed-v2") == 0)
        return fixture_seed_v2() == 0 ? 0 : 1;
    if (apd_db_init() != 0)
        return 2;
    if (strcmp(command, "identity") == 0)
        rc = fixture_identity();
    else if (strcmp(command, "enrollment") == 0 && argc == 5)
        rc = fixture_enrollment(argv[2], argv[3], argv[4]);
    else if (strcmp(command, "negative") == 0)
        rc = fixture_negative();
    else
        rc = -1;
    apd_db_close();
    return rc == 0 ? 0 : 1;
}
