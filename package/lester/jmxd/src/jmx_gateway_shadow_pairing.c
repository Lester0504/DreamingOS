// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_gateway_shadow_pairing.c - authenticated Gateway Shadow pairing
 *
 * Four-message protocol:
 *   A start    -> signed offer + local-only human pairing code
 *   B approve  -> verified offer/code + signed acceptance
 *   A finalize -> verified acceptance/code proof + signed confirmation
 *   B confirm  -> verified confirmation, then and only then paired
 *
 * The transport is deliberately outside this module.  Only public, signed
 * exchange objects may be sent to the peer.  The Ed25519 private key and the
 * short-lived initiator code file are local 0600 files and never occur in an
 * exchange object or SQLite row.
 */
#include "jmx_gateway_shadow_pairing.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define GS_PAIR_DB_DEFAULT "/etc/dreamingwrt/config.db"
#define GS_PAIR_DIR_DEFAULT "/etc/dreamingwrt/gateway-shadow"
#define GS_PAIR_KEY_FILE "identity.key"
#define GS_PAIR_CODE_PREFIX "pending-"
#define GS_PAIR_CODE_SUFFIX ".code"
#define GS_PAIR_KEY_LEN 32
#define GS_PAIR_SIGNATURE_LEN 64
#define GS_PAIR_CODE_LEN 8
#define GS_PAIR_TTL_SECONDS 300
#define GS_PAIR_CODE_KDF_ITERATIONS 200000
#define GS_PAIR_TRANSCRIPT_MAX 4096

struct gs_binding {
    char role[16];
    char management_ipv4[64];
    int heartbeat_prefix_length;
    char virtual_ipv4[64];
    int virtual_router_id;
    int priority;
};

struct gs_identity {
    EVP_PKEY *key;
    unsigned char public_key[GS_PAIR_KEY_LEN];
    char public_hex[GS_PAIR_KEY_LEN * 2 + 1];
    char fingerprint[SHA256_DIGEST_LENGTH * 2 + 1];
    char device_id[32];
};

struct gs_session {
    char role[16];
    char state[32];
    char session_id[65];
    char local_fingerprint[65];
    char peer_id[64];
    char peer_fingerprint[65];
    char peer_public_key[65];
    char challenge[65];
    char code_hash[65];
    char offer_digest[65];
    char acceptance_digest[65];
    struct gs_binding local_binding;
    struct gs_binding peer_binding;
    int64_t expires_at;
};

static const char *gs_pair_db_path(void)
{
    const char *value = getenv("DREAMINGWRT_CONFIG_DB");
    return value && value[0] ? value : GS_PAIR_DB_DEFAULT;
}

static const char *gs_pair_dir(void)
{
    const char *value = getenv("DREAMINGWRT_GATEWAY_SHADOW_DIR");
    return value && value[0] ? value : GS_PAIR_DIR_DEFAULT;
}

static int64_t gs_now(void)
{
    return (int64_t)time(NULL);
}

static struct json_object *gs_result(int ok, const char *error)
{
    struct json_object *result = json_object_new_object();
    if (!result) return NULL;
    json_object_object_add(result, "ok", json_object_new_boolean(ok));
    json_object_object_add(result, "pairing_supported",
                           json_object_new_boolean(1));
    if (!ok && error)
        json_object_object_add(result, "error", json_object_new_string(error));
    return result;
}

static void gs_hex(const unsigned char *input, size_t length, char *output)
{
    static const char alphabet[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < length; ++i) {
        output[i * 2] = alphabet[input[i] >> 4];
        output[i * 2 + 1] = alphabet[input[i] & 15];
    }
    output[length * 2] = '\0';
}

static int gs_unhex(const char *input, unsigned char *output, size_t length)
{
    size_t i;
    if (!input || strlen(input) != length * 2) return -1;
    for (i = 0; i < length; ++i) {
        unsigned int value;
        char pair[3] = { input[i * 2], input[i * 2 + 1], 0 };
        if (sscanf(pair, "%2x", &value) != 1) return -1;
        output[i] = (unsigned char)value;
    }
    return 0;
}

static int gs_random_hex(char *output, size_t byte_count)
{
    unsigned char raw[64];
    if (byte_count > sizeof(raw) || RAND_bytes(raw, (int)byte_count) != 1)
        return -1;
    gs_hex(raw, byte_count, output);
    OPENSSL_cleanse(raw, sizeof(raw));
    return 0;
}

static int gs_sha256_hex(const void *data, size_t length, char output[65])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (!SHA256((const unsigned char *)data, length, digest)) return -1;
    gs_hex(digest, sizeof(digest), output);
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static const char *gs_json_string(struct json_object *object, const char *key)
{
    struct json_object *value = NULL;
    if (!object || !json_object_is_type(object, json_type_object) ||
        !json_object_object_get_ex(object, key, &value) || !value ||
        !json_object_is_type(value, json_type_string)) return NULL;
    return json_object_get_string(value);
}

static int64_t gs_json_i64(struct json_object *object, const char *key, int *ok)
{
    struct json_object *value = NULL;
    if (!object || !json_object_object_get_ex(object, key, &value) || !value ||
        !(json_object_is_type(value, json_type_int))) {
        if (ok) *ok = 0;
        return 0;
    }
    if (ok) *ok = 1;
    return json_object_get_int64(value);
}

static int gs_protocol_header_valid(struct json_object *object, const char *type)
{
    const char *protocol = gs_json_string(object, "protocol");
    const char *message_type = gs_json_string(object, "type");
    int ok = 0;
    int64_t version = gs_json_i64(object, "version", &ok);
    return protocol && !strcmp(protocol, JMX_GATEWAY_SHADOW_PAIRING_PROTOCOL) &&
           message_type && !strcmp(message_type, type) && ok &&
           version == JMX_GATEWAY_SHADOW_PAIRING_VERSION;
}

static int gs_valid_hex(const char *value, size_t bytes)
{
    size_t i;
    if (!value || strlen(value) != bytes * 2) return 0;
    for (i = 0; value[i]; ++i)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    return 1;
}

static int gs_valid_id(const char *value)
{
    size_t i, length;
    if (!value || !(length = strlen(value)) || length >= 64) return 0;
    for (i = 0; i < length; ++i)
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= 'A' && value[i] <= 'Z') ||
              (value[i] >= '0' && value[i] <= '9') || value[i] == '-' ||
              value[i] == '_' || value[i] == '.')) return 0;
    return 1;
}

static int gs_ipv4_cidr(const char *value)
{
    char address[INET_ADDRSTRLEN];
    struct in_addr parsed;
    const char *slash;
    char *end = NULL;
    long prefix;
    size_t length;
    if (!value || !(slash = strrchr(value, '/'))) return 0;
    length = (size_t)(slash - value);
    if (!length || length >= sizeof(address)) return 0;
    memcpy(address, value, length); address[length] = '\0';
    errno = 0; prefix = strtol(slash + 1, &end, 10);
    return !errno && end && !*end && prefix >= 1 && prefix <= 32 &&
           inet_pton(AF_INET, address, &parsed) == 1;
}

static int gs_binding_read(struct json_object *object, const char *prefix,
                           struct gs_binding *binding)
{
    char key[96];
    const char *value;
    struct json_object *number = NULL;
#define BINDING_KEY(field) do { \
    if (snprintf(key, sizeof(key), "%s%s", prefix ? prefix : "", field) >= (int)sizeof(key)) \
        return -1; \
} while (0)
    if (!object || !binding) return -1;
    memset(binding, 0, sizeof(*binding));
    BINDING_KEY("role"); value = gs_json_string(object, key);
    if (!value || (strcmp(value, "primary") && strcmp(value, "secondary"))) return -1;
    snprintf(binding->role, sizeof(binding->role), "%s", value);
    BINDING_KEY("management_ipv4"); value = gs_json_string(object, key);
    if (!gs_ipv4_cidr(value)) return -1;
    snprintf(binding->management_ipv4, sizeof(binding->management_ipv4), "%s", value);
    BINDING_KEY("heartbeat_prefix_length");
    if (!json_object_object_get_ex(object, key, &number) || !number ||
        !json_object_is_type(number, json_type_int)) return -1;
    binding->heartbeat_prefix_length = json_object_get_int(number);
    BINDING_KEY("virtual_ipv4"); value = gs_json_string(object, key);
    if (!gs_ipv4_cidr(value)) return -1;
    snprintf(binding->virtual_ipv4, sizeof(binding->virtual_ipv4), "%s", value);
    BINDING_KEY("virtual_router_id");
    if (!json_object_object_get_ex(object, key, &number) || !number ||
        !json_object_is_type(number, json_type_int)) return -1;
    binding->virtual_router_id = json_object_get_int(number);
    BINDING_KEY("priority");
    if (!json_object_object_get_ex(object, key, &number) || !number ||
        !json_object_is_type(number, json_type_int)) return -1;
    binding->priority = json_object_get_int(number);
#undef BINDING_KEY
    return binding->heartbeat_prefix_length >= 1 && binding->heartbeat_prefix_length <= 32 &&
           binding->virtual_router_id >= 1 && binding->virtual_router_id <= 255 &&
           binding->priority >= 1 && binding->priority <= 254 ? 0 : -1;
}

static void gs_binding_add(struct json_object *object, const char *prefix,
                           const struct gs_binding *binding)
{
    char key[96];
#define ADD_TEXT(field, value) do { snprintf(key, sizeof(key), "%s%s", prefix, field); \
    json_object_object_add(object, key, json_object_new_string(value)); } while (0)
#define ADD_INT(field, value) do { snprintf(key, sizeof(key), "%s%s", prefix, field); \
    json_object_object_add(object, key, json_object_new_int(value)); } while (0)
    ADD_TEXT("role", binding->role);
    ADD_TEXT("management_ipv4", binding->management_ipv4);
    ADD_INT("heartbeat_prefix_length", binding->heartbeat_prefix_length);
    ADD_TEXT("virtual_ipv4", binding->virtual_ipv4);
    ADD_INT("virtual_router_id", binding->virtual_router_id);
    ADD_INT("priority", binding->priority);
#undef ADD_TEXT
#undef ADD_INT
}

static int gs_binding_compatible(const struct gs_binding *initiator,
                                 const struct gs_binding *responder)
{
    char i_management[INET_ADDRSTRLEN], r_management[INET_ADDRSTRLEN];
    char virtual_ip[INET_ADDRSTRLEN];
    const char *slash;
#define CIDR_ADDRESS(source, target) do { \
    slash = strchr(source, '/'); \
    if (!slash || (size_t)(slash - source) >= sizeof(target)) return 0; \
    memcpy(target, source, (size_t)(slash - source)); \
    target[slash - source] = '\0'; \
} while (0)
    if (!initiator || !responder) return 0;
    CIDR_ADDRESS(initiator->management_ipv4, i_management);
    CIDR_ADDRESS(responder->management_ipv4, r_management);
    CIDR_ADDRESS(initiator->virtual_ipv4, virtual_ip);
#undef CIDR_ADDRESS
    return strcmp(initiator->role, responder->role) &&
           initiator->heartbeat_prefix_length == responder->heartbeat_prefix_length &&
           initiator->virtual_router_id == responder->virtual_router_id &&
           !strcmp(initiator->virtual_ipv4, responder->virtual_ipv4) &&
           strcmp(i_management, r_management) && strcmp(i_management, virtual_ip) &&
           strcmp(r_management, virtual_ip) && initiator->priority != responder->priority &&
           ((!strcmp(initiator->role, "primary") &&
             initiator->priority > responder->priority) ||
            (!strcmp(responder->role, "primary") &&
             responder->priority > initiator->priority));
}

static int gs_binding_equal(const struct gs_binding *left,
                            const struct gs_binding *right)
{
    return left && right && !strcmp(left->role, right->role) &&
           !strcmp(left->management_ipv4, right->management_ipv4) &&
           left->heartbeat_prefix_length == right->heartbeat_prefix_length &&
           !strcmp(left->virtual_ipv4, right->virtual_ipv4) &&
           left->virtual_router_id == right->virtual_router_id &&
           left->priority == right->priority;
}

static struct json_object *gs_config_object(struct json_object *payload)
{
    struct json_object *config = NULL;
    if (payload && json_object_object_get_ex(payload, "config", &config) && config &&
        json_object_is_type(config, json_type_object)) return config;
    return payload;
}

static int gs_open_db(sqlite3 **database)
{
    int status;
    if (!database) return -1;
    *database = NULL;
    status = sqlite3_open_v2(gs_pair_db_path(), database,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (status != SQLITE_OK) {
        if (*database) sqlite3_close(*database);
        *database = NULL;
        return -1;
    }
    sqlite3_busy_timeout(*database, 3000);
    return 0;
}

static int gs_exec(sqlite3 *database, const char *sql)
{
    char *message = NULL;
    int status = sqlite3_exec(database, sql, NULL, NULL, &message);
    if (message) sqlite3_free(message);
    return status == SQLITE_OK ? 0 : -1;
}

int jmx_gateway_shadow_pairing_schema_ensure(void)
{
    sqlite3 *database = NULL;
    const char *sql =
        "CREATE TABLE IF NOT EXISTS gateway_shadow_pairing_session("
        "id INTEGER PRIMARY KEY CHECK(id=1),"
        "role TEXT NOT NULL, state TEXT NOT NULL, session_id TEXT NOT NULL,"
        "local_fingerprint TEXT NOT NULL, peer_id TEXT NOT NULL DEFAULT '',"
        "peer_fingerprint TEXT NOT NULL DEFAULT '',"
        "peer_public_key TEXT NOT NULL DEFAULT '', challenge TEXT NOT NULL,"
        "code_hash TEXT NOT NULL, offer_digest TEXT NOT NULL,"
        "acceptance_digest TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL,"
        "local_role TEXT NOT NULL, local_management_ipv4 TEXT NOT NULL,"
        "local_heartbeat_prefix_length INTEGER NOT NULL, local_virtual_ipv4 TEXT NOT NULL,"
        "local_virtual_router_id INTEGER NOT NULL, local_priority INTEGER NOT NULL,"
        "peer_role TEXT NOT NULL DEFAULT '', peer_management_ipv4 TEXT NOT NULL DEFAULT '',"
        "peer_heartbeat_prefix_length INTEGER NOT NULL DEFAULT 0,"
        "peer_virtual_ipv4 TEXT NOT NULL DEFAULT '', peer_virtual_router_id INTEGER NOT NULL DEFAULT 0,"
        "peer_priority INTEGER NOT NULL DEFAULT 0,"
        "updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS gateway_shadow_pairing_peer("
        "id INTEGER PRIMARY KEY CHECK(id=1), peer_id TEXT NOT NULL,"
        "public_key TEXT NOT NULL, fingerprint TEXT NOT NULL,"
        "local_role TEXT NOT NULL, local_management_ipv4 TEXT NOT NULL,"
        "local_heartbeat_prefix_length INTEGER NOT NULL, local_virtual_ipv4 TEXT NOT NULL,"
        "local_virtual_router_id INTEGER NOT NULL, local_priority INTEGER NOT NULL,"
        "peer_role TEXT NOT NULL, peer_management_ipv4 TEXT NOT NULL,"
        "peer_heartbeat_prefix_length INTEGER NOT NULL, peer_virtual_ipv4 TEXT NOT NULL,"
        "peer_virtual_router_id INTEGER NOT NULL, peer_priority INTEGER NOT NULL,"
        "binding_digest TEXT NOT NULL,"
        "trust_state TEXT NOT NULL CHECK(trust_state IN ('paired','revoked')),"
        "paired_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS gateway_shadow_peer("
        "id INTEGER PRIMARY KEY CHECK(id=1), peer_id TEXT NOT NULL DEFAULT '',"
        "certificate_fingerprint TEXT NOT NULL DEFAULT '',"
        "trust_state TEXT NOT NULL DEFAULT 'unpaired'"
        " CHECK(trust_state IN ('unpaired','pending','paired','revoked')),"
        "management_address TEXT NOT NULL DEFAULT '',"
        "last_seen_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0);"
        "INSERT OR IGNORE INTO gateway_shadow_peer(id) VALUES(1);";
    int status;
    if (gs_open_db(&database) != 0) return -1;
    status = gs_exec(database, sql);
    sqlite3_close(database);
    return status;
}

static int gs_prepare_dir(void)
{
    const char *directory = gs_pair_dir();
    struct stat status;
    if (mkdir(directory, 0700) != 0 && errno != EEXIST) return -1;
    if (lstat(directory, &status) != 0 || !S_ISDIR(status.st_mode) ||
        S_ISLNK(status.st_mode)) return -1;
    if (chmod(directory, 0700) != 0) return -1;
    return 0;
}

static int gs_path(char *output, size_t output_size, const char *leaf)
{
    int length;
    if (!output || !leaf) return -1;
    length = snprintf(output, output_size, "%s/%s", gs_pair_dir(), leaf);
    return length > 0 && (size_t)length < output_size ? 0 : -1;
}

static int gs_write_secret(const char *path, const void *data, size_t length)
{
    char temporary[1024];
    unsigned char suffix[8];
    char suffix_hex[17];
    int descriptor = -1, status = -1;
    size_t offset = 0;
    if (RAND_bytes(suffix, sizeof(suffix)) != 1) return -1;
    gs_hex(suffix, sizeof(suffix), suffix_hex);
    OPENSSL_cleanse(suffix, sizeof(suffix));
    if (snprintf(temporary, sizeof(temporary), "%s.tmp.%s", path, suffix_hex) >=
        (int)sizeof(temporary)) return -1;
    descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (descriptor < 0) return -1;
    while (offset < length) {
        ssize_t count = write(descriptor, (const unsigned char *)data + offset,
                              length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) goto done;
        offset += (size_t)count;
    }
    if (fchmod(descriptor, 0600) != 0 || fsync(descriptor) != 0) goto done;
    if (close(descriptor) != 0) { descriptor = -1; goto done; }
    descriptor = -1;
    if (rename(temporary, path) != 0) goto done;
    status = 0;
done:
    if (descriptor >= 0) close(descriptor);
    if (status != 0) unlink(temporary);
    return status;
}

static int gs_read_secret(const char *path, void *data, size_t length)
{
    struct stat status;
    size_t offset = 0;
    int descriptor = open(path, O_RDONLY | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
        !S_ISREG(status.st_mode) || (status.st_mode & 077) != 0 ||
        (size_t)status.st_size != length) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    while (offset < length) {
        ssize_t count = read(descriptor, (unsigned char *)data + offset,
                             length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(descriptor); return -1; }
        offset += (size_t)count;
    }
    close(descriptor);
    return 0;
}

static int gs_load_identity(struct gs_identity *identity)
{
    char path[1024];
    struct stat key_status;
    unsigned char private_key[GS_PAIR_KEY_LEN];
    size_t public_length = sizeof(identity->public_key);
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int generated = 0, status = -1;

    if (!identity || gs_prepare_dir() != 0 ||
        gs_path(path, sizeof(path), GS_PAIR_KEY_FILE) != 0) return -1;
    memset(identity, 0, sizeof(*identity));
    memset(private_key, 0, sizeof(private_key));
    if (lstat(path, &key_status) == 0) {
        if (!S_ISREG(key_status.st_mode) || S_ISLNK(key_status.st_mode) ||
            gs_read_secret(path, private_key, sizeof(private_key)) != 0) goto done;
    } else if (errno == ENOENT) {
        context = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        if (!context || EVP_PKEY_keygen_init(context) <= 0 ||
            EVP_PKEY_keygen(context, &key) <= 0) goto done;
        {
            size_t private_length = sizeof(private_key);
            if (EVP_PKEY_get_raw_private_key(key, private_key, &private_length) <= 0 ||
                private_length != sizeof(private_key) ||
                gs_write_secret(path, private_key, sizeof(private_key)) != 0) goto done;
        }
        generated = 1;
    } else goto done;
    if (!generated) {
        key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_key,
                                           sizeof(private_key));
        if (!key) goto done;
    }
    if (EVP_PKEY_get_raw_public_key(key, identity->public_key, &public_length) <= 0 ||
        public_length != sizeof(identity->public_key) ||
        !SHA256(identity->public_key, public_length, digest)) goto done;
    gs_hex(identity->public_key, public_length, identity->public_hex);
    gs_hex(digest, sizeof(digest), identity->fingerprint);
    snprintf(identity->device_id, sizeof(identity->device_id), "gs-%.20s",
             identity->fingerprint);
    identity->key = key;
    key = NULL;
    status = 0;
done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    OPENSSL_cleanse(private_key, sizeof(private_key));
    OPENSSL_cleanse(digest, sizeof(digest));
    return status;
}

static void gs_free_identity(struct gs_identity *identity)
{
    if (!identity) return;
    EVP_PKEY_free(identity->key);
    OPENSSL_cleanse(identity, sizeof(*identity));
}

static int gs_sign(EVP_PKEY *key, const char *message, char signature_hex[129])
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char signature[GS_PAIR_SIGNATURE_LEN];
    size_t length = sizeof(signature);
    int status = -1;
    if (context && EVP_DigestSignInit(context, NULL, NULL, NULL, key) > 0 &&
        EVP_DigestSign(context, signature, &length,
                       (const unsigned char *)message, strlen(message)) > 0 &&
        length == sizeof(signature)) {
        gs_hex(signature, length, signature_hex);
        status = 0;
    }
    OPENSSL_cleanse(signature, sizeof(signature));
    EVP_MD_CTX_free(context);
    return status;
}

static int gs_verify(const char *public_hex, const char *message,
                     const char *signature_hex)
{
    unsigned char public_key[GS_PAIR_KEY_LEN];
    unsigned char signature[GS_PAIR_SIGNATURE_LEN];
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *context = NULL;
    int status = -1;
    if (gs_unhex(public_hex, public_key, sizeof(public_key)) != 0 ||
        gs_unhex(signature_hex, signature, sizeof(signature)) != 0 ||
        !(key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key,
                                            sizeof(public_key))) ||
        !(context = EVP_MD_CTX_new()) ||
        EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) <= 0) goto done;
    status = EVP_DigestVerify(context, signature, sizeof(signature),
                              (const unsigned char *)message, strlen(message)) == 1 ? 0 : -1;
done:
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(signature, sizeof(signature));
    return status;
}

static int gs_public_fingerprint(const char *public_hex, char output[65])
{
    unsigned char public_key[GS_PAIR_KEY_LEN];
    int status;
    if (gs_unhex(public_hex, public_key, sizeof(public_key)) != 0) return -1;
    status = gs_sha256_hex(public_key, sizeof(public_key), output);
    OPENSSL_cleanse(public_key, sizeof(public_key));
    return status;
}

static int gs_offer_transcript(struct json_object *offer, char *output, size_t size)
{
    struct gs_binding binding;
    const char *protocol = gs_json_string(offer, "protocol");
    const char *type = gs_json_string(offer, "type");
    const char *session = gs_json_string(offer, "session_id");
    const char *id = gs_json_string(offer, "initiator_id");
    const char *public_key = gs_json_string(offer, "initiator_public_key");
    const char *fingerprint = gs_json_string(offer, "initiator_fingerprint");
    const char *challenge = gs_json_string(offer, "challenge");
    const char *code_hash = gs_json_string(offer, "code_hash");
    int ok = 0;
    int64_t expires = gs_json_i64(offer, "expires_at", &ok);
    int length;
    if (!gs_protocol_header_valid(offer, "offer") ||
        !protocol || !type || !gs_valid_hex(session, 16) ||
        !gs_valid_id(id) || !gs_valid_hex(public_key, GS_PAIR_KEY_LEN) ||
        !gs_valid_hex(fingerprint, SHA256_DIGEST_LENGTH) ||
        !gs_valid_hex(challenge, 32) || !gs_valid_hex(code_hash, 32) || !ok ||
        gs_binding_read(offer, "initiator_", &binding) != 0)
        return -1;
    length = snprintf(output, size,
                      "GS-OFFER|1|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|%d|%d|%lld",
                      session, id, public_key, fingerprint, challenge, code_hash,
                      binding.role, binding.management_ipv4,
                      binding.heartbeat_prefix_length, binding.virtual_ipv4,
                      binding.virtual_router_id, binding.priority,
                      (long long)expires);
    return length > 0 && (size_t)length < size ? 0 : -1;
}

static int gs_acceptance_transcript(struct json_object *acceptance, char *output,
                                    size_t size, int include_proof)
{
    struct gs_binding initiator_binding, responder_binding;
    const char *session = gs_json_string(acceptance, "session_id");
    const char *offer_digest = gs_json_string(acceptance, "offer_digest");
    const char *initiator_id = gs_json_string(acceptance, "initiator_id");
    const char *initiator_fp = gs_json_string(acceptance, "initiator_fingerprint");
    const char *responder_id = gs_json_string(acceptance, "responder_id");
    const char *responder_public = gs_json_string(acceptance, "responder_public_key");
    const char *responder_fp = gs_json_string(acceptance, "responder_fingerprint");
    const char *proof = gs_json_string(acceptance, "code_proof");
    int ok = 0, length;
    int64_t expires = gs_json_i64(acceptance, "expires_at", &ok);
    if (!gs_protocol_header_valid(acceptance, "acceptance") ||
        !gs_valid_hex(session, 16) || !gs_valid_hex(offer_digest, 32) ||
        !gs_valid_id(initiator_id) || !gs_valid_hex(initiator_fp, 32) ||
        !gs_valid_id(responder_id) || !gs_valid_hex(responder_public, 32) ||
        !gs_valid_hex(responder_fp, 32) || !ok ||
        gs_binding_read(acceptance, "initiator_", &initiator_binding) != 0 ||
        gs_binding_read(acceptance, "responder_", &responder_binding) != 0 ||
        !gs_binding_compatible(&initiator_binding, &responder_binding) ||
        (include_proof && !gs_valid_hex(proof, 32))) return -1;
    if (include_proof)
        length = snprintf(output, size,
                          "GS-ACCEPT|1|%s|%s|%s|%s|%s|%s|%s|%s|"
                          "%s|%s|%d|%s|%d|%d|%s|%s|%d|%s|%d|%d|%lld",
                          session, offer_digest, initiator_id, initiator_fp,
                          responder_id, responder_public, responder_fp, proof,
                          initiator_binding.role, initiator_binding.management_ipv4,
                          initiator_binding.heartbeat_prefix_length,
                          initiator_binding.virtual_ipv4, initiator_binding.virtual_router_id,
                          initiator_binding.priority, responder_binding.role,
                          responder_binding.management_ipv4,
                          responder_binding.heartbeat_prefix_length,
                          responder_binding.virtual_ipv4, responder_binding.virtual_router_id,
                          responder_binding.priority,
                          (long long)expires);
    else
        length = snprintf(output, size,
                          "GS-ACCEPT-PROOF|1|%s|%s|%s|%s|%s|%s|%s|"
                          "%s|%s|%d|%s|%d|%d|%s|%s|%d|%s|%d|%d|%lld",
                          session, offer_digest, initiator_id, initiator_fp,
                          responder_id, responder_public, responder_fp,
                          initiator_binding.role, initiator_binding.management_ipv4,
                          initiator_binding.heartbeat_prefix_length,
                          initiator_binding.virtual_ipv4, initiator_binding.virtual_router_id,
                          initiator_binding.priority, responder_binding.role,
                          responder_binding.management_ipv4,
                          responder_binding.heartbeat_prefix_length,
                          responder_binding.virtual_ipv4, responder_binding.virtual_router_id,
                          responder_binding.priority,
                          (long long)expires);
    return length > 0 && (size_t)length < size ? 0 : -1;
}

static int gs_confirmation_transcript(struct json_object *confirmation, char *output,
                                      size_t size)
{
    struct gs_binding initiator_binding, responder_binding;
    const char *session = gs_json_string(confirmation, "session_id");
    const char *acceptance = gs_json_string(confirmation, "acceptance_digest");
    const char *initiator = gs_json_string(confirmation, "initiator_fingerprint");
    const char *responder = gs_json_string(confirmation, "responder_fingerprint");
    int ok = 0, length;
    int64_t expires = gs_json_i64(confirmation, "expires_at", &ok);
    if (!gs_protocol_header_valid(confirmation, "confirmation") ||
        !gs_valid_hex(session, 16) || !gs_valid_hex(acceptance, 32) ||
        !gs_valid_hex(initiator, 32) || !gs_valid_hex(responder, 32) || !ok ||
        gs_binding_read(confirmation, "initiator_", &initiator_binding) != 0 ||
        gs_binding_read(confirmation, "responder_", &responder_binding) != 0 ||
        !gs_binding_compatible(&initiator_binding, &responder_binding))
        return -1;
    length = snprintf(output, size,
                      "GS-CONFIRM|1|%s|%s|%s|%s|"
                      "%s|%s|%d|%s|%d|%d|%s|%s|%d|%s|%d|%d|%lld",
                      session, acceptance, initiator, responder,
                      initiator_binding.role, initiator_binding.management_ipv4,
                      initiator_binding.heartbeat_prefix_length,
                      initiator_binding.virtual_ipv4, initiator_binding.virtual_router_id,
                      initiator_binding.priority, responder_binding.role,
                      responder_binding.management_ipv4,
                      responder_binding.heartbeat_prefix_length,
                      responder_binding.virtual_ipv4, responder_binding.virtual_router_id,
                      responder_binding.priority,
                      (long long)expires);
    return length > 0 && (size_t)length < size ? 0 : -1;
}

static int gs_code_hash(const char *session, const char *challenge, const char *code,
                        char output[65])
{
    unsigned char salt[48], digest[SHA256_DIGEST_LENGTH];
    if (!gs_valid_hex(session, 16) || !gs_valid_hex(challenge, 32) || !code ||
        strlen(code) != GS_PAIR_CODE_LEN) return -1;
    if (gs_unhex(session, salt, 16) != 0 ||
        gs_unhex(challenge, salt + 16, 32) != 0 ||
        PKCS5_PBKDF2_HMAC(code, GS_PAIR_CODE_LEN, salt, sizeof(salt),
                          GS_PAIR_CODE_KDF_ITERATIONS, EVP_sha256(),
                          sizeof(digest), digest) != 1) {
        OPENSSL_cleanse(salt, sizeof(salt));
        return -1;
    }
    gs_hex(digest, sizeof(digest), output);
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int gs_code_proof(const char *code, const char *transcript, char output[65])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (!code || strlen(code) != GS_PAIR_CODE_LEN || !transcript ||
        !HMAC(EVP_sha256(), code, GS_PAIR_CODE_LEN,
              (const unsigned char *)transcript, strlen(transcript), digest, &length) ||
        length != SHA256_DIGEST_LENGTH) return -1;
    gs_hex(digest, length, output);
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int gs_code_path(const char *session, char *output, size_t size)
{
    char leaf[128];
    if (!gs_valid_hex(session, 16)) return -1;
    if (snprintf(leaf, sizeof(leaf), "%s%s%s", GS_PAIR_CODE_PREFIX, session,
                 GS_PAIR_CODE_SUFFIX) >= (int)sizeof(leaf)) return -1;
    return gs_path(output, size, leaf);
}

static int gs_save_session(const struct gs_session *session)
{
    sqlite3 *database = NULL;
    sqlite3_stmt *statement = NULL;
    const char *sql =
        "INSERT INTO gateway_shadow_pairing_session("
        "id,role,state,session_id,local_fingerprint,peer_id,peer_fingerprint,"
        "peer_public_key,challenge,code_hash,offer_digest,acceptance_digest,"
        "expires_at,local_role,local_management_ipv4,local_heartbeat_prefix_length,"
        "local_virtual_ipv4,local_virtual_router_id,local_priority,peer_role,"
        "peer_management_ipv4,peer_heartbeat_prefix_length,peer_virtual_ipv4,"
        "peer_virtual_router_id,peer_priority,updated_at) "
        "VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25) "
        "ON CONFLICT(id) DO UPDATE SET role=excluded.role,state=excluded.state,"
        "session_id=excluded.session_id,local_fingerprint=excluded.local_fingerprint,"
        "peer_id=excluded.peer_id,peer_fingerprint=excluded.peer_fingerprint,"
        "peer_public_key=excluded.peer_public_key,challenge=excluded.challenge,"
        "code_hash=excluded.code_hash,offer_digest=excluded.offer_digest,"
        "acceptance_digest=excluded.acceptance_digest,expires_at=excluded.expires_at,"
        "local_role=excluded.local_role,local_management_ipv4=excluded.local_management_ipv4,"
        "local_heartbeat_prefix_length=excluded.local_heartbeat_prefix_length,"
        "local_virtual_ipv4=excluded.local_virtual_ipv4,local_virtual_router_id=excluded.local_virtual_router_id,"
        "local_priority=excluded.local_priority,peer_role=excluded.peer_role,"
        "peer_management_ipv4=excluded.peer_management_ipv4,"
        "peer_heartbeat_prefix_length=excluded.peer_heartbeat_prefix_length,"
        "peer_virtual_ipv4=excluded.peer_virtual_ipv4,peer_virtual_router_id=excluded.peer_virtual_router_id,"
        "peer_priority=excluded.peer_priority,"
        "updated_at=excluded.updated_at";
    int status = -1;
    if (jmx_gateway_shadow_pairing_schema_ensure() != 0 || gs_open_db(&database) != 0 ||
        sqlite3_prepare_v2(database, sql, -1, &statement, NULL) != SQLITE_OK) goto done;
#define BIND_TEXT(index, value) sqlite3_bind_text(statement, index, value, -1, SQLITE_TRANSIENT)
    BIND_TEXT(1, session->role); BIND_TEXT(2, session->state);
    BIND_TEXT(3, session->session_id); BIND_TEXT(4, session->local_fingerprint);
    BIND_TEXT(5, session->peer_id); BIND_TEXT(6, session->peer_fingerprint);
    BIND_TEXT(7, session->peer_public_key); BIND_TEXT(8, session->challenge);
    BIND_TEXT(9, session->code_hash); BIND_TEXT(10, session->offer_digest);
    BIND_TEXT(11, session->acceptance_digest);
    sqlite3_bind_int64(statement, 12, session->expires_at);
    BIND_TEXT(13, session->local_binding.role);
    BIND_TEXT(14, session->local_binding.management_ipv4);
    sqlite3_bind_int(statement, 15, session->local_binding.heartbeat_prefix_length);
    BIND_TEXT(16, session->local_binding.virtual_ipv4);
    sqlite3_bind_int(statement, 17, session->local_binding.virtual_router_id);
    sqlite3_bind_int(statement, 18, session->local_binding.priority);
    BIND_TEXT(19, session->peer_binding.role);
    BIND_TEXT(20, session->peer_binding.management_ipv4);
    sqlite3_bind_int(statement, 21, session->peer_binding.heartbeat_prefix_length);
    BIND_TEXT(22, session->peer_binding.virtual_ipv4);
    sqlite3_bind_int(statement, 23, session->peer_binding.virtual_router_id);
    sqlite3_bind_int(statement, 24, session->peer_binding.priority);
#undef BIND_TEXT
    sqlite3_bind_int64(statement, 25, gs_now());
    status = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
done:
    sqlite3_finalize(statement);
    if (database) sqlite3_close(database);
    return status;
}

static int gs_load_session(struct gs_session *session)
{
    sqlite3 *database = NULL;
    sqlite3_stmt *statement = NULL;
    const char *sql =
        "SELECT role,state,session_id,local_fingerprint,peer_id,peer_fingerprint,"
        "peer_public_key,challenge,code_hash,offer_digest,acceptance_digest,expires_at "
        ",local_role,local_management_ipv4,local_heartbeat_prefix_length,local_virtual_ipv4,"
        "local_virtual_router_id,local_priority,peer_role,peer_management_ipv4,"
        "peer_heartbeat_prefix_length,peer_virtual_ipv4,peer_virtual_router_id,peer_priority "
        "FROM gateway_shadow_pairing_session WHERE id=1";
    int status = -1;
    if (!session || jmx_gateway_shadow_pairing_schema_ensure() != 0 ||
        gs_open_db(&database) != 0 ||
        sqlite3_prepare_v2(database, sql, -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_ROW) goto done;
    memset(session, 0, sizeof(*session));
#define COPY_COLUMN(field, index) do { \
    const unsigned char *v = sqlite3_column_text(statement, index); \
    snprintf(session->field, sizeof(session->field), "%s", v ? (const char *)v : ""); \
} while (0)
    COPY_COLUMN(role, 0); COPY_COLUMN(state, 1); COPY_COLUMN(session_id, 2);
    COPY_COLUMN(local_fingerprint, 3); COPY_COLUMN(peer_id, 4);
    COPY_COLUMN(peer_fingerprint, 5); COPY_COLUMN(peer_public_key, 6);
    COPY_COLUMN(challenge, 7); COPY_COLUMN(code_hash, 8);
    COPY_COLUMN(offer_digest, 9); COPY_COLUMN(acceptance_digest, 10);
    session->expires_at = sqlite3_column_int64(statement, 11);
    { const unsigned char *v = sqlite3_column_text(statement, 12);
      snprintf(session->local_binding.role, sizeof(session->local_binding.role), "%s", v ? (const char *)v : ""); }
    { const unsigned char *v = sqlite3_column_text(statement, 13);
      snprintf(session->local_binding.management_ipv4, sizeof(session->local_binding.management_ipv4), "%s", v ? (const char *)v : ""); }
    session->local_binding.heartbeat_prefix_length = sqlite3_column_int(statement, 14);
    { const unsigned char *v = sqlite3_column_text(statement, 15);
      snprintf(session->local_binding.virtual_ipv4, sizeof(session->local_binding.virtual_ipv4), "%s", v ? (const char *)v : ""); }
    session->local_binding.virtual_router_id = sqlite3_column_int(statement, 16);
    session->local_binding.priority = sqlite3_column_int(statement, 17);
    { const unsigned char *v = sqlite3_column_text(statement, 18);
      snprintf(session->peer_binding.role, sizeof(session->peer_binding.role), "%s", v ? (const char *)v : ""); }
    { const unsigned char *v = sqlite3_column_text(statement, 19);
      snprintf(session->peer_binding.management_ipv4, sizeof(session->peer_binding.management_ipv4), "%s", v ? (const char *)v : ""); }
    session->peer_binding.heartbeat_prefix_length = sqlite3_column_int(statement, 20);
    { const unsigned char *v = sqlite3_column_text(statement, 21);
      snprintf(session->peer_binding.virtual_ipv4, sizeof(session->peer_binding.virtual_ipv4), "%s", v ? (const char *)v : ""); }
    session->peer_binding.virtual_router_id = sqlite3_column_int(statement, 22);
    session->peer_binding.priority = sqlite3_column_int(statement, 23);
#undef COPY_COLUMN
    status = 0;
done:
    sqlite3_finalize(statement);
    if (database) sqlite3_close(database);
    return status;
}

static int gs_binding_digest(const struct gs_binding *local,
                             const struct gs_binding *peer, char output[65])
{
    char transcript[1024];
    int length;
    if (!local || !peer || !gs_binding_compatible(local, peer)) return -1;
    length = snprintf(transcript, sizeof(transcript),
                      "GS-BINDING|1|%s|%s|%d|%s|%d|%d|%s|%s|%d|%s|%d|%d",
                      local->role, local->management_ipv4,
                      local->heartbeat_prefix_length, local->virtual_ipv4,
                      local->virtual_router_id, local->priority, peer->role,
                      peer->management_ipv4, peer->heartbeat_prefix_length,
                      peer->virtual_ipv4, peer->virtual_router_id, peer->priority);
    if (length <= 0 || (size_t)length >= sizeof(transcript)) return -1;
    length = gs_sha256_hex(transcript, (size_t)length, output);
    OPENSSL_cleanse(transcript, sizeof(transcript));
    return length;
}

static int gs_commit_peer(const char *peer_id, const char *public_key,
                          const char *fingerprint,
                          const struct gs_binding *local_binding,
                          const struct gs_binding *peer_binding)
{
    sqlite3 *database = NULL;
    sqlite3_stmt *statement = NULL;
    const char *trust_sql =
        "INSERT INTO gateway_shadow_pairing_peer"
        "(id,peer_id,public_key,fingerprint,local_role,local_management_ipv4,"
        "local_heartbeat_prefix_length,local_virtual_ipv4,local_virtual_router_id,"
        "local_priority,peer_role,peer_management_ipv4,peer_heartbeat_prefix_length,"
        "peer_virtual_ipv4,peer_virtual_router_id,peer_priority,binding_digest,"
        "trust_state,paired_at,updated_at)"
        " VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,"
        "'paired',?17,?17) ON CONFLICT(id) DO UPDATE SET "
        "peer_id=excluded.peer_id,public_key=excluded.public_key,"
        "fingerprint=excluded.fingerprint,local_role=excluded.local_role,"
        "local_management_ipv4=excluded.local_management_ipv4,"
        "local_heartbeat_prefix_length=excluded.local_heartbeat_prefix_length,"
        "local_virtual_ipv4=excluded.local_virtual_ipv4,"
        "local_virtual_router_id=excluded.local_virtual_router_id,"
        "local_priority=excluded.local_priority,peer_role=excluded.peer_role,"
        "peer_management_ipv4=excluded.peer_management_ipv4,"
        "peer_heartbeat_prefix_length=excluded.peer_heartbeat_prefix_length,"
        "peer_virtual_ipv4=excluded.peer_virtual_ipv4,"
        "peer_virtual_router_id=excluded.peer_virtual_router_id,"
        "peer_priority=excluded.peer_priority,binding_digest=excluded.binding_digest,"
        "trust_state='paired',"
        "paired_at=excluded.paired_at,updated_at=excluded.updated_at";
    char binding_digest[65];
    int status = -1;
    if (!gs_valid_id(peer_id) || !gs_valid_hex(public_key, 32) ||
        !gs_valid_hex(fingerprint, 32) ||
        gs_binding_digest(local_binding, peer_binding, binding_digest) != 0 ||
        jmx_gateway_shadow_pairing_schema_ensure() != 0 || gs_open_db(&database) != 0 ||
        gs_exec(database, "BEGIN IMMEDIATE") != 0 ||
        sqlite3_prepare_v2(database, trust_sql, -1, &statement, NULL) != SQLITE_OK) goto rollback;
    sqlite3_bind_text(statement, 1, peer_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, public_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, local_binding->role, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 5, local_binding->management_ipv4, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 6, local_binding->heartbeat_prefix_length);
    sqlite3_bind_text(statement, 7, local_binding->virtual_ipv4, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 8, local_binding->virtual_router_id);
    sqlite3_bind_int(statement, 9, local_binding->priority);
    sqlite3_bind_text(statement, 10, peer_binding->role, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 11, peer_binding->management_ipv4, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 12, peer_binding->heartbeat_prefix_length);
    sqlite3_bind_text(statement, 13, peer_binding->virtual_ipv4, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 14, peer_binding->virtual_router_id);
    sqlite3_bind_int(statement, 15, peer_binding->priority);
    sqlite3_bind_text(statement, 16, binding_digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 17, gs_now());
    if (sqlite3_step(statement) != SQLITE_DONE) goto rollback;
    sqlite3_finalize(statement); statement = NULL;
    if (sqlite3_prepare_v2(database,
            "UPDATE gateway_shadow_peer SET peer_id=?1,certificate_fingerprint=?2,"
            "management_address=?3,trust_state='paired',updated_at=?4 WHERE id=1",
            -1, &statement, NULL) != SQLITE_OK)
        goto rollback;
    sqlite3_bind_text(statement, 1, peer_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, fingerprint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, peer_binding->management_ipv4, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 4, gs_now());
    if (sqlite3_step(statement) != SQLITE_DONE) goto rollback;
    sqlite3_finalize(statement); statement = NULL;
    if (sqlite3_prepare_v2(database,
            "UPDATE gateway_shadow_pairing_session SET state='paired',updated_at=?1 WHERE id=1",
            -1, &statement, NULL) != SQLITE_OK) goto rollback;
    sqlite3_bind_int64(statement, 1, gs_now());
    if (sqlite3_step(statement) != SQLITE_DONE || gs_exec(database, "COMMIT") != 0)
        goto rollback;
    status = 0;
    goto done;
rollback:
    if (database) (void)gs_exec(database, "ROLLBACK");
done:
    OPENSSL_cleanse(binding_digest, sizeof(binding_digest));
    sqlite3_finalize(statement);
    if (database) sqlite3_close(database);
    return status;
}

struct json_object *jmx_gateway_shadow_pairing_identity(void)
{
    struct gs_identity identity;
    struct json_object *result;
    if (gs_load_identity(&identity) != 0) return gs_result(0, "identity_unavailable");
    result = gs_result(1, NULL);
    json_object_object_add(result, "algorithm", json_object_new_string("Ed25519"));
    json_object_object_add(result, "device_id", json_object_new_string(identity.device_id));
    json_object_object_add(result, "public_key", json_object_new_string(identity.public_hex));
    json_object_object_add(result, "fingerprint", json_object_new_string(identity.fingerprint));
    json_object_object_add(result, "private_key_exportable", json_object_new_boolean(0));
    gs_free_identity(&identity);
    return result;
}

static struct json_object *gs_start_new(struct json_object *payload)
{
    struct gs_identity identity;
    struct gs_session session;
    struct json_object *offer = NULL, *result = NULL;
    char code[GS_PAIR_CODE_LEN + 1];
    char transcript[GS_PAIR_TRANSCRIPT_MAX], signature[129], code_path[1024];
    uint32_t random_code;
    memset(&session, 0, sizeof(session)); memset(code, 0, sizeof(code));
    if (gs_binding_read(gs_config_object(payload), "", &session.local_binding) != 0)
        return gs_result(0, "pairing_binding_invalid");
    if (gs_load_identity(&identity) != 0 || RAND_bytes((unsigned char *)&random_code,
                                                       sizeof(random_code)) != 1)
        return gs_result(0, "identity_or_rng_unavailable");
    snprintf(code, sizeof(code), "%08u", (unsigned int)(random_code % 100000000U));
    snprintf(session.role, sizeof(session.role), "initiator");
    snprintf(session.state, sizeof(session.state), "offer_created");
    snprintf(session.local_fingerprint, sizeof(session.local_fingerprint), "%s",
             identity.fingerprint);
    session.expires_at = gs_now() + GS_PAIR_TTL_SECONDS;
    if (gs_random_hex(session.session_id, 16) != 0 ||
        gs_random_hex(session.challenge, 32) != 0 ||
        gs_code_hash(session.session_id, session.challenge, code, session.code_hash) != 0)
        goto failed;
    offer = json_object_new_object();
    json_object_object_add(offer, "protocol", json_object_new_string(JMX_GATEWAY_SHADOW_PAIRING_PROTOCOL));
    json_object_object_add(offer, "version", json_object_new_int(1));
    json_object_object_add(offer, "type", json_object_new_string("offer"));
    json_object_object_add(offer, "session_id", json_object_new_string(session.session_id));
    json_object_object_add(offer, "initiator_id", json_object_new_string(identity.device_id));
    json_object_object_add(offer, "initiator_public_key", json_object_new_string(identity.public_hex));
    json_object_object_add(offer, "initiator_fingerprint", json_object_new_string(identity.fingerprint));
    json_object_object_add(offer, "challenge", json_object_new_string(session.challenge));
    json_object_object_add(offer, "code_hash", json_object_new_string(session.code_hash));
    gs_binding_add(offer, "initiator_", &session.local_binding);
    json_object_object_add(offer, "expires_at", json_object_new_int64(session.expires_at));
    if (gs_offer_transcript(offer, transcript, sizeof(transcript)) != 0 ||
        gs_sign(identity.key, transcript, signature) != 0 ||
        gs_sha256_hex(transcript, strlen(transcript), session.offer_digest) != 0 ||
        gs_code_path(session.session_id, code_path, sizeof(code_path)) != 0 ||
        gs_write_secret(code_path, code, GS_PAIR_CODE_LEN) != 0 ||
        gs_save_session(&session) != 0) goto failed;
    json_object_object_add(offer, "signature", json_object_new_string(signature));
    result = gs_result(1, NULL);
    json_object_object_add(result, "action", json_object_new_string("start"));
    json_object_object_add(result, "paired", json_object_new_boolean(0));
    json_object_object_add(result, "pairing_code", json_object_new_string(code));
    json_object_object_add(result, "pairing_code_scope",
                           json_object_new_string("local_display_only"));
    json_object_object_add(result, "offer", offer); offer = NULL;
    goto done;
failed:
    if (session.session_id[0] && gs_code_path(session.session_id, code_path,
                                              sizeof(code_path)) == 0) unlink(code_path);
    result = gs_result(0, "pairing_start_failed");
done:
    if (offer) json_object_put(offer);
    OPENSSL_cleanse(code, sizeof(code));
    OPENSSL_cleanse(transcript, sizeof(transcript));
    OPENSSL_cleanse(signature, sizeof(signature));
    gs_free_identity(&identity);
    return result;
}

static struct json_object *gs_finalize(struct json_object *payload)
{
    struct gs_identity identity;
    struct gs_session session;
    struct json_object *acceptance = NULL, *confirmation = NULL, *result = NULL;
    char transcript[GS_PAIR_TRANSCRIPT_MAX], proof_transcript[GS_PAIR_TRANSCRIPT_MAX];
    char digest[65], expected_fp[65], expected_proof[65], signature[129];
    char code[GS_PAIR_CODE_LEN + 1], code_path[1024];
    const char *session_id, *offer_digest, *initiator_id, *initiator_fp;
    const char *responder_id, *responder_public, *responder_fp, *proof, *sig;
    struct gs_binding initiator_binding, responder_binding;
    int ok = 0; int64_t expires;
    memset(code, 0, sizeof(code));
    if (!payload || !json_object_object_get_ex(payload, "acceptance", &acceptance) ||
        !acceptance || gs_load_session(&session) != 0 ||
        strcmp(session.role, "initiator") || strcmp(session.state, "offer_created") ||
        session.expires_at < gs_now() || gs_load_identity(&identity) != 0)
        return gs_result(0, "no_active_initiator_pairing");
    session_id = gs_json_string(acceptance, "session_id");
    offer_digest = gs_json_string(acceptance, "offer_digest");
    initiator_id = gs_json_string(acceptance, "initiator_id");
    initiator_fp = gs_json_string(acceptance, "initiator_fingerprint");
    responder_id = gs_json_string(acceptance, "responder_id");
    responder_public = gs_json_string(acceptance, "responder_public_key");
    responder_fp = gs_json_string(acceptance, "responder_fingerprint");
    proof = gs_json_string(acceptance, "code_proof"); sig = gs_json_string(acceptance, "signature");
    expires = gs_json_i64(acceptance, "expires_at", &ok);
    if (!session_id || strcmp(session_id, session.session_id) || !offer_digest ||
        strcmp(offer_digest, session.offer_digest) || !initiator_id ||
        strcmp(initiator_id, identity.device_id) || !initiator_fp ||
        strcmp(initiator_fp, identity.fingerprint) || !responder_id ||
        !responder_public || !responder_fp || !proof || !sig || !ok ||
        expires != session.expires_at ||
        gs_binding_read(acceptance, "initiator_", &initiator_binding) != 0 ||
        gs_binding_read(acceptance, "responder_", &responder_binding) != 0 ||
        !gs_binding_equal(&initiator_binding, &session.local_binding) ||
        !gs_binding_compatible(&initiator_binding, &responder_binding) ||
        gs_public_fingerprint(responder_public, expected_fp) != 0 ||
        CRYPTO_memcmp(expected_fp, responder_fp, 64) != 0 ||
        gs_acceptance_transcript(acceptance, transcript, sizeof(transcript), 1) != 0 ||
        gs_verify(responder_public, transcript, sig) != 0 ||
        gs_acceptance_transcript(acceptance, proof_transcript, sizeof(proof_transcript), 0) != 0 ||
        gs_code_path(session.session_id, code_path, sizeof(code_path)) != 0 ||
        gs_read_secret(code_path, code, GS_PAIR_CODE_LEN) != 0 ||
        gs_code_proof(code, proof_transcript, expected_proof) != 0 ||
        CRYPTO_memcmp(expected_proof, proof, 64) != 0 ||
        gs_sha256_hex(transcript, strlen(transcript), digest) != 0) {
        result = gs_result(0, "acceptance_verification_failed"); goto done;
    }
    snprintf(session.peer_id, sizeof(session.peer_id), "%s", responder_id);
    snprintf(session.peer_fingerprint, sizeof(session.peer_fingerprint), "%s", responder_fp);
    snprintf(session.peer_public_key, sizeof(session.peer_public_key), "%s", responder_public);
    session.peer_binding = responder_binding;
    snprintf(session.acceptance_digest, sizeof(session.acceptance_digest), "%s", digest);
    snprintf(session.state, sizeof(session.state), "acceptance_verified");
    if (gs_save_session(&session) != 0) { result = gs_result(0, "pairing_state_write_failed"); goto done; }
    confirmation = json_object_new_object();
    json_object_object_add(confirmation, "protocol", json_object_new_string(JMX_GATEWAY_SHADOW_PAIRING_PROTOCOL));
    json_object_object_add(confirmation, "version", json_object_new_int(1));
    json_object_object_add(confirmation, "type", json_object_new_string("confirmation"));
    json_object_object_add(confirmation, "session_id", json_object_new_string(session.session_id));
    json_object_object_add(confirmation, "acceptance_digest", json_object_new_string(session.acceptance_digest));
    json_object_object_add(confirmation, "initiator_fingerprint", json_object_new_string(identity.fingerprint));
    json_object_object_add(confirmation, "responder_fingerprint", json_object_new_string(responder_fp));
    gs_binding_add(confirmation, "initiator_", &session.local_binding);
    gs_binding_add(confirmation, "responder_", &session.peer_binding);
    json_object_object_add(confirmation, "expires_at", json_object_new_int64(session.expires_at));
    if (gs_confirmation_transcript(confirmation, transcript, sizeof(transcript)) != 0 ||
        gs_sign(identity.key, transcript, signature) != 0 ||
        gs_commit_peer(responder_id, responder_public, responder_fp,
                       &session.local_binding, &session.peer_binding) != 0) {
        result = gs_result(0, "confirmation_creation_failed"); goto done;
    }
    json_object_object_add(confirmation, "signature", json_object_new_string(signature));
    unlink(code_path);
    result = gs_result(1, NULL);
    json_object_object_add(result, "action", json_object_new_string("finalize"));
    json_object_object_add(result, "paired", json_object_new_boolean(1));
    json_object_object_add(result, "peer_fingerprint", json_object_new_string(responder_fp));
    json_object_object_add(result, "confirmation", confirmation); confirmation = NULL;
done:
    if (confirmation) json_object_put(confirmation);
    OPENSSL_cleanse(code, sizeof(code)); OPENSSL_cleanse(expected_proof, sizeof(expected_proof));
    OPENSSL_cleanse(transcript, sizeof(transcript)); OPENSSL_cleanse(proof_transcript, sizeof(proof_transcript));
    OPENSSL_cleanse(signature, sizeof(signature)); gs_free_identity(&identity);
    return result;
}

struct json_object *jmx_gateway_shadow_pairing_protocol_start(struct json_object *payload)
{
    const char *action = gs_json_string(payload, "action");
    if (!action || !strcmp(action, "start")) return gs_start_new(payload);
    if (!strcmp(action, "finalize")) return gs_finalize(payload);
    return gs_result(0, "pairing_action_invalid");
}

static struct json_object *gs_approve_offer(struct json_object *payload)
{
    struct gs_identity identity; struct gs_session session;
    struct gs_binding initiator_binding, responder_binding;
    struct json_object *offer = NULL, *acceptance = NULL, *result = NULL;
    char offer_transcript[GS_PAIR_TRANSCRIPT_MAX], proof_transcript[GS_PAIR_TRANSCRIPT_MAX];
    char offer_digest[65], expected_fp[65], expected_hash[65], proof[65], signature[129];
    const char *code, *session_id, *initiator_id, *initiator_public, *initiator_fp;
    const char *challenge, *code_hash, *offer_signature; int ok = 0; int64_t expires;
    memset(&session, 0, sizeof(session));
    code = gs_json_string(payload, "pairing_code");
    if (!payload || !json_object_object_get_ex(payload, "offer", &offer) || !offer ||
        !code || strlen(code) != GS_PAIR_CODE_LEN || gs_load_identity(&identity) != 0)
        return gs_result(0, "offer_or_code_missing");
    if (gs_binding_read(offer, "initiator_", &initiator_binding) != 0 ||
        gs_binding_read(gs_config_object(payload), "", &responder_binding) != 0 ||
        !gs_binding_compatible(&initiator_binding, &responder_binding)) {
        gs_free_identity(&identity);
        return gs_result(0, "pairing_binding_conflict");
    }
    session_id = gs_json_string(offer, "session_id"); initiator_id = gs_json_string(offer, "initiator_id");
    initiator_public = gs_json_string(offer, "initiator_public_key");
    initiator_fp = gs_json_string(offer, "initiator_fingerprint");
    challenge = gs_json_string(offer, "challenge"); code_hash = gs_json_string(offer, "code_hash");
    offer_signature = gs_json_string(offer, "signature"); expires = gs_json_i64(offer, "expires_at", &ok);
    if (!session_id || !initiator_id || !initiator_public || !initiator_fp || !challenge ||
        !code_hash || !offer_signature || !ok || expires < gs_now() ||
        expires > gs_now() + GS_PAIR_TTL_SECONDS + 30 ||
        gs_public_fingerprint(initiator_public, expected_fp) != 0 ||
        CRYPTO_memcmp(expected_fp, initiator_fp, 64) != 0 ||
        gs_offer_transcript(offer, offer_transcript, sizeof(offer_transcript)) != 0 ||
        gs_verify(initiator_public, offer_transcript, offer_signature) != 0 ||
        gs_code_hash(session_id, challenge, code, expected_hash) != 0 ||
        CRYPTO_memcmp(expected_hash, code_hash, 64) != 0 ||
        gs_sha256_hex(offer_transcript, strlen(offer_transcript), offer_digest) != 0) {
        result = gs_result(0, "offer_verification_failed"); goto done;
    }
    acceptance = json_object_new_object();
    json_object_object_add(acceptance, "protocol", json_object_new_string(JMX_GATEWAY_SHADOW_PAIRING_PROTOCOL));
    json_object_object_add(acceptance, "version", json_object_new_int(1));
    json_object_object_add(acceptance, "type", json_object_new_string("acceptance"));
    json_object_object_add(acceptance, "session_id", json_object_new_string(session_id));
    json_object_object_add(acceptance, "offer_digest", json_object_new_string(offer_digest));
    json_object_object_add(acceptance, "initiator_id", json_object_new_string(initiator_id));
    json_object_object_add(acceptance, "initiator_fingerprint", json_object_new_string(initiator_fp));
    json_object_object_add(acceptance, "responder_id", json_object_new_string(identity.device_id));
    json_object_object_add(acceptance, "responder_public_key", json_object_new_string(identity.public_hex));
    json_object_object_add(acceptance, "responder_fingerprint", json_object_new_string(identity.fingerprint));
    gs_binding_add(acceptance, "initiator_", &initiator_binding);
    gs_binding_add(acceptance, "responder_", &responder_binding);
    json_object_object_add(acceptance, "expires_at", json_object_new_int64(expires));
    if (gs_acceptance_transcript(acceptance, proof_transcript, sizeof(proof_transcript), 0) != 0 ||
        gs_code_proof(code, proof_transcript, proof) != 0) {
        result = gs_result(0, "acceptance_creation_failed"); goto done;
    }
    json_object_object_add(acceptance, "code_proof", json_object_new_string(proof));
    if (gs_acceptance_transcript(acceptance, proof_transcript, sizeof(proof_transcript), 1) != 0 ||
        gs_sign(identity.key, proof_transcript, signature) != 0 ||
        gs_sha256_hex(proof_transcript, strlen(proof_transcript), session.acceptance_digest) != 0) {
        result = gs_result(0, "acceptance_creation_failed"); goto done;
    }
    json_object_object_add(acceptance, "signature", json_object_new_string(signature));
    snprintf(session.role, sizeof(session.role), "responder");
    snprintf(session.state, sizeof(session.state), "acceptance_created");
    snprintf(session.session_id, sizeof(session.session_id), "%s", session_id);
    snprintf(session.local_fingerprint, sizeof(session.local_fingerprint), "%s", identity.fingerprint);
    snprintf(session.peer_id, sizeof(session.peer_id), "%s", initiator_id);
    snprintf(session.peer_fingerprint, sizeof(session.peer_fingerprint), "%s", initiator_fp);
    snprintf(session.peer_public_key, sizeof(session.peer_public_key), "%s", initiator_public);
    snprintf(session.challenge, sizeof(session.challenge), "%s", challenge);
    snprintf(session.code_hash, sizeof(session.code_hash), "%s", code_hash);
    snprintf(session.offer_digest, sizeof(session.offer_digest), "%s", offer_digest);
    session.local_binding = responder_binding;
    session.peer_binding = initiator_binding;
    session.expires_at = expires;
    if (gs_save_session(&session) != 0) { result = gs_result(0, "pairing_state_write_failed"); goto done; }
    result = gs_result(1, NULL);
    json_object_object_add(result, "action", json_object_new_string("approve"));
    json_object_object_add(result, "paired", json_object_new_boolean(0));
    json_object_object_add(result, "acceptance", acceptance); acceptance = NULL;
done:
    if (acceptance) json_object_put(acceptance);
    OPENSSL_cleanse(expected_hash, sizeof(expected_hash)); OPENSSL_cleanse(proof, sizeof(proof));
    OPENSSL_cleanse(signature, sizeof(signature)); OPENSSL_cleanse(proof_transcript, sizeof(proof_transcript));
    gs_free_identity(&identity); return result;
}

static struct json_object *gs_confirm(struct json_object *payload)
{
    struct gs_identity identity; struct gs_session session; struct json_object *confirmation = NULL;
    struct gs_binding initiator_binding, responder_binding;
    char transcript[GS_PAIR_TRANSCRIPT_MAX]; const char *session_id, *acceptance_digest;
    const char *initiator_fp, *responder_fp, *signature; int ok = 0; int64_t expires;
    struct json_object *result;
    if (!payload || !json_object_object_get_ex(payload, "confirmation", &confirmation) ||
        !confirmation || gs_load_session(&session) != 0 || strcmp(session.role, "responder") ||
        strcmp(session.state, "acceptance_created") || session.expires_at < gs_now() ||
        gs_load_identity(&identity) != 0) return gs_result(0, "no_active_responder_pairing");
    session_id = gs_json_string(confirmation, "session_id");
    acceptance_digest = gs_json_string(confirmation, "acceptance_digest");
    initiator_fp = gs_json_string(confirmation, "initiator_fingerprint");
    responder_fp = gs_json_string(confirmation, "responder_fingerprint");
    signature = gs_json_string(confirmation, "signature");
    expires = gs_json_i64(confirmation, "expires_at", &ok);
    if (!session_id || strcmp(session_id, session.session_id) || !acceptance_digest ||
        strcmp(acceptance_digest, session.acceptance_digest) || !initiator_fp ||
        strcmp(initiator_fp, session.peer_fingerprint) || !responder_fp ||
        strcmp(responder_fp, identity.fingerprint) || !signature || !ok ||
        expires != session.expires_at ||
        gs_binding_read(confirmation, "initiator_", &initiator_binding) != 0 ||
        gs_binding_read(confirmation, "responder_", &responder_binding) != 0 ||
        !gs_binding_equal(&initiator_binding, &session.peer_binding) ||
        !gs_binding_equal(&responder_binding, &session.local_binding) ||
        gs_confirmation_transcript(confirmation, transcript, sizeof(transcript)) != 0 ||
        gs_verify(session.peer_public_key, transcript, signature) != 0 ||
        gs_commit_peer(session.peer_id, session.peer_public_key, session.peer_fingerprint,
                       &session.local_binding, &session.peer_binding) != 0) {
        result = gs_result(0, "confirmation_verification_failed"); goto done;
    }
    result = gs_result(1, NULL);
    json_object_object_add(result, "action", json_object_new_string("confirm"));
    json_object_object_add(result, "paired", json_object_new_boolean(1));
    json_object_object_add(result, "peer_fingerprint",
                           json_object_new_string(session.peer_fingerprint));
done:
    OPENSSL_cleanse(transcript, sizeof(transcript)); gs_free_identity(&identity); return result;
}

struct json_object *jmx_gateway_shadow_pairing_protocol_approve(struct json_object *payload)
{
    const char *action = gs_json_string(payload, "action");
    if (!action || !strcmp(action, "approve")) return gs_approve_offer(payload);
    if (!strcmp(action, "confirm")) return gs_confirm(payload);
    return gs_result(0, "pairing_action_invalid");
}
