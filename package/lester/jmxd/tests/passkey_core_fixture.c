#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <json-c/json.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#include "webd/webd_passkey.h"
#include "webd/webd_session_idle.h"

#define FIXTURE_KEY_PATH WEBD_PASSKEY_DIR "/fixture-private.pem"
#define FIXTURE_STATE_PATH WEBD_PASSKEY_DIR "/fixture-state.json"
#define FIXTURE_CONFIG_DB WEBD_PASSKEY_DIR "/fixture-config.db"
#define FIXTURE_APP_DB WEBD_PASSKEY_DIR "/fixture-app.db"

struct byte_buffer {
    unsigned char data[4096];
    size_t length;
};

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void check(int condition, const char *message)
{
    if (!condition)
        fail(message);
}

static const char *json_string(struct json_object *object, const char *key)
{
    struct json_object *value = NULL;

    if (!object || !json_object_object_get_ex(object, key, &value) ||
        !json_object_is_type(value, json_type_string))
        return NULL;
    return json_object_get_string(value);
}

static struct json_object *json_object_value(struct json_object *object,
                                             const char *key)
{
    struct json_object *value = NULL;

    if (!object || !json_object_object_get_ex(object, key, &value) ||
        !json_object_is_type(value, json_type_object))
        return NULL;
    return value;
}

static void append_bytes(struct byte_buffer *buffer, const void *data,
                         size_t length)
{
    check(buffer && data && buffer->length + length <= sizeof(buffer->data),
          "byte buffer overflow");
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
}

static void append_u8(struct byte_buffer *buffer, unsigned int value)
{
    unsigned char byte = (unsigned char)value;

    append_bytes(buffer, &byte, 1);
}

static void append_cbor_text(struct byte_buffer *buffer, const char *value)
{
    size_t length = strlen(value);

    check(length < 24, "fixture CBOR text too long");
    append_u8(buffer, 0x60U + (unsigned int)length);
    append_bytes(buffer, value, length);
}

static void append_cbor_bytes(struct byte_buffer *buffer,
                              const unsigned char *data, size_t length)
{
    if (length < 24) {
        append_u8(buffer, 0x40U + (unsigned int)length);
    } else if (length <= 0xff) {
        append_u8(buffer, 0x58);
        append_u8(buffer, (unsigned int)length);
    } else {
        append_u8(buffer, 0x59);
        append_u8(buffer, (unsigned int)(length >> 8));
        append_u8(buffer, (unsigned int)length);
    }
    append_bytes(buffer, data, length);
}

static char *base64url(const unsigned char *data, size_t length)
{
    size_t capacity = ((length + 2) / 3) * 4 + 1;
    char *encoded = calloc(capacity, 1);

    check(encoded != NULL, "base64 allocation failed");
    check(webd_base64url_encode(data, length, encoded, capacity) == 0,
          "base64url encode failed");
    return encoded;
}

static int verify_password(const char *username, const char *password)
{
    return username && password && !strcmp(username, "admin") &&
           !strcmp(password, "correct-password");
}

static void sqlite_exec_ok(sqlite3 *database, const char *sql)
{
    char *error = NULL;

    if (sqlite3_exec(database, sql, NULL, NULL, &error) != SQLITE_OK) {
        fprintf(stderr, "sqlite: %s\n", error ? error : "unknown error");
        sqlite3_free(error);
        fail("sqlite statement failed");
    }
}

static void open_databases(sqlite3 **config_db, sqlite3 **app_db)
{
    check(sqlite3_open(FIXTURE_CONFIG_DB, config_db) == SQLITE_OK,
          "open config database failed");
    check(sqlite3_open(FIXTURE_APP_DB, app_db) == SQLITE_OK,
          "open app database failed");
    sqlite_exec_ok(*config_db,
        "CREATE TABLE IF NOT EXISTS web_users ("
        "username TEXT PRIMARY KEY,role TEXT NOT NULL,status TEXT NOT NULL,"
        "web_login_timeout_min INTEGER NOT NULL DEFAULT 60,"
        "updated_at INTEGER NOT NULL DEFAULT 0);"
        "INSERT OR REPLACE INTO web_users"
        "(username,role,status,web_login_timeout_min,updated_at)"
        "VALUES('admin','owner','enabled',60,0);");
    sqlite_exec_ok(*app_db,
        "CREATE TABLE IF NOT EXISTS web_sessions ("
        "token TEXT PRIMARY KEY,username TEXT NOT NULL,type TEXT NOT NULL,"
        "created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,"
        "revoked INTEGER NOT NULL DEFAULT 0,session_id TEXT NOT NULL DEFAULT '',"
        "last_activity_at INTEGER NOT NULL DEFAULT 0,"
        "refresh_consumed_at INTEGER NOT NULL DEFAULT 0,"
        "replaced_by TEXT NOT NULL DEFAULT '');");
    check(webd_session_idle_migrate(*config_db, *app_db) == WEBD_SESSION_IDLE_OK,
          "session migration failed");
}

static EVP_PKEY *generate_key(void)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;

    check(context != NULL, "EC context allocation failed");
    check(EVP_PKEY_keygen_init(context) == 1,
          "EC keygen initialization failed");
    check(EVP_PKEY_CTX_set_group_name(context, "prime256v1") == 1,
          "EC group selection failed");
    check(EVP_PKEY_generate(context, &key) == 1,
          "EC key generation failed");
    EVP_PKEY_CTX_free(context);
    return key;
}

static void save_key(EVP_PKEY *key)
{
    FILE *file = fopen(FIXTURE_KEY_PATH, "w");

    check(file != NULL, "open private key failed");
    check(PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL) == 1,
          "write private key failed");
    check(fclose(file) == 0, "close private key failed");
    check(chmod(FIXTURE_KEY_PATH, 0600) == 0, "chmod private key failed");
}

static EVP_PKEY *load_key(void)
{
    FILE *file = fopen(FIXTURE_KEY_PATH, "r");
    EVP_PKEY *key;

    check(file != NULL, "open persisted private key failed");
    key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    check(key != NULL, "read persisted private key failed");
    return key;
}

static void cose_key(EVP_PKEY *key, struct byte_buffer *buffer)
{
    unsigned char public_key[65];
    size_t public_key_length = sizeof(public_key);

    check(EVP_PKEY_get_octet_string_param(
              key, OSSL_PKEY_PARAM_PUB_KEY, public_key,
              sizeof(public_key), &public_key_length) == 1,
          "read EC public key failed");
    check(public_key_length == sizeof(public_key) && public_key[0] == 0x04,
          "unexpected EC public key encoding");
    append_u8(buffer, 0xa5);
    append_u8(buffer, 0x01);
    append_u8(buffer, 0x02);
    append_u8(buffer, 0x03);
    append_u8(buffer, 0x26);
    append_u8(buffer, 0x20);
    append_u8(buffer, 0x01);
    append_u8(buffer, 0x21);
    append_cbor_bytes(buffer, public_key + 1, 32);
    append_u8(buffer, 0x22);
    append_cbor_bytes(buffer, public_key + 33, 32);
}

static void write_u32(unsigned char *output, uint32_t value)
{
    output[0] = (unsigned char)(value >> 24);
    output[1] = (unsigned char)(value >> 16);
    output[2] = (unsigned char)(value >> 8);
    output[3] = (unsigned char)value;
}

static void registration_auth_data(EVP_PKEY *key, const char *rp_id,
                                   const unsigned char *credential_id,
                                   size_t credential_id_length,
                                   struct byte_buffer *buffer)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned char flags = 0x41;
    unsigned char count[4] = {0, 0, 0, 1};
    unsigned char aaguid[16] = {0};
    unsigned char credential_length[2];

    SHA256((const unsigned char *)rp_id, strlen(rp_id), hash);
    credential_length[0] = (unsigned char)(credential_id_length >> 8);
    credential_length[1] = (unsigned char)credential_id_length;
    append_bytes(buffer, hash, sizeof(hash));
    append_bytes(buffer, &flags, sizeof(flags));
    append_bytes(buffer, count, sizeof(count));
    append_bytes(buffer, aaguid, sizeof(aaguid));
    append_bytes(buffer, credential_length, sizeof(credential_length));
    append_bytes(buffer, credential_id, credential_id_length);
    cose_key(key, buffer);
}

static void attestation_object(const struct byte_buffer *auth_data,
                               struct byte_buffer *attestation)
{
    append_u8(attestation, 0xa3);
    append_cbor_text(attestation, "fmt");
    append_cbor_text(attestation, "none");
    append_cbor_text(attestation, "authData");
    append_cbor_bytes(attestation, auth_data->data, auth_data->length);
    append_cbor_text(attestation, "attStmt");
    append_u8(attestation, 0xa0);
}

static char *client_data(const char *type, const char *challenge,
                         const char *rp_id)
{
    struct json_object *object = json_object_new_object();
    char origin[320];
    const char *serialized;
    char *copy;

    check(snprintf(origin, sizeof(origin), "https://%s", rp_id) <
              (int)sizeof(origin),
          "origin overflow");
    json_object_object_add(object, "type", json_object_new_string(type));
    json_object_object_add(object, "challenge",
                           json_object_new_string(challenge));
    json_object_object_add(object, "origin", json_object_new_string(origin));
    serialized = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
    copy = strdup(serialized);
    json_object_put(object);
    check(copy != NULL, "client data allocation failed");
    return copy;
}

static struct json_object *body_with_two(const char *first_key,
                                         const char *first_value,
                                         const char *second_key,
                                         const char *second_value)
{
    struct json_object *body = json_object_new_object();

    json_object_object_add(body, first_key, json_object_new_string(first_value));
    json_object_object_add(body, second_key, json_object_new_string(second_value));
    return body;
}

static void save_state(const char *credential_id, const char *credential_hex,
                       const char *rp_id)
{
    struct json_object *state = json_object_new_object();
    const char *serialized;
    FILE *file;

    json_object_object_add(state, "credential_id",
                           json_object_new_string(credential_id));
    json_object_object_add(state, "credential_id_hex",
                           json_object_new_string(credential_hex));
    json_object_object_add(state, "rp_id", json_object_new_string(rp_id));
    serialized = json_object_to_json_string_ext(state, JSON_C_TO_STRING_PLAIN);
    file = fopen(FIXTURE_STATE_PATH, "w");
    check(file != NULL, "open fixture state failed");
    check(fwrite(serialized, 1, strlen(serialized), file) == strlen(serialized),
          "write fixture state failed");
    check(fclose(file) == 0, "close fixture state failed");
    json_object_put(state);
}

static struct json_object *load_state(void)
{
    struct json_object *state = json_object_from_file(FIXTURE_STATE_PATH);

    check(state != NULL, "load fixture state failed");
    return state;
}

static void sign_assertion(EVP_PKEY *key, const unsigned char *auth_data,
                           size_t auth_data_length, const char *client_json,
                           unsigned char **signature,
                           size_t *signature_length)
{
    unsigned char client_hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    check(context != NULL, "signature context allocation failed");
    SHA256((const unsigned char *)client_json, strlen(client_json), client_hash);
    check(EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, key) == 1,
          "signature initialization failed");
    check(EVP_DigestSignUpdate(context, auth_data, auth_data_length) == 1 &&
              EVP_DigestSignUpdate(context, client_hash,
                                   sizeof(client_hash)) == 1,
          "signature update failed");
    check(EVP_DigestSignFinal(context, NULL, signature_length) == 1,
          "signature length failed");
    *signature = malloc(*signature_length);
    check(*signature != NULL, "signature allocation failed");
    check(EVP_DigestSignFinal(context, *signature, signature_length) == 1,
          "signature generation failed");
    EVP_MD_CTX_free(context);
}

static unsigned char assertion_flags = 0x01;
static void assertion_auth_data(const char *rp_id, uint32_t sign_count,
                                unsigned char output[37])
{
    SHA256((const unsigned char *)rp_id, strlen(rp_id), output);
    output[32] = assertion_flags;
    write_u32(output + 33, sign_count);
}

static struct json_object *assertion_body(EVP_PKEY *key, const char *rp_id,
                                          const char *challenge,
                                          const char *credential_id,
                                          uint32_t sign_count)
{
    unsigned char auth_data[37];
    unsigned char *signature = NULL;
    size_t signature_length = 0;
    char *client_json = client_data("webauthn.get", challenge, rp_id);
    char *client_b64;
    char *auth_b64;
    char *signature_b64;
    struct json_object *body = json_object_new_object();

    assertion_auth_data(rp_id, sign_count, auth_data);
    sign_assertion(key, auth_data, sizeof(auth_data), client_json,
                   &signature, &signature_length);
    client_b64 = base64url((const unsigned char *)client_json,
                           strlen(client_json));
    auth_b64 = base64url(auth_data, sizeof(auth_data));
    signature_b64 = base64url(signature, signature_length);
    json_object_object_add(body, "clientDataJSON",
                           json_object_new_string(client_b64));
    json_object_object_add(body, "authenticatorData",
                           json_object_new_string(auth_b64));
    json_object_object_add(body, "signature",
                           json_object_new_string(signature_b64));
    json_object_object_add(body, "credential_id",
                           json_object_new_string(credential_id));
    free(client_json);
    free(client_b64);
    free(auth_b64);
    free(signature_b64);
    free(signature);
    return body;
}

static const char *begin_authentication(struct json_object **response_out)
{
    struct json_object *response;
    struct json_object *options;
    const char *challenge;
    int status = 0;

    response = webd_passkey_authenticate_begin(NULL, &status);
    check(response != NULL && status == 200,
          "authenticate begin failed");
    options = json_object_value(response,
                                "publicKeyCredentialRequestOptions");
    challenge = json_string(options, "challenge");
    check(challenge != NULL, "authentication challenge missing");
    *response_out = response;
    return challenge;
}

static void expire_challenge(const char *challenge)
{
    unsigned char decoded[WEBD_PASSKEY_CHALLENGE_LEN];
    char hex[WEBD_PASSKEY_CHALLENGE_HEX_LEN + 1];
    char path[1024];
    struct json_object *record;
    size_t i;

    check(webd_base64url_decode(challenge, strlen(challenge), decoded,
                                sizeof(decoded)) ==
              WEBD_PASSKEY_CHALLENGE_LEN,
          "decode expiring challenge failed");
    for (i = 0; i < sizeof(decoded); i++)
        snprintf(hex + i * 2, sizeof(hex) - i * 2, "%02x", decoded[i]);
    check(snprintf(path, sizeof(path), "%s/auth-%s.json",
                   WEBD_PASSKEY_CHALLENGE_DIR, hex) < (int)sizeof(path),
          "challenge path overflow");
    record = json_object_from_file(path);
    check(record != NULL, "load challenge record failed");
    json_object_object_add(record, "created_at",
                           json_object_new_int64((int64_t)time(NULL) - 120));
    check(json_object_to_file_ext(path, record,
                                  JSON_C_TO_STRING_PLAIN) == 0,
          "write expired challenge failed");
    json_object_put(record);
}

static void register_phase(void)
{
    struct json_object *request;
    struct json_object *response;
    struct json_object *options;
    struct byte_buffer auth_data = {{0}, 0};
    struct byte_buffer attestation = {{0}, 0};
    unsigned char credential_id[16] = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f
    };
    EVP_PKEY *key;
    char rp_id[WEBD_PASSKEY_RP_ID_MAX + 1];
    const char *challenge;
    char *client_json;
    char *client_b64;
    char *attestation_b64;
    char *credential_b64;
    int status = 0;

    check(webd_passkey_init() == 0, "passkey init failed");
    webd_passkey_set_password_verifier(verify_password);
    request = body_with_two("password", "wrong-password", "display_name",
                            "Fixture key");
    response = webd_passkey_register_begin(request, "admin", "127.0.0.1",
                                            &status);
    check(status == 401 && response != NULL,
          "wrong registration password was not rejected");
    json_object_put(response);
    json_object_put(request);

    request = body_with_two("password", "correct-password", "display_name",
                            "Fixture key");
    response = webd_passkey_register_begin(request, "admin", "127.0.0.1",
                                            &status);
    check(status == 200 && response != NULL, "registration begin failed");
    options = json_object_value(response,
                                "publicKeyCredentialCreationOptions");
    challenge = json_string(options, "challenge");
    check(challenge != NULL, "registration challenge missing");
    check(webd_passkey_rp_id(rp_id, sizeof(rp_id)) == 0 && rp_id[0],
          "RP ID unavailable");

    key = generate_key();
    save_key(key);
    registration_auth_data(key, rp_id, credential_id, sizeof(credential_id),
                           &auth_data);
    attestation_object(&auth_data, &attestation);
    client_json = client_data("webauthn.create", challenge, rp_id);
    client_b64 = base64url((const unsigned char *)client_json,
                           strlen(client_json));
    attestation_b64 = base64url(attestation.data, attestation.length);
    credential_b64 = base64url(credential_id, sizeof(credential_id));
    json_object_put(response);
    json_object_put(request);

    request = json_object_new_object();
    json_object_object_add(request, "clientDataJSON",
                           json_object_new_string(client_b64));
    json_object_object_add(request, "attestationObject",
                           json_object_new_string(attestation_b64));
    json_object_object_add(request, "rawId",
                           json_object_new_string(credential_b64));
    response = webd_passkey_register_finish(request, "admin", &status);
    check(status == 200 && response != NULL,
          "registration finish failed");
    check(json_string(response, "credential_id") != NULL &&
              json_string(response, "credential_id_hex") != NULL,
          "registration response missing credential id");
    check(!strcmp(json_string(response, "friendly_name"), "Fixture key"),
          "begin display_name was not persisted");
    save_state(json_string(response, "credential_id"),
               json_string(response, "credential_id_hex"), rp_id);
    json_object_put(response);
    json_object_put(request);
    EVP_PKEY_free(key);
    free(client_json);
    free(client_b64);
    free(attestation_b64);
    free(credential_b64);
    puts("register_ok");
}

static void reauthentication_checks(EVP_PKEY *key, const char *rp_id,
                                     const char *credential_id, sqlite3 *config_db,
                                     sqlite3 *app_db)
{
    const char *binding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    struct json_object *begin, *options, *body, *response, *value;
    const char *challenge;
    int status;

    response = webd_passkey_reauthenticate_begin("other-user", binding, &status);
    check(status == 404, "reauth offered another user's credentials");
    json_object_put(response);
    for (int test = 0; test < 5; test++) {
        begin = webd_passkey_reauthenticate_begin("admin", binding, &status);
        check(status == 200, "reauth begin failed");
        options = json_object_value(begin, "publicKeyCredentialRequestOptions");
        check(options && !strcmp(json_string(options, "userVerification"), "required"),
              "reauth does not require UV");
        challenge = json_string(options, "challenge");
        assertion_flags = test == 0 ? 0x01 : 0x05;
        body = assertion_body(key, rp_id, challenge, credential_id, 3);
        if (test == 4) {
            response = webd_passkey_authenticate_finish(body, config_db, app_db, &status);
            check(status == 400, "reauth challenge accepted by login");
            json_object_put(response);
        }
        response = webd_passkey_reauthenticate_finish(body, config_db,
            test == 2 ? "other-user" : "admin", test == 1 ? other : binding, &status);
        if (test < 3) {
            check(status == (test == 0 ? 401 : 403), "reauth failed to bind UV/user/session-operation");
        } else if (test == 3) {
            check(status == 200 && !json_object_object_get_ex(response, "access_token", &value),
                  "reauth created login token or failed");
            json_object_put(response);
            response = webd_passkey_reauthenticate_finish(body, config_db, "admin", binding, &status);
            check(status == 400, "reauth replay accepted");
        } else {
            check(status == 401, "reauth sign count rollback accepted");
        }
        json_object_put(response); json_object_put(body); json_object_put(begin);
    }
    assertion_flags = 0x01;
    challenge = begin_authentication(&begin);
    body = assertion_body(key, rp_id, challenge, credential_id, 4);
    response = webd_passkey_reauthenticate_finish(body, config_db, "admin", binding, &status);
    check(status == 400, "login challenge accepted as operation confirmation");
    json_object_put(response); json_object_put(body); json_object_put(begin);
}

static void authenticate_phase(void)
{
    struct json_object *state;
    struct json_object *begin_response;
    struct json_object *body;
    struct json_object *response;
    struct json_object *credentials = NULL;
    struct json_object *item;
    sqlite3 *config_db = NULL;
    sqlite3 *app_db = NULL;
    struct webd_session_idle_info idle_info;
    EVP_PKEY *key;
    const char *credential_id;
    const char *credential_hex;
    const char *rp_id;
    const char *challenge;
    const char *access_token;
    char credential_path[1024];
    struct stat credential_stat;
    int status = 0;

    check(webd_passkey_init() == 0, "passkey re-init failed");
    webd_passkey_set_password_verifier(verify_password);
    state = load_state();
    credential_id = json_string(state, "credential_id");
    credential_hex = json_string(state, "credential_id_hex");
    rp_id = json_string(state, "rp_id");
    check(credential_id && credential_hex && rp_id,
          "persisted fixture state incomplete");
    key = load_key();
    open_databases(&config_db, &app_db);

    check(snprintf(credential_path, sizeof(credential_path), "%s/%s.json",
                   WEBD_PASSKEY_CRED_DIR, credential_hex) <
              (int)sizeof(credential_path),
          "credential path overflow");
    check(stat(credential_path, &credential_stat) == 0,
          "persisted credential missing after restart");
    check((credential_stat.st_mode & 0777) == 0600,
          "credential permissions are not 0600");

    response = webd_passkey_list("admin", &status);
    check(status == 200 && response != NULL &&
              json_object_object_get_ex(response, "credentials", &credentials) &&
              json_object_array_length(credentials) == 1,
          "persisted credential list failed");
    item = json_object_array_get_idx(credentials, 0);
    check(!strcmp(json_string(item, "friendly_name"), "Fixture key"),
          "persisted display name mismatch");
    json_object_put(response);

    body = body_with_two("credential_id", credential_id, "display_name",
                         "Renamed key");
    response = webd_passkey_rename(body, "admin", &status);
    check(status == 200 && response != NULL &&
              !strcmp(json_string(response, "friendly_name"), "Renamed key"),
          "display_name rename failed");
    json_object_put(response);
    json_object_put(body);

    challenge = begin_authentication(&begin_response);
    body = assertion_body(key, rp_id, challenge, credential_id, 2);
    response = webd_passkey_authenticate_finish(body, config_db, app_db,
                                                &status);
    check(status == 200 && response != NULL,
          "passkey authentication failed after restart");
    access_token = json_string(response, "access_token");
    check(access_token != NULL &&
              webd_session_idle_access_check(
                  config_db, app_db, access_token, (int64_t)time(NULL), 1,
                  &idle_info) == WEBD_SESSION_IDLE_OK &&
              !strcmp(idle_info.username, "admin"),
          "passkey token failed session idle validation");
    json_object_put(response);
    json_object_put(begin_response);

    response = webd_passkey_authenticate_finish(body, config_db, app_db,
                                                &status);
    check(status == 400 && response != NULL &&
              !strcmp(json_string(response, "error"), "challenge_expired"),
          "challenge replay was not rejected");
    json_object_put(response);
    json_object_put(body);

    challenge = begin_authentication(&begin_response);
    body = assertion_body(key, rp_id, challenge, credential_id, 2);
    response = webd_passkey_authenticate_finish(body, config_db, app_db,
                                                &status);
    check(status == 401 && response != NULL &&
              !strcmp(json_string(response, "error"),
                      "sign_count_rollback"),
          "sign count rollback was not rejected");
    json_object_put(response);
    json_object_put(body);
    json_object_put(begin_response);

    challenge = begin_authentication(&begin_response);
    body = assertion_body(key, rp_id, challenge, credential_id, 3);
    expire_challenge(challenge);
    response = webd_passkey_authenticate_finish(body, config_db, app_db,
                                                &status);
    check(status == 400 && response != NULL &&
              !strcmp(json_string(response, "error"), "challenge_expired"),
          "expired challenge was not rejected");
    json_object_put(response);
    json_object_put(body);
    json_object_put(begin_response);

    {
        unsigned char output[8];

        check(webd_base64url_decode("a", 1, output, sizeof(output)) < 0,
              "invalid base64url length accepted");
        check(webd_base64url_decode("AA!", 3, output, sizeof(output)) < 0,
              "invalid base64url alphabet accepted");
        check(webd_base64url_decode("AAAAAAAA", 8, output, 2) < 0,
              "base64url output overflow accepted");
    }

    reauthentication_checks(key, rp_id, credential_id, config_db, app_db);

    body = body_with_two("credential_id", credential_id, "password",
                         "wrong-password");
    response = webd_passkey_delete(body, "admin", "127.0.0.1", &status);
    check(status == 401 && response != NULL,
          "wrong deletion password was not rejected");
    json_object_put(response);
    json_object_put(body);
    body = body_with_two("credential_id", credential_id, "password",
                         "correct-password");
    response = webd_passkey_delete(body, "admin", "127.0.0.1", &status);
    check(status == 200 && response != NULL,
          "credential deletion failed");
    json_object_put(response);
    json_object_put(body);

    EVP_PKEY_free(key);
    sqlite3_close(config_db);
    sqlite3_close(app_db);
    json_object_put(state);
    puts("authenticate_ok");
}

int main(int argc, char **argv)
{
    if (argc != 2)
        fail("usage: passkey-core-fixture register|authenticate");
    if (!strcmp(argv[1], "register"))
        register_phase();
    else if (!strcmp(argv[1], "authenticate"))
        authenticate_phase();
    else
        fail("unknown phase");
    return 0;
}
