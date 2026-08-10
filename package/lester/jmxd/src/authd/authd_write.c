// SPDX-License-Identifier: GPL-2.0-or-later
#include "authd_internal.h"

#include <ctype.h>
#include <math.h>

#define AUTHD_PASSWORD_ITERATIONS 210000
#define AUTHD_VOUCHER_BATCH_MAX 1000

static sqlite3_stmt *authd_write_prepare(const char *sql)
{
    sqlite3_stmt *st = NULL;

    if (!g_authd_db || sqlite3_prepare_v2(g_authd_db, sql, -1, &st, NULL) != SQLITE_OK)
        return NULL;
    return st;
}

static const char *authd_req_string(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v = NULL;

    if (!o || !json_object_object_get_ex(o, key, &v) || !v ||
        !json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v);
}

static int authd_req_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

static int authd_req_has(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v);
}

static int64_t authd_req_i64(struct json_object *o, const char *key, int64_t def)
{
    struct json_object *v = NULL;

    if (!o || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    if (json_object_is_type(v, json_type_int))
        return json_object_get_int64(v);
    return def;
}

static int authd_safe_id(const char *s)
{
    size_t i, n;

    if (!s || !(n = strlen(s)) || n > 95)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '-' && c != '_' && c != '.' && c != ':')
            return 0;
    }
    return 1;
}

static int authd_text_ok(const char *s, size_t max_len, int required)
{
    size_t i, n;

    if (!s)
        return !required;
    n = strlen(s);
    if ((required && n == 0) || n > max_len)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 && c != '\t')
            return 0;
    }
    return 1;
}

static int authd_account_name_ok(const char *s)
{
    size_t i, n;

    if (!s || !(n = strlen(s)) || n > 96)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '-' && c != '_' && c != '.' && c != '@')
            return 0;
    }
    return 1;
}

static int authd_voucher_code_ok(const char *s)
{
    size_t i, n;

    if (!s || (n = strlen(s)) < 6 || n > 64)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '-' && c != '_')
            return 0;
    }
    return 1;
}

static void authd_hex(const unsigned char *input, size_t input_len, char *output)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < input_len; i++) {
        output[i * 2] = digits[input[i] >> 4];
        output[i * 2 + 1] = digits[input[i] & 15];
    }
    output[input_len * 2] = '\0';
}

static int authd_random_id(const char *prefix, char *out, size_t out_len)
{
    unsigned char random[12];
    char hex[sizeof(random) * 2 + 1];

    if (!out || out_len < strlen(prefix) + sizeof(hex) + 1 || RAND_bytes(random, sizeof(random)) != 1)
        return -1;
    authd_hex(random, sizeof(random), hex);
    snprintf(out, out_len, "%s%s", prefix, hex);
    return 0;
}

static int authd_write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t n = write(fd, buf + offset, len - offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        offset += (size_t)n;
    }
    return 0;
}

static int authd_secret_key(unsigned char key[32])
{
    int fd;
    int dirfd;
    size_t offset = 0;
    struct stat st;
    int write_ok;

    fd = open(AUTHD_SECRET_KEY_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != 32 ||
            (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            close(fd);
            return -1;
        }
        while (offset < 32) {
            ssize_t n = read(fd, key + offset, 32 - offset);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) {
                close(fd);
                OPENSSL_cleanse(key, 32);
                return -1;
            }
            offset += (size_t)n;
        }
        close(fd);
        return 0;
    }
    if (errno != ENOENT || RAND_priv_bytes(key, 32) != 1)
        return -1;
    fd = open(AUTHD_SECRET_KEY_PATH, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        OPENSSL_cleanse(key, 32);
        return errno == EEXIST ? authd_secret_key(key) : -1;
    }
    write_ok = authd_write_all(fd, key, 32) == 0 && fsync(fd) == 0;
    if (close(fd) != 0)
        write_ok = 0;
    if (!write_ok) {
        unlink(AUTHD_SECRET_KEY_PATH);
        OPENSSL_cleanse(key, 32);
        return -1;
    }
    dirfd = open("/etc/dreamingwrt", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fsync(dirfd) != 0) {
        if (dirfd >= 0) close(dirfd);
        unlink(AUTHD_SECRET_KEY_PATH);
        OPENSSL_cleanse(key, 32);
        return -1;
    }
    close(dirfd);
    return 0;
}

static int authd_secret_encrypt(const char *plain, char *out, size_t out_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[32], nonce[12], tag[16], cipher[512];
    char nonce_hex[25], tag_hex[33], cipher_hex[1025];
    size_t plain_len = strlen(plain ? plain : "");
    int len = 0, total = 0, ok = -1;

    if (!plain || plain_len < 1 || plain_len > 256 ||
        authd_secret_key(key) != 0 || RAND_bytes(nonce, sizeof(nonce)) != 1)
        return -1;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, cipher, &len, (const unsigned char *)plain,
                          (int)plain_len) != 1)
        goto done;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, cipher + total, &len) != 1)
        goto done;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto done;
    authd_hex(nonce, sizeof(nonce), nonce_hex);
    authd_hex(tag, sizeof(tag), tag_hex);
    authd_hex(cipher, (size_t)total, cipher_hex);
    if (snprintf(out, out_len, "v1:%s:%s:%s", nonce_hex, tag_hex, cipher_hex) >=
        (int)out_len)
        goto done;
    ok = 0;
done:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(cipher, sizeof(cipher));
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int authd_row_exists(const char *table, const char *id)
{
    char sql[160];
    sqlite3_stmt *st;
    int found = 0;

    if (!authd_safe_id(id))
        return 0;
    snprintf(sql, sizeof(sql), "SELECT 1 FROM %s WHERE id=?1", table);
    st = authd_write_prepare(sql);
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        found = sqlite3_step(st) == SQLITE_ROW;
    }
    sqlite3_finalize(st);
    return found;
}

static struct json_object *authd_write_success(const char *id, const char *action)
{
    struct json_object *data = json_object_new_object();

    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "id", json_object_new_string(id ? id : ""));
    json_object_object_add(data, "action", json_object_new_string(action ? action : "saved"));
    json_object_object_add(data, "updated_at", json_object_new_int64(authd_now_s()));
    return authd_envelope(data);
}

static int64_t authd_parse_duration_text(const char *text)
{
    double value;
    char unit[32] = "";

    if (!text || !text[0] || sscanf(text, "%lf %31s", &value, unit) < 1 ||
        !isfinite(value) || value < 0)
        return -1;
    if (!unit[0] || !strcasecmp(unit, "s") || !strcasecmp(unit, "sec") ||
        strstr(unit, "秒"))
        return (int64_t)llround(value);
    if (!strcasecmp(unit, "m") || !strcasecmp(unit, "min") || strstr(unit, "分"))
        return (int64_t)llround(value * 60.0);
    if (!strcasecmp(unit, "h") || !strcasecmp(unit, "hour") || strstr(unit, "时"))
        return (int64_t)llround(value * 3600.0);
    if (!strcasecmp(unit, "d") || !strcasecmp(unit, "day") || strstr(unit, "天"))
        return (int64_t)llround(value * 86400.0);
    return -1;
}

static int64_t authd_duration_value(struct json_object *request, const char *seconds_key,
                                    const char *text_key, int64_t def)
{
    struct json_object *v = NULL;
    const char *text;

    if (request && json_object_object_get_ex(request, seconds_key, &v) && v &&
        json_object_is_type(v, json_type_int))
        return json_object_get_int64(v);
    text = authd_req_string(request, text_key, NULL);
    return text ? authd_parse_duration_text(text) : def;
}

static int64_t authd_rate_value(struct json_object *request, const char *bps_key,
                                const char *ui_key, int64_t def)
{
    struct json_object *v = NULL;
    const char *text;
    double value;
    char unit[32] = "";

    if (request && json_object_object_get_ex(request, bps_key, &v) && v &&
        json_object_is_type(v, json_type_int))
        return json_object_get_int64(v);
    if (!request || !json_object_object_get_ex(request, ui_key, &v) || !v)
        return def;
    if (json_object_is_type(v, json_type_int) || json_object_is_type(v, json_type_double))
        return (int64_t)llround(json_object_get_double(v) * 1000000.0);
    text = json_object_is_type(v, json_type_string) ? json_object_get_string(v) : NULL;
    if (!text || sscanf(text, "%lf %31s", &value, unit) < 1 || !isfinite(value) || value < 0)
        return -1;
    if (!unit[0] || !strcasecmp(unit, "mbps") || !strcasecmp(unit, "m"))
        return (int64_t)llround(value * 1000000.0);
    if (!strcasecmp(unit, "kbps") || !strcasecmp(unit, "k"))
        return (int64_t)llround(value * 1000.0);
    if (!strcasecmp(unit, "gbps") || !strcasecmp(unit, "g"))
        return (int64_t)llround(value * 1000000000.0);
    if (!strcasecmp(unit, "bps"))
        return (int64_t)llround(value);
    return -1;
}

static int64_t authd_price_minor(struct json_object *request, int64_t def)
{
    struct json_object *v = NULL;

    if (request && json_object_object_get_ex(request, "price_minor", &v) && v &&
        json_object_is_type(v, json_type_int))
        return json_object_get_int64(v);
    if (request && json_object_object_get_ex(request, "price", &v) && v &&
        (json_object_is_type(v, json_type_int) || json_object_is_type(v, json_type_double))) {
        double value = json_object_get_double(v);
        if (!isfinite(value) || value < 0 || value > 1000000000.0)
            return -1;
        return (int64_t)llround(value * 100.0);
    }
    return def;
}

static int64_t authd_amount_minor(struct json_object *request, int64_t def)
{
    struct json_object *v = NULL;

    if (request && json_object_object_get_ex(request, "amount_minor", &v) && v &&
        json_object_is_type(v, json_type_int))
        return json_object_get_int64(v);
    if (request && json_object_object_get_ex(request, "amount", &v) && v &&
        (json_object_is_type(v, json_type_int) || json_object_is_type(v, json_type_double))) {
        double value = json_object_get_double(v);
        if (!isfinite(value) || value < 0 || value > 1000000000.0)
            return -1;
        return (int64_t)llround(value * 100.0);
    }
    return def;
}

static int64_t authd_time_value(struct json_object *request, const char *key, int64_t def)
{
    struct json_object *v = NULL;
    const char *text;
    struct tm tmv;
    int year, month, day, hour = 0, minute = 0, second = 0;

    if (!request || !json_object_object_get_ex(request, key, &v) || !v)
        return def;
    if (json_object_is_type(v, json_type_int))
        return json_object_get_int64(v);
    text = json_object_is_type(v, json_type_string) ? json_object_get_string(v) : NULL;
    if (!text || !text[0])
        return 0;
    if (sscanf(text, "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) < 5)
        return -1;
    if (year < 2020 || year > 2200 || month < 1 || month > 12 || day < 1 || day > 31 ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60)
        return -1;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year = year - 1900;
    tmv.tm_mon = month - 1;
    tmv.tm_mday = day;
    tmv.tm_hour = hour;
    tmv.tm_min = minute;
    tmv.tm_sec = second;
    tmv.tm_isdst = -1;
    {
        struct tm check;
        time_t epoch = mktime(&tmv);
        if (epoch == (time_t)-1 || !localtime_r(&epoch, &check) ||
            check.tm_year != year - 1900 || check.tm_mon != month - 1 ||
            check.tm_mday != day || check.tm_hour != hour || check.tm_min != minute)
            return -1;
        return (int64_t)epoch;
    }
}

static int authd_password_hash(const char *password, char *out, size_t out_len)
{
    unsigned char salt[16], digest[32];
    char salt_hex[sizeof(salt) * 2 + 1], digest_hex[sizeof(digest) * 2 + 1];

    if (!password || strlen(password) < 8 || strlen(password) > 256 ||
        RAND_bytes(salt, sizeof(salt)) != 1 ||
        PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, sizeof(salt),
                          AUTHD_PASSWORD_ITERATIONS, EVP_sha256(), sizeof(digest), digest) != 1)
        return -1;
    authd_hex(salt, sizeof(salt), salt_hex);
    authd_hex(digest, sizeof(digest), digest_hex);
    if (snprintf(out, out_len, "pbkdf2-sha256$%d$%s$%s",
                 AUTHD_PASSWORD_ITERATIONS, salt_hex, digest_hex) >= (int)out_len)
        return -1;
    return 0;
}

static int authd_mac_normalize(const char *input, char *out, size_t out_len)
{
    unsigned int b[6];

    if (!input || !input[0]) {
        if (out_len) out[0] = '\0';
        return 0;
    }
    if (sscanf(input, "%2x:%2x:%2x:%2x:%2x:%2x", &b[0], &b[1], &b[2],
               &b[3], &b[4], &b[5]) != 6 || strlen(input) != 17)
        return -1;
    snprintf(out, out_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
    return 0;
}

static int authd_source_address_ok(const char *input)
{
    char buf[128], *slash;
    struct in_addr v4;
    struct in6_addr v6;
    long prefix;
    char *end = NULL;

    if (!input || !input[0] || strlen(input) >= sizeof(buf))
        return 0;
    snprintf(buf, sizeof(buf), "%s", input);
    slash = strchr(buf, '/');
    if (slash) *slash++ = '\0';
    if (inet_pton(AF_INET, buf, &v4) == 1) {
        if (!slash) return 1;
        prefix = strtol(slash, &end, 10);
        return end && !*end && prefix >= 0 && prefix <= 32;
    }
    if (inet_pton(AF_INET6, buf, &v6) == 1) {
        if (!slash) return 1;
        prefix = strtol(slash, &end, 10);
        return end && !*end && prefix >= 0 && prefix <= 128;
    }
    return 0;
}

static int authd_sources_json(struct json_object *request, char *out, size_t out_len,
                              const char *existing)
{
    struct json_object *value = NULL;
    int i, count;
    const char *text;

    if (!request || (!json_object_object_get_ex(request, "source_addresses", &value) &&
                     !json_object_object_get_ex(request, "allowed_source", &value))) {
        snprintf(out, out_len, "%s", existing ? existing : "[]");
        return 0;
    }
    if (json_object_is_type(value, json_type_string)) {
        text = json_object_get_string(value);
        if (!text[0]) {
            snprintf(out, out_len, "[]");
            return 0;
        }
        if (!authd_source_address_ok(text))
            return -1;
        snprintf(out, out_len, "[\"%s\"]", text);
        return 0;
    }
    if (!json_object_is_type(value, json_type_array) ||
        (count = json_object_array_length(value)) > 128)
        return -1;
    for (i = 0; i < count; i++) {
        struct json_object *item = json_object_array_get_idx(value, i);
        if (!item || !json_object_is_type(item, json_type_string) ||
            !authd_source_address_ok(json_object_get_string(item)))
            return -1;
    }
    text = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
    if (strlen(text) >= out_len)
        return -1;
    snprintf(out, out_len, "%s", text);
    return 0;
}

static int authd_package_exists(const char *id)
{
    return !id || !id[0] || authd_row_exists("authentication_packages", id);
}

struct json_object *authd_package_upsert(struct json_object *request)
{
    const char *id_in = authd_req_string(request, "id", "");
    const char *name = authd_req_string(request, "name", "");
    const char *currency = authd_req_string(request, "currency", "CNY");
    const char *note = authd_req_string(request, "note", "");
    int update = authd_req_bool(request, "_update", 0);
    int enabled = authd_req_bool(request, "enabled", 1);
    int64_t validity = authd_duration_value(request, "validity_seconds", "validity", 0);
    int64_t price = authd_price_minor(request, 0);
    int64_t up = authd_rate_value(request, "upload_bps", "up_rate", 0);
    int64_t down = authd_rate_value(request, "download_bps", "down_rate", 0);
    char id[96];
    sqlite3_stmt *st;
    int exists, rc;

    if (!authd_text_ok(name, 128, 1) || !authd_text_ok(note, 2048, 0) ||
        strlen(currency) != 3 || validity < 0 || price < 0 || up < 0 || down < 0)
        return authd_error("invalid_package", "invalid package fields");
    snprintf(id, sizeof(id), "%s", id_in);
    if (!id[0] && authd_random_id("pkg-", id, sizeof(id)) != 0)
        return authd_error("random_failed", "package id generation failed");
    if (!authd_safe_id(id))
        return authd_error("invalid_package_id", "invalid package id");
    exists = authd_row_exists("authentication_packages", id);
    if (update && !exists)
        return authd_error("package_not_found", "package does not exist");
    if (!update && exists)
        return authd_error("package_exists", "package id already exists");
    st = authd_write_prepare(
        "INSERT INTO authentication_packages(id,name,validity_seconds,price_minor,currency,download_bps,upload_bps,enabled,note,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,validity_seconds=excluded.validity_seconds,"
        "price_minor=excluded.price_minor,currency=excluded.currency,download_bps=excluded.download_bps,"
        "upload_bps=excluded.upload_bps,enabled=excluded.enabled,note=excluded.note,updated_at=excluded.updated_at");
    if (!st)
        return authd_error("storage_error", "package storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, validity);
    sqlite3_bind_int64(st, 4, price);
    sqlite3_bind_text(st, 5, currency, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, down);
    sqlite3_bind_int64(st, 7, up);
    sqlite3_bind_int(st, 8, enabled);
    sqlite3_bind_text(st, 9, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, authd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return authd_error("package_save_failed", "package could not be saved");
    return authd_write_success(id, exists ? "updated" : "created");
}

struct json_object *authd_package_delete(struct json_object *request)
{
    const char *id = authd_req_string(request, "id", "");
    sqlite3_stmt *st;
    int refs = 0;

    if (!authd_safe_id(id))
        return authd_error("invalid_package_id", "invalid package id");
    if (!authd_row_exists("authentication_packages", id))
        return authd_error("package_not_found", "package does not exist");
    st = authd_write_prepare("SELECT (SELECT COUNT(*) FROM authentication_accounts WHERE package_id=?1)+"
                             "(SELECT COUNT(*) FROM authentication_vouchers WHERE package_id=?1)");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) refs = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    if (refs > 0)
        return authd_error("package_in_use", "package is referenced by accounts or vouchers");
    st = authd_write_prepare("DELETE FROM authentication_packages WHERE id=?1");
    if (!st) return authd_error("storage_error", "package storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("package_delete_failed", "package could not be deleted");
    }
    sqlite3_finalize(st);
    return authd_write_success(id, "deleted");
}

static int authd_auth_type_ok(const char *type)
{
    static const char *types[] = {"web", "web_account", "pppoe", "pppoe_relay",
                                  "l2tp", "pptp", "openvpn", NULL};
    int i;
    for (i = 0; types[i]; i++) if (!strcmp(type, types[i])) return 1;
    return 0;
}

struct json_object *authd_account_upsert(struct json_object *request)
{
    const char *id_in = authd_req_string(request, "id", "");
    const char *username = authd_req_string(request, "username", authd_req_string(request, "account", ""));
    const char *name = authd_req_string(request, "display_name", authd_req_string(request, "name", ""));
    const char *auth_type = authd_req_string(request, "auth_type", "web_account");
    const char *package_id = authd_req_string(request, "package_id", "");
    const char *password = authd_req_string(request, "password", "");
    const char *contact = authd_req_string(request, "contact", authd_req_string(request, "phone", ""));
    const char *mac_in = authd_req_string(request, "bound_mac", authd_req_string(request, "mac", ""));
    const char *note = authd_req_string(request, "note", "");
    const char *status_in = authd_req_string(request, "status", "");
    int update = authd_req_bool(request, "_update", 0);
    int64_t expires = authd_time_value(request, "expires_at", 0);
    char id[96], mac[18], sources[8192], password_hash[256] = "", old_hash[256] = "", old_sources[8192] = "[]";
    char status[16] = "enabled";
    sqlite3_stmt *st;
    int exists, rc;

    snprintf(id, sizeof(id), "%s", id_in);
    if (!id[0] && authd_random_id("acct-", id, sizeof(id)) != 0)
        return authd_error("random_failed", "account id generation failed");
    if (!authd_safe_id(id) || !authd_account_name_ok(username) || !authd_text_ok(name, 128, 0) ||
        !authd_auth_type_ok(auth_type) || !authd_safe_id(package_id[0] ? package_id : "none") ||
        !authd_package_exists(package_id) || !authd_text_ok(contact, 256, 0) ||
        !authd_text_ok(note, 2048, 0) || expires < 0 || authd_mac_normalize(mac_in, mac, sizeof(mac)) != 0)
        return authd_error("invalid_account", "invalid account fields");
    exists = authd_row_exists("authentication_accounts", id);
    if (update && !exists)
        return authd_error("account_not_found", "account does not exist");
    if (!update && exists)
        return authd_error("account_exists", "account id already exists");
    if (exists) {
        st = authd_write_prepare("SELECT password_hash,allowed_source,status FROM authentication_accounts WHERE id=?1");
        if (st) {
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                snprintf(old_hash, sizeof(old_hash), "%s", authd_sqlite_text(st, 0, ""));
                snprintf(old_sources, sizeof(old_sources), "%s", authd_sqlite_text(st, 1, "[]"));
                snprintf(status, sizeof(status), "%s", authd_sqlite_text(st, 2, "enabled"));
            }
        }
        sqlite3_finalize(st);
    }
    if (!exists && !password[0])
        return authd_error("password_required", "new account requires a password");
    if (password[0]) {
        if (authd_password_hash(password, password_hash, sizeof(password_hash)) != 0)
            return authd_error("invalid_password", "password must be 8 to 256 characters");
    } else {
        snprintf(password_hash, sizeof(password_hash), "%s", old_hash);
    }
    if (status_in[0]) snprintf(status, sizeof(status), "%s", status_in);
    else if (request && json_object_object_get(request, "enabled"))
        snprintf(status, sizeof(status), "%s", authd_req_bool(request, "enabled", 1) ? "enabled" : "disabled");
    if (strcmp(status, "enabled") && strcmp(status, "disabled") && strcmp(status, "expired")) {
        OPENSSL_cleanse(password_hash, sizeof(password_hash));
        OPENSSL_cleanse(old_hash, sizeof(old_hash));
        return authd_error("invalid_account_status", "invalid account status");
    }
    if (authd_sources_json(request, sources, sizeof(sources), old_sources) != 0) {
        OPENSSL_cleanse(password_hash, sizeof(password_hash));
        OPENSSL_cleanse(old_hash, sizeof(old_hash));
        return authd_error("invalid_source_addresses", "source addresses must be valid IPv4 or IPv6 CIDRs");
    }
    st = authd_write_prepare(
        "INSERT INTO authentication_accounts(id,username,display_name,auth_type,package_id,password_hash,expires_at,"
        "contact,bound_mac,allowed_source,status,note,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13) "
        "ON CONFLICT(id) DO UPDATE SET username=excluded.username,display_name=excluded.display_name,"
        "auth_type=excluded.auth_type,package_id=excluded.package_id,password_hash=excluded.password_hash,"
        "expires_at=excluded.expires_at,contact=excluded.contact,bound_mac=excluded.bound_mac,"
        "allowed_source=excluded.allowed_source,status=excluded.status,note=excluded.note,updated_at=excluded.updated_at");
    if (!st) {
        OPENSSL_cleanse(password_hash, sizeof(password_hash));
        OPENSSL_cleanse(old_hash, sizeof(old_hash));
        return authd_error("storage_error", "account storage unavailable");
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, auth_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, package_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, password_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, expires);
    sqlite3_bind_text(st, 8, contact, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, mac, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, sources, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 11, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 12, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 13, authd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    OPENSSL_cleanse(password_hash, sizeof(password_hash));
    OPENSSL_cleanse(old_hash, sizeof(old_hash));
    if (rc != SQLITE_DONE) {
        if (sqlite3_extended_errcode(g_authd_db) == SQLITE_CONSTRAINT_UNIQUE)
            return authd_error("account_name_conflict", "account username already exists");
        return authd_error("account_save_failed", "account could not be saved");
    }
    return authd_write_success(id, exists ? "updated" : "created");
}

struct json_object *authd_account_delete(struct json_object *request)
{
    const char *id = authd_req_string(request, "id", "");
    sqlite3_stmt *st;
    int active = 0;

    if (!authd_safe_id(id)) return authd_error("invalid_account_id", "invalid account id");
    if (!authd_row_exists("authentication_accounts", id))
        return authd_error("account_not_found", "account does not exist");
    st = authd_write_prepare("SELECT COUNT(*) FROM authentication_sessions WHERE account_id=?1 AND ended_at=0 AND state IN ('authorized','online')");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) active = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    if (active > 0) return authd_error("account_has_active_sessions", "disconnect active sessions before deleting account");
    st = authd_write_prepare("DELETE FROM authentication_accounts WHERE id=?1");
    if (!st) return authd_error("storage_error", "account storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("account_delete_failed", "account could not be deleted");
    }
    sqlite3_finalize(st);
    return authd_write_success(id, "deleted");
}

static int authd_response_ok(struct json_object *response)
{
    struct json_object *ok = NULL;
    struct json_object *data = NULL;

    if (!response)
        return 0;
    if (json_object_object_get_ex(response, "ok", &ok) && ok &&
        !json_object_get_boolean(ok))
        return 0;
    if (json_object_object_get_ex(response, "data", &data) && data &&
        json_object_object_get_ex(data, "ok", &ok) && ok)
        return json_object_get_boolean(ok);
    return 1;
}

static const char *authd_response_error(struct json_object *response)
{
    struct json_object *data = NULL;
    struct json_object *error = NULL;

    if (response && json_object_object_get_ex(response, "data", &data) && data &&
        json_object_object_get_ex(data, "error", &error) && error)
        return json_object_get_string(error);
    return "write_failed";
}

struct json_object *authd_accounts_bulk(struct json_object *request)
{
    struct json_object *ids = NULL;
    int enabled = authd_req_bool(request, "enabled", 1);
    int count, i, changed;
    sqlite3_stmt *exists = NULL;
    sqlite3_stmt *active = NULL;
    sqlite3_stmt *update = NULL;
    struct json_object *data;

    if (!request || !json_object_object_get_ex(request, "ids", &ids) ||
        !ids || !json_object_is_type(ids, json_type_array) ||
        (count = json_object_array_length(ids)) < 1 || count > 500)
        return authd_error("invalid_account_batch", "ids must contain 1 to 500 account ids");
    if (sqlite3_exec(g_authd_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return authd_error("storage_busy", "account storage is busy");
    exists = authd_write_prepare("SELECT 1 FROM authentication_accounts WHERE id=?1");
    active = authd_write_prepare("SELECT 1 FROM authentication_sessions WHERE account_id=?1 AND ended_at=0 AND state IN ('authorized','online') LIMIT 1");
    update = authd_write_prepare("UPDATE authentication_accounts SET status=?2,updated_at=?3 WHERE id=?1");
    if (!exists || !active || !update)
        goto storage_failed;
    for (i = 0; i < count; i++) {
        struct json_object *item = json_object_array_get_idx(ids, i);
        const char *id = item && json_object_is_type(item, json_type_string) ?
                         json_object_get_string(item) : "";

        if (!authd_safe_id(id)) {
            sqlite3_finalize(exists); sqlite3_finalize(active); sqlite3_finalize(update);
            sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
            return authd_error("invalid_account_id", "batch contains an invalid account id");
        }
        sqlite3_reset(exists); sqlite3_clear_bindings(exists);
        sqlite3_bind_text(exists, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(exists) != SQLITE_ROW) {
            sqlite3_finalize(exists); sqlite3_finalize(active); sqlite3_finalize(update);
            sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
            return authd_error("account_not_found", "batch account does not exist");
        }
        if (!enabled) {
            sqlite3_reset(active); sqlite3_clear_bindings(active);
            sqlite3_bind_text(active, 1, id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(active) == SQLITE_ROW) {
                sqlite3_finalize(exists); sqlite3_finalize(active); sqlite3_finalize(update);
                sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
                return authd_error("account_has_active_sessions", "disconnect active sessions before disabling account");
            }
        }
        sqlite3_reset(update); sqlite3_clear_bindings(update);
        sqlite3_bind_text(update, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(update, 2, enabled ? "enabled" : "disabled", -1, SQLITE_STATIC);
        sqlite3_bind_int64(update, 3, authd_now_s());
        if (sqlite3_step(update) != SQLITE_DONE)
            goto storage_failed;
    }
    sqlite3_finalize(exists); sqlite3_finalize(active); sqlite3_finalize(update);
    if (sqlite3_exec(g_authd_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
        return authd_error("account_batch_failed", "account batch commit failed");
    }
    changed = count;
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "updated", json_object_new_int(changed));
    json_object_object_add(data, "enabled", json_object_new_boolean(enabled));
    return authd_envelope(data);

storage_failed:
    sqlite3_finalize(exists); sqlite3_finalize(active); sqlite3_finalize(update);
    sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
    return authd_error("account_batch_failed", "account batch was rolled back");
}

static int authd_password_policy_bool(struct json_object *request, const char *key,
                                      struct json_object *out)
{
    struct json_object *value = NULL;

    if (!request || !json_object_object_get_ex(request, key, &value) || !value ||
        !json_object_is_type(value, json_type_boolean))
        return -1;
    json_object_object_add(out, key, json_object_new_boolean(json_object_get_boolean(value)));
    return 0;
}

struct json_object *authd_password_policy_set(struct json_object *request)
{
    static const char *keys[] = {"enabled", "pppoe", "l2tp", "pptp", "openvpn",
                                 "web_change", "web_logout", NULL};
    struct json_object *policy = json_object_new_object();
    sqlite3_stmt *st;
    const char *text;
    int i;

    if (authd_req_bool(request, "reset_to_defaults", 0)) {
        st = authd_write_prepare("UPDATE authentication_settings SET password_policy_json='{}',updated_at=?1 WHERE id=1");
        if (!st)
            return authd_error("storage_error", "password policy storage unavailable");
        sqlite3_bind_int64(st, 1, authd_now_s());
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            return authd_error("password_policy_save_failed", "password policy defaults could not be restored");
        }
        sqlite3_finalize(st);
        {
            struct json_object *data = json_object_new_object();
            json_object_object_add(data, "ok", json_object_new_boolean(1));
            json_object_object_add(data, "reset_to_defaults", json_object_new_boolean(1));
            json_object_object_add(data, "password_policy", json_object_new_object());
            return authd_envelope(data);
        }
    }

    for (i = 0; keys[i]; i++) {
        if (authd_password_policy_bool(request, keys[i], policy) != 0) {
            json_object_put(policy);
            return authd_error("invalid_password_policy", "all password policy fields must be booleans");
        }
    }
    text = json_object_to_json_string_ext(policy, JSON_C_TO_STRING_PLAIN);
    st = authd_write_prepare("UPDATE authentication_settings SET password_policy_json=?1,updated_at=?2 WHERE id=1");
    if (!st) {
        json_object_put(policy);
        return authd_error("storage_error", "password policy storage unavailable");
    }
    sqlite3_bind_text(st, 1, text, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, authd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        json_object_put(policy);
        return authd_error("password_policy_save_failed", "password policy could not be saved");
    }
    sqlite3_finalize(st);
    {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "password_policy", policy);
        return authd_envelope(data);
    }
}

static int authd_json_bool_if_present(struct json_object *request, const char *key,
                                      struct json_object *config)
{
    struct json_object *value = NULL;
    if (!authd_req_has(request, key))
        return 0;
    if (!json_object_object_get_ex(request, key, &value) || !value ||
        !json_object_is_type(value, json_type_boolean))
        return -1;
    json_object_object_add(config, key, json_object_new_boolean(json_object_get_boolean(value)));
    return 0;
}

static int authd_json_string_if_present(struct json_object *request, const char *key,
                                        size_t max_len, struct json_object *config)
{
    struct json_object *value = NULL;
    const char *text;
    if (!authd_req_has(request, key))
        return 0;
    if (!json_object_object_get_ex(request, key, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return -1;
    text = json_object_get_string(value);
    if (!authd_text_ok(text, max_len, 0))
        return -1;
    json_object_object_add(config, key, json_object_new_string(text));
    return 0;
}

static int authd_url_ok(const char *value, int allow_empty)
{
    const char *host;
    if (!value || !value[0])
        return allow_empty;
    if (!strncmp(value, "https://", 8))
        host = value + 8;
    else if (!strncmp(value, "http://", 7))
        host = value + 7;
    else
        return 0;
    return host[0] && !strchr(value, '\n') && !strchr(value, '\r') &&
           strlen(value) <= 2048;
}

static int authd_domain_ok(const char *value)
{
    size_t i, n;
    if (!value || !(n = strlen(value)) || n > 253 || value[0] == '-' ||
        value[n - 1] == '-')
        return 0;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!isalnum(c) && c != '.' && c != '-')
            return 0;
    }
    return strchr(value, '.') != NULL;
}

static int authd_string_array_copy(struct json_object *request, const char *key,
                                   int max_count, size_t max_len,
                                   struct json_object *config)
{
    struct json_object *value = NULL;
    int i, count;
    if (!authd_req_has(request, key))
        return 0;
    if (!json_object_object_get_ex(request, key, &value) || !value ||
        !json_object_is_type(value, json_type_array) ||
        (count = json_object_array_length(value)) > max_count)
        return -1;
    for (i = 0; i < count; i++) {
        struct json_object *item = json_object_array_get_idx(value, i);
        if (!item || !json_object_is_type(item, json_type_string) ||
            !authd_text_ok(json_object_get_string(item), max_len, 1))
            return -1;
    }
    json_object_object_add(config, key, json_object_get(value));
    return 0;
}

struct json_object *authd_web_set(struct json_object *request)
{
    static const char *bool_keys[] = {
        "redirect_enabled", "secure_portal", "password_enabled", "voucher_enabled",
        "radius_enabled", "external_api_enabled", "payment_enabled", "google_enabled",
        "free_access_enabled", "terms_required", "radius_disconnect_enabled", NULL
    };
    static const char *string_keys[] = {
        "expiration_unit", "redirect_url", "portal_hostname", "voucher_default_package_id",
        "radius_profile_id", "radius_auth_type", "external_api_url", "external_api_auth_url",
        "google_client_id", "google_domain", "payment_provider", "payment_currency", NULL
    };
    struct json_object *config = json_object_new_object();
    struct json_object *existing = NULL;
    sqlite3_stmt *st;
    const char *config_text;
    const char *guest_password = authd_req_string(request, "guest_password", "");
    char secret_cipher[1400] = "";
    int enabled = authd_req_bool(request, "enabled", 0);
    int64_t default_minutes = authd_req_i64(request, "default_authorization_minutes",
                              authd_req_i64(request, "default_expiration", 60));
    const char *expiration_unit = authd_req_string(request, "expiration_unit", "minutes");
    int64_t idle_seconds = authd_req_i64(request, "idle_timeout_seconds", -1);
    int radius_port = (int)authd_req_i64(request, "radius_disconnect_port", 3799);
    int i, secret_supplied = guest_password[0] != '\0';

    if (!request || !json_object_is_type(request, json_type_object)) {
        json_object_put(config);
        return authd_error("invalid_web_config", "WEB authentication config must be an object");
    }
    if (authd_req_bool(request, "reset_to_defaults", 0)) {
        if (sqlite3_exec(g_authd_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
            return authd_error("storage_busy", "WEB authentication storage is busy");
        st = authd_write_prepare("UPDATE authentication_settings SET enabled=0,default_auth_type='free',"
                                 "default_authorization_minutes=60,idle_timeout_seconds=900,"
                                 "config_json='{}',updated_at=?1 WHERE id=1");
        if (!st)
            goto storage_failed;
        sqlite3_bind_int64(st, 1, authd_now_s());
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            goto storage_failed;
        }
        sqlite3_finalize(st);
        st = authd_write_prepare("UPDATE authentication_portal SET secret_config_cipher='',updated_at=?1 WHERE id=1");
        if (!st)
            goto storage_failed;
        sqlite3_bind_int64(st, 1, authd_now_s());
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            goto storage_failed;
        }
        sqlite3_finalize(st);
        if (sqlite3_exec(g_authd_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
            goto storage_failed_no_stmt;
        json_object_put(config);
        return authd_write_success("web", "reset_to_defaults");
    }
    st = authd_write_prepare("SELECT config_json FROM authentication_settings WHERE id=1");
    if (st && sqlite3_step(st) == SQLITE_ROW)
        existing = json_tokener_parse(authd_sqlite_text(st, 0, "{}"));
    sqlite3_finalize(st);
    if (existing && json_object_is_type(existing, json_type_object)) {
        json_object_object_foreach(existing, key, value)
            json_object_object_add(config, key, json_object_get(value));
    }
    if (existing)
        json_object_put(existing);

    if (idle_seconds < 0)
        idle_seconds = authd_req_i64(request, "idle_timeout", 15) * 60;
    if (!authd_req_has(request, "default_authorization_minutes")) {
        if (!strcmp(expiration_unit, "hours"))
            default_minutes *= 60;
        else if (!strcmp(expiration_unit, "days"))
            default_minutes *= 1440;
        else if (strcmp(expiration_unit, "minutes"))
            goto invalid;
    }
    if (default_minutes < 1 || default_minutes > 525600 || idle_seconds < 0 ||
        idle_seconds > 31536000 || radius_port < 1 || radius_port > 65535)
        goto invalid;
    for (i = 0; bool_keys[i]; i++)
        if (authd_json_bool_if_present(request, bool_keys[i], config) != 0)
            goto invalid;
    for (i = 0; string_keys[i]; i++)
        if (authd_json_string_if_present(request, string_keys[i], 2048, config) != 0)
            goto invalid;
    if (authd_string_array_copy(request, "networks", 128, 128, config) != 0 ||
        authd_string_array_copy(request, "payment_package_ids", 128, 95, config) != 0)
        goto invalid;
    if (!authd_url_ok(authd_req_string(request, "redirect_url", ""), 1) ||
        !authd_url_ok(authd_req_string(request, "external_api_url", ""), 1) ||
        !authd_url_ok(authd_req_string(request, "external_api_auth_url", ""), 1))
        goto invalid;
    if (authd_req_has(request, "radius_auth_type")) {
        const char *type = authd_req_string(request, "radius_auth_type", "");
        if (strcmp(type, "pap") && strcmp(type, "chap") && strcmp(type, "mschapv2"))
            goto invalid;
    }
    if (secret_supplied && authd_secret_encrypt(guest_password, secret_cipher,
                                                 sizeof(secret_cipher)) != 0) {
        json_object_put(config);
        return authd_error("secret_storage_failed", "guest password could not be encrypted");
    }
    json_object_object_add(config, "radius_disconnect_port", json_object_new_int(radius_port));
    config_text = json_object_to_json_string_ext(config, JSON_C_TO_STRING_PLAIN);
    if (strlen(config_text) > 32768)
        goto invalid;
    if (sqlite3_exec(g_authd_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        json_object_put(config);
        return authd_error("storage_busy", "WEB authentication storage is busy");
    }
    st = authd_write_prepare("UPDATE authentication_settings SET enabled=?1,"
                             "default_authorization_minutes=?2,idle_timeout_seconds=?3,"
                             "config_json=?4,updated_at=?5 WHERE id=1");
    if (!st)
        goto storage_failed;
    sqlite3_bind_int(st, 1, enabled);
    sqlite3_bind_int64(st, 2, default_minutes);
    sqlite3_bind_int64(st, 3, idle_seconds);
    sqlite3_bind_text(st, 4, config_text, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, authd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        goto storage_failed;
    }
    sqlite3_finalize(st);
    if (secret_supplied) {
        st = authd_write_prepare("UPDATE authentication_portal SET secret_config_cipher=?1,updated_at=?2 WHERE id=1");
        if (!st)
            goto storage_failed;
        sqlite3_bind_text(st, 1, secret_cipher, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, authd_now_s());
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            goto storage_failed;
        }
        sqlite3_finalize(st);
    }
    if (sqlite3_exec(g_authd_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto storage_failed_no_stmt;
    OPENSSL_cleanse(secret_cipher, sizeof(secret_cipher));
    json_object_put(config);
    return authd_write_success("web", "updated");

invalid:
    json_object_put(config);
    return authd_error("invalid_web_config", "WEB authentication config contains invalid fields");
storage_failed:
    sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
storage_failed_no_stmt:
    sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
    OPENSSL_cleanse(secret_cipher, sizeof(secret_cipher));
    json_object_put(config);
    return authd_error("web_config_save_failed", "WEB authentication config could not be saved");
}

static int authd_color_ok(const char *value)
{
    size_t i;
    if (!value || strlen(value) != 7 || value[0] != '#')
        return 0;
    for (i = 1; i < 7; i++)
        if (!isxdigit((unsigned char)value[i]))
            return 0;
    return 1;
}

static int authd_asset_url_ok(const char *value)
{
    if (!value || !value[0])
        return 1;
    if (authd_url_ok(value, 0))
        return 1;
    return value[0] == '/' && value[1] != '/' && !strstr(value, "..") &&
           !strchr(value, '\n') && !strchr(value, '\r') && strlen(value) <= 8192;
}

struct json_object *authd_portal_set(struct json_object *request)
{
    static const char *bool_keys[] = {"background_image_enabled", "background_tile",
                                      "logo_enabled", "terms_enabled", NULL};
    static const char *string_keys[] = {"background_type", "background_image_url", "logo_url",
                                        "logo_position", "welcome_position", "terms_text", NULL};
    static const char *color_keys[] = {"background_color", "box_color", "text_color", "link_color",
                                       "button_color", "button_text_color", NULL};
    struct json_object *appearance = json_object_new_object();
    struct json_object *languages = NULL;
    sqlite3_stmt *st;
    const char *title = authd_req_string(request, "title", "");
    const char *welcome = authd_req_string(request, "welcome_text", "");
    const char *prompt = authd_req_string(request, "auth_prompt",
                         authd_req_string(request, "authentication_text", ""));
    const char *success = authd_req_string(request, "success_message",
                          authd_req_string(request, "success_text", ""));
    const char *button = authd_req_string(request, "button_text", "");
    const char *language = authd_req_string(request, "language", "zh-CN");
    const char *appearance_text;
    int box_opacity = (int)authd_req_i64(request, "box_opacity", 78);
    int box_radius = (int)authd_req_i64(request, "box_radius", 12);
    int logo_size = (int)authd_req_i64(request, "logo_size", 72);
    int i;

    if (authd_req_bool(request, "reset_to_defaults", 0)) {
        st = authd_write_prepare("UPDATE authentication_portal SET published_version=0,title='',"
                                 "welcome_text='',auth_prompt='',success_message='',button_text='',"
                                 "language='zh-CN',public_config_json='{}',updated_at=?1 WHERE id=1");
        if (!st) {
            json_object_put(appearance);
            return authd_error("storage_error", "portal storage unavailable");
        }
        sqlite3_bind_int64(st, 1, authd_now_s());
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            json_object_put(appearance);
            return authd_error("portal_config_save_failed", "portal defaults could not be restored");
        }
        sqlite3_finalize(st);
        json_object_put(appearance);
        return authd_write_success("portal", "reset_to_defaults");
    }

    if (!authd_text_ok(title, 160, 1) || !authd_text_ok(welcome, 4096, 0) ||
        !authd_text_ok(prompt, 4096, 0) || !authd_text_ok(success, 4096, 0) ||
        !authd_text_ok(button, 128, 1) || !authd_text_ok(language, 32, 1) ||
        box_opacity < 0 || box_opacity > 100 || box_radius < 0 || box_radius > 64 ||
        logo_size < 24 || logo_size > 320)
        goto invalid;
    for (i = 0; bool_keys[i]; i++)
        if (authd_json_bool_if_present(request, bool_keys[i], appearance) != 0)
            goto invalid;
    for (i = 0; string_keys[i]; i++)
        if (authd_json_string_if_present(request, string_keys[i], 8192, appearance) != 0)
            goto invalid;
    for (i = 0; color_keys[i]; i++) {
        const char *value = authd_req_string(request, color_keys[i], "");
        if (authd_req_has(request, color_keys[i])) {
            if (!authd_color_ok(value))
                goto invalid;
            json_object_object_add(appearance, color_keys[i], json_object_new_string(value));
        }
    }
    if (!authd_asset_url_ok(authd_req_string(request, "background_image_url", "")))
        goto invalid;
    if (!authd_asset_url_ok(authd_req_string(request, "logo_url", "")))
        goto invalid;
    if (json_object_object_get_ex(request, "languages", &languages) && languages) {
        int count, j;
        if (!json_object_is_type(languages, json_type_array) ||
            (count = json_object_array_length(languages)) > 16)
            goto invalid;
        for (j = 0; j < count; j++) {
            struct json_object *entry = json_object_array_get_idx(languages, j);
            if (!entry || !json_object_is_type(entry, json_type_string) ||
                !authd_text_ok(json_object_get_string(entry), 32, 1))
                goto invalid;
        }
        json_object_object_add(appearance, "languages", json_object_get(languages));
        if (json_object_array_length(languages) > 0)
            language = json_object_get_string(json_object_array_get_idx(languages, 0));
    }
    json_object_object_add(appearance, "box_opacity", json_object_new_int(box_opacity));
    json_object_object_add(appearance, "box_radius", json_object_new_int(box_radius));
    json_object_object_add(appearance, "logo_size", json_object_new_int(logo_size));
    appearance_text = json_object_to_json_string_ext(appearance, JSON_C_TO_STRING_PLAIN);
    if (strlen(appearance_text) > 32768)
        goto invalid;
    st = authd_write_prepare("UPDATE authentication_portal SET title=?1,welcome_text=?2,auth_prompt=?3,"
                             "success_message=?4,button_text=?5,language=?6,public_config_json=?7,updated_at=?8 WHERE id=1");
    if (!st) {
        json_object_put(appearance);
        return authd_error("storage_error", "portal storage unavailable");
    }
    sqlite3_bind_text(st, 1, title, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, welcome, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, prompt, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, success, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, button, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, language, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, appearance_text, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, authd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        json_object_put(appearance);
        return authd_error("portal_config_save_failed", "portal config could not be saved");
    }
    sqlite3_finalize(st);
    json_object_put(appearance);
    return authd_write_success("portal", "updated");
invalid:
    json_object_put(appearance);
    return authd_error("invalid_portal_config", "portal config contains invalid fields");
}

static int authd_access_value_ok(const char *type, const char *value)
{
    if (!strcmp(type, "cidr"))
        return authd_source_address_ok(value);
    if (!strcmp(type, "dns"))
        return authd_source_address_ok(value) && !strchr(value, '/');
    if (!strcmp(type, "domain"))
        return authd_domain_ok(value);
    return 0;
}

struct json_object *authd_access_rule_upsert(struct json_object *request)
{
    const char *id_in = authd_req_string(request, "id", "");
    const char *scope = authd_req_string(request, "scope",
                        authd_req_string(request, "rule_type", ""));
    const char *type = authd_req_string(request, "type",
                       authd_req_string(request, "target_type", ""));
    const char *value = authd_req_string(request, "value",
                        authd_req_string(request, "target_value", ""));
    const char *note = authd_req_string(request, "note", "");
    int enabled = authd_req_bool(request, "enabled", 1);
    int priority = (int)authd_req_i64(request, "priority", 1000);
    int update = authd_req_bool(request, "_update", 0);
    char id[96];
    sqlite3_stmt *st;
    int exists;

    snprintf(id, sizeof(id), "%s", id_in);
    if (!id[0] && authd_random_id("acr-", id, sizeof(id)) != 0)
        return authd_error("random_failed", "access rule id generation failed");
    if (!authd_safe_id(id) ||
        (strcmp(scope, "pre_authorization") && strcmp(scope, "post_authorization") &&
         strcmp(scope, "restricted_dns")) ||
        !authd_access_value_ok(type, value) || !authd_text_ok(note, 2048, 0) ||
        priority < 0 || priority > 1000000)
        return authd_error("invalid_access_rule", "access rule contains invalid fields");
    if (!strcmp(scope, "restricted_dns") && strcmp(type, "dns"))
        return authd_error("invalid_access_rule", "restricted DNS rule must use type=dns");
    exists = authd_row_exists("authentication_access_rules", id);
    if (update && !exists)
        return authd_error("access_rule_not_found", "access rule does not exist");
    if (!update && exists)
        return authd_error("access_rule_exists", "access rule id already exists");
    st = authd_write_prepare(
        "INSERT INTO authentication_access_rules(id,rule_type,target_type,target_value,enabled,priority,note,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8) ON CONFLICT(id) DO UPDATE SET "
        "rule_type=excluded.rule_type,target_type=excluded.target_type,target_value=excluded.target_value,"
        "enabled=excluded.enabled,priority=excluded.priority,note=excluded.note,updated_at=excluded.updated_at");
    if (!st)
        return authd_error("storage_error", "access rule storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, scope, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, value, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, enabled);
    sqlite3_bind_int(st, 6, priority);
    sqlite3_bind_text(st, 7, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 8, authd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("access_rule_save_failed", "access rule could not be saved");
    }
    sqlite3_finalize(st);
    return authd_write_success(id, exists ? "updated" : "created");
}

struct json_object *authd_access_rule_delete(struct json_object *request)
{
    const char *id = authd_req_string(request, "id", "");
    sqlite3_stmt *st;
    if (!authd_safe_id(id) || !authd_row_exists("authentication_access_rules", id))
        return authd_error("access_rule_not_found", "access rule does not exist");
    st = authd_write_prepare("DELETE FROM authentication_access_rules WHERE id=?1");
    if (!st)
        return authd_error("storage_error", "access rule storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("access_rule_delete_failed", "access rule could not be deleted");
    }
    sqlite3_finalize(st);
    return authd_write_success(id, "deleted");
}

/*
 * Attach the machine-readable hints the UI needs to point at the offending
 * field instead of showing a generic "save failed".
 */
static struct json_object *authd_field_error(const char *error, const char *message,
                                             const char *field,
                                             struct json_object *options)
{
    struct json_object *root = authd_error(error, message);
    struct json_object *data = NULL;

    if (json_object_object_get_ex(root, "data", &data) && data) {
        if (field && field[0])
            json_object_object_add(data, "field", json_object_new_string(field));
        if (options)
            json_object_object_add(data, "options", options);
    } else if (options) {
        json_object_put(options);
    }
    return root;
}

/*
 * Resolve the caller's delegated interface to a wan.id.
 *
 * An empty value is legal and means "use the preferred enabled WAN": the field
 * is optional in the UI, and rejecting empty input made every default-shaped
 * create fail with delegated_interface_not_found. A non-empty value still has
 * to match an enabled line by id / ifname / device.
 *
 * Returns 1 on success, 0 when nothing matched, -1 on storage failure, and
 * writes to *fell_back when the value came from the default rather than input.
 */
static int authd_delegated_wan_normalize(const char *input, char *out, size_t out_len,
                                         int *fell_back)
{
    sqlite3_stmt *st;
    int found = 0;

    if (fell_back)
        *fell_back = 0;
    if (!input || !input[0]) {
        int rc = authd_delegated_interface_default(out, out_len);

        if (rc == 1 && fell_back)
            *fell_back = 1;
        return rc;
    }
    if (!authd_text_ok(input, 128, 1))
        return 0;
    st = authd_write_prepare(
        "SELECT id FROM wan WHERE enabled=1 AND (id=?1 OR ifname=?1 OR device=?1) "
        "ORDER BY CASE WHEN id=?1 THEN 0 WHEN ifname=?1 THEN 1 ELSE 2 END LIMIT 1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, input, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(out, out_len, "%s", authd_sqlite_text(st, 0, ""));
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

static int authd_delegated_account_exists(const char *account)
{
    sqlite3_stmt *st;
    int found = 0;
    if (!account || !account[0])
        return 1;
    st = authd_write_prepare("SELECT 1 FROM authentication_accounts WHERE id=?1 OR username=?1 LIMIT 1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, account, -1, SQLITE_TRANSIENT);
    found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static int authd_delegated_username_conflict(const char *username, const char *id)
{
    sqlite3_stmt *st;
    int conflict = 0;
    st = authd_write_prepare("SELECT 1 FROM authentication_delegated_services WHERE username=?1 AND id<>?2 LIMIT 1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, id ? id : "", -1, SQLITE_TRANSIENT);
    conflict = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return conflict;
}

struct json_object *authd_delegated_upsert(struct json_object *request)
{
    const char *id_in = authd_req_string(request, "id", "");
    const char *line_name = authd_req_string(request, "line_name",
                            authd_req_string(request, "name", ""));
    const char *username = authd_req_string(request, "username",
                           authd_req_string(request, "account", ""));
    const char *password = authd_req_string(request, "password", "");
    const char *interface_in = authd_req_string(request, "interface", "");
    const char *delegated_account = authd_req_string(request, "delegated_account", "");
    const char *note = authd_req_string(request, "note", "");
    int enabled = authd_req_bool(request, "enabled", 1);
    int update = authd_req_bool(request, "_update", 0);
    char id[96], interface_id[96], password_cipher[1400] = "", old_cipher[1400] = "";
    sqlite3_stmt *st;
    struct json_object *response, *success_data = NULL;
    int exists, wan_found, account_found, conflict, rc, wan_fell_back = 0;

    snprintf(id, sizeof(id), "%s", id_in);
    if (!id[0] && authd_random_id("dlg-", id, sizeof(id)) != 0)
        return authd_error("random_failed", "delegated service id generation failed");
    if (!authd_safe_id(id) || !authd_text_ok(line_name, 128, 1) ||
        !authd_account_name_ok(username) || !authd_text_ok(delegated_account, 96, 0) ||
        !authd_text_ok(note, 2048, 0))
        return authd_error("invalid_delegated_service", "delegated service contains invalid fields");
    exists = authd_row_exists("authentication_delegated_services", id);
    if (update && !exists)
        return authd_error("delegated_service_not_found", "delegated service does not exist");
    if (!update && exists)
        return authd_error("delegated_service_exists", "delegated service id already exists");
    wan_found = authd_delegated_wan_normalize(interface_in, interface_id,
                                              sizeof(interface_id), &wan_fell_back);
    if (wan_found < 0)
        return authd_error("storage_error", "WAN configuration storage unavailable");
    if (!wan_found) {
        /*
         * Separate the two reasons: the caller named a line that is not an
         * enabled WAN, or there is no enabled WAN to fall back to at all. The
         * first is a fixable form error, the second is a network config
         * problem the user has to solve elsewhere.
         */
        if (!interface_in[0])
            return authd_field_error("delegated_interface_unavailable",
                                     "no enabled WAN is available for delegated dialing",
                                     "interface", NULL);
        return authd_field_error("delegated_interface_not_found",
                                 "delegated interface is not an enabled WAN",
                                 "interface", authd_delegated_interface_options());
    }
    account_found = authd_delegated_account_exists(delegated_account);
    if (account_found < 0)
        return authd_error("storage_error", "account storage unavailable");
    if (!account_found)
        return authd_field_error("delegated_account_not_found",
                                 "delegated account does not exist",
                                 "delegated_account", NULL);
    conflict = authd_delegated_username_conflict(username, id);
    if (conflict < 0)
        return authd_error("storage_error", "delegated service storage unavailable");
    if (conflict)
        return authd_error("delegated_username_conflict", "delegated username is already configured");
    if (update) {
        st = authd_write_prepare("SELECT password_cipher FROM authentication_delegated_services WHERE id=?1");
        if (!st)
            return authd_error("storage_error", "delegated service storage unavailable");
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            snprintf(old_cipher, sizeof(old_cipher), "%s", authd_sqlite_text(st, 0, ""));
        sqlite3_finalize(st);
    }
    if (password[0]) {
        if (authd_secret_encrypt(password, password_cipher, sizeof(password_cipher)) != 0)
            return authd_error("secret_storage_failed", "delegated password could not be encrypted");
    } else if (update && old_cipher[0]) {
        snprintf(password_cipher, sizeof(password_cipher), "%s", old_cipher);
    } else {
        return authd_field_error("password_required",
                                 "new delegated service requires a password",
                                 "password", NULL);
    }
    st = authd_write_prepare(
        "INSERT INTO authentication_delegated_services(id,line_name,username,password_cipher,interface,"
        "delegated_account,enabled,state,note,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10) ON CONFLICT(id) DO UPDATE SET "
        "line_name=excluded.line_name,username=excluded.username,password_cipher=excluded.password_cipher,"
        "interface=excluded.interface,delegated_account=excluded.delegated_account,enabled=excluded.enabled,"
        "state=excluded.state,note=excluded.note,updated_at=excluded.updated_at");
    if (!st) {
        OPENSSL_cleanse(password_cipher, sizeof(password_cipher));
        return authd_error("storage_error", "delegated service storage unavailable");
    }
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, line_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, password_cipher, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, interface_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, delegated_account, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 7, enabled);
    sqlite3_bind_text(st, 8, enabled ? "pending_runtime" : "disabled", -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 9, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, authd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    OPENSSL_cleanse(password_cipher, sizeof(password_cipher));
    OPENSSL_cleanse(old_cipher, sizeof(old_cipher));
    if (rc != SQLITE_DONE)
        return authd_error("delegated_service_save_failed", "delegated service could not be saved");
    response = authd_write_success(id, exists ? "updated" : "created");
    /*
     * Report the line that actually took effect. When the interface was left
     * empty we picked one, and the caller must be able to show which without
     * a second round trip.
     */
    if (json_object_object_get_ex(response, "data", &success_data) && success_data) {
        json_object_object_add(success_data, "interface", json_object_new_string(interface_id));
        json_object_object_add(success_data, "interface_defaulted",
                               json_object_new_boolean(wan_fell_back));
    }
    return response;
}

struct json_object *authd_delegated_delete(struct json_object *request)
{
    const char *id = authd_req_string(request, "id", "");
    sqlite3_stmt *st;
    if (!authd_safe_id(id) || !authd_row_exists("authentication_delegated_services", id))
        return authd_error("delegated_service_not_found", "delegated service does not exist");
    st = authd_write_prepare("DELETE FROM authentication_delegated_services WHERE id=?1");
    if (!st)
        return authd_error("storage_error", "delegated service storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("delegated_service_delete_failed", "delegated service could not be deleted");
    }
    sqlite3_finalize(st);
    return authd_write_success(id, "deleted");
}

struct json_object *authd_delegated_import(struct json_object *request)
{
    struct json_object *rows = NULL, *results = json_object_new_array();
    int confirm = authd_req_bool(request, "confirm", 0);
    int count, i;
    if (!request || !json_object_object_get_ex(request, "rows", &rows) || !rows ||
        !json_object_is_type(rows, json_type_array) ||
        (count = json_object_array_length(rows)) < 1 || count > 500) {
        json_object_put(results);
        return authd_error("invalid_import_rows", "rows must contain 1 to 500 delegated services");
    }
    if (sqlite3_exec(g_authd_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        json_object_put(results);
        return authd_error("storage_busy", "delegated import storage is busy");
    }
    for (i = 0; i < count; i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        struct json_object *response, *entry;
        if (!row || !json_object_is_type(row, json_type_object)) {
            sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
            json_object_put(results);
            return authd_error("invalid_import_row", "delegated import row must be an object");
        }
        response = authd_delegated_upsert(row);
        if (!authd_response_ok(response)) {
            const char *error = authd_response_error(response);
            struct json_object *root = authd_error(error, "delegated import was rolled back");
            struct json_object *data = NULL;
            sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
            if (json_object_object_get_ex(root, "data", &data) && data)
                json_object_object_add(data, "line", json_object_new_int(i + 1));
            json_object_put(response);
            json_object_put(results);
            return root;
        }
        entry = json_object_new_object();
        json_object_object_add(entry, "line", json_object_new_int(i + 1));
        if (confirm) {
            struct json_object *data = NULL;
            if (json_object_object_get_ex(response, "data", &data) && data)
                json_object_object_add(entry, "result", json_object_get(data));
        }
        json_object_array_add(results, entry);
        json_object_put(response);
    }
    if (!confirm)
        sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
    else if (sqlite3_exec(g_authd_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
        json_object_put(results);
        return authd_error("delegated_import_failed", "delegated import commit failed");
    }
    {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "validated", json_object_new_int(count));
        json_object_object_add(data, "imported", json_object_new_int(confirm ? count : 0));
        json_object_object_add(data, "dry_run", json_object_new_boolean(!confirm));
        json_object_object_add(data, "results", results);
        return authd_envelope(data);
    }
}

static int authd_time_hhmm_ok(const char *value)
{
    int hour, minute;
    char tail;
    return value && strlen(value) == 5 &&
           sscanf(value, "%2d:%2d%c", &hour, &minute, &tail) == 2 &&
           hour >= 0 && hour <= 23 && minute >= 0 && minute <= 59;
}

static int authd_public_address_ok(const char *input)
{
    char buf[128], *slash;
    struct in_addr v4;
    struct in6_addr v6;
    uint32_t address;
    long prefix;
    char *end = NULL;

    if (!input || !input[0] || strlen(input) >= sizeof(buf))
        return 0;
    snprintf(buf, sizeof(buf), "%s", input);
    slash = strchr(buf, '/');
    if (slash) *slash++ = '\0';
    if (inet_pton(AF_INET, buf, &v4) == 1) {
        if (slash) {
            prefix = strtol(slash, &end, 10);
            if (!end || *end || prefix < 0 || prefix > 32)
                return 0;
        }
        address = ntohl(v4.s_addr);
        if ((address >> 24) == 0 || (address >> 24) == 10 ||
            (address >> 24) == 127 || (address >> 24) >= 224 ||
            (address & 0xfff00000U) == 0xac100000U ||
            (address & 0xffff0000U) == 0xc0a80000U ||
            (address & 0xffff0000U) == 0xa9fe0000U ||
            (address & 0xffc00000U) == 0x64400000U)
            return 0;
        return 1;
    }
    if (inet_pton(AF_INET6, buf, &v6) == 1) {
        if (slash) {
            prefix = strtol(slash, &end, 10);
            if (!end || *end || prefix < 0 || prefix > 128)
                return 0;
        }
        return (v6.s6_addr[0] & 0xe0U) == 0x20U;
    }
    return 0;
}

static int authd_notification_string_array(struct json_object *request, const char *key,
                                           int max_count, size_t max_len,
                                           int (*validator)(const char *),
                                           struct json_object *config)
{
    struct json_object *value = NULL;
    int count, i;
    if (!authd_req_has(request, key)) {
        json_object_object_add(config, key, json_object_new_array());
        return 0;
    }
    if (!json_object_object_get_ex(request, key, &value) || !value ||
        !json_object_is_type(value, json_type_array) ||
        (count = json_object_array_length(value)) > max_count)
        return -1;
    for (i = 0; i < count; i++) {
        struct json_object *item = json_object_array_get_idx(value, i);
        const char *text;
        if (!item || !json_object_is_type(item, json_type_string))
            return -1;
        text = json_object_get_string(item);
        if (!authd_text_ok(text, max_len, 1) || (validator && !validator(text)))
            return -1;
    }
    json_object_object_add(config, key, json_object_get(value));
    return 0;
}

static int authd_notification_content(struct json_object *request,
                                      struct json_object *config)
{
    const char *input = authd_req_string(request, "content", "");
    char *sanitized;
    if (!authd_text_ok(input, 32768, 0))
        return -1;
    sanitized = authd_html_sanitize(input, 32768);
    if (!sanitized)
        return -1;
    json_object_object_add(config, "content", json_object_new_string(sanitized));
    free(sanitized);
    return 0;
}

static int authd_notification_config_build(struct json_object *request,
                                           const char *kind,
                                           struct json_object *config)
{
    const char *redirect = authd_req_string(request, "redirect_url", "");
    int countdown = (int)authd_req_i64(request, "countdown", 60);

    if (!request || !config || !kind ||
        (strcmp(kind, "realtime") && strcmp(kind, "expiry") &&
         strcmp(kind, "expired")))
        return -1;
    if (authd_notification_content(request, config) != 0 ||
        countdown < 0 || countdown > 86400 || !authd_url_ok(redirect, 1))
        return -1;
    json_object_object_add(config, "redirect_url", json_object_new_string(redirect));
    json_object_object_add(config, "countdown", json_object_new_int(countdown));
    if (!strcmp(kind, "realtime")) {
        if (authd_json_bool_if_present(request, "dial_users", config) != 0 ||
            authd_json_bool_if_present(request, "lan_users", config) != 0 ||
            authd_notification_string_array(request, "targets", 1000, 128,
                                             authd_source_address_ok, config) != 0 ||
            authd_notification_string_array(request, "groups", 1000, 128,
                                             NULL, config) != 0)
            return -1;
    } else if (!strcmp(kind, "expiry")) {
        int days_before = (int)authd_req_i64(request, "days_before", 5);
        if (days_before < 1 || days_before > 365 ||
            authd_notification_string_array(request, "times", 24, 5,
                                             authd_time_hhmm_ok, config) != 0)
            return -1;
        json_object_object_add(config, "days_before", json_object_new_int(days_before));
    } else if (authd_notification_string_array(request, "public_ip_allowlist", 1000, 128,
                                                authd_public_address_ok, config) != 0 ||
               authd_notification_string_array(request, "domain_allowlist", 1000, 253,
                                                authd_domain_ok, config) != 0) {
        return -1;
    }
    return strlen(json_object_to_json_string_ext(config, JSON_C_TO_STRING_PLAIN)) <= 131072 ? 0 : -1;
}

static struct json_object *authd_notification_saved_singleton(const char *kind,
                                                               int *enabled,
                                                               int64_t *updated_at)
{
    sqlite3_stmt *st;
    struct json_object *config = NULL;
    const char *text;

    st = authd_write_prepare(
        "SELECT enabled,config_json,updated_at FROM authentication_notifications WHERE kind=?1");
    if (!st)
        return NULL;
    sqlite3_bind_text(st, 1, kind, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (enabled)
            *enabled = sqlite3_column_int(st, 0) ? 1 : 0;
        text = authd_sqlite_text(st, 1, "{}");
        config = json_tokener_parse(text);
        if (!config || !json_object_is_type(config, json_type_object)) {
            if (config)
                json_object_put(config);
            config = NULL;
        }
        if (updated_at)
            *updated_at = sqlite3_column_int64(st, 2);
    }
    sqlite3_finalize(st);
    return config;
}

static struct json_object *authd_notification_saved_periodic(const char *id,
                                                              int *enabled,
                                                              int64_t *updated_at)
{
    sqlite3_stmt *st;
    struct json_object *config = NULL, *part;
    int col;

    if (!authd_safe_id(id))
        return NULL;
    st = authd_write_prepare(
        "SELECT name,audience_json,schedule_json,content_json,enabled,updated_at "
        "FROM authentication_notification_schedules WHERE id=?1");
    if (!st)
        return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        config = json_object_new_object();
        json_object_object_add(config, "id", json_object_new_string(id));
        json_object_object_add(config, "name",
                               json_object_new_string(authd_sqlite_text(st, 0, "")));
        for (col = 1; col <= 3; col++) {
            part = json_tokener_parse(authd_sqlite_text(st, col, "{}"));
            if (!part || !json_object_is_type(part, json_type_object)) {
                if (part)
                    json_object_put(part);
                json_object_put(config);
                config = NULL;
                break;
            }
            json_object_object_foreach(part, key, value)
                json_object_object_add(config, key, json_object_get(value));
            json_object_put(part);
        }
        if (config) {
            if (enabled)
                *enabled = sqlite3_column_int(st, 4) ? 1 : 0;
            if (updated_at)
                *updated_at = sqlite3_column_int64(st, 5);
        }
    }
    sqlite3_finalize(st);
    return config;
}

static int authd_periodic_preview_config_build(struct json_object *request,
                                                struct json_object *config)
{
    const char *name = authd_req_string(request, "name", "");
    const char *recipients = authd_req_string(request, "recipients", "");
    const char *schedule = authd_req_string(request, "schedule", "");
    const char *at = authd_req_string(request, "time", "");
    const char *redirect = authd_req_string(request, "redirect_url", "");
    const char *note = authd_req_string(request, "note", "");
    int countdown = (int)authd_req_i64(request, "countdown", 60);

    if (!authd_text_ok(name, 128, 1) || !authd_text_ok(recipients, 4096, 1) ||
        !authd_text_ok(schedule, 256, 1) || !authd_time_hhmm_ok(at) ||
        !authd_url_ok(redirect, 1) || !authd_text_ok(note, 2048, 0) ||
        countdown < 0 || countdown > 86400 ||
        authd_notification_content(request, config) != 0)
        return -1;
    json_object_object_add(config, "name", json_object_new_string(name));
    json_object_object_add(config, "recipients", json_object_new_string(recipients));
    json_object_object_add(config, "schedule", json_object_new_string(schedule));
    json_object_object_add(config, "time", json_object_new_string(at));
    json_object_object_add(config, "redirect_url", json_object_new_string(redirect));
    json_object_object_add(config, "countdown", json_object_new_int(countdown));
    json_object_object_add(config, "note", json_object_new_string(note));
    return strlen(json_object_to_json_string_ext(config, JSON_C_TO_STRING_PLAIN)) <= 131072 ? 0 : -1;
}

static void authd_notification_content_digest(const char *content, char output[65])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char *)(content ? content : ""),
           strlen(content ? content : ""), digest);
    authd_hex(digest, sizeof(digest), output);
}

struct json_object *authd_notification_preview(struct json_object *request)
{
    const char *kind = authd_req_string(request, "kind", "realtime");
    const char *source = authd_req_string(request, "source", "draft");
    const char *id = authd_req_string(request, "id", "");
    struct json_object *config = NULL, *data, *rendered;
    struct json_object *content_o = NULL;
    const char *content = "";
    char digest[65];
    int enabled = authd_req_bool(request, "enabled", 0);
    int64_t updated_at = 0;

    if (strcmp(kind, "realtime") && strcmp(kind, "expiry") &&
        strcmp(kind, "expired") && strcmp(kind, "periodic"))
        return authd_error("invalid_notification_kind", "notification kind is invalid");
    if (strcmp(source, "draft") && strcmp(source, "saved"))
        return authd_error("invalid_preview_source", "preview source must be draft or saved");
    if (!strcmp(source, "saved")) {
        config = !strcmp(kind, "periodic") ?
            authd_notification_saved_periodic(id, &enabled, &updated_at) :
            authd_notification_saved_singleton(kind, &enabled, &updated_at);
        if (!config)
            return authd_error("notification_not_found", "saved notification config was not found");
    } else {
        config = json_object_new_object();
        if ((!strcmp(kind, "periodic") &&
             authd_periodic_preview_config_build(request, config) != 0) ||
            (strcmp(kind, "periodic") &&
             authd_notification_config_build(request, kind, config) != 0)) {
            json_object_put(config);
            return authd_error("invalid_notification", "notification preview contains invalid fields");
        }
    }
    if (json_object_object_get_ex(config, "content", &content_o) && content_o &&
        json_object_is_type(content_o, json_type_string))
        content = json_object_get_string(content_o);
    authd_notification_content_digest(content, digest);
    rendered = json_object_new_object();
    json_object_object_add(rendered, "content_html", json_object_new_string(content));
    json_object_object_add(rendered, "content_sha256", json_object_new_string(digest));
    json_object_object_add(rendered, "sanitized", json_object_new_boolean(1));
    data = json_object_new_object();
    json_object_object_add(data, "contract",
                           json_object_new_string("authentication-notification-preview.v1"));
    json_object_object_add(data, "kind", json_object_new_string(kind));
    json_object_object_add(data, "source", json_object_new_string(source));
    json_object_object_add(data, "enabled", json_object_new_boolean(enabled));
    json_object_object_add(data, "updated_at", json_object_new_int64(updated_at));
    json_object_object_add(data, "config", config);
    json_object_object_add(data, "rendered", rendered);
    json_object_object_add(data, "delivery_attempted", json_object_new_boolean(0));
    json_object_object_add(data, "delivery_supported", json_object_new_boolean(0));
    json_object_object_add(data, "delivery_reason",
                           json_object_new_string("captive_portal_session_delivery_pending"));
    return authd_envelope(data);
}

struct json_object *authd_notification_set(struct json_object *request)
{
    const char *kind = authd_req_string(request, "kind", authd_req_string(request, "id", ""));
    struct json_object *config = json_object_new_object();
    int enabled = authd_req_bool(request, "enabled", 0);
    sqlite3_stmt *st;
    const char *config_text;

    if (strcmp(kind, "realtime") && strcmp(kind, "expiry") && strcmp(kind, "expired")) {
        json_object_put(config);
        return authd_error("invalid_notification_kind", "notification kind is invalid");
    }
    if (authd_req_bool(request, "reset_to_defaults", 0)) {
        st = authd_write_prepare("UPDATE authentication_notifications SET enabled=0,config_json='{}',updated_at=?1 WHERE kind=?2");
        if (!st) {
            json_object_put(config);
            return authd_error("storage_error", "notification storage unavailable");
        }
        sqlite3_bind_int64(st, 1, authd_now_s());
        sqlite3_bind_text(st, 2, kind, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_DONE) {
            sqlite3_finalize(st);
            json_object_put(config);
            return authd_error("notification_save_failed", "notification defaults could not be restored");
        }
        sqlite3_finalize(st);
        json_object_put(config);
        return authd_write_success(kind, "reset_to_defaults");
    }
    if (authd_notification_config_build(request, kind, config) != 0)
        goto invalid;
    config_text = json_object_to_json_string_ext(config, JSON_C_TO_STRING_PLAIN);
    st = authd_write_prepare("UPDATE authentication_notifications SET enabled=?1,config_json=?2,updated_at=?3 WHERE kind=?4");
    if (!st) {
        json_object_put(config);
        return authd_error("storage_error", "notification storage unavailable");
    }
    sqlite3_bind_int(st, 1, enabled);
    sqlite3_bind_text(st, 2, config_text, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, authd_now_s());
    sqlite3_bind_text(st, 4, kind, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        json_object_put(config);
        return authd_error("notification_save_failed", "notification config could not be saved");
    }
    sqlite3_finalize(st);
    json_object_put(config);
    return authd_write_success(kind, "updated");
invalid:
    json_object_put(config);
    return authd_error("invalid_notification", "notification config contains invalid fields");
}

struct json_object *authd_notification_schedule_upsert(struct json_object *request)
{
    const char *id_in = authd_req_string(request, "id", "");
    const char *name = authd_req_string(request, "name", "");
    const char *recipients = authd_req_string(request, "recipients", "");
    const char *schedule_text = authd_req_string(request, "schedule", "");
    const char *time_text = authd_req_string(request, "time", "");
    const char *redirect = authd_req_string(request, "redirect_url", "");
    const char *note = authd_req_string(request, "note", "");
    int countdown = (int)authd_req_i64(request, "countdown", 60);
    int enabled = authd_req_bool(request, "enabled", 1);
    int update = authd_req_bool(request, "_update", 0);
    struct json_object *audience = json_object_new_object();
    struct json_object *schedule = json_object_new_object();
    struct json_object *content = json_object_new_object();
    char id[96];
    char *sanitized = NULL;
    sqlite3_stmt *st;
    int exists, rc;

    snprintf(id, sizeof(id), "%s", id_in);
    if (!id[0] && authd_random_id("nts-", id, sizeof(id)) != 0)
        goto random_failed;
    if (!authd_safe_id(id) || !authd_text_ok(name, 128, 1) ||
        !authd_text_ok(recipients, 4096, 1) || !authd_text_ok(schedule_text, 256, 1) ||
        !authd_time_hhmm_ok(time_text) || !authd_url_ok(redirect, 1) ||
        !authd_text_ok(note, 2048, 0) || countdown < 0 || countdown > 86400)
        goto invalid;
    sanitized = authd_html_sanitize(authd_req_string(request, "content", ""), 32768);
    if (!sanitized)
        goto invalid;
    exists = authd_row_exists("authentication_notification_schedules", id);
    if (update && !exists)
        goto not_found;
    if (!update && exists)
        goto exists_error;
    json_object_object_add(audience, "recipients", json_object_new_string(recipients));
    json_object_object_add(schedule, "schedule", json_object_new_string(schedule_text));
    json_object_object_add(schedule, "time", json_object_new_string(time_text));
    json_object_object_add(content, "content", json_object_new_string(sanitized));
    json_object_object_add(content, "redirect_url", json_object_new_string(redirect));
    json_object_object_add(content, "countdown", json_object_new_int(countdown));
    json_object_object_add(content, "note", json_object_new_string(note));
    st = authd_write_prepare(
        "INSERT INTO authentication_notification_schedules(id,notification_id,name,audience_json,schedule_json,"
        "content_json,enabled,created_at,updated_at) VALUES(?1,'periodic',?2,?3,?4,?5,?6,?7,?7) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name,audience_json=excluded.audience_json,"
        "schedule_json=excluded.schedule_json,content_json=excluded.content_json,enabled=excluded.enabled,"
        "updated_at=excluded.updated_at");
    if (!st)
        goto storage_failed;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, json_object_to_json_string_ext(audience, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, json_object_to_json_string_ext(schedule, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, json_object_to_json_string_ext(content, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, enabled);
    sqlite3_bind_int64(st, 7, authd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    free(sanitized);
    json_object_put(audience); json_object_put(schedule); json_object_put(content);
    if (rc != SQLITE_DONE)
        return authd_error("notification_schedule_save_failed", "periodic notification could not be saved");
    return authd_write_success(id, exists ? "updated" : "created");
random_failed:
    free(sanitized); json_object_put(audience); json_object_put(schedule); json_object_put(content);
    return authd_error("random_failed", "notification schedule id generation failed");
invalid:
    free(sanitized); json_object_put(audience); json_object_put(schedule); json_object_put(content);
    return authd_error("invalid_notification_schedule", "periodic notification contains invalid fields");
not_found:
    free(sanitized); json_object_put(audience); json_object_put(schedule); json_object_put(content);
    return authd_error("notification_schedule_not_found", "periodic notification does not exist");
exists_error:
    free(sanitized); json_object_put(audience); json_object_put(schedule); json_object_put(content);
    return authd_error("notification_schedule_exists", "periodic notification id already exists");
storage_failed:
    free(sanitized); json_object_put(audience); json_object_put(schedule); json_object_put(content);
    return authd_error("storage_error", "notification schedule storage unavailable");
}

struct json_object *authd_notification_schedule_delete(struct json_object *request)
{
    const char *id = authd_req_string(request, "id", "");
    sqlite3_stmt *st;
    if (!authd_safe_id(id) || !authd_row_exists("authentication_notification_schedules", id))
        return authd_error("notification_schedule_not_found", "periodic notification does not exist");
    st = authd_write_prepare("DELETE FROM authentication_notification_schedules WHERE id=?1");
    if (!st)
        return authd_error("storage_error", "notification schedule storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("notification_schedule_delete_failed", "periodic notification could not be deleted");
    }
    sqlite3_finalize(st);
    return authd_write_success(id, "deleted");
}

static int authd_ledger_account_snapshot(const char *account_ref,
                                         char *account_id, size_t account_id_len,
                                         char *username, size_t username_len,
                                         char *display_name, size_t display_name_len)
{
    sqlite3_stmt *st;
    int found = 0;

    if (!account_ref || !account_ref[0] || !authd_text_ok(account_ref, 96, 1))
        return 0;
    st = authd_write_prepare(
        "SELECT id,username,display_name FROM authentication_accounts "
        "WHERE id=?1 OR username=?1 ORDER BY CASE WHEN id=?1 THEN 0 ELSE 1 END LIMIT 1");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, account_ref, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(account_id, account_id_len, "%s", authd_sqlite_text(st, 0, ""));
        snprintf(username, username_len, "%s", authd_sqlite_text(st, 1, ""));
        snprintf(display_name, display_name_len, "%s", authd_sqlite_text(st, 2, ""));
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

struct json_object *authd_ledger_upsert(struct json_object *request)
{
    const char *id_in = authd_req_string(request, "id", "");
    const char *account_ref = authd_req_string(request, "account_id",
                              authd_req_string(request, "account",
                              authd_req_string(request, "username", "")));
    const char *operator_input = authd_req_string(request, "operator", "");
    const char *currency_input = authd_req_string(request, "currency", "CNY");
    const char *description_input = authd_req_string(request, "description", "");
    const char *note_input = authd_req_string(request, "note", "");
    int update = authd_req_bool(request, "_update", 0);
    int64_t charged_at = authd_time_value(request, "charged_at", 0);
    int64_t amount_minor = authd_amount_minor(request, -1);
    int64_t created_at = authd_now_s();
    char id[96], account_id[96] = "", username[97] = "", display_name[129] = "";
    char operator_name[129], currency[4], description[513], note[2049];
    sqlite3_stmt *st;
    int exists, account_found, rc;

    snprintf(id, sizeof(id), "%s", id_in);
    snprintf(operator_name, sizeof(operator_name), "%s", operator_input);
    snprintf(currency, sizeof(currency), "%s", currency_input);
    snprintf(description, sizeof(description), "%s", description_input);
    snprintf(note, sizeof(note), "%s", note_input);
    if (!id[0] && authd_random_id("led-", id, sizeof(id)) != 0)
        return authd_error("random_failed", "ledger id generation failed");
    if (!authd_safe_id(id))
        return authd_error("invalid_ledger_id", "invalid ledger id");
    exists = authd_row_exists("authentication_ledger", id);
    if (update && !exists)
        return authd_error("ledger_not_found", "ledger entry does not exist");
    if (!update && exists)
        return authd_error("ledger_exists", "ledger id already exists");

    if (update) {
        st = authd_write_prepare(
            "SELECT account_id,account_username,account_display_name,charged_at,operator,"
            "amount_minor,currency,description,note,created_at FROM authentication_ledger WHERE id=?1");
        if (!st)
            return authd_error("storage_error", "ledger storage unavailable");
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_ROW) {
            sqlite3_finalize(st);
            return authd_error("ledger_not_found", "ledger entry does not exist");
        }
        snprintf(account_id, sizeof(account_id), "%s", authd_sqlite_text(st, 0, ""));
        snprintf(username, sizeof(username), "%s", authd_sqlite_text(st, 1, ""));
        snprintf(display_name, sizeof(display_name), "%s", authd_sqlite_text(st, 2, ""));
        if (!authd_req_has(request, "charged_at"))
            charged_at = sqlite3_column_int64(st, 3);
        if (!authd_req_has(request, "operator"))
            snprintf(operator_name, sizeof(operator_name), "%s", authd_sqlite_text(st, 4, ""));
        if (!authd_req_has(request, "amount_minor") && !authd_req_has(request, "amount"))
            amount_minor = sqlite3_column_int64(st, 5);
        if (!authd_req_has(request, "currency"))
            snprintf(currency, sizeof(currency), "%s", authd_sqlite_text(st, 6, "CNY"));
        if (!authd_req_has(request, "description"))
            snprintf(description, sizeof(description), "%s", authd_sqlite_text(st, 7, ""));
        if (!authd_req_has(request, "note"))
            snprintf(note, sizeof(note), "%s", authd_sqlite_text(st, 8, ""));
        created_at = sqlite3_column_int64(st, 9);
        sqlite3_finalize(st);
    }

    if (account_ref[0]) {
        account_found = authd_ledger_account_snapshot(account_ref, account_id, sizeof(account_id),
                                                      username, sizeof(username),
                                                      display_name, sizeof(display_name));
        if (account_found < 0)
            return authd_error("storage_error", "account storage unavailable");
        if (!account_found)
            return authd_error("ledger_account_not_found", "ledger account does not exist");
    } else if (!update) {
        return authd_error("invalid_ledger_account", "ledger account is required");
    }

    if (charged_at <= 0)
        charged_at = update ? charged_at : authd_now_s();
    if (charged_at <= 0 || amount_minor < 0 || amount_minor > 100000000000LL ||
        !authd_text_ok(operator_name, 128, 1) ||
        strlen(currency) != 3 || !isalpha((unsigned char)currency[0]) ||
        !isalpha((unsigned char)currency[1]) || !isalpha((unsigned char)currency[2]) ||
        !authd_text_ok(description, 512, 0) || !authd_text_ok(note, 2048, 0))
        return authd_error("invalid_ledger", "invalid ledger fields");

    st = authd_write_prepare(
        "INSERT INTO authentication_ledger(id,account_id,account_username,account_display_name,"
        "charged_at,operator,amount_minor,currency,description,note,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,upper(?8),?9,?10,?11,?12) "
        "ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id,"
        "account_username=excluded.account_username,account_display_name=excluded.account_display_name,"
        "charged_at=excluded.charged_at,operator=excluded.operator,amount_minor=excluded.amount_minor,"
        "currency=excluded.currency,description=excluded.description,note=excluded.note,"
        "updated_at=excluded.updated_at");
    if (!st)
        return authd_error("storage_error", "ledger storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, account_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, username, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, display_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, charged_at);
    sqlite3_bind_text(st, 6, operator_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, amount_minor);
    sqlite3_bind_text(st, 8, currency, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, description, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 10, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 11, created_at);
    sqlite3_bind_int64(st, 12, authd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE)
        return authd_error("ledger_save_failed", "ledger entry could not be saved");
    return authd_write_success(id, exists ? "updated" : "created");
}

struct json_object *authd_ledger_delete(struct json_object *request)
{
    const char *id = authd_req_string(request, "id", "");
    sqlite3_stmt *st;

    if (!authd_safe_id(id) || !authd_row_exists("authentication_ledger", id))
        return authd_error("ledger_not_found", "ledger entry does not exist");
    st = authd_write_prepare("DELETE FROM authentication_ledger WHERE id=?1");
    if (!st)
        return authd_error("storage_error", "ledger storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("ledger_delete_failed", "ledger entry could not be deleted");
    }
    sqlite3_finalize(st);
    return authd_write_success(id, "deleted");
}

static struct json_object *authd_import_row_call(const char *type, struct json_object *row)
{
    if (!strcmp(type, "accounts"))
        return authd_account_upsert(row);
    if (!strcmp(type, "packages"))
        return authd_package_upsert(row);
    if (!strcmp(type, "vouchers"))
        return authd_voucher_create(row);
    return authd_error("invalid_import_type", "import type must be accounts, packages or vouchers");
}

struct json_object *authd_accounts_import(struct json_object *request)
{
    const char *type = authd_req_string(request, "type", "accounts");
    struct json_object *rows = NULL;
    struct json_object *results = json_object_new_array();
    int confirm = authd_req_bool(request, "confirm", 0);
    int count, i;

    if (strcmp(type, "accounts") && strcmp(type, "packages") && strcmp(type, "vouchers")) {
        json_object_put(results);
        return authd_error("invalid_import_type", "import type must be accounts, packages or vouchers");
    }
    if (!request || !json_object_object_get_ex(request, "rows", &rows) || !rows ||
        !json_object_is_type(rows, json_type_array) ||
        (count = json_object_array_length(rows)) < 1 || count > 500) {
        json_object_put(results);
        return authd_error("invalid_import_rows", "rows must contain 1 to 500 objects");
    }
    if (sqlite3_exec(g_authd_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        json_object_put(results);
        return authd_error("storage_busy", "authentication import storage is busy");
    }
    for (i = 0; i < count; i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        struct json_object *response;
        struct json_object *entry;
        struct json_object *data = NULL;

        if (!row || !json_object_is_type(row, json_type_object)) {
            sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
            json_object_put(results);
            return authd_error("invalid_import_row", "import row must be an object");
        }
        response = authd_import_row_call(type, row);
        if (!authd_response_ok(response)) {
            const char *error = authd_response_error(response);
            struct json_object *root = authd_error(error, "authentication import was rolled back");
            struct json_object *root_data = NULL;
            sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
            if (json_object_object_get_ex(root, "data", &root_data) && root_data)
                json_object_object_add(root_data, "line", json_object_new_int(i + 1));
            json_object_put(response);
            json_object_put(results);
            return root;
        }
        entry = json_object_new_object();
        json_object_object_add(entry, "line", json_object_new_int(i + 1));
        if (confirm && json_object_object_get_ex(response, "data", &data) && data)
            json_object_object_add(entry, "result", json_object_get(data));
        json_object_array_add(results, entry);
        json_object_put(response);
    }
    if (!confirm) {
        sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
    } else if (sqlite3_exec(g_authd_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
        json_object_put(results);
        return authd_error("import_commit_failed", "authentication import commit failed");
    }
    {
        struct json_object *data = json_object_new_object();
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "type", json_object_new_string(type));
        json_object_object_add(data, "validated", json_object_new_int(count));
        json_object_object_add(data, "imported", json_object_new_int(confirm ? count : 0));
        json_object_object_add(data, "dry_run", json_object_new_boolean(!confirm));
        json_object_object_add(data, "results", results);
        return authd_envelope(data);
    }
}

static int authd_voucher_digest(const char *code, char digest_hex[SHA256_DIGEST_LENGTH * 2 + 1])
{
    unsigned char key[32], digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len = 0;

    if (!code || !code[0] || authd_secret_key(key) != 0)
        return -1;
    if (!HMAC(EVP_sha256(), key, sizeof(key), (const unsigned char *)code,
              strlen(code), digest, &digest_len) || digest_len != SHA256_DIGEST_LENGTH) {
        OPENSSL_cleanse(key, sizeof(key));
        OPENSSL_cleanse(digest, sizeof(digest));
        return -1;
    }
    OPENSSL_cleanse(key, sizeof(key));
    authd_hex(digest, SHA256_DIGEST_LENGTH, digest_hex);
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int authd_voucher_generate(char *out, size_t out_len, int length)
{
    static const char alphabet[] = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    unsigned char random[128];
    size_t alphabet_len = sizeof(alphabet) - 1;
    unsigned int ceiling = 256U - (256U % (unsigned int)alphabet_len);
    int i = 0;

    if (!out || length < 6 || length > 64 || out_len <= (size_t)length ||
        RAND_bytes(random, sizeof(random)) != 1)
        return -1;
    for (size_t j = 0; j < sizeof(random) && i < length; j++) {
        if ((unsigned int)random[j] >= ceiling)
            continue;
        out[i++] = alphabet[random[j] % alphabet_len];
    }
    if (i != length) {
        OPENSSL_cleanse(random, sizeof(random));
        return -1;
    }
    out[length] = '\0';
    OPENSSL_cleanse(random, sizeof(random));
    return 0;
}

static void authd_voucher_hint(const char *code, char *out, size_t out_len)
{
    size_t n = strlen(code);
    if (n <= 8) snprintf(out, out_len, "%.2s***%s", code, code + (n > 2 ? n - 2 : 0));
    else snprintf(out, out_len, "%.4s****%s", code, code + n - 4);
}

static struct json_object *authd_voucher_insert_one(struct json_object *request, const char *batch_id,
                                                    const char *provided_code, int length)
{
    char id[96], code[65], digest[SHA256_DIGEST_LENGTH * 2 + 1], hint[32];
    const char *package_id = authd_req_string(request, "package_id", "");
    const char *note = authd_req_string(request, "note", "");
    int64_t expires = authd_time_value(request, "expires_at", 0);
    int64_t duration = authd_duration_value(request, "duration_seconds", "duration", 0);
    int64_t up = authd_rate_value(request, "upload_bps", "up_rate", 0);
    int64_t down = authd_rate_value(request, "download_bps", "down_rate", 0);
    int quota = (int)authd_req_i64(request, "max_uses", authd_req_i64(request, "quota", 1));
    sqlite3_stmt *st;
    int rc;
    struct json_object *item;

    if (!authd_package_exists(package_id) || !authd_text_ok(note, 2048, 0) ||
        expires < 0 || duration < 0 || up < 0 || down < 0 || quota < 1 || quota > 100000)
        return NULL;
    if (provided_code && provided_code[0]) {
        if (!authd_voucher_code_ok(provided_code)) return NULL;
        snprintf(code, sizeof(code), "%s", provided_code);
    } else if (authd_voucher_generate(code, sizeof(code), length) != 0) {
        return NULL;
    }
    if (authd_random_id("vch-", id, sizeof(id)) != 0 || authd_voucher_digest(code, digest) != 0)
        return NULL;
    authd_voucher_hint(code, hint, sizeof(hint));
    st = authd_write_prepare(
        "INSERT INTO authentication_vouchers(id,batch_id,code_digest,code_cipher,display_hint,package_id,status,"
        "expires_at,duration_seconds,max_uses,used_count,download_bps,upload_bps,note,created_at,updated_at) "
        "VALUES(?1,?2,?3,'',?4,?5,'unused',?6,?7,?8,0,?9,?10,?11,?12,?12)");
    if (!st) return NULL;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, batch_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, digest, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, hint, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, package_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, expires);
    sqlite3_bind_int64(st, 7, duration);
    sqlite3_bind_int(st, 8, quota);
    sqlite3_bind_int64(st, 9, down);
    sqlite3_bind_int64(st, 10, up);
    sqlite3_bind_text(st, 11, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 12, authd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    OPENSSL_cleanse(digest, sizeof(digest));
    if (rc != SQLITE_DONE) {
        OPENSSL_cleanse(code, sizeof(code));
        return NULL;
    }
    item = json_object_new_object();
    json_object_object_add(item, "id", json_object_new_string(id));
    json_object_object_add(item, "batch_id", json_object_new_string(batch_id));
    json_object_object_add(item, "code", json_object_new_string(code));
    json_object_object_add(item, "display_hint", json_object_new_string(hint));
    json_object_object_add(item, "one_time_reveal", json_object_new_boolean(1));
    OPENSSL_cleanse(code, sizeof(code));
    return item;
}

struct json_object *authd_voucher_create(struct json_object *request)
{
    const char *provided = authd_req_string(request, "code", "");
    int count = (int)authd_req_i64(request, "count", 1);
    int length = (int)authd_req_i64(request, "length", 12);
    char batch_id[96];
    struct json_object *created = json_object_new_array();
    struct json_object *data;
    int i;
    int own_transaction = sqlite3_get_autocommit(g_authd_db) != 0;

    if (count < 1 || count > AUTHD_VOUCHER_BATCH_MAX || length < 6 || length > 64 ||
        (provided[0] && count != 1)) {
        json_object_put(created);
        return authd_error("invalid_voucher_batch", "count must be 1..1000 and explicit code requires count=1");
    }
    if (authd_random_id("batch-", batch_id, sizeof(batch_id)) != 0) {
        json_object_put(created);
        return authd_error("random_failed", "voucher batch generation failed");
    }
    if (own_transaction &&
        sqlite3_exec(g_authd_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        json_object_put(created);
        return authd_error("storage_busy", "voucher storage is busy");
    }
    for (i = 0; i < count; i++) {
        struct json_object *item = authd_voucher_insert_one(request, batch_id, provided, length);
        if (!item) {
            if (own_transaction)
                sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
            json_object_put(created);
            return authd_error("voucher_create_failed", "voucher batch was rolled back");
        }
        json_object_array_add(created, item);
    }
    if (own_transaction && sqlite3_exec(g_authd_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_exec(g_authd_db, "ROLLBACK", NULL, NULL, NULL);
        json_object_put(created);
        return authd_error("voucher_create_failed", "voucher batch commit failed");
    }
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "batch_id", json_object_new_string(batch_id));
    json_object_object_add(data, "count", json_object_new_int(count));
    json_object_object_add(data, "created", created);
    json_object_object_add(data, "codes_returned_once", json_object_new_boolean(1));
    return authd_envelope(data);
}

struct json_object *authd_voucher_update(struct json_object *request)
{
    const char *id = authd_req_string(request, "id", "");
    const char *package_id = authd_req_string(request, "package_id", "");
    const char *note = authd_req_string(request, "note", "");
    const char *code = authd_req_string(request, "code", "");
    int64_t expires = authd_time_value(request, "expires_at", 0);
    int64_t duration = authd_duration_value(request, "duration_seconds", "duration", 0);
    int64_t up = authd_rate_value(request, "upload_bps", "up_rate", 0);
    int64_t down = authd_rate_value(request, "download_bps", "down_rate", 0);
    int quota = (int)authd_req_i64(request, "max_uses", authd_req_i64(request, "quota", 1));
    sqlite3_stmt *st;

    if (!authd_safe_id(id) || !authd_row_exists("authentication_vouchers", id))
        return authd_error("voucher_not_found", "voucher does not exist");
    if (code[0]) return authd_error("voucher_code_immutable", "voucher code cannot be changed after creation");
    if (!authd_package_exists(package_id) || !authd_text_ok(note, 2048, 0) ||
        expires < 0 || duration < 0 || up < 0 || down < 0 || quota < 1 || quota > 100000)
        return authd_error("invalid_voucher", "invalid voucher fields");
    st = authd_write_prepare("UPDATE authentication_vouchers SET package_id=?2,expires_at=?3,duration_seconds=?4,"
                             "max_uses=?5,download_bps=?6,upload_bps=?7,note=?8,updated_at=?9 WHERE id=?1");
    if (!st) return authd_error("storage_error", "voucher storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, package_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, expires);
    sqlite3_bind_int64(st, 4, duration);
    sqlite3_bind_int(st, 5, quota);
    sqlite3_bind_int64(st, 6, down);
    sqlite3_bind_int64(st, 7, up);
    sqlite3_bind_text(st, 8, note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 9, authd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("voucher_save_failed", "voucher could not be saved");
    }
    sqlite3_finalize(st);
    return authd_write_success(id, "updated");
}

struct json_object *authd_voucher_delete(struct json_object *request)
{
    const char *id = authd_req_string(request, "id", "");
    sqlite3_stmt *st;
    if (!authd_safe_id(id) || !authd_row_exists("authentication_vouchers", id))
        return authd_error("voucher_not_found", "voucher does not exist");
    st = authd_write_prepare("DELETE FROM authentication_vouchers WHERE id=?1");
    if (!st) return authd_error("storage_error", "voucher storage unavailable");
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("voucher_delete_failed", "voucher could not be deleted");
    }
    sqlite3_finalize(st);
    return authd_write_success(id, "deleted");
}

struct json_object *authd_vouchers_expired_delete(struct json_object *request)
{
    sqlite3_stmt *st;
    struct json_object *data;
    int deleted;
    (void)request;

    st = authd_write_prepare("DELETE FROM authentication_vouchers WHERE status='expired' OR (expires_at>0 AND expires_at<=?1)");
    if (!st) return authd_error("storage_error", "voucher storage unavailable");
    sqlite3_bind_int64(st, 1, authd_now_s());
    if (sqlite3_step(st) != SQLITE_DONE) {
        sqlite3_finalize(st);
        return authd_error("voucher_delete_failed", "expired vouchers could not be deleted");
    }
    deleted = sqlite3_changes(g_authd_db);
    sqlite3_finalize(st);
    data = json_object_new_object();
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "deleted", json_object_new_int(deleted));
    return authd_envelope(data);
}
