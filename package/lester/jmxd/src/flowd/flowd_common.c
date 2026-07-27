// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_internal.h"

sqlite3 *g_flowd_config_db;
struct ubus_context *g_flowd_ubus;
struct blob_buf g_flowd_blob;
uint64_t g_flowd_seq;

int64_t flowd_now_s(void)
{
    return (int64_t)time(NULL);
}

void flowd_make_id(const char *prefix, char *out, size_t out_len)
{
    struct timeval tv;

    if (!out || out_len == 0)
        return;
    gettimeofday(&tv, NULL);
    snprintf(out, out_len, "%s-%lld-%06ld-%llu-%u",
             prefix && prefix[0] ? prefix : "id",
             (long long)tv.tv_sec, (long)tv.tv_usec,
             (unsigned long long)++g_flowd_seq, (unsigned)getpid());
}

const char *flowd_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    if (!json_object_is_type(v, json_type_string))
        return def;
    return json_object_get_string(v) ? json_object_get_string(v) : def;
}

int flowd_json_int(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_int(v);
}

int flowd_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;

    if (!o || !key || !json_object_object_get_ex(o, key, &v) || !v)
        return def;
    return json_object_get_boolean(v) ? 1 : 0;
}

struct json_object *flowd_json_parse_or_object(const char *s)
{
    struct json_object *o = NULL;

    if (s && s[0])
        o = json_tokener_parse(s);
    if (!o || !json_object_is_type(o, json_type_object)) {
        if (o)
            json_object_put(o);
        return json_object_new_object();
    }
    return o;
}

struct json_object *flowd_json_parse_or_array(const char *s)
{
    struct json_object *o = NULL;

    if (s && s[0])
        o = json_tokener_parse(s);
    if (!o || !json_object_is_type(o, json_type_array)) {
        if (o)
            json_object_put(o);
        return json_object_new_array();
    }
    return o;
}

const char *flowd_sqlite_text(sqlite3_stmt *st, int col, const char *def)
{
    const unsigned char *s;

    if (!st)
        return def;
    s = sqlite3_column_text(st, col);
    return s ? (const char *)s : def;
}

struct json_object *flowd_json_from_blob(struct blob_attr *msg)
{
    char *s;
    struct json_object *o = NULL;

    if (!msg)
        return json_object_new_object();
    s = blobmsg_format_json(msg, true);
    if (s) {
        o = json_tokener_parse(s);
        free(s);
    }
    return o ? o : json_object_new_object();
}

struct json_object *flowd_payload_or_self(struct json_object *body)
{
    struct json_object *payload = NULL;

    if (body && json_object_object_get_ex(body, "payload", &payload) && payload &&
        json_object_is_type(payload, json_type_object))
        return payload;
    return body;
}

struct json_object *flowd_error(const char *code, const char *message)
{
    struct json_object *o = json_object_new_object();

    json_object_object_add(o, "ok", json_object_new_boolean(0));
    json_object_object_add(o, "error", json_object_new_string(code ? code : "error"));
    json_object_object_add(o, "message", json_object_new_string(message ? message : ""));
    return o;
}

int flowd_text_ok(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s)
        return 1;
    if (strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p < 0x20 && *p != '\t' && *p != '\n' && *p != '\r')
            return 0;
    }
    return 1;
}

int flowd_token_ok(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s || !s[0] || strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.' || *p == ':' || *p == '/'))
            return 0;
    }
    return 1;
}

int flowd_id_ok(const char *s)
{
    return flowd_token_ok(s, FLOWD_MAX_ID - 1);
}

int flowd_path_ok(const char *s)
{
    size_t len;

    if (!s || !s[0])
        return 1;
    len = strlen(s);
    if (len >= FLOWD_MAX_TEXT)
        return 0;
    if (s[0] != '/')
        return 0;
    if (strstr(s, "/../") || strstr(s, "/./") || strstr(s, "//"))
        return 0;
    if ((len >= 2 && strcmp(s + len - 2, "/.") == 0) ||
        (len >= 3 && strcmp(s + len - 3, "/..") == 0))
        return 0;
    return flowd_token_ok(s, FLOWD_MAX_TEXT - 1);
}

int flowd_url_ok(const char *s)
{
    const unsigned char *p;

    if (!s || !s[0] || strlen(s) >= 1024)
        return 0;
    if (strncmp(s, "https://", 8) != 0)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p <= 0x20 || *p >= 0x7f || *p == '\'' || *p == '"' || *p == '`')
            return 0;
    }
    return 1;
}

int flowd_json_fits(struct json_object *o, size_t max_len)
{
    const char *s = o ? json_object_to_json_string(o) : "{}";

    return s && strlen(s) <= max_len;
}

int flowd_file_exists(const char *path)
{
    struct stat st;

    return path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int flowd_dir_exists(const char *path)
{
    struct stat st;

    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int flowd_mkdir_p(const char *path, mode_t mode)
{
    char buf[FLOWD_MAX_TEXT];
    char *p;

    if (!path || !path[0] || !flowd_path_ok(path))
        return -1;
    snprintf(buf, sizeof(buf), "%s", path);
    for (p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, mode) != 0 && errno != EEXIST)
            return -1;
        *p = '/';
    }
    if (mkdir(buf, mode) != 0 && errno != EEXIST)
        return -1;
    return flowd_dir_exists(path) ? 0 : -1;
}

const char *flowd_policy_direction(const char *s)
{
    if (!s || !s[0])
        return "dst";
    if (!strcmp(s, "src") || !strcmp(s, "dst") || !strcmp(s, "both"))
        return s;
    return NULL;
}

const char *flowd_policy_action(const char *s)
{
    if (!s || !s[0])
        return "route";
    if (!strcmp(s, "route") || !strcmp(s, "bypass") || !strcmp(s, "block") ||
        !strcmp(s, "mark"))
        return s;
    return NULL;
}

const char *flowd_policy_family(const char *s)
{
    if (!s || !s[0])
        return "both";
    if (!strcmp(s, "ipv4") || !strcmp(s, "ipv6") || !strcmp(s, "both"))
        return s;
    return NULL;
}

static int flowd_country_code_ok(const char *s)
{
    return s && strlen(s) == 2 && isalpha((unsigned char)s[0]) &&
           isalpha((unsigned char)s[1]);
}

static void flowd_country_upper(const char *in, char out[3])
{
    out[0] = (char)toupper((unsigned char)in[0]);
    out[1] = (char)toupper((unsigned char)in[1]);
    out[2] = '\0';
}

int flowd_countries_normalize(struct json_object *in, char *out, size_t out_len,
                              struct json_object **out_arr)
{
    struct json_object *arr = NULL;
    struct json_object *norm = json_object_new_array();
    const char *serialized;
    int i, n;

    if (!out || out_len == 0) {
        json_object_put(norm);
        return -1;
    }
    out[0] = '\0';
    if (!in) {
        json_object_put(norm);
        return -1;
    }
    if (json_object_is_type(in, json_type_array)) {
        arr = in;
    } else if (json_object_is_type(in, json_type_string)) {
        char buf[FLOWD_MAX_JSON];
        char *p, *save = NULL;

        snprintf(buf, sizeof(buf), "%s", json_object_get_string(in));
        for (p = strtok_r(buf, ", \t\r\n", &save); p; p = strtok_r(NULL, ", \t\r\n", &save)) {
            char cc[3];

            if (!flowd_country_code_ok(p)) {
                json_object_put(norm);
                return -1;
            }
            flowd_country_upper(p, cc);
            json_object_array_add(norm, json_object_new_string(cc));
        }
    } else {
        json_object_put(norm);
        return -1;
    }

    if (arr) {
        n = json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            struct json_object *v = json_object_array_get_idx(arr, i);
            const char *s = v && json_object_is_type(v, json_type_string) ?
                            json_object_get_string(v) : NULL;
            char cc[3];

            if (!flowd_country_code_ok(s)) {
                json_object_put(norm);
                return -1;
            }
            flowd_country_upper(s, cc);
            json_object_array_add(norm, json_object_new_string(cc));
        }
    }

    if (json_object_array_length(norm) <= 0) {
        json_object_put(norm);
        return -1;
    }
    serialized = json_object_to_json_string_ext(norm, JSON_C_TO_STRING_PLAIN);
    if (!serialized || strlen(serialized) >= out_len) {
        json_object_put(norm);
        return -1;
    }
    snprintf(out, out_len, "%s", serialized);
    if (out_arr)
        *out_arr = norm;
    else
        json_object_put(norm);
    return 0;
}
