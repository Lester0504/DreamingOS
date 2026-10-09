// SPDX-License-Identifier: GPL-2.0-or-later
/* Independently authored DreamingWrt Netboot configuration authority. */
#include "netboot_internal.h"
#include "jmx_netconfig_db.h"
#include <ctype.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct json_object *nb_value(struct json_object *o, const char *key)
{ struct json_object *v = NULL; if (o) json_object_object_get_ex(o, key, &v); return v; }
const char *nb_string(struct json_object *o, const char *key)
{ struct json_object *v = nb_value(o, key); return json_object_is_type(v, json_type_string) ? json_object_get_string(v) : ""; }
int64_t nb_number(struct json_object *o, const char *key)
{ return json_object_get_int64(nb_value(o, key)); }
int nb_bool(struct json_object *o, const char *key)
{ return json_object_get_boolean(nb_value(o, key)); }
struct json_object *nb_clone(struct json_object *o)
{ return o ? json_tokener_parse(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN)) : NULL; }
void nb_text(struct json_object *o, const char *k, const char *v)
{ json_object_object_add(o, k, json_object_new_string(v ? v : "")); }
void nb_int(struct json_object *o, const char *k, int64_t v)
{ json_object_object_add(o, k, json_object_new_int64(v)); }
void nb_flag(struct json_object *o, const char *k, int v)
{ json_object_object_add(o, k, json_object_new_boolean(v)); }

struct json_object *nb_reply(struct json_object *data)
{
    struct json_object *r = json_object_new_object();
    nb_int(r, "code", 2000); nb_text(r, "message", "success");
    nb_flag(r, "ok", 1); nb_int(r, "http_status", 200);
    json_object_object_add(r, "data", data); return r;
}
struct json_object *nb_error(int http, const char *code, const char *field)
{
    struct json_object *r = nb_reply(json_object_new_object());
    struct json_object *d = nb_value(r, "data");
    nb_int(r, "code", 4000); nb_flag(r, "ok", 0); nb_int(r, "http_status", http);
    nb_text(r, "message", code); nb_text(d, "error", code); nb_text(d, "field", field);
    nb_flag(d, "ok", 0); return r;
}

static struct json_object *defaults(void)
{
    return json_tokener_parse("{\"revision\":0,\"settings\":{\"enabled\":false,"
        "\"interface_ids\":[],\"http_port\":8069,\"menu_timeout\":10,"
        "\"default_image_id\":\"\",\"allow_unknown\":false},\"images\":[],\"clients\":[]}");
}

sqlite3 *nb_open(int writing)
{
    sqlite3 *db = NULL;
    /* An absent config database is an authority error; never create a competing DB. */
    /* DHCP apply also updates its runtime readback in config.db. Borrow the
     * main-loop authority connection so those writes join our transaction;
     * a second writer would deadlock behind Netboot's BEGIN IMMEDIATE.
     * HTTP worker reads still use their own readonly connections. */
    if (writing) {
        db = jmx_netconfig_db_write_connection();
        if (!db) return NULL;
    } else if (sqlite3_open_v2(NB_DB_PATH, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) {
        sqlite3_close(db); return NULL;
    }
    sqlite3_busy_timeout(db, 3000);
    if (writing && sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS netboot_config (id INTEGER PRIMARY KEY CHECK(id=1),"
        " revision INTEGER NOT NULL, document TEXT NOT NULL)", NULL, NULL, NULL) != SQLITE_OK) {
        return NULL;
    }
    return db;
}

struct json_object *nb_load(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    struct json_object *o = NULL;
    if (!db) return NULL;
    if (sqlite3_prepare_v2(db, "SELECT document FROM netboot_config WHERE id=1", -1, &st, NULL) != SQLITE_OK) {
        /* Only a not-yet-created module table means pristine defaults. */
        if (strstr(sqlite3_errmsg(db), "no such table: netboot_config")) return defaults();
        return NULL;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) o = json_tokener_parse((const char *)sqlite3_column_text(st, 0));
    else if (rc == SQLITE_DONE) o = defaults();
    sqlite3_finalize(st);
    if (o && (!json_object_is_type(nb_value(o, "settings"), json_type_object) ||
              !json_object_is_type(nb_value(o, "images"), json_type_array) ||
              !json_object_is_type(nb_value(o, "clients"), json_type_array))) {
        json_object_put(o); return NULL;
    }
    return o;
}

int nb_store(sqlite3 *db, struct json_object *o)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO netboot_config VALUES(1,?1,?2) "
        "ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,document=excluded.document", -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, nb_number(o, "revision"));
    sqlite3_bind_text(st, 2, json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st); sqlite3_finalize(st); return rc == SQLITE_DONE ? 0 : -1;
}

struct json_object *nb_find(struct json_object *a, const char *id)
{
    if (!id || !json_object_is_type(a, json_type_array)) return NULL;
    for (size_t i = 0; i < json_object_array_length(a); i++) {
        struct json_object *o = json_object_array_get_idx(a, i);
        if (!strcmp(nb_string(o, "id"), id)) return o;
    }
    return NULL;
}

int nb_safe_text(const char *s, size_t maximum)
{
    if (!s || strlen(s) > maximum) return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) if (*p < 32 || *p == 127) return 0;
    return 1;
}

int nb_mac(const char *input, char output[18])
{
    unsigned char bytes[6];
    if (!input || strlen(input) != 17) return -1;
    for (size_t i = 0; i < 6; i++) {
        if (!isxdigit((unsigned char)input[i*3]) || !isxdigit((unsigned char)input[i*3+1]) ||
            (i < 5 && input[i*3+2] != ':' && input[i*3+2] != '-')) return -1;
        char pair[3] = { input[i*3], input[i*3+1], 0 };
        bytes[i] = (unsigned char)strtoul(pair, NULL, 16);
    }
    if ((bytes[0] & 1) || !(bytes[0]|bytes[1]|bytes[2]|bytes[3]|bytes[4]|bytes[5])) return -1;
    snprintf(output, 18, "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5]);
    return 0;
}

static void hex(const unsigned char *in, size_t n, char *out)
{ for (size_t i=0;i<n;i++) sprintf(out+i*2, "%02x", in[i]); }
static int unhex(const char *in, size_t n, unsigned char *out)
{
    if (strlen(in) != n*2) return -1;
    for (size_t i=0;i<n;i++) {
        if (!isxdigit((unsigned char)in[i*2]) || !isxdigit((unsigned char)in[i*2+1])) return -1;
        char p[3] = {in[i*2],in[i*2+1],0}; out[i]=(unsigned char)strtoul(p,NULL,16);
    }
    return 0;
}
int nb_password_set(struct json_object *s, const char *password)
{
    unsigned char salt[16], key[32]; char a[33]={0}, b[65]={0};
    if (!nb_safe_text(password, 128)) return -1;
    if (!*password) { json_object_object_del(s,"password_salt"); json_object_object_del(s,"password_hash"); return 0; }
    if (RAND_bytes(salt,sizeof salt)!=1 || PKCS5_PBKDF2_HMAC(password,strlen(password),salt,sizeof salt,100000,EVP_sha256(),sizeof key,key)!=1) return -1;
    hex(salt,sizeof salt,a); hex(key,sizeof key,b); nb_text(s,"password_salt",a); nb_text(s,"password_hash",b);
    OPENSSL_cleanse(key,sizeof key); return 0;
}
int nb_password_check(struct json_object *s, const char *password)
{
    unsigned char salt[16], stored[32], key[32]; int ok=0;
    if (!*nb_string(s,"password_hash")) return 1;
    if (!password || strlen(password)>128 || unhex(nb_string(s,"password_salt"),16,salt) || unhex(nb_string(s,"password_hash"),32,stored)) return 0;
    if (PKCS5_PBKDF2_HMAC(password,strlen(password),salt,sizeof salt,100000,EVP_sha256(),sizeof key,key)==1) ok=CRYPTO_memcmp(key,stored,sizeof key)==0;
    OPENSSL_cleanse(key,sizeof key); return ok;
}
