// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_signature_update.c - DreamingWrt signature catalog and update backend
 */
#include "jmx_signature_update.h"
#include "jmx_netconfig_db.h"
#include "jmx_db.h"
#include "jmx.h"
#include "jmx_signature_db.h"
#include "jmx_system_data_path.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <regex.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* DreamingWrt bundled signature DB status/catalog helpers */
#ifndef JMX_SIGNATURE_DB_DEFAULT
#define JMX_SIGNATURE_DB_DEFAULT "/etc/dreamingwrt/dreamingwrt_signatures.db"
#endif
#define JMX_SIGNATURE_ICON_URL_PREFIX "/static/images/logo/"
#define JMX_SIGNATURE_ICON_TARGET_DIR "/www/dreamingwrt/static/images/logo"
#define JMX_SIGNATURE_GEOIP_TARGET_DIR "/etc/dreamingwrt/geoip"
#define JMX_SIGNATURE_GEOIP_COUNTRY_TARGET "/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb"
#define JMX_FINGERPRINT_DB_TARGET "/etc/dreamingwrt/fingerprint/fingerprint.db"
#define JMX_FINGERPRINT_DB_APPLICATION_ID 1146570320
#define JMX_FINGERPRINT_DB_SCHEMA_VERSION 1
#define JMX_SIGNATURE_UPDATE_TMP_TEMPLATE "/tmp/jmxd_sigupd_XXXXXX"

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} nc_sig_string_list_t;

typedef struct {
    char phase[32];
    char error[96];
    char package_path[256];
    char build_date[64];
    int64_t ts;
    int validated;
    int applied;
} nc_sig_update_status_t;

static nc_sig_update_status_t g_sig_update_status = {
    .phase = "idle",
};

#define NC_SIG_HOST_RULE_CACHE_MAX 8192

typedef struct {
    int rule_id;
    int app_id;
    int priority;
    char proto[16];
    char match_type[16];
    char pattern[256];
    int regex_ready;
    regex_t regex;
} nc_sig_host_rule_cache_t;

static nc_sig_host_rule_cache_t *g_sig_host_rules;
static int g_sig_host_rule_count;
static time_t g_sig_host_db_mtime;
static off_t g_sig_host_db_size;

static int nc_sig_scalar_i(sqlite3 *db, const char *sql);
static int nc_sig_table_exists(sqlite3 *db, const char *name);
static int nc_sig_regular_file_count(const char *dir);
static void nc_sig_error(struct json_object *errors, const char *code, const char *detail);
static int nc_unlink_if_exists(const char *path);

static void nc_sig_status_set(const char *phase, const char *error, const char *path)
{
    snprintf(g_sig_update_status.phase, sizeof(g_sig_update_status.phase), "%s", phase ? phase : "idle");
    snprintf(g_sig_update_status.error, sizeof(g_sig_update_status.error), "%s", error ? error : "");
    snprintf(g_sig_update_status.package_path, sizeof(g_sig_update_status.package_path), "%s", path ? path : "");
    g_sig_update_status.ts = nc_now_s();
}

static int nc_read_file_text(const char *path, char *buf, size_t len)
{
    FILE *fp;
    size_t n;
    if (!path || !buf || len == 0)
        return -1;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    n = fread(buf, 1, len - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return 0;
}

static int nc_run_cmd(char *const argv[])
{
    pid_t pid;
    int status = -1;

    if (!argv || !argv[0])
        return -1;
    pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    if (pid < 0)
        return -1;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

static int nc_run_cmd_stdout_to_file(char *const argv[], const char *out_path)
{
    pid_t pid;
    int status = -1;
    int fd;

    if (!argv || !argv[0] || !out_path)
        return -1;
    fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;
    pid = fork();
    if (pid == 0) {
        dup2(fd, STDOUT_FILENO);
        close(fd);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fd);
    if (pid < 0)
        return -1;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

static int nc_sha256_file(const char *path, char *out, size_t out_len)
{
    unsigned char buf[4096];
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    char hex[EVP_MAX_MD_SIZE * 2 + 1];
    EVP_MD_CTX *ctx = NULL;
    FILE *fp = NULL;
    size_t n;
    int ok = -1;

    if (!path || !out || out_len < 65)
        return -1;
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(fp);
        return -1;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto done;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1)
            goto done;
    }
    if (ferror(fp))
        goto done;
    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1)
        goto done;
    for (n = 0; n < md_len; n++)
        snprintf(hex + n * 2, sizeof(hex) - n * 2, "%02x", md[n]);
    hex[md_len * 2] = '\0';
    snprintf(out, out_len, "%s", hex);
    ok = 0;
done:
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    return ok;
}

static char *nc_trim_ws(char *s)
{
    char *e;
    if (!s)
        return s;
    while (*s && isspace((unsigned char)*s))
        s++;
    if (!*s)
        return s;
    e = s + strlen(s) - 1;
    while (e >= s && isspace((unsigned char)*e))
        *e-- = '\0';
    return s;
}

static int nc_path_is_regular_readable(const char *path)
{
    struct stat st;
    return path && lstat(path, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 1 &&
           access(path, R_OK) == 0;
}

static int nc_path_is_dir(const char *path)
{
    struct stat st;
    return path && lstat(path, &st) == 0 && S_ISDIR(st.st_mode) &&
           access(path, R_OK | X_OK) == 0;
}

static void nc_sig_string_list_free(nc_sig_string_list_t *list)
{
    size_t i;

    if (!list)
        return;
    for (i = 0; i < list->count; i++)
        free(list->items[i]);
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int nc_sig_string_list_add(nc_sig_string_list_t *list, const char *item)
{
    char **tmp;
    size_t ncap;

    if (!list || !item)
        return -1;
    if (list->count == list->cap) {
        ncap = list->cap ? list->cap * 2 : 64;
        tmp = realloc(list->items, ncap * sizeof(*tmp));
        if (!tmp)
            return -1;
        list->items = tmp;
        list->cap = ncap;
    }
    list->items[list->count] = strdup(item);
    if (!list->items[list->count])
        return -1;
    list->count++;
    return 0;
}

static int nc_sig_string_cmp(const void *a, const void *b)
{
    const char * const *sa = (const char * const *)a;
    const char * const *sb = (const char * const *)b;
    return strcmp(*sa, *sb);
}

static int nc_sha256_tree_collect(const char *root, const char *rel_dir,
                                  nc_sig_string_list_t *files)
{
    char dir_path[PATH_MAX];
    DIR *dp;
    struct dirent *de;
    int rc = -1;

    if (!root || !rel_dir || !files || rel_dir[0] == '/' || strstr(rel_dir, ".."))
        return -1;
    if (rel_dir[0]) {
        if (snprintf(dir_path, sizeof(dir_path), "%s/%s", root, rel_dir) >= (int)sizeof(dir_path))
            return -1;
    } else if (snprintf(dir_path, sizeof(dir_path), "%s", root) >= (int)sizeof(dir_path)) {
        return -1;
    }
    dp = opendir(dir_path);
    if (!dp)
        return -1;
    while ((de = readdir(dp)) != NULL) {
        char child_rel[PATH_MAX];
        char child_path[PATH_MAX];
        struct stat st;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        if (strchr(de->d_name, '/') || strstr(de->d_name, ".."))
            goto done;
        if (rel_dir[0]) {
            if (snprintf(child_rel, sizeof(child_rel), "%s/%s", rel_dir, de->d_name) >= (int)sizeof(child_rel))
                goto done;
        } else if (snprintf(child_rel, sizeof(child_rel), "%s", de->d_name) >= (int)sizeof(child_rel)) {
            goto done;
        }
        if (snprintf(child_path, sizeof(child_path), "%s/%s", root, child_rel) >= (int)sizeof(child_path))
            goto done;
        if (lstat(child_path, &st) != 0)
            goto done;
        if (S_ISDIR(st.st_mode)) {
            if (nc_sha256_tree_collect(root, child_rel, files) != 0)
                goto done;
        } else if (S_ISREG(st.st_mode) && st.st_nlink == 1 && access(child_path, R_OK) == 0) {
            if (nc_sig_string_list_add(files, child_rel) != 0)
                goto done;
        } else {
            goto done;
        }
    }
    rc = 0;
done:
    closedir(dp);
    return rc;
}

static int nc_sha256_tree(const char *dir, char *out, size_t out_len)
{
    nc_sig_string_list_t files = {0};
    EVP_MD_CTX *ctx = NULL;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    size_t i;
    int rc = -1;

    if (!dir || !out || out_len < 65 || !nc_path_is_dir(dir))
        return -1;
    if (nc_sha256_tree_collect(dir, "", &files) != 0)
        goto done;
    qsort(files.items, files.count, sizeof(*files.items), nc_sig_string_cmp);
    ctx = EVP_MD_CTX_new();
    if (!ctx)
        goto done;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto done;
    for (i = 0; i < files.count; i++) {
        char path[PATH_MAX];
        char file_sha[65] = {0};
        char line[PATH_MAX + 80];
        int len;

        if (snprintf(path, sizeof(path), "%s/%s", dir, files.items[i]) >= (int)sizeof(path))
            goto done;
        if (nc_sha256_file(path, file_sha, sizeof(file_sha)) != 0)
            goto done;
        len = snprintf(line, sizeof(line), "%s  %s\n", file_sha, files.items[i]);
        if (len <= 0 || len >= (int)sizeof(line))
            goto done;
        if (EVP_DigestUpdate(ctx, line, (size_t)len) != 1)
            goto done;
    }
    if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1)
        goto done;
    for (i = 0; i < md_len; i++)
        snprintf(out + i * 2, out_len - i * 2, "%02x", md[i]);
    out[md_len * 2] = '\0';
    rc = 0;
done:
    if (ctx)
        EVP_MD_CTX_free(ctx);
    nc_sig_string_list_free(&files);
    return rc;
}

static int nc_sig_check_regular_tree(const char *dir, struct json_object *errors)
{
    DIR *dp;
    struct dirent *de;
    int ok = 0;

    if (!dir || !dir[0])
        return -1;
    dp = opendir(dir);
    if (!dp)
        return -1;
    while ((de = readdir(dp)) != NULL) {
        char path[PATH_MAX];
        struct stat st;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        if (strstr(de->d_name, "..") || strchr(de->d_name, '/')) {
            nc_sig_error(errors, "invalid_icon_entry", de->d_name);
            ok = -1;
            continue;
        }
        if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= (int)sizeof(path)) {
            nc_sig_error(errors, "icon_path_too_long", de->d_name);
            ok = -1;
            continue;
        }
        if (lstat(path, &st) != 0) {
            nc_sig_error(errors, "icon_entry_unreadable", de->d_name);
            ok = -1;
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (nc_sig_check_regular_tree(path, errors) != 0)
                ok = -1;
        } else if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || access(path, R_OK) != 0) {
            nc_sig_error(errors, "invalid_icon_entry_type", de->d_name);
            ok = -1;
        }
    }
    closedir(dp);
    return ok;
}

static int nc_unlink_if_exists(const char *path)
{
    if (path && access(path, F_OK) == 0)
        return unlink(path);
    return 0;
}

static int nc_mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    size_t i;
    if (!path || !path[0] || strlen(path) >= sizeof(tmp))
        return -1;
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (i = 1; tmp[i]; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return -1;
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int nc_tar_list_and_extract(const char *package_path, const char *tmpdir)
{
    char *const list_argv[] = { "tar", "-tf", (char *)package_path, NULL };
    char *const verbose_argv[] = { "tar", "-tvf", (char *)package_path, NULL };
    char *const extract_argv[] = { "tar", "-xf", (char *)package_path, "-C", (char *)tmpdir, NULL };
    FILE *fp = NULL;
    char list_path[PATH_MAX];
    char verbose_path[PATH_MAX];
    char line[512];
    int has_conf = 0, has_db = 0, has_icon_dir = 0;
    int count = 0;

    if (!package_path || !tmpdir || strlen(tmpdir) + 24 >= sizeof(list_path))
        return -1;
    snprintf(list_path, sizeof(list_path), "%s/.tar-list", tmpdir);
    snprintf(verbose_path, sizeof(verbose_path), "%s/.tar-list-v", tmpdir);
    if (nc_run_cmd_stdout_to_file(verbose_argv, verbose_path) != 0)
        return -1;
    fp = fopen(verbose_path, "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] != '-' && line[0] != 'd') {
            fclose(fp);
            nc_unlink_if_exists(verbose_path);
            return -1;
        }
    }
    fclose(fp);
    fp = NULL;
    nc_unlink_if_exists(verbose_path);

    if (nc_run_cmd_stdout_to_file(list_argv, list_path) != 0)
        return -1;
    fp = fopen(list_path, "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *name = nc_trim_ws(line);
        if (!strncmp(name, "./", 2))
            name += 2;
        if (!name[0] || name[0] == '/' || strstr(name, "..")) {
            fclose(fp);
            return -1;
        }
        count++;
        if (!strcmp(name, "signature-update.conf"))
            has_conf = 1;
        else if (!strcmp(name, "dreamingwrt_signatures.db"))
            has_db = 1;
        else if (!strcmp(name, "manifest.json")) {
            /* v2 manifest */
        }
        else if (!strncmp(name, "logo/", 5))
            has_icon_dir = 1;
        else if (!strncmp(name, "geoip/", 6) ||
                 !strncmp(name, "reputation/", 11) ||
                 !strncmp(name, "content/", 8) ||
                 !strncmp(name, "fingerprint/", 12) ||
                 !strncmp(name, "ips/", 4) ||
                 !strncmp(name, "device_icon/", 12)) {
            /* v2 optional datasets */
        }
        else {
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    nc_unlink_if_exists(list_path);
    if (count < 3 || !has_conf || !has_db || !has_icon_dir)
        return -1;
    return nc_run_cmd(extract_argv);
}

static int nc_sqlite_integrity_check(const char *path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int ok = -1;

    if (!path || sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check;", -1, &st, NULL) != SQLITE_OK)
        goto done;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *res = (const char *)sqlite3_column_text(st, 0);
        if (res && !strcmp(res, "ok"))
            ok = 0;
    }
done:
    if (st)
        sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    return ok;
}

static int nc_signature_runtime_invalid_rule_count(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int count = -1;
    static const char *sql =
        "SELECT COUNT(*) FROM dpi_rule WHERE enabled=1 "
        "AND lower(match_type) IN ('exact','fixed','bm') "
        "AND length(CASE WHEN lower(pattern_format)='hex' "
        "THEN COALESCE(pattern_hex,'') ELSE COALESCE(pattern_text,'') END)=0";

    if (!db || sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

static int nc_mmdb_marker_check(const char *path)
{
    static const unsigned char marker[] = {
        0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'
    };
    unsigned char buf[131072];
    struct stat st;
    FILE *fp;
    size_t n, i;

    if (!path || stat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || st.st_size > (off_t)(128U * 1024U * 1024U))
        return -1;
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    if (st.st_size > (off_t)sizeof(buf) &&
        fseeko(fp, st.st_size - (off_t)sizeof(buf), SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (n < sizeof(marker))
        return -1;
    for (i = 0; i + sizeof(marker) <= n; i++) {
        if (memcmp(buf + i, marker, sizeof(marker)) == 0)
            return 0;
    }
    return -1;
}

static int nc_signature_upload_path_ok(const char *path)
{
    const unsigned char *p = (const unsigned char *)path;
    if (!path || path[0] != '/' || strlen(path) >= 256 || strstr(path, ".."))
        return 0;
    for (; *p; p++) {
        if (isalnum(*p) || *p == '/' || *p == '_' || *p == '-' || *p == '.' || *p == '+')
            continue;
        return 0;
    }
    return 1;
}

static int nc_conf_load(const char *path, struct json_object **out)
{
    char buf[8192];
    char *save = NULL;
    char *line;
    struct json_object *conf = NULL;

    if (!out)
        return -1;
    *out = NULL;
    if (nc_read_file_text(path, buf, sizeof(buf)) != 0)
        return -1;
    conf = json_object_new_object();
    line = strtok_r(buf, "\n", &save);
    while (line) {
        char *eq;
        char *key;
        char *val;
        line = nc_trim_ws(line);
        if (!line[0] || line[0] == '#') {
            line = strtok_r(NULL, "\n", &save);
            continue;
        }
        eq = strchr(line, '=');
        if (!eq) {
            line = strtok_r(NULL, "\n", &save);
            continue;
        }
        *eq = '\0';
        key = nc_trim_ws(line);
        val = nc_trim_ws(eq + 1);
        if (val[0] && (val[0] == '"' || val[0] == '\'') && val[strlen(val) - 1] == val[0]) {
            val[strlen(val) - 1] = '\0';
            val++;
        }
        if (key[0])
            json_object_object_add(conf, key, json_object_new_string(val));
        line = strtok_r(NULL, "\n", &save);
    }
    *out = conf;
    return 0;
}

static const char *nc_conf_str(struct json_object *conf, const char *key)
{
    struct json_object *v = NULL;
    if (!conf || !json_object_object_get_ex(conf, key, &v) || !v)
        return "";
    return json_object_get_string(v) ? json_object_get_string(v) : "";
}

static long long nc_conf_i64(struct json_object *conf, const char *key, long long def)
{
    const char *s = nc_conf_str(conf, key);
    if (!s || !s[0])
        return def;
    return atoll(s);
}

static void nc_sig_error(struct json_object *errors, const char *code, const char *detail)
{
    struct json_object *e;
    if (!errors)
        return;
    e = json_object_new_object();
    json_object_object_add(e, "code", json_object_new_string(code ? code : "error"));
    json_object_object_add(e, "detail", json_object_new_string(detail ? detail : ""));
    json_object_array_add(errors, e);
}

static int nc_sig_required_conf(struct json_object *conf, struct json_object *errors)
{
    static const char *keys[] = {
        "format", "version", "build_epoch", "build_date", "source_db", "db_sha256",
        "apps", "dpi_rules", "domain_groups", "domain_entries", "device_vendors",
        "device_types", "device_fingerprint_rules", "carrier_prefixes",
        "app_icon_mappings", "icon_assets", "logo_files", NULL
    };
    int ok = 1;
    int i;
    for (i = 0; keys[i]; i++) {
        if (!nc_conf_str(conf, keys[i])[0]) {
            nc_sig_error(errors, "missing_conf_field", keys[i]);
            ok = 0;
        }
    }
    return ok;
}

static void nc_sig_counts_json(sqlite3 *db, struct json_object *counts)
{
    int geoip_countries = nc_sig_table_exists(db, "geoip_country")
        ? nc_sig_scalar_i(db, "SELECT COUNT(*) FROM geoip_country WHERE enabled=1")
        : 0;
    int geoip_country_prefixes = nc_sig_table_exists(db, "geoip_country_prefix")
        ? nc_sig_scalar_i(db, "SELECT COUNT(*) FROM geoip_country_prefix WHERE enabled=1")
        : 0;
    int reputation_ip_entries = nc_sig_table_exists(db, "reputation_ip_entry")
        ? nc_sig_scalar_i(db, "SELECT COUNT(*) FROM reputation_ip_entry WHERE enabled=1")
        : 0;
    int reputation_domain_entries = nc_sig_table_exists(db, "reputation_domain_entry")
        ? nc_sig_scalar_i(db, "SELECT COUNT(*) FROM reputation_domain_entry WHERE enabled=1")
        : 0;
    int reputation_url_entries = nc_sig_table_exists(db, "reputation_url_entry")
        ? nc_sig_scalar_i(db, "SELECT COUNT(*) FROM reputation_url_entry WHERE enabled=1")
        : 0;
    int content_categories = nc_sig_table_exists(db, "content_category")
        ? nc_sig_scalar_i(db, "SELECT COUNT(*) FROM content_category WHERE enabled=1")
        : 0;
    int content_domain_entries = nc_sig_table_exists(db, "content_domain_entry")
        ? nc_sig_scalar_i(db, "SELECT COUNT(*) FROM content_domain_entry WHERE enabled=1")
        : 0;

    json_object_object_add(counts, "apps", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM app WHERE enabled=1")));
    json_object_object_add(counts, "dpi_rules", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM dpi_rule WHERE enabled=1")));
    json_object_object_add(counts, "domain_groups", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM domain_group")));
    json_object_object_add(counts, "domain_entries", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM domain_entry")));
    json_object_object_add(counts, "device_vendors", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM device_vendor")));
    json_object_object_add(counts, "device_types", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM device_type")));
    json_object_object_add(counts, "device_fingerprint_rules", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM device_fingerprint_rule WHERE enabled=1")));
    json_object_object_add(counts, "carrier_prefixes", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM carrier_prefix WHERE enabled=1")));
    json_object_object_add(counts, "geoip_countries", json_object_new_int(geoip_countries));
    json_object_object_add(counts, "geoip_country_prefixes", json_object_new_int(geoip_country_prefixes));
    json_object_object_add(counts, "reputation_ip_entries", json_object_new_int(reputation_ip_entries));
    json_object_object_add(counts, "reputation_domain_entries", json_object_new_int(reputation_domain_entries));
    json_object_object_add(counts, "reputation_url_entries", json_object_new_int(reputation_url_entries));
    json_object_object_add(counts, "content_categories", json_object_new_int(content_categories));
    json_object_object_add(counts, "content_domain_entries", json_object_new_int(content_domain_entries));
    json_object_object_add(counts, "app_icon_mappings", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM app_icon")));
    json_object_object_add(counts, "icon_assets", json_object_new_int(nc_sig_scalar_i(db, "SELECT COUNT(*) FROM icon_asset")));
}

static int nc_json_get_count(struct json_object *counts, const char *key)
{
    struct json_object *v = NULL;
    if (!counts || !json_object_object_get_ex(counts, key, &v) || !v)
        return -1;
    return json_object_get_int(v);
}

static int nc_sig_check_count(struct json_object *conf, struct json_object *counts,
                              struct json_object *errors, const char *key)
{
    long long expected = nc_conf_i64(conf, key, -1);
    int actual = nc_json_get_count(counts, key);
    char detail[128];

    if (expected < 0 || actual < 0)
        return -1;
    if (expected != actual) {
        snprintf(detail, sizeof(detail), "%s expected=%lld actual=%d", key, expected, actual);
        nc_sig_error(errors, "count_mismatch", detail);
        return -1;
    }
    return 0;
}

static int nc_sig_validate_manifest(const char *tmpdir, struct json_object *d,
                                    struct json_object *errors)
{
    char path[PATH_MAX];
    struct json_object *manifest = NULL;
    struct json_object *datasets = NULL;
    int ok = 0;
    int i, n;
    int fingerprint_datasets = 0;

    if (!tmpdir || !d || !errors ||
        snprintf(path, sizeof(path), "%s/manifest.json", tmpdir) >= (int)sizeof(path)) {
        nc_sig_error(errors, "manifest_path_too_long", "manifest.json");
        return -1;
    }
    manifest = json_object_from_file(path);
    if (!manifest || !json_object_is_type(manifest, json_type_object)) {
        nc_sig_error(errors, "invalid_manifest_json", "manifest.json");
        if (manifest)
            json_object_put(manifest);
        return -1;
    }
    json_object_object_add(d, "manifest", json_object_get(manifest));
    if (strcmp(nc_json_str_def(manifest, "format", ""), "signature-update-v2") != 0) {
        nc_sig_error(errors, "unsupported_manifest_format",
                     nc_json_str_def(manifest, "format", ""));
        ok = -1;
    }
    if (!json_object_object_get_ex(manifest, "datasets", &datasets) ||
        !datasets || !json_object_is_type(datasets, json_type_array)) {
        nc_sig_error(errors, "missing_manifest_datasets", "datasets");
        json_object_put(manifest);
        return -1;
    }
    n = json_object_array_length(datasets);
    for (i = 0; i < n; i++) {
        struct json_object *ds = json_object_array_get_idx(datasets, i);
        const char *name = nc_json_str_def(ds, "name", "");
        const char *rel = nc_json_str_def(ds, "path", "");
        const char *sha = nc_json_str_def(ds, "sha256", "");
        char ds_path[PATH_MAX];
        char got[65] = {0};

        if (!name[0] || !rel[0] || rel[0] == '/' || strstr(rel, "..")) {
            nc_sig_error(errors, "invalid_dataset_entry", name);
            ok = -1;
            continue;
        }
        if (!strcmp(name, "fingerprint") &&
            strcmp(rel, "fingerprint/fingerprint.db") != 0) {
            nc_sig_error(errors, "fingerprint_path_not_canonical", rel);
            ok = -1;
            continue;
        }
        if (!strcmp(name, "fingerprint"))
            fingerprint_datasets++;
        if (snprintf(ds_path, sizeof(ds_path), "%s/%s", tmpdir, rel) >= (int)sizeof(ds_path)) {
            nc_sig_error(errors, "dataset_path_too_long", name);
            ok = -1;
            continue;
        }
        if (rel[strlen(rel) - 1] == '/') {
            if (!nc_path_is_dir(ds_path)) {
                nc_sig_error(errors, "dataset_dir_missing", name);
                ok = -1;
            } else if (sha[0] && nc_sha256_tree(ds_path, got, sizeof(got)) != 0) {
                nc_sig_error(errors, "dataset_sha256_failed", name);
                ok = -1;
            } else if (sha[0] && strcasecmp(sha, got) != 0) {
                nc_sig_error(errors, "dataset_sha256_mismatch", name);
                ok = -1;
            }
            continue;
        }
        if (!nc_path_is_regular_readable(ds_path)) {
            nc_sig_error(errors, "dataset_file_missing", name);
            ok = -1;
            continue;
        }
        if (sha[0] && nc_sha256_file(ds_path, got, sizeof(got)) != 0) {
            nc_sig_error(errors, "dataset_sha256_failed", name);
            ok = -1;
        } else if (sha[0] && strcasecmp(sha, got) != 0) {
            nc_sig_error(errors, "dataset_sha256_mismatch", name);
            ok = -1;
        }
    }
    if (fingerprint_datasets > 1) {
        nc_sig_error(errors, "duplicate_fingerprint_dataset", "fingerprint");
        ok = -1;
    }
    if (nc_path_is_dir(tmpdir)) {
        char fingerprint_dir[PATH_MAX];
        int fingerprint_tree_present = 0;

        if (snprintf(fingerprint_dir, sizeof(fingerprint_dir), "%s/fingerprint", tmpdir) >=
            (int)sizeof(fingerprint_dir)) {
            nc_sig_error(errors, "path_too_long", "fingerprint");
            ok = -1;
        } else {
            fingerprint_tree_present = nc_path_is_dir(fingerprint_dir);
            if (fingerprint_tree_present != (fingerprint_datasets == 1)) {
                nc_sig_error(errors, "fingerprint_manifest_payload_mismatch",
                             fingerprint_tree_present ? "payload_without_manifest" :
                                                        "manifest_without_payload");
                ok = -1;
            }
        }
    }
    json_object_put(manifest);
    return ok;
}

static const char *nc_sig_icon_runtime_name(const char *name)
{
    if (name && !strcasecmp(name, "tencent-docs.svg"))
        return "tencent.svg";
    return name;
}

static int nc_sig_check_icon_files(sqlite3 *db, const char *logo_dir, struct json_object *errors)
{
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT icon_file FROM icon_asset WHERE COALESCE(icon_file,'')<>''";
    int ok = 0;
    int checked = 0;
    char path[PATH_MAX];
    char detail[PATH_MAX + 32];

    if (!db || !logo_dir || sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *icon_file = (const char *)sqlite3_column_text(st, 0);
        const char *name = icon_file;
        if (!icon_file || !icon_file[0])
            continue;
        if (!strncmp(icon_file, "icons/", 6))
            name = icon_file + 6;
        name = nc_sig_icon_runtime_name(name);
        if (strstr(name, "..") || strchr(name, '/')) {
            nc_sig_error(errors, "invalid_icon_file", icon_file);
            ok = -1;
            continue;
        }
        if (snprintf(path, sizeof(path), "%s/%s", logo_dir, name) >= (int)sizeof(path)) {
            nc_sig_error(errors, "icon_path_too_long", icon_file);
            ok = -1;
            continue;
        }
        checked++;
        if (!nc_path_is_regular_readable(path)) {
            snprintf(detail, sizeof(detail), "%s missing", icon_file);
            nc_sig_error(errors, "icon_file_unreadable", detail);
            ok = -1;
        }
    }
    sqlite3_finalize(st);
    if (checked == 0) {
        nc_sig_error(errors, "icon_files_empty", "no icon_asset rows with icon_file");
        ok = -1;
    }
    return ok;
}

static int nc_sig_regular_file_count(const char *dir)
{
    DIR *dp;
    struct dirent *de;
    int count = 0;

    if (!dir || !dir[0] || !(dp = opendir(dir)))
        return -1;
    while ((de = readdir(dp)) != NULL) {
        char path[PATH_MAX];
        struct stat st;
        int nested;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) >= (int)sizeof(path) ||
            lstat(path, &st) != 0) {
            closedir(dp);
            return -1;
        }
        if (S_ISREG(st.st_mode)) {
            count++;
        } else if (S_ISDIR(st.st_mode)) {
            nested = nc_sig_regular_file_count(path);
            if (nested < 0 || count > INT_MAX - nested) {
                closedir(dp);
                return -1;
            }
            count += nested;
        } else {
            closedir(dp);
            return -1;
        }
    }
    closedir(dp);
    return count;
}

static int nc_signature_db_path(char *path, size_t path_len)
{
    enum jmx_system_db_source source;
    char error[64];

    if (jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, path, path_len,
                              &source, error, sizeof(error)) == 0)
        return 0;
    LOG_WARN("signature DB resolve failed: %s\n", error);
    return -1;
}

int nc_sig_open(sqlite3 **db)
{
    char path[512];

    if (!db) return -1;
    *db = NULL;
    if (nc_signature_db_path(path, sizeof(path)) != 0)
        return -1;
    if (sqlite3_open_v2(path, db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK)
        return 0;
    if (*db) {
        sqlite3_close(*db);
        *db = NULL;
    }
    return -1;
}

static void nc_sig_icon_file_public(const char *icon_file, char *buf, size_t len)
{
    const char *base = icon_file;
    size_t n;

    if (!buf || len == 0)
        return;
    buf[0] = '\0';
    if (!icon_file || !icon_file[0])
        return;
    if (!strncmp(icon_file, "icons/", 6))
        base = icon_file + 6;
    /* The imported signature DB historically pointed the whole Tencent
     * family at an asset that is not part of the runtime icon contract. */
    base = nc_sig_icon_runtime_name(base);
    snprintf(buf, len, "%s", base);
    n = strlen(buf);
    if (n > 4 && !strcasecmp(buf + n - 4, ".jpg"))
        memcpy(buf + n - 4, ".png", 5);
    else if (n > 5 && !strcasecmp(buf + n - 5, ".jpeg"))
        memcpy(buf + n - 5, ".png", 5);
}

static int nc_sig_host_is_or_subdomain(const char *host, const char *domain)
{
    size_t host_len;
    size_t domain_len;

    if (!host || !host[0] || !domain || !domain[0])
        return 0;
    host_len = strlen(host);
    domain_len = strlen(domain);
    if (host_len < domain_len ||
        strcasecmp(host + host_len - domain_len, domain) != 0)
        return 0;
    return host_len == domain_len || host[host_len - domain_len - 1] == '.';
}

static int nc_sig_builtin_host_app_id(const char *host)
{
    /* Keep this list intentionally small. It only closes high-confidence
     * gaps after the updateable signature database has failed to match. */
    if (nc_sig_host_is_or_subdomain(host, "alidns.com"))
        return 100000071; /* Ali HTTPDNS */
    if (nc_sig_host_is_or_subdomain(host, "weixin.qq.com") ||
        nc_sig_host_is_or_subdomain(host, "wechat.com"))
        return 100000243; /* WeChat */
    return 0;
}

static void nc_sig_icon_url(const char *icon_file, char *buf, size_t len)
{
    char public_file[256];

    if (!buf || len == 0)
        return;
    buf[0] = '\0';
    nc_sig_icon_file_public(icon_file, public_file, sizeof(public_file));
    if (!public_file[0])
        return;
    snprintf(buf, len, "%s%s", JMX_SIGNATURE_ICON_URL_PREFIX, public_file);
}

static const char *nc_sig_entity_type_guess(const char *name, const char *category_slug, const char *family)
{
    if ((family && strstr(family, "protocol")) ||
        (category_slug && strstr(category_slug, "protocol")))
        return "protocol";
    if ((family && strstr(family, "system")) ||
        (category_slug && strstr(category_slug, "system")) ||
        (name && (strstr(name, "更新") || strstr(name, "Update") || strstr(name, "update"))))
        return "system_update";
    if ((family && strstr(family, "ad")) ||
        (category_slug && strstr(category_slug, "ad")))
        return "ad_tracking";
    if ((family && strstr(family, "account")) ||
        (category_slug && strstr(category_slug, "account")))
        return "account";
    if ((family && strstr(family, "vendor")) ||
        (name && (strstr(name, "系列") || strstr(name, "专用协议") || strstr(name, "通用协议"))))
        return "vendor_family";
    if ((family && strstr(family, "service")) ||
        (category_slug && strstr(category_slug, "service")))
        return "service";
    return "app";
}

static void nc_sig_add_app_meta_fields(struct json_object *o, int app_id,
                                       const char *name, const char *category_slug,
                                       const char *category, const char *family,
                                       const char *icon_key, const char *icon_file)
{
    char icon_url[256];
    const char *entity_type = nc_sig_entity_type_guess(name, category_slug, family);

    if (!o)
        return;
    if (category_slug)
        json_object_object_add(o, "category_slug", json_object_new_string(category_slug));
    if (category)
        json_object_object_add(o, "category", json_object_new_string(category));
    if (family)
        json_object_object_add(o, "family", json_object_new_string(family));
    json_object_object_add(o, "icon_key", json_object_new_string(icon_key ? icon_key : ""));
    nc_sig_icon_file_public(icon_file, icon_url, sizeof(icon_url));
    json_object_object_add(o, "icon_file", json_object_new_string(icon_url));
    nc_sig_icon_url(icon_file, icon_url, sizeof(icon_url));
    json_object_object_add(o, "icon_url", json_object_new_string(icon_url));
    json_object_object_add(o, "entity_type", json_object_new_string(app_id > 0 ? entity_type : "unknown"));
    json_object_object_add(o, "unknown", json_object_new_boolean(app_id <= 0));
}

int jmx_signature_db_fill_app_meta(struct json_object *obj, int app_id)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    const char *sql =
        "SELECT a.name,COALESCE(c.slug,''),COALESCE(c.name,''),COALESCE(a.family,''),"
        "COALESCE(ai.icon_key,''),COALESCE(ia.icon_file,'') "
        "FROM app a "
        "LEFT JOIN app_category c ON c.category_id=a.category_id "
        "LEFT JOIN app_icon ai ON ai.app_id=a.app_id "
        "LEFT JOIN icon_asset ia ON ia.icon_key=ai.icon_key "
        "WHERE a.app_id=?1 AND a.enabled=1 LIMIT 1";
    int ok = -1;

    if (!obj || app_id <= 0)
        return -1;
    if (nc_sig_open(&db) != 0)
        return -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, app_id);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(st, 0);
            const char *category_slug = (const char *)sqlite3_column_text(st, 1);
            const char *category = (const char *)sqlite3_column_text(st, 2);
            const char *family = (const char *)sqlite3_column_text(st, 3);
            const char *icon_key = (const char *)sqlite3_column_text(st, 4);
            const char *icon_file = (const char *)sqlite3_column_text(st, 5);
            if (name && name[0]) {
                json_object_object_add(obj, "app_name", json_object_new_string(name));
                json_object_object_add(obj, "name", json_object_new_string(name));
            }
            nc_sig_add_app_meta_fields(obj, app_id, name, category_slug, category,
                                       family, icon_key, icon_file);
            ok = 0;
        }
    }
    if (st) sqlite3_finalize(st);
    sqlite3_close(db);
    return ok;
}

static int nc_sig_add_resolved_app(sqlite3 *db, struct json_object *o, int app_id,
                                   int rule_id, const char *matched_value,
                                   const char *source, double confidence)
{
    sqlite3_stmt *st = NULL;
    const char *sql =
        "SELECT a.name,COALESCE(c.slug,''),COALESCE(c.name,''),COALESCE(a.family,''),"
        "COALESCE(ai.icon_key,''),COALESCE(ia.icon_file,'') "
        "FROM app a "
        "LEFT JOIN app_category c ON c.category_id=a.category_id "
        "LEFT JOIN app_icon ai ON ai.app_id=a.app_id "
        "LEFT JOIN icon_asset ia ON ia.icon_key=ai.icon_key "
        "WHERE a.app_id=?1 AND a.enabled=1 LIMIT 1";

    if (!db || !o || app_id <= 0)
        return -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, app_id);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 0);
        json_object_object_add(o, "app_id", json_object_new_int(app_id));
        json_object_object_add(o, "app_name", json_object_new_string(name ? name : ""));
        nc_sig_add_app_meta_fields(o, app_id, name,
                                   (const char *)sqlite3_column_text(st, 1),
                                   (const char *)sqlite3_column_text(st, 2),
                                   (const char *)sqlite3_column_text(st, 3),
                                   (const char *)sqlite3_column_text(st, 4),
                                   (const char *)sqlite3_column_text(st, 5));
        json_object_object_add(o, "confidence", json_object_new_double(confidence));
        json_object_object_add(o, "source", json_object_new_string(source ? source : ""));
        json_object_object_add(o, "matched_rule_id", json_object_new_int(rule_id));
        json_object_object_add(o, "matched_value", json_object_new_string(matched_value ? matched_value : ""));
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    return -1;
}

static int nc_sig_pattern_is_host_candidate(const char *pattern)
{
    static const char *suffixes[] = {
        ".com", "\\.com", ".cn", "\\.cn", ".net", "\\.net",
        ".org", "\\.org", ".tv", "\\.tv", ".cc", "\\.cc",
        ".io", "\\.io", ".app", "\\.app", ".cloud", "\\.cloud",
        ".top", "\\.top", ".vip", "\\.vip", ".me", "\\.me",
        NULL
    };
    int has_alpha = 0;

    if (!pattern || !pattern[0] || !strchr(pattern, '.'))
        return 0;
    if (strstr(pattern, "\\x") || strstr(pattern, "Host:") ||
        strstr(pattern, "User-Agent:") || strstr(pattern, "\r") ||
        strstr(pattern, "\n"))
        return 0;
    for (const char *p = pattern; *p; p++) {
        if (isalpha((unsigned char)*p)) {
            has_alpha = 1;
            break;
        }
    }
    if (!has_alpha)
        return 0;
    for (int i = 0; suffixes[i]; i++) {
        if (strstr(pattern, suffixes[i]))
            return 1;
    }
    if (strstr(pattern, "(com|") || strstr(pattern, "|com)") ||
        strstr(pattern, "(cn|") || strstr(pattern, "|cn)") ||
        strstr(pattern, "(net|") || strstr(pattern, "|net)"))
        return 1;
    return 0;
}

static int nc_sig_pattern_match_score(const char *host, const char *match_type,
                                      const char *pattern)
{
    if (!host || !host[0] || !pattern || !pattern[0])
        return 0;
    if (!nc_sig_pattern_is_host_candidate(pattern))
        return 0;
    if (!strcmp(host, pattern))
        return 100;
    if (strlen(host) > strlen(pattern) &&
        host[strlen(host) - strlen(pattern) - 1] == '.' &&
        !strcmp(host + strlen(host) - strlen(pattern), pattern))
        return 95;
    if (match_type && (!strcmp(match_type, "bm") || !strcmp(match_type, "bm_str") ||
                       !strcmp(match_type, "contains"))) {
        if (strlen(pattern) >= 5 && strstr(host, pattern))
            return 85;
    }
    if (match_type && !strcmp(match_type, "regex") && strlen(pattern) >= 5) {
        regex_t re;
        int rc;
        if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0)
            return 0;
        rc = regexec(&re, host, 0, NULL, 0);
        regfree(&re);
        if (rc == 0)
            return 90;
    }
    return 0;
}

static void nc_sig_host_rule_cache_free(void)
{
    int i;

    if (!g_sig_host_rules)
        return;
    for (i = 0; i < g_sig_host_rule_count; i++) {
        if (g_sig_host_rules[i].regex_ready)
            regfree(&g_sig_host_rules[i].regex);
    }
    free(g_sig_host_rules);
    g_sig_host_rules = NULL;
    g_sig_host_rule_count = 0;
    g_sig_host_db_mtime = 0;
    g_sig_host_db_size = 0;
}

static int nc_sig_host_rule_match_score(const nc_sig_host_rule_cache_t *rule,
                                        const char *host)
{
    const char *pattern;

    if (!rule || !host || !host[0])
        return 0;
    pattern = rule->pattern;
    if (!pattern[0])
        return 0;
    if (!strcmp(host, pattern))
        return 100;
    if (strlen(host) > strlen(pattern) &&
        host[strlen(host) - strlen(pattern) - 1] == '.' &&
        !strcmp(host + strlen(host) - strlen(pattern), pattern))
        return 95;
    if ((!strcmp(rule->match_type, "bm") || !strcmp(rule->match_type, "bm_str") ||
         !strcmp(rule->match_type, "contains")) &&
        strlen(pattern) >= 5 && strstr(host, pattern))
        return 85;
    if (!strcmp(rule->match_type, "regex") && rule->regex_ready &&
        regexec(&rule->regex, host, 0, NULL, 0) == 0)
        return 90;
    return 0;
}

static int nc_sig_host_rule_cache_load(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    struct stat sb;
    char path[512];
    int loaded = 0;

    if (!db)
        return -1;
    if (nc_signature_db_path(path, sizeof(path)) != 0)
        return -1;
    if (stat(path, &sb) != 0)
        memset(&sb, 0, sizeof(sb));
    if (g_sig_host_rules && g_sig_host_db_mtime == sb.st_mtime &&
        g_sig_host_db_size == sb.st_size)
        return 0;

    nc_sig_host_rule_cache_free();
    g_sig_host_rules = calloc(NC_SIG_HOST_RULE_CACHE_MAX, sizeof(*g_sig_host_rules));
    if (!g_sig_host_rules)
        return -1;

    if (sqlite3_prepare_v2(db,
            "SELECT r.rule_id,r.app_id,COALESCE(r.proto,''),"
            "COALESCE(r.match_type,''),COALESCE(r.pattern_text,''),"
            "COALESCE(r.priority,50) "
            "FROM dpi_rule r JOIN app a ON a.app_id=r.app_id AND a.enabled=1 "
            "WHERE r.enabled=1 AND r.pattern_format='text' "
            "AND length(r.pattern_text)>=3 "
            "ORDER BY r.priority ASC,length(r.pattern_text) DESC,r.rule_id ASC",
            -1, &st, NULL) != SQLITE_OK) {
        nc_sig_host_rule_cache_free();
        return -1;
    }

    while (sqlite3_step(st) == SQLITE_ROW &&
           loaded < NC_SIG_HOST_RULE_CACHE_MAX) {
        const char *pattern = (const char *)sqlite3_column_text(st, 4);
        const char *match_type = (const char *)sqlite3_column_text(st, 3);
        nc_sig_host_rule_cache_t *rule;

        if (!nc_sig_pattern_is_host_candidate(pattern))
            continue;
        rule = &g_sig_host_rules[loaded];
        rule->rule_id = sqlite3_column_int(st, 0);
        rule->app_id = sqlite3_column_int(st, 1);
        rule->priority = sqlite3_column_int(st, 5);
        snprintf(rule->proto, sizeof(rule->proto), "%s",
                 (const char *)sqlite3_column_text(st, 2));
        snprintf(rule->match_type, sizeof(rule->match_type), "%s",
                 match_type ? match_type : "");
        snprintf(rule->pattern, sizeof(rule->pattern), "%s",
                 pattern ? pattern : "");
        if (!strcmp(rule->match_type, "regex") &&
            regcomp(&rule->regex, rule->pattern,
                    REG_EXTENDED | REG_NOSUB | REG_ICASE) == 0)
            rule->regex_ready = 1;
        loaded++;
    }
    sqlite3_finalize(st);
    g_sig_host_rule_count = loaded;
    g_sig_host_db_mtime = sb.st_mtime;
    g_sig_host_db_size = sb.st_size;
    return 0;
}

static int nc_sig_resolve_host_app_id_from_cache(sqlite3 *db, const char *host,
                                                 const char *proto,
                                                 int dst_port, int *app_id)
{
    int best_score = 0, best_app = 0, best_prio = 999999;
    int i;

    (void)dst_port;
    if (app_id)
        *app_id = 0;
    if (!db || !host || !host[0] || !app_id)
        return -1;
    if (nc_sig_host_rule_cache_load(db) != 0)
        return -1;

    for (i = 0; i < g_sig_host_rule_count; i++) {
        nc_sig_host_rule_cache_t *rule = &g_sig_host_rules[i];
        int score;

        if (proto && proto[0] && rule->proto[0] &&
            strcasecmp(rule->proto, proto) != 0)
            continue;
        score = nc_sig_host_rule_match_score(rule, host);
        if (score <= 0)
            continue;
        if (score > best_score ||
            (score == best_score && rule->priority < best_prio)) {
            best_score = score;
            best_app = rule->app_id;
            best_prio = rule->priority;
            if (score >= 100)
                break;
        }
    }

    if (best_app > 0) {
        *app_id = best_app;
        return 0;
    }
    return 1;
}

static int nc_sig_resolve_host_with_db(sqlite3 *db, const char *host,
                                       const char *proto, int dst_port,
                                       struct json_object *out)
{
    sqlite3_stmt *st = NULL;
    const char *sql =
        "SELECT r.rule_id,r.app_id,COALESCE(r.match_type,''),COALESCE(r.pattern_text,''),"
        "COALESCE(r.priority,50) "
        "FROM dpi_rule r "
        "WHERE r.enabled=1 AND r.pattern_format='text' AND length(r.pattern_text)>=3 "
        "AND (?1='' OR r.proto='' OR r.proto IS NULL OR lower(r.proto)=lower(?1)) "
        "ORDER BY r.priority ASC,length(r.pattern_text) DESC,r.rule_id ASC";
    int rc = -1;
    int best_score = 0, best_rule = 0, best_app = 0, best_prio = 999999;
    char best_pattern[256] = {0};
    char best_source[32] = {0};

    (void)dst_port;
    if (!db || !host || !host[0] || !out)
        return -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, proto ? proto : "", -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        int rule_id = sqlite3_column_int(st, 0);
        int app_id = sqlite3_column_int(st, 1);
        const char *match_type = (const char *)sqlite3_column_text(st, 2);
        const char *pattern = (const char *)sqlite3_column_text(st, 3);
        int prio = sqlite3_column_int(st, 4);
        int score = nc_sig_pattern_match_score(host, match_type, pattern);
        if (score <= 0)
            continue;
        if (score > best_score || (score == best_score && prio < best_prio)) {
            best_score = score;
            best_rule = rule_id;
            best_app = app_id;
            best_prio = prio;
            snprintf(best_pattern, sizeof(best_pattern), "%s", pattern ? pattern : "");
            snprintf(best_source, sizeof(best_source), "%s",
                     match_type && match_type[0] ? match_type : "dpi_rule");
            if (score >= 100)
                break;
        }
    }
    sqlite3_finalize(st);
    if (best_app > 0) {
        double confidence = best_score >= 95 ? 0.95 : (best_score >= 85 ? 0.85 : 0.70);
        rc = nc_sig_add_resolved_app(db, out, best_app, best_rule, best_pattern,
                                     best_source, confidence);
    }
    return rc;
}

int jmx_signature_db_resolve_host_app_id(const char *host, const char *proto,
                                         int dst_port, int *app_id)
{
    sqlite3 *db = NULL;
    int rc = -1;

    if (app_id)
        *app_id = 0;
    if (!host || !host[0] || !app_id)
        return -1;
    if (nc_sig_open(&db) != 0)
        return -1;

    rc = jmx_signature_db_resolve_host_app_id_with_db(db, host, proto, dst_port,
                                                      app_id);
    sqlite3_close(db);
    return rc;
}

int jmx_signature_db_open(sqlite3 **db)
{
    return nc_sig_open(db);
}

void jmx_signature_db_close(sqlite3 *db)
{
    if (db)
        sqlite3_close(db);
}

int jmx_signature_db_resolve_host_app_id_with_db(sqlite3 *db, const char *host,
                                                 const char *proto,
                                                 int dst_port, int *app_id)
{
    struct json_object *out = NULL;
    struct json_object *v = NULL;
    int rc = -1;
    int cache_rc;

    if (app_id)
        *app_id = 0;
    if (!db || !host || !host[0] || !app_id)
        return -1;

    cache_rc = nc_sig_resolve_host_app_id_from_cache(db, host, proto, dst_port,
                                                     app_id);
    if (cache_rc == 0)
        return 0;
    if (cache_rc > 0) {
        *app_id = nc_sig_builtin_host_app_id(host);
        return *app_id > 0 ? 0 : -1;
    }

    out = json_object_new_object();
    if (out && nc_sig_resolve_host_with_db(db, host, proto, dst_port, out) == 0 &&
        json_object_object_get_ex(out, "app_id", &v) && v) {
        *app_id = json_object_get_int(v);
        rc = *app_id > 0 ? 0 : -1;
    }
    if (out)
        json_object_put(out);
    if (rc != 0) {
        *app_id = nc_sig_builtin_host_app_id(host);
        rc = *app_id > 0 ? 0 : -1;
    }
    return rc;
}

static int nc_sig_scalar_i(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL; int v = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int(st, 0);
    if (st) sqlite3_finalize(st);
    return v;
}

static int nc_sig_table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (!db || !name)
        return 0;
    if (sqlite3_prepare_v2(db,
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        exists = sqlite3_step(st) == SQLITE_ROW;
    }
    if (st)
        sqlite3_finalize(st);
    return exists;
}

static int nc_sig_pragma_i(sqlite3 *db, const char *pragma, int *value)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!db || !pragma || !value ||
        sqlite3_prepare_v2(db, pragma, -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *value = sqlite3_column_int(st, 0);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

static int nc_sig_fingerprint_validate(const char *path, struct json_object *d,
                                       struct json_object *errors)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    char sha[65] = {0};
    char detail[160];
    int application_id = 0;
    int schema_version = 0;
    int expected = 0;
    int actual = 0;
    int rc = -1;

    if (!nc_path_is_regular_readable(path)) {
        nc_sig_error(errors, "fingerprint_db_missing", path ? path : "");
        return -1;
    }
    if (nc_sqlite_integrity_check(path) != 0) {
        nc_sig_error(errors, "fingerprint_integrity_failed", path);
        return -1;
    }
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        nc_sig_error(errors, "fingerprint_open_failed", path);
        goto done;
    }
    if (nc_sig_pragma_i(db, "PRAGMA application_id", &application_id) != 0 ||
        application_id != JMX_FINGERPRINT_DB_APPLICATION_ID) {
        snprintf(detail, sizeof(detail), "application_id expected=%d actual=%d",
                 JMX_FINGERPRINT_DB_APPLICATION_ID, application_id);
        nc_sig_error(errors, "fingerprint_application_id_mismatch", detail);
        goto done;
    }
    if (nc_sig_pragma_i(db, "PRAGMA user_version", &schema_version) != 0 ||
        schema_version != JMX_FINGERPRINT_DB_SCHEMA_VERSION) {
        snprintf(detail, sizeof(detail), "user_version expected=%d actual=%d",
                 JMX_FINGERPRINT_DB_SCHEMA_VERSION, schema_version);
        nc_sig_error(errors, "fingerprint_schema_mismatch", detail);
        goto done;
    }
    if (!nc_sig_table_exists(db, "fingerprint_device") ||
        !nc_sig_table_exists(db, "fingerprint_meta")) {
        nc_sig_error(errors, "fingerprint_schema_missing",
                     "fingerprint_device or fingerprint_meta");
        goto done;
    }
    if (sqlite3_prepare_v2(db,
            "SELECT CAST(value AS INTEGER) FROM fingerprint_meta WHERE key='device_count'",
            -1, &st, NULL) != SQLITE_OK || sqlite3_step(st) != SQLITE_ROW) {
        nc_sig_error(errors, "fingerprint_device_count_missing", "fingerprint_meta");
        goto done;
    }
    expected = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    st = NULL;
    actual = nc_sig_scalar_i(db, "SELECT COUNT(*) FROM fingerprint_device");
    if (expected <= 0 || actual != expected) {
        snprintf(detail, sizeof(detail), "device_count expected=%d actual=%d",
                 expected, actual);
        nc_sig_error(errors, "fingerprint_device_count_mismatch", detail);
        goto done;
    }
    if (nc_sha256_file(path, sha, sizeof(sha)) != 0) {
        nc_sig_error(errors, "fingerprint_sha256_failed", path);
        goto done;
    }
    json_object_object_add(d, "fingerprint_present", json_object_new_boolean(1));
    json_object_object_add(d, "fingerprint_device_count", json_object_new_int(actual));
    json_object_object_add(d, "fingerprint_sha256", json_object_new_string(sha));
    rc = 0;
done:
    if (st)
        sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    return rc;
}

static void nc_sig_meta(sqlite3 *db, struct json_object *meta)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT key,value FROM meta ORDER BY key", -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *k = (const char *)sqlite3_column_text(st, 0);
            const char *v = (const char *)sqlite3_column_text(st, 1);
            if (k) json_object_object_add(meta, k, json_object_new_string(v ? v : ""));
        }
    }
    if (st) sqlite3_finalize(st);
}

static void nc_sig_update_build_date_from_conf(struct json_object *d)
{
    struct json_object *conf = NULL;

    if (d && json_object_object_get_ex(d, "conf", &conf) && conf) {
        snprintf(g_sig_update_status.build_date, sizeof(g_sig_update_status.build_date), "%s",
                 nc_conf_str(conf, "build_date"));
        return;
    }
    g_sig_update_status.build_date[0] = '\0';
}

static void nc_sig_remove_tmpdir(const char *tmpdir)
{
    char *const argv[] = { "rm", "-rf", (char *)tmpdir, NULL };
    if (tmpdir && !strncmp(tmpdir, "/tmp/jmxd_sigupd_", 17))
        nc_run_cmd(argv);
}

static int nc_signature_update_validate_path(const char *package_path, struct json_object *d,
                                             char *out_tmpdir, size_t out_tmpdir_len)
{
    char tmp_template[] = JMX_SIGNATURE_UPDATE_TMP_TEMPLATE;
    char conf_path[PATH_MAX];
    char db_path[PATH_MAX];
    char logo_dir[PATH_MAX];
    char fingerprint_dir[PATH_MAX];
    char fingerprint_db[PATH_MAX];
    char sha[65] = {0};
    struct json_object *errors = json_object_new_array();
    struct json_object *conf = NULL;
    struct json_object *counts = json_object_new_object();
    struct json_object *meta = json_object_new_object();
    sqlite3 *db = NULL;
    jmx_rule_set_t rule_set;
    int ok = 1;
    int tmp_created = 0;
    const char *expected_sha;
    const char *format;

    json_object_object_add(d, "path", json_object_new_string(package_path ? package_path : ""));
    json_object_object_add(d, "validated", json_object_new_boolean(0));
    json_object_object_add(d, "errors", errors);

    if (!nc_signature_upload_path_ok(package_path)) {
        nc_sig_error(errors, "invalid_path", "path must be absolute and shell-safe");
        ok = 0;
        goto done;
    }
    if (access(package_path, R_OK) != 0) {
        nc_sig_error(errors, "package_unreadable", package_path);
        ok = 0;
        goto done;
    }
    if (!mkdtemp(tmp_template)) {
        nc_sig_error(errors, "mkdtemp_failed", strerror(errno));
        ok = 0;
        goto done;
    }
    tmp_created = 1;
    if (out_tmpdir && out_tmpdir_len)
        snprintf(out_tmpdir, out_tmpdir_len, "%s", tmp_template);

    if (nc_tar_list_and_extract(package_path, tmp_template) != 0) {
        nc_sig_error(errors, "invalid_package_layout", "expected signature-update.conf, dreamingwrt_signatures.db and logo/");
        ok = 0;
        goto done;
    }
    if (snprintf(conf_path, sizeof(conf_path), "%s/signature-update.conf", tmp_template) >= (int)sizeof(conf_path) ||
        snprintf(db_path, sizeof(db_path), "%s/dreamingwrt_signatures.db", tmp_template) >= (int)sizeof(db_path) ||
        snprintf(logo_dir, sizeof(logo_dir), "%s/logo", tmp_template) >= (int)sizeof(logo_dir) ||
        snprintf(fingerprint_dir, sizeof(fingerprint_dir), "%s/fingerprint", tmp_template) >= (int)sizeof(fingerprint_dir) ||
        snprintf(fingerprint_db, sizeof(fingerprint_db), "%s/fingerprint/fingerprint.db", tmp_template) >= (int)sizeof(fingerprint_db)) {
        nc_sig_error(errors, "path_too_long", "package extract path");
        ok = 0;
        goto done;
    }
    if (!nc_path_is_regular_readable(conf_path) ||
        !nc_path_is_regular_readable(db_path) ||
        !nc_path_is_dir(logo_dir)) {
        nc_sig_error(errors, "missing_entry", "package entries not found after extract");
        ok = 0;
        goto done;
    }
    if (nc_conf_load(conf_path, &conf) != 0) {
        nc_sig_error(errors, "conf_parse_failed", "cannot read signature-update.conf");
        ok = 0;
        goto done;
    }
    json_object_object_add(d, "conf", json_object_get(conf));
    format = nc_conf_str(conf, "format");
    json_object_object_add(d, "format", json_object_new_string(format));
    if (strcmp(format, "signature-update-v1") != 0 &&
        strcmp(format, "signature-update-v2") != 0) {
        nc_sig_error(errors, "unsupported_format", format);
        ok = 0;
    }
    if (!nc_sig_required_conf(conf, errors))
        ok = 0;
    if (strcmp(format, "signature-update-v2") == 0 &&
        nc_sig_validate_manifest(tmp_template, d, errors) != 0)
        ok = 0;
    if (!strcmp(format, "signature-update-v1") && nc_path_is_dir(fingerprint_dir)) {
        nc_sig_error(errors, "fingerprint_requires_v2", "fingerprint/fingerprint.db");
        ok = 0;
    } else if (!strcmp(format, "signature-update-v2") && nc_path_is_dir(fingerprint_dir)) {
        int files = nc_sig_regular_file_count(fingerprint_dir);
        if (files != 1 || !nc_path_is_regular_readable(fingerprint_db)) {
            nc_sig_error(errors, "fingerprint_layout_invalid",
                         "expected only fingerprint/fingerprint.db");
            ok = 0;
        } else if (nc_sig_fingerprint_validate(fingerprint_db, d, errors) != 0) {
            ok = 0;
        }
    } else {
        json_object_object_add(d, "fingerprint_present", json_object_new_boolean(0));
    }
    if (nc_sha256_file(db_path, sha, sizeof(sha)) != 0) {
        nc_sig_error(errors, "sha256_failed", "cannot hash dreamingwrt_signatures.db");
        ok = 0;
    }
    expected_sha = nc_conf_str(conf, "db_sha256");
    if (expected_sha[0] && strcasecmp(expected_sha, sha) != 0) {
        nc_sig_error(errors, "db_sha256_mismatch", sha);
        ok = 0;
    }
    json_object_object_add(d, "db_sha256", json_object_new_string(sha));
    if (nc_sqlite_integrity_check(db_path) != 0) {
        nc_sig_error(errors, "sqlite_integrity_failed", "PRAGMA integrity_check failed");
        ok = 0;
    }
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        nc_sig_error(errors, "cannot_open_signature_db", db ? sqlite3_errmsg(db) : "open failed");
        ok = 0;
    } else {
        int logo_files;
        int invalid_runtime_rules;

        nc_sig_counts_json(db, counts);
        invalid_runtime_rules = nc_signature_runtime_invalid_rule_count(db);
        json_object_object_add(counts, "empty_fixed_payload_rules",
                               json_object_new_int(invalid_runtime_rules));
        if (invalid_runtime_rules < 0) {
            nc_sig_error(errors, "runtime_rule_validation_failed",
                         "cannot validate fixed/exact/bm payloads");
            ok = 0;
        } else if (invalid_runtime_rules > 0) {
            char detail[96];
            snprintf(detail, sizeof(detail),
                     "%d enabled fixed/exact/bm rules have empty payloads",
                     invalid_runtime_rules);
            nc_sig_error(errors, "runtime_empty_fixed_payload", detail);
            ok = 0;
        }
        logo_files = nc_sig_regular_file_count(logo_dir);
        if (logo_files < 0) {
            nc_sig_error(errors, "logo_file_count_failed", logo_dir);
            ok = 0;
        } else {
            json_object_object_add(counts, "logo_files", json_object_new_int(logo_files));
        }
        nc_sig_check_count(conf, counts, errors, "apps");
        nc_sig_check_count(conf, counts, errors, "dpi_rules");
        nc_sig_check_count(conf, counts, errors, "domain_groups");
        nc_sig_check_count(conf, counts, errors, "domain_entries");
        nc_sig_check_count(conf, counts, errors, "device_vendors");
        nc_sig_check_count(conf, counts, errors, "device_types");
        nc_sig_check_count(conf, counts, errors, "device_fingerprint_rules");
        nc_sig_check_count(conf, counts, errors, "carrier_prefixes");
        nc_sig_check_count(conf, counts, errors, "app_icon_mappings");
        nc_sig_check_count(conf, counts, errors, "icon_assets");
        nc_sig_check_count(conf, counts, errors, "logo_files");
        if (json_object_array_length(errors) > 0)
            ok = 0;
        if (nc_sig_check_icon_files(db, logo_dir, errors) != 0)
            ok = 0;
        nc_sig_meta(db, meta);
        sqlite3_close(db);
        db = NULL;
    }
    if (nc_sig_check_regular_tree(logo_dir, errors) != 0)
        ok = 0;
    if (ok && jmx_load_signature_db(db_path, &rule_set) != 0) {
        nc_sig_error(errors, "runtime_loader_failed", "jmxd runtime loader rejected dreamingwrt_signatures.db");
        ok = 0;
    } else if (ok) {
        jmx_rule_set_free(&rule_set);
    }
    json_object_object_add(d, "counts", counts);
    counts = NULL;
    json_object_object_add(d, "meta", meta);
    meta = NULL;
done:
    if (db)
        sqlite3_close(db);
    if (conf)
        json_object_put(conf);
    if (counts)
        json_object_put(counts);
    if (meta)
        json_object_put(meta);
    json_object_object_add(d, "ok", json_object_new_boolean(ok));
    json_object_object_add(d, "validated", json_object_new_boolean(ok));
    if (!ok && tmp_created)
        nc_sig_remove_tmpdir(tmp_template);
    return ok ? 0 : -1;
}

struct json_object *jmx_signature_update_validate(struct json_object *cfg)
{
    const char *path = cfg ? nc_json_str_def(cfg, "path", "") : "";
    struct json_object *d = json_object_new_object();
    char tmpdir[PATH_MAX] = {0};
    int rc;

    nc_sig_status_set("validating", "", path);
    rc = nc_signature_update_validate_path(path, d, tmpdir, sizeof(tmpdir));
    if (rc == 0) {
        nc_sig_status_set("validated", "", path);
        g_sig_update_status.validated = 1;
        g_sig_update_status.applied = 0;
        nc_sig_update_build_date_from_conf(d);
        nc_sig_remove_tmpdir(tmpdir);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
    }
    nc_sig_status_set("validation_failed", "validation_failed", path);
    g_sig_update_status.validated = 0;
    g_sig_update_status.build_date[0] = '\0';
    return jmx_gen_api_response_data(API_CODE_ERROR, d);
}

static int nc_signature_install_icons(const char *icon_dir)
{
    char backup[PATH_MAX];
    char tmp_target[PATH_MAX];
    char target_parent[PATH_MAX] = "/www/dreamingwrt/static/images";
    char *const rm_backup[] = { "rm", "-rf", backup, NULL };
    char *const rm_tmp[] = { "rm", "-rf", tmp_target, NULL };
    char *const cp_icons[] = { "cp", "-a", (char *)icon_dir, tmp_target, NULL };

    if (!icon_dir || !icon_dir[0])
        return -1;
    if (snprintf(backup, sizeof(backup), "%s/.logo.bak.%lld",
                 target_parent, (long long)nc_now_s()) >= (int)sizeof(backup) ||
        snprintf(tmp_target, sizeof(tmp_target), "%s/.logo.new.%lld",
                 target_parent, (long long)nc_now_s()) >= (int)sizeof(tmp_target))
        return -1;
    if (nc_mkdir_p(target_parent) != 0)
        return -1;
    nc_run_cmd(rm_tmp);
    if (nc_run_cmd(cp_icons) != 0)
        return -1;
    if (access(JMX_SIGNATURE_ICON_TARGET_DIR, F_OK) == 0) {
        if (rename(JMX_SIGNATURE_ICON_TARGET_DIR, backup) != 0) {
            nc_run_cmd(rm_tmp);
            return -1;
        }
    } else {
        backup[0] = '\0';
    }
    if (rename(tmp_target, JMX_SIGNATURE_ICON_TARGET_DIR) != 0) {
        if (backup[0])
            rename(backup, JMX_SIGNATURE_ICON_TARGET_DIR);
        nc_run_cmd(rm_tmp);
        return -1;
    }
    if (backup[0])
        nc_run_cmd(rm_backup);
    return 0;
}

static int nc_signature_install_geoip_dataset(const char *tmpdir, struct json_object *d,
                                              struct json_object *errors, int *installed)
{
    char src_mmdb[PATH_MAX];
    char tmp_target[PATH_MAX];
    struct stat st;

    if (installed)
        *installed = 0;
    if (!tmpdir || !tmpdir[0])
        return -1;
    if (snprintf(src_mmdb, sizeof(src_mmdb), "%s/geoip/GeoLite2-Country.mmdb", tmpdir) >=
        (int)sizeof(src_mmdb)) {
        nc_sig_error(errors, "path_too_long", "geoip source path");
        return -1;
    }
    if (lstat(src_mmdb, &st) != 0) {
        json_object_object_add(d, "geoip_installed", json_object_new_boolean(0));
        return 0;
    }
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || access(src_mmdb, R_OK) != 0) {
        nc_sig_error(errors, "invalid_geoip_dataset", "geoip/GeoLite2-Country.mmdb");
        return -1;
    }
    if (nc_mmdb_marker_check(src_mmdb) != 0) {
        nc_sig_error(errors, "invalid_geoip_mmdb", "geoip/GeoLite2-Country.mmdb");
        return -1;
    }
    if (nc_mkdir_p(JMX_SIGNATURE_GEOIP_TARGET_DIR) != 0) {
        nc_sig_error(errors, "mkdir_failed", JMX_SIGNATURE_GEOIP_TARGET_DIR);
        return -1;
    }
    if (snprintf(tmp_target, sizeof(tmp_target), "%s.tmp.%lld",
                 JMX_SIGNATURE_GEOIP_COUNTRY_TARGET, (long long)nc_now_s()) >=
        (int)sizeof(tmp_target)) {
        nc_sig_error(errors, "path_too_long", "geoip target path");
        return -1;
    }
    if (nc_copy_file(src_mmdb, tmp_target) != 0) {
        nc_sig_error(errors, "copy_geoip_failed", tmp_target);
        nc_unlink_if_exists(tmp_target);
        return -1;
    }
    if (rename(tmp_target, JMX_SIGNATURE_GEOIP_COUNTRY_TARGET) != 0) {
        nc_sig_error(errors, "rename_geoip_failed", strerror(errno));
        nc_unlink_if_exists(tmp_target);
        return -1;
    }
    json_object_object_add(d, "geoip_installed", json_object_new_boolean(1));
    json_object_object_add(d, "target_geoip", json_object_new_string(JMX_SIGNATURE_GEOIP_COUNTRY_TARGET));
    if (installed)
        *installed = 1;
    return 0;
}

struct json_object *jmx_signature_update_apply(struct json_object *cfg)
{
    const char *path = cfg ? nc_json_str_def(cfg, "path", "") : "";
    struct json_object *d = json_object_new_object();
    char tmpdir[PATH_MAX] = {0};
    char src_db[PATH_MAX];
    char src_icons[PATH_MAX];
    char src_fingerprint[PATH_MAX];
    char tmp_db[PATH_MAX];
    char backup_db[PATH_MAX];
    char tmp_fingerprint[PATH_MAX] = {0};
    char backup_fingerprint[PATH_MAX] = {0};
    struct json_object *errors = NULL;
    char fingerprint_sha[65] = {0};
    int had_db = 0;
    int had_fingerprint = 0;
    int have_db_backup = 0;
    int have_fingerprint_backup = 0;
    int db_replaced = 0;
    int fingerprint_replaced = 0;
    int fingerprint_imported = 0;
    int fingerprint_present = 0;
    int fingerprint_device_count = 0;
    int geoip_installed = 0;
    int rc = -1;

    nc_sig_status_set("applying", "", path);
    if (nc_signature_update_validate_path(path, d, tmpdir, sizeof(tmpdir)) != 0) {
        nc_sig_status_set("apply_validation_failed", "validation_failed", path);
        g_sig_update_status.build_date[0] = '\0';
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    nc_sig_update_build_date_from_conf(d);
    json_object_object_get_ex(d, "errors", &errors);
    if (snprintf(src_db, sizeof(src_db), "%s/dreamingwrt_signatures.db", tmpdir) >= (int)sizeof(src_db) ||
        snprintf(src_icons, sizeof(src_icons), "%s/logo", tmpdir) >= (int)sizeof(src_icons) ||
        snprintf(src_fingerprint, sizeof(src_fingerprint), "%s/fingerprint/fingerprint.db", tmpdir) >= (int)sizeof(src_fingerprint)) {
        nc_sig_error(errors, "path_too_long", "package source path");
        goto done;
    }
    fingerprint_present = nc_path_is_regular_readable(src_fingerprint);
    if (fingerprint_present) {
        struct json_object *v = NULL;
        if (json_object_object_get_ex(d, "fingerprint_device_count", &v) && v)
            fingerprint_device_count = json_object_get_int(v);
        if (nc_sha256_file(src_fingerprint, fingerprint_sha, sizeof(fingerprint_sha)) != 0) {
            nc_sig_error(errors, "fingerprint_sha256_failed", src_fingerprint);
            goto done;
        }
    }
    if (nc_mkdir_p("/etc/dreamingwrt") != 0) {
        nc_sig_error(errors, "mkdir_failed", "/etc/dreamingwrt");
        goto done;
    }
    if (fingerprint_present && nc_mkdir_p("/etc/dreamingwrt/fingerprint") != 0) {
        nc_sig_error(errors, "mkdir_failed", "/etc/dreamingwrt/fingerprint");
        goto done;
    }
    if (snprintf(tmp_db, sizeof(tmp_db), "%s.tmp.%lld",
                 JMX_SIGNATURE_DB_DEFAULT, (long long)nc_now_s()) >= (int)sizeof(tmp_db) ||
        snprintf(backup_db, sizeof(backup_db), "%s.bak.%lld",
                 JMX_SIGNATURE_DB_DEFAULT, (long long)nc_now_s()) >= (int)sizeof(backup_db) ||
        (fingerprint_present &&
         (snprintf(tmp_fingerprint, sizeof(tmp_fingerprint), "%s.tmp.%lld",
                   JMX_FINGERPRINT_DB_TARGET, (long long)nc_now_s()) >= (int)sizeof(tmp_fingerprint) ||
          snprintf(backup_fingerprint, sizeof(backup_fingerprint), "%s.bak.%lld",
                   JMX_FINGERPRINT_DB_TARGET, (long long)nc_now_s()) >= (int)sizeof(backup_fingerprint)))) {
        nc_sig_error(errors, "path_too_long", "runtime db path");
        goto done;
    }
    had_db = access(JMX_SIGNATURE_DB_DEFAULT, F_OK) == 0;
    if (had_db) {
        if (!nc_path_is_regular_readable(JMX_SIGNATURE_DB_DEFAULT) ||
            nc_copy_file(JMX_SIGNATURE_DB_DEFAULT, backup_db) != 0) {
            nc_sig_error(errors, "backup_db_failed", JMX_SIGNATURE_DB_DEFAULT);
            goto done;
        }
        have_db_backup = 1;
    }
    had_fingerprint = access(JMX_FINGERPRINT_DB_TARGET, F_OK) == 0;
    if (fingerprint_present && had_fingerprint) {
        if (!nc_path_is_regular_readable(JMX_FINGERPRINT_DB_TARGET) ||
            nc_copy_file(JMX_FINGERPRINT_DB_TARGET, backup_fingerprint) != 0) {
            nc_sig_error(errors, "backup_fingerprint_failed", JMX_FINGERPRINT_DB_TARGET);
            goto done;
        }
        have_fingerprint_backup = 1;
    }
    if (nc_copy_file(src_db, tmp_db) != 0) {
        nc_sig_error(errors, "copy_db_failed", tmp_db);
        goto done;
    }
    if (fingerprint_present && nc_copy_file(src_fingerprint, tmp_fingerprint) != 0) {
        nc_sig_error(errors, "copy_fingerprint_failed", tmp_fingerprint);
        goto rollback;
    }
    if (rename(tmp_db, JMX_SIGNATURE_DB_DEFAULT) != 0) {
        nc_sig_error(errors, "rename_db_failed", strerror(errno));
        goto rollback;
    }
    db_replaced = 1;
    if (jmx_runtime_reload_signature_db(JMX_SIGNATURE_DB_DEFAULT) != 0) {
        nc_sig_error(errors, "runtime_reload_failed", JMX_SIGNATURE_DB_DEFAULT);
        goto rollback;
    }
    if (fingerprint_present) {
        if (rename(tmp_fingerprint, JMX_FINGERPRINT_DB_TARGET) != 0) {
            nc_sig_error(errors, "rename_fingerprint_failed", strerror(errno));
            goto rollback;
        }
        fingerprint_replaced = 1;
        if (db_try_import_fingerprint_catalog() < 0) {
            nc_sig_error(errors, "fingerprint_import_failed", JMX_FINGERPRINT_DB_TARGET);
            goto rollback;
        }
        fingerprint_imported = 1;
    }
    if (nc_signature_install_icons(src_icons) != 0) {
        nc_sig_error(errors, "icon_install_failed", JMX_SIGNATURE_ICON_TARGET_DIR);
        goto rollback;
    }
    if (nc_signature_install_geoip_dataset(tmpdir, d, errors, &geoip_installed) != 0)
        goto rollback;
    json_object_object_add(d, "applied", json_object_new_boolean(1));
    json_object_object_add(d, "runtime_reloaded", json_object_new_boolean(1));
    json_object_object_add(d, "target_db", json_object_new_string(JMX_SIGNATURE_DB_DEFAULT));
    json_object_object_add(d, "target_icons", json_object_new_string(JMX_SIGNATURE_ICON_TARGET_DIR));
    json_object_object_add(d, "fingerprint_installed", json_object_new_boolean(fingerprint_present));
    if (fingerprint_present) {
        json_object_object_add(d, "fingerprint_target",
                               json_object_new_string(JMX_FINGERPRINT_DB_TARGET));
        json_object_object_add(d, "fingerprint_device_count",
                               json_object_new_int(fingerprint_device_count));
        json_object_object_add(d, "fingerprint_sha256",
                               json_object_new_string(fingerprint_sha));
    }
    if (!geoip_installed)
        json_object_object_add(d, "geoip_installed", json_object_new_boolean(0));
    nc_sig_update_build_date_from_conf(d);
    rc = 0;
    goto done;

rollback:
    nc_unlink_if_exists(tmp_db);
    if (tmp_fingerprint[0])
        nc_unlink_if_exists(tmp_fingerprint);
    if (db_replaced) {
        if (had_db) {
            if (!have_db_backup || nc_copy_file(backup_db, JMX_SIGNATURE_DB_DEFAULT) != 0)
                nc_sig_error(errors, "rollback_db_file_failed", JMX_SIGNATURE_DB_DEFAULT);
        } else if (nc_unlink_if_exists(JMX_SIGNATURE_DB_DEFAULT) != 0) {
            nc_sig_error(errors, "rollback_db_remove_failed", JMX_SIGNATURE_DB_DEFAULT);
        }
    }
    if (fingerprint_replaced) {
        if (had_fingerprint) {
            if (!have_fingerprint_backup ||
                nc_copy_file(backup_fingerprint, JMX_FINGERPRINT_DB_TARGET) != 0)
                nc_sig_error(errors, "rollback_fingerprint_file_failed",
                             JMX_FINGERPRINT_DB_TARGET);
        } else if (nc_unlink_if_exists(JMX_FINGERPRINT_DB_TARGET) != 0) {
            nc_sig_error(errors, "rollback_fingerprint_remove_failed",
                         JMX_FINGERPRINT_DB_TARGET);
        }
    }
    if (db_replaced && jmx_runtime_reload_signature_db(NULL) != 0)
        nc_sig_error(errors, "rollback_runtime_reload_failed", JMX_SIGNATURE_DB_DEFAULT);
    if (fingerprint_imported && db_try_import_fingerprint_catalog() < 0)
        nc_sig_error(errors, "rollback_fingerprint_import_failed",
                     JMX_FINGERPRINT_DB_TARGET);
done:
    nc_unlink_if_exists(tmp_db);
    if (tmp_fingerprint[0])
        nc_unlink_if_exists(tmp_fingerprint);
    if (have_db_backup)
        nc_unlink_if_exists(backup_db);
    if (have_fingerprint_backup)
        nc_unlink_if_exists(backup_fingerprint);
    nc_sig_remove_tmpdir(tmpdir);
    if (rc == 0) {
        nc_sig_status_set("applied", "", path);
        g_sig_update_status.validated = 1;
        g_sig_update_status.applied = 1;
        return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
    }
    nc_sig_status_set("apply_failed", "apply_failed", path);
    g_sig_update_status.applied = 0;
    json_object_object_del(d, "ok");
    json_object_object_add(d, "ok", json_object_new_boolean(0));
    json_object_object_add(d, "applied", json_object_new_boolean(0));
    return jmx_gen_api_response_data(API_CODE_ERROR, d);
}

struct json_object *jmx_signature_update_status(struct json_object *cfg)
{
    struct json_object *d = json_object_new_object();
    char runtime_db[512] = {0};
    (void)cfg;
    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "phase", json_object_new_string(g_sig_update_status.phase));
    json_object_object_add(d, "error", json_object_new_string(g_sig_update_status.error));
    json_object_object_add(d, "path", json_object_new_string(g_sig_update_status.package_path));
    json_object_object_add(d, "build_date", json_object_new_string(g_sig_update_status.build_date));
    json_object_object_add(d, "validated", json_object_new_boolean(g_sig_update_status.validated));
    json_object_object_add(d, "applied", json_object_new_boolean(g_sig_update_status.applied));
    json_object_object_add(d, "ts", json_object_new_int64(g_sig_update_status.ts));
    (void)nc_signature_db_path(runtime_db, sizeof(runtime_db));
    json_object_object_add(d, "runtime_db", json_object_new_string(runtime_db));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

static int nc_signature_db_status_valid(sqlite3 *db)
{
    static const char *required_tables[] = {"app", "dpi_rule", "meta"};
    sqlite3_stmt *st = NULL;
    size_t i;
    int valid = 0;

    if (!db || sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &st, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(st) != SQLITE_ROW ||
        strcmp((const char *)sqlite3_column_text(st, 0), "ok"))
        goto out;
    sqlite3_finalize(st);
    st = NULL;

    for (i = 0; i < sizeof(required_tables) / sizeof(required_tables[0]); i++) {
        if (sqlite3_prepare_v2(db,
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                -1, &st, NULL) != SQLITE_OK)
            goto out;
        sqlite3_bind_text(st, 1, required_tables[i], -1, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_ROW)
            goto out;
        sqlite3_finalize(st);
        st = NULL;
    }
    valid = 1;
out:
    sqlite3_finalize(st);
    return valid;
}

struct json_object *jmx_signature_db_status(struct json_object *cfg)
{
    char path[512] = {0};
    (void)cfg; sqlite3 *db = NULL; struct stat st;
    int ok = 0, exists = 0;
    struct json_object *d = json_object_new_object(), *counts = json_object_new_object(), *meta = json_object_new_object();
    if (nc_signature_db_path(path, sizeof(path)) == 0)
        exists = access(path, R_OK) == 0;
    else
        snprintf(path, sizeof(path), "%s", JMX_SIGNATURE_DB_DEFAULT);
    json_object_object_add(d, "path", json_object_new_string(path));
    json_object_object_add(d, "exists", json_object_new_boolean(exists));
    json_object_object_add(d, "source", json_object_new_string("dreamingwrt_signatures.db"));
    json_object_object_add(d, "legacy_app_dat", json_object_new_string("disabled"));
    json_object_object_add(d, "legacy_ikuai_audit", json_object_new_string("disabled"));
    if (stat(path, &st) == 0) { json_object_object_add(d, "size_bytes", json_object_new_int64(st.st_size)); json_object_object_add(d, "mtime", json_object_new_int64(st.st_mtime)); }
    if (exists && nc_sig_open(&db) == 0 && nc_signature_db_status_valid(db)) {
        ok = 1;
        json_object_object_add(d, "ok", json_object_new_boolean(1));
        json_object_object_add(d, "state", json_object_new_string("ready"));
        nc_sig_counts_json(db, counts);
        nc_sig_meta(db, meta); sqlite3_close(db);
    } else {
        if (db)
            sqlite3_close(db);
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "state", json_object_new_string(exists ? "invalid" : "unavailable"));
        json_object_object_add(d, "error", json_object_new_string(
            exists ? "invalid_signature_database" : "signature_database_unavailable"));
    }
    json_object_object_add(d, "counts", counts); json_object_object_add(d, "meta", meta);
    return jmx_gen_api_response_data(ok || !exists ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

struct json_object *jmx_signature_db_apps(struct json_object *cfg)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL; int limit = 200, offset = 0; const char *q = "";
    struct json_object *d = json_object_new_object(), *arr = json_object_new_array();
    int ok = 0, step_rc = SQLITE_DONE;
    if (cfg) {
        limit = nc_json_int_def(cfg, "limit", 200);
        offset = nc_json_int_def(cfg, "offset", 0);
        q = nc_json_str_def(cfg, "q",
            nc_json_str_def(cfg, "search",
            nc_json_str_def(cfg, "search_text", "")));
    }
    if (limit <= 0 || limit > 1000) limit = 200; if (offset < 0) offset = 0;
    { char path[512] = {0}; (void)nc_signature_db_path(path, sizeof(path)); json_object_object_add(d, "path", json_object_new_string(path)); }
    if (nc_sig_open(&db) != 0) { json_object_object_add(d, "ok", json_object_new_boolean(0)); json_object_object_add(d, "apps", arr); return jmx_gen_api_response_data(API_CODE_ERROR, d); }
    const char *sql = "SELECT a.app_id,a.name,COALESCE(c.slug,''),COALESCE(c.name,''),COALESCE(a.family,''),"
                      "COALESCE(ai.icon_key,''),COALESCE(ia.icon_file,''),"
                      "(SELECT COUNT(*) FROM dpi_rule r WHERE r.app_id=a.app_id AND r.enabled=1) AS rules "
                      "FROM app a LEFT JOIN app_category c ON c.category_id=a.category_id "
                      "LEFT JOIN app_icon ai ON ai.app_id=a.app_id "
                      "LEFT JOIN icon_asset ia ON ia.icon_key=ai.icon_key "
                      "WHERE a.enabled=1 AND (?1='' OR a.name LIKE '%'||?1||'%' OR a.normalized_name LIKE '%'||?1||'%') "
                      "ORDER BY a.app_id LIMIT ?2 OFFSET ?3";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, q, -1, SQLITE_TRANSIENT); sqlite3_bind_int(st, 2, limit); sqlite3_bind_int(st, 3, offset);
        while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) { struct json_object *o = json_object_new_object();
            json_object_object_add(o, "app_id", json_object_new_int(sqlite3_column_int(st,0)));
            nc_add_text(o, "name", st, 1);
            nc_add_text(o, "app_name", st, 1);
            nc_sig_add_app_meta_fields(o, sqlite3_column_int(st,0),
                                       (const char *)sqlite3_column_text(st,1),
                                       (const char *)sqlite3_column_text(st,2),
                                       (const char *)sqlite3_column_text(st,3),
                                       (const char *)sqlite3_column_text(st,4),
                                       (const char *)sqlite3_column_text(st,5),
                                       (const char *)sqlite3_column_text(st,6));
            json_object_object_add(o, "rules", json_object_new_int(sqlite3_column_int(st,7)));
            json_object_array_add(arr, o); }
        ok = (step_rc == SQLITE_DONE);
    }
    if (!ok) json_object_object_add(d, "error", json_object_new_string("signature_query_failed"));
    if (st) sqlite3_finalize(st); sqlite3_close(db);
    json_object_object_add(d, "ok", json_object_new_boolean(ok)); json_object_object_add(d, "limit", json_object_new_int(limit)); json_object_object_add(d, "offset", json_object_new_int(offset)); json_object_object_add(d, "apps", arr);
    return jmx_gen_api_response_data(ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

struct json_object *jmx_signature_db_rules(struct json_object *cfg)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL; int limit = 200, offset = 0, app_id = 0;
    struct json_object *d = json_object_new_object(), *arr = json_object_new_array();
    int ok = 0, step_rc = SQLITE_DONE;
    if (cfg) { limit = nc_json_int_def(cfg, "limit", 200); offset = nc_json_int_def(cfg, "offset", 0); app_id = nc_json_int_def(cfg, "app_id", 0); }
    if (limit <= 0 || limit > 1000) limit = 200; if (offset < 0) offset = 0;
    if (nc_sig_open(&db) != 0) { json_object_object_add(d, "ok", json_object_new_boolean(0)); json_object_object_add(d, "rules", arr); return jmx_gen_api_response_data(API_CODE_ERROR, d); }
    const char *sql = "SELECT r.rule_id,r.app_id,COALESCE(a.name,''),COALESCE(r.proto,''),COALESCE(r.direction,''),COALESCE(r.match_type,''),COALESCE(r.pattern_format,''),COALESCE(r.pattern_text,''),COALESCE(r.pattern_hex,''),r.offset,r.priority,r.pkt_seq,"
                      "COALESCE(c.slug,''),COALESCE(c.name,''),COALESCE(a.family,''),COALESCE(ai.icon_key,''),COALESCE(ia.icon_file,'') "
                      "FROM dpi_rule r LEFT JOIN app a ON a.app_id=r.app_id "
                      "LEFT JOIN app_category c ON c.category_id=a.category_id "
                      "LEFT JOIN app_icon ai ON ai.app_id=a.app_id "
                      "LEFT JOIN icon_asset ia ON ia.icon_key=ai.icon_key "
                      "WHERE r.enabled=1 AND (?1=0 OR r.app_id=?1) ORDER BY r.priority,r.rule_id LIMIT ?2 OFFSET ?3";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, app_id); sqlite3_bind_int(st, 2, limit); sqlite3_bind_int(st, 3, offset);
        while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) { struct json_object *o = json_object_new_object();
            json_object_object_add(o, "rule_id", json_object_new_int(sqlite3_column_int(st,0)));
            json_object_object_add(o, "app_id", json_object_new_int(sqlite3_column_int(st,1)));
            nc_add_text(o, "app_name", st, 2);
            nc_add_text(o, "proto", st, 3);
            nc_add_text(o, "direction", st, 4);
            nc_add_text(o, "match_type", st, 5);
            nc_add_text(o, "pattern_format", st, 6);
            nc_add_text(o, "pattern_text", st, 7);
            nc_add_text(o, "pattern_hex", st, 8);
            json_object_object_add(o, "offset", json_object_new_int(sqlite3_column_int(st,9)));
            json_object_object_add(o, "priority", json_object_new_int(sqlite3_column_int(st,10)));
            json_object_object_add(o, "pkt_seq", json_object_new_int(sqlite3_column_int(st,11)));
            nc_sig_add_app_meta_fields(o, sqlite3_column_int(st,1),
                                       (const char *)sqlite3_column_text(st,2),
                                       (const char *)sqlite3_column_text(st,12),
                                       (const char *)sqlite3_column_text(st,13),
                                       (const char *)sqlite3_column_text(st,14),
                                       (const char *)sqlite3_column_text(st,15),
                                       (const char *)sqlite3_column_text(st,16));
            json_object_array_add(arr, o); }
        ok = (step_rc == SQLITE_DONE);
    }
    if (!ok) json_object_object_add(d, "error", json_object_new_string("signature_query_failed"));
    if (st) sqlite3_finalize(st); sqlite3_close(db);
    json_object_object_add(d, "ok", json_object_new_boolean(ok)); json_object_object_add(d, "app_id", json_object_new_int(app_id)); json_object_object_add(d, "limit", json_object_new_int(limit)); json_object_object_add(d, "offset", json_object_new_int(offset)); json_object_object_add(d, "rules", arr);
    return jmx_gen_api_response_data(ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

struct json_object *jmx_signature_db_carriers(struct json_object *cfg)
{
    (void)cfg; sqlite3 *db = NULL; sqlite3_stmt *st = NULL;
    struct json_object *d = json_object_new_object(), *arr = json_object_new_array();
    int ok = 0, step_rc = SQLITE_DONE;
    if (nc_sig_open(&db) != 0) { json_object_object_add(d, "ok", json_object_new_boolean(0)); json_object_object_add(d, "carriers", arr); return jmx_gen_api_response_data(API_CODE_ERROR, d); }
    const char *sql = "SELECT COALESCE(carrier,''),carrier_id,COALESCE(MAX(carrier_name),''),COUNT(*),MIN(updated_at),MAX(updated_at) FROM carrier_prefix WHERE enabled=1 GROUP BY carrier,carrier_id ORDER BY carrier_id";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) { struct json_object *o = json_object_new_object();
            nc_add_text(o, "carrier", st, 0);
            json_object_object_add(o, "carrier_id", json_object_new_int(sqlite3_column_int(st,1)));
            nc_add_text(o, "name", st, 2);
            json_object_object_add(o, "prefixes", json_object_new_int(sqlite3_column_int(st,3)));
            json_object_object_add(o, "first_updated_at", json_object_new_int64(sqlite3_column_int64(st,4)));
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st,5)));
            json_object_array_add(arr, o); }
        ok = (step_rc == SQLITE_DONE);
    }
    if (!ok) json_object_object_add(d, "error", json_object_new_string("signature_query_failed"));
    if (st) sqlite3_finalize(st); sqlite3_close(db);
    { char path[512] = {0}; (void)nc_signature_db_path(path, sizeof(path)); json_object_object_add(d, "ok", json_object_new_boolean(ok)); json_object_object_add(d, "path", json_object_new_string(path)); } json_object_object_add(d, "carriers", arr);
    return jmx_gen_api_response_data(ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}

struct json_object *jmx_signature_db_carrier_prefixes(struct json_object *cfg)
{
    sqlite3 *db = NULL; sqlite3_stmt *st = NULL; int limit = 500, offset = 0; const char *carrier = "";
    struct json_object *d = json_object_new_object(), *arr = json_object_new_array();
    int ok = 0, step_rc = SQLITE_DONE;
    if (cfg) { limit = nc_json_int_def(cfg, "limit", 500); offset = nc_json_int_def(cfg, "offset", 0); carrier = nc_json_str_def(cfg, "carrier", ""); }
    if (limit <= 0 || limit > 5000) limit = 500; if (offset < 0) offset = 0;
    if (nc_sig_open(&db) != 0) { json_object_object_add(d, "ok", json_object_new_boolean(0)); json_object_object_add(d, "prefixes", arr); return jmx_gen_api_response_data(API_CODE_ERROR, d); }
    const char *sql = "SELECT COALESCE(carrier,''),carrier_id,COALESCE(carrier_name,''),COALESCE(cidr,''),COALESCE(source,''),COALESCE(sort_key,'') FROM carrier_prefix WHERE enabled=1 AND (?1='' OR carrier=?1) ORDER BY sort_key LIMIT ?2 OFFSET ?3";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, carrier, -1, SQLITE_TRANSIENT); sqlite3_bind_int(st, 2, limit); sqlite3_bind_int(st, 3, offset);
        while ((step_rc = sqlite3_step(st)) == SQLITE_ROW) { struct json_object *o = json_object_new_object();
            nc_add_text(o, "carrier", st, 0);
            json_object_object_add(o, "carrier_id", json_object_new_int(sqlite3_column_int(st,1)));
            nc_add_text(o, "name", st, 2);
            nc_add_text(o, "cidr", st, 3);
            nc_add_text(o, "source", st, 4);
            nc_add_text(o, "sort_key", st, 5);
            json_object_array_add(arr, o); }
        ok = (step_rc == SQLITE_DONE);
    }
    if (!ok) json_object_object_add(d, "error", json_object_new_string("signature_query_failed"));
    if (st) sqlite3_finalize(st); sqlite3_close(db);
    json_object_object_add(d, "ok", json_object_new_boolean(ok)); json_object_object_add(d, "carrier", json_object_new_string(carrier)); json_object_object_add(d, "limit", json_object_new_int(limit)); json_object_object_add(d, "offset", json_object_new_int(offset)); json_object_object_add(d, "prefixes", arr);
    return jmx_gen_api_response_data(ok ? API_CODE_SUCCESS : API_CODE_ERROR, d);
}
struct json_object *jmx_signature_db_domain_groups(struct json_object *cfg)
{
    (void)cfg; sqlite3 *db=NULL; sqlite3_stmt *st=NULL;
    struct json_object *d=json_object_new_object(), *arr=json_object_new_array();
    int ok = 0, step_rc = SQLITE_DONE;
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"groups",arr);return jmx_gen_api_response_data(API_CODE_ERROR,d);} 
    const char *sql="SELECT g.group_id,COALESCE(g.category,''),COALESCE(g.subcategory,''),COUNT(e.domain),COALESCE(g.source,''),COALESCE(g.sort_key,'') FROM domain_group g LEFT JOIN domain_entry e ON e.group_id=g.group_id GROUP BY g.group_id,g.category,g.subcategory,g.source,g.sort_key ORDER BY g.sort_key,g.group_id";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){while((step_rc=sqlite3_step(st))==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"group_id",json_object_new_int(sqlite3_column_int(st,0)));nc_add_text(o,"category",st,1);nc_add_text(o,"subcategory",st,2);json_object_object_add(o,"domains",json_object_new_int(sqlite3_column_int(st,3)));nc_add_text(o,"source",st,4);nc_add_text(o,"sort_key",st,5);json_object_array_add(arr,o);} ok=(step_rc==SQLITE_DONE);}
    if(!ok)json_object_object_add(d,"error",json_object_new_string("signature_query_failed"));
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(ok));json_object_object_add(d,"groups",arr);return jmx_gen_api_response_data(ok?API_CODE_SUCCESS:API_CODE_ERROR,d);
}

struct json_object *jmx_signature_db_domains(struct json_object *cfg)
{
    sqlite3 *db=NULL; sqlite3_stmt *st=NULL; int limit=500,offset=0,group_id=0; const char*q="";
    struct json_object*d=json_object_new_object(),*arr=json_object_new_array();
    int ok = 0, step_rc = SQLITE_DONE;
    if(cfg){limit=nc_json_int_def(cfg,"limit",500);offset=nc_json_int_def(cfg,"offset",0);group_id=nc_json_int_def(cfg,"group_id",0);q=nc_json_str_def(cfg,"q","");}
    if(limit<=0||limit>5000)limit=500;if(offset<0)offset=0;
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"domains",arr);return jmx_gen_api_response_data(API_CODE_ERROR,d);} 
    const char*sql="SELECT COALESCE(e.domain,''),COALESCE(e.remark,''),COALESCE(e.source,''),e.group_id,COALESCE(g.category,''),COALESCE(g.subcategory,''),COALESCE(e.sort_key,'') FROM domain_entry e JOIN domain_group g ON g.group_id=e.group_id WHERE (?1=0 OR e.group_id=?1) AND (?2='' OR e.domain LIKE '%'||?2||'%' OR e.remark LIKE '%'||?2||'%') ORDER BY e.sort_key,e.domain LIMIT ?3 OFFSET ?4";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){sqlite3_bind_int(st,1,group_id);sqlite3_bind_text(st,2,q,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,limit);sqlite3_bind_int(st,4,offset);while((step_rc=sqlite3_step(st))==SQLITE_ROW){struct json_object*o=json_object_new_object();const char*domain=(const char*)sqlite3_column_text(st,0);nc_add_text(o,"domain",st,0);nc_add_text(o,"remark",st,1);nc_add_text(o,"source",st,2);json_object_object_add(o,"group_id",json_object_new_int(sqlite3_column_int(st,3)));nc_add_text(o,"category",st,4);nc_add_text(o,"subcategory",st,5);nc_add_text(o,"sort_key",st,6);nc_sig_resolve_host_with_db(db,domain,"",0,o);json_object_array_add(arr,o);} ok=(step_rc==SQLITE_DONE);}
    if(!ok)json_object_object_add(d,"error",json_object_new_string("signature_query_failed"));
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(ok));json_object_object_add(d,"group_id",json_object_new_int(group_id));json_object_object_add(d,"q",json_object_new_string(q));json_object_object_add(d,"limit",json_object_new_int(limit));json_object_object_add(d,"offset",json_object_new_int(offset));json_object_object_add(d,"domains",arr);return jmx_gen_api_response_data(ok?API_CODE_SUCCESS:API_CODE_ERROR,d);
}

struct json_object *jmx_signature_db_resolve_app(struct json_object *cfg)
{
    sqlite3 *db = NULL;
    struct json_object *d = json_object_new_object();
    const char *host = cfg ? nc_json_str_def(cfg, "host", "") : "";
    const char *dst_ip = cfg ? nc_json_str_def(cfg, "dst_ip", "") : "";
    const char *proto = cfg ? nc_json_str_def(cfg, "proto", "") : "";
    int dst_port = cfg ? nc_json_int_def(cfg, "dst_port", 0) : 0;
    int ok = 0;

    json_object_object_add(d, "host", json_object_new_string(host ? host : ""));
    json_object_object_add(d, "dst_ip", json_object_new_string(dst_ip ? dst_ip : ""));
    json_object_object_add(d, "proto", json_object_new_string(proto ? proto : ""));
    json_object_object_add(d, "dst_port", json_object_new_int(dst_port));
    if ((!host || !host[0]) && (!dst_ip || !dst_ip[0])) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("host_or_dst_ip_required"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    if (nc_sig_open(&db) != 0) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "error", json_object_new_string("cannot_open_signature_db"));
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }
    if (host && host[0])
        ok = (nc_sig_resolve_host_with_db(db, host, proto, dst_port, d) == 0);
    sqlite3_close(db);
    if (!ok) {
        json_object_object_add(d, "ok", json_object_new_boolean(0));
        json_object_object_add(d, "matched", json_object_new_boolean(0));
        json_object_object_add(d, "entity_type", json_object_new_string("unknown"));
        json_object_object_add(d, "confidence", json_object_new_double(0.0));
        return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
    }
    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "matched", json_object_new_boolean(1));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_signature_db_device_vendors(struct json_object *cfg)
{
    sqlite3 *db=NULL;sqlite3_stmt*st=NULL;int limit=500,offset=0;const char*q="";struct json_object*d=json_object_new_object(),*arr=json_object_new_array();
    int ok = 0, step_rc = SQLITE_DONE;
    if(cfg){limit=nc_json_int_def(cfg,"limit",500);offset=nc_json_int_def(cfg,"offset",0);q=nc_json_str_def(cfg,"q","");} if(limit<=0||limit>5000)limit=500;if(offset<0)offset=0;
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"vendors",arr);return jmx_gen_api_response_data(API_CODE_ERROR,d);} 
    const char*sql=
        "SELECT v.vendor_id,COALESCE(v.name,''),COALESCE(v.normalized_name,''),"
        "COALESCE(v.legacy_id,''),COALESCE(v.source,''),"
        "(SELECT COUNT(*) FROM device_fingerprint_rule r "
        " WHERE r.vendor_id=v.vendor_id AND r.enabled=1),"
        "COALESCE(v.logo_key,''),COALESCE(ia.icon_file,''),"
        "(SELECT COUNT(*) FROM device_vendor_alias a WHERE a.vendor_id=v.vendor_id) "
        "FROM device_vendor v LEFT JOIN icon_asset ia ON ia.icon_key=v.logo_key "
        "WHERE (?1='' OR v.name LIKE '%'||?1||'%' "
        "OR v.normalized_name LIKE '%'||?1||'%' "
        "OR EXISTS(SELECT 1 FROM device_vendor_alias a WHERE a.vendor_id=v.vendor_id "
        "AND (a.alias LIKE '%'||?1||'%' OR a.normalized_alias LIKE '%'||?1||'%'))) "
        "ORDER BY v.vendor_id LIMIT ?2 OFFSET ?3";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){sqlite3_bind_text(st,1,q,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,limit);sqlite3_bind_int(st,3,offset);while((step_rc=sqlite3_step(st))==SQLITE_ROW){struct json_object*o=json_object_new_object();char logo_file[256],logo_url[320];const char*raw=(const char*)sqlite3_column_text(st,7);json_object_object_add(o,"vendor_id",json_object_new_int(sqlite3_column_int(st,0)));nc_add_text(o,"name",st,1);nc_add_text(o,"normalized_name",st,2);nc_add_text(o,"legacy_id",st,3);nc_add_text(o,"source",st,4);json_object_object_add(o,"rules",json_object_new_int(sqlite3_column_int(st,5)));nc_add_text(o,"logo_key",st,6);nc_sig_icon_file_public(raw,logo_file,sizeof(logo_file));nc_sig_icon_url(raw,logo_url,sizeof(logo_url));json_object_object_add(o,"logo_file",json_object_new_string(logo_file));json_object_object_add(o,"logo_url",json_object_new_string(logo_url));json_object_object_add(o,"alias_count",json_object_new_int(sqlite3_column_int(st,8)));json_object_array_add(arr,o);} ok=(step_rc==SQLITE_DONE);}
    if(!ok)json_object_object_add(d,"error",json_object_new_string("signature_query_failed"));
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(ok));json_object_object_add(d,"vendors",arr);return jmx_gen_api_response_data(ok?API_CODE_SUCCESS:API_CODE_ERROR,d);
}

struct json_object *jmx_signature_db_device_types(struct json_object *cfg)
{
    sqlite3 *db=NULL;sqlite3_stmt*st=NULL;struct json_object*d=json_object_new_object(),*arr=json_object_new_array();(void)cfg;
    int ok = 0, step_rc = SQLITE_DONE;
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"types",arr);return jmx_gen_api_response_data(API_CODE_ERROR,d);} 
    const char*sql="SELECT type_id,COALESCE(slug,''),COALESCE(name,''),COALESCE(legacy_id,''),COALESCE(source,''),(SELECT COUNT(*) FROM device_fingerprint_rule r WHERE r.type_id=t.type_id AND r.enabled=1) FROM device_type t ORDER BY type_id";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){while((step_rc=sqlite3_step(st))==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"type_id",json_object_new_int(sqlite3_column_int(st,0)));nc_add_text(o,"slug",st,1);nc_add_text(o,"name",st,2);nc_add_text(o,"legacy_id",st,3);nc_add_text(o,"source",st,4);json_object_object_add(o,"rules",json_object_new_int(sqlite3_column_int(st,5)));json_object_array_add(arr,o);} ok=(step_rc==SQLITE_DONE);}
    if(!ok)json_object_object_add(d,"error",json_object_new_string("signature_query_failed"));
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(ok));json_object_object_add(d,"types",arr);return jmx_gen_api_response_data(ok?API_CODE_SUCCESS:API_CODE_ERROR,d);
}

struct json_object *jmx_signature_db_fingerprint_rules(struct json_object *cfg)
{
    sqlite3 *db=NULL;sqlite3_stmt*st=NULL;int limit=500,offset=0;const char*match_type="",*q="";struct json_object*d=json_object_new_object(),*arr=json_object_new_array();
    int ok = 0, step_rc = SQLITE_DONE;
    if(cfg){limit=nc_json_int_def(cfg,"limit",500);offset=nc_json_int_def(cfg,"offset",0);match_type=nc_json_str_def(cfg,"match_type","");q=nc_json_str_def(cfg,"q","");} if(limit<=0||limit>5000)limit=500;if(offset<0)offset=0;
    if(nc_sig_open(&db)!=0){json_object_object_add(d,"ok",json_object_new_boolean(0));json_object_object_add(d,"rules",arr);return jmx_gen_api_response_data(API_CODE_ERROR,d);} 
    const char*sql="SELECT rule_id,COALESCE(source,''),COALESCE(match_type,''),COALESCE(pattern,''),COALESCE(pattern2,''),vendor_id,type_id,COALESCE(vendor_name,''),COALESCE(type_name,''),COALESCE(os_name,''),COALESCE(model,''),confidence,COALESCE(legacy_id,''),COALESCE(sort_key,'') FROM device_fingerprint_rule WHERE enabled=1 AND (?1='' OR match_type=?1) AND (?2='' OR pattern LIKE '%'||?2||'%' OR model LIKE '%'||?2||'%' OR vendor_name LIKE '%'||?2||'%') ORDER BY sort_key,rule_id LIMIT ?3 OFFSET ?4";
    if(sqlite3_prepare_v2(db,sql,-1,&st,NULL)==SQLITE_OK){sqlite3_bind_text(st,1,match_type,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,q,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,limit);sqlite3_bind_int(st,4,offset);while((step_rc=sqlite3_step(st))==SQLITE_ROW){struct json_object*o=json_object_new_object();json_object_object_add(o,"rule_id",json_object_new_int(sqlite3_column_int(st,0)));nc_add_text(o,"source",st,1);nc_add_text(o,"match_type",st,2);nc_add_text(o,"pattern",st,3);nc_add_text(o,"pattern2",st,4);json_object_object_add(o,"vendor_id",json_object_new_int(sqlite3_column_int(st,5)));json_object_object_add(o,"type_id",json_object_new_int(sqlite3_column_int(st,6)));nc_add_text(o,"vendor",st,7);nc_add_text(o,"type",st,8);nc_add_text(o,"os_name",st,9);nc_add_text(o,"model",st,10);json_object_object_add(o,"confidence",json_object_new_double(sqlite3_column_double(st,11)));nc_add_text(o,"legacy_id",st,12);nc_add_text(o,"sort_key",st,13);json_object_array_add(arr,o);} ok=(step_rc==SQLITE_DONE);}
    if(!ok)json_object_object_add(d,"error",json_object_new_string("signature_query_failed"));
    if(st)sqlite3_finalize(st);sqlite3_close(db);json_object_object_add(d,"ok",json_object_new_boolean(ok));json_object_object_add(d,"match_type",json_object_new_string(match_type));json_object_object_add(d,"q",json_object_new_string(q));json_object_object_add(d,"limit",json_object_new_int(limit));json_object_object_add(d,"offset",json_object_new_int(offset));json_object_object_add(d,"rules",arr);return jmx_gen_api_response_data(ok?API_CODE_SUCCESS:API_CODE_ERROR,d);
}
