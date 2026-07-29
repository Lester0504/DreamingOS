// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_internal.h"

struct aegisxd_download_ctx {
    FILE *fp;
    uint64_t written;
    uint64_t max_bytes;
    char etag[AEGISXD_MAX_TEXT];
    char last_modified[AEGISXD_MAX_TEXT];
    char content_type[AEGISXD_MAX_TEXT];
    char error[AEGISXD_MAX_TEXT];
};

static const struct aegisxd_feed_manifest g_builtin_feeds[] = {
    {
        .feed_id = "emerging-threats-open-suricata",
        .name = "Emerging Threats Open Suricata",
        .kind = "suricata_rules",
        .url = "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz",
        .format = "suricata_tar_gz",
        .category_hint = "ids_ips",
        .max_bytes = AEGISXD_MAX_FEED_BYTES,
        .connect_timeout_sec = 30,
        .timeout_sec = 900,
    },
    {
        .feed_id = "urlhaus-hostfile",
        .name = "URLHaus Hostfile",
        .kind = "reputation_items",
        .url = "https://urlhaus.abuse.ch/downloads/hostfile/",
        .format = "hosts",
        .category_hint = "malware_c2",
        .max_bytes = 8U * 1024U * 1024U,
    },
    {
        .feed_id = "oisd-big",
        .name = "OISD Big",
        .kind = "domain_categories",
        .url = "https://big.oisd.nl",
        .format = "domain_list",
        .category_hint = "ads_trackers_mixed",
        .max_bytes = 32U * 1024U * 1024U,
    },
    {
        .feed_id = "stevenblack-hosts",
        .name = "StevenBlack Hosts",
        .kind = "domain_categories",
        .url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        .format = "hosts",
        .category_hint = "ads_trackers_malware",
        .max_bytes = 16U * 1024U * 1024U,
    },
    {
        .feed_id = "stevenblack-fakenews-gambling-porn",
        .name = "StevenBlack Fakenews Gambling Porn",
        .kind = "domain_categories",
        .url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts",
        .format = "hosts",
        .category_hint = "fakenews_gambling_adult",
        .max_bytes = 32U * 1024U * 1024U,
    },
};

static const struct aegisxd_feed_manifest *aegisxd_find_builtin_feed(const char *feed_id)
{
    size_t i;

    if (!feed_id || !feed_id[0])
        return NULL;
    for (i = 0; i < ARRAY_SIZE(g_builtin_feeds); i++) {
        if (!strcmp(g_builtin_feeds[i].feed_id, feed_id))
            return &g_builtin_feeds[i];
    }
    return NULL;
}

static const char *aegisxd_job_result_error(struct json_object *result)
{
    struct json_object *err = NULL;

    if (!result || !json_object_object_get_ex(result, "error", &err) || !err)
        return "";
    return json_object_get_string(err) ? json_object_get_string(err) : "";
}

int aegisxd_job_result_ok(struct json_object *result)
{
    struct json_object *ok = NULL;

    return result && json_object_object_get_ex(result, "ok", &ok) &&
           json_object_get_boolean(ok);
}

int aegisxd_job_running_count(void)
{
    sqlite3_stmt *st;
    sqlite3_stmt *up = NULL;
    int running = 0;
    int64_t now = aegisxd_now_s();

    st = aegisxd_prepare(
        "SELECT job_id,pid,started_at FROM aegis_job_state WHERE state='running'");
    if (!st)
        return 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *job_id = aegisxd_sqlite_text(st, 0, "");
        int pid = sqlite3_column_int(st, 1);
        int64_t started = sqlite3_column_int64(st, 2);
        int alive = 0;

        if (pid > 0 && kill((pid_t)pid, 0) == 0)
            alive = 1;
        else if (pid == 0 && now - started < 30)
            alive = 1;
        if (alive) {
            running++;
            continue;
        }
        if (!up)
            up = aegisxd_prepare(
                "UPDATE aegis_job_state SET state='error',finished_at=?,last_error=? "
                "WHERE job_id=? AND state='running'");
        if (up) {
            sqlite3_reset(up);
            sqlite3_clear_bindings(up);
            sqlite3_bind_int64(up, 1, now);
            sqlite3_bind_text(up, 2, "worker_exited_without_result", -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(up, 3, job_id, -1, SQLITE_TRANSIENT);
            sqlite3_step(up);
        }
    }
    sqlite3_finalize(st);
    if (up)
        sqlite3_finalize(up);
    return running;
}

int aegisxd_job_record_start(const char *job_id, const char *op,
                                    const char *feed_id, int dry_run)
{
    sqlite3_stmt *st;
    int rc;

    if (!job_id || !op || !g_aegisxd_db)
        return -1;
    st = aegisxd_prepare(
        "INSERT INTO aegis_job_state"
        "(job_id,op,feed_id,state,dry_run,pid,started_at,finished_at,ok_count,fail_count,last_error,result_json) "
        "VALUES(?,?,?,'running',?,0,?,0,0,0,'','{}')");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, op, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, feed_id ? feed_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, dry_run ? 1 : 0);
    sqlite3_bind_int64(st, 5, aegisxd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

void aegisxd_job_record_pid(const char *job_id, pid_t pid)
{
    sqlite3_stmt *st;

    if (!job_id || !g_aegisxd_db)
        return;
    st = aegisxd_prepare("UPDATE aegis_job_state SET pid=? WHERE job_id=? AND state='running'");
    if (!st)
        return;
    sqlite3_bind_int(st, 1, (int)pid);
    sqlite3_bind_text(st, 2, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

void aegisxd_job_record_finish(const char *job_id, struct json_object *result)
{
    sqlite3_stmt *st;
    const char *json_s = result ? json_object_to_json_string(result) : "{}";
    int ok_count = 0;
    int fail_count = 1;
    struct json_object *v = NULL;

    if (!job_id || !g_aegisxd_db)
        return;
    if (result && json_object_object_get_ex(result, "ok_count", &v))
        ok_count = json_object_get_int(v);
    if (result && json_object_object_get_ex(result, "fail_count", &v))
        fail_count = json_object_get_int(v);
    if (aegisxd_job_result_ok(result) && fail_count == 0 && ok_count == 0)
        ok_count = 1;
    st = aegisxd_prepare(
        "UPDATE aegis_job_state SET state=?,finished_at=?,ok_count=?,fail_count=?,"
        "last_error=?,result_json=? WHERE job_id=?");
    if (!st)
        return;
    sqlite3_bind_text(st, 1, aegisxd_job_result_ok(result) ? "done" : "error",
                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, aegisxd_now_s());
    sqlite3_bind_int(st, 3, ok_count);
    sqlite3_bind_int(st, 4, fail_count);
    sqlite3_bind_text(st, 5, aegisxd_job_result_error(result), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, json_s ? json_s : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, job_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

struct json_object *aegisxd_feed_jobs_json(int *running_out)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st;
    int running = aegisxd_job_running_count();

    st = aegisxd_prepare(
        "SELECT job_id,op,feed_id,state,dry_run,pid,started_at,finished_at,"
        "ok_count,fail_count,last_error,result_json "
        "FROM aegis_job_state ORDER BY started_at DESC LIMIT 20");
    if (st) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            const char *result_s = aegisxd_sqlite_text(st, 11, "{}");
            struct json_object *result = json_tokener_parse(result_s);

            aegisxd_json_add_string(o, "job_id", aegisxd_sqlite_text(st, 0, ""));
            aegisxd_json_add_string(o, "op", aegisxd_sqlite_text(st, 1, ""));
            aegisxd_json_add_string(o, "feed_id", aegisxd_sqlite_text(st, 2, ""));
            aegisxd_json_add_string(o, "state", aegisxd_sqlite_text(st, 3, ""));
            json_object_object_add(o, "dry_run", json_object_new_boolean(sqlite3_column_int(st, 4)));
            json_object_object_add(o, "pid", json_object_new_int(sqlite3_column_int(st, 5)));
            json_object_object_add(o, "started_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
            json_object_object_add(o, "finished_at", json_object_new_int64(sqlite3_column_int64(st, 7)));
            json_object_object_add(o, "ok_count", json_object_new_int(sqlite3_column_int(st, 8)));
            json_object_object_add(o, "fail_count", json_object_new_int(sqlite3_column_int(st, 9)));
            aegisxd_json_add_string(o, "last_error", aegisxd_sqlite_text(st, 10, ""));
            json_object_object_add(o, "result", result ? result : json_object_new_object());
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
    if (running_out)
        *running_out = running;
    return arr;
}

static int aegisxd_seed_one_feed(const struct aegisxd_feed_manifest *f)
{
    sqlite3_stmt *st;
    int rc;

    if (!f || !g_aegisxd_db)
        return -1;
    st = aegisxd_prepare(
        "INSERT OR IGNORE INTO aegis_feeds"
        "(feed_id,name,kind,url,enabled,format,meta_json,updated_at) "
        "VALUES(?,?,?,?,1,?,?,?)");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, f->feed_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, f->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, f->kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, f->url, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, f->format, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 7, aegisxd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int aegisxd_seed_builtin_feeds(void)
{
    size_t i;

    for (i = 0; i < ARRAY_SIZE(g_builtin_feeds); i++) {
        if (aegisxd_seed_one_feed(&g_builtin_feeds[i]) != 0)
            return -1;
    }
    return 0;
}

static int aegisxd_sha256_file(const char *path, char out_hex[65])
{
    unsigned char buf[8192];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx;
    FILE *fp;
    size_t n;
    unsigned int i;

    if (!path || !out_hex)
        return -1;
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(fp);
        return -1;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            return -1;
        }
    }
    if (ferror(fp) || EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 ||
        digest_len != 32) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return -1;
    }
    EVP_MD_CTX_free(ctx);
    fclose(fp);
    for (i = 0; i < digest_len; i++)
        snprintf(out_hex + (i * 2), 3, "%02x", digest[i]);
    out_hex[64] = '\0';
    return 0;
}

static void aegisxd_trim_header_value(char *s)
{
    size_t len;

    if (!s)
        return;
    while (*s == ' ' || *s == '\t')
        memmove(s, s + 1, strlen(s));
    len = strlen(s);
    while (len > 0 && (s[len - 1] == '\r' || s[len - 1] == '\n' ||
                       s[len - 1] == ' ' || s[len - 1] == '\t'))
        s[--len] = '\0';
}

static size_t aegisxd_curl_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct aegisxd_download_ctx *ctx = userdata;
    size_t len = size * nmemb;
    char line[AEGISXD_MAX_TEXT];
    char *v;

    if (!ctx || !ptr)
        return len;
    if (len >= sizeof(line))
        return len;
    memcpy(line, ptr, len);
    line[len] = '\0';
    if (!strncasecmp(line, "etag:", 5)) {
        v = line + 5;
        aegisxd_trim_header_value(v);
        snprintf(ctx->etag, sizeof(ctx->etag), "%s", v);
    } else if (!strncasecmp(line, "last-modified:", 14)) {
        v = line + 14;
        aegisxd_trim_header_value(v);
        snprintf(ctx->last_modified, sizeof(ctx->last_modified), "%s", v);
    } else if (!strncasecmp(line, "content-type:", 13)) {
        v = line + 13;
        aegisxd_trim_header_value(v);
        snprintf(ctx->content_type, sizeof(ctx->content_type), "%s", v);
    }
    return len;
}

static size_t aegisxd_curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct aegisxd_download_ctx *ctx = userdata;
    size_t len = size * nmemb;

    if (!ctx || !ctx->fp || !ptr)
        return 0;
    if (ctx->written + len > ctx->max_bytes) {
        snprintf(ctx->error, sizeof(ctx->error), "%s", "feed_too_large");
        return 0;
    }
    if (fwrite(ptr, 1, len, ctx->fp) != len) {
        snprintf(ctx->error, sizeof(ctx->error), "%s", "write_failed");
        return 0;
    }
    ctx->written += len;
    return len;
}

static int aegisxd_download_feed(const struct aegisxd_feed_manifest *f,
                                 const char *tmp_path, struct aegisxd_download_ctx *ctx)
{
    CURL *curl;
    CURLcode cc;
    long connect_timeout = 15;
    long timeout = 120;

    if (!f || !tmp_path || !ctx)
        return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->max_bytes = f->max_bytes ? f->max_bytes : AEGISXD_MAX_FEED_BYTES;
    if (f->connect_timeout_sec > 0)
        connect_timeout = f->connect_timeout_sec;
    if (f->timeout_sec > 0)
        timeout = f->timeout_sec;
    ctx->fp = fopen(tmp_path, "wb");
    if (!ctx->fp) {
        snprintf(ctx->error, sizeof(ctx->error), "%s", "open_tmp_failed");
        return -1;
    }
    curl = curl_easy_init();
    if (!curl) {
        fclose(ctx->fp);
        ctx->fp = NULL;
        snprintf(ctx->error, sizeof(ctx->error), "%s", "curl_init_failed");
        return -1;
    }
    curl_easy_setopt(curl, CURLOPT_URL, f->url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dreamingwrt-aegisxd/0.1");
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)ctx->max_bytes);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, aegisxd_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, aegisxd_curl_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, ctx);
    cc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(ctx->fp);
    ctx->fp = NULL;
    if (cc != CURLE_OK) {
        if (!ctx->error[0])
            snprintf(ctx->error, sizeof(ctx->error), "curl_%d", (int)cc);
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

static int aegisxd_line_looks_domain(const char *s)
{
    const char *p = s;
    int dot = 0;

    if (!s || !s[0] || s[0] == '#')
        return 0;
    while (*p == ' ' || *p == '\t')
        p++;
    if (!*p || *p == '#')
        return 0;
    for (; *p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n'; p++) {
        if (*p == '.')
            dot = 1;
        else if (!(isalnum((unsigned char)*p) || *p == '-' || *p == '_' || *p == '*'))
            return 0;
    }
    return dot;
}

static int aegisxd_count_text_items(const char *path, const char *format)
{
    FILE *fp;
    char line[4096];
    int count = 0;

    fp = fopen(path, "r");
    if (!fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        char first[1024], second[1024];
        int n;

        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        n = sscanf(line, "%1023s %1023s", first, second);
        if (n <= 0)
            continue;
        if (format && !strcmp(format, "hosts")) {
            if (n >= 2 && (strchr(first, '.') || strchr(first, ':')) &&
                aegisxd_line_looks_domain(second))
                count++;
        } else if (aegisxd_line_looks_domain(first)) {
            count++;
        }
    }
    fclose(fp);
    return count;
}

static struct json_object *aegisxd_feed_meta_json(const struct aegisxd_feed_manifest *f,
                                                  int dry_run, int item_count,
                                                  uint64_t bytes)
{
    struct json_object *meta = json_object_new_object();

    aegisxd_json_add_string(meta, "format", f ? f->format : "");
    aegisxd_json_add_string(meta, "category_hint", f ? f->category_hint : "");
    json_object_object_add(meta, "dry_run", json_object_new_boolean(dry_run));
    json_object_object_add(meta, "downloaded_bytes", json_object_new_int64((int64_t)bytes));
    json_object_object_add(meta, "max_bytes", json_object_new_int64((int64_t)(f && f->max_bytes ? f->max_bytes : AEGISXD_MAX_FEED_BYTES)));
    json_object_object_add(meta, "connect_timeout_sec", json_object_new_int(f && f->connect_timeout_sec > 0 ? f->connect_timeout_sec : 15));
    json_object_object_add(meta, "timeout_sec", json_object_new_int(f && f->timeout_sec > 0 ? f->timeout_sec : 120));
    json_object_object_add(meta, "estimated_item_count", json_object_new_int(item_count));
    if (f && !strcmp(f->format, "suricata_tar_gz"))
        aegisxd_json_add_string(meta, "parse_status", "downloaded_not_imported");
    else
        aegisxd_json_add_string(meta, "parse_status", "text_count_only");
    return meta;
}

static int aegisxd_record_feed_success(const struct aegisxd_feed_manifest *f,
                                       const char *artifact_path,
                                       const char *sha256,
                                       const struct aegisxd_download_ctx *ctx,
                                       int item_count, struct json_object *meta)
{
    sqlite3_stmt *st;
    const char *meta_s;
    int rc;

    if (!f || !artifact_path || !sha256 || !ctx || !meta)
        return -1;
    meta_s = json_object_to_json_string(meta);
    st = aegisxd_prepare(
        "INSERT INTO aegis_feeds"
        "(feed_id,name,kind,url,enabled,format,etag,last_modified,content_type,sha256,"
        " last_success_at,last_error,item_count,artifact_path,meta_json,updated_at) "
        "VALUES(?1,?2,?3,?4,1,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15) "
        "ON CONFLICT(feed_id) DO UPDATE SET "
        "name=excluded.name,kind=excluded.kind,url=excluded.url,format=excluded.format,"
        "etag=excluded.etag,last_modified=excluded.last_modified,content_type=excluded.content_type,"
        "sha256=excluded.sha256,last_success_at=excluded.last_success_at,last_error='',"
        "item_count=excluded.item_count,artifact_path=excluded.artifact_path,"
        "meta_json=excluded.meta_json,updated_at=excluded.updated_at");
    if (!st)
        return -1;
    sqlite3_bind_text(st, 1, f->feed_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, f->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, f->kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, f->url, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, f->format, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, ctx->etag, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, ctx->last_modified, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, ctx->content_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 9, sha256, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 10, aegisxd_now_s());
    sqlite3_bind_text(st, 11, "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 12, item_count);
    sqlite3_bind_text(st, 13, artifact_path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 14, meta_s ? meta_s : "{}", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 15, aegisxd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void aegisxd_record_feed_error(const struct aegisxd_feed_manifest *f, const char *err)
{
    sqlite3_stmt *st;

    if (!f || !g_aegisxd_db)
        return;
    st = aegisxd_prepare(
        "UPDATE aegis_feeds SET last_error=?,updated_at=? WHERE feed_id=?");
    if (!st)
        return;
    sqlite3_bind_text(st, 1, err ? err : "error", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, aegisxd_now_s());
    sqlite3_bind_text(st, 3, f->feed_id, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

static struct json_object *aegisxd_update_one_feed(const struct aegisxd_feed_manifest *f,
                                                   int dry_run)
{
    struct json_object *result = json_object_new_object();
    struct json_object *meta = NULL;
    struct aegisxd_download_ctx ctx;
    char tmp_path[AEGISXD_MAX_PATH];
    char artifact_path[AEGISXD_MAX_PATH];
    char sha256[65];
    int item_count = 0;
    int ok = 0;

    aegisxd_json_add_string(result, "feed_id", f ? f->feed_id : "");
    if (!f) {
        json_object_object_add(result, "ok", json_object_new_boolean(0));
        aegisxd_json_add_string(result, "error", "unknown_feed");
        return result;
    }
    if (aegisxd_mkdir_p(AEGISXD_FEED_DIR, 0755) != 0) {
        json_object_object_add(result, "ok", json_object_new_boolean(0));
        aegisxd_json_add_string(result, "error", "workdir_failed");
        return result;
    }
    snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp", AEGISXD_FEED_DIR, f->feed_id);
    snprintf(artifact_path, sizeof(artifact_path), "%s/%s.feed", AEGISXD_FEED_DIR, f->feed_id);
    unlink(tmp_path);
    if (aegisxd_download_feed(f, tmp_path, &ctx) != 0) {
        json_object_object_add(result, "ok", json_object_new_boolean(0));
        aegisxd_json_add_string(result, "error", ctx.error[0] ? ctx.error : "download_failed");
        json_object_object_add(result, "downloaded_bytes", json_object_new_int64((int64_t)ctx.written));
        json_object_object_add(result, "max_bytes", json_object_new_int64((int64_t)(f->max_bytes ? f->max_bytes : AEGISXD_MAX_FEED_BYTES)));
        json_object_object_add(result, "connect_timeout_sec", json_object_new_int(f->connect_timeout_sec > 0 ? f->connect_timeout_sec : 15));
        json_object_object_add(result, "timeout_sec", json_object_new_int(f->timeout_sec > 0 ? f->timeout_sec : 120));
        aegisxd_record_feed_error(f, ctx.error[0] ? ctx.error : "download_failed");
        return result;
    }
    if (aegisxd_sha256_file(tmp_path, sha256) != 0) {
        unlink(tmp_path);
        json_object_object_add(result, "ok", json_object_new_boolean(0));
        aegisxd_json_add_string(result, "error", "sha256_failed");
        aegisxd_record_feed_error(f, "sha256_failed");
        return result;
    }
    if (strcmp(f->format, "suricata_tar_gz"))
        item_count = aegisxd_count_text_items(tmp_path, f->format);
    if (rename(tmp_path, artifact_path) != 0) {
        unlink(tmp_path);
        json_object_object_add(result, "ok", json_object_new_boolean(0));
        aegisxd_json_add_string(result, "error", "artifact_rename_failed");
        aegisxd_record_feed_error(f, "artifact_rename_failed");
        return result;
    }
    meta = aegisxd_feed_meta_json(f, dry_run, item_count, ctx.written);
    ok = aegisxd_record_feed_success(f, artifact_path, sha256, &ctx, item_count, meta) == 0;
    json_object_object_add(result, "ok", json_object_new_boolean(ok));
    aegisxd_json_add_string(result, "name", f->name);
    aegisxd_json_add_string(result, "kind", f->kind);
    aegisxd_json_add_string(result, "url", f->url);
    aegisxd_json_add_string(result, "format", f->format);
    aegisxd_json_add_string(result, "sha256", sha256);
    aegisxd_json_add_string(result, "etag", ctx.etag);
    aegisxd_json_add_string(result, "last_modified", ctx.last_modified);
    aegisxd_json_add_string(result, "content_type", ctx.content_type);
    aegisxd_json_add_string(result, "artifact_path", artifact_path);
    json_object_object_add(result, "downloaded_bytes", json_object_new_int64((int64_t)ctx.written));
    json_object_object_add(result, "item_count", json_object_new_int(item_count));
    json_object_object_add(result, "dry_run", json_object_new_boolean(dry_run));
    json_object_object_add(result, "auto_import", json_object_new_boolean(!dry_run && ok));
    if (!dry_run && ok) {
        struct json_object *import_result = aegisxd_import_feed_id(f->feed_id);
        struct json_object *import_ok = NULL;
        int imported_ok = json_object_object_get_ex(import_result, "ok", &import_ok) &&
                          json_object_get_boolean(import_ok);

        json_object_object_add(result, "import_ok", json_object_new_boolean(imported_ok));
        json_object_object_add(result, "import_result", import_result);
        if (!imported_ok)
            ok = 0;
    }
    if (!ok)
        aegisxd_json_add_string(result, "error", "db_update_failed");
    json_object_object_add(result, "ok", json_object_new_boolean(ok));
    json_object_object_add(result, "meta", meta);
    return result;
}

static struct json_object *aegisxd_feed_update_run(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *results = json_object_new_array();
    const char *feed_id = aegisxd_json_str(body, "feed_id", "");
    int dry_run = aegisxd_json_bool(body, "dry_run", 1);
    int ok_count = 0;
    int fail_count = 0;
    size_t i;

    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
    aegisxd_json_add_string(resp, "state", "done");
    json_object_object_add(resp, "running", json_object_new_boolean(0));
    json_object_object_add(resp, "dry_run", json_object_new_boolean(dry_run));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));

    if (feed_id && feed_id[0]) {
        struct json_object *r = aegisxd_update_one_feed(aegisxd_find_builtin_feed(feed_id), dry_run);
        struct json_object *okv = NULL;

        if (json_object_object_get_ex(r, "ok", &okv) && json_object_get_boolean(okv))
            ok_count++;
        else
            fail_count++;
        json_object_array_add(results, r);
    } else {
        for (i = 0; i < ARRAY_SIZE(g_builtin_feeds); i++) {
            struct json_object *r = aegisxd_update_one_feed(&g_builtin_feeds[i], dry_run);
            struct json_object *okv = NULL;

            if (json_object_object_get_ex(r, "ok", &okv) && json_object_get_boolean(okv))
                ok_count++;
            else
                fail_count++;
            json_object_array_add(results, r);
        }
    }

    json_object_object_add(resp, "ok_count", json_object_new_int(ok_count));
    json_object_object_add(resp, "fail_count", json_object_new_int(fail_count));
    json_object_object_add(resp, "results", results);
    if (fail_count > 0)
        json_object_object_add(resp, "ok", json_object_new_boolean(0));
    return resp;
}

int aegisxd_feed_update_worker_main(const char *job_id, const char *feed_id, int dry_run)
{
    struct json_object *body;
    struct json_object *result;
    int ok;

    if (aegisxd_db_init() != 0) {
        result = aegisxd_error("db_init_failed", "failed to initialize aegis database in worker");
    } else {
        body = json_object_new_object();
        if (feed_id && feed_id[0])
            aegisxd_json_add_string(body, "feed_id", feed_id);
        json_object_object_add(body, "dry_run", json_object_new_boolean(dry_run));
        result = aegisxd_feed_update_run(body);
        json_object_put(body);
    }
    ok = aegisxd_job_result_ok(result);
    aegisxd_job_record_finish(job_id, result);
    json_object_put(result);
    aegisxd_db_close();
    return ok ? 0 : 1;
}

struct json_object *aegisxd_feed_update_start(struct json_object *body)
{
    const char *feed_id = aegisxd_json_str(body, "feed_id", "");
    int dry_run = aegisxd_json_bool(body, "dry_run", 1);
    /* Keep the single-threaded ubus loop responsive during slow downloads. */
    int background = aegisxd_json_bool(body, "background",
                       aegisxd_json_bool(body, "async", 1));
    char job_id[128];
    pid_t pid;

    if (!background)
        return aegisxd_feed_update_run(body);
    if (aegisxd_job_running_count() > 0) {
        struct json_object *resp = aegisxd_error("job_already_running",
            "another aegis feed job is already running");

        aegisxd_json_add_string(resp, "state", "running");
        json_object_object_add(resp, "running", json_object_new_boolean(1));
        json_object_object_add(resp, "jobs", aegisxd_feed_jobs_json(NULL));
        return resp;
    }
    snprintf(job_id, sizeof(job_id), "feed-update-%lld-%ld",
             (long long)aegisxd_now_s(), (long)getpid());
    if (aegisxd_job_record_start(job_id, "feed_update", feed_id, dry_run) != 0)
        return aegisxd_error("job_record_failed", "failed to record aegis feed job");
    pid = fork();
    if (pid < 0) {
        struct json_object *err = aegisxd_error("fork_failed", "failed to start feed update worker");

        aegisxd_job_record_finish(job_id, err);
        return err;
    }
    if (pid == 0) {
        char dry_buf[8];

        snprintf(dry_buf, sizeof(dry_buf), "%d", dry_run ? 1 : 0);
        execl("/usr/bin/dreamingwrt-aegisxd", "dreamingwrt-aegisxd",
              "--feed-update-worker", job_id, feed_id ? feed_id : "", dry_buf,
              (char *)NULL);
        _exit(127);
    }
    aegisxd_job_record_pid(job_id, pid);

    {
        struct json_object *resp = json_object_new_object();

        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        aegisxd_json_add_string(resp, "service", "dreamingwrt-aegisxd");
        aegisxd_json_add_string(resp, "state", "running");
        json_object_object_add(resp, "running", json_object_new_boolean(1));
        json_object_object_add(resp, "background", json_object_new_boolean(1));
        aegisxd_json_add_string(resp, "job_id", job_id);
        aegisxd_json_add_string(resp, "op", "feed_update");
        aegisxd_json_add_string(resp, "feed_id", feed_id);
        json_object_object_add(resp, "pid", json_object_new_int((int)pid));
        json_object_object_add(resp, "dry_run", json_object_new_boolean(dry_run));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
        return resp;
    }
}
