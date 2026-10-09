// SPDX-License-Identifier: GPL-2.0-or-later
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <json-c/json.h>

#include "flowd_internal.h"
#include "flowd_nft_apply.h"
#include "flowd_terminal_policy_tc.h"
#include "../terminal_policy/terminal_policy.h"

#define FLOWD_TERMINAL_POLICY_DB_PATH "/etc/dreamingwrt/terminal_policy.db"
#define FLOWD_TP_NFT_TABLE "dreamingwrt_terminal_policy"
#define FLOWD_TP_NFT_TABLE_COMMENT "dreamingwrt-terminal-policy-v1"
#define FLOWD_TP_NFT_EXPECTED_RULES 16384
/* Run before fw4's established/related fast-path (priority 0).  A terminal
 * policy drop must also stop traffic from already-established conntrack flows;
 * -150 is after conntrack's state attachment but before fw4's mangle/filter
 * chains, so an existing flow cannot bypass a newly-applied policy. */
#define FLOWD_TP_NFT_HOOK_PRIORITY (-150)

/*
 * Fingerprint set used to prove the kernel really carries the rules we
 * rendered.  Every emitted rule gets a "tp|<id>|<family>|<prefix>/<plen>|<kind>"
 * comment, so a readback of `nft -j list table` can be compared element by
 * element instead of merely checking that the table exists.
 */
struct flowd_tp_nft_expect {
    char **items;
    size_t count;
    size_t cap;
};

static void flowd_tp_nft_expect_free(struct flowd_tp_nft_expect *expect)
{
    size_t i;

    if (!expect)
        return;
    for (i = 0; i < expect->count; i++)
        free(expect->items[i]);
    free(expect->items);
    memset(expect, 0, sizeof(*expect));
}

static int flowd_tp_nft_expect_push(struct flowd_tp_nft_expect *expect, char *item)
{
    if (!expect || !item)
        return -1;
    if (expect->count >= FLOWD_TP_NFT_EXPECTED_RULES)
        return -1;
    if (expect->count == expect->cap) {
        size_t new_cap = expect->cap ? expect->cap * 2 : 64;
        char **grown;

        if (new_cap > FLOWD_TP_NFT_EXPECTED_RULES)
            new_cap = FLOWD_TP_NFT_EXPECTED_RULES;
        grown = realloc(expect->items, new_cap * sizeof(*grown));
        if (!grown)
            return -1;
        expect->items = grown;
        expect->cap = new_cap;
    }
    expect->items[expect->count++] = item;
    return 0;
}

static int flowd_tp_nft_expect_add(struct flowd_tp_nft_expect *expect,
                                   const char *id, int family,
                                   const char *prefix, int plen,
                                   const char *kind)
{
    char item[512];
    char *copy;

    if (!expect || !id || !prefix || !kind)
        return -1;
    if (snprintf(item, sizeof(item), "tp|%s|%d|%s/%d|%s",
                 id, family, prefix, plen, kind) >= (int)sizeof(item))
        return -1;
    copy = strdup(item);
    if (!copy)
        return -1;
    if (flowd_tp_nft_expect_push(expect, copy) != 0) {
        free(copy);
        return -1;
    }
    return 0;
}

static int flowd_tp_nft_expect_has(const struct flowd_tp_nft_expect *expect,
                                   const char *item)
{
    size_t i;

    if (!expect || !item)
        return 0;
    for (i = 0; i < expect->count; i++)
        if (!strcmp(expect->items[i], item))
            return 1;
    return 0;
}

static int flowd_tp_nft_expect_equal(const struct flowd_tp_nft_expect *expected,
                                     const struct flowd_tp_nft_expect *actual,
                                     size_t *missing, size_t *foreign)
{
    size_t i;
    size_t miss = 0;
    size_t extra = 0;

    if (missing)
        *missing = 0;
    if (foreign)
        *foreign = 0;
    if (!expected || !actual)
        return 0;
    for (i = 0; i < expected->count; i++)
        if (!flowd_tp_nft_expect_has(actual, expected->items[i]))
            miss++;
    for (i = 0; i < actual->count; i++)
        if (!flowd_tp_nft_expect_has(expected, actual->items[i]))
            extra++;
    if (missing)
        *missing = miss;
    if (foreign)
        *foreign = extra;
    return miss == 0 && extra == 0 && expected->count == actual->count;
}

static int flowd_tp_nft_actual_from_json(struct json_object *root,
                                         struct flowd_tp_nft_expect *actual)
{
    struct json_object *items = NULL;
    size_t i;

    if (!root || !actual ||
        !json_object_object_get_ex(root, "nftables", &items) ||
        !json_object_is_type(items, json_type_array))
        return -1;
    memset(actual, 0, sizeof(*actual));
    for (i = 0; i < json_object_array_length(items); i++) {
        struct json_object *entry = json_object_array_get_idx(items, i);
        struct json_object *rule = NULL;
        struct json_object *comment = NULL;
        const char *comment_s;
        char *copy;

        if (!entry || !json_object_object_get_ex(entry, "rule", &rule) ||
            !json_object_object_get_ex(rule, "comment", &comment))
            continue;
        comment_s = json_object_get_string(comment);
        if (!comment_s || strncmp(comment_s, "tp|", 3) != 0)
            continue;
        /* Must go through the push helper: the set is a grown array, and
         * writing items[count] directly dereferenced a NULL items pointer the
         * first time a comment matched. */
        copy = strdup(comment_s);
        if (!copy) {
            flowd_tp_nft_expect_free(actual);
            return -1;
        }
        if (flowd_tp_nft_expect_push(actual, copy) != 0) {
            free(copy);
            flowd_tp_nft_expect_free(actual);
            return -1;
        }
    }
    return 0;
}

static int flowd_tp_text(sqlite3_stmt *st, int col, const char *def, char *out, size_t out_len)
{
    const unsigned char *v = sqlite3_column_text(st, col);

    if (!out || !out_len || !v)
        return -1;
    snprintf(out, out_len, "%s", (const char *)v);
    return out[0] ? 0 : (def ? (snprintf(out, out_len, "%s", def), 0) : -1);
}

static int flowd_tp_bool(sqlite3_stmt *st, int col)
{
    return sqlite3_column_int(st, col) != 0;
}

/*
 * Projection of unified terminal policies into flowd's compile/readback view.
 * The executor is live: compile describes the nft/tc/quota consumer that will
 * own the generation, while runtime_applied and runtime_reason come from the
 * same kernel readback used by terminal_policy_apply().
 */
struct json_object *flowd_terminal_policy_compile(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *out = json_object_new_object();
    struct json_object *rules = json_object_new_array();
    int enabled_count = 0;
    int total_count = 0;
    int rc;
    struct json_object *runtime = NULL;
    struct json_object *runtime_applied = NULL;
    struct json_object *runtime_reason = NULL;
    int executor_available;
    int runtime_ok = 0;

    if (!out || !rules) {
        if (rules) json_object_put(rules);
        if (out) json_object_put(out);
        return NULL;
    }
    json_object_object_add(out, "rules", rules);

    if (sqlite3_open_v2(FLOWD_TERMINAL_POLICY_DB_PATH, &db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        json_object_object_add(out, "available", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string("terminal_policy_db_unavailable"));
        return out;
    }

    rc = sqlite3_prepare_v2(db,
        "SELECT id,name,enabled,rate_upload_kbps,rate_download_kbps,rate_mode,"
        "deadline_at,quota_bytes,quota_accounting,quota_mode,deny_protocols,status "
        "FROM policies ORDER BY created_at DESC",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        json_object_object_add(out, "available", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string("terminal_policy_query_failed"));
        return out;
    }

    while (sqlite3_step(st) == SQLITE_ROW) {
        char id[128], name[256], rate_mode[32], quota_accounting[32];
        char quota_mode[32], deny_protocols[128], status[32];
        struct json_object *rule = json_object_new_object();
        int enabled = flowd_tp_bool(st, 2);

        if (!rule)
            continue;
        total_count++;
        if (enabled)
            enabled_count++;
        flowd_tp_text(st, 0, "unknown", id, sizeof(id));
        flowd_tp_text(st, 1, id, name, sizeof(name));
        flowd_tp_text(st, 5, "per_ip", rate_mode, sizeof(rate_mode));
        flowd_tp_text(st, 8, "upload_plus_download", quota_accounting, sizeof(quota_accounting));
        flowd_tp_text(st, 9, "per_ip", quota_mode, sizeof(quota_mode));
        flowd_tp_text(st, 10, "", deny_protocols, sizeof(deny_protocols));
        flowd_tp_text(st, 11, "disabled", status, sizeof(status));

        json_object_object_add(rule, "id", json_object_new_string(id));
        json_object_object_add(rule, "name", json_object_new_string(name));
        json_object_object_add(rule, "enabled", json_object_new_boolean(enabled));
        json_object_object_add(rule, "rate_upload_kbps",
                               json_object_new_int(sqlite3_column_int(st, 3)));
        json_object_object_add(rule, "rate_download_kbps",
                               json_object_new_int(sqlite3_column_int(st, 4)));
        json_object_object_add(rule, "rate_mode", json_object_new_string(rate_mode));
        json_object_object_add(rule, "deadline_at",
                               json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(rule, "quota_bytes",
                               json_object_new_int64(sqlite3_column_int64(st, 7)));
        json_object_object_add(rule, "quota_accounting", json_object_new_string(quota_accounting));
        json_object_object_add(rule, "quota_mode", json_object_new_string(quota_mode));
        if (deny_protocols[0])
            json_object_object_add(rule, "deny_protocols",
                                   json_object_new_string(deny_protocols));
        json_object_object_add(rule, "status", json_object_new_string(status));
        json_object_object_add(rule, "runtime_kind", json_object_new_string("terminal_policy"));
        json_object_object_add(rule, "mutates_dataplane", json_object_new_boolean(enabled));
        json_object_array_add(rules, rule);
    }
    sqlite3_finalize(st);
    sqlite3_close(db);

    executor_available = flowd_terminal_policy_executor_available() &&
                         flowd_terminal_policy_tc_executor_available();
    if (executor_available)
        runtime = flowd_terminal_policy_runtime();
    if (runtime) {
        if (json_object_object_get_ex(runtime, "runtime_applied", &runtime_applied) &&
            runtime_applied)
            runtime_ok = json_object_get_boolean(runtime_applied);
        json_object_object_get_ex(runtime, "reason", &runtime_reason);
        if (!runtime_reason)
            json_object_object_get_ex(runtime, "runtime_reason", &runtime_reason);
        json_object_object_add(out, "runtime", runtime);
    }
    json_object_object_add(out, "available", json_object_new_boolean(executor_available));
    json_object_object_add(out, "total", json_object_new_int(total_count));
    json_object_object_add(out, "enabled", json_object_new_int(enabled_count));
    json_object_object_add(out, "dataplane", json_object_new_string("nft_tc_quota"));
    json_object_object_add(out, "mutates_dataplane", json_object_new_boolean(executor_available));
    json_object_object_add(out, "runtime_applied", json_object_new_boolean(runtime_ok));
    json_object_object_add(out, "runtime_reason", json_object_new_string(
        runtime_reason && json_object_get_string(runtime_reason) ?
            json_object_get_string(runtime_reason) :
            (executor_available ? "terminal_policy_runtime_unverified" :
                                  "terminal_policy_executor_unavailable")));
    return out;
}

/* Dynamic nft string buffer used only while rendering one apply file. */
struct flowd_tp_buf {
    char *s;
    size_t len;
    size_t cap;
};

static int flowd_tp_buf_put(struct flowd_tp_buf *b, const char *fmt, ...)
{
    char tmp[512];
    va_list ap;
    int n;

    if (!b || !fmt)
        return -1;
    va_start(ap, fmt);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(tmp))
        return -1;
    if (b->len + (size_t)n + 1 > b->cap) {
        size_t new_cap = b->cap ? b->cap * 2 : 4096;
        char *ns;

        while (new_cap < b->len + (size_t)n + 1)
            new_cap *= 2;
        ns = realloc(b->s, new_cap);
        if (!ns)
            return -1;
        b->s = ns;
        b->cap = new_cap;
    }
    memcpy(b->s + b->len, tmp, (size_t)n);
    b->len += (size_t)n;
    b->s[b->len] = '\0';
    return 0;
}

/*
 * Append raw text of any length.
 *
 * flowd_tp_buf_put() formats through a 512-byte stack buffer and fails when the
 * result does not fit.  That is fine for the per-rule lines it renders, but the
 * rollback file embeds the *entire* previous nft table, which passes 512 bytes
 * as soon as a handful of rules exist.  Sending it through the formatter made
 * flowd_tp_render_nft() fail with an empty err string, surfacing as
 * terminal_policy_render_failed, and from that point on every apply failed —
 * the policy set could never grow past roughly three rules.
 */
static int flowd_tp_buf_append(struct flowd_tp_buf *b, const char *text)
{
    size_t n;

    if (!b || !text)
        return -1;
    n = strlen(text);
    if (!n)
        return 0;
    if (b->len + n + 1 > b->cap) {
        size_t new_cap = b->cap ? b->cap * 2 : 4096;
        char *ns;

        while (new_cap < b->len + n + 1)
            new_cap *= 2;
        ns = realloc(b->s, new_cap);
        if (!ns)
            return -1;
        b->s = ns;
        b->cap = new_cap;
    }
    memcpy(b->s + b->len, text, n);
    b->len += n;
    b->s[b->len] = '\0';
    return 0;
}

static char *flowd_tp_read_text_file(const char *path, size_t max_len)
{
    FILE *fp;
    char *buf;
    size_t len = 0;
    size_t n;

    if (!path || !max_len)
        return NULL;
    fp = fopen(path, "r");
    if (!fp)
        return NULL;
    buf = calloc(1, max_len + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    while (len < max_len && (n = fread(buf + len, 1, max_len - len, fp)) > 0)
        len += n;
    if (ferror(fp) || (len == max_len && !feof(fp))) {
        free(buf);
        buf = NULL;
    } else {
        buf[len] = '\0';
    }
    fclose(fp);
    return buf;
}

static int flowd_tp_nft_previous_text(const char *runtime_dir,
                                      const char *revision,
                                      char **text_out)
{
    char path[PATH_MAX];
    char leaf[192];
    char *argv[8];
    int rc;
    char *text;

    if (!runtime_dir || !revision || !text_out)
        return -1;
    *text_out = NULL;
    snprintf(leaf, sizeof(leaf), "tp-%s-previous.nft", revision);
    if (flowd_nft_join(path, sizeof(path), runtime_dir, leaf) != 0)
        return -1;
    argv[0] = (char *)FLOWD_NFT_BINARY;
    argv[1] = (char *)"-s";
    argv[2] = (char *)"list";
    argv[3] = (char *)"table";
    argv[4] = (char *)"inet";
    argv[5] = (char *)FLOWD_TP_NFT_TABLE;
    argv[6] = NULL;
    rc = flowd_nft_run(FLOWD_NFT_BINARY, argv, path);
    if (rc != 0)
        return 0; /* No previous table is a valid first-apply state. */
    text = flowd_tp_read_text_file(path, 512U * 1024U);
    if (!text || !strstr(text, "table inet " FLOWD_TP_NFT_TABLE)) {
        free(text);
        return -1;
    }
    *text_out = text;
    return 1;
}

static int flowd_tp_rule_needs_apply(const char *status, const char *deny_protocols)
{
    if (!status || !deny_protocols)
        return 0;
    if (!strcmp(status, "blocked_time") || !strcmp(status, "blocked_quota"))
        return 1;
    if (!strcmp(status, "active") && deny_protocols[0])
        return 1;
    return 0;
}

static const char *flowd_tp_internet_match(int family, const char *elem)
{
    static char match[256];

    if (!elem || !elem[0])
        return NULL;
    snprintf(match, sizeof(match), "iifname \"br-lan\" oifname != \"br-lan\" %s %s",
             family == 6 ? "ip6 saddr" : "ip saddr", elem);
    return match;
}

static int flowd_tp_nft_put_rule(struct flowd_tp_buf *apply,
                                 struct flowd_tp_nft_expect *expect,
                                 const char *id, int family,
                                 const char *prefix, int plen,
                                 const char *match, const char *kind)
{
    char comment[512];
    char line[1280];

    if (!apply || !expect || !id || !prefix || !match || !kind)
        return -1;
    if (snprintf(comment, sizeof(comment), "tp|%s|%d|%s/%d|%s",
                 id, family, prefix, plen, kind) >= (int)sizeof(comment))
        return -1;
    /* Composed here and appended raw: a long IPv6 match plus a long policy id
     * can exceed the formatter's 512-byte scratch buffer, and that failure mode
     * is indistinguishable from OOM at the call site. */
    if (snprintf(line, sizeof(line), "    %s counter drop comment \"%s\"\n",
                 match, comment) >= (int)sizeof(line))
        return -1;
    if (flowd_tp_buf_append(apply, line) != 0)
        return -1;
    return flowd_tp_nft_expect_add(expect, id, family, prefix, plen, kind);
}

/*
 * Renders the nft program for the current policy set and, as a side effect,
 * fills @expect with one fingerprint per emitted rule.
 *
 * dry_run=1 skips the previous-generation snapshot and the file writes.  The
 * runtime path uses it so the expectation it verifies against is produced by
 * the exact same code that produced the rules, instead of a second, drifting
 * reimplementation of the same SQL.
 */
static int flowd_tp_render_nft(const char *runtime_dir, const char *revision,
                               char *apply_path, size_t apply_path_len,
                               char *rollback_path, size_t rollback_path_len,
                               int *readback_required,
                               struct flowd_tp_nft_expect *expect,
                               int dry_run,
                               char *err, size_t err_len)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *pol = NULL;
    sqlite3_stmt *tgt = NULL;
    sqlite3_stmt *blocks = NULL;
    struct flowd_tp_buf apply = { 0 };
    struct flowd_tp_buf rollback = { 0 };
    char *previous_nft = NULL;
    int need_table = 0;
    int previous_rc;
    int rc = -1;
    int row_rc;

    if (!runtime_dir || !revision || !readback_required || !expect ||
        (!dry_run && (!apply_path || !rollback_path)) ||
        !flowd_nft_safe_token(revision, 120)) {
        snprintf(err, err_len, "%s", "invalid_tp_nft_args");
        return -1;
    }
    *readback_required = 0;
    memset(expect, 0, sizeof(*expect));

    /* Snapshot the currently owned table before rendering the new generation.
     * The rollback file must restore the complete previous rule set, not merely
     * destroy the table; otherwise a failed tc/nft apply silently drops the
     * last working policy generation. */
    if (!dry_run) {
        previous_rc = flowd_tp_nft_previous_text(runtime_dir, revision, &previous_nft);
        if (previous_rc < 0) {
            snprintf(err, err_len, "%s", "tp_nft_previous_readback_failed");
            return -1;
        }
    } else {
        previous_rc = 0;
    }
    (void)previous_rc;

    if (sqlite3_open_v2(FLOWD_TERMINAL_POLICY_DB_PATH, &db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        snprintf(err, err_len, "%s", "terminal_policy_db_unavailable");
        sqlite3_close(db);
        return -1;
    }

    /* Keep the sqlite status in its own variable.  `rc` is the function's
     * return code and must stay -1 until the render genuinely completes:
     * assigning SQLITE_OK (0) to it made every later `goto out` — including a
     * mid-scan SQLITE_BUSY — report success while apply_path/rollback_path were
     * still uninitialised, and the caller then ran `nft -f <stack garbage>`. */
    if (sqlite3_prepare_v2(db,
        "SELECT id,enabled,deny_protocols,status,deadline_at,quota_mode,"
        "(SELECT COUNT(*) FROM quota_blocks qb WHERE qb.policy_id=policies.id) "
        "FROM policies WHERE enabled=1 ORDER BY created_at DESC",
        -1, &pol, NULL) != SQLITE_OK) {
        snprintf(err, err_len, "%s", "terminal_policy_query_failed");
        goto out;
    }

    if (flowd_tp_buf_put(&apply,
                         "destroy table inet %s\n"
                         "table inet %s {\n"
                         "  comment \"%s-%s\"\n"
                         "  chain forward {\n"
                         "    type filter hook forward priority %d; policy accept;\n",
                         FLOWD_TP_NFT_TABLE, FLOWD_TP_NFT_TABLE,
                         FLOWD_TP_NFT_TABLE_COMMENT, revision,
                         FLOWD_TP_NFT_HOOK_PRIORITY) != 0) {
        snprintf(err, err_len, "%s", "tp_nft_render_oom");
        goto out;
    }

    while ((row_rc = sqlite3_step(pol)) == SQLITE_ROW) {
        char id[128], status[32], deny[128], quota_mode[32];
        int enabled = sqlite3_column_int(pol, 1);
        int block_count = sqlite3_column_int(pol, 6);
        int policy_emitted = 0;

        if (!enabled)
            continue;
        flowd_tp_text(pol, 0, "unk", id, sizeof(id));
        flowd_tp_text(pol, 3, "disabled", status, sizeof(status));
        flowd_tp_text(pol, 2, "", deny, sizeof(deny));
        flowd_tp_text(pol, 5, "per_ip", quota_mode, sizeof(quota_mode));

        if (!flowd_tp_rule_needs_apply(status, deny) && block_count <= 0)
            continue;
        if (!flowd_id_ok(id)) {
            snprintf(err, err_len, "%s", "tp_rule_invalid_id");
            goto out;
        }

        /* Query targets for this policy. */
        if (tgt)
            sqlite3_finalize(tgt);
        tgt = NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT family,prefix,prefix_len FROM targets WHERE policy_id=? ORDER BY family,prefix",
            -1, &tgt, NULL) != SQLITE_OK) {
            snprintf(err, err_len, "%s", "tp_target_query_failed");
            goto out;
        }
        sqlite3_bind_text(tgt, 1, id, -1, SQLITE_STATIC);

        while (sqlite3_step(tgt) == SQLITE_ROW) {
            int family = sqlite3_column_int(tgt, 0);
            const char *prefix = (const char *)sqlite3_column_text(tgt, 1);
            int plen = sqlite3_column_int(tgt, 2);
            char addr[128];
            char elem[192];
            char deny_work[128];

            if (!prefix || !prefix[0] || plen < 0 || plen > 128)
                continue;
            snprintf(addr, sizeof(addr), "%s", prefix);
            if (plen == 32 && family == 4)
                snprintf(elem, sizeof(elem), "%s", addr);
            else if (plen == 128 && family == 6)
                snprintf(elem, sizeof(elem), "%s", addr);
            else
                snprintf(elem, sizeof(elem), "%s/%d", addr, plen);

            if (!strcmp(status, "blocked_time") || !strcmp(status, "blocked_quota")) {
                const char *match = flowd_tp_internet_match(family, elem);
                if (!match || flowd_tp_nft_put_rule(&apply, expect, id, family,
                                                     addr, plen, match, "block") != 0)
                    goto oom;
                policy_emitted = 1;
            } else if (deny[0]) {
                char *save = NULL;
                snprintf(deny_work, sizeof(deny_work), "%s", deny);
                char *tok = strtok_r(deny_work, ",", &save);

                while (tok) {
                    while (*tok == ' ')
                        tok++;
                    if (!strcmp(tok, "tcp")) {
                        char match[384];
                        const char *base = flowd_tp_internet_match(family, elem);
                        if (!base || snprintf(match, sizeof(match), "%s meta l4proto tcp", base) >= (int)sizeof(match) ||
                            flowd_tp_nft_put_rule(&apply, expect, id, family, addr,
                                                  plen, match, "tcp") != 0)
                            goto oom;
                        policy_emitted = 1;
                    } else if (!strcmp(tok, "udp")) {
                        char match[384];
                        const char *base = flowd_tp_internet_match(family, elem);
                        if (!base || snprintf(match, sizeof(match), "%s meta l4proto udp", base) >= (int)sizeof(match) ||
                            flowd_tp_nft_put_rule(&apply, expect, id, family, addr,
                                                  plen, match, "udp") != 0)
                            goto oom;
                        policy_emitted = 1;
                    } else if (!strcmp(tok, "icmp")) {
                        char match[384];
                        const char *base = flowd_tp_internet_match(family, elem);
                        const char *l4 = family == 6 ? "ipv6-icmp" : "icmp";
                        if (!base || snprintf(match, sizeof(match), "%s meta l4proto %s", base, l4) >= (int)sizeof(match) ||
                            flowd_tp_nft_put_rule(&apply, expect, id, family, addr,
                                                  plen, match, "icmp") != 0)
                            goto oom;
                        policy_emitted = 1;
                    }
                    tok = strtok_r(NULL, ",", &save);
                }
            }
            continue;
        oom:
            snprintf(err, err_len, "%s", "tp_nft_render_oom");
            goto out;
        }
        sqlite3_finalize(tgt);
        tgt = NULL;

        /* per_ip quota blocks are client-specific.  Keep active policy targets
         * reachable for the other clients and render only exhausted addresses. */
        if (!strcmp(quota_mode, "per_ip") && strcmp(status, "blocked_quota") != 0) {
            if (sqlite3_prepare_v2(db,
                "SELECT family,client_ip FROM quota_blocks WHERE policy_id=? "
                "ORDER BY family,client_ip", -1, &blocks, NULL) != SQLITE_OK) {
                snprintf(err, err_len, "%s", "tp_quota_block_query_failed");
                goto out;
            }
            sqlite3_bind_text(blocks, 1, id, -1, SQLITE_STATIC);
            while (sqlite3_step(blocks) == SQLITE_ROW) {
                int family = sqlite3_column_int(blocks, 0);
                const char *ip = (const char *)sqlite3_column_text(blocks, 1);
                const char *match;
                if (!ip || !ip[0] || (family != 4 && family != 6))
                    continue;
                match = flowd_tp_internet_match(family, ip);
                if (!match || flowd_tp_nft_put_rule(&apply, expect, id, family,
                                                     ip, family == 6 ? 128 : 32,
                                                     match, "quota") != 0)
                    goto oom;
                policy_emitted = 1;
            }
            sqlite3_finalize(blocks);
            blocks = NULL;
        }
        if (policy_emitted)
            need_table = 1;
    }
    if (row_rc != SQLITE_DONE) {
        snprintf(err, err_len, "%s", "terminal_policy_scan_failed");
        goto out;
    }

    if (!need_table) {
        apply.len = 0;
        if (apply.s)
            apply.s[0] = '\0';
        if (flowd_tp_buf_put(&apply, "destroy table inet %s\n",
                             FLOWD_TP_NFT_TABLE) != 0) {
            snprintf(err, err_len, "%s", "tp_nft_render_oom");
            goto out;
        }
    } else {
        if (flowd_tp_buf_put(&apply, "  }\n}\n") != 0) {
            snprintf(err, err_len, "%s", "tp_nft_render_oom");
            goto out;
        }
        *readback_required = 1;
    }

    if (dry_run) {
        rc = 0;
        goto out;
    }

    if (flowd_tp_buf_put(&rollback,
                         "destroy table inet %s\n",
                         FLOWD_TP_NFT_TABLE) != 0) {
        snprintf(err, err_len, "%s", "tp_nft_rollback_render_oom");
        goto out;
    }
    if (previous_nft &&
        (flowd_tp_buf_append(&rollback, previous_nft) != 0 ||
         flowd_tp_buf_append(&rollback, "\n") != 0)) {
        snprintf(err, err_len, "%s", "tp_nft_rollback_render_oom");
        goto out;
    }

    {
        char leaf_apply[160];
        char leaf_roll[160];

        snprintf(leaf_apply, sizeof(leaf_apply), "tp-%s-apply.nft", revision);
        snprintf(leaf_roll, sizeof(leaf_roll), "tp-%s-rollback.nft", revision);
        if (flowd_nft_join(apply_path, apply_path_len, runtime_dir, leaf_apply) != 0 ||
            flowd_nft_join(rollback_path, rollback_path_len, runtime_dir, leaf_roll) != 0) {
            snprintf(err, err_len, "%s", "tp_nft_path_invalid");
            goto out;
        }
        if (flowd_nft_write_file(apply_path, apply.s ? apply.s : "") != 0 ||
            flowd_nft_write_file(rollback_path, rollback.s ? rollback.s : "") != 0) {
            snprintf(err, err_len, "%s", "tp_nft_write_failed");
            goto out;
        }
    }

    rc = 0;
out:
    if (blocks)
        sqlite3_finalize(blocks);
    if (tgt)
        sqlite3_finalize(tgt);
    if (pol)
        sqlite3_finalize(pol);
    sqlite3_close(db);
    free(apply.s);
    free(rollback.s);
    free(previous_nft);
    if (rc != 0)
        flowd_tp_nft_expect_free(expect);
    return rc;
}

int flowd_terminal_policy_executor_available(void)
{
    if (access(FLOWD_NFT_BINARY, X_OK) != 0)
        return 0;
    if (access(FLOWD_TERMINAL_POLICY_DB_PATH, R_OK) != 0)
        return 0;
    return 1;
}

/*
 * Drift reconciliation.
 *
 * Storage is the source of truth, but the dataplane can diverge from it without
 * anybody calling apply: the daemon restarts and inherits an older nft
 * generation, an apply is interrupted, or an outside writer flushes a table.
 * Before this existed, such a state simply persisted — the runtime readback
 * reported the mismatch honestly and nothing acted on it, so a rule the user had
 * saved was silently not in force.
 *
 * Returns 1 when an apply was performed and succeeded, 0 when the dataplane
 * already matched, and -1 when a needed apply failed.
 */
int flowd_terminal_policy_reconcile(const struct flowd_settings *settings,
                                    char *reason, size_t reason_len)
{
    struct json_object *runtime;
    struct json_object *flag = NULL;
    int consistent = 0;
    int rc;

    if (reason && reason_len)
        reason[0] = '\0';
    if (!settings || strcmp(settings->apply_mode, "managed"))
        return 0;
    if (!flowd_terminal_policy_executor_available())
        return 0;
    runtime = flowd_terminal_policy_runtime();
    if (!runtime)
        return -1;
    if (json_object_object_get_ex(runtime, "ok", &flag))
        consistent = json_object_get_boolean(flag);
    if (!consistent && reason && reason_len) {
        struct json_object *why = NULL;

        if (json_object_object_get_ex(runtime, "reason", &why) &&
            json_object_get_string(why))
            snprintf(reason, reason_len, "%s", json_object_get_string(why));
    }
    json_object_put(runtime);
    if (consistent)
        return 0;
    {
        struct json_object *applied = flowd_terminal_policy_apply(settings);
        int ok = 0;

        flag = NULL;
        if (applied) {
            if (json_object_object_get_ex(applied, "ok", &flag))
                ok = json_object_get_boolean(flag);
            if (!ok && reason && reason_len) {
                struct json_object *why = NULL;

                if (json_object_object_get_ex(applied, "reason", &why) &&
                    json_object_get_string(why))
                    snprintf(reason, reason_len, "%s",
                             json_object_get_string(why));
            }
            json_object_put(applied);
        }
        rc = ok ? 1 : -1;
    }
    return rc;
}

/*
 * Persist lifecycle transitions that are time/quota driven.  The write path
 * stores the rule; this scan is what turns scheduled -> active, active ->
 * blocked_time and blocked_quota after the accounting runtime crosses the
 * limit.  A changed row makes the next tick call the apply executor.
 */
int flowd_terminal_policy_lifecycle_scan(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    sqlite3_stmt *usage = NULL;
    sqlite3_stmt *blocked = NULL;
    int changed = 0;
    int row_rc;
    time_t now = time(NULL);

    if (sqlite3_open_v2(FLOWD_TERMINAL_POLICY_DB_PATH, &db,
                        SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    if (sqlite3_prepare_v2(db,
        "SELECT id,enabled,started_at,duration_count,deadline_at,quota_bytes,quota_mode,status "
        "FROM policies", -1, &st, NULL) != SQLITE_OK) {
        sqlite3_finalize(st);
        sqlite3_close(db);
        return -1;
    }
    while ((row_rc = sqlite3_step(st)) == SQLITE_ROW) {
        char id[128], status[32], next[32];
        int enabled = sqlite3_column_int(st, 1);
        int64_t started = sqlite3_column_int64(st, 2);
        int64_t dcount = sqlite3_column_int64(st, 3);
        int64_t deadline = sqlite3_column_int64(st, 4);
        int64_t quota = sqlite3_column_int64(st, 5);
        int64_t used = 0;
        int per_ip_blocked = 0;
        const char *quota_mode = (const char *)sqlite3_column_text(st, 6);
        const char *statusv = (const char *)sqlite3_column_text(st, 7);

        snprintf(id, sizeof(id), "%s", (const char *)sqlite3_column_text(st, 0));
        snprintf(status, sizeof(status), "%s", statusv ? statusv : "disabled");
        if (quota > 0 && quota_mode && strcmp(quota_mode, TP_QUOTA_PER_IP) != 0 && !usage) {
            if (sqlite3_prepare_v2(db,
                "SELECT used_bytes FROM quota_usage WHERE policy_id=?", -1,
                &usage, NULL) == SQLITE_OK)
                sqlite3_bind_text(usage, 1, id, -1, SQLITE_STATIC);
        }
        if (usage) {
            sqlite3_reset(usage);
            sqlite3_clear_bindings(usage);
            sqlite3_bind_text(usage, 1, id, -1, SQLITE_STATIC);
            if (sqlite3_step(usage) == SQLITE_ROW)
                used = sqlite3_column_int64(usage, 0);
        }
        /* Per-IP accounting records exhaustion in quota_blocks.  The
         * aggregate quota_usage row is intentionally only a display/checkpoint
         * sum, so using it as the lifecycle source would miss a single client
         * that crossed its own quota.  Query the block table per policy and
         * let the accounting runtime create those rows transactionally. */
        if (quota > 0 && quota_mode && !strcmp(quota_mode, TP_QUOTA_PER_IP)) {
            if (!blocked && sqlite3_prepare_v2(db,
                "SELECT 1 FROM quota_blocks WHERE policy_id=? LIMIT 1", -1,
                &blocked, NULL) == SQLITE_OK) {
                /* Statement is reused for each policy below. */
            }
            if (blocked) {
                sqlite3_reset(blocked);
                sqlite3_clear_bindings(blocked);
                sqlite3_bind_text(blocked, 1, id, -1, SQLITE_STATIC);
                per_ip_blocked = sqlite3_step(blocked) == SQLITE_ROW;
            }
        }
        if (!enabled) {
            snprintf(next, sizeof(next), "%s", TP_STATUS_DISABLED);
        } else if (started > (int64_t)now) {
            snprintf(next, sizeof(next), "%s", TP_STATUS_SCHEDULED);
        } else if (quota > 0 && quota_mode &&
                   ((!strcmp(quota_mode, TP_QUOTA_PER_IP) && per_ip_blocked) ||
                    (strcmp(quota_mode, TP_QUOTA_PER_IP) != 0 && used >= quota))) {
            snprintf(next, sizeof(next), "%s", TP_STATUS_BLOCKED_QUOTA);
        } else if (dcount > 0 && deadline > 0 && (int64_t)now >= deadline) {
            snprintf(next, sizeof(next), "%s", TP_STATUS_BLOCKED_TIME);
        } else {
            snprintf(next, sizeof(next), "%s", TP_STATUS_ACTIVE);
        }
        if (strcmp(next, status) != 0) {
            sqlite3_stmt *up = NULL;

            if (sqlite3_prepare_v2(db,
                "UPDATE policies SET status=?,last_transition_at=?,"
                "generation=generation+1,updated_at=? WHERE id=?", -1,
                &up, NULL) == SQLITE_OK) {
                sqlite3_bind_text(up, 1, next, -1, SQLITE_STATIC);
                sqlite3_bind_int64(up, 2, (sqlite3_int64)now);
                sqlite3_bind_int64(up, 3, (sqlite3_int64)now);
                sqlite3_bind_text(up, 4, id, -1, SQLITE_STATIC);
                if (sqlite3_step(up) == SQLITE_DONE)
                    changed++;
                sqlite3_finalize(up);
            }
        }
    }
    if (usage)
        sqlite3_finalize(usage);
    if (blocked)
        sqlite3_finalize(blocked);
    if (st)
        sqlite3_finalize(st);
    sqlite3_close(db);
    return row_rc == SQLITE_DONE ? changed : -1;
}

static struct json_object *flowd_tp_readback_json(const char *runtime_dir)
{
    struct json_object *obj = NULL;
    char leaf[192];
    char path[PATH_MAX];
    char *argv[7];
    int rc;

    if (!runtime_dir)
        return NULL;
    snprintf(leaf, sizeof(leaf), "tp-readback-command.log");
    if (flowd_nft_join(path, sizeof(path), runtime_dir, leaf) != 0)
        return NULL;
    argv[0] = (char *)FLOWD_NFT_BINARY;
    argv[1] = "-j";
    argv[2] = "list";
    argv[3] = "table";
    argv[4] = "inet";
    argv[5] = (char *)FLOWD_TP_NFT_TABLE;
    argv[6] = NULL;
    rc = flowd_nft_run(FLOWD_NFT_BINARY, argv, path);
    if (rc != 0)
        goto out;
    obj = flowd_nft_read_json_file(path);
    if (!obj)
        goto out;
out:
    return obj;
}

/*
 * Compares the rules the kernel currently carries against the rules the stored
 * policy set implies, rule by rule.  Reports the verdict plus the missing and
 * foreign counts into @out.  Returns 1 when the dataplane matches the store.
 */
static int flowd_tp_nft_verify(const char *runtime_dir,
                               struct json_object *readback,
                               struct json_object *out,
                               const char **reason_out)
{
    struct flowd_tp_nft_expect expected = { 0 };
    struct flowd_tp_nft_expect actual = { 0 };
    char revision[160];
    char err[256] = "";
    int readback_required = 0;
    size_t missing = 0;
    size_t foreign = 0;
    int match = 0;
    const char *reason = NULL;

    flowd_make_id("tpv", revision, sizeof(revision));
    if (flowd_tp_render_nft(runtime_dir, revision, NULL, 0, NULL, 0,
                            &readback_required, &expected, 1,
                            err, sizeof(err)) != 0) {
        reason = "terminal_policy_expectation_render_failed";
        goto done;
    }
    if (!readback_required) {
        /* No policy needs an nft rule.  A present table means stale state. */
        /* An empty table is still stale state.  The managed renderer emits a
         * destroy command when storage has no rules, so the only consistent
         * kernel state is an absent table, not an empty one. */
        if (readback)
            reason = "terminal_policy_nft_stale_rules";
        else
            match = 1;
        if (match)
            reason = "terminal_policy_nft_not_required";
        goto done;
    }
    if (!readback) {
        reason = "terminal_policy_nft_table_absent";
        goto done;
    }
    if (flowd_tp_nft_actual_from_json(readback, &actual) != 0) {
        reason = "terminal_policy_nft_readback_unparsable";
        goto done;
    }
    match = flowd_tp_nft_expect_equal(&expected, &actual, &missing, &foreign);
    if (!match)
        reason = "terminal_policy_nft_rule_mismatch";

done:
    if (out) {
        json_object_object_add(out, "nft_rules_expected",
                               json_object_new_int64((int64_t)expected.count));
        json_object_object_add(out, "nft_rules_present",
                               json_object_new_int64((int64_t)actual.count));
        json_object_object_add(out, "nft_rules_missing",
                               json_object_new_int64((int64_t)missing));
        json_object_object_add(out, "nft_rules_foreign",
                               json_object_new_int64((int64_t)foreign));
        json_object_object_add(out, "nft_readback_required",
                               json_object_new_boolean(readback_required));
        json_object_object_add(out, "nft_verified", json_object_new_boolean(match));
    }
    if (reason_out)
        *reason_out = reason;
    flowd_tp_nft_expect_free(&expected);
    flowd_tp_nft_expect_free(&actual);
    return match;
}

struct json_object *flowd_terminal_policy_runtime(void)
{
    struct flowd_settings settings;
    struct json_object *out = json_object_new_object();
    struct json_object *readback;
    const char *reason = NULL;
    int nft_ok;
    int tc_ok = 0;
    int ok = 0;

    if (!out)
        return NULL;
    json_object_object_add(out, "available", json_object_new_boolean(
        flowd_terminal_policy_executor_available()));
    if (flowd_settings_load(&settings) != 0)
        snprintf(settings.runtime_dir, sizeof(settings.runtime_dir),
                 "/tmp/dreamingwrt");
    readback = flowd_tp_readback_json(settings.runtime_dir);
    {
        struct json_object *tcr = flowd_terminal_policy_tc_runtime();
        struct json_object *tc_flag = NULL;

        if (tcr) {
            if (json_object_object_get_ex(tcr, "rate_rules_applied", &tc_flag))
                tc_ok = json_object_get_boolean(tc_flag);
            json_object_object_add(out, "tc", tcr);
        }
    }
    nft_ok = flowd_tp_nft_verify(settings.runtime_dir, readback, out, &reason);
    json_object_object_add(out, "table", json_object_new_string(FLOWD_TP_NFT_TABLE));
    if (readback)
        json_object_object_add(out, "readback", readback);
    {
        struct json_object *quota = flowd_terminal_quota_runtime_status();

        if (quota)
            json_object_object_add(out, "quota", quota);
    }
    ok = nft_ok && tc_ok;
    json_object_object_add(out, "runtime_applied", json_object_new_boolean(ok));
    if (!ok)
        json_object_object_add(out, "reason",
                               json_object_new_string(!nft_ok && reason ? reason :
                                   (!tc_ok ? "terminal_policy_tc_not_applied" :
                                             "terminal_policy_runtime_unverified")));
    else if (reason)
        json_object_object_add(out, "runtime_reason", json_object_new_string(reason));
    json_object_object_add(out, "ok", json_object_new_boolean(ok));
    return out;
}

struct json_object *flowd_terminal_policy_apply(const struct flowd_settings *settings)
{
    struct json_object *out = json_object_new_object();
    char runtime_dir[FLOWD_MAX_TEXT];
    char revision[160];
    char apply_path[PATH_MAX];
    char rollback_path[PATH_MAX];
    char err[256] = "";
    char output_path[PATH_MAX];
    char leaf[192];
    char *check_argv[6];
    char *apply_argv[4];
    char *rollback_argv[4];
    int lock_fd = -1;
    int readback_required = 0;
    struct flowd_tp_nft_expect expected = { 0 };
    int rc;

    if (!out)
        return NULL;
    apply_path[0] = '\0';
    rollback_path[0] = '\0';
    output_path[0] = '\0';
    json_object_object_add(out, "available", json_object_new_boolean(
        flowd_terminal_policy_executor_available()));
    if (!settings || strcmp(settings->apply_mode, "managed")) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string("flowd_apply_mode_disabled"));
        return out;
    }
    if (!flowd_terminal_policy_executor_available()) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string("terminal_policy_executor_unavailable"));
        return out;
    }
    snprintf(runtime_dir, sizeof(runtime_dir), "%s", settings->runtime_dir);
    /* Reconcile lifecycle transitions (scheduled->active, active->blocked_time/quota) */
    flowd_terminal_policy_lifecycle_scan();
    flowd_make_id("tp", revision, sizeof(revision));
    if (flowd_tp_render_nft(runtime_dir, revision, apply_path, sizeof(apply_path),
                            rollback_path, sizeof(rollback_path), &readback_required,
                            &expected, 0, err, sizeof(err)) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string(err[0] ? err : "terminal_policy_render_failed"));
        return out;
    }
    /* Defence in depth: never hand nft a path the renderer did not fill in. */
    if (apply_path[0] != '/' || rollback_path[0] != '/') {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string("terminal_policy_render_path_missing"));
        flowd_tp_nft_expect_free(&expected);
        return out;
    }
    snprintf(leaf, sizeof(leaf), "tp-apply.lock");
    if (flowd_nft_join(output_path, sizeof(output_path), runtime_dir, leaf) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string("terminal_policy_lock_path_invalid"));
        flowd_tp_nft_expect_free(&expected);
        return out;
    }
    lock_fd = open(output_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_fd < 0 || flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        if (lock_fd >= 0)
            close(lock_fd);
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string("terminal_policy_apply_busy"));
        flowd_tp_nft_expect_free(&expected);
        return out;
    }
    check_argv[0] = (char *)FLOWD_NFT_BINARY;
    check_argv[1] = "-c";
    check_argv[2] = "-f";
    check_argv[3] = apply_path;
    check_argv[4] = NULL;
    apply_argv[0] = (char *)FLOWD_NFT_BINARY;
    apply_argv[1] = "-f";
    apply_argv[2] = apply_path;
    apply_argv[3] = NULL;
    rollback_argv[0] = (char *)FLOWD_NFT_BINARY;
    rollback_argv[1] = "-f";
    rollback_argv[2] = rollback_path;
    rollback_argv[3] = NULL;

    snprintf(leaf, sizeof(leaf), "tp-%s-command.log", revision);
    if (flowd_nft_join(output_path, sizeof(output_path), runtime_dir, leaf) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string("terminal_policy_output_path_invalid"));
        goto out;
    }
    if (flowd_nft_run(FLOWD_NFT_BINARY, check_argv, output_path) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string("terminal_policy_isolated_validation_failed"));
        /* nft -c runs against the rendered file only.  It has not touched the
         * owned table or tc state, so callers must restore storage without
         * issuing another data-plane apply into the same failed executor. */
        json_object_object_add(out, "rollback_noop", json_object_new_boolean(1));
        json_object_object_add(out, "rollback_ok", json_object_new_boolean(1));
        json_object_object_add(out, "nft_rollback_ok", json_object_new_boolean(1));
        json_object_object_add(out, "tc_rollback_ok", json_object_new_boolean(1));
        goto out;
    }
    rc = flowd_nft_run(FLOWD_NFT_BINARY, apply_argv, output_path);
    if (rc == 0) {
        struct json_object *rb = readback_required ? flowd_tp_readback_json(runtime_dir) : NULL;
        struct json_object *tc_apply = flowd_terminal_policy_tc_apply(settings);
        struct json_object *tc_ok_obj = NULL;
        int tc_ok = tc_apply &&
                    json_object_object_get_ex(tc_apply, "ok", &tc_ok_obj) &&
                    json_object_get_boolean(tc_ok_obj);
        struct flowd_tp_nft_expect actual = { 0 };
        size_t missing = 0;
        size_t foreign = 0;
        int nft_ok = 0;
        int tc_verified = 0;

        if (tc_apply)
            json_object_object_add(out, "tc", tc_apply);
        json_object_object_add(out, "nft_readback_required",
                               json_object_new_boolean(readback_required));
        /* Rule-by-rule proof that the kernel carries what we rendered.  A
         * present table is not evidence: rules can be dropped, replaced by a
         * competing writer, or left over from an older generation. */
        if (!readback_required) {
            nft_ok = 1;
        } else if (rb && flowd_tp_nft_actual_from_json(rb, &actual) == 0) {
            nft_ok = flowd_tp_nft_expect_equal(&expected, &actual,
                                               &missing, &foreign);
        }
        json_object_object_add(out, "nft_rules_expected",
                               json_object_new_int64((int64_t)expected.count));
        json_object_object_add(out, "nft_rules_present",
                               json_object_new_int64((int64_t)actual.count));
        json_object_object_add(out, "nft_rules_missing",
                               json_object_new_int64((int64_t)missing));
        json_object_object_add(out, "nft_rules_foreign",
                               json_object_new_int64((int64_t)foreign));
        json_object_object_add(out, "nft_verified", json_object_new_boolean(nft_ok));
        flowd_tp_nft_expect_free(&actual);
        /* tc commands returning 0 is not proof either; re-read the classes,
         * filters and ingress redirects that the rules imply. */
        if (tc_ok) {
            struct json_object *tcr = flowd_terminal_policy_tc_runtime();
            struct json_object *flag = NULL;

            if (tcr) {
                tc_verified = json_object_object_get_ex(tcr, "rate_rules_applied", &flag) &&
                              json_object_get_boolean(flag);
                json_object_object_add(out, "tc_readback", tcr);
            }
        }
        json_object_object_add(out, "tc_verified", json_object_new_boolean(tc_verified));
        if (nft_ok && tc_ok && tc_verified) {
            json_object_object_add(out, "ok", json_object_new_boolean(1));
            json_object_object_add(out, "runtime_applied", json_object_new_boolean(1));
            if (rb)
                json_object_object_add(out, "readback", rb);
            if (!readback_required)
                json_object_object_add(out, "runtime_reason",
                                       json_object_new_string("tc_applied_nft_not_required"));
            goto out;
        }
        if (rb)
            json_object_put(rb);
        rc = -1;
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason",
                               json_object_new_string(!tc_ok ?
                                   "terminal_policy_tc_apply_failed" :
                                   (!tc_verified ?
                                        "terminal_policy_tc_readback_mismatch" :
                                        "terminal_policy_nft_readback_mismatch")));
        {
            int nft_rb = flowd_nft_run(FLOWD_NFT_BINARY, rollback_argv, output_path) == 0;
            int tc_rb = flowd_terminal_policy_tc_restore_previous() == 0;
            json_object_object_add(out, "rollback_ok",
                                   json_object_new_boolean(nft_rb && tc_rb));
            json_object_object_add(out, "nft_rollback_ok",
                                   json_object_new_boolean(nft_rb));
            json_object_object_add(out, "tc_rollback_ok",
                                   json_object_new_boolean(tc_rb));
        }
        goto out;
    }
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "reason",
                           json_object_new_string(rc != 0 ? "terminal_policy_apply_failed"
                                                            : "terminal_policy_readback_failed"));
    {
        int nft_rb = flowd_nft_run(FLOWD_NFT_BINARY, rollback_argv, output_path) == 0;
        int tc_rb = flowd_terminal_policy_tc_restore_previous() == 0;
        json_object_object_add(out, "rollback_ok",
                               json_object_new_boolean(nft_rb && tc_rb));
        json_object_object_add(out, "nft_rollback_ok", json_object_new_boolean(nft_rb));
        json_object_object_add(out, "tc_rollback_ok", json_object_new_boolean(tc_rb));
    }
out:
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
    flowd_tp_nft_expect_free(&expected);
    json_object_object_add(out, "revision", json_object_new_string(revision));
    json_object_object_add(out, "apply_path", json_object_new_string(apply_path));
    json_object_object_add(out, "rollback_path", json_object_new_string(rollback_path));
    return out;
}
