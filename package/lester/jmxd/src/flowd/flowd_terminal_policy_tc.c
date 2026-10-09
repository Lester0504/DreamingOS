// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_terminal_policy_tc.h"
#include "jmx_strbuf.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <dirent.h>
#include <sqlite3.h>
#include <json-c/json.h>

#define FLOWD_TP_TC_BINARY "/sbin/tc"
#define FLOWD_TP_TC_IP_BINARY "/sbin/ip"
#define FLOWD_TP_TC_UBUS_BINARY "/bin/ubus"
#define FLOWD_TP_TC_LAN "br-lan"
#define FLOWD_TP_TC_UPLOAD_IFB "ifb-tp-upload"
#define FLOWD_TP_TC_DB "/etc/dreamingwrt/terminal_policy.db"
#define FLOWD_TP_TC_ROOT_HANDLE "1:"
/*
 * `htb default 0` sends unclassified packets straight out through HTB's direct
 * queue, unshaped.  This matters: a terminal policy must only constrain the
 * addresses it targets.  An earlier shape used a catch-all fallback class,
 * which silently placed a ceiling on every other client on the bridge.
 */
#define FLOWD_TP_TC_HTB_DEFAULT "0"
#define FLOWD_TP_TC_MAX_RULES 256
#define FLOWD_TP_TC_MAX_WANS 16
#define FLOWD_TP_TC_OWNER_FILE "/var/run/dreamingwrt-terminal-policy-tc"
#define FLOWD_TP_TC_STATE_FILE "/var/run/dreamingwrt-terminal-policy-tc.state"
#define FLOWD_TP_TC_PREVIOUS_STATE_FILE "/var/run/dreamingwrt-terminal-policy-tc.previous"
/*
 * Intent marker.  Written immediately before the first dataplane mutation of an
 * apply and removed once the transaction has either committed or fully rolled
 * back.  Its presence at the start of an apply means the previous transaction
 * died in the middle (process killed, box lost power), so whatever htb root sits
 * on the bridge is ours to remove.  Without it an interrupted apply left an
 * orphan qdisc that no later apply was permitted to touch, and the executor
 * stayed wedged on tp_tc_lan_ownership_conflict until someone cleaned up by hand.
 */
#define FLOWD_TP_TC_INTENT_FILE "/var/run/dreamingwrt-terminal-policy-tc.intent"
#define FLOWD_TP_TC_UPLOAD_PREF "47999"
#define FLOWD_TP_TC_UPLOAD_INGRESS_OWNER_FILE "/var/run/dreamingwrt-terminal-policy-tc.upload-ingress"
#define FLOWD_TP_TC_DOWNLOAD_EGRESS_PREF_BASE 47800U
#define FLOWD_TP_TC_DOWNLOAD_EGRESS_PREF_SPAN 100U
static int g_tp_tc_owned;

struct flowd_tp_tc_capture {
    char *data;
    size_t len;
};

static int flowd_tp_tc_token_ok(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s || !s[0] || strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == ':' || *p == '/'))
            return 0;
    }
    return 1;
}

static int flowd_tp_tc_capture_append(struct flowd_tp_tc_capture *capture,
                                     const char *data, size_t len)
{
    size_t keep = len;
    size_t max = 1024U * 512U;
    char *next;

    if (!capture || !data || !len)
        return 0;
    if (capture->len >= max)
        return -1;
    if (keep > max - capture->len)
        keep = max - capture->len;
    next = realloc(capture->data, capture->len + keep + 1);
    if (!next)
        return -1;
    memcpy(next + capture->len, data, keep);
    capture->len += keep;
    next[capture->len] = '\0';
    capture->data = next;
    return keep == len ? 0 : -1;
}

static int flowd_tp_tc_run(char *const argv[], struct flowd_tp_tc_capture *capture)
{
    int pipefd[2] = { -1, -1 };
    pid_t pid;
    int status = 0;
    int done = 0;
    int64_t deadline;
    struct pollfd pfd;
    char buf[4096];

    if (!argv || !argv[0] || !capture)
        return -1;
    memset(capture, 0, sizeof(*capture));
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0 || pipe(pipefd) != 0)
        return -1;
    deadline = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + 5000;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(126);
        close(pipefd[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);
    pfd.fd = pipefd[0];
    pfd.events = POLLIN | POLLHUP;
    while (!done) {
        ssize_t n;
        int64_t now;
        pid_t wait_rc;

        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
            if (flowd_tp_tc_capture_append(capture, buf, (size_t)n) != 0) {
                kill(pid, SIGTERM);
                waitpid(pid, &status, 0);
                close(pipefd[0]);
                free(capture->data);
                capture->data = NULL;
                capture->len = 0;
                return -2;
            }
        }
        wait_rc = waitpid(pid, &status, WNOHANG);
        if (wait_rc == pid)
            done = 1;
        else if (wait_rc < 0 && errno != EINTR) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
            close(pipefd[0]);
            free(capture->data);
            capture->data = NULL;
            capture->len = 0;
            return -1;
        }
        now = -1;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
            now = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        if (!done && (now < 0 || now >= deadline)) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
            close(pipefd[0]);
            free(capture->data);
            capture->data = NULL;
            capture->len = 0;
            return -3;
        }
        if (!done)
            poll(&pfd, 1, 20);
    }
    while (read(pipefd[0], buf, sizeof(buf)) > 0)
        ;
    close(pipefd[0]);
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int flowd_tp_tc_cmd(char *const argv[])
{
    struct flowd_tp_tc_capture capture;
    int rc = flowd_tp_tc_run(argv, &capture);

    free(capture.data);
    return rc;
}

static struct json_object *flowd_tp_tc_json_cmd(char *const argv[])
{
    struct flowd_tp_tc_capture capture;
    struct json_object *obj = NULL;

    if (flowd_tp_tc_run(argv, &capture) != 0)
        return NULL;
    obj = json_tokener_parse(capture.data ? capture.data : "");
    free(capture.data);
    return obj;
}

static int flowd_tp_tc_qdisc_kind(const char *ifname, char *kind, size_t kind_len)
{
    char *argv[] = { (char *)FLOWD_TP_TC_BINARY, "-j", "qdisc", "show", "dev",
                     (char *)ifname, NULL };
    struct flowd_tp_tc_capture capture;
    struct json_object *root = NULL, *items = NULL, *entry = NULL, *value = NULL;
    int rc, ok = 0;

    rc = flowd_tp_tc_run(argv, &capture);
    if (rc != 0)
        goto out;
    root = json_tokener_parse(capture.data);
    if (!root)
        goto out;
    if (json_object_is_type(root, json_type_array)) {
        items = root;
    } else if (!json_object_object_get_ex(root, "qdisc", &items) ||
               !json_object_is_type(items, json_type_array)) {
        goto out;
    }
    for (size_t i = 0; i < json_object_array_length(items); i++) {
        entry = json_object_array_get_idx(items, i);
        if (!entry || !json_object_object_get_ex(entry, "root", &value) ||
            !json_object_get_boolean(value))
            continue;
        if (!json_object_object_get_ex(entry, "kind", &value))
            continue;
        snprintf(kind, kind_len, "%s", json_object_get_string(value));
        ok = 1;
        break;
    }
out:
    if (root)
        json_object_put(root);
    free(capture.data);
    return ok ? 0 : -1;
}

/* Extent of flowd_tp_tc_rule.addr. The on-disk parser validates against this
 * rather than against its own scratch buffer: a token longer than the rule
 * field would be truncated on the way in, and the shortened text then fails
 * inet_pton at apply time, dropping the rule with no explanation. */
#define FLOWD_TP_TC_ADDR_LEN 64

struct flowd_tp_tc_rule {
    unsigned int classid;
    int family;
    char addr[FLOWD_TP_TC_ADDR_LEN];
    int plen;
    unsigned int rate_kbps;
};

static int flowd_tp_tc_rule_add(struct flowd_tp_tc_rule *rules, unsigned int *count,
                                int family, const char *addr, int plen, int rate_kbps,
                                unsigned int classid)
{
    unsigned int i;

    if (!rules || !count || !addr || *count >= FLOWD_TP_TC_MAX_RULES)
        return -1;
    for (i = 0; i < *count; i++) {
        if (rules[i].family == family && rules[i].plen == plen &&
            !strcmp(rules[i].addr, addr))
            return rules[i].rate_kbps == (unsigned int)rate_kbps ? 0 : -2;
    }
    if (!flowd_tp_tc_token_ok(addr, 64) || plen < 0 || plen > 128 || rate_kbps <= 0)
        return -1;
    memset(&rules[*count], 0, sizeof(rules[*count]));
    rules[*count].classid = classid ? classid : 100 + (*count % 8000U);
    rules[*count].family = family;
    rules[*count].plen = plen;
    rules[*count].rate_kbps = (unsigned int)rate_kbps;
    snprintf(rules[*count].addr, sizeof(rules[*count].addr), "%s", addr);
    (*count)++;
    return 0;
}

static int flowd_tp_tc_rules_load(struct flowd_tp_tc_rule *up_rules, unsigned int *up_count,
                                   struct flowd_tp_tc_rule *down_rules, unsigned int *down_count)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *pol = NULL, *tgt = NULL;
    int rc = -1;
    int row_rc;
    /* Per-IP classes occupy the low range; shared-policy classes get a
     * stable, separate range so a shared class never collides with an
     * unrelated host rule.  The class id is persisted in the tc state file. */
    unsigned int next_up_classid = 4000;
    unsigned int next_down_classid = 4000;

    if (!up_rules || !up_count || !down_rules || !down_count ||
        sqlite3_open_v2(FLOWD_TP_TC_DB, &db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
        goto out;
    if (sqlite3_prepare_v2(db,
        "SELECT id,enabled,rate_upload_kbps,rate_download_kbps,rate_mode,status FROM policies WHERE enabled=1",
        -1, &pol, NULL) != SQLITE_OK)
        goto out;
    while ((row_rc = sqlite3_step(pol)) == SQLITE_ROW) {
        char id[128], status[32];
        const unsigned char *idv = sqlite3_column_text(pol, 0);
        const unsigned char *modev = sqlite3_column_text(pol, 4);
        const unsigned char *statusv = sqlite3_column_text(pol, 5);
        int up_kbps = sqlite3_column_int(pol, 2);
        int down_kbps = sqlite3_column_int(pol, 3);
        int enabled = sqlite3_column_int(pol, 1);

        if (!enabled || (up_kbps <= 0 && down_kbps <= 0))
            continue;
        int shared_rate = modev && !strcmp((const char *)modev, "shared");
        unsigned int up_classid = 0;
        unsigned int down_classid = 0;

        if (modev && strcmp((const char *)modev, "per_ip") != 0 &&
            strcmp((const char *)modev, "shared") != 0) {
            rc = -4;
            goto out;
        }
        if (up_kbps > 0)
            up_classid = shared_rate ? next_up_classid++ : 0;
        if (down_kbps > 0)
            down_classid = shared_rate ? next_down_classid++ : 0;
        if (!idv)
            continue;
        snprintf(id, sizeof(id), "%s", (const char *)idv);
        memset(status, 0, sizeof(status));
        if (statusv)
            snprintf(status, sizeof(status), "%s", (const char *)statusv);
        if (status[0] && strcmp(status, "active") != 0)
            continue;
        if (tgt)
            sqlite3_finalize(tgt);
        tgt = NULL;
        if (sqlite3_prepare_v2(db,
            "SELECT family,prefix,prefix_len FROM targets WHERE policy_id=? ORDER BY family,prefix",
            -1, &tgt, NULL) != SQLITE_OK)
            goto out;
        sqlite3_bind_text(tgt, 1, id, -1, SQLITE_STATIC);
        while (sqlite3_step(tgt) == SQLITE_ROW) {
            int family = sqlite3_column_int(tgt, 0);
            int plen = sqlite3_column_int(tgt, 2);
            const unsigned char *prefix = sqlite3_column_text(tgt, 1);

            if (!prefix || !prefix[0] || plen <= 0 ||
                (family == 4 && plen > 32) || (family == 6 && plen > 128) ||
                (family != 4 && family != 6))
                continue;
            /* The only advertised rate mode is strict per-IP.  A legacy row
             * carrying a prefix must fail closed instead of silently turning
             * one client's class into a shared subnet class. */
            if ((up_kbps > 0 || down_kbps > 0) && !shared_rate &&
                ((family == 4 && plen != 32) || (family == 6 && plen != 128))) {
                rc = -5;
                goto out;
            }
            if (up_kbps > 0 && flowd_tp_tc_rule_add(up_rules, up_count, family,
                                     (const char *)prefix, plen, up_kbps,
                                     up_classid) != 0) {
                rc = -2;
                goto out;
            }
            if (down_kbps > 0 && flowd_tp_tc_rule_add(down_rules, down_count, family,
                                     (const char *)prefix, plen, down_kbps,
                                     down_classid) != 0) {
                rc = -2;
                goto out;
            }
        }
    }
    rc = row_rc == SQLITE_DONE ? 0 : -3;
out:
    if (tgt)
        sqlite3_finalize(tgt);
    if (pol)
        sqlite3_finalize(pol);
    if (db)
        sqlite3_close(db);
    return rc;
}

static void flowd_tp_tc_owner_refresh(void)
{
    g_tp_tc_owned = access(FLOWD_TP_TC_OWNER_FILE, R_OK) == 0;
}

static int flowd_tp_tc_intent_set(void)
{
    int fd = open(FLOWD_TP_TC_INTENT_FILE,
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    if (fd < 0)
        return -1;
    return close(fd) == 0 ? 0 : -1;
}

static void flowd_tp_tc_intent_clear(void)
{
    unlink(FLOWD_TP_TC_INTENT_FILE);
}

static int flowd_tp_tc_intent_pending(void)
{
    return access(FLOWD_TP_TC_INTENT_FILE, F_OK) == 0;
}

static int flowd_tp_tc_apply_rules(const char *dev,
                                   const struct flowd_tp_tc_rule *rules,
                                   unsigned int count, const char *match_key)
{
    char rate[32];
    char classid[32];
    unsigned int i;
    int rc;

    char *qdisc[] = { (char *)FLOWD_TP_TC_BINARY, "qdisc", "replace", "dev",
                      (char *)dev, "root", "handle", "1:",
                      "htb", "default", (char *)FLOWD_TP_TC_HTB_DEFAULT, NULL };

    if (!dev || !match_key || (strcmp(match_key, "src") && strcmp(match_key, "dst")))
        return -1;
    rc = flowd_tp_tc_cmd(qdisc);
    if (rc != 0)
        return -1;
    memset(classid, 0, sizeof(classid));
    for (i = 0; i < count; i++) {
        snprintf(classid, sizeof(classid), "1:%u", rules[i].classid);
        snprintf(rate, sizeof(rate), "%ukbit", rules[i].rate_kbps);
        {
            char *cls[] = { (char *)FLOWD_TP_TC_BINARY, "class", "replace", "dev",
                            (char *)dev, "parent", "1:", "classid", classid,
                            "htb", "rate", rate, "ceil", rate, NULL };
            if (flowd_tp_tc_cmd(cls) != 0)
                return -1;
        }
        {
            char match[160];
            char pref[16];
            const char *protocol = rules[i].family == 6 ? "ipv6" : "ip";
            const char *match_proto = rules[i].family == 6 ? "ip6" : "ip";
            snprintf(match, sizeof(match), "%s/%d", rules[i].addr, rules[i].plen);
            snprintf(pref, sizeof(pref), "%u", 10U + i);
            char *flt[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "replace", "dev",
                            (char *)dev, "parent", "1:", "protocol", (char *)protocol,
                            "pref", pref, "u32", "match", (char *)match_proto,
                            (char *)match_key, match, "flowid", classid, NULL };
            if (flowd_tp_tc_cmd(flt) != 0)
                return -1;
        }
    }
    return 0;
}


struct flowd_tp_tc_wan {
    char wan[IFNAMSIZ];
    char ifb[32];
    char lan_dev[IFNAMSIZ];
    int legacy_ingress;
};

struct flowd_tp_tc_state {
    struct flowd_tp_tc_rule upload[FLOWD_TP_TC_MAX_RULES];
    struct flowd_tp_tc_rule download[FLOWD_TP_TC_MAX_RULES];
    unsigned int upload_count;
    unsigned int download_count;
    char upload_ifb[IFNAMSIZ];
    struct flowd_tp_tc_wan wans[FLOWD_TP_TC_MAX_WANS];
    size_t wan_count;
};

static int flowd_tp_tc_ifname_ok(const char *name);
static int flowd_tp_tc_ifb_name(const char *wan, char *out, size_t out_len);
static void flowd_tp_tc_down_clear(const struct flowd_tp_tc_wan *wans, size_t count);
static void flowd_tp_tc_clear_all_down(void);
static int flowd_tp_tc_ingress_pref(const char *wan, char *out, size_t out_len);
static int flowd_tp_tc_download_egress_pref(const char *dev, char *out, size_t out_len);
static int flowd_tp_tc_discover_lan_ports(struct flowd_tp_tc_wan *wans, size_t *count);
static int flowd_tp_tc_upload_prepare(void);
static void flowd_tp_tc_upload_clear(void);
static int flowd_tp_tc_upload_cleanup_orphan(void);
static int flowd_tp_tc_verify_upload_ingress(struct json_object *report);

/* ---------------------------------------------------------------------------
 * Rule-by-rule tc readback.
 *
 * Ownership flags and "the root qdisc is htb" prove nothing about whether the
 * individual per-client classes and u32 filters survived.  The verifier below
 * derives the exact htb class rate and the exact u32 match words each rule
 * implies, then compares them against what the kernel reports.  Offsets and
 * output shapes were taken from live `tc` output (iproute2-6.18) rather than
 * assumed:
 *   ipv4 src @12, ipv4 dst @16, ipv6 src @8..20, ipv6 dst @24..36
 *   `tc -j class show` reports htb rate/ceil in bytes per second
 * u32 match words are read from the text form on purpose: a filter carries
 * several "match" keys inside one options object, and JSON object parsing
 * collapses repeated keys so only the last word would survive.
 * ------------------------------------------------------------------------- */

struct flowd_tp_tc_fp {
    char **items;
    size_t count;
    size_t cap;
};

static void flowd_tp_tc_fp_free(struct flowd_tp_tc_fp *set)
{
    size_t i;

    if (!set)
        return;
    for (i = 0; i < set->count; i++)
        free(set->items[i]);
    free(set->items);
    memset(set, 0, sizeof(*set));
}

static int flowd_tp_tc_fp_add(struct flowd_tp_tc_fp *set, const char *item)
{
    char *copy;

    if (!set || !item)
        return -1;
    if (set->count >= 4096U)
        return -1;
    if (set->count == set->cap) {
        size_t new_cap = set->cap ? set->cap * 2 : 32;
        char **grown = realloc(set->items, new_cap * sizeof(*grown));

        if (!grown)
            return -1;
        set->items = grown;
        set->cap = new_cap;
    }
    copy = strdup(item);
    if (!copy)
        return -1;
    set->items[set->count++] = copy;
    return 0;
}

static int flowd_tp_tc_fp_has(const struct flowd_tp_tc_fp *set, const char *item)
{
    size_t i;

    if (!set || !item)
        return 0;
    for (i = 0; i < set->count; i++)
        if (!strcmp(set->items[i], item))
            return 1;
    return 0;
}

static int flowd_tp_tc_fp_equal(const struct flowd_tp_tc_fp *expected,
                                const struct flowd_tp_tc_fp *actual,
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
        if (!flowd_tp_tc_fp_has(actual, expected->items[i]))
            miss++;
    for (i = 0; i < actual->count; i++)
        if (!flowd_tp_tc_fp_has(expected, actual->items[i]))
            extra++;
    if (missing)
        *missing = miss;
    if (foreign)
        *foreign = extra;
    return miss == 0 && extra == 0 && expected->count == actual->count;
}

/* Expected u32 match words for one rule, as "off:hexvalue" tokens. */
static int flowd_tp_tc_expect_filter(struct flowd_tp_tc_fp *set,
                                     const struct flowd_tp_tc_rule *rule,
                                     unsigned int pref, const char *match_key)
{
    char item[256];
    char words[160];
    size_t used = 0;
    int base;

    if (!set || !rule || !match_key)
        return -1;
    words[0] = '\0';
    if (rule->family == 4) {
        struct in_addr a4;

        if (inet_pton(AF_INET, rule->addr, &a4) != 1)
            return -1;
        base = !strcmp(match_key, "src") ? 12 : 16;
        if (snprintf(words, sizeof(words), "%d:%08x", base,
                     (unsigned int)ntohl(a4.s_addr)) >= (int)sizeof(words))
            return -1;
    } else if (rule->family == 6) {
        struct in6_addr a6;
        int i;

        if (inet_pton(AF_INET6, rule->addr, &a6) != 1)
            return -1;
        base = !strcmp(match_key, "src") ? 8 : 24;
        for (i = 0; i < 4; i++) {
            unsigned int word = ((unsigned int)a6.s6_addr[i * 4] << 24) |
                                ((unsigned int)a6.s6_addr[i * 4 + 1] << 16) |
                                ((unsigned int)a6.s6_addr[i * 4 + 2] << 8) |
                                (unsigned int)a6.s6_addr[i * 4 + 3];
            int n = snprintf(words + used, sizeof(words) - used, "%s%d:%08x",
                             used ? "," : "", base + i * 4, word);

            if (n < 0 || (size_t)n >= sizeof(words) - used)
                return -1;
            used += (size_t)n;
        }
    } else {
        return -1;
    }
    if (snprintf(item, sizeof(item), "%s|%u|1:%u|%s",
                 rule->family == 6 ? "ipv6" : "ip", pref, rule->classid,
                 words) >= (int)sizeof(item))
        return -1;
    return flowd_tp_tc_fp_add(set, item);
}

/* Parses `tc filter show` text into the same fingerprint form. */
static int flowd_tp_tc_actual_filters(const char *dev, const char *parent,
                                     struct flowd_tp_tc_fp *set)
{
    char *argv[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "show", "dev",
                     (char *)dev, "parent", (char *)parent, NULL };
    struct flowd_tp_tc_capture capture;
    char proto[16] = "";
    char flowid[32] = "";
    char words[160] = "";
    unsigned int pref = 0;
    int have_leaf = 0;
    char *line;
    char *save = NULL;
    int rc = -1;

    if (!dev || !parent || !set)
        return -1;
    memset(set, 0, sizeof(*set));
    if (flowd_tp_tc_run(argv, &capture) != 0) {
        free(capture.data);
        return -1;
    }
    if (!capture.data) {
        free(capture.data);
        return 0;
    }
    for (line = strtok_r(capture.data, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char p[16];
        unsigned int pv;
        char fid[32];
        unsigned int off;
        char value[32];
        char mask[32];

        if ((line[0] == ' ' || line[0] == '\t') &&
            sscanf(line, " match %31[0-9a-fA-F]/%31[0-9a-fA-F] at %u",
                   value, mask, &off) == 3) {
            unsigned long v = strtoul(value, NULL, 16);
            size_t used = strlen(words);
            int n;

            if (!have_leaf)
                continue;
            n = snprintf(words + used, sizeof(words) - used, "%s%u:%08lx",
                         used ? "," : "", off, v);
            if (n < 0 || (size_t)n >= sizeof(words) - used)
                goto out;
            continue;
        }
        if (strncmp(line, "filter ", 7))
            continue;
        if (have_leaf) {
            char item[256];

            if (snprintf(item, sizeof(item), "%s|%u|%s|%s", proto, pref,
                         flowid, words) >= (int)sizeof(item) ||
                flowd_tp_tc_fp_add(set, item) != 0)
                goto out;
            have_leaf = 0;
        }
        words[0] = '\0';
        if (sscanf(line, "filter protocol %15s pref %u", p, &pv) != 2)
            continue;
        {
            const char *fp = strstr(line, "flowid ");

            if (!fp || sscanf(fp, "flowid %31s", fid) != 1)
                continue;
        }
        snprintf(proto, sizeof(proto), "%s", p);
        snprintf(flowid, sizeof(flowid), "%s", fid);
        pref = pv;
        have_leaf = 1;
    }
    if (have_leaf) {
        char item[256];

        if (snprintf(item, sizeof(item), "%s|%u|%s|%s", proto, pref, flowid,
                     words) >= (int)sizeof(item) ||
            flowd_tp_tc_fp_add(set, item) != 0)
            goto out;
    }
    rc = 0;
out:
    free(capture.data);
    if (rc != 0)
        flowd_tp_tc_fp_free(set);
    return rc;
}

/* htb class rate/ceil readback.  kbit -> bytes/s is exact (1 kbit = 125 B/s),
 * but a small tolerance absorbs kernel rate-table rounding. */
static int flowd_tp_tc_class_rate_ok(struct json_object *classes,
                                     unsigned int classid,
                                     unsigned int rate_kbps)
{
    int64_t want = (int64_t)rate_kbps * 125;
    int64_t tol = want / 100 + 1;
    char handle[32];
    size_t i;

    if (!classes || !json_object_is_type(classes, json_type_array))
        return 0;
    snprintf(handle, sizeof(handle), "1:%u", classid);
    for (i = 0; i < json_object_array_length(classes); i++) {
        struct json_object *entry = json_object_array_get_idx(classes, i);
        struct json_object *v = NULL;
        const char *h;
        int64_t rate;
        int64_t ceil;

        if (!entry || !json_object_object_get_ex(entry, "handle", &v))
            continue;
        h = json_object_get_string(v);
        if (!h || strcmp(h, handle))
            continue;
        if (!json_object_object_get_ex(entry, "rate", &v))
            return 0;
        rate = json_object_get_int64(v);
        ceil = rate;
        if (json_object_object_get_ex(entry, "ceil", &v))
            ceil = json_object_get_int64(v);
        if (rate < want - tol || rate > want + tol)
            return 0;
        if (ceil < want - tol || ceil > want + tol)
            return 0;
        return 1;
    }
    return 0;
}

/* Confirms the root htb qdisc leaves unclassified traffic unshaped, so a
 * policy cannot accidentally cap clients it does not target. */
static int flowd_tp_tc_htb_default_direct(const char *dev)
{
    char *argv[] = { (char *)FLOWD_TP_TC_BINARY, "-j", "qdisc", "show", "dev",
                     (char *)dev, NULL };
    struct json_object *root = NULL;
    struct json_object *items = NULL;
    int ok = 0;
    size_t i;

    if (!dev)
        return 0;
    root = flowd_tp_tc_json_cmd(argv);
    if (!root)
        return 0;
    items = json_object_is_type(root, json_type_array) ? root : NULL;
    if (!items && (!json_object_object_get_ex(root, "qdisc", &items) ||
                   !json_object_is_type(items, json_type_array)))
        goto out;
    for (i = 0; i < json_object_array_length(items); i++) {
        struct json_object *entry = json_object_array_get_idx(items, i);
        struct json_object *v = NULL;
        struct json_object *opts = NULL;
        const char *def;

        if (!entry || !json_object_object_get_ex(entry, "root", &v) ||
            !json_object_get_boolean(v))
            continue;
        if (!json_object_object_get_ex(entry, "options", &opts) ||
            !json_object_object_get_ex(opts, "default", &v))
            break;
        def = json_object_get_string(v);
        /* iproute2 prints the default classid as hex text, e.g. "0" / "0x0". */
        if (def && (!strcmp(def, "0") || !strcmp(def, "0x0")))
            ok = 1;
        break;
    }
out:
    json_object_put(root);
    return ok;
}

/*
 * Verifies one device carries exactly the classes and filters @rules imply.
 * Writes the per-device verdict into @report and returns 1 on a full match.
 */
static int flowd_tp_tc_verify_dev(const char *dev,
                                  const struct flowd_tp_tc_rule *rules,
                                  unsigned int count, const char *match_key,
                                  struct json_object *report)
{
    struct flowd_tp_tc_fp expected = { 0 };
    struct flowd_tp_tc_fp actual = { 0 };
    struct json_object *classes = NULL;
    char kind[32] = "";
    size_t missing = 0;
    size_t foreign = 0;
    unsigned int class_bad = 0;
    unsigned int i;
    int filters_ok = 0;
    int ok = 0;
    const char *reason = NULL;

    if (!dev || !rules || !match_key)
        return 0;
    if (flowd_tp_tc_qdisc_kind(dev, kind, sizeof(kind)) != 0 ||
        strcmp(kind, "htb")) {
        reason = "root_qdisc_not_htb";
        goto done;
    }
    {
        char *cargv[] = { (char *)FLOWD_TP_TC_BINARY, "-j", "class", "show",
                          "dev", (char *)dev, NULL };
        classes = flowd_tp_tc_json_cmd(cargv);
    }
    if (!classes) {
        reason = "class_readback_failed";
        goto done;
    }
    if (!flowd_tp_tc_htb_default_direct(dev)) {
        reason = "htb_default_not_direct";
        goto done;
    }
    for (i = 0; i < count; i++) {
        if (!flowd_tp_tc_class_rate_ok(classes, rules[i].classid,
                                       rules[i].rate_kbps))
            class_bad++;
        if (flowd_tp_tc_expect_filter(&expected, &rules[i], 10U + i,
                                      match_key) != 0) {
            reason = "expectation_build_failed";
            goto done;
        }
    }
    if (class_bad) {
        reason = "class_rate_mismatch";
        goto done;
    }
    if (flowd_tp_tc_actual_filters(dev, FLOWD_TP_TC_ROOT_HANDLE, &actual) != 0) {
        reason = "filter_readback_failed";
        goto done;
    }
    filters_ok = flowd_tp_tc_fp_equal(&expected, &actual, &missing, &foreign);
    if (!filters_ok) {
        reason = "filter_mismatch";
        goto done;
    }
    ok = 1;
done:
    if (report) {
        json_object_object_add(report, "dev", json_object_new_string(dev));
        json_object_object_add(report, "qdisc", json_object_new_string(kind));
        json_object_object_add(report, "filters_expected",
                               json_object_new_int64((int64_t)expected.count));
        json_object_object_add(report, "filters_present",
                               json_object_new_int64((int64_t)actual.count));
        json_object_object_add(report, "filters_missing",
                               json_object_new_int64((int64_t)missing));
        json_object_object_add(report, "filters_foreign",
                               json_object_new_int64((int64_t)foreign));
        json_object_object_add(report, "class_rate_mismatch",
                               json_object_new_int64((int64_t)class_bad));
        json_object_object_add(report, "verified", json_object_new_boolean(ok));
        if (!ok && reason)
            json_object_object_add(report, "reason",
                                   json_object_new_string(reason));
    }
    if (classes)
        json_object_put(classes);
    flowd_tp_tc_fp_free(&expected);
    flowd_tp_tc_fp_free(&actual);
    return ok;
}

/* Download shaping is attached to the bridge port egress.  By this point DNAT
 * has already restored the terminal destination, so the IFB u32 rule can match
 * the actual client address. */
static int flowd_tp_tc_verify_download_egress(const struct flowd_tp_tc_wan *w,
                                              struct json_object *report)
{
    char *argv[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "show", "dev",
                     NULL, "egress", NULL };
    struct flowd_tp_tc_capture capture;
    char pref[16];
    char needle[64];
    int ok = 0;

    if (!w || w->legacy_ingress || !w->lan_dev[0] || !w->ifb[0])
        return 0;
    if (flowd_tp_tc_download_egress_pref(w->lan_dev, pref, sizeof(pref)) != 0)
        return 0;
    argv[4] = (char *)w->lan_dev;
    if (flowd_tp_tc_run(argv, &capture) != 0) {
        free(capture.data);
        if (report)
            json_object_object_add(report, "egress_reason",
                                   json_object_new_string("egress_readback_failed"));
        return 0;
    }
    snprintf(needle, sizeof(needle), "pref %s matchall", pref);
    if (capture.data && strstr(capture.data, needle)) {
        const char *dev_hit = strstr(capture.data, w->ifb);

        ok = dev_hit != NULL;
    }
    free(capture.data);
    if (report) {
        json_object_object_add(report, "egress_dev",
                               json_object_new_string(w->lan_dev));
        json_object_object_add(report, "egress_pref",
                               json_object_new_string(pref));
        json_object_object_add(report, "egress_verified",
                               json_object_new_boolean(ok));
        if (!ok)
            json_object_object_add(report, "egress_reason",
                                   json_object_new_string("egress_redirect_absent"));
    }
    return ok;
}

static int flowd_tp_tc_verify_upload_ingress(struct json_object *report)
{
    char *argv[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "show", "dev",
                     (char *)FLOWD_TP_TC_LAN, "parent", "ffff:", NULL };
    struct flowd_tp_tc_capture capture;
    char needle[96];
    int ok = 0;

    if (flowd_tp_tc_run(argv, &capture) != 0) {
        free(capture.data);
        if (report)
            json_object_object_add(report, "upload_ingress_reason",
                                   json_object_new_string("upload_ingress_readback_failed"));
        return 0;
    }
    snprintf(needle, sizeof(needle), "pref %s matchall", FLOWD_TP_TC_UPLOAD_PREF);
    if (capture.data && strstr(capture.data, needle) &&
        strstr(capture.data, FLOWD_TP_TC_UPLOAD_IFB))
        ok = 1;
    free(capture.data);
    if (report) {
        json_object_object_add(report, "upload_ingress_pref",
                               json_object_new_string(FLOWD_TP_TC_UPLOAD_PREF));
        json_object_object_add(report, "upload_ingress_verified",
                               json_object_new_boolean(ok));
        if (!ok)
            json_object_object_add(report, "upload_ingress_reason",
                                   json_object_new_string("upload_redirect_absent"));
    }
    return ok;
}

static int flowd_tp_tc_ifname_ok(const char *name)
{
    size_t i;

    if (!name || !name[0] || strlen(name) >= IFNAMSIZ ||
        !strcmp(name, FLOWD_TP_TC_LAN) || !strcmp(name, "lo"))
        return 0;
    for (i = 0; name[i]; i++)
        if (!(isalnum((unsigned char)name[i]) || name[i] == '_' ||
              name[i] == '-' || name[i] == '.'))
            return 0;
    return 1;
}

static int flowd_tp_tc_state_write_path(const char *state_path,
                                        const struct flowd_tp_tc_state *state)
{
    char tmp[128];
    FILE *fp;
    unsigned int i;

    if (!state_path || state_path[0] != '/' || !state ||
        state->upload_count > FLOWD_TP_TC_MAX_RULES ||
        state->download_count > FLOWD_TP_TC_MAX_RULES ||
        state->wan_count > FLOWD_TP_TC_MAX_WANS)
        return -1;
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", state_path, (long)getpid());
    fp = fopen(tmp, "w");
    if (!fp)
        return -1;
    if (fprintf(fp, "v4\n") < 0)
        goto fail;
    if (fprintf(fp, "a %s\n", state->upload_ifb[0] ?
                state->upload_ifb : FLOWD_TP_TC_UPLOAD_IFB) < 0)
        goto fail;
    for (i = 0; i < state->upload_count; i++)
        if (fprintf(fp, "u %d %d %u %u %s\n", state->upload[i].family,
                    state->upload[i].plen, state->upload[i].rate_kbps,
                    state->upload[i].classid,
                    state->upload[i].addr) < 0)
            goto fail;
    for (i = 0; i < state->download_count; i++)
        if (fprintf(fp, "d %d %d %u %u %s\n", state->download[i].family,
                    state->download[i].plen, state->download[i].rate_kbps,
                    state->download[i].classid,
                    state->download[i].addr) < 0)
            goto fail;
    for (i = 0; i < state->wan_count; i++)
        if (fprintf(fp, "p %s\n", state->wans[i].wan) < 0)
            goto fail;
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0 || fclose(fp) != 0)
        return unlink(tmp), -1;
    if (rename(tmp, state_path) != 0)
        return unlink(tmp), -1;
    return 0;
fail:
    fclose(fp);
    unlink(tmp);
    return -1;
}

static int flowd_tp_tc_state_write(const struct flowd_tp_tc_state *state)
{
    return flowd_tp_tc_state_write_path(FLOWD_TP_TC_STATE_FILE, state);
}

static int flowd_tp_tc_state_read_path(const char *state_path,
                                       struct flowd_tp_tc_state *state)
{
    FILE *fp;
    char line[256];
    unsigned int next_up = 0, next_down = 0, next_wan = 0;

    if (!state_path || state_path[0] != '/' || !state)
        return -1;
    memset(state, 0, sizeof(*state));
    fp = fopen(state_path, "r");
    if (!fp)
        return errno == ENOENT ? 0 : -1;
    int version = 0;
    if (!fgets(line, sizeof(line), fp))
        goto corrupt;
    if (!strcmp(line, "v1\n")) version = 1;
    else if (!strcmp(line, "v2\n")) version = 2;
    else if (!strcmp(line, "v3\n")) version = 3;
    else if (!strcmp(line, "v4\n")) version = 4;
    else goto corrupt;
    snprintf(state->upload_ifb, sizeof(state->upload_ifb), "%s",
             FLOWD_TP_TC_UPLOAD_IFB);
    while (fgets(line, sizeof(line), fp)) {
        char kind;
        int family, plen;
        unsigned int rate;
        char value[128];

        if (sscanf(line, " a %127s", value) == 1) {
            if (strcmp(value, FLOWD_TP_TC_UPLOAD_IFB))
                goto corrupt;
            snprintf(state->upload_ifb, sizeof(state->upload_ifb), "%s", value);
            continue;
        }

        unsigned int classid = 0;
        int parsed = sscanf(line, " %c %d %d %u %u %127s", &kind, &family,
                            &plen, &rate, &classid, value);
        if (parsed == 6 && (kind == 'u' || kind == 'd')) {
            struct flowd_tp_tc_rule *rules;
            unsigned int *count;
            if ((kind == 'u' && next_up >= FLOWD_TP_TC_MAX_RULES) ||
                (kind == 'd' && next_down >= FLOWD_TP_TC_MAX_RULES) ||
                (family != 4 && family != 6) || plen < 1 || plen > 128 || !rate ||
                classid < 1 || classid > 8000 ||
                !flowd_tp_tc_token_ok(value, FLOWD_TP_TC_ADDR_LEN - 1))
                goto corrupt;
            rules = kind == 'u' ? state->upload : state->download;
            count = kind == 'u' ? &next_up : &next_down;
            memset(&rules[*count], 0, sizeof(rules[*count]));
            rules[*count].classid = classid;
            rules[*count].family = family;
            rules[*count].plen = plen;
            rules[*count].rate_kbps = rate;
            JMX_STRBUF_COPY(rules[*count].addr, value);
            (*count)++;
            continue;
        }
        if (version < 4 && sscanf(line, " %c %d %d %u %127s", &kind,
                                  &family, &plen, &rate, value) == 5 &&
            (kind == 'u' || kind == 'd')) {
            struct flowd_tp_tc_rule *rules;
            unsigned int *count;
            if ((kind == 'u' && next_up >= FLOWD_TP_TC_MAX_RULES) ||
                (kind == 'd' && next_down >= FLOWD_TP_TC_MAX_RULES) ||
                (family != 4 && family != 6) || plen < 1 || plen > 128 || !rate ||
                !flowd_tp_tc_token_ok(value, FLOWD_TP_TC_ADDR_LEN - 1))
                goto corrupt;
            rules = kind == 'u' ? state->upload : state->download;
            count = kind == 'u' ? &next_up : &next_down;
            memset(&rules[*count], 0, sizeof(rules[*count]));
            rules[*count].classid = 100 + (*count % 8000U);
            rules[*count].family = family;
            rules[*count].plen = plen;
            rules[*count].rate_kbps = rate;
            JMX_STRBUF_COPY(rules[*count].addr, value);
            (*count)++;
            continue;
        }
        if ((sscanf(line, " p %127s", value) == 1) ||
            (sscanf(line, " w %127s", value) == 1)) {
            if (next_wan >= FLOWD_TP_TC_MAX_WANS ||
                !flowd_tp_tc_ifname_ok(value) ||
                snprintf(state->wans[next_wan].wan,
                         sizeof(state->wans[next_wan].wan), "%s", value) >=
                    (int)sizeof(state->wans[next_wan].wan) ||
                flowd_tp_tc_ifb_name(value, state->wans[next_wan].ifb,
                                     sizeof(state->wans[next_wan].ifb)) != 0)
                goto corrupt;
            state->wans[next_wan].legacy_ingress = line[0] == 'w';
            snprintf(state->wans[next_wan].lan_dev,
                     sizeof(state->wans[next_wan].lan_dev), "%s", value);
            next_wan++;
            continue;
        }
        goto corrupt;
    }
    fclose(fp);
    state->upload_count = next_up;
    state->download_count = next_down;
    state->wan_count = next_wan;
    return 1;
corrupt:
    fclose(fp);
    return -1;
}

static int flowd_tp_tc_state_read(struct flowd_tp_tc_state *state)
{
    return flowd_tp_tc_state_read_path(FLOWD_TP_TC_STATE_FILE, state);
}

static int flowd_tp_tc_state_wans_clear(const struct flowd_tp_tc_state *state)
{
    if (!state || !state->wan_count)
        return 0;
    flowd_tp_tc_down_clear(state->wans, state->wan_count);
    return 0;
}

/* Download packets reach the client through the bridge's forwarding port.
 * At WAN ingress they still carry the pre-DNAT address, so a WAN-side IFB
 * cannot classify them by terminal destination.  Discover the actual bridge
 * ports and shape on each port's egress instead. */
static int flowd_tp_tc_discover_lan_ports(struct flowd_tp_tc_wan *wans, size_t *count)
{
    DIR *dir;
    struct dirent *entry;
    size_t n = 0;

    if (!wans || !count)
        return -1;
    *count = 0;
    dir = opendir("/sys/class/net/" FLOWD_TP_TC_LAN "/brif");
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL && n < FLOWD_TP_TC_MAX_WANS) {
        const char *port = entry->d_name;
        int duplicate = 0;

        if (port[0] == '.' || !flowd_tp_tc_ifname_ok(port) ||
            if_nametoindex(port) == 0)
            continue;
        for (size_t i = 0; i < n; i++)
            if (!strcmp(wans[i].lan_dev, port))
                duplicate = 1;
        if (duplicate)
            continue;
        memset(&wans[n], 0, sizeof(wans[n]));
        snprintf(wans[n].wan, sizeof(wans[n].wan), "%s", port);
        snprintf(wans[n].lan_dev, sizeof(wans[n].lan_dev), "%s", port);
        if (flowd_tp_tc_ifb_name(port, wans[n].ifb, sizeof(wans[n].ifb)) != 0)
            continue;
        n++;
    }
    closedir(dir);
    *count = n;
    return 0;
}

static int flowd_tp_tc_ifb_name(const char *wan, char *out, size_t out_len)
{
    unsigned int hash = 2166136261U;
    const unsigned char *p;

    if (!wan || !out || !out_len)
        return -1;
    for (p = (const unsigned char *)wan; *p; p++)
        hash = (hash ^ *p) * 16777619U;
    return snprintf(out, out_len, "ifb-tp-%04x", hash & 0xffffU) >= (int)out_len ? -1 : 0;
}


/*
 * Ingress filter priority band.
 *
 * The QoS shaper (flowd_tc_apply.c) installs its own matchall mirred redirect
 * at a fixed pref 49152 on the same WAN ingress qdisc.  Terminal policy must
 * stay clear of it, otherwise `filter replace` at the same pref would silently
 * take over the QoS redirect and send WAN ingress to the wrong IFB.  Band
 * 48000-48099 is reserved here for that reason; do not widen it into 49xxx.
 */
#define FLOWD_TP_TC_INGRESS_PREF_BASE 48000U
#define FLOWD_TP_TC_INGRESS_PREF_SPAN 100U

static int flowd_tp_tc_ingress_pref(const char *wan, char *out, size_t out_len)
{
    unsigned int hash = 2166136261U;
    for (const unsigned char *p = (const unsigned char *)wan; p && *p; p++)
        hash = (hash ^ *p) * 16777619U;
    return snprintf(out, out_len, "%u",
                    FLOWD_TP_TC_INGRESS_PREF_BASE +
                    (hash % FLOWD_TP_TC_INGRESS_PREF_SPAN)) >= (int)out_len ? -1 : 0;
}

static int flowd_tp_tc_download_egress_pref(const char *dev, char *out, size_t out_len)
{
    unsigned int hash = 2166136261U;

    if (!dev || !out || !out_len)
        return -1;
    for (const unsigned char *p = (const unsigned char *)dev; *p; p++)
        hash = (hash ^ *p) * 16777619U;
    return snprintf(out, out_len, "%u",
                    FLOWD_TP_TC_DOWNLOAD_EGRESS_PREF_BASE +
                    (hash % FLOWD_TP_TC_DOWNLOAD_EGRESS_PREF_SPAN)) >= (int)out_len ? -1 : 0;
}

/* True when the device already carries an ingress (ffff:) qdisc. */
static int flowd_tp_tc_has_ingress_qdisc(const char *dev)
{
    char *argv[] = { (char *)FLOWD_TP_TC_BINARY, "qdisc", "show", "dev",
                     (char *)dev, "ingress", NULL };
    struct flowd_tp_tc_capture capture;
    int found = 0;

    if (!dev)
        return 0;
    if (flowd_tp_tc_run(argv, &capture) != 0) {
        free(capture.data);
        return 0;
    }
    if (capture.data && strstr(capture.data, "ingress"))
        found = 1;
    free(capture.data);
    return found;
}

static int flowd_tp_tc_ifb_prepare(struct flowd_tp_tc_wan *w)
{
    char *add[] = { (char *)FLOWD_TP_TC_IP_BINARY, "link", "add", w->ifb,
                    "type", "ifb", NULL };
    char *up[] = { (char *)FLOWD_TP_TC_IP_BINARY, "link", "set", "dev", w->ifb,
                   "up", NULL };
    char pref[16];
    char *qdisc[] = { (char *)FLOWD_TP_TC_BINARY, "qdisc", "add", "dev",
                      NULL, "clsact", NULL };
    char *filter[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "replace", "dev",
                       NULL, "egress", "protocol", "all", "pref", NULL,
                       "matchall", "action", "mirred", "egress", "redirect",
                       "dev", NULL, NULL };

    if (!w || !w->ifb[0])
        return -1;

    if (flowd_tp_tc_cmd(add) != 0) {
        char *show[] = { (char *)FLOWD_TP_TC_IP_BINARY, "link", "show", "dev", w->ifb, NULL };
        if (flowd_tp_tc_cmd(show) != 0)
            return -1;
    }
    if (flowd_tp_tc_cmd(up) != 0)
        return -1;
    if (w->legacy_ingress) {
        char *iqdisc[] = { (char *)FLOWD_TP_TC_BINARY, "qdisc", "add", "dev",
                           w->wan, "handle", "ffff:", "ingress", NULL };
        char *ifilter[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "replace", "dev",
                            w->wan, "parent", "ffff:", "protocol", "all",
                            "pref", NULL, "matchall", "action", "mirred",
                            "egress", "redirect", "dev", w->ifb, NULL };

        if (flowd_tp_tc_ingress_pref(w->wan, pref, sizeof(pref)) != 0)
            return -1;
        ifilter[10] = pref;
        if (!flowd_tp_tc_has_ingress_qdisc(w->wan) &&
            flowd_tp_tc_cmd(iqdisc) != 0 && !flowd_tp_tc_has_ingress_qdisc(w->wan))
            return -1;
        return flowd_tp_tc_cmd(ifilter);
    }
    if (!w->lan_dev[0] ||
        flowd_tp_tc_download_egress_pref(w->lan_dev, pref, sizeof(pref)) != 0)
        return -1;
    qdisc[4] = w->lan_dev;
    filter[4] = w->lan_dev;
    filter[9] = pref;
    filter[16] = w->ifb;
    if (flowd_tp_tc_cmd(qdisc) != 0) {
        char *show[] = { (char *)FLOWD_TP_TC_BINARY, "qdisc", "show", "dev",
                         w->lan_dev, "clsact", NULL };
        if (flowd_tp_tc_cmd(show) != 0)
            return -1;
    }
    if (flowd_tp_tc_cmd(filter) != 0)
        return -1;
    return 0;
}

/* Upload is shaped after the bridge ingress hook. Client packets enter br-lan,
 * so a root qdisc on br-lan egress never sees them before routing. */
static int flowd_tp_tc_upload_prepare(void)
{
    char *add[] = { (char *)FLOWD_TP_TC_IP_BINARY, "link", "add",
                    (char *)FLOWD_TP_TC_UPLOAD_IFB, "type", "ifb", NULL };
    char *up[] = { (char *)FLOWD_TP_TC_IP_BINARY, "link", "set", "dev",
                   (char *)FLOWD_TP_TC_UPLOAD_IFB, "up", NULL };
    char *qdisc[] = { (char *)FLOWD_TP_TC_BINARY, "qdisc", "add", "dev",
                      (char *)FLOWD_TP_TC_LAN, "handle", "ffff:", "ingress", NULL };
    char *filter[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "replace", "dev",
                       (char *)FLOWD_TP_TC_LAN, "parent", "ffff:", "protocol", "all",
                       "pref", FLOWD_TP_TC_UPLOAD_PREF, "matchall", "action",
                       "mirred", "egress", "redirect", "dev",
                       (char *)FLOWD_TP_TC_UPLOAD_IFB, NULL };
    char *show[] = { (char *)FLOWD_TP_TC_IP_BINARY, "link", "show", "dev",
                     (char *)FLOWD_TP_TC_UPLOAD_IFB, NULL };

    if (flowd_tp_tc_cmd(add) != 0 && flowd_tp_tc_cmd(show) != 0)
        return -1;
    if (flowd_tp_tc_cmd(up) != 0)
        return -1;
    if (!flowd_tp_tc_has_ingress_qdisc(FLOWD_TP_TC_LAN)) {
        if (flowd_tp_tc_cmd(qdisc) != 0 &&
            !flowd_tp_tc_has_ingress_qdisc(FLOWD_TP_TC_LAN))
            return -1;
        {
            int fd = open(FLOWD_TP_TC_UPLOAD_INGRESS_OWNER_FILE,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd < 0 || close(fd) != 0) {
                if (fd >= 0)
                    close(fd);
                return -1;
            }
        }
    }
    return flowd_tp_tc_cmd(filter);
}

static int flowd_tp_tc_upload_ingress_inspect(int *ours, int *foreign)
{
    char *show[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "show", "dev",
                     (char *)FLOWD_TP_TC_LAN, "parent", "ffff:", NULL };
    struct flowd_tp_tc_capture capture;
    char *line;
    char *save = NULL;
    int found_ours = 0;
    int found_foreign = 0;

    if (ours)
        *ours = 0;
    if (foreign)
        *foreign = 0;

    if (flowd_tp_tc_run(show, &capture) != 0) {
        free(capture.data);
        return -1;
    }
    for (line = capture.data ? strtok_r(capture.data, "\n", &save) : NULL;
         line; line = strtok_r(NULL, "\n", &save)) {
        const char *pref_text = strstr(line, " pref ");
        unsigned long pref;

        if (pref_text) {
            char *end = NULL;

            pref = strtoul(pref_text + 6, &end, 10);
            if (!end || end == pref_text + 6)
                continue;
            if (pref == (unsigned long)atoi(FLOWD_TP_TC_UPLOAD_PREF))
                found_ours = 1;
            else
                found_foreign = 1;
        }
    }
    free(capture.data);
    if (ours)
        *ours = found_ours;
    if (foreign)
        *foreign = found_foreign;
    return 0;
}

static void flowd_tp_tc_upload_clear(void)
{
    char *filter[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "del", "dev",
                       (char *)FLOWD_TP_TC_LAN, "parent", "ffff:", "pref",
                       FLOWD_TP_TC_UPLOAD_PREF, NULL };
    char *del[] = { (char *)FLOWD_TP_TC_IP_BINARY, "link", "del",
                    (char *)FLOWD_TP_TC_UPLOAD_IFB, NULL };

    {
        int ours = 0;
        int foreign = 0;
        int own_ingress = access(FLOWD_TP_TC_UPLOAD_INGRESS_OWNER_FILE, F_OK) == 0;

        (void)flowd_tp_tc_upload_ingress_inspect(&ours, &foreign);
        (void)flowd_tp_tc_cmd(filter);
        if (own_ingress && ours && !foreign) {
            char *qdisc[] = { (char *)FLOWD_TP_TC_BINARY, "qdisc", "del", "dev",
                              (char *)FLOWD_TP_TC_LAN, "ingress", NULL };
            (void)flowd_tp_tc_cmd(qdisc);
        }
        unlink(FLOWD_TP_TC_UPLOAD_INGRESS_OWNER_FILE);
    }
    (void)flowd_tp_tc_cmd(del);
}

static int flowd_tp_tc_upload_cleanup_orphan(void)
{
    char *show[] = { (char *)FLOWD_TP_TC_IP_BINARY, "link", "show", "dev",
                     (char *)FLOWD_TP_TC_UPLOAD_IFB, NULL };
    struct flowd_tp_tc_capture capture;
    int exists;
    int ours = 0;
    int foreign = 0;

    if (flowd_tp_tc_run(show, &capture) != 0) {
        free(capture.data);
        return 0;
    }
    exists = capture.data != NULL;
    free(capture.data);
    if (exists) {
        (void)flowd_tp_tc_upload_ingress_inspect(&ours, &foreign);
        flowd_tp_tc_upload_clear();
        /* The marker may be missing if the process died between creating the
         * ingress qdisc and writing it.  In that narrow recovery window the
         * dedicated pref is enough to prove the qdisc was ours; never remove a
         * qdisc that still carries a foreign ingress filter. */
        if (ours && !foreign) {
            char *qdisc[] = { (char *)FLOWD_TP_TC_BINARY, "qdisc", "del", "dev",
                              (char *)FLOWD_TP_TC_LAN, "ingress", NULL };
            (void)flowd_tp_tc_cmd(qdisc);
        }
    }
    return 0;
}

static void flowd_tp_tc_ifb_clear(const struct flowd_tp_tc_wan *w)
{
    char pref[16];
    if (!w || !w->ifb[0])
        return;
    if (w->legacy_ingress) {
        if (flowd_tp_tc_ingress_pref(w->wan, pref, sizeof(pref)) != 0)
            return;
        char *filter[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "del", "dev",
                           (char *)w->wan, "parent", "ffff:", "pref", pref, NULL };
        (void)flowd_tp_tc_cmd(filter);
    } else {
        if (!w->lan_dev[0] ||
            flowd_tp_tc_download_egress_pref(w->lan_dev, pref, sizeof(pref)) != 0)
            return;
        char *filter[] = { (char *)FLOWD_TP_TC_BINARY, "filter", "del", "dev",
                           (char *)w->lan_dev, "egress", "pref", pref, NULL };
        (void)flowd_tp_tc_cmd(filter);
    }
    char *del[] = { (char *)FLOWD_TP_TC_IP_BINARY, "link", "del", (char *)w->ifb, NULL };

    (void)flowd_tp_tc_cmd(del);
}

static void flowd_tp_tc_down_clear(const struct flowd_tp_tc_wan *wans, size_t count)
{
    size_t i;
    char kind[32];

    for (i = 0; i < count; i++) {
        if (!wans[i].ifb[0])
            continue;
        kind[0] = '\0';
        if (flowd_tp_tc_qdisc_kind(wans[i].ifb, kind, sizeof(kind)) == 0 && !strcmp(kind, "htb")) {
            char *del[] = { (char *)FLOWD_TP_TC_BINARY, "qdisc", "del", "dev",
                            (char *)wans[i].ifb, "root", NULL };
            (void)flowd_tp_tc_cmd(del);
        }
        flowd_tp_tc_ifb_clear(&wans[i]);
    }
}

static int flowd_tp_tc_apply_state(const struct flowd_tp_tc_state *state)
{
    size_t i;

    if (!state)
        return -1;
    /* The failed generation may have left a partial qdisc/filter set behind.
     * Reconcile from a clean, owned baseline before restoring the snapshot. */
    if (g_tp_tc_owned || flowd_tp_tc_intent_pending()) {
        flowd_tp_tc_clear_all_down();
        flowd_tp_tc_upload_clear();
    }
    if (state->upload_count) {
        if (flowd_tp_tc_upload_prepare() != 0 ||
            flowd_tp_tc_apply_rules(FLOWD_TP_TC_UPLOAD_IFB, state->upload,
                                    state->upload_count, "src") != 0)
            return -1;
    }
    for (i = 0; i < state->wan_count; i++) {
        if (!state->download_count)
            break;
        if (flowd_tp_tc_ifb_prepare((struct flowd_tp_tc_wan *)&state->wans[i]) != 0 ||
            flowd_tp_tc_apply_rules(state->wans[i].ifb, state->download,
                                    state->download_count, "dst") != 0)
            return -1;
    }
    if (state->download_count && !state->wan_count)
        return -1;
    return 0;
}

int flowd_terminal_policy_tc_restore_previous(void)
{
    struct flowd_tp_tc_state state;
    int rc;

    flowd_tp_tc_owner_refresh();
    rc = flowd_tp_tc_state_read_path(FLOWD_TP_TC_PREVIOUS_STATE_FILE, &state);
    if (rc <= 0) {
        if (g_tp_tc_owned || flowd_tp_tc_intent_pending()) {
            flowd_tp_tc_clear_all_down();
            flowd_tp_tc_upload_clear();
            unlink(FLOWD_TP_TC_STATE_FILE);
            unlink(FLOWD_TP_TC_OWNER_FILE);
            g_tp_tc_owned = 0;
        }
        flowd_tp_tc_intent_clear();
        return rc < 0 ? -1 : 0;
    }
    /* Clear IFBs while ownership is still held: clear_lan() below clears the
     * owner flag, which would otherwise make clear_all_down() a no-op.  Also
     * scrub IFBs recorded in the previous snapshot in case a WAN vanished
     * from current netifd discovery. */
    if (g_tp_tc_owned || flowd_tp_tc_intent_pending()) {
        flowd_tp_tc_clear_all_down();
        flowd_tp_tc_upload_clear();
    }
    flowd_tp_tc_state_wans_clear(&state);
    g_tp_tc_owned = 0;
    if (flowd_tp_tc_apply_state(&state) != 0)
        return -1;
    if (flowd_tp_tc_state_write(&state) != 0)
        return -1;
    {
        int fd = open(FLOWD_TP_TC_OWNER_FILE,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0)
            return -1;
        {
            const char owner[] = "dreamingwrt-terminal-policy-tc-v1\n";
            ssize_t wrote = write(fd, owner, sizeof(owner) - 1);
            if (wrote != (ssize_t)(sizeof(owner) - 1)) {
                close(fd);
                return -1;
            }
        }
        if (close(fd) != 0)
            return -1;
        unlink(FLOWD_TP_TC_PREVIOUS_STATE_FILE);
    }
    g_tp_tc_owned = 1;
    flowd_tp_tc_intent_clear();
    return 0;
}


static void flowd_tp_tc_clear_all_down(void)
{
    struct flowd_tp_tc_wan wans[FLOWD_TP_TC_MAX_WANS];
    /* An interrupted apply may have created IFBs and ingress redirects before
     * the owner marker existed, so the intent marker also authorises cleanup. */
    if (!g_tp_tc_owned && !flowd_tp_tc_intent_pending())
        return;
    size_t count = 0;

    memset(wans, 0, sizeof(wans));
    (void)flowd_tp_tc_discover_lan_ports(wans, &count);
    flowd_tp_tc_down_clear(wans, count);
}

int flowd_terminal_policy_tc_executor_available(void)
{
    if (access(FLOWD_TP_TC_BINARY, X_OK) != 0)
        return 0;
    if (access(FLOWD_TP_TC_DB, R_OK) != 0)
        return 0;
    if (if_nametoindex(FLOWD_TP_TC_LAN) == 0)
        return 0;
    return 1;
}

struct json_object *flowd_terminal_policy_tc_apply(const struct flowd_settings *settings)
{
    struct json_object *out = json_object_new_object();
    struct flowd_tp_tc_rule rules[FLOWD_TP_TC_MAX_RULES];
    struct flowd_tp_tc_rule down_rules[FLOWD_TP_TC_MAX_RULES];
    struct flowd_tp_tc_wan wans[FLOWD_TP_TC_MAX_WANS];
    struct flowd_tp_tc_state old_state;
    struct flowd_tp_tc_state new_state;
    unsigned int count = 0;
    unsigned int down_count = 0;
    size_t wan_count = 0;
    char err[128] = "";
    int rc;
    int old_state_rc;
    int rollback_ok = 1;
    int interrupted;

    if (!out)
        return NULL;
    json_object_object_add(out, "kind", json_object_new_string("terminal_policy_tc"));
    json_object_object_add(out, "lan", json_object_new_string(FLOWD_TP_TC_LAN));
    if (!settings || strcmp(settings->apply_mode, "managed")) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason", json_object_new_string("flowd_apply_mode_disabled"));
        return out;
    }
    flowd_tp_tc_owner_refresh();
    if (!flowd_terminal_policy_tc_executor_available()) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason", json_object_new_string("tp_tc_executor_unavailable"));
        return out;
    }
    /* Read the marker before anything overwrites it. */
    interrupted = flowd_tp_tc_intent_pending();
    json_object_object_add(out, "recovered_interrupted_apply",
                           json_object_new_boolean(interrupted));
    old_state_rc = flowd_tp_tc_state_read(&old_state);
    if (g_tp_tc_owned && old_state_rc <= 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "reason", json_object_new_string(
            old_state_rc < 0 ? "tp_tc_owned_state_corrupt" : "tp_tc_owned_state_missing"));
        return out;
    }
    memset(rules, 0, sizeof(rules));
    memset(down_rules, 0, sizeof(down_rules));
    memset(&new_state, 0, sizeof(new_state));
    if (old_state_rc > 0) {
        if (flowd_tp_tc_state_write_path(FLOWD_TP_TC_PREVIOUS_STATE_FILE,
                                         &old_state) != 0) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "reason",
                                   json_object_new_string("tp_tc_previous_state_write_failed"));
            return out;
        }
        flowd_tp_tc_state_wans_clear(&old_state);
        flowd_tp_tc_upload_clear();
    } else {
        unlink(FLOWD_TP_TC_PREVIOUS_STATE_FILE);
        (void)flowd_tp_tc_upload_cleanup_orphan();
    }
    /* Load the desired set and settle every precondition before mutating the
     * dataplane.  A download rule with no usable WAN used to be detected only
     * after br-lan had already been rebuilt, which turned an unsatisfiable
     * request into a live-state change plus a rollback. */
    rc = flowd_tp_tc_rules_load(rules, &count, down_rules, &down_count);
    if (rc < 0) {
        snprintf(err, sizeof(err), "tp_tc_rules_load_failed");
        goto failed;
    }
    if (down_count > 0) {
        (void)flowd_tp_tc_discover_lan_ports(wans, &wan_count);
        if (wan_count == 0) {
            snprintf(err, sizeof(err), "tp_tc_no_wan_ifb");
            goto failed;
        }
    }
    if (flowd_tp_tc_intent_set() != 0) {
        snprintf(err, sizeof(err), "tp_tc_intent_write_failed");
        goto failed;
    }
    /* Download shaping lives on bridge-port clsact qdiscs; never replace or
     * delete the bridge root, which may belong to the system QoS owner. */
    if (count > 0 &&
        (flowd_tp_tc_upload_prepare() != 0 ||
         flowd_tp_tc_apply_rules(FLOWD_TP_TC_UPLOAD_IFB, rules, count, "src") != 0)) {
        snprintf(err, sizeof(err), "tp_tc_upload_apply_failed");
        goto failed;
    }
    for (size_t i = 0; i < wan_count; i++) {
        if (flowd_tp_tc_ifb_prepare(&wans[i]) != 0 ||
            flowd_tp_tc_apply_rules(wans[i].ifb, down_rules, down_count, "dst") != 0) {
            snprintf(err, sizeof(err), "tp_tc_download_apply_failed");
            goto failed;
        }
    }
    new_state.upload_count = count;
    new_state.download_count = down_count;
    snprintf(new_state.upload_ifb, sizeof(new_state.upload_ifb), "%s",
             FLOWD_TP_TC_UPLOAD_IFB);
    memcpy(new_state.upload, rules, sizeof(rules));
    memcpy(new_state.download, down_rules, sizeof(down_rules));
    new_state.wan_count = wan_count;
    memcpy(new_state.wans, wans, sizeof(wans));
    if (count == 0 && down_count == 0) {
        flowd_tp_tc_upload_clear();
        unlink(FLOWD_TP_TC_STATE_FILE);
        unlink(FLOWD_TP_TC_OWNER_FILE);
        unlink(FLOWD_TP_TC_PREVIOUS_STATE_FILE);
        g_tp_tc_owned = 0;
        flowd_tp_tc_intent_clear();
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "upload_rules_applied", json_object_new_int(0));
        json_object_object_add(out, "download_rules_applied", json_object_new_int(0));
        json_object_object_add(out, "download_ifbs", json_object_new_int(0));
        json_object_object_add(out, "direction_support", json_object_new_string("ipv4_ipv6_upload_download"));
        return out;
    }
    if (flowd_tp_tc_state_write(&new_state) != 0) {
        snprintf(err, sizeof(err), "tp_tc_state_write_failed");
        goto failed;
    }
    {
        int fd = open(FLOWD_TP_TC_OWNER_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd >= 0) {
            const char owner[] = "dreamingwrt-terminal-policy-tc-v1\n";
            ssize_t wrote = write(fd, owner, sizeof(owner) - 1);
            (void)wrote;
            close(fd);
            g_tp_tc_owned = 1;
        }
    }
    if (!g_tp_tc_owned) {
        snprintf(err, sizeof(err), "tp_tc_owner_write_failed");
        goto failed;
    }
    unlink(FLOWD_TP_TC_PREVIOUS_STATE_FILE);
    flowd_tp_tc_intent_clear();
    json_object_object_add(out, "ok", json_object_new_boolean(1));
    json_object_object_add(out, "upload_rules_applied", json_object_new_int((int)count));
    json_object_object_add(out, "download_rules_applied", json_object_new_int((int)down_count));
    json_object_object_add(out, "download_ifbs", json_object_new_int((int)wan_count));
    json_object_object_add(out, "direction_support", json_object_new_string("ipv4_ipv6_upload_download"));
    return out;
failed:
    if (wan_count > 0)
        flowd_tp_tc_down_clear(wans, wan_count);
    flowd_tp_tc_upload_clear();
    unlink(FLOWD_TP_TC_STATE_FILE);
    g_tp_tc_owned = 0;
    if (old_state_rc > 0) {
        if (flowd_tp_tc_apply_state(&old_state) == 0 &&
            flowd_tp_tc_state_write(&old_state) == 0) {
            int fd = open(FLOWD_TP_TC_OWNER_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd >= 0) {
                const char owner[] = "dreamingwrt-terminal-policy-tc-v1\n";
                ssize_t wrote = write(fd, owner, sizeof(owner) - 1);
                if (wrote == (ssize_t)(sizeof(owner) - 1) && close(fd) == 0) {
                    unlink(FLOWD_TP_TC_PREVIOUS_STATE_FILE);
                    g_tp_tc_owned = 1;
                } else {
                    close(fd);
                    rollback_ok = 0;
                }
            } else {
                rollback_ok = 0;
            }
        } else {
            rollback_ok = 0;
        }
    } else {
        unlink(FLOWD_TP_TC_OWNER_FILE);
    }
    /* Only drop the intent marker if the dataplane is genuinely back to a known
     * state.  A failed rollback must keep it, so the next apply knows it is
     * allowed to force-clear whatever was left behind. */
    if (rollback_ok)
        flowd_tp_tc_intent_clear();
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "reason", json_object_new_string(err[0] ? err : "tp_tc_apply_failed"));
    json_object_object_add(out, "rollback_ok", json_object_new_boolean(rollback_ok));
    return out;
}

struct json_object *flowd_terminal_policy_tc_runtime(void)
{
    struct json_object *out = json_object_new_object();
    struct json_object *upload = NULL, *classes = NULL, *filters = NULL;
    struct json_object *downloads = json_object_new_array();
    struct flowd_tp_tc_wan wans[FLOWD_TP_TC_MAX_WANS];
    struct flowd_tp_tc_rule up_rules[FLOWD_TP_TC_MAX_RULES];
    struct flowd_tp_tc_rule down_rules[FLOWD_TP_TC_MAX_RULES];
    unsigned int up_count = 0, down_count = 0;
    size_t wan_count = 0;
    char kind[32] = "noqueue";
    int load_rc;
    int rate_required;
    int rate_applied;
    int upload_ok = 1;
    int download_ok = 1;
    const char *reason = NULL;

    if (!out)
        return NULL;
    flowd_tp_tc_owner_refresh();
    flowd_tp_tc_qdisc_kind(FLOWD_TP_TC_UPLOAD_IFB, kind, sizeof(kind));
    memset(up_rules, 0, sizeof(up_rules));
    memset(down_rules, 0, sizeof(down_rules));
    load_rc = flowd_tp_tc_rules_load(up_rules, &up_count, down_rules, &down_count);
    rate_required = load_rc == 0 && (up_count > 0 || down_count > 0);
    if (load_rc != 0)
        reason = "tp_tc_rules_load_failed";
    json_object_object_add(out, "lan", json_object_new_string(FLOWD_TP_TC_LAN));
    json_object_object_add(out, "upload_ifb", json_object_new_string(FLOWD_TP_TC_UPLOAD_IFB));
    json_object_object_add(out, "qdisc", json_object_new_string(kind));
    json_object_object_add(out, "kind", json_object_new_string("terminal_policy_tc"));
    json_object_object_add(out, "owned", json_object_new_boolean(g_tp_tc_owned));
    json_object_object_add(out, "interrupted_apply_pending",
                           json_object_new_boolean(flowd_tp_tc_intent_pending()));
    {
        char *qargv[] = { (char *)FLOWD_TP_TC_BINARY, "-j", "qdisc", "show", "dev",
                          (char *)FLOWD_TP_TC_UPLOAD_IFB, NULL };
        char *cargv[] = { (char *)FLOWD_TP_TC_BINARY, "-j", "class", "show", "dev",
                          (char *)FLOWD_TP_TC_UPLOAD_IFB, NULL };
        char *fargv[] = { (char *)FLOWD_TP_TC_BINARY, "-j", "filter", "show", "dev",
                          (char *)FLOWD_TP_TC_UPLOAD_IFB, "parent", "1:", NULL };
        upload = flowd_tp_tc_json_cmd(qargv);
        classes = flowd_tp_tc_json_cmd(cargv);
        filters = flowd_tp_tc_json_cmd(fargv);
    }
    if (upload)
        json_object_object_add(out, "upload_qdisc", upload);
    if (classes)
        json_object_object_add(out, "upload_classes", classes);
    if (filters)
        json_object_object_add(out, "upload_filters", filters);
    /* Upload half: the dedicated IFB must carry exactly the src classes/filters
     * the stored rules imply, and br-lan ingress must redirect to it. */
    if (up_count > 0) {
        struct json_object *report = json_object_new_object();
        int ingress_ok;

        upload_ok = flowd_tp_tc_verify_dev(FLOWD_TP_TC_UPLOAD_IFB, up_rules,
                                           up_count, "src", report) && g_tp_tc_owned;
        ingress_ok = flowd_tp_tc_verify_upload_ingress(report);
        upload_ok = upload_ok && ingress_ok;
        if (report)
            json_object_object_add(out, "upload_verify", report);
        if (!upload_ok && !reason)
            reason = "tp_tc_upload_readback_mismatch";
    } else if (rate_required || g_tp_tc_owned) {
        /* Download-only, or stale ownership with no rules left: the upload IFB
         * must be absent and br-lan must not carry our redirect. */
        upload_ok = strcmp(kind, "htb") != 0;
        if (!upload_ok && !reason)
            reason = "tp_tc_upload_stale_htb";
    }
    memset(wans, 0, sizeof(wans));
    (void)flowd_tp_tc_discover_lan_ports(wans, &wan_count);
    for (size_t i = 0; i < wan_count; i++) {
        struct json_object *item = json_object_new_object();
        char *qargv[] = { (char *)FLOWD_TP_TC_BINARY, "-j", "qdisc", "show", "dev",
                          wans[i].ifb, NULL };
        char *cargv[] = { (char *)FLOWD_TP_TC_BINARY, "-j", "class", "show", "dev",
                          wans[i].ifb, NULL };
        char *fargv[] = { (char *)FLOWD_TP_TC_BINARY, "-j", "filter", "show", "dev",
                          wans[i].ifb, "parent", "1:", NULL };
        struct json_object *q = flowd_tp_tc_json_cmd(qargv);
        struct json_object *c = flowd_tp_tc_json_cmd(cargv);
        struct json_object *f = flowd_tp_tc_json_cmd(fargv);
        json_object_object_add(item, "wan", json_object_new_string(wans[i].wan));
        json_object_object_add(item, "egress_dev", json_object_new_string(wans[i].lan_dev));
        json_object_object_add(item, "ifb", json_object_new_string(wans[i].ifb));
        if (q) json_object_object_add(item, "qdisc", q);
        if (c) json_object_object_add(item, "classes", c);
        if (f) json_object_object_add(item, "filters", f);
        if (down_count > 0) {
            int dev_ok = flowd_tp_tc_verify_dev(wans[i].ifb, down_rules,
                                                down_count, "dst", item);
            int ing_ok = flowd_tp_tc_verify_download_egress(&wans[i], item);

            if (!dev_ok || !ing_ok) {
                download_ok = 0;
                if (!reason)
                    reason = !dev_ok ? "tp_tc_download_readback_mismatch" :
                                       "tp_tc_egress_redirect_missing";
            }
        }
        json_object_array_add(downloads, item);
    }
    json_object_object_add(out, "downloads", downloads);
    if (down_count > 0) {
        if (wan_count == 0) {
            download_ok = 0;
            if (!reason)
                reason = "tp_tc_no_wan_ifb";
        }
        if (!g_tp_tc_owned) {
            download_ok = 0;
            if (!reason)
                reason = "tp_tc_not_owned";
        }
    }
    rate_applied = load_rc == 0 && upload_ok && download_ok;
    if (!rate_required && load_rc == 0 && !g_tp_tc_owned)
        rate_applied = 1;
    json_object_object_add(out, "ok", json_object_new_boolean(rate_applied));
    json_object_object_add(out, "rate_rules_expected", json_object_new_int((int)(up_count + down_count)));
    json_object_object_add(out, "upload_rules_expected", json_object_new_int((int)up_count));
    json_object_object_add(out, "download_rules_expected", json_object_new_int((int)down_count));
    json_object_object_add(out, "rate_rules_applied", json_object_new_boolean(rate_applied));
    json_object_object_add(out, "rate_readback", json_object_new_string("per_rule_class_filter"));
    json_object_object_add(out, "direction_support", json_object_new_string("ipv4_ipv6_upload_download"));
    if (!rate_applied)
        json_object_object_add(out, "reason",
                               json_object_new_string(reason ? reason :
                                   "tp_tc_runtime_unverified"));
    return out;
}
