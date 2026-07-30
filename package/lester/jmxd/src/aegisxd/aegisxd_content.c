// SPDX-License-Identifier: GPL-2.0-or-later
/* AegisX content-filter policy control plane. */
#include "aegisxd_internal.h"

#define CONTENT_MAX_LIST 128
#define CONTENT_MAX_DOMAIN 253
#define CONTENT_PROVENANCE_MAX_RULES 60000

struct content_provenance_rule {
    char domain[254];
    char kind[32];
    char source_id[64];
};

struct content_provenance_cache {
    struct content_provenance_rule *rules;
    size_t count;
    size_t capacity;
    char path[AEGISXD_MAX_PATH];
    int revision;
    off_t size;
    time_t mtime;
    int schema_ready;
};

static struct content_provenance_cache g_content_provenance;

struct content_string_list {
    char **items;
    size_t count;
};

struct content_safe_search {
    int google;
    int bing;
    int youtube;
};

struct content_filter {
    int managed;
    int policy_count;
    int enhanced;
    int ad_block;
    struct content_safe_search safe_search;
    struct content_string_list categories;
    struct content_string_list allows;
    struct content_string_list blocks;
    struct content_string_list emitted_blocks;
    struct content_string_list emitted_categories;
};

struct content_safe_search_host {
    const char *provider;
    const char *host;
    const char *ipv4;
    const char *ipv6;
};

static const struct content_safe_search_host content_safe_search_hosts[] = {
    { "google", "forcesafesearch.google.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "google", "google.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "google", "www.google.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "google", "encrypted.google.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "google", "images.google.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "bing", "strict.bing.com", "204.79.197.220", "" },
    { "bing", "www.bing.com", "204.79.197.220", "" },
    { "youtube", "restrict.youtube.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "youtube", "www.youtube.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "youtube", "m.youtube.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "youtube", "youtubei.googleapis.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "youtube", "youtube.googleapis.com", "216.239.38.120", "2001:4860:4802:32::" },
    { "youtube", "www.youtube-nocookie.com", "216.239.38.120", "2001:4860:4802:32::" },
};

static int content_id_ok(const char *s)
{
    size_t n;
    if (!s || !(n = strlen(s)) || n > 95)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '_' &&
            s[i] != '.')
            return 0;
    return 1;
}

static int content_text_ok(const char *s, size_t max, int required)
{
    size_t n;
    if (!s)
        return !required;
    n = strlen(s);
    if ((required && !n) || n > max)
        return 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] == 0x7f)
            return 0;
    return 1;
}

static int content_mode_ok(const char *s)
{
    return s && (!strcmp(s, "off") || !strcmp(s, "basic") || !strcmp(s, "enhanced"));
}

static void content_domain_normalize(char *out, size_t out_len, const char *raw)
{
    const char *p = raw ? raw : "";
    size_t n;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (!strncasecmp(p, "https://", 8)) p += 8;
    else if (!strncasecmp(p, "http://", 7)) p += 7;
    n = strcspn(p, "/?#");
    if (n >= out_len) n = out_len - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    while (n && (out[n - 1] == '.' || isspace((unsigned char)out[n - 1])))
        out[--n] = '\0';
    for (size_t i = 0; i < n; i++)
        out[i] = (char)tolower((unsigned char)out[i]);
}

static int content_domain_ok(const char *s)
{
    size_t n;
    int dot = 0, label = 0;
    if (!s || !(n = strlen(s)) || n > CONTENT_MAX_DOMAIN)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '.') {
            if (!label || s[i - 1] == '-') return 0;
            dot = 1; label = 0; continue;
        }
        if (!isalnum(c) && c != '-') return 0;
        if (!label && c == '-') return 0;
        if (++label > 63) return 0;
    }
    return dot && label && s[n - 1] != '-';
}

static int content_list_add(struct content_string_list *list, const char *value)
{
    char **next;
    if (!list || !value || !value[0])
        return -1;
    for (size_t i = 0; i < list->count; i++)
        if (!strcmp(list->items[i], value))
            return 0;
    if (list->count >= CONTENT_MAX_LIST)
        return -1;
    next = realloc(list->items, (list->count + 1) * sizeof(*next));
    if (!next)
        return -1;
    list->items = next;
    list->items[list->count] = strdup(value);
    if (!list->items[list->count])
        return -1;
    list->count++;
    return 0;
}

static void content_list_free(struct content_string_list *list)
{
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) free(list->items[i]);
    free(list->items); memset(list, 0, sizeof(*list));
}

static int content_list_has(const struct content_string_list *list, const char *value)
{
    if (!list || !value) return 0;
    for (size_t i = 0; i < list->count; i++)
        if (!strcmp(list->items[i], value)) return 1;
    return 0;
}

static int content_domain_matches(const char *domain, const char *rule)
{
    size_t dn, rn;
    if (!domain || !rule) return 0;
    dn = strlen(domain); rn = strlen(rule);
    return dn == rn ? !strcmp(domain, rule) :
        (dn > rn && domain[dn - rn - 1] == '.' && !strcmp(domain + dn - rn, rule));
}

static int content_domain_list_matches(const struct content_string_list *list,
                                       const char *domain)
{
    if (!list || !domain) return 0;
    for (size_t i = 0; i < list->count; i++)
        if (content_domain_matches(domain, list->items[i])) return 1;
    return 0;
}

int aegisxd_content_revision_get(void)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT revision FROM aegis_content_meta WHERE id=1");
    int revision = -1;

    if (st && sqlite3_step(st) == SQLITE_ROW)
        revision = sqlite3_column_int(st, 0);
    if (st)
        sqlite3_finalize(st);
    return revision;
}

static void content_provenance_reset(void)
{
    free(g_content_provenance.rules);
    memset(&g_content_provenance, 0, sizeof(g_content_provenance));
    g_content_provenance.revision = -1;
}

static int content_provenance_cmp(const void *a, const void *b)
{
    const struct content_provenance_rule *ra = a, *rb = b;

    return strcmp(ra->domain, rb->domain);
}

static int content_provenance_add(const char *domain, const char *kind,
                                  const char *source_id)
{
    struct content_provenance_rule *next;
    size_t capacity;

    if (!content_domain_ok(domain) || !kind || !kind[0] || !source_id ||
        !source_id[0] || g_content_provenance.count >= CONTENT_PROVENANCE_MAX_RULES)
        return -1;
    if (g_content_provenance.count == g_content_provenance.capacity) {
        capacity = g_content_provenance.capacity ?
            g_content_provenance.capacity * 2 : 256;
        if (capacity > CONTENT_PROVENANCE_MAX_RULES)
            capacity = CONTENT_PROVENANCE_MAX_RULES;
        next = realloc(g_content_provenance.rules, capacity * sizeof(*next));
        if (!next)
            return -1;
        g_content_provenance.rules = next;
        g_content_provenance.capacity = capacity;
    }
    next = &g_content_provenance.rules[g_content_provenance.count++];
    snprintf(next->domain, sizeof(next->domain), "%s", domain);
    snprintf(next->kind, sizeof(next->kind), "%s", kind);
    snprintf(next->source_id, sizeof(next->source_id), "%s", source_id);
    return 0;
}

static int content_provenance_load_file(const char *path, int revision,
                                        const struct stat *file_stat)
{
    FILE *fp;
    char line[1024];
    char pending_domain[254] = "";
    char pending_kind[32] = "";
    char pending_source[64] = "";
    int saw_ipv4 = 0;
    int schema_ready = 0;

    content_provenance_reset();
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char domain[254] = "", kind[32] = "", source[64] = "";
        char expected[600];

        if (!strcmp(line, "# aegis-provenance-version=1\n") ||
            !strcmp(line, "# aegis-provenance-version=1")) {
            schema_ready = 1;
            continue;
        }
        if (sscanf(line, "# aegis provenance=%31s source=%63s domain=%253s",
                   kind, source, domain) == 3) {
            domain[strcspn(domain, " \t\r\n")] = '\0';
            snprintf(pending_domain, sizeof(pending_domain), "%s", domain);
            snprintf(pending_kind, sizeof(pending_kind), "%s", kind);
            snprintf(pending_source, sizeof(pending_source), "%s", source);
            saw_ipv4 = 0;
            continue;
        }
        if (sscanf(line, "# aegis monitor=%31s source=%63s domain=%253s",
                   kind, source, domain) == 3) {
            domain[strcspn(domain, " \t\r\n")] = '\0';
            if (strcmp(kind, "pcdn") ||
                content_provenance_add(domain, "pcdn_monitor", source) != 0)
                goto fail;
            pending_domain[0] = '\0';
            saw_ipv4 = 0;
            continue;
        }
        if (!pending_domain[0])
            continue;
        snprintf(expected, sizeof(expected), "address=/%s/0.0.0.0\n", pending_domain);
        if (!strcmp(line, expected)) {
            saw_ipv4 = 1;
            continue;
        }
        snprintf(expected, sizeof(expected), "address=/%s/::\n", pending_domain);
        if (saw_ipv4 && !strcmp(line, expected)) {
            if (content_provenance_add(pending_domain, pending_kind,
                                       pending_source) != 0)
                goto fail;
        }
        pending_domain[0] = '\0';
        saw_ipv4 = 0;
    }
    if (ferror(fp) || !schema_ready)
        goto fail;
    fclose(fp);
    qsort(g_content_provenance.rules, g_content_provenance.count,
          sizeof(*g_content_provenance.rules), content_provenance_cmp);
    snprintf(g_content_provenance.path, sizeof(g_content_provenance.path),
             "%s", path);
    g_content_provenance.revision = revision;
    g_content_provenance.size = file_stat->st_size;
    g_content_provenance.mtime = file_stat->st_mtime;
    g_content_provenance.schema_ready = 1;
    return 0;
fail:
    fclose(fp);
    content_provenance_reset();
    return -1;
}

static int content_provenance_ensure(void)
{
    struct json_object *root = NULL, *revision_json = NULL;
    const char *path;
    struct stat st;
    int revision;
    int ok = 0;

    root = json_object_from_file(AEGISXD_RUNTIME_DIR "/active.json");
    if (!root || !json_object_is_type(root, json_type_object) ||
        (strcmp(aegisxd_json_str(root, "scope", ""), "dns_filter") &&
         strcmp(aegisxd_json_str(root, "scope", ""), "all")) ||
        !json_object_object_get_ex(root, "content_revision", &revision_json) ||
        !revision_json || !json_object_is_type(revision_json, json_type_int))
        goto out;
    revision = json_object_get_int(revision_json);
    path = aegisxd_json_str(root, "dnsmasq_conf_file", "");
    if (!path[0] || lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        access(path, R_OK) != 0)
        goto out;
    if (g_content_provenance.schema_ready &&
        g_content_provenance.revision == revision &&
        !strcmp(g_content_provenance.path, path) &&
        g_content_provenance.size == st.st_size &&
        g_content_provenance.mtime == st.st_mtime)
        ok = 1;
    else
        ok = content_provenance_load_file(path, revision, &st) == 0;
out:
    if (root)
        json_object_put(root);
    if (!ok)
        content_provenance_reset();
    return ok ? 0 : -1;
}

int aegisxd_content_dns_provenance_ready(void)
{
    return content_provenance_ensure() == 0;
}

int aegisxd_content_installed_dns_rule_match(const char *domain,
                                             char kind[32], char source_id[64],
                                             char matched_rule[254])
{
    char normalized[254];
    char *candidate;

    if (kind)
        kind[0] = '\0';
    if (source_id)
        source_id[0] = '\0';
    if (matched_rule)
        matched_rule[0] = '\0';
    if (!domain || strlen(domain) >= sizeof(normalized))
        return 0;
    snprintf(normalized, sizeof(normalized), "%s", domain);
    for (char *p = normalized; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    while (normalized[0] && normalized[strlen(normalized) - 1] == '.')
        normalized[strlen(normalized) - 1] = '\0';
    if (!content_domain_ok(normalized) || content_provenance_ensure() != 0)
        return 0;
    candidate = normalized;
    while (candidate && candidate[0]) {
        struct content_provenance_rule key = { 0 };
        struct content_provenance_rule *match;

        snprintf(key.domain, sizeof(key.domain), "%s", candidate);
        match = bsearch(&key, g_content_provenance.rules,
                        g_content_provenance.count,
                        sizeof(*g_content_provenance.rules),
                        content_provenance_cmp);
        if (match) {
            if (kind)
                snprintf(kind, 32, "%s", match->kind);
            if (source_id)
                snprintf(source_id, 64, "%s", match->source_id);
            if (matched_rule)
                snprintf(matched_rule, 254, "%s", match->domain);
            return 1;
        }
        candidate = strchr(candidate, '.');
        if (candidate)
            candidate++;
    }
    return 0;
}

static int content_json_empty_array(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    return !o || !json_object_object_get_ex(o, key, &v) ||
        (json_object_is_type(v, json_type_array) && json_object_array_length(v) == 0);
}

static int content_safe_search_provider_enabled(const struct content_safe_search *safe,
                                                const char *provider)
{
    if (!safe || !provider)
        return 0;
    if (!strcmp(provider, "google"))
        return safe->google;
    if (!strcmp(provider, "bing"))
        return safe->bing;
    if (!strcmp(provider, "youtube"))
        return safe->youtube;
    return 0;
}

static int content_safe_search_parse(struct json_object *safe,
                                     struct content_safe_search *out,
                                     const char **error)
{
    struct json_object *value = NULL;

    if (out)
        memset(out, 0, sizeof(*out));
    if (!safe)
        return 0;
    if (!json_object_is_type(safe, json_type_object)) {
        if (error)
            *error = "invalid_safe_search";
        return -1;
    }
    json_object_object_foreach(safe, key, item) {
        if (strcmp(key, "google") && strcmp(key, "bing") &&
            strcmp(key, "youtube")) {
            if (error)
                *error = "invalid_safe_search_field";
            return -1;
        }
        if (!json_object_is_type(item, json_type_boolean)) {
            if (error)
                *error = "invalid_safe_search_value";
            return -1;
        }
    }
    if (!out)
        return 0;
    if (json_object_object_get_ex(safe, "google", &value))
        out->google = json_object_get_boolean(value);
    if (json_object_object_get_ex(safe, "bing", &value))
        out->bing = json_object_get_boolean(value);
    if (json_object_object_get_ex(safe, "youtube", &value))
        out->youtube = json_object_get_boolean(value);
    return 0;
}

static int content_safe_search_rule_count(const struct content_safe_search *safe)
{
    int count = 0;

    for (size_t i = 0; i < ARRAY_SIZE(content_safe_search_hosts); i++)
        if (content_safe_search_provider_enabled(safe,
                                                content_safe_search_hosts[i].provider))
            count++;
    return count;
}

static int content_safe_search_provider_count(const struct content_safe_search *safe)
{
    return safe ? !!safe->google + !!safe->bing + !!safe->youtube : 0;
}

static struct json_object *content_safe_search_state_json(
    const struct content_safe_search *safe, int policy_count)
{
    struct json_object *state = json_object_new_object();
    struct json_object *providers = json_object_new_object();
    struct json_object *enabled = json_object_new_array();

    json_object_object_add(providers, "google",
                           json_object_new_boolean(safe && safe->google));
    json_object_object_add(providers, "bing",
                           json_object_new_boolean(safe && safe->bing));
    json_object_object_add(providers, "youtube",
                           json_object_new_boolean(safe && safe->youtube));
    if (safe && safe->google)
        json_object_array_add(enabled, json_object_new_string("google"));
    if (safe && safe->bing)
        json_object_array_add(enabled, json_object_new_string("bing"));
    if (safe && safe->youtube)
        json_object_array_add(enabled, json_object_new_string("youtube"));
    json_object_object_add(state, "providers", providers);
    json_object_object_add(state, "enabled_providers", enabled);
    json_object_object_add(state, "provider_count",
                           json_object_new_int(content_safe_search_provider_count(safe)));
    json_object_object_add(state, "rule_count",
                           json_object_new_int(content_safe_search_rule_count(safe)));
    json_object_object_add(state, "active_policy_count",
                           json_object_new_int(policy_count < 0 ? 0 : policy_count));
    aegisxd_json_add_string(state, "merge", "logical_or");
    return state;
}

static int content_safe_search_effective(struct content_safe_search *safe,
                                         int *policy_count)
{
    sqlite3_stmt *st;
    int count = 0;

    if (safe)
        memset(safe, 0, sizeof(*safe));
    st = aegisxd_config_prepare(
        "SELECT safe_search_json,scope_json,schedule_json FROM aegis_content_policies "
        "WHERE enabled=1 AND mode<>'off' ORDER BY id");
    if (!st)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct content_safe_search parsed;
        struct json_object *value = json_tokener_parse(
            aegisxd_sqlite_text(st, 0, "{}"));
        struct json_object *scope = json_tokener_parse(
            aegisxd_sqlite_text(st, 1, "{}"));
        struct json_object *schedule = json_tokener_parse(
            aegisxd_sqlite_text(st, 2, "{}"));
        int global = scope && json_object_is_type(scope, json_type_object) &&
            !strcmp(aegisxd_json_str(scope, "type", "all"), "all") &&
            content_json_empty_array(scope, "devices") &&
            content_json_empty_array(scope, "networks");
        int always = schedule && json_object_is_type(schedule, json_type_object) &&
            !strcmp(aegisxd_json_str(schedule, "type", "always"), "always");

        count++;
        if (!value || !global || !always ||
            content_safe_search_parse(value, &parsed, NULL) != 0) {
            if (value)
                json_object_put(value);
            if (scope)
                json_object_put(scope);
            if (schedule)
                json_object_put(schedule);
            sqlite3_finalize(st);
            return -1;
        }
        if (safe) {
            safe->google |= parsed.google;
            safe->bing |= parsed.bing;
            safe->youtube |= parsed.youtube;
        }
        json_object_put(value);
        json_object_put(scope);
        json_object_put(schedule);
    }
    sqlite3_finalize(st);
    if (policy_count)
        *policy_count = count;
    return 0;
}

int aegisxd_content_safe_search_effective_values(int *google, int *bing,
                                                  int *youtube,
                                                  int *policy_count,
                                                  int *provider_count,
                                                  int *rule_count)
{
    struct content_safe_search safe;
    int policies = 0;

    if (content_safe_search_effective(&safe, &policies) != 0)
        return -1;
    if (google)
        *google = safe.google;
    if (bing)
        *bing = safe.bing;
    if (youtube)
        *youtube = safe.youtube;
    if (policy_count)
        *policy_count = policies;
    if (provider_count)
        *provider_count = content_safe_search_provider_count(&safe);
    if (rule_count)
        *rule_count = content_safe_search_rule_count(&safe);
    return 0;
}

static int content_safe_search_domain_claimed(const struct content_safe_search *safe,
                                              const char *domain)
{
    if (!safe || !domain)
        return 0;
    for (size_t i = 0; i < ARRAY_SIZE(content_safe_search_hosts); i++)
        if (content_domain_matches(content_safe_search_hosts[i].host, domain) &&
            content_safe_search_provider_enabled(safe,
                                                 content_safe_search_hosts[i].provider))
            return 1;
    return 0;
}

static struct json_object *content_canonical_object(struct json_object *body,
                                                     const char **error)
{
    struct json_object *out = json_object_new_object();
    struct json_object *scope = NULL, *safe = NULL, *schedule = NULL, *categories = NULL;
    struct json_object *copy;
    struct content_safe_search safe_values = { 0 };
    const char *id = aegisxd_json_str(body, "id", "");
    const char *name = aegisxd_json_str(body, "name", "");
    const char *mode = aegisxd_json_str(body, "mode", "basic");
    const char *scope_type = "all", *schedule_type = "always";
    int enabled = aegisxd_json_bool(body, "enabled", 1);
    int ad_block = aegisxd_json_bool(body, "ad_block", 0);

    *error = NULL;
    if (!content_id_ok(id)) *error = "invalid_content_policy_id";
    else if (!content_text_ok(name, 128, 1)) *error = "invalid_content_policy_name";
    else if (!content_mode_ok(mode)) *error = "invalid_content_policy_mode";
    if (body) json_object_object_get_ex(body, "scope", &scope);
    if (scope && !json_object_is_type(scope, json_type_object)) *error = "invalid_content_policy_scope";
    if (scope) scope_type = aegisxd_json_str(scope, "type", "all");
    if (!*error && (strcmp(scope_type, "all") || !content_json_empty_array(scope, "devices") ||
        !content_json_empty_array(scope, "networks"))) *error = "content_scope_not_supported";
    if (body) json_object_object_get_ex(body, "safe_search", &safe);
    if (!*error)
        (void)content_safe_search_parse(safe, &safe_values, error);
    if (body) json_object_object_get_ex(body, "schedule", &schedule);
    if (!*error && schedule && !json_object_is_type(schedule, json_type_object)) *error = "invalid_content_schedule";
    if (schedule) schedule_type = aegisxd_json_str(schedule, "type", "always");
    if (!*error && strcmp(schedule_type, "always")) *error = "content_schedule_not_supported";
    if (body) json_object_object_get_ex(body, "categories", &categories);
    if (!*error && categories && (!json_object_is_type(categories, json_type_array) ||
        json_object_array_length(categories) > 64)) *error = "invalid_content_categories";
    if (!*error && categories)
        for (size_t i = 0; i < json_object_array_length(categories); i++) {
            struct json_object *v = json_object_array_get_idx(categories, i);
            const char *s = v && json_object_is_type(v, json_type_string) ? json_object_get_string(v) : "";
            if (!content_id_ok(s)) { *error = "invalid_content_category"; break; }
        }
    json_object_object_add(out, "id", json_object_new_string(id));
    json_object_object_add(out, "name", json_object_new_string(name));
    json_object_object_add(out, "enabled", json_object_new_boolean(enabled));
    json_object_object_add(out, "mode", json_object_new_string(mode));
    copy = scope ? json_object_get(scope) : json_tokener_parse("{\"type\":\"all\",\"devices\":[],\"networks\":[]}");
    json_object_object_add(out, "scope", copy);
    json_object_object_add(out, "ad_block", json_object_new_boolean(ad_block));
    copy = json_object_new_object();
    json_object_object_add(copy, "google", json_object_new_boolean(safe_values.google));
    json_object_object_add(copy, "bing", json_object_new_boolean(safe_values.bing));
    json_object_object_add(copy, "youtube", json_object_new_boolean(safe_values.youtube));
    json_object_object_add(out, "safe_search", copy);
    copy = categories ? json_object_get(categories) : json_object_new_array();
    json_object_object_add(out, "categories", copy);
    copy = schedule ? json_object_get(schedule) : json_tokener_parse("{\"type\":\"always\"}");
    json_object_object_add(out, "schedule", copy);
    return out;
}

static struct json_object *content_capabilities(void)
{
    struct json_object *cap = json_object_new_object();
    json_object_object_add(cap, "content_policy_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "domain_overrides_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "ad_block_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "safe_search_supported", json_object_new_boolean(1));
    aegisxd_json_add_string(cap, "safe_search_providers", "google,bing,youtube");
    aegisxd_json_add_string(cap, "safe_search_merge", "logical_or");
    json_object_object_add(cap, "schedule_supported", json_object_new_boolean(0));
    json_object_object_add(cap, "all_scope_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "device_scope_supported", json_object_new_boolean(0));
    json_object_object_add(cap, "network_scope_supported", json_object_new_boolean(0));
    json_object_object_add(cap, "dataplane_apply_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "rollback_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "confirm_required", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_filter_supported", json_object_new_boolean(1));
    aegisxd_json_add_string(cap, "pcdn_default_mode", "block");
    json_object_object_add(cap, "pcdn_feed_update", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_guarded_apply", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_monitor_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_hit_monitoring_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_hit_count_supported", json_object_new_boolean(1));
    json_object_object_add(cap, "pcdn_hit_attribution_ready",
                           json_object_new_boolean(aegisxd_pcdn_hit_attribution_ready()));
    return cap;
}

static struct json_object *content_policy_row(sqlite3_stmt *st)
{
    struct json_object *o = json_object_new_object();
    struct json_object *v;
    aegisxd_json_add_string(o, "id", aegisxd_sqlite_text(st, 0, ""));
    aegisxd_json_add_string(o, "name", aegisxd_sqlite_text(st, 1, ""));
    json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 2)));
    aegisxd_json_add_string(o, "mode", aegisxd_sqlite_text(st, 3, "off"));
    v = json_tokener_parse(aegisxd_sqlite_text(st, 4, "{}")); json_object_object_add(o, "scope", v ? v : json_object_new_object());
    json_object_object_add(o, "ad_block", json_object_new_boolean(sqlite3_column_int(st, 5)));
    v = json_tokener_parse(aegisxd_sqlite_text(st, 6, "{}")); json_object_object_add(o, "safe_search", v ? v : json_object_new_object());
    v = json_tokener_parse(aegisxd_sqlite_text(st, 7, "[]")); json_object_object_add(o, "categories", v ? v : json_object_new_array());
    v = json_tokener_parse(aegisxd_sqlite_text(st, 8, "{}")); json_object_object_add(o, "schedule", v ? v : json_object_new_object());
    json_object_object_add(o, "revision", json_object_new_int(sqlite3_column_int(st, 9)));
    aegisxd_json_add_string(o, "apply_state", aegisxd_sqlite_text(st, 10, "pending"));
    aegisxd_json_add_string(o, "last_error", aegisxd_sqlite_text(st, 11, ""));
    json_object_object_add(o, "created_at", json_object_new_int64(sqlite3_column_int64(st, 12)));
    json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 13)));
    return o;
}

struct json_object *aegisxd_content_runtime_json(void)
{
    struct json_object *o = json_object_new_object();
    struct json_object *safe = json_object_new_object();
    struct json_object *active_root = NULL, *active_safe = NULL;
    struct content_safe_search configured_safe;
    int safe_policy_count = 0;
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT managed,revision,last_apply_state,last_error,updated_at FROM aegis_content_meta WHERE id=1");
    int managed = 0, revision = 0, active; const char *state = "unmanaged", *error = ""; int64_t updated = 0;
    if (st && sqlite3_step(st) == SQLITE_ROW) {
        managed = sqlite3_column_int(st, 0); revision = sqlite3_column_int(st, 1);
        state = aegisxd_sqlite_text(st, 2, "unmanaged"); error = aegisxd_sqlite_text(st, 3, "");
        updated = sqlite3_column_int64(st, 4);
        json_object_object_add(o, "managed", json_object_new_boolean(managed));
        json_object_object_add(o, "revision", json_object_new_int(revision));
        aegisxd_json_add_string(o, "apply_state", state); aegisxd_json_add_string(o, "last_error", error);
        json_object_object_add(o, "updated_at", json_object_new_int64(updated));
    } else json_object_object_add(o, "managed", json_object_new_boolean(0));
    if (st) sqlite3_finalize(st);
    active = access(AEGISXD_RUNTIME_DIR "/active.json", F_OK) == 0;
    json_object_object_add(o, "active", json_object_new_boolean(active));
    json_object_object_add(o, "legacy_compatibility_active",
                           json_object_new_boolean(!managed && active));
    if (content_safe_search_effective(&configured_safe, &safe_policy_count) == 0) {
        json_object_object_add(safe, "configured",
                               content_safe_search_state_json(&configured_safe,
                                                              safe_policy_count));
        json_object_object_add(safe, "configuration_valid", json_object_new_boolean(1));
    } else {
        memset(&configured_safe, 0, sizeof(configured_safe));
        json_object_object_add(safe, "configured",
                               content_safe_search_state_json(&configured_safe, 0));
        json_object_object_add(safe, "configuration_valid", json_object_new_boolean(0));
        aegisxd_json_add_string(safe, "configuration_error",
                                "invalid_persisted_safe_search");
    }
    active_root = active ? json_object_from_file(AEGISXD_RUNTIME_DIR "/active.json") : NULL;
    if (active_root && json_object_is_type(active_root, json_type_object) &&
        json_object_object_get_ex(active_root, "safe_search", &active_safe) &&
        json_object_is_type(active_safe, json_type_object))
        json_object_object_add(safe, "active", json_object_get(active_safe));
    else {
        struct content_safe_search inactive_safe = { 0 };
        json_object_object_add(safe, "active",
                               content_safe_search_state_json(&inactive_safe, 0));
    }
    if (active_root)
        json_object_put(active_root);
    json_object_object_add(safe, "installed", json_object_new_boolean(active));
    aegisxd_json_add_string(safe, "readback_source",
                            AEGISXD_RUNTIME_DIR "/active.json");
    json_object_object_add(o, "safe_search", safe);
    json_object_object_add(o, "pcdn", aegisxd_pcdn_get_json());
    aegisxd_json_add_string(o, "source", "config.db:aegis_content_meta+runtime_active_json");
    return o;
}

struct json_object *aegisxd_content_policies_json(struct json_object *body)
{
    struct json_object *resp = json_object_new_object(), *items = json_object_new_array();
    const char *id = aegisxd_json_str(body, "id", "");
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT id,name,enabled,mode,scope_json,ad_block,safe_search_json,categories_json,schedule_json,"
        "revision,apply_state,last_error,created_at,updated_at FROM aegis_content_policies "
        "WHERE (?1='' OR id=?1) ORDER BY updated_at DESC,id");
    if (st) sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    while (st && sqlite3_step(st) == SQLITE_ROW) json_object_array_add(items, content_policy_row(st));
    if (st) sqlite3_finalize(st);
    if (id[0] && json_object_array_length(items) == 0) {
        json_object_put(resp);
        json_object_put(items);
        return aegisxd_error("content_policy_not_found", "content policy does not exist");
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "items", items); json_object_object_add(resp, "total", json_object_new_int((int)json_object_array_length(items)));
    json_object_object_add(resp, "runtime", aegisxd_content_runtime_json());
    json_object_object_add(resp, "capabilities", content_capabilities());
    return resp;
}

struct json_object *aegisxd_content_policy_validate_json(struct json_object *body)
{
    const char *error = NULL; struct json_object *policy = content_canonical_object(body, &error);
    struct json_object *resp = json_object_new_object(), *blockers = json_object_new_array();
    if (error) json_object_array_add(blockers, json_object_new_string(error));
    json_object_object_add(resp, "ok", json_object_new_boolean(!error));
    json_object_object_add(resp, "valid", json_object_new_boolean(!error));
    json_object_object_add(resp, "dry_run", json_object_new_boolean(1));
    json_object_object_add(resp, "confirm_required", json_object_new_boolean(1));
    json_object_object_add(resp, "changed", json_object_new_boolean(0));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
    json_object_object_add(resp, "policy", policy); json_object_object_add(resp, "blockers", blockers);
    if (error) aegisxd_json_add_string(resp, "error", error);
    json_object_object_add(resp, "capabilities", content_capabilities());
    return resp;
}

static int content_apply_requested(struct json_object *body, struct json_object **result)
{
    struct json_object *req = json_object_new_object();
    struct json_object *blockers = NULL;
    int empty = 0, ok;

    json_object_object_add(req, "confirm", json_object_new_boolean(1));
    aegisxd_json_add_string(req, "operation", "apply");
    aegisxd_json_add_string(req, "scope", "dns_filter");
    aegisxd_json_add_string(req, "requested_by", "content_policy");
    json_object_object_add(req, "force", json_object_new_boolean(1));
    *result = aegisxd_apply(req);
    ok = aegisxd_json_bool(*result, "ok", 0);
    if (!ok && json_object_object_get_ex(*result, "blockers", &blockers) &&
        json_object_is_type(blockers, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(blockers); i++) {
            struct json_object *v = json_object_array_get_idx(blockers, i);
            if (v && json_object_is_type(v, json_type_string) &&
                !strcmp(json_object_get_string(v), "dnsmasq_rules_empty")) {
                empty = 1;
                break;
            }
        }
    }
    if (empty) {
        json_object_put(*result);
        json_object_object_del(req, "force");
        json_object_object_del(req, "requested_by");
        json_object_object_del(req, "operation");
        aegisxd_json_add_string(req, "operation", "disable");
        *result = aegisxd_apply(req);
        ok = aegisxd_json_bool(*result, "ok", 0);
    }
    json_object_put(req);
    return ok ? 0 : -1;
}

static int content_resource_count(void)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT (SELECT COUNT(*) FROM aegis_content_policies)+"
        "(SELECT COUNT(*) FROM aegis_domain_overrides)+"
        "(SELECT COUNT(*) FROM aegis_pcdn_settings WHERE enabled=1)");
    int count = -1;

    if (st && sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    if (st)
        sqlite3_finalize(st);
    return count;
}

static int content_managed(void)
{
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT managed FROM aegis_content_meta WHERE id=1");
    int managed = 0;

    if (st && sqlite3_step(st) == SQLITE_ROW)
        managed = sqlite3_column_int(st, 0);
    if (st)
        sqlite3_finalize(st);
    return managed;
}

static int content_meta_mark(const char *state, const char *error)
{
    int resources = content_resource_count();
    int managed;
    sqlite3_stmt *st = aegisxd_config_prepare(
        "UPDATE aegis_content_meta SET managed=?1,revision=revision+1,"
        "last_apply_state=?2,last_error=?3,updated_at=?4 WHERE id=1");
    int rc;

    if (resources < 0 || !st) {
        if (st)
            sqlite3_finalize(st);
        return -1;
    }
    managed = resources > 0;
    sqlite3_bind_int(st, 1, managed);
    sqlite3_bind_text(st, 2, state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, aegisxd_now_s());
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static const char *content_apply_success_state(struct json_object *apply)
{
    if (!content_managed())
        return "legacy";
    return aegisxd_json_bool(apply, "applied", 0) ? "active" : "disabled";
}

static int content_apply_changed(struct json_object *apply)
{
    return apply && aegisxd_json_bool(apply, "dataplane_changed", 0);
}

static int content_apply_state_set(const char *state, const char *error)
{
    static const char *updates[] = {
        "UPDATE aegis_content_meta SET last_apply_state=?1,last_error=?2,updated_at=?3 WHERE id=1",
        "UPDATE aegis_content_policies SET apply_state=CASE "
            "WHEN enabled=0 OR mode='off' THEN 'disabled' ELSE ?1 END,"
            "last_error=?2,updated_at=?3",
        "UPDATE aegis_domain_overrides SET apply_state=CASE "
            "WHEN enabled=0 THEN 'disabled' ELSE ?1 END,last_error=?2,updated_at=?3",
    };

    for (size_t i = 0; i < ARRAY_SIZE(updates); i++) {
        sqlite3_stmt *st = aegisxd_config_prepare(updates[i]);
        int rc;
        if (!st) return -1;
        sqlite3_bind_text(st, 1, state, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, error ? error : "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, aegisxd_now_s());
        rc = sqlite3_step(st); sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

struct json_object *aegisxd_content_policy_set_json(struct json_object *body)
{
    struct json_object *validation = aegisxd_content_policy_validate_json(body), *policy = NULL, *apply = NULL;
    const char *id, *name, *mode; struct json_object *scope, *safe, *categories, *schedule;
    char stable_id[96];
    int enabled, ad_block, confirm = aegisxd_json_bool(body, "confirm", 0), do_apply = aegisxd_json_bool(body, "apply", 0), rc;
    sqlite3_stmt *st;
    if (!aegisxd_json_bool(validation, "ok", 0) || !confirm) return validation;
    json_object_object_get_ex(validation, "policy", &policy); id = aegisxd_json_str(policy, "id", "");
    snprintf(stable_id, sizeof(stable_id), "%s", id);
    name = aegisxd_json_str(policy, "name", ""); mode = aegisxd_json_str(policy, "mode", "basic");
    enabled = aegisxd_json_bool(policy, "enabled", 1); ad_block = aegisxd_json_bool(policy, "ad_block", 0);
    json_object_object_get_ex(policy, "scope", &scope); json_object_object_get_ex(policy, "safe_search", &safe);
    json_object_object_get_ex(policy, "categories", &categories); json_object_object_get_ex(policy, "schedule", &schedule);
    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        json_object_put(validation); return aegisxd_error("storage_error", "content policy transaction could not start");
    }
    st = aegisxd_config_prepare(
        "INSERT INTO aegis_content_policies(id,name,enabled,mode,scope_json,ad_block,safe_search_json,categories_json,schedule_json,revision,apply_state,last_error,created_at,updated_at) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,1,?10,'',?11,?11) ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,mode=excluded.mode,"
        "scope_json=excluded.scope_json,ad_block=excluded.ad_block,safe_search_json=excluded.safe_search_json,categories_json=excluded.categories_json,schedule_json=excluded.schedule_json,"
        "revision=aegis_content_policies.revision+1,apply_state=excluded.apply_state,last_error='',updated_at=excluded.updated_at");
    if (!st) goto rollback;
    sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,2,name,-1,SQLITE_TRANSIENT); sqlite3_bind_int(st,3,enabled);
    sqlite3_bind_text(st,4,mode,-1,SQLITE_TRANSIENT); sqlite3_bind_text(st,5,json_object_to_json_string_ext(scope,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    sqlite3_bind_int(st,6,ad_block); sqlite3_bind_text(st,7,json_object_to_json_string_ext(safe,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,8,json_object_to_json_string_ext(categories,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,9,json_object_to_json_string_ext(schedule,JSON_C_TO_STRING_PLAIN),-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,10,do_apply?"applying":"pending",-1,SQLITE_STATIC); sqlite3_bind_int64(st,11,aegisxd_now_s());
    rc=sqlite3_step(st); sqlite3_finalize(st); if(rc!=SQLITE_DONE) goto rollback;
    if (content_meta_mark(do_apply ? "applying" : "pending", "") != 0) goto rollback;
    if (do_apply && content_apply_requested(body, &apply) != 0) goto rollback_apply;
    if (do_apply && content_apply_state_set(content_apply_success_state(apply), "") != 0)
        goto rollback_apply;
    if (sqlite3_exec(g_aegisxd_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) goto rollback_apply;
    json_object_put(validation); validation = aegisxd_content_policies_json(NULL);
    json_object_object_add(validation,"changed",json_object_new_boolean(1)); json_object_object_add(validation,"dataplane_changed",json_object_new_boolean(content_apply_changed(apply)));
    aegisxd_json_add_string(validation,"id",stable_id); if(apply) json_object_object_add(validation,"apply",apply);
    return validation;
rollback_apply:
    if (apply) json_object_put(apply);
rollback:
    sqlite3_exec(g_aegisxd_config_db,"ROLLBACK",NULL,NULL,NULL);
    if (do_apply) {
        struct json_object *restore = NULL;
        (void)content_apply_requested(body, &restore);
        if (restore) json_object_put(restore);
    }
    json_object_put(validation);
    validation=aegisxd_error("content_policy_apply_failed","content policy was not committed and the previous configuration remains authoritative");
    json_object_object_add(validation,"rollback_ok",json_object_new_boolean(1)); return validation;
}

struct json_object *aegisxd_content_policy_delete_json(struct json_object *body)
{
    const char *id = aegisxd_json_str(body, "id", "");
    int confirm = aegisxd_json_bool(body, "confirm", 0);
    int do_apply = aegisxd_json_bool(body, "apply", 0);
    int exists = 0;
    sqlite3_stmt *st;
    struct json_object *resp, *apply = NULL;

    if (!content_id_ok(id))
        return aegisxd_error("invalid_content_policy_id", "content policy id is invalid");
    st = aegisxd_config_prepare("SELECT 1 FROM aegis_content_policies WHERE id=?1");
    if (st) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        exists = sqlite3_step(st) == SQLITE_ROW;
        sqlite3_finalize(st);
    }
    if (!exists)
        return aegisxd_error("content_policy_not_found", "content policy does not exist");
    if (!confirm) {
        resp = json_object_new_object();
        json_object_object_add(resp, "ok", json_object_new_boolean(1));
        json_object_object_add(resp, "dry_run", json_object_new_boolean(1));
        json_object_object_add(resp, "confirm_required", json_object_new_boolean(1));
        json_object_object_add(resp, "changed", json_object_new_boolean(0));
        json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(0));
        return resp;
    }
    if (sqlite3_exec(g_aegisxd_config_db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return aegisxd_error("storage_error", "content policy transaction could not start");
    st = aegisxd_config_prepare("DELETE FROM aegis_domain_overrides WHERE policy_id=?1");
    if (!st)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!exists)
        goto rollback;
    st = aegisxd_config_prepare("DELETE FROM aegis_content_policies WHERE id=?1");
    if (!st)
        goto rollback;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!exists || content_meta_mark(do_apply ? "applying" : "pending", "") != 0)
        goto rollback;
    if (do_apply && content_apply_requested(body, &apply) != 0)
        goto rollback_apply;
    if (do_apply && content_apply_state_set(content_apply_success_state(apply), "") != 0)
        goto rollback_apply;
    if (sqlite3_exec(g_aegisxd_config_db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        goto rollback_apply;
    resp = aegisxd_content_policies_json(NULL);
    json_object_object_add(resp, "changed", json_object_new_boolean(1));
    json_object_object_add(resp, "dataplane_changed", json_object_new_boolean(content_apply_changed(apply)));
    aegisxd_json_add_string(resp, "id", id);
    aegisxd_json_add_string(resp, "action", "deleted");
    if (apply)
        json_object_object_add(resp, "apply", apply);
    return resp;

rollback_apply:
    if (apply)
        json_object_put(apply);
rollback:
    sqlite3_exec(g_aegisxd_config_db, "ROLLBACK", NULL, NULL, NULL);
    if (do_apply) {
        struct json_object *restore = NULL;
        (void)content_apply_requested(body, &restore);
        if (restore)
            json_object_put(restore);
    }
    resp = aegisxd_error("content_policy_delete_failed",
                         "delete failed; previous configuration remains authoritative");
    json_object_object_add(resp, "rollback_ok", json_object_new_boolean(1));
    return resp;
}

static struct json_object *content_override_row(sqlite3_stmt *st)
{
    struct json_object *o=json_object_new_object();aegisxd_json_add_string(o,"id",aegisxd_sqlite_text(st,0,""));aegisxd_json_add_string(o,"policy_id",aegisxd_sqlite_text(st,1,""));aegisxd_json_add_string(o,"domain",aegisxd_sqlite_text(st,2,""));aegisxd_json_add_string(o,"action",aegisxd_sqlite_text(st,3,""));json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,4)));aegisxd_json_add_string(o,"note",aegisxd_sqlite_text(st,5,""));aegisxd_json_add_string(o,"apply_state",aegisxd_sqlite_text(st,6,"pending"));aegisxd_json_add_string(o,"last_error",aegisxd_sqlite_text(st,7,""));json_object_object_add(o,"created_at",json_object_new_int64(sqlite3_column_int64(st,8)));json_object_object_add(o,"updated_at",json_object_new_int64(sqlite3_column_int64(st,9)));return o;
}

struct json_object *aegisxd_domain_overrides_json(struct json_object *body)
{
    struct json_object *resp = json_object_new_object();
    struct json_object *items = json_object_new_array();
    const char *id = aegisxd_json_str(body, "id", "");
    sqlite3_stmt *st = aegisxd_config_prepare(
        "SELECT id,policy_id,domain,action,enabled,note,apply_state,last_error,created_at,updated_at "
        "FROM aegis_domain_overrides WHERE (?1='' OR id=?1) ORDER BY domain");

    if (st)
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    while (st && sqlite3_step(st) == SQLITE_ROW)
        json_object_array_add(items, content_override_row(st));
    if (st)
        sqlite3_finalize(st);
    if (id[0] && json_object_array_length(items) == 0) {
        json_object_put(resp);
        json_object_put(items);
        return aegisxd_error("domain_override_not_found", "domain override does not exist");
    }
    json_object_object_add(resp, "ok", json_object_new_boolean(1));
    json_object_object_add(resp, "items", items);
    json_object_object_add(resp, "total",
                           json_object_new_int((int)json_object_array_length(items)));
    json_object_object_add(resp, "runtime", aegisxd_content_runtime_json());
    json_object_object_add(resp, "capabilities", content_capabilities());
    return resp;
}

struct json_object *aegisxd_domain_override_set_json(struct json_object *body)
{
    char domain[256],generated[96],existing_id[96]="";const char *id=aegisxd_json_str(body,"id","");const char *policy_id=aegisxd_json_str(body,"policy_id","");const char *action=aegisxd_json_str(body,"action","");const char *note=aegisxd_json_str(body,"note","");int enabled=aegisxd_json_bool(body,"enabled",1),confirm=aegisxd_json_bool(body,"confirm",0),do_apply=aegisxd_json_bool(body,"apply",0),rc;sqlite3_stmt *st;struct json_object *resp,*apply=NULL;uint64_t hash=1469598103934665603ULL;
    content_domain_normalize(domain,sizeof(domain),aegisxd_json_str(body,"domain",""));if(!content_domain_ok(domain))return aegisxd_error("invalid_domain","domain override is invalid");if(strcmp(action,"allow")&&strcmp(action,"block"))return aegisxd_error("invalid_domain_override_action","action must be allow or block");if(policy_id[0]&&!content_id_ok(policy_id))return aegisxd_error("invalid_content_policy_id","policy id is invalid");if(!content_text_ok(note,256,0))return aegisxd_error("invalid_note","domain override note is invalid");if(!id[0]){for(const unsigned char *p=(const unsigned char*)policy_id;*p;p++){hash^=*p;hash*=1099511628211ULL;}hash^=(unsigned char)'|';hash*=1099511628211ULL;for(const unsigned char *p=(const unsigned char*)domain;*p;p++){hash^=*p;hash*=1099511628211ULL;}snprintf(generated,sizeof(generated),"domain-override-%016" PRIx64,hash);id=generated;}if(!content_id_ok(id))return aegisxd_error("invalid_domain_override_id","domain override id is invalid");
    if(policy_id[0]){int policy_exists=0;st=aegisxd_config_prepare("SELECT 1 FROM aegis_content_policies WHERE id=?1");if(st){sqlite3_bind_text(st,1,policy_id,-1,SQLITE_TRANSIENT);policy_exists=sqlite3_step(st)==SQLITE_ROW;sqlite3_finalize(st);}if(!policy_exists)return aegisxd_error("content_policy_not_found","domain override policy does not exist");}
    st=aegisxd_config_prepare("SELECT id FROM aegis_domain_overrides WHERE policy_id=?1 AND domain=?2 LIMIT 1");if(st){sqlite3_bind_text(st,1,policy_id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,domain,-1,SQLITE_TRANSIENT);if(sqlite3_step(st)==SQLITE_ROW)snprintf(existing_id,sizeof(existing_id),"%s",aegisxd_sqlite_text(st,0,""));sqlite3_finalize(st);}if(existing_id[0]&&strcmp(existing_id,id))return aegisxd_error("domain_override_conflict","domain already has an override in this policy; update the existing resource id");
    if(!confirm){resp=json_object_new_object();json_object_object_add(resp,"ok",json_object_new_boolean(1));json_object_object_add(resp,"valid",json_object_new_boolean(1));json_object_object_add(resp,"dry_run",json_object_new_boolean(1));json_object_object_add(resp,"confirm_required",json_object_new_boolean(1));json_object_object_add(resp,"changed",json_object_new_boolean(0));json_object_object_add(resp,"dataplane_changed",json_object_new_boolean(0));aegisxd_json_add_string(resp,"id",id);aegisxd_json_add_string(resp,"domain",domain);aegisxd_json_add_string(resp,"action",action);return resp;}
    if(sqlite3_exec(g_aegisxd_config_db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return aegisxd_error("storage_error","domain override transaction could not start");
    st=aegisxd_config_prepare("INSERT INTO aegis_domain_overrides(id,policy_id,domain,action,enabled,note,apply_state,last_error,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,'',?8,?8) ON CONFLICT(id) DO UPDATE SET policy_id=excluded.policy_id,domain=excluded.domain,action=excluded.action,enabled=excluded.enabled,note=excluded.note,apply_state=excluded.apply_state,last_error='',updated_at=excluded.updated_at");if(!st)goto rollback;sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,policy_id,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,domain,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,action,-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,5,enabled);sqlite3_bind_text(st,6,note,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,do_apply?"applying":"pending",-1,SQLITE_STATIC);sqlite3_bind_int64(st,8,aegisxd_now_s());rc=sqlite3_step(st);sqlite3_finalize(st);if(rc!=SQLITE_DONE||content_meta_mark(do_apply?"applying":"pending","")!=0)goto rollback;if(do_apply&&content_apply_requested(body,&apply)!=0)goto rollback_apply;if(do_apply&&content_apply_state_set(content_apply_success_state(apply),"")!=0)goto rollback_apply;if(sqlite3_exec(g_aegisxd_config_db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto rollback_apply;
    resp=aegisxd_domain_overrides_json(NULL);json_object_object_add(resp,"changed",json_object_new_boolean(1));json_object_object_add(resp,"dataplane_changed",json_object_new_boolean(content_apply_changed(apply)));aegisxd_json_add_string(resp,"id",id);if(apply)json_object_object_add(resp,"apply",apply);return resp;
rollback_apply:if(apply)json_object_put(apply);
rollback:sqlite3_exec(g_aegisxd_config_db,"ROLLBACK",NULL,NULL,NULL);if(do_apply){struct json_object *restore=NULL;(void)content_apply_requested(body,&restore);if(restore)json_object_put(restore);}resp=aegisxd_error("domain_override_apply_failed","domain override was not committed; previous configuration remains authoritative");json_object_object_add(resp,"rollback_ok",json_object_new_boolean(1));return resp;
}

struct json_object *aegisxd_domain_override_delete_json(struct json_object *body)
{
    const char *id=aegisxd_json_str(body,"id","");int confirm=aegisxd_json_bool(body,"confirm",0),do_apply=aegisxd_json_bool(body,"apply",0),exists=0;sqlite3_stmt *st;struct json_object *resp,*apply=NULL;if(!content_id_ok(id))return aegisxd_error("invalid_domain_override_id","domain override id is invalid");st=aegisxd_config_prepare("SELECT 1 FROM aegis_domain_overrides WHERE id=?1");if(st){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);exists=sqlite3_step(st)==SQLITE_ROW;sqlite3_finalize(st);}if(!exists)return aegisxd_error("domain_override_not_found","domain override does not exist");if(!confirm){resp=json_object_new_object();json_object_object_add(resp,"ok",json_object_new_boolean(1));json_object_object_add(resp,"dry_run",json_object_new_boolean(1));json_object_object_add(resp,"confirm_required",json_object_new_boolean(1));json_object_object_add(resp,"changed",json_object_new_boolean(0));json_object_object_add(resp,"dataplane_changed",json_object_new_boolean(0));return resp;}if(sqlite3_exec(g_aegisxd_config_db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)return aegisxd_error("storage_error","domain override transaction could not start");st=aegisxd_config_prepare("DELETE FROM aegis_domain_overrides WHERE id=?1");if(!st)goto rollback;sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);exists=sqlite3_step(st)==SQLITE_DONE;sqlite3_finalize(st);if(!exists||content_meta_mark(do_apply?"applying":"pending","")!=0)goto rollback;if(do_apply&&content_apply_requested(body,&apply)!=0)goto rollback_apply;if(do_apply&&content_apply_state_set(content_apply_success_state(apply),"")!=0)goto rollback_apply;if(sqlite3_exec(g_aegisxd_config_db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK)goto rollback_apply;resp=aegisxd_domain_overrides_json(NULL);json_object_object_add(resp,"changed",json_object_new_boolean(1));json_object_object_add(resp,"dataplane_changed",json_object_new_boolean(content_apply_changed(apply)));aegisxd_json_add_string(resp,"id",id);aegisxd_json_add_string(resp,"action","deleted");if(apply)json_object_object_add(resp,"apply",apply);return resp;
rollback_apply:if(apply)json_object_put(apply);
rollback:sqlite3_exec(g_aegisxd_config_db,"ROLLBACK",NULL,NULL,NULL);if(do_apply){struct json_object *restore=NULL;(void)content_apply_requested(body,&restore);if(restore)json_object_put(restore);}resp=aegisxd_error("domain_override_delete_failed","delete failed; previous configuration remains authoritative");json_object_object_add(resp,"rollback_ok",json_object_new_boolean(1));return resp;
}

void *aegisxd_content_filter_load(void)
{
    struct content_filter *f=calloc(1,sizeof(*f));sqlite3_stmt *st;if(!f)return NULL;st=aegisxd_config_prepare("SELECT managed FROM aegis_content_meta WHERE id=1");if(st&&sqlite3_step(st)==SQLITE_ROW)f->managed=sqlite3_column_int(st,0);if(st)sqlite3_finalize(st);if(!f->managed)return f;
    st=aegisxd_config_prepare("SELECT mode,ad_block,categories_json,safe_search_json,scope_json,schedule_json FROM aegis_content_policies WHERE enabled=1 AND mode<>'off' ORDER BY id");if(!st){free(f);return NULL;}while(sqlite3_step(st)==SQLITE_ROW){const char *mode=aegisxd_sqlite_text(st,0,"");struct json_object *arr=json_tokener_parse(aegisxd_sqlite_text(st,2,"[]"));struct json_object *safe=json_tokener_parse(aegisxd_sqlite_text(st,3,"{}"));struct json_object *scope=json_tokener_parse(aegisxd_sqlite_text(st,4,"{}"));struct json_object *schedule=json_tokener_parse(aegisxd_sqlite_text(st,5,"{}"));struct content_safe_search parsed;int global=scope&&json_object_is_type(scope,json_type_object)&&!strcmp(aegisxd_json_str(scope,"type","all"),"all")&&content_json_empty_array(scope,"devices")&&content_json_empty_array(scope,"networks");int always=schedule&&json_object_is_type(schedule,json_type_object)&&!strcmp(aegisxd_json_str(schedule,"type","always"),"always");if(!safe||!global||!always||content_safe_search_parse(safe,&parsed,NULL)!=0){if(arr)json_object_put(arr);if(safe)json_object_put(safe);if(scope)json_object_put(scope);if(schedule)json_object_put(schedule);sqlite3_finalize(st);aegisxd_content_filter_free(f);return NULL;}f->policy_count++;f->safe_search.google|=parsed.google;f->safe_search.bing|=parsed.bing;f->safe_search.youtube|=parsed.youtube;if(!strcmp(mode,"enhanced"))f->enhanced=1;if(sqlite3_column_int(st,1))f->ad_block=1;if(arr&&json_object_is_type(arr,json_type_array))for(size_t i=0;i<json_object_array_length(arr);i++){struct json_object *v=json_object_array_get_idx(arr,i);if(v&&json_object_is_type(v,json_type_string))content_list_add(&f->categories,json_object_get_string(v));}if(arr)json_object_put(arr);json_object_put(safe);json_object_put(scope);json_object_put(schedule);}sqlite3_finalize(st);
    st=aegisxd_config_prepare("SELECT domain,action FROM aegis_domain_overrides WHERE enabled=1 ORDER BY domain");while(st&&sqlite3_step(st)==SQLITE_ROW){const char *d=aegisxd_sqlite_text(st,0,"");const char *a=aegisxd_sqlite_text(st,1,"");if(!strcmp(a,"allow"))content_list_add(&f->allows,d);else if(!strcmp(a,"block"))content_list_add(&f->blocks,d);}if(st)sqlite3_finalize(st);
    return f;
}

void aegisxd_content_filter_free(void *opaque)
{
    struct content_filter *f=opaque;if(!f)return;content_list_free(&f->categories);content_list_free(&f->allows);content_list_free(&f->blocks);content_list_free(&f->emitted_blocks);content_list_free(&f->emitted_categories);free(f);
}

int aegisxd_content_filter_domain_blocked(void *opaque,const char *domain,const char *category,int reputation)
{
    struct content_filter *f=opaque;int blocked=0;if(!f)return 0;if(!f->managed)blocked=1;else if(content_safe_search_domain_claimed(&f->safe_search,domain))blocked=0;else if(content_domain_list_matches(&f->allows,domain))blocked=0;else if(content_domain_list_matches(&f->blocks,domain))blocked=1;else if(!f->policy_count)blocked=0;else if(f->enhanced)blocked=1;else if(category&&content_list_has(&f->categories,category))blocked=1;else if(f->ad_block&&category&&(strstr(category,"ads")||strstr(category,"track")))blocked=1;(void)reputation;if(blocked&&content_list_has(&f->blocks,domain))(void)content_list_add(&f->emitted_blocks,domain);return blocked;
}

int aegisxd_content_filter_domain_explicitly_blocked(void *opaque,
                                                      const char *domain)
{
    struct content_filter *f = opaque;

    return f && content_domain_list_matches(&f->blocks, domain) &&
        !content_domain_list_matches(&f->allows, domain) &&
        !content_safe_search_domain_claimed(&f->safe_search, domain);
}

int aegisxd_content_filter_mark_category_emitted(void *opaque,
                                                  const char *domain)
{
    struct content_filter *f = opaque;

    return f ? content_list_add(&f->emitted_categories, domain) : -1;
}

static int content_pcdn_allow_cb(const char *domain, void *opaque)
{
    struct content_filter *f = opaque;

    return f && (content_safe_search_domain_claimed(&f->safe_search, domain) ||
                 content_domain_list_matches(&f->allows, domain) ||
                 content_domain_list_matches(&f->blocks, domain) ||
                 content_domain_list_matches(&f->emitted_categories, domain) ||
                 content_domain_list_matches(&f->emitted_blocks, domain));
}

int aegisxd_content_filter_write_explicit_blocks(void *opaque, FILE *fp)
{
    struct content_filter *f = opaque;
    int written = 0, pcdn_written;

    if (!f || !fp || !f->managed)
        return 0;
    for (size_t i = 0; i < f->blocks.count; i++) {
        if (content_safe_search_domain_claimed(&f->safe_search, f->blocks.items[i]) ||
            content_domain_list_matches(&f->allows, f->blocks.items[i]) ||
            content_list_has(&f->emitted_blocks, f->blocks.items[i]))
            continue;
        fprintf(fp, "# aegis provenance=explicit_block source=domain_override domain=%s\n",
                f->blocks.items[i]);
        fprintf(fp, "address=/%s/0.0.0.0\naddress=/%s/::\n",
                f->blocks.items[i], f->blocks.items[i]);
        written++;
    }
    pcdn_written = aegisxd_pcdn_write_dnsmasq(fp, content_pcdn_allow_cb, f);
    if (pcdn_written < 0)
        return -1;
    written += pcdn_written;
    for (size_t i = 0; i < f->allows.count; i++) {
        if (content_safe_search_domain_claimed(&f->safe_search, f->allows.items[i]))
            continue;
        fprintf(fp, "server=/%s/#\n", f->allows.items[i]);
    }
    for (size_t i = 0; i < ARRAY_SIZE(content_safe_search_hosts); i++) {
        const struct content_safe_search_host *host = &content_safe_search_hosts[i];

        if (!content_safe_search_provider_enabled(&f->safe_search, host->provider))
            continue;
        fprintf(fp, "# safe-search provider=%s host=%s\n", host->provider, host->host);
        fprintf(fp, "address=/%s/%s\n", host->host, host->ipv4);
        if (host->ipv6[0])
            fprintf(fp, "address=/%s/%s\n", host->host, host->ipv6);
        written++;
    }
    return written;
}
