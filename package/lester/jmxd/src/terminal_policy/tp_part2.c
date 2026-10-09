/* -----------------------------------------------------------------------
 * Duration computation: started_at + count * unit -> deadline_at
 * ----------------------------------------------------------------------- */
static int tp_compute_deadline(int started_at, int count,
                                const char *unit, time_t *out)
{
    struct tm tm_now;
    time_t base;

    if (count <= 0) {
        *out = 0;
        return 0;
    }

    /* For calendar units, we do month/year math via broken-down time */
    if (!strcmp(unit, "months") || !strcmp(unit, "years")) {
        base = (time_t)started_at;
        localtime_r(&base, &tm_now);

        if (!strcmp(unit, "months")) {
            int total_months = tm_now.tm_mon + count;
            tm_now.tm_mon = total_months % 12;
            tm_now.tm_year += total_months / 12;
            /* Handle month overflow days (e.g. Jan 31 + 1 month = Feb 28/29) */
            if (mktime(&tm_now) < 0) return -1;
        } else {
            tm_now.tm_year += count;
            if (mktime(&tm_now) < 0) return -1;
        }
        *out = (time_t)mktime(&tm_now);
        return 0;
    }

    /* Fixed seconds for hours/days/weeks */
    long long secs = count;
    if (!strcmp(unit, "hours")) secs *= 3600;
    else if (!strcmp(unit, "days")) secs *= 86400;
    else if (!strcmp(unit, "weeks")) secs *= 604800;
    else return -1;

    *out = (time_t)(started_at + secs);
    return 0;
}

/* -----------------------------------------------------------------------
 * Protocol parsing and validation
 * ----------------------------------------------------------------------- */
static int tp_protocol_valid(const char *proto)
{
    if (!proto || !proto[0]) return 1; /* empty means all allowed */
    return (!strcasecmp(proto, TP_PROTO_TCP) ||
            !strcasecmp(proto, TP_PROTO_UDP) ||
            !strcasecmp(proto, TP_PROTO_ICMP));
}

static int tp_has_protocol(const char *denied, const char *proto)
{
    if (!denied || !denied[0]) return 0;
    const char *p = denied;
    size_t plen = strlen(proto);
    while (*p) {
        /* skip leading whitespace/comma */
        while (*p == ',' || *p == ' ') p++;
        if (!*p) break;
        /* compare */
        if (strncmp(p, proto, plen) == 0 &&
            (p[plen] == ',' || p[plen] == '\0' || p[plen] == ' '))
            return 1;
        p += plen;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Target resolution: expand ip / cidr / range into rows
 * Returns 0 on success, -1 on error (err->detail populated)
 * For ranges, splits into minimal CIDR set.
 * ----------------------------------------------------------------------- */
static uint32_t tp_ipv4_aton(const char *s)
{
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) == 1)
        return ntohl(a.s_addr);
    return (uint32_t)-1;
}

/* Convert integer IP to dotted string, fills out buf */
static void tp_ntop_uint32(uint32_t ip, char *buf, size_t len)
{
    snprintf(buf, len, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
              ip & 0xFF);
}

/* Split an IP range [start..end] into minimal CIDR list.
 * Each element is "prefix/prefix_len". Returns count of entries written,
 * or -1 on error. Max entries limited by max_entries. */
static int tp_cidr_split_range(uint32_t start, uint32_t end,
                                char **entries, int max_entries)
{
    int n = 0;
    while (start <= end && n < max_entries) {
        /* Find largest prefix that starts at 'start' and stays within [start, end] */
        int best_prefix = 32;
        if (start == 0) best_prefix = 0; /* full space */

        for (int bits = 31; bits >= 0; bits--) {
            uint32_t mask = ~((1U << bits) - 1);
            if ((start & mask) != start) continue; /* not aligned */
            uint32_t block_end = start | ((1U << bits) - 1);
            if (block_end <= end) {
                best_prefix = 32 - bits;
                break;
            }
        }

        char buf[48];
        tp_ntop_uint32(start, buf, sizeof(buf));
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "/%d", best_prefix);
        entries[n++] = strdup(buf);

        /* Advance past this block */
        uint32_t block_size = 1U << (32 - best_prefix);
        start += block_size;
        if (start < block_size) start = 0; /* wrap, shouldn't happen normally */
    }
    return n;
}

typedef struct tp_target_row {
    int family;
    char prefix[65];     /* e.g. "192.168.1.10" or "192.168.1.0/24" */
    int prefix_len;
} tp_target_row_t;

#define MAX_TARGET_ROWS 4096

static int tp_expand_targets(struct json_object *targets,
                              tp_target_row_t *rows, int *out_count,
                              tp_error_t *err)
{
    int count = 0;
    size_t i;

    if (!json_object_is_type(targets, json_type_array)) {
        snprintf(err->detail, sizeof(err->detail),
                 "targets must be a JSON array");
        err->code = "invalid_parameter";
        return -1;
    }

    for (i = 0; i < json_object_array_length(targets) && count < MAX_TARGET_ROWS; i++) {
        struct json_object *t = json_object_array_get_idx(targets, i);
        if (!t || !json_object_is_type(t, json_type_object)) continue;

        const char *kind = json_str_def(t, "kind", "ip");
        const char *value = json_str_def(t, "value", "");
        const char *start_ip = json_str_def(t, "start", "");
        const char *end_ip = json_str_def(t, "end", "");

        if (!strcmp(kind, "ip")) {
            struct in_addr v4;
            struct in6_addr v6;
            tp_target_row_t *r = &rows[count++];

            if (inet_pton(AF_INET, value, &v4) == 1) {
                r->family = 4;
                r->prefix_len = 32;
                snprintf(r->prefix, sizeof(r->prefix), "%s", value);
            } else if (inet_pton(AF_INET6, value, &v6) == 1) {
                r->family = 6;
                r->prefix_len = 128;
                snprintf(r->prefix, sizeof(r->prefix), "%s", value);
            } else {
                snprintf(err->detail, sizeof(err->detail),
                         "targets[%zu]: '%s' is not a valid IP address", i, value);
                err->code = "invalid_target";
                return -1;
            }
        } else if (!strcmp(kind, "cidr")) {
            tp_target_row_t *r = &rows[count++];
            char buf[128];
            char *slash;

            snprintf(buf, sizeof(buf), "%s", value);
            slash = strchr(buf, '/');
            if (slash) {
                r->prefix_len = atoi(slash + 1);
                *slash = '\0';
                strncpy(r->prefix, buf, sizeof(r->prefix) - 1);
                r->prefix[sizeof(r->prefix)-1] = '\0';
            } else {
                strncpy(r->prefix, buf, sizeof(r->prefix) - 1);
                r->prefix[sizeof(r->prefix)-1] = '\0';
                /* Determine prefix length from address */
                struct in_addr v4;
                struct in6_addr v6;
                if (inet_pton(AF_INET, r->prefix, &v4) == 1)
                    r->prefix_len = 32, r->family = 4;
                else if (inet_pton(AF_INET6, r->prefix, &v6) == 1)
                    r->prefix_len = 128, r->family = 6;
                else {
                    snprintf(err->detail, sizeof(err->detail),
                             "targets[%zu]: '%s' is not a valid CIDR", i, value);
                    err->code = "invalid_target";
                    return -1;
                }
            }
            r->family = (r->prefix_len <= 32) ? 4 : 6;
        } else if (!strcmp(kind, "range")) {
            if (!start_ip[0] || !end_ip[0]) {
                snprintf(err->detail, sizeof(err->detail),
                         "targets[%zu]: range requires start and end", i);
                err->code = "invalid_target";
                return -1;
            }

            uint32_t s4, e4;
            char **cidrs = NULL;
            int nc;

            s4 = tp_ipv4_aton(start_ip);
            e4 = tp_ipv4_aton(end_ip);
            if (s4 == (uint32_t)-1 || e4 == (uint32_t)-1 || s4 > e4) {
                snprintf(err->detail, sizeof(err->detail),
                         "targets[%zu]: invalid IP range [%s, %s]",
                         i, start_ip, end_ip);
                err->code = "invalid_target";
                return -1;
            }

            cidrs = malloc(sizeof(char *) * MAX_TARGET_ROWS);
            if (!cidrs) {
                err->code = "internal_error";
                snprintf(err->detail, sizeof(err->detail), "memory allocation failed");
                return -1;
            }

            nc = tp_cidr_split_range(s4, e4, cidrs, MAX_TARGET_ROWS);
            if (nc < 0) {
                free(cidrs);
                err->code = "target_expansion_limit";
                snprintf(err->detail, sizeof(err->detail),
                         "targets[%zu]: range expands to too many CIDRs (max 4096)", i);
                return -1;
            }

            for (int c = 0; c < nc && count < MAX_TARGET_ROWS; c++) {
                tp_target_row_t *r = &rows[count++];
                r->family = 4;
                strncpy(r->prefix, cidrs[c], sizeof(r->prefix) - 1);
                r->prefix[sizeof(r->prefix) - 1] = '\0';
                /* parse prefix_len from the CIDR string */
                char *sl = strchr(r->prefix, '/');
                if (sl) {
                    *sl = '\0';
                    r->prefix_len = atoi(sl + 1);
                } else {
                    r->prefix_len = 32;
                    strncat(r->prefix, "/32", sizeof(r->prefix) - strlen(r->prefix) - 1);
                }
                free(cidrs[c]);
            }
            free(cidrs);
        } else {
            snprintf(err->detail, sizeof(err->detail),
                     "targets[%zu]: unknown kind '%s'", i, kind);
            err->code = "unsupported_target_kind";
            return -1;
        }
    }

    *out_count = count;
    return 0;
}

