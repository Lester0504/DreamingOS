{
    if (!cfg) return -1;
    const char *id = nc_json_str_def(cfg, "id", "");
    if (!id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_routing_db_init();
    int64_t now = nc_now_s();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "INSERT INTO adv_routing_table(id,name,family,priority,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,family=excluded.family,priority=excluded.priority,updated_at=excluded.updated_at") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, nc_json_str_def(cfg, "name", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, nc_json_str_def(cfg, "family", "ipv4"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, nc_json_int_def(cfg, "priority", 100));
        sqlite3_bind_int64(st, 5, now);
        sqlite3_bind_int64(st, 6, now);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

int jmx_routing_table_delete(const char *id)
{
    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_routing_db_init();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "DELETE FROM adv_routing_table WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

struct json_object *jmx_bulk_ip_get_v2(void)
{
    return jmx_bulk_ip_get();
}

int jmx_bulk_ip_reserve(struct json_object *cfg)
{
    struct json_object *request,*items,*response,*code=NULL; int ok=0;
    if(!cfg||jmx_netconfig_db_init()!=0)return -1; nc_ipam_db_init();
    request=json_object_new_object(); items=json_object_new_array();
    json_object_object_add(request,"action",json_object_new_string("reserve"));
    json_object_object_add(request,"network_id",json_object_new_string(nc_json_str_def(cfg,"network_id","lan")));
    json_object_object_add(request,"expected_revision",json_object_new_int64(nc_ipam_revision()));
    json_object_array_add(items,json_object_get(cfg));json_object_object_add(request,"items",items);
    response=jmx_bulk_ip_transaction(request);json_object_put(request);
    if(response&&json_object_object_get_ex(response,"code",&code))ok=json_object_get_int(code)==API_CODE_SUCCESS;
    if(response)json_object_put(response);return ok?0:-1;
}

int jmx_bulk_ip_delete(const char *id)
{
    struct json_object *request,*items,*item,*response,*code=NULL;sqlite3_stmt *st=NULL;char nid[64]="";int ok=0;
    if(!id||!id[0]||jmx_netconfig_db_init()!=0)return -1;nc_ipam_db_init();
    if(nc_prepare(&st,"SELECT network_id FROM ipam_address WHERE id=?1")==0){sqlite3_bind_text(st,1,id,-1,SQLITE_TRANSIENT);if(sqlite3_step(st)==SQLITE_ROW&&sqlite3_column_text(st,0))snprintf(nid,sizeof(nid),"%s",(const char*)sqlite3_column_text(st,0));sqlite3_finalize(st);}
    if(!nid[0])return -1;
    request=json_object_new_object();items=json_object_new_array();item=json_object_new_object();
    json_object_object_add(request,"action",json_object_new_string("delete"));json_object_object_add(request,"network_id",json_object_new_string(nid));json_object_object_add(request,"expected_revision",json_object_new_int64(nc_ipam_revision()));
    json_object_object_add(item,"id",json_object_new_string(id));json_object_array_add(items,item);json_object_object_add(request,"items",items);
    response=jmx_bulk_ip_transaction(request);json_object_put(request);
    if(response&&json_object_object_get_ex(response,"code",&code))ok=json_object_get_int(code)==API_CODE_SUCCESS;
    if(response)json_object_put(response);return ok?0:-1;
}

/* ── Flow Control rules CRUD (new) ── */
static void nc_flow_rule_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS flow_rule ("
        "id TEXT PRIMARY KEY,"
        "enabled INTEGER DEFAULT 1,"
        "source TEXT DEFAULT 'any',"
        "destination TEXT DEFAULT 'any',"
        "app TEXT DEFAULT '',"
        "protocol TEXT DEFAULT '',"
        "action TEXT DEFAULT 'class',"
        "target TEXT DEFAULT '',"
        "schedule TEXT DEFAULT 'always',"
        "fallback TEXT DEFAULT 'default',"
        "sticky INTEGER DEFAULT 0,"
        "hits INTEGER DEFAULT 0,"
        "remark TEXT DEFAULT '',"
        "sort_order INTEGER DEFAULT 0,"
        "created_at INTEGER DEFAULT 0,"
        "updated_at INTEGER DEFAULT 0"
        ")");
}

struct json_object *jmx_flow_rules_list(void)
{
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;
    if (jmx_netconfig_db_init() != 0) return arr;
    nc_flow_rule_db_init();
    if (nc_prepare(&st, "SELECT id,enabled,source,destination,app,protocol,action,target,schedule,fallback,sticky,hits,remark FROM flow_rule ORDER BY sort_order,id") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *r = json_object_new_object();
            nc_add_text(r, "id", st, 0);
            json_object_object_add(r, "enabled", json_object_new_boolean(sqlite3_column_int(st, 1)));
            nc_add_text(r, "source", st, 2); nc_add_text(r, "destination", st, 3);
            nc_add_text(r, "app", st, 4); nc_add_text(r, "protocol", st, 5);
            nc_add_text(r, "action", st, 6); nc_add_text(r, "target", st, 7);
            nc_add_text(r, "schedule", st, 8); nc_add_text(r, "fallback", st, 9);
            json_object_object_add(r, "sticky", json_object_new_boolean(sqlite3_column_int(st, 10)));
            json_object_object_add(r, "hits", json_object_new_int(sqlite3_column_int(st, 11)));
            nc_add_text(r, "remark", st, 12);
            json_object_array_add(arr, r);
        }
        sqlite3_finalize(st);
    }
    return arr;
}

int jmx_flow_rule_set(struct json_object *cfg)
{
    if (!cfg) return -1;
    const char *id = nc_json_str_def(cfg, "id", "");
    if (!id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_flow_db_init();
    int64_t now = nc_now_s();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "INSERT INTO flow_rules(id,enabled,priority,name,type,source,destination,apps,protocol,action,target,qos_class,schedule,fallback,sticky,remark,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,priority=excluded.priority,name=excluded.name,type=excluded.type,source=excluded.source,destination=excluded.destination,apps=excluded.apps,protocol=excluded.protocol,action=excluded.action,target=excluded.target,qos_class=excluded.qos_class,schedule=excluded.schedule,fallback=excluded.fallback,sticky=excluded.sticky,remark=excluded.remark,updated_at=excluded.updated_at") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, nc_json_bool_def(cfg, "enabled", 1));
        sqlite3_bind_int(st, 3, nc_json_int_def(cfg, "priority", 0));
        sqlite3_bind_text(st, 4, nc_json_str_def(cfg, "name", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, nc_json_str_def(cfg, "type", "app"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 6, nc_json_str_def(cfg, "source", "any"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, nc_json_str_def(cfg, "destination", "any"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 8, nc_json_str_def(cfg, "apps", nc_json_str_def(cfg, "match_value", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, nc_json_str_def(cfg, "protocol", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 10, nc_json_str_def(cfg, "action", "class"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 11, nc_json_str_def(cfg, "target", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 12, nc_json_str_def(cfg, "qos_class", "normal"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, nc_json_str_def(cfg, "schedule", "always"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, nc_json_str_def(cfg, "fallback", "auto"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 15, nc_json_bool_def(cfg, "sticky", 1));
        sqlite3_bind_text(st, 16, nc_json_str_def(cfg, "remark", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 17, now);
        sqlite3_bind_int64(st, 18, now);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

int jmx_flow_client_limit_save(struct json_object *cfg)
{
    if (!cfg) return -1;
    const char *id = nc_json_str_def(cfg, "id", "");
    if (!id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_flow_db_init();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "INSERT INTO flow_client_limits(id,enabled,client,ip,device_group,upload_kbps,download_kbps,mode,remark) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,client=excluded.client,ip=excluded.ip,device_group=excluded.device_group,upload_kbps=excluded.upload_kbps,download_kbps=excluded.download_kbps,mode=excluded.mode,remark=excluded.remark") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, nc_json_bool_def(cfg, "enabled", 1));
        sqlite3_bind_text(st, 3, nc_json_str_def(cfg, "client", nc_json_str_def(cfg, "name", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, nc_json_str_def(cfg, "ip", nc_json_str_def(cfg, "target", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, nc_json_str_def(cfg, "group", nc_json_str_def(cfg, "device_group", "")), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 6, nc_json_int_def(cfg, "upload_kbps", 0));
        sqlite3_bind_int(st, 7, nc_json_int_def(cfg, "download_kbps", 0));
        sqlite3_bind_text(st, 8, nc_json_str_def(cfg, "mode", "inherit"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 9, nc_json_str_def(cfg, "remark", ""), -1, SQLITE_TRANSIENT);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

int jmx_flow_rule_delete(const char *id)
{
    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    nc_flow_rule_db_init();
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "DELETE FROM flow_rule WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        int rc = nc_step_done(st);
        sqlite3_finalize(st);
        return rc;
    }
    return -1;
}

/* ═══ CPU Interrupt Affinity Control ═══ */
static int nc_irq_read_text(const char *path, char *out, size_t out_len)
{
    FILE *fp;

    if (!path || !out || out_len < 2) return -1;
    out[0] = 0;
    fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(out, out_len, fp)) {
        fclose(fp);
        out[0] = 0;
        return -1;
    }
    fclose(fp);
    out[strcspn(out, "\r\n")] = 0;
    return 0;
}

static void nc_irq_add_optional_text(struct json_object *o, const char *key,
                                     const char *path)
{
    char value[512] = "";
    if (nc_irq_read_text(path, value, sizeof(value)) == 0)
        json_object_object_add(o, key, json_object_new_string(value));
    else
        json_object_object_add(o, key, json_object_new_null());
}

/*
 * Softirq / RPS tuning surface.
 *
 * These knobs are plain procfs and sysfs files, so "supported" is decided by
 * probing the file rather than by a compile-time assumption. Reporting a knob
 * as unsupported while it is in fact readable and writable is the specific
 * defect this surface exists to avoid.
 */
static int nc_net_tune_path_writable(const char *path)
{
    struct stat st;

    if (!path || stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    return (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0;
}

/*
 * Writable sysctl knobs on this surface, with the accepted range.
 *
 * The bounds are enforced here rather than in the UI on purpose: netdev_budget
 * or netdev_max_backlog set to 0 stalls packet reception, which is a
 * "can cut the network" class of change. A client that skips validation, or
 * calls ubus directly, must still be refused.
 */
typedef struct {
    const char *knob;
    const char *path;
    long long min;
    long long max;
} nc_net_tune_knob_t;

static const nc_net_tune_knob_t nc_net_tune_knobs[] = {
    { "netdev_budget",       "/proc/sys/net/core/netdev_budget",       1, 65536 },
    { "netdev_budget_usecs", "/proc/sys/net/core/netdev_budget_usecs", 1, 10000000 },
    { "netdev_max_backlog",  "/proc/sys/net/core/netdev_max_backlog",  1, 1048576 },
    { "busy_poll",           "/proc/sys/net/core/busy_poll",           0, 1000000 },
    { "busy_read",           "/proc/sys/net/core/busy_read",           0, 1000000 },
};

static const nc_net_tune_knob_t *nc_net_tune_knob_find(const char *knob)
{
    size_t i;

    if (!knob || !*knob)
        return NULL;
    for (i = 0; i < sizeof(nc_net_tune_knobs) / sizeof(nc_net_tune_knobs[0]); i++) {
        if (!strcmp(knob, nc_net_tune_knobs[i].knob))
            return &nc_net_tune_knobs[i];
    }
    return NULL;
}

/* Adds {value,present,writable,write_reason} for one sysctl-style knob. */
static void nc_net_tune_add_knob(struct json_object *parent, const char *key,
                                 const char *path)
{
    struct json_object *o = json_object_new_object();
    char value[128] = "";
    int present = (nc_irq_read_text(path, value, sizeof(value)) == 0);
    int writable = present ? nc_net_tune_path_writable(path) : 0;
    const nc_net_tune_knob_t *bounds = nc_net_tune_knob_find(key);

    json_object_object_add(o, "path", json_object_new_string(path));
    json_object_object_add(o, "present", json_object_new_boolean(present));
    if (present) {
        char *end = NULL;
        long long n = strtoll(value, &end, 10);

        json_object_object_add(o, "raw", json_object_new_string(value));
        if (end && end != value && *end == 0)
            json_object_object_add(o, "value", json_object_new_int64((int64_t)n));
        else
            json_object_object_add(o, "value", json_object_new_null());
    } else {
        json_object_object_add(o, "raw", json_object_new_null());
        json_object_object_add(o, "value", json_object_new_null());
    }
    json_object_object_add(o, "writable", json_object_new_boolean(writable));
    /* Publish the accepted range so the UI can show it instead of guessing. */
    if (bounds) {
        json_object_object_add(o, "min", json_object_new_int64((int64_t)bounds->min));
        json_object_object_add(o, "max", json_object_new_int64((int64_t)bounds->max));
    } else {
        json_object_object_add(o, "min", json_object_new_null());
        json_object_object_add(o, "max", json_object_new_null());
    }
    if (!present)
        json_object_object_add(o, "write_reason",
                               json_object_new_string("sysctl_absent_kernel_lacks_knob"));
    else if (!writable)
        json_object_object_add(o, "write_reason",
                               json_object_new_string("sysctl_read_only"));
    else
        json_object_object_add(o, "write_reason", json_object_new_null());
    json_object_object_add(parent, key, o);
}

/*
 * Translates /proc/net/softnet_stat into named per-CPU counters.
 *
 * The file is whitespace separated hex with no header. Column 1 is packets
 * processed, column 2 is dropped, column 3 is time_squeeze - the number of
 * times the softirq poll loop exhausted netdev_budget before draining the
 * queue. A non-zero time_squeeze is the only evidence that raising the budget
 * would help, which is why it is surfaced rather than left for the frontend to
 * parse out of raw hex.
 */
static struct json_object *nc_net_softnet_stat_read(struct json_object *summary)
{
    struct json_object *rows = json_object_new_array();
    FILE *fp = fopen("/proc/net/softnet_stat", "r");
    char line[1024];
    int cpu = 0;
    int64_t total_processed = 0, total_dropped = 0, total_squeeze = 0;

    if (!fp) {
        if (summary) {
            json_object_object_add(summary, "present", json_object_new_boolean(0));
            json_object_object_add(summary, "reason",
                                   json_object_new_string("proc_net_softnet_stat_unavailable"));
        }
        return rows;
    }
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long processed = 0, dropped = 0, squeeze = 0;
        struct json_object *o;

        if (sscanf(line, "%llx %llx %llx", &processed, &dropped, &squeeze) < 3)
            continue;
        o = json_object_new_object();
        json_object_object_add(o, "cpu", json_object_new_int(cpu));
        json_object_object_add(o, "processed", json_object_new_int64((int64_t)processed));
        json_object_object_add(o, "dropped", json_object_new_int64((int64_t)dropped));
        json_object_object_add(o, "time_squeeze", json_object_new_int64((int64_t)squeeze));
        json_object_array_add(rows, o);
        total_processed += (int64_t)processed;
        total_dropped += (int64_t)dropped;
        total_squeeze += (int64_t)squeeze;
        cpu++;
    }
    fclose(fp);
    if (summary) {
        json_object_object_add(summary, "present", json_object_new_boolean(1));
        json_object_object_add(summary, "reason", json_object_new_null());
        json_object_object_add(summary, "cpu_count", json_object_new_int(cpu));
        json_object_object_add(summary, "processed", json_object_new_int64(total_processed));
        json_object_object_add(summary, "dropped", json_object_new_int64(total_dropped));
        json_object_object_add(summary, "time_squeeze", json_object_new_int64(total_squeeze));
        /*
         * budget_exhausted says "raising netdev_budget may help"; dropped says
         * "the backlog already overflowed". They are different severities and
         * must not be collapsed into one health flag.
         */
        json_object_object_add(summary, "budget_exhausted",
                               json_object_new_boolean(total_squeeze > 0));
        json_object_object_add(summary, "backlog_dropping",
                               json_object_new_boolean(total_dropped > 0));
    }
    return rows;
}

/* Counts entries under queues/ matching a prefix, e.g. "rx-" or "tx-". */
static int nc_net_iface_queue_count(const char *ifname, const char *dir_prefix)
{
    char path[256];
    DIR *dir;
    struct dirent *entry;
    int count = 0;
    size_t plen;

    if (!ifname || !dir_prefix)
        return 0;
    if ((size_t)snprintf(path, sizeof(path), "/sys/class/net/%s/queues",
                         ifname) >= sizeof(path))
        return 0;
    dir = opendir(path);
    if (!dir)
        return 0;
    plen = strlen(dir_prefix);
    while ((entry = readdir(dir)) != NULL) {
        if (!strncmp(entry->d_name, dir_prefix, plen))
            count++;
    }
    closedir(dir);
    return count;
}

static void nc_cpu_steering_mask_zero(nc_cpu_steering_mask_t *mask)
{
    if (mask)
        memset(mask, 0, sizeof(*mask));
}

static int nc_cpu_steering_mask_set(nc_cpu_steering_mask_t *mask, int cpu)
{
    if (!mask || cpu < 0 || cpu >= NC_CPU_STEERING_MASK_WORDS * 32)
        return -1;
    mask->words[cpu / 32] |= 1U << (cpu % 32);
    return 0;
}

static int nc_cpu_steering_mask_has(const nc_cpu_steering_mask_t *mask, int cpu)
{
    if (!mask || cpu < 0 || cpu >= NC_CPU_STEERING_MASK_WORDS * 32)
        return 0;
    return (mask->words[cpu / 32] & (1U << (cpu % 32))) != 0;
}

static void nc_cpu_steering_mask_and(nc_cpu_steering_mask_t *dst,
                                     const nc_cpu_steering_mask_t *rhs)
{
    size_t i;

    if (!dst || !rhs)
        return;
    for (i = 0; i < NC_CPU_STEERING_MASK_WORDS; i++)
        dst->words[i] &= rhs->words[i];
}

static void nc_cpu_steering_mask_or(nc_cpu_steering_mask_t *dst,
                                    const nc_cpu_steering_mask_t *rhs)
{
    size_t i;

    if (!dst || !rhs)
        return;
    for (i = 0; i < NC_CPU_STEERING_MASK_WORDS; i++)
        dst->words[i] |= rhs->words[i];
}

static void nc_cpu_steering_mask_remove(nc_cpu_steering_mask_t *dst,
                                        const nc_cpu_steering_mask_t *rhs)
{
    size_t i;

    if (!dst || !rhs)
        return;
    for (i = 0; i < NC_CPU_STEERING_MASK_WORDS; i++)
        dst->words[i] &= ~rhs->words[i];
}

static int nc_cpu_steering_mask_any(const nc_cpu_steering_mask_t *mask)
{
    size_t i;

    if (!mask)
        return 0;
    for (i = 0; i < NC_CPU_STEERING_MASK_WORDS; i++) {
        if (mask->words[i])
            return 1;
    }
    return 0;
}

static int nc_cpu_steering_mask_parse(const char *text,
                                      nc_cpu_steering_mask_t *mask)
{
    size_t nibble = 0;
    int saw_digit = 0;
    const char *p;

    if (!text || !mask || !*text)
        return -1;
    nc_cpu_steering_mask_zero(mask);
    for (p = text + strlen(text); p != text;) {
        unsigned value;
        char c;

        c = *--p;
        if (c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        if (!isxdigit((unsigned char)c) || nibble >= NC_CPU_STEERING_MASK_WORDS * 8)
            return -1;
        if (c >= '0' && c <= '9')
            value = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            value = (unsigned)(c - 'a' + 10);
        else
            value = (unsigned)(c - 'A' + 10);
        mask->words[nibble / 8] |= (uint32_t)value << ((nibble % 8) * 4);
        nibble++;
        saw_digit = 1;
    }
    return saw_digit ? 0 : -1;
}

static int nc_cpu_steering_list_parse(const char *text,
                                      nc_cpu_steering_mask_t *mask)
{
    char copy[512];
    char *save = NULL;
    char *part;

    if (!text || !mask || !*text || strlen(text) >= sizeof(copy))
        return -1;
    snprintf(copy, sizeof(copy), "%s", text);
    nc_cpu_steering_mask_zero(mask);
    part = strtok_r(copy, ",", &save);
    while (part) {
        char *dash = strchr(part, '-');
        char *end = NULL;
        unsigned long first;
        unsigned long last;

        while (*part && isspace((unsigned char)*part))
            part++;
        if (!*part || (dash && strchr(dash + 1, '-')))
            return -1;
        if (dash)
            *dash++ = 0;
        first = strtoul(part, &end, 10);
        if (end == part || *end)
            return -1;
        last = first;
        if (dash) {
            char *range_end = NULL;
            while (*dash && isspace((unsigned char)*dash))
                dash++;
            last = strtoul(dash, &range_end, 10);
            if (range_end == dash || *range_end || last < first)
                return -1;
        }
        if (last >= NC_CPU_STEERING_MASK_WORDS * 32)
            return -1;
        while (first <= last) {
            if (nc_cpu_steering_mask_set(mask, (int)first) != 0)
                return -1;
            first++;
        }
        part = strtok_r(NULL, ",", &save);
    }
    return nc_cpu_steering_mask_any(mask) ? 0 : -1;
}

static int nc_cpu_steering_read_mask_file(const char *path,
                                          nc_cpu_steering_mask_t *mask)
{
    char value[1024] = "";

    if (!path || !mask || nc_irq_read_text(path, value, sizeof(value)) != 0)
        return -1;
    return nc_cpu_steering_mask_parse(value, mask);
}

static int nc_cpu_steering_read_cpu_sets(nc_cpu_steering_mask_t *online,
                                         nc_cpu_steering_mask_t *allowed,
                                         nc_cpu_steering_mask_t *eligible)
{
    char value[512] = "";
    long count;
    int cpu;

    if (!online || !allowed || !eligible)
        return -1;
    nc_cpu_steering_mask_zero(online);
    nc_cpu_steering_mask_zero(allowed);
    if (nc_irq_read_text("/sys/devices/system/cpu/online", value,
                         sizeof(value)) == 0) {
        if (nc_cpu_steering_list_parse(value, online) != 0)
            return -1;
    } else {
        count = sysconf(_SC_NPROCESSORS_ONLN);
        if (count <= 0 || count > NC_CPU_STEERING_MASK_WORDS * 32)
            return -1;
        for (cpu = 0; cpu < count; cpu++)
            nc_cpu_steering_mask_set(online, cpu);
    }
    if (nc_cpu_steering_read_mask_file("/proc/irq/default_smp_affinity", allowed) != 0)
        *allowed = *online;
    *eligible = *online;
    nc_cpu_steering_mask_and(eligible, allowed);
    return nc_cpu_steering_mask_any(eligible) ? 0 : -1;
}

static void nc_cpu_steering_mask_to_json(const nc_cpu_steering_mask_t *mask,
                                         struct json_object *array)
{
    int cpu;

    if (!mask || !array)
        return;
    for (cpu = 0; cpu < NC_CPU_STEERING_MASK_WORDS * 32; cpu++) {
        if (nc_cpu_steering_mask_has(mask, cpu))
            json_object_array_add(array, json_object_new_int(cpu));
    }
}

static int nc_cpu_steering_mask_to_text(const nc_cpu_steering_mask_t *mask,
                                        char *out, size_t out_len)
{
    int high = NC_CPU_STEERING_MASK_WORDS - 1;
    size_t used = 0;
    int n;

    if (!mask || !out || out_len < 2 || !nc_cpu_steering_mask_any(mask))
        return -1;
    while (high > 0 && mask->words[high] == 0)
        high--;
    n = snprintf(out, out_len, "%x", mask->words[high]);
    if (n < 0 || (size_t)n >= out_len)
        return -1;
    used = (size_t)n;
    while (--high >= 0) {
        n = snprintf(out + used, out_len - used, ",%08x", mask->words[high]);
        if (n < 0 || (size_t)n >= out_len - used)
            return -1;
        used += (size_t)n;
    }
    return 0;
}

static int nc_cpu_steering_mask_to_list(const nc_cpu_steering_mask_t *mask,
                                        char *out, size_t out_len)
{
    size_t used = 0;
    int cpu;

    if (!mask || !out || out_len < 2 || !nc_cpu_steering_mask_any(mask))
        return -1;
    for (cpu = 0; cpu < NC_CPU_STEERING_MASK_WORDS * 32; cpu++) {
        int start;
        int end;
        int n;

        if (!nc_cpu_steering_mask_has(mask, cpu))
            continue;
        start = cpu;
        end = cpu;
        while (end + 1 < NC_CPU_STEERING_MASK_WORDS * 32 &&
               nc_cpu_steering_mask_has(mask, end + 1))
            end++;
        if (used)
            n = snprintf(out + used, out_len - used, ",");
        else
            n = 0;
        if (n < 0 || (size_t)n >= out_len - used)
            return -1;
        used += (size_t)n;
        if (start == end)
            n = snprintf(out + used, out_len - used, "%d", start);
        else
            n = snprintf(out + used, out_len - used, "%d-%d", start, end);
        if (n < 0 || (size_t)n >= out_len - used)
            return -1;
        used += (size_t)n;
        cpu = end;
    }
    return used ? 0 : -1;
}

static int nc_cpu_steering_ifname_eligible(const char *ifname,
                                           char *reason, size_t reason_len)
{
    char path[320];
    char link[512];
    ssize_t n;

    if (reason && reason_len)
        reason[0] = 0;
    if (!ifname || !ifname[0] || !strcmp(ifname, "lo")) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "network_interface_not_eligible");
        return 0;
    }
    snprintf(path, sizeof(path), "/sys/class/net/%s/device", ifname);
    n = readlink(path, link, sizeof(link) - 1);
    if (n <= 0) {
        if (reason && reason_len)
            snprintf(reason, reason_len, "virtual_or_no_physical_device");
        return 0;
    }
    return 1;
}

static int nc_cpu_steering_descriptor_ifname(const char *descriptor,
                                             char *ifname, size_t ifname_len)
{
    DIR *dir;
    struct dirent *entry;

    if (!descriptor || !ifname || ifname_len == 0)
        return 0;
    ifname[0] = 0;
    dir = opendir("/sys/class/net");
    if (!dir)
        return 0;
    while ((entry = readdir(dir)) != NULL) {
        size_t n = strlen(entry->d_name);
        const char *match;

        if (!n || entry->d_name[0] == '.' ||
            !nc_cpu_steering_ifname_eligible(entry->d_name, NULL, 0))
            continue;
        match = strstr(descriptor, entry->d_name);
        if (match && (match == descriptor ||
                      !isalnum((unsigned char)match[-1])) &&
            !isalnum((unsigned char)match[n])) {
            snprintf(ifname, ifname_len, "%s", entry->d_name);
            closedir(dir);
            return 1;
        }
    }
    closedir(dir);
    return 0;
}

static void nc_cpu_steering_add_common(struct json_object *out,
                                       const char *semantic)
{
    if (!out)
        return;
    json_object_object_add(out, "semantic", json_object_new_string(semantic));
    json_object_object_add(out, "persistent", json_object_new_boolean(0));
    json_object_object_add(out, "persistent_reason",
                           json_object_new_string("runtime_only_not_persistent"));
}

/*
 * Per-interface identity plus RPS capability.
 *
 * MAC and PCI address are reported because interface identity must be able to
 * follow the hardware rather than the kernel's ethN ordering. Virtual
 * interfaces legitimately have no PCI address or driver, so those fields are
 * null rather than being faked or causing the row to be dropped.
 */
static struct json_object *nc_net_iface_tuning_list(void)
{
    struct json_object *rows = json_object_new_array();
    DIR *dir = opendir("/sys/class/net");
    struct dirent *entry;

    if (!dir)
        return rows;
    while ((entry = readdir(dir)) != NULL) {
        char path[320];
        char link[512];
        char value[128] = "";
        struct json_object *o;
        struct json_object *queues;
        struct json_object *xps_queues;
        int rx, tx, rps_present = 0, rps_writable = 0;
        int xps_present = 0, xps_writable = 0, q;
        int eligible;
        char eligibility_reason[96] = "";
        ssize_t n;

        if (entry->d_name[0] == '.' || !strcmp(entry->d_name, "lo"))
            continue;

        o = json_object_new_object();
        json_object_object_add(o, "ifname", json_object_new_string(entry->d_name));

        snprintf(path, sizeof(path), "/sys/class/net/%s/address", entry->d_name);
        if (nc_irq_read_text(path, value, sizeof(value)) == 0 && value[0])
            json_object_object_add(o, "mac", json_object_new_string(value));
        else
            json_object_object_add(o, "mac", json_object_new_null());

        /* device symlink resolves to the bus id, e.g. 0000:00:10.0 for PCI. */
        snprintf(path, sizeof(path), "/sys/class/net/%s/device", entry->d_name);
        n = readlink(path, link, sizeof(link) - 1);
        if (n > 0) {
            char *base;
            link[n] = 0;
            base = strrchr(link, '/');
            json_object_object_add(o, "bus_id",
                                   json_object_new_string(base ? base + 1 : link));
        } else {
            json_object_object_add(o, "bus_id", json_object_new_null());
        }

        snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", entry->d_name);
        n = readlink(path, link, sizeof(link) - 1);
        if (n > 0) {
            char *base;
            link[n] = 0;
            base = strrchr(link, '/');
            json_object_object_add(o, "driver",
                                   json_object_new_string(base ? base + 1 : link));
        } else {
            json_object_object_add(o, "driver", json_object_new_null());
        }

        rx = nc_net_iface_queue_count(entry->d_name, "rx-");
        tx = nc_net_iface_queue_count(entry->d_name, "tx-");
        eligible = nc_cpu_steering_ifname_eligible(entry->d_name,
                                                   eligibility_reason,
                                                   sizeof(eligibility_reason));
        json_object_object_add(o, "rx_queues", json_object_new_int(rx));
        json_object_object_add(o, "tx_queues", json_object_new_int(tx));
        json_object_object_add(o, "eligible", json_object_new_boolean(eligible));
        if (eligible)
            json_object_object_add(o, "eligibility_reason", json_object_new_null());
        else
            json_object_object_add(o, "eligibility_reason",
                                   json_object_new_string(eligibility_reason[0] ?
                                                          eligibility_reason :
                                                          "network_interface_not_eligible"));

        queues = json_object_new_array();
        for (q = 0; q < rx; q++) {
            struct json_object *qo;
            int present, writable;

            snprintf(path, sizeof(path), "/sys/class/net/%s/queues/rx-%d/rps_cpus",
                     entry->d_name, q);
            value[0] = 0;
            present = (nc_irq_read_text(path, value, sizeof(value)) == 0);
            writable = present ? nc_net_tune_path_writable(path) : 0;
            if (present)
                rps_present = 1;
            if (writable)
                rps_writable = 1;
            qo = json_object_new_object();
            json_object_object_add(qo, "queue", json_object_new_int(q));
            json_object_object_add(qo, "present", json_object_new_boolean(present));
            json_object_object_add(qo, "writable", json_object_new_boolean(writable));
            if (present)
                json_object_object_add(qo, "rps_cpus", json_object_new_string(value));
            else
                json_object_object_add(qo, "rps_cpus", json_object_new_null());
            json_object_array_add(queues, qo);
        }
        json_object_object_add(o, "rx_queue_rps", queues);

        xps_queues = json_object_new_array();
        for (q = 0; q < tx; q++) {
            struct json_object *qo;
            int present, writable;

            snprintf(path, sizeof(path), "/sys/class/net/%s/queues/tx-%d/xps_cpus",
                     entry->d_name, q);
            value[0] = 0;
            present = (nc_irq_read_text(path, value, sizeof(value)) == 0);
            writable = present ? nc_net_tune_path_writable(path) : 0;
            if (present)
                xps_present = 1;
            if (writable)
                xps_writable = 1;
            qo = json_object_new_object();
            json_object_object_add(qo, "queue", json_object_new_int(q));
            json_object_object_add(qo, "present", json_object_new_boolean(present));
            json_object_object_add(qo, "writable", json_object_new_boolean(writable));
            if (present)
                json_object_object_add(qo, "xps_cpus", json_object_new_string(value));
            else
                json_object_object_add(qo, "xps_cpus", json_object_new_null());
            json_object_array_add(xps_queues, qo);
        }
        json_object_object_add(o, "tx_queue_xps", xps_queues);
        json_object_object_add(o, "xps_supported", json_object_new_boolean(xps_present));
        json_object_object_add(o, "xps_writable", json_object_new_boolean(xps_writable));
        if (!xps_present)
            json_object_object_add(o, "xps_reason",
                                   json_object_new_string(tx > 0 ?
                                       "xps_cpus_absent_for_tx_queue" :
                                       "no_tx_queue_exposed_in_sysfs"));
        else if (!xps_writable)
            json_object_object_add(o, "xps_reason",
                                   json_object_new_string("xps_cpus_read_only"));
        else
            json_object_object_add(o, "xps_reason", json_object_new_null());
        json_object_object_add(o, "rps_supported", json_object_new_boolean(rps_present));
        json_object_object_add(o, "rps_writable", json_object_new_boolean(rps_writable));
        if (!rps_present)
            json_object_object_add(o, "rps_reason",
                                   json_object_new_string(rx > 0 ?
                                       "rps_cpus_absent_for_rx_queue" :
                                       "no_rx_queue_exposed_in_sysfs"));
        else if (!rps_writable)
            json_object_object_add(o, "rps_reason",
                                   json_object_new_string("rps_cpus_read_only"));
        else
            json_object_object_add(o, "rps_reason", json_object_new_null());
        /*
         * Single-queue virtual NICs cannot be spread across cores the way a
         * multi-queue NIC can, so capability is reported per interface instead
         * of one verdict for the whole box.
         */
        json_object_object_add(o, "multi_queue",
                               json_object_new_boolean(rx > 1 || tx > 1));
        json_object_array_add(rows, o);
    }
    closedir(dir);
    return rows;
}

struct json_object *jmx_system_net_tuning_get(void)
{
    struct json_object *d = json_object_new_object();
    struct json_object *softirq = json_object_new_object();
    struct json_object *knobs = json_object_new_object();
    struct json_object *softnet = json_object_new_object();

    json_object_object_add(d, "ok", json_object_new_boolean(1));
    json_object_object_add(d, "semantic",
                           json_object_new_string("network_rps_xps_cpu_exclusion"));
    json_object_object_add(d, "legacy_semantic",
                           json_object_new_string("net_softirq_and_nic_tuning"));
    /*
     * Writes were approved by the user on 2026-08-09. "Supported" is decided by
     * probing the files, not by a hardcoded 0: reporting a knob as unwritable
     * while the kernel accepts writes is the defect this surface must avoid.
     */
    {
        int any_writable = 0;
        size_t i;

        for (i = 0; i < sizeof(nc_net_tune_knobs) / sizeof(nc_net_tune_knobs[0]); i++) {
            if (nc_net_tune_path_writable(nc_net_tune_knobs[i].path)) {
                any_writable = 1;
                break;
            }
        }
        json_object_object_add(d, "write_supported", json_object_new_boolean(any_writable));
        json_object_object_add(d, "write_reason",
                               any_writable ?
                               json_object_new_string("sysctl_writes_open") :
                               json_object_new_string("no_writable_sysctl_knob_present"));
        json_object_object_add(d, "write_method",
                               json_object_new_string("system_net_tuning_set"));
    }
    /* Runtime values only: every knob here resets on reboot. */
    json_object_object_add(d, "persistent", json_object_new_boolean(0));
    json_object_object_add(d, "persistent_reason",
                           json_object_new_string("runtime_sysctl_resets_on_reboot"));

    nc_net_tune_add_knob(knobs, "netdev_budget",
                         "/proc/sys/net/core/netdev_budget");
    nc_net_tune_add_knob(knobs, "netdev_budget_usecs",
                         "/proc/sys/net/core/netdev_budget_usecs");
    nc_net_tune_add_knob(knobs, "netdev_max_backlog",
                         "/proc/sys/net/core/netdev_max_backlog");
    nc_net_tune_add_knob(knobs, "busy_poll", "/proc/sys/net/core/busy_poll");
    nc_net_tune_add_knob(knobs, "busy_read", "/proc/sys/net/core/busy_read");
    json_object_object_add(softirq, "knobs", knobs);

    json_object_object_add(softirq, "per_cpu", nc_net_softnet_stat_read(softnet));
    json_object_object_add(softirq, "softnet_summary", softnet);
    json_object_object_add(d, "softirq", softirq);

    json_object_object_add(d, "interfaces", nc_net_iface_tuning_list());
    {
        struct json_object *ifaces = NULL;
        struct json_object *online_json = json_object_new_array();
        struct json_object *eligible_json = json_object_new_array();
        struct json_object *eligible_ifaces = json_object_new_array();
        struct json_object *excluded_json = json_object_new_array();
        nc_cpu_steering_mask_t online, allowed, eligible, common, current;
        int saw_target = 0;
        size_t i;

        nc_cpu_steering_mask_zero(&online);
        nc_cpu_steering_mask_zero(&allowed);
        nc_cpu_steering_mask_zero(&eligible);
        nc_cpu_steering_mask_zero(&common);
        if (nc_cpu_steering_read_cpu_sets(&online, &allowed, &eligible) == 0) {
            nc_cpu_steering_mask_to_json(&online, online_json);
            nc_cpu_steering_mask_to_json(&eligible, eligible_json);
        }
        if (json_object_object_get_ex(d, "interfaces", &ifaces) && ifaces &&
            json_object_is_type(ifaces, json_type_array)) {
            for (i = 0; i < json_object_array_length(ifaces); i++) {
                struct json_object *iface = json_object_array_get_idx(ifaces, i);
                struct json_object *value = NULL;
                struct json_object *queues = NULL;
                int q;

                if (!iface || !json_object_is_type(iface, json_type_object) ||
                    !json_object_object_get_ex(iface, "eligible", &value) ||
                    !json_object_get_boolean(value))
                    continue;
                if (json_object_object_get_ex(iface, "ifname", &value) && value &&
                    json_object_is_type(value, json_type_string))
                    json_object_array_add(eligible_ifaces,
                                          json_object_new_string(json_object_get_string(value)));
                if (json_object_object_get_ex(iface, "rx_queue_rps", &queues) && queues) {
                    for (q = 0; q < (int)json_object_array_length(queues); q++) {
                        struct json_object *item = json_object_array_get_idx(queues, q);
                        const char *raw = NULL;
                        if (item && json_object_object_get_ex(item, "rps_cpus", &value) && value &&
                            json_object_is_type(value, json_type_string))
                            raw = json_object_get_string(value);
                        if (raw && nc_cpu_steering_mask_parse(raw, &current) == 0) {
                            if (!saw_target) common = current;
                            else nc_cpu_steering_mask_or(&common, &current);
                            saw_target = 1;
                        }
                    }
                }
                if (json_object_object_get_ex(iface, "tx_queue_xps", &queues) && queues) {
                    for (q = 0; q < (int)json_object_array_length(queues); q++) {
                        struct json_object *item = json_object_array_get_idx(queues, q);
                        const char *raw = NULL;
                        if (item && json_object_object_get_ex(item, "xps_cpus", &value) && value &&
                            json_object_is_type(value, json_type_string))
                            raw = json_object_get_string(value);
                        if (raw && nc_cpu_steering_mask_parse(raw, &current) == 0) {
                            if (!saw_target) common = current;
                            else nc_cpu_steering_mask_or(&common, &current);
                            saw_target = 1;
                        }
                    }
                }
            }
        }
        if (saw_target) {
            nc_cpu_steering_mask_remove(&eligible, &common);
            nc_cpu_steering_mask_to_json(&eligible, excluded_json);
        }
        json_object_object_add(d, "online_cpus", online_json);
        json_object_object_add(d, "eligible_network_cpus", eligible_json);
        json_object_object_add(d, "eligible_network_interfaces", eligible_ifaces);
        json_object_object_add(d, "excluded_soft_cpus", excluded_json);
    }
    json_object_object_add(d, "cpu_exclusion_supported", json_object_new_boolean(1));
    json_object_object_add(d, "cpu_exclusion_write_method",
                           json_object_new_string("system_net_tuning_set"));
    json_object_object_add(d, "irqbalance_present",
                           json_object_new_boolean(nc_sys_file_exists("/etc/init.d/irqbalance")));
    json_object_object_add(d, "irqbalance_running",
                           json_object_new_boolean(nc_adv_process_running("irqbalance")));
    json_object_object_add(d, "irq_affinity_writable",
                           json_object_new_boolean(nc_irq_affinity_any_writable()));
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

struct json_object *jmx_system_cpu_interrupt_get(void)
{
    struct json_object *d = json_object_new_object();
    struct json_object *irqs = json_object_new_array();
    struct json_object *online_json = json_object_new_array();
    struct json_object *eligible_json = json_object_new_array();
    struct json_object *excluded_json = json_object_new_array();
    FILE *fp = fopen("/proc/interrupts", "r");
    char line[4096];
    int cpu_count = 0;
    int irq_count = 0;
    int writable_irq_count = 0;
    nc_cpu_steering_mask_t online, allowed, eligible, common;
    int saw_ethernet = 0;

    nc_cpu_steering_mask_zero(&online);
    nc_cpu_steering_mask_zero(&allowed);
    nc_cpu_steering_mask_zero(&eligible);
    nc_cpu_steering_mask_zero(&common);
    if (nc_cpu_steering_read_cpu_sets(&online, &allowed, &eligible) == 0) {
        nc_cpu_steering_mask_to_json(&online, online_json);
        nc_cpu_steering_mask_to_json(&eligible, eligible_json);
    }

    json_object_object_add(d, "ok", json_object_new_boolean(fp != NULL));
    json_object_object_add(d, "semantic",
                           json_object_new_string("ethernet_irq_affinity_cpu_exclusion"));
    json_object_object_add(d, "legacy_semantic",
                           json_object_new_string("irq_smp_affinity"));
    json_object_object_add(d, "persistent", json_object_new_boolean(0));
    /*
     * A per-CPU "turn softirq/hardirq off" switch does not exist in Linux, so
     * these stay false. They previously carried no reason, which the UI showed
     * as a blanket "not supported" and was read as "no interrupt tuning is
     * possible at all" - the opposite of the truth. The reason strings and the
     * tunable_* pointers below say what is actually available instead.
     */
    json_object_object_add(d, "softirq_toggle_supported", json_object_new_boolean(0));
    json_object_object_add(d, "softirq_toggle_reason",
                           json_object_new_string("no_kernel_interface_to_disable_softirq_per_cpu"));
    json_object_object_add(d, "hardirq_toggle_supported", json_object_new_boolean(0));
    json_object_object_add(d, "hardirq_toggle_reason",
                           json_object_new_string("no_kernel_interface_to_disable_hardirq_per_cpu"));
    json_object_object_add(d, "softirq_tunable_supported",
                           json_object_new_boolean(nc_net_tune_path_writable("/proc/sys/net/core/netdev_budget")));
    json_object_object_add(d, "affinity_tunable_supported",
                           json_object_new_boolean(nc_irq_affinity_any_writable()));
    /* Where the softirq/RPS detail lives, so the UI need not guess. */
    json_object_object_add(d, "net_tuning_endpoint",
                           json_object_new_string("/api/v1/system/advanced/net-tuning"));
    nc_irq_add_optional_text(d, "cpu_possible", "/sys/devices/system/cpu/possible");
    nc_irq_add_optional_text(d, "cpu_online", "/sys/devices/system/cpu/online");
    nc_irq_add_optional_text(d, "allowed_smp_affinity", "/proc/irq/default_smp_affinity");

    if (!fp) {
        json_object_object_add(d, "error", json_object_new_string("proc_interrupts_unavailable"));
        json_object_object_add(d, "irqs", irqs);
        return jmx_gen_api_response_data(API_CODE_ERROR, d);
    }

    if (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while ((p = strstr(p, "CPU")) != NULL) {
            char *end = NULL;
            (void)strtol(p + 3, &end, 10);
            if (end == p + 3) break;
            cpu_count++;
            p = end;
        }
    }

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        char *end = NULL;
        long irq;
        struct json_object *o;
        struct json_object *counts;
        int64_t total = 0;
        char path[160];
        char descriptor[2048] = "";
        char ifname[IFNAMSIZ] = "";
        char affinity_list[512] = "";
        int ethernet;

        while (*p && isspace((unsigned char)*p)) p++;
        if (!isdigit((unsigned char)*p)) continue;
        irq = strtol(p, &end, 10);
        if (end == p || *end != ':' || irq <= 0 || irq > 1048575) continue;
        p = end + 1;
        o = json_object_new_object();
        counts = json_object_new_array();
        for (int i = 0; i < cpu_count; i++) {
            unsigned long long count;
            while (*p && isspace((unsigned char)*p)) p++;
            if (!isdigit((unsigned char)*p)) break;
            count = strtoull(p, &end, 10);
            if (end == p) break;
            json_object_array_add(counts, json_object_new_int64((int64_t)count));
            if (count <= (unsigned long long)(INT64_MAX - total)) total += (int64_t)count;
            else total = INT64_MAX;
            p = end;
        }
        while (*p && isspace((unsigned char)*p)) p++;
        snprintf(descriptor, sizeof(descriptor), "%s", p);
        descriptor[strcspn(descriptor, "\r\n")] = 0;
        ethernet = nc_cpu_steering_descriptor_ifname(descriptor, ifname,
                                                     sizeof(ifname));

        json_object_object_add(o, "irq", json_object_new_int64(irq));
        json_object_object_add(o, "interrupts", counts);
        json_object_object_add(o, "total", json_object_new_int64(total));
        json_object_object_add(o, "name", json_object_new_string(descriptor));
        json_object_object_add(o, "ethernet_irq", json_object_new_boolean(ethernet));
        if (ethernet) {
            json_object_object_add(o, "ifname", json_object_new_string(ifname));
            json_object_object_add(o, "eligible", json_object_new_boolean(1));
            json_object_object_add(o, "eligibility_reason", json_object_new_null());
        } else {
            json_object_object_add(o, "ifname", json_object_new_null());
            json_object_object_add(o, "eligible", json_object_new_boolean(0));
            json_object_object_add(o, "eligibility_reason",
                                   json_object_new_string("non_ethernet_irq"));
        }
        snprintf(path, sizeof(path), "/proc/irq/%ld/smp_affinity", irq);
        nc_irq_add_optional_text(o, "smp_affinity", path);
        {
            int writable = nc_irq_affinity_path_writable(path);
            json_object_object_add(o, "writable", json_object_new_boolean(writable));
            if (writable) {
                writable_irq_count++;
                json_object_object_add(o, "write_reason", json_object_new_null());
            } else {
                json_object_object_add(o, "write_reason",
                                       json_object_new_string("kernel_managed_affinity_or_read_only"));
            }
        }
        snprintf(path, sizeof(path), "/proc/irq/%ld/smp_affinity_list", irq);
        nc_irq_add_optional_text(o, "smp_affinity_list", path);
        if (ethernet && nc_irq_read_text(path, affinity_list,
                                         sizeof(affinity_list)) == 0) {
            nc_cpu_steering_mask_t current;
            if (nc_cpu_steering_list_parse(affinity_list, &current) == 0) {
                if (!saw_ethernet)
                    common = current;
                else
                    nc_cpu_steering_mask_or(&common, &current);
                saw_ethernet = 1;
            }
        }
        snprintf(path, sizeof(path), "/proc/irq/%ld/effective_affinity", irq);
        nc_irq_add_optional_text(o, "effective_affinity", path);
        snprintf(path, sizeof(path), "/proc/irq/%ld/effective_affinity_list", irq);
        nc_irq_add_optional_text(o, "effective_affinity_list", path);
        {
            int managed = !nc_irq_affinity_path_writable(
                "/proc/irq/0/smp_affinity");
            snprintf(path, sizeof(path), "/proc/irq/%ld/smp_affinity", irq);
            managed = !nc_irq_affinity_path_writable(path);
            json_object_object_add(o, "managed", json_object_new_boolean(managed));
            json_object_object_add(o, "managed_reason",
                                   json_object_new_string(managed ?
                                       "managed_irq_or_read_only" :
                                       "runtime_affinity_writable"));
        }
        json_object_object_add(o, "persistent", json_object_new_boolean(0));
        json_object_array_add(irqs, o);
        irq_count++;
    }
    fclose(fp);
    json_object_object_add(d, "cpu_count", json_object_new_int(cpu_count));
    json_object_object_add(d, "irq_count", json_object_new_int(irq_count));
    json_object_object_add(d, "writable_irq_count", json_object_new_int(writable_irq_count));
    json_object_object_add(d, "write_supported", json_object_new_boolean(writable_irq_count > 0));
    if (writable_irq_count == 0)
        json_object_object_add(d, "write_reason", json_object_new_string("no_writable_irq_affinity"));
    else
        json_object_object_add(d, "write_reason", json_object_new_null());
    json_object_object_add(d, "irqs", irqs);
    json_object_object_add(d, "online_cpus", online_json);
    json_object_object_add(d, "eligible_network_cpus", eligible_json);
    if (saw_ethernet) {
        nc_cpu_steering_mask_remove(&eligible, &common);
        nc_cpu_steering_mask_to_json(&eligible, excluded_json);
    }
    json_object_object_add(d, "excluded_hard_cpus", excluded_json);
    json_object_object_add(d, "irqbalance_present",
                           json_object_new_boolean(nc_sys_file_exists("/etc/init.d/irqbalance")));
    json_object_object_add(d, "irqbalance_running",
                           json_object_new_boolean(nc_adv_process_running("irqbalance")));
    json_object_object_add(d, "irqbalance_reason",
                           json_object_new_string(nc_adv_process_running("irqbalance") ?
                               "irqbalance_conflict" : "irqbalance_not_running"));
    json_object_object_add(d, "ts", json_object_new_int64(nc_now_s()));
    return jmx_gen_api_response_data(API_CODE_SUCCESS, d);
}

/* Writes one text value to a procfs/sysfs file and reports errno on failure. */
static int nc_net_tune_write_path(const char *path, const char *value,
                                  struct json_object *out)
{
    FILE *fp = fopen(path, "w");
    int write_rc;
    int flush_rc;
    int saved_errno;
    int close_rc;
    char msg[320];

    if (!fp) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("write_failed"));
        snprintf(msg, sizeof(msg), "cannot open %s: %s", path, strerror(errno));
        json_object_object_add(out, "message", json_object_new_string(msg));
        return -1;
    }
    errno = 0;
    write_rc = fprintf(fp, "%s\n", value);
    flush_rc = write_rc < 0 ? -1 : fflush(fp);
    saved_errno = errno;
    close_rc = fclose(fp);
    if (write_rc >= 0 && flush_rc == 0 && close_rc == 0)
        return 0;
    if (!saved_errno)
        saved_errno = errno;
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string("write_failed"));
    snprintf(msg, sizeof(msg), "cannot write %s: %s", path,
             saved_errno ? strerror(saved_errno) : "kernel rejected value");
    json_object_object_add(out, "message", json_object_new_string(msg));
    return -1;
}

/* Validates an RPS/affinity style hex CPU mask, optionally comma grouped. */
static int nc_net_tune_mask_valid(const char *mask)
{
    size_t len;
    const char *p;

    if (!mask || !*mask)
        return 0;
    len = strlen(mask);
    if (len > 255)
        return 0;
    if (mask[0] == ',' || mask[len - 1] == ',' || strstr(mask, ",,"))
        return 0;
    for (p = mask; *p; p++) {
        if (*p != ',' && !isxdigit((unsigned char)*p))
            return 0;
    }
    return 1;
}

static void nc_cpu_steering_add_cpus(struct json_object *out, const char *key,
                                     const nc_cpu_steering_mask_t *mask)
{
    struct json_object *array = json_object_new_array();

    nc_cpu_steering_mask_to_json(mask, array);
    json_object_object_add(out, key, array);
}

static void nc_cpu_steering_add_skip(struct json_object *skipped,
                                     int kind, const char *ifname, int number,
                                     const char *path, const char *reason)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "kind", json_object_new_string(
        kind == NC_CPU_STEERING_RX ? "rx" :
        kind == NC_CPU_STEERING_TX ? "tx" : "ethernet_irq"));
    if (ifname && ifname[0])
        json_object_object_add(item, "ifname", json_object_new_string(ifname));
    else
        json_object_object_add(item, "ifname", json_object_new_null());
    if (kind == NC_CPU_STEERING_IRQ)
        json_object_object_add(item, "irq", json_object_new_int(number));
    else
        json_object_object_add(item, "queue", json_object_new_int(number));
    if (path && path[0])
        json_object_object_add(item, "path", json_object_new_string(path));
    else
        json_object_object_add(item, "path", json_object_new_null());
    json_object_object_add(item, "reason", json_object_new_string(
                               reason && reason[0] ? reason : "unknown"));
    json_object_array_add(skipped, item);
}

static void nc_cpu_steering_add_target(struct json_object *array,
                                       const nc_cpu_steering_target_t *target,
                                       const char *status, const char *reason)
{
    struct json_object *item = json_object_new_object();

    json_object_object_add(item, "kind", json_object_new_string(
        target->kind == NC_CPU_STEERING_RX ? "rx" :
        target->kind == NC_CPU_STEERING_TX ? "tx" : "ethernet_irq"));
    json_object_object_add(item, "ifname", target->ifname[0] ?
                           json_object_new_string(target->ifname) :
                           json_object_new_null());
    if (target->kind == NC_CPU_STEERING_IRQ)
        json_object_object_add(item, "irq", json_object_new_int(target->number));
    else
        json_object_object_add(item, "queue", json_object_new_int(target->number));
    json_object_object_add(item, "path", json_object_new_string(target->path));
    json_object_object_add(item, "previous", json_object_new_string(target->previous));
    json_object_object_add(item, "requested", json_object_new_string(target->requested));
    json_object_object_add(item, "readback", target->readback[0] ?
                           json_object_new_string(target->readback) :
                           json_object_new_null());
    json_object_object_add(item, "status", json_object_new_string(status));
    if (reason && reason[0])
        json_object_object_add(item, "reason", json_object_new_string(reason));
    else
        json_object_object_add(item, "reason", json_object_new_null());
    json_object_array_add(array, item);
}

static int nc_cpu_steering_target_text_parse(
    const nc_cpu_steering_target_t *target, const char *text,
    nc_cpu_steering_mask_t *mask)
{
    if (!target || !text || !mask)
        return -1;
    return target->kind == NC_CPU_STEERING_IRQ ?
           nc_cpu_steering_list_parse(text, mask) :
           nc_cpu_steering_mask_parse(text, mask);
}

static int nc_cpu_steering_target_text_equal(
    const nc_cpu_steering_target_t *target, const char *left,
    const char *right)
{
    nc_cpu_steering_mask_t left_mask, right_mask;

    return target && left && right &&
           nc_cpu_steering_target_text_parse(target, left, &left_mask) == 0 &&
           nc_cpu_steering_target_text_parse(target, right, &right_mask) == 0 &&
           !memcmp(&left_mask, &right_mask, sizeof(left_mask));
}

static int nc_cpu_steering_parse_request(struct json_object *cfg,
                                         nc_cpu_steering_mask_t *requested,
                                         nc_cpu_steering_mask_t *eligible,
                                         struct json_object *out)
{
    struct json_object *cpus = NULL;
    struct json_object *item;
    nc_cpu_steering_mask_t online, allowed;
    size_t i;

    if (!cfg || !requested || !eligible || !out ||
        !json_object_object_get_ex(cfg, "cpus", &cpus) || !cpus ||
        !json_object_is_type(cpus, json_type_array) ||
        json_object_array_length(cpus) == 0) {
        json_object_object_add(out, "error", json_object_new_string("invalid_cpu_list"));
        json_object_object_add(out, "message",
                               json_object_new_string("cpus must be a non-empty integer array"));
        return -1;
    }
    nc_cpu_steering_mask_zero(requested);
    if (nc_cpu_steering_read_cpu_sets(&online, &allowed, eligible) != 0) {
        json_object_object_add(out, "error", json_object_new_string("cpu_offline_or_not_allowed"));
        return -1;
    }
    for (i = 0; i < json_object_array_length(cpus); i++) {
        int cpu;

        item = json_object_array_get_idx(cpus, i);
        if (!item || !json_object_is_type(item, json_type_int)) {
            json_object_object_add(out, "error", json_object_new_string("invalid_cpu_list"));
            return -1;
        }
        cpu = json_object_get_int(item);
        if (cpu < 0 || cpu >= NC_CPU_STEERING_MASK_WORDS * 32 ||
            !nc_cpu_steering_mask_has(&online, cpu)) {
            json_object_object_add(out, "error",
                                   json_object_new_string("cpu_offline_or_not_allowed"));
            json_object_object_add(out, "failed_cpu", json_object_new_int(cpu));
            return -1;
        }
        if (!nc_cpu_steering_mask_has(&allowed, cpu)) {
            json_object_object_add(out, "error",
                                   json_object_new_string("cpu_offline_or_not_allowed"));
            json_object_object_add(out, "failed_cpu", json_object_new_int(cpu));
            return -1;
        }
        nc_cpu_steering_mask_set(requested, cpu);
    }
    nc_cpu_steering_add_cpus(out, "requested_cpus", requested);
    return 0;
}

static int nc_cpu_steering_parse_directions(struct json_object *cfg,
                                            int *want_rx, int *want_tx,
                                            struct json_object *out)
{
    struct json_object *directions = NULL;
    size_t i;

    *want_rx = 0;
    *want_tx = 0;
    if (!json_object_object_get_ex(cfg, "directions", &directions) || !directions) {
        *want_rx = 1;
        *want_tx = 1;
        return 0;
    }
    if (!json_object_is_type(directions, json_type_array) ||
        json_object_array_length(directions) == 0) {
        json_object_object_add(out, "error", json_object_new_string("invalid_directions"));
        return -1;
    }
    for (i = 0; i < json_object_array_length(directions); i++) {
        struct json_object *item = json_object_array_get_idx(directions, i);
        const char *direction;

        if (!item || !json_object_is_type(item, json_type_string)) {
            json_object_object_add(out, "error", json_object_new_string("invalid_directions"));
            return -1;
        }
        direction = json_object_get_string(item);
        if (!strcmp(direction, "rx"))
            *want_rx = 1;
        else if (!strcmp(direction, "tx"))
            *want_tx = 1;
        else {
            json_object_object_add(out, "error", json_object_new_string("invalid_directions"));
            return -1;
        }
    }
    return (*want_rx || *want_tx) ? 0 : -1;
}

static int nc_cpu_steering_target_prepare(nc_cpu_steering_target_t *target,
                                          const char *operation,
                                          const nc_cpu_steering_mask_t *requested,
                                          const nc_cpu_steering_mask_t *eligible,
                                          struct json_object *skipped)
{
    nc_cpu_steering_mask_t current, next;
    char current_text[512] = "";
    char next_text[512] = "";

    if (nc_irq_read_text(target->path, current_text, sizeof(current_text)) != 0 ||
        nc_cpu_steering_target_text_parse(target, current_text, &current) != 0) {
        nc_cpu_steering_add_skip(skipped, target->kind, target->ifname,
                                 target->number, target->path, "read_failed");
        return -1;
    }
    if ((target->kind == NC_CPU_STEERING_IRQ ?
         !nc_irq_affinity_path_writable(target->path) :
         !nc_net_tune_path_writable(target->path))) {
        nc_cpu_steering_add_skip(skipped, target->kind, target->ifname,
                                 target->number, target->path,
                                 target->kind == NC_CPU_STEERING_IRQ ?
                                 "managed_irq" : "queue_or_irq_not_writable");
        return -1;
    }
    next = current;
    if (!strcmp(operation, "exclude_cpus"))
        nc_cpu_steering_mask_remove(&next, requested);
    else
        nc_cpu_steering_mask_or(&next, requested);
    if (!nc_cpu_steering_mask_any(&next)) {
        nc_cpu_steering_add_skip(skipped, target->kind, target->ifname,
                                 target->number, target->path,
                                 "no_eligible_cpu_remaining");
        return -1;
    }
    {
        nc_cpu_steering_mask_t eligible_next = next;
        nc_cpu_steering_mask_and(&eligible_next, eligible);
        if (!nc_cpu_steering_mask_any(&eligible_next)) {
            nc_cpu_steering_add_skip(skipped, target->kind, target->ifname,
                                     target->number, target->path,
                                     "no_eligible_cpu_remaining");
            return -1;
        }
    }
    if ((target->kind == NC_CPU_STEERING_IRQ ?
         nc_cpu_steering_mask_to_list(&next, next_text, sizeof(next_text)) :
         nc_cpu_steering_mask_to_text(&next, next_text, sizeof(next_text))) != 0) {
        nc_cpu_steering_add_skip(skipped, target->kind, target->ifname,
                                 target->number, target->path, "invalid_mask");
        return -1;
    }
    snprintf(target->previous, sizeof(target->previous), "%s", current_text);
    snprintf(target->requested, sizeof(target->requested), "%s", next_text);
    return 0;
}

static int nc_cpu_steering_apply_targets(nc_cpu_steering_target_t *targets,
                                         size_t target_count,
                                         struct json_object *skipped,
                                         struct json_object *out,
                                         const char *operation,
                                         const nc_cpu_steering_mask_t *requested,
                                         const nc_cpu_steering_mask_t *eligible)
{
    struct json_object *changed = json_object_new_array();
    struct json_object *readback = json_object_new_array();
    size_t i;
    int failed = 0;
    int rollback_ok = 1;
    const char *failure_error = "readback_mismatch";

    for (i = 0; i < target_count; i++) {
        struct json_object *write_result = json_object_new_object();
        nc_cpu_steering_mask_t desired, got;
        char value[512] = "";

        if (nc_cpu_steering_target_text_parse(&targets[i], targets[i].requested,
                                              &desired) != 0) {
            targets[i].changed = 1;
            failed = 1;
            failure_error = "write_failed";
            json_object_put(write_result);
            break;
        }
        targets[i].changed = !nc_cpu_steering_target_text_equal(
            &targets[i], targets[i].previous, targets[i].requested);
        if (!targets[i].changed) {
            nc_cpu_steering_add_target(readback, &targets[i], "unchanged", NULL);
            json_object_put(write_result);
            continue;
        }
        if (nc_net_tune_write_path(targets[i].path, targets[i].requested,
                                   write_result) != 0) {
            targets[i].changed = 1;
            failed = 1;
            failure_error = "write_failed";
            json_object_put(write_result);
            break;
        }
        if (nc_irq_read_text(targets[i].path, value, sizeof(value)) != 0 ||
            nc_cpu_steering_target_text_parse(&targets[i], value, &got) != 0 ||
            memcmp(&desired, &got, sizeof(desired)) != 0) {
            snprintf(targets[i].readback, sizeof(targets[i].readback), "%s", value);
            failed = 1;
            failure_error = "readback_mismatch";
            json_object_put(write_result);
            break;
        }
        snprintf(targets[i].readback, sizeof(targets[i].readback), "%s", value);
        nc_cpu_steering_add_target(readback, &targets[i], "applied", NULL);
        json_object_put(write_result);
    }
    if (!failed) {
        for (i = 0; i < target_count; i++) {
            if (targets[i].changed)
                nc_cpu_steering_add_target(changed, &targets[i], "applied", NULL);
        }
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        nc_cpu_steering_add_cpus(out, "applied_cpus", requested);
        json_object_object_add(out, "changed_nodes", changed);
        json_object_object_add(out, "readback", readback);
        json_object_object_add(out, "rollback_performed", json_object_new_boolean(0));
        json_object_object_add(out, "rollback_succeeded", json_object_new_boolean(1));
        json_object_object_add(out, "skipped_nodes", skipped);
        (void)operation;
        (void)eligible;
        return 0;
    }

    json_object_object_add(out, "rollback_performed", json_object_new_boolean(1));
    if (i < target_count && targets[i].changed)
        i++;
    while (i > 0) {
        nc_cpu_steering_target_t *target;
        struct json_object *rollback_result;
        char restored[512] = "";
        int target_rollback_ok = 1;

        target = &targets[--i];
        if (!target->changed)
            continue;
        rollback_result = json_object_new_object();
        if (nc_net_tune_write_path(target->path, target->previous,
                                   rollback_result) != 0 ||
            nc_irq_read_text(target->path, restored, sizeof(restored)) != 0 ||
            !nc_cpu_steering_target_text_equal(target, restored,
                                               target->previous)) {
            target_rollback_ok = 0;
            rollback_ok = 0;
        }
        snprintf(target->readback, sizeof(target->readback), "%s", restored);
        nc_cpu_steering_add_target(changed, target,
                                   target_rollback_ok ? "rolled_back" :
                                                        "rollback_failed",
                                   target_rollback_ok ? NULL : "rollback_failed");
        nc_cpu_steering_add_target(readback, target,
                                   target_rollback_ok ? "rolled_back" :
                                                        "rollback_failed",
                                   target_rollback_ok ? NULL : "rollback_failed");
        json_object_put(rollback_result);
    }
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string(
                               rollback_ok ? failure_error : "rollback_failed"));
    json_object_object_add(out, "rollback_succeeded",
                           json_object_new_boolean(rollback_ok));
    json_object_object_add(out, "changed_nodes", changed);
    json_object_object_add(out, "readback", readback);
    json_object_object_add(out, "skipped_nodes", skipped);
    (void)operation;
    (void)eligible;
    return -1;
}

static int nc_cpu_steering_operation_ok(const char *operation)
{
    return operation && (!strcmp(operation, "exclude_cpus") ||
                         !strcmp(operation, "include_cpus"));
}

static void nc_cpu_steering_result_init(struct json_object *out,
                                        const char *semantic,
                                        const char *operation)
{
    nc_cpu_steering_add_common(out, semantic);
    json_object_object_add(out, "operation", json_object_new_string(operation));
    json_object_object_add(out, "changed_nodes", json_object_new_array());
    json_object_object_add(out, "skipped_nodes", json_object_new_array());
    json_object_object_add(out, "readback", json_object_new_array());
    json_object_object_add(out, "rollback_performed", json_object_new_boolean(0));
    json_object_object_add(out, "rollback_succeeded", json_object_new_boolean(1));
}

static struct json_object *nc_cpu_steering_result_array(struct json_object *out,
                                                         const char *key)
{
    struct json_object *array = NULL;

    if (out)
        json_object_object_get_ex(out, key, &array);
    return array;
}

static int nc_cpu_steering_batch_net_set(struct json_object *cfg,
                                         struct json_object *out)
{
    const char *operation = nc_json_str_def(cfg, "operation", "");
    nc_cpu_steering_mask_t requested, eligible;
    struct json_object *skipped;
    struct json_object *directions;
    DIR *dir;
    struct dirent *entry;
    nc_cpu_steering_target_t targets[NC_CPU_STEERING_TARGET_MAX];
    size_t target_count = 0;
    int want_rx = 0;
    int want_tx = 0;
    int saw_eligible = 0;
    int preflight_failed = 0;

    nc_cpu_steering_result_init(out, "network_rps_xps_cpu_exclusion_set", operation);
    skipped = nc_cpu_steering_result_array(out, "skipped_nodes");
    if (!nc_cpu_steering_operation_ok(operation)) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_operation"));
        return -1;
    }
    if (nc_cpu_steering_parse_request(cfg, &requested, &eligible, out) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        return -1;
    }
    if (nc_cpu_steering_parse_directions(cfg, &want_rx, &want_tx, out) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        return -1;
    }
    directions = json_object_new_array();
    if (want_rx)
        json_object_array_add(directions, json_object_new_string("rx"));
    if (want_tx)
        json_object_array_add(directions, json_object_new_string("tx"));
    json_object_object_add(out, "directions", directions);
    json_object_object_add(out, "irqbalance_present",
                           json_object_new_boolean(nc_sys_file_exists("/etc/init.d/irqbalance")));
    json_object_object_add(out, "irqbalance_running",
                           json_object_new_boolean(nc_adv_process_running("irqbalance")));
    if (nc_sys_file_exists("/etc/init.d/irqbalance") ||
        nc_adv_process_running("irqbalance")) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("irqbalance_conflict"));
        return -1;
    }
    dir = opendir("/sys/class/net");
    if (!dir) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("network_interface_not_eligible"));
        return -1;
    }
    while ((entry = readdir(dir)) != NULL) {
        char reason[96] = "";
        int rx, tx, q;

        if (entry->d_name[0] == '.' || !strcmp(entry->d_name, "lo"))
            continue;
        if (!nc_cpu_steering_ifname_eligible(entry->d_name, reason, sizeof(reason))) {
            continue;
        }
        saw_eligible = 1;
        rx = nc_net_iface_queue_count(entry->d_name, "rx-");
        tx = nc_net_iface_queue_count(entry->d_name, "tx-");
        for (q = 0; want_rx && q < rx; q++) {
            nc_cpu_steering_target_t target;
            memset(&target, 0, sizeof(target));
            target.kind = NC_CPU_STEERING_RX;
            target.number = q;
            /*
             * target.ifname is IFNAMSIZ; a directory entry under
             * /sys/class/net cannot legitimately be longer, and steering a
             * truncated name would write the wrong queue's mask.
             */
            if (JMX_STRBUF_COPY(target.ifname, entry->d_name) != 0)
                continue;
            snprintf(target.path, sizeof(target.path),
                     "/sys/class/net/%s/queues/rx-%d/rps_cpus", entry->d_name, q);
            if (nc_cpu_steering_target_prepare(&target, operation, &requested,
                                               &eligible, skipped) != 0) {
                preflight_failed = 1;
                continue;
            }
            if (target_count < NC_CPU_STEERING_TARGET_MAX)
                targets[target_count++] = target;
        }
        for (q = 0; want_tx && q < tx; q++) {
            nc_cpu_steering_target_t target;
            memset(&target, 0, sizeof(target));
            target.kind = NC_CPU_STEERING_TX;
            target.number = q;
            if (JMX_STRBUF_COPY(target.ifname, entry->d_name) != 0)
                continue;
            snprintf(target.path, sizeof(target.path),
                     "/sys/class/net/%s/queues/tx-%d/xps_cpus", entry->d_name, q);
            if (nc_cpu_steering_target_prepare(&target, operation, &requested,
                                               &eligible, skipped) != 0) {
                preflight_failed = 1;
                continue;
            }
            if (target_count < NC_CPU_STEERING_TARGET_MAX)
                targets[target_count++] = target;
        }
    }
    closedir(dir);
    if (!saw_eligible) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("network_interface_not_eligible"));
        return -1;
    }
    if (target_count == 0 || preflight_failed) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        if (target_count == 0)
            json_object_object_add(out, "error", json_object_new_string("queue_or_irq_not_writable"));
        else
            json_object_object_add(out, "error", json_object_new_string("queue_or_irq_not_writable"));
        return -1;
    }
    nc_cpu_steering_add_cpus(out, "requested_cpus", &requested);
    return nc_cpu_steering_apply_targets(targets, target_count, skipped, out,
                                         operation, &requested, &eligible);
}

static int nc_cpu_steering_batch_irq_set(struct json_object *cfg,
                                         struct json_object *out)
{
    const char *operation = nc_json_str_def(cfg, "operation", "");
    const char *scope = nc_json_str_def(cfg, "scope", "");
    nc_cpu_steering_mask_t requested, eligible;
    struct json_object *skipped;
    FILE *fp;
    char line[4096];
    int cpu_count = 0;
    nc_cpu_steering_target_t targets[NC_CPU_STEERING_TARGET_MAX];
    size_t target_count = 0;
    int preflight_failed = 0;

    nc_cpu_steering_result_init(out, "ethernet_irq_affinity_cpu_exclusion_set", operation);
    skipped = nc_cpu_steering_result_array(out, "skipped_nodes");
    if (!nc_cpu_steering_operation_ok(operation) || strcmp(scope, "ethernet_irq")) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("invalid_operation"));
        return -1;
    }
    if (nc_cpu_steering_parse_request(cfg, &requested, &eligible, out) != 0) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        return -1;
    }
    json_object_object_add(out, "scope", json_object_new_string(scope));
    json_object_object_add(out, "irqbalance_present",
                           json_object_new_boolean(nc_sys_file_exists("/etc/init.d/irqbalance")));
    json_object_object_add(out, "irqbalance_running",
                           json_object_new_boolean(nc_adv_process_running("irqbalance")));
    if (nc_sys_file_exists("/etc/init.d/irqbalance") ||
        nc_adv_process_running("irqbalance")) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("irqbalance_conflict"));
        return -1;
    }
    fp = fopen("/proc/interrupts", "r");
    if (!fp) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string("proc_interrupts_unavailable"));
        return -1;
    }
    if (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while ((p = strstr(p, "CPU")) != NULL) {
            char *end = NULL;
            (void)strtol(p + 3, &end, 10);
            if (end == p + 3)
                break;
            cpu_count++;
            p = end;
        }
    }
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        char *end = NULL;
        long irq;
        char descriptor[2048] = "";
        char ifname[IFNAMSIZ] = "";
        nc_cpu_steering_target_t target;

        while (*p && isspace((unsigned char)*p))
            p++;
        if (!isdigit((unsigned char)*p))
            continue;
        irq = strtol(p, &end, 10);
        if (end == p || *end != ':' || irq <= 0 || irq > 1048575)
            continue;
        p = end + 1;
        for (int i = 0; i < cpu_count; i++) {
            while (*p && isspace((unsigned char)*p))
                p++;
            if (!isdigit((unsigned char)*p))
                break;
            (void)strtoull(p, &end, 10);
            p = end;
        }
        while (*p && isspace((unsigned char)*p))
            p++;
        snprintf(descriptor, sizeof(descriptor), "%s", p);
        descriptor[strcspn(descriptor, "\r\n")] = 0;
        if (!nc_cpu_steering_descriptor_ifname(descriptor, ifname, sizeof(ifname)))
            continue;
        memset(&target, 0, sizeof(target));
        target.kind = NC_CPU_STEERING_IRQ;
        target.number = (int)irq;
        snprintf(target.ifname, sizeof(target.ifname), "%s", ifname);
        snprintf(target.path, sizeof(target.path),
                 "/proc/irq/%ld/smp_affinity_list", irq);
        if (nc_cpu_steering_target_prepare(&target, operation, &requested,
                                           &eligible, skipped) != 0) {
            preflight_failed = 1;
            continue;
        }
        if (target_count < NC_CPU_STEERING_TARGET_MAX)
            targets[target_count++] = target;
    }
    fclose(fp);
    if (target_count == 0 || preflight_failed) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error", json_object_new_string(
                                   target_count ? "managed_irq" : "network_interface_not_eligible"));
        return -1;
    }
    nc_cpu_steering_add_cpus(out, "requested_cpus", &requested);
    return nc_cpu_steering_apply_targets(targets, target_count, skipped, out,
                                         operation, &requested, &eligible);
}

/*
 * Runtime network tuning writes: sysctl knobs and per-queue rps_cpus.
 *
 * Two payload shapes, matching the read surface:
 *   {"knob":"netdev_budget","value":600}
 *   {"ifname":"eth1","rx_queue":0,"rps_cpus":"00ff"}
 *
 * Every accepted write is read back from the kernel and the readback value is
 * what gets returned. Reporting success from the write syscall alone would let
 * a silently clamped or rejected value look applied.
 */
int jmx_system_net_tuning_set(struct json_object *cfg, struct json_object *out)
{
    const char *knob;
    const char *ifname;
    const char *rps;
    char readback[256] = "";
    const char *operation = cfg ? nc_json_str_def(cfg, "operation", "") : "";

    if (!cfg || !out) return -1;
    if (operation[0])
        return nc_cpu_steering_batch_net_set(cfg, out);
    json_object_object_add(out, "semantic",
                           json_object_new_string("net_softirq_and_nic_tuning_set"));
    /* Runtime only. Saying otherwise would let the UI claim it was stored. */
    json_object_object_add(out, "persistent", json_object_new_boolean(0));
    json_object_object_add(out, "persistent_reason",
                           json_object_new_string("runtime_sysctl_resets_on_reboot"));

    knob = nc_json_str_def(cfg, "knob", "");
    ifname = nc_json_str_def(cfg, "ifname", "");
    rps = nc_json_str_def(cfg, "rps_cpus", "");

    if (knob[0] && (ifname[0] || rps[0])) {
        json_object_object_add(out, "ok", json_object_new_boolean(0));
        json_object_object_add(out, "error",
                               json_object_new_string("ambiguous_payload"));
        json_object_object_add(out, "message",
                               json_object_new_string("send either knob or ifname+rps_cpus, not both"));
        return -1;
    }

    if (knob[0]) {
        const nc_net_tune_knob_t *spec = nc_net_tune_knob_find(knob);
        struct json_object *val = NULL;
        int64_t requested;
        char buf[64];

        json_object_object_add(out, "knob", json_object_new_string(knob));
        if (!spec) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("unknown_knob"));
            return -1;
        }
        json_object_object_add(out, "path", json_object_new_string(spec->path));
        json_object_object_add(out, "min", json_object_new_int64((int64_t)spec->min));
        json_object_object_add(out, "max", json_object_new_int64((int64_t)spec->max));
        if (!json_object_object_get_ex(cfg, "value", &val) || !val ||
            !(json_object_is_type(val, json_type_int) ||
              json_object_is_type(val, json_type_string))) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("missing_value"));
            return -1;
        }
        if (json_object_is_type(val, json_type_string)) {
            const char *raw = json_object_get_string(val);
            char *end = NULL;
            long long n = strtoll(raw ? raw : "", &end, 10);

            if (!raw || !*raw || !end || *end != 0) {
                json_object_object_add(out, "ok", json_object_new_boolean(0));
                json_object_object_add(out, "error",
                                       json_object_new_string("value_not_an_integer"));
                return -1;
            }
            requested = (int64_t)n;
        } else {
            requested = (int64_t)json_object_get_int64(val);
        }
        json_object_object_add(out, "requested", json_object_new_int64(requested));
        /* Out-of-range values are refused here; 0 budget stalls receive. */
        if (requested < spec->min || requested > spec->max) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("value_out_of_range"));
            return -1;
        }
        if (nc_irq_read_text(spec->path, readback, sizeof(readback)) != 0) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("sysctl_absent_kernel_lacks_knob"));
            return -1;
        }
        json_object_object_add(out, "previous", json_object_new_string(readback));
        if (!nc_net_tune_path_writable(spec->path)) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("sysctl_read_only"));
            return -1;
        }
        snprintf(buf, sizeof(buf), "%lld", (long long)requested);
        if (nc_net_tune_write_path(spec->path, buf, out) != 0)
            return -1;
        readback[0] = 0;
        if (nc_irq_read_text(spec->path, readback, sizeof(readback)) != 0) {
            json_object_object_add(out, "ok", json_object_new_boolean(0));
            json_object_object_add(out, "error",
                                   json_object_new_string("readback_failed"));
            return -1;
        }
        json_object_object_add(out, "readback", json_object_new_string(readback));
        {
            char *end = NULL;
            long long got = strtoll(readback, &end, 10);

            if (end && *end == 0)
                json_object_object_add(out, "value",
                                       json_object_new_int64((int64_t)got));
            else
                json_object_object_add(out, "value", json_object_new_null());
            /* The kernel may clamp. Report what it actually holds. */
            if (end && *end == 0 && got != (long long)requested) {
                json_object_object_add(out, "ok", json_object_new_boolean(0));
                json_object_object_add(out, "error",
                                       json_object_new_string("readback_mismatch"));
                return -1;
            }
        }
        json_object_object_add(out, "ok", json_object_new_boolean(1));
        json_object_object_add(out, "ts", json_object_new_int64(nc_now_s()));
        return 0;
    }

    if (ifname[0] || rps[0]) {
        int queue = nc_json_int_def(cfg, "rx_queue", -1);
        char path[256];
        size_t i;

        json_object_object_add(out, "ifname", json_object_new_string(ifname));
        json_object_object_add(out, "rx_queue", json_object_new_int(queue));
        json_object_object_add(out, "rps_cpus", json_object_new_string(rps));
