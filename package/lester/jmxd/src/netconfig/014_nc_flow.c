/* ══════════════════════════════════════════════════════════════════════
 * Flow control: QoS + policy routing product state
 * ══════════════════════════════════════════════════════════════════════ */

static void nc_flow_db_init(void)
{
    nc_exec("CREATE TABLE IF NOT EXISTS flow_global (id INTEGER PRIMARY KEY CHECK (id = 1),enabled INTEGER NOT NULL DEFAULT 1,mode TEXT NOT NULL DEFAULT 'smart',default_policy TEXT NOT NULL DEFAULT 'auto',unknown_policy TEXT NOT NULL DEFAULT 'normal',dpi_required INTEGER NOT NULL DEFAULT 1,log_decisions INTEGER NOT NULL DEFAULT 1,sticky_session INTEGER NOT NULL DEFAULT 1,apply_state TEXT NOT NULL DEFAULT 'draft',last_apply_at INTEGER NOT NULL DEFAULT 0,updated_at INTEGER NOT NULL)");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_qos (id INTEGER PRIMARY KEY CHECK (id = 1),enabled INTEGER NOT NULL DEFAULT 1,scheduler TEXT NOT NULL DEFAULT 'cake',total_download_mbps INTEGER NOT NULL DEFAULT 1000,total_upload_mbps INTEGER NOT NULL DEFAULT 100,latency_target_ms INTEGER NOT NULL DEFAULT 25,per_host_fairness INTEGER NOT NULL DEFAULT 1,ack_filter INTEGER NOT NULL DEFAULT 1,diffserv TEXT NOT NULL DEFAULT 'diffserv4')");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_classes (id TEXT PRIMARY KEY,name TEXT NOT NULL,priority INTEGER NOT NULL,guarantee INTEGER NOT NULL DEFAULT 0,ceiling INTEGER NOT NULL DEFAULT 100,latency_target INTEGER NOT NULL DEFAULT 100,examples TEXT NOT NULL DEFAULT '',color TEXT NOT NULL DEFAULT '')");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_groups (id TEXT PRIMARY KEY,name TEXT NOT NULL,carrier TEXT NOT NULL DEFAULT '',mode TEXT NOT NULL,hash TEXT NOT NULL DEFAULT 'src_ip,dst_ip,dst_port',health_check INTEGER NOT NULL DEFAULT 1,failback INTEGER NOT NULL DEFAULT 1,remark TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1)");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_group_members (id INTEGER PRIMARY KEY AUTOINCREMENT,group_id TEXT NOT NULL,target TEXT NOT NULL,weight INTEGER NOT NULL DEFAULT 100,role TEXT NOT NULL DEFAULT 'active',sort_order INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_rules (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,priority INTEGER NOT NULL,name TEXT NOT NULL,type TEXT NOT NULL,source TEXT NOT NULL DEFAULT '',destination TEXT NOT NULL DEFAULT '',apps TEXT NOT NULL DEFAULT '',protocol TEXT NOT NULL DEFAULT '',action TEXT NOT NULL,target TEXT NOT NULL DEFAULT '',qos_class TEXT NOT NULL DEFAULT '',schedule TEXT NOT NULL DEFAULT 'always',fallback TEXT NOT NULL DEFAULT 'auto',sticky INTEGER NOT NULL DEFAULT 1,remark TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_client_limits (id TEXT PRIMARY KEY,enabled INTEGER NOT NULL DEFAULT 1,client TEXT NOT NULL,ip TEXT NOT NULL DEFAULT '',device_group TEXT NOT NULL DEFAULT '',upload_kbps INTEGER NOT NULL DEFAULT 0,download_kbps INTEGER NOT NULL DEFAULT 0,mode TEXT NOT NULL DEFAULT 'inherit',remark TEXT NOT NULL DEFAULT '')");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_runtime_hits (id INTEGER PRIMARY KEY AUTOINCREMENT,ts INTEGER NOT NULL,rule_id TEXT NOT NULL,client TEXT NOT NULL DEFAULT '',src_ip TEXT NOT NULL DEFAULT '',dst TEXT NOT NULL DEFAULT '',action TEXT NOT NULL,target TEXT NOT NULL,up_bytes INTEGER NOT NULL DEFAULT 0,down_bytes INTEGER NOT NULL DEFAULT 0,reason TEXT NOT NULL DEFAULT '')");
    nc_exec("INSERT OR IGNORE INTO flow_global(id,updated_at) VALUES(1,0)");
    nc_exec("UPDATE flow_global SET apply_state='draft',last_apply_at=0 WHERE apply_state='applied'");
    nc_exec("INSERT OR IGNORE INTO flow_qos(id) VALUES(1)");
    nc_exec("INSERT OR IGNORE INTO flow_classes(id,name,priority,guarantee,ceiling,latency_target,examples,color) VALUES('realtime','实时',1,20,100,18,'游戏 / 会议 / 语音','#1d7dff')");
    nc_exec("INSERT OR IGNORE INTO flow_classes(id,name,priority,guarantee,ceiling,latency_target,examples,color) VALUES('streaming','流媒体',3,10,100,50,'视频 / 直播','#7c3aed')");
    nc_exec("INSERT OR IGNORE INTO flow_classes(id,name,priority,guarantee,ceiling,latency_target,examples,color) VALUES('normal','普通',5,0,100,100,'网页 / 下载','#64748b')");

    /* Smart mode tables */
    nc_exec("CREATE TABLE IF NOT EXISTS flow_smart (id INTEGER PRIMARY KEY CHECK (id = 1), mode TEXT NOT NULL DEFAULT 'custom', updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("INSERT OR IGNORE INTO flow_smart(id) VALUES(1)");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_smart_line_mode (wan_id TEXT PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'custom', updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_smart_priority (app_key TEXT PRIMARY KEY, priority INTEGER NOT NULL DEFAULT 5, updated_at INTEGER NOT NULL DEFAULT 0)");
    nc_exec("CREATE TABLE IF NOT EXISTS flow_smart_line_priority (wan_id TEXT NOT NULL, app_key TEXT NOT NULL, priority INTEGER NOT NULL, updated_at INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(wan_id,app_key))");
    /*
     * Seed the category rows.
     *
     * The keys are the categories the classifier actually reports, not the
     * eleven the old LuCI page used. Two independent sources agree on this set:
     * the signature database's `app_category` table (17 slugs, measured on 30.1
     * across 5873 apps) and the kernel module's dense slot array
     * (JMX_APP_CAT_SLOTS = 18, jmx_conntrack.h:105 -- the 17 plus Unknown),
     * which is already counting live per-category traffic in
     * /proc/dreamingwrt/jmx/wan<N>/proto_stats.
     *
     * Only seven of the old eleven overlapped. Four old keys (entertainment /
     * productivity / social / work) match no application at all, while the two
     * largest real categories -- tool (1475 apps) and video (557) -- had nowhere
     * to go. A score on a key the classifier never produces cannot affect
     * traffic, so the old table could not express a priority for most of what
     * the router actually sees.
     *
     * `cloud` is seeded even though the signature database currently has no apps
     * in it: the kernel reserves the slot, so a future database that populates it
     * would otherwise start with no configurable priority.
     *
     * INSERT OR IGNORE, so a score the user already changed is never reset: the
     * seed only fills in keys that are absent. The four retired keys are left
     * in place rather than deleted -- see nc_flow_priority_key_ok(), which stops
     * accepting new writes to them while jmx_flow_control_apply() ignores them.
     * Deleting rows on a schema upgrade would silently discard a user's setting.
     */
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('game',0)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('video',1)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('chat',1)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('web',1)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('unknown',2)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('music',2)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('protocol',3)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('enterprise',3)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('cloud',3)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('tool',4)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('education',4)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('job',4)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('ai',4)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('security',4)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('life',5)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('finance',5)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('shopping',6)");
    nc_exec("INSERT OR IGNORE INTO flow_smart_priority(app_key,priority) VALUES('download',7)");
}

/*
 * The category keys the classifier can actually produce, with the DSCP class
 * each score maps to. Kept in one table so the write validator, the read path
 * and the dataplane apply cannot drift apart.
 *
 * `retired` marks the four keys the old eleven-category list had that no
 * application matches. Existing rows are preserved and still read back, but new
 * writes are refused and apply skips them: a score that cannot classify anything
 * is worse than absent, because the UI implies it works.
 */
struct nc_flow_category {
    const char *key;
    int retired;
};

static const struct nc_flow_category g_nc_flow_categories[] = {
    { "game", 0 }, { "video", 0 }, { "chat", 0 }, { "web", 0 },
    { "unknown", 0 }, { "music", 0 }, { "protocol", 0 }, { "enterprise", 0 },
    { "cloud", 0 }, { "tool", 0 }, { "education", 0 }, { "job", 0 },
    { "ai", 0 }, { "security", 0 }, { "life", 0 }, { "finance", 0 },
    { "shopping", 0 }, { "download", 0 },
    /* Retired: present in the old list, matched by no application. */
    { "entertainment", 1 }, { "productivity", 1 }, { "social", 1 }, { "work", 1 },
};

/* Writable category key? Retired keys are readable but not writable. */
static int nc_flow_priority_key_ok(const char *key)
{
    size_t i;

    if (!key || !key[0])
        return 0;
    for (i = 0; i < sizeof(g_nc_flow_categories) / sizeof(g_nc_flow_categories[0]); i++) {
        if (!strcmp(key, g_nc_flow_categories[i].key))
            return !g_nc_flow_categories[i].retired;
    }
    return 0;
}

static int nc_flow_priority_key_known(const char *key)
{
    size_t i;

    if (!key || !key[0])
        return 0;
    for (i = 0; i < sizeof(g_nc_flow_categories) / sizeof(g_nc_flow_categories[0]); i++) {
        if (!strcmp(key, g_nc_flow_categories[i].key))
            return 1;
    }
    return 0;
}

/* ── Smart flow control: category priority -> DSCP -> cake tin ───────────────
 *
 * The dataplane path is nftables marking DSCP plus cake reading it, chosen
 * because it works on the current kernel: cake and htb are loaded on 30.1 while
 * cls_flower and act_police are not present at all, and cake's diffserv modes
 * need neither. Verified on the device: `cake diffserv4` and `diffserv8` both
 * instantiate, and `ip dscp set` is accepted in a postrouting chain.
 *
 * What this cannot do yet, and why the reason codes matter: the kernel module
 * already resolves a per-flow category (JMX_APP_CAT_SLOTS = 18, visible in
 * /proc/dreamingwrt/jmx/wan<N>/proto_stats), but it exposes it only as
 * statistics -- ct->mark carries route priority and WAN id, not the category.
 * Marking DSCP from the resolved category needs a kernel change, and a vermagic
 * freeze is active, so jmx.ko can be compiled but not installed. Until then the
 * classifier input available to nft is the transport tuple, which covers the
 * categories that are identifiable by port and honestly does not cover the rest.
 */
#define NC_FLOW_QOS_TABLE "dreamingwrt_flow_qos"
#define NC_FLOW_QOS_MAX_RULES 256
#define NC_FLOW_QOS_MAX_WANS 16

struct nc_flow_qos_apply {
    char ifname[32];
    char scheduler[32];
    char diffserv[32];
    char running_qdisc[64];
    int download_mbps;
    int upload_mbps;
    int latency_target_ms;
    int per_host_fairness;
    int ack_filter;
    int category_count;
    int rule_count;
    int wan_count;
    int rolled_back;
    char wan_ids[NC_FLOW_QOS_MAX_WANS][64];
    char wan_ifnames[NC_FLOW_QOS_MAX_WANS][64];
    char wan_previous_qdisc[NC_FLOW_QOS_MAX_WANS][64];
    char reason[64];
    char message[256];
    char rules[NC_FLOW_QOS_MAX_RULES][192];
};

/*
 * Score (0-7) to DSCP class, collapsed onto cake's four diffserv4 tins.
 *
 * diffserv8 would map one score per tin, but four tins divide the link into
 * wider shares, so a low-priority tin stays usable on a modest line instead of
 * being starved. The scores order traffic; they are not a promise of independent
 * bandwidth per step.
 */
static const char *nc_flow_dscp_for_priority(int priority)
{
    if (priority <= 0)
        return "cs5";   /* Voice tin */
    if (priority <= 2)
        return "af41";  /* Video tin */
    if (priority <= 5)
        return "cs0";   /* Best Effort tin */
    return "cs1";       /* Bulk tin */
}

/*
 * Transport-level signature for the categories that can be recognised without
 * the kernel's per-flow category. Deliberately small and conservative: a wrong
 * guess here silently reprioritises unrelated traffic, which is harder to
 * notice than a category that simply is not covered yet.
 */
struct nc_flow_qos_signature {
    const char *key;
    const char *match;
};

static const struct nc_flow_qos_signature g_nc_flow_qos_signatures[] = {
    /* Interactive DNS and QUIC/HTTP control traffic. */
    { "web",      "udp dport 53" },
    { "web",      "tcp dport 53" },
    /* Real-time media and conferencing default ports. */
    { "chat",     "udp dport 3478-3481" },
    /* Mail submission and retrieval are bulk-ish background work. */
    { "tool",     "tcp dport { 25, 110, 143, 465, 587, 993, 995 }" },
    /* BitTorrent default range: the clearest bulk signal available. */
    { "download", "tcp dport 6881-6889" },
    { "download", "udp dport 6881-6889" },
    /* NTP: tiny, latency-sensitive, and unambiguous. */
    { "protocol", "udp dport 123" },
};

static void nc_flow_qos_read_running_qdisc(char *out, size_t out_len,
                                           const char *ifname)
{
    char cmd[192];
    char line[256];
    FILE *fp;

    snprintf(out, out_len, "unknown");
    if (!ifname || !ifname[0])
        return;
    snprintf(cmd, sizeof(cmd), "tc qdisc show dev %s 2>/dev/null", ifname);
    fp = popen(cmd, "r");
    if (!fp)
        return;
    if (fgets(line, sizeof(line), fp)) {
        char *p = strstr(line, "qdisc ");

        if (p) {
            char name[64] = "";

            if (sscanf(p + 6, "%63s", name) == 1)
                snprintf(out, out_len, "%s", name);
        }
    }
    pclose(fp);
}

/*
 * The device the lowest-metric default route points at, i.e. the one actually
 * carrying traffic right now.
 */
static int nc_flow_qos_default_route_device(char *out, size_t out_len)
{
    char line[256];
    FILE *fp;
    int found = 0;

    out[0] = '\0';
    fp = popen("ip -4 route show default 2>/dev/null", "r");
    if (!fp)
        return 0;
    while (!found && fgets(line, sizeof(line), fp)) {
        char device[64] = "";
        char *at = strstr(line, " dev ");

        if (!at)
            continue;
        if (sscanf(at + 5, "%63s", device) == 1 && if_nametoindex(device) > 0) {
            snprintf(out, out_len, "%s", device);
            found = 1;
        }
    }
    pclose(fp);
    return found;
}

/*
 * Egress interface for shaping: the enabled WAN that carries traffic, named as
 * the device tc can actually attach to.
 *
 * The wan table stores the logical UCI name ("wan3"), which on this platform is
 * not a device at all: every WAN is PPPoE, so the interface carrying the default
 * route is "pppoe-wan3" while "wan3" does not exist in the kernel. Shaping the
 * logical name fails outright, and shaping the underlying ethernet port would
 * queue below the PPPoE encapsulation, where the shaper no longer sits at the
 * bottleneck the DSCP marks are meant to order.
 *
 * nc_wan_runtime_l3_device() already asks netifd for the answer and rejects a
 * device the kernel does not have (if_nametoindex), so reuse it rather than
 * guessing a name from the configuration.
 *
 * Several WANs are usually up at once, and the first enabled row is not
 * necessarily the one forwarding: on 30.1 pppoe-wan is connected and has an
 * address while pppoe-wan3 holds the metric-10 default route. Shaping the wrong
 * live link is the worst outcome available, because everything reports success
 * and no user traffic is ordered, so prefer the default route's device and fall
 * back to row order only when it cannot be read.
 */
static int nc_flow_qos_egress_ifname(char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    int found = 0;

    out[0] = '\0';
    if (nc_flow_qos_default_route_device(out, out_len))
        return 0;
    if (nc_prepare(&st, "SELECT ifname FROM wan WHERE enabled=1 AND ifname<>'' ORDER BY id") == 0) {
        while (!found && sqlite3_step(st) == SQLITE_ROW) {
            const char *s = (const char *)sqlite3_column_text(st, 0);
            char device[64] = "";

            if (!s || !s[0])
                continue;
            if (nc_safe_id_ok(s) &&
                nc_wan_runtime_l3_device(s, device, sizeof(device)) == 0 &&
                device[0]) {
                snprintf(out, out_len, "%s", device);
                found = 1;
            } else if (if_nametoindex(s) > 0) {
                /* Already a real device (a non-PPPoE WAN such as dhcp on eth1). */
                snprintf(out, out_len, "%s", s);
                found = 1;
            }
        }
        sqlite3_finalize(st);
    }
    if (!found)
        out[0] = '\0';
    return found ? 0 : -1;
}

static int nc_flow_qos_wans_load(struct nc_flow_qos_apply *plan)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    plan->wan_count = 0;
    if (nc_prepare(&st, "SELECT id,ifname FROM wan WHERE enabled=1 ORDER BY id") != 0)
        return -1;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *section = (const char *)sqlite3_column_text(st, 1);
        char device[64] = "";

        if (!id || !id[0] || plan->wan_count >= NC_FLOW_QOS_MAX_WANS)
            continue;
        if (section && section[0] && nc_wan_runtime_l3_device(section, device, sizeof(device)) != 0)
            device[0] = '\0';
        if (!device[0] && section && if_nametoindex(section) > 0)
            snprintf(device, sizeof(device), "%s", section);
        if (!device[0]) {
            sqlite3_finalize(st);
            return -1;
        }
        snprintf(plan->wan_ids[plan->wan_count], sizeof(plan->wan_ids[0]), "%s", id);
        snprintf(plan->wan_ifnames[plan->wan_count], sizeof(plan->wan_ifnames[0]), "%s", device);
        nc_flow_qos_read_running_qdisc(plan->wan_previous_qdisc[plan->wan_count],
                                       sizeof(plan->wan_previous_qdisc[0]), device);
        plan->wan_count++;
        rc = 0;
    }
    sqlite3_finalize(st);
    return (plan->wan_count > 0 && rc == 0) ? 0 : -1;
}

static int nc_flow_qos_priority_for_wan(const char *wan_id, const char *app_key,
                                        int fallback)
{
    sqlite3_stmt *st = NULL;
    int value = fallback;

    if (!wan_id || !app_key ||
        nc_prepare(&st, "SELECT priority FROM flow_smart_line_priority WHERE wan_id=?1 AND app_key=?2") != 0)
        return fallback;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, app_key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        value = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return value;
}

/*
 * Build the plan. Returns 0 when it can be applied, -1 with reason/message set
 * when it cannot. Never mutates anything.
 */
static int nc_flow_qos_plan_load(struct nc_flow_qos_apply *plan)
{
    sqlite3_stmt *st = NULL;
    int enabled = 0;
    size_t i;

    memset(plan, 0, sizeof(*plan));
    snprintf(plan->scheduler, sizeof(plan->scheduler), "cake");
    snprintf(plan->diffserv, sizeof(plan->diffserv), "diffserv4");
    snprintf(plan->running_qdisc, sizeof(plan->running_qdisc), "unknown");

    if (nc_prepare(&st, "SELECT enabled,scheduler,total_download_mbps,total_upload_mbps,"
                        "latency_target_ms,per_host_fairness,ack_filter,diffserv "
                        "FROM flow_qos WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *s;

            enabled = sqlite3_column_int(st, 0);
            s = (const char *)sqlite3_column_text(st, 1);
            if (s && s[0]) snprintf(plan->scheduler, sizeof(plan->scheduler), "%s", s);
            plan->download_mbps = sqlite3_column_int(st, 2);
            plan->upload_mbps = sqlite3_column_int(st, 3);
            plan->latency_target_ms = sqlite3_column_int(st, 4);
            plan->per_host_fairness = sqlite3_column_int(st, 5);
            plan->ack_filter = sqlite3_column_int(st, 6);
            s = (const char *)sqlite3_column_text(st, 7);
            if (s && s[0]) snprintf(plan->diffserv, sizeof(plan->diffserv), "%s", s);
        }
        sqlite3_finalize(st);
        st = NULL;
    }

    if (nc_flow_qos_wans_load(plan) != 0) {
        snprintf(plan->reason, sizeof(plan->reason), "no_egress_interface");
        snprintf(plan->message, sizeof(plan->message),
                 "no enabled WAN resolves to a device present in the kernel; there is nothing to shape");
        return -1;
    }
    /*
     * plan->ifname is IFNAMSIZ-sized while wan_ifnames[] holds 64 bytes, so a
     * kernel device name always fits but a malformed longer one would not.
     */
    JMX_STRBUF_COPY(plan->ifname, plan->wan_ifnames[0]);
    JMX_STRBUF_COPY(plan->running_qdisc, plan->wan_previous_qdisc[0]);

    /* Build a separate DSCP rule set for every enabled WAN. Each override is
     * layered on the global priority baseline, so old global payloads remain
     * valid while a single WAN can be changed independently. */
    for (int wi = 0; wi < plan->wan_count; wi++) {
        if (nc_prepare(&st, "SELECT app_key,priority FROM flow_smart_priority") != 0)
            continue;
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *key = (const char *)sqlite3_column_text(st, 0);
            int priority;

            if (!key || !nc_flow_priority_key_ok(key))
                continue;
            priority = nc_flow_qos_priority_for_wan(plan->wan_ids[wi], key,
                                                    sqlite3_column_int(st, 1));
            plan->category_count++;
            for (i = 0; i < sizeof(g_nc_flow_qos_signatures) /
                            sizeof(g_nc_flow_qos_signatures[0]); i++) {
                if (strcmp(g_nc_flow_qos_signatures[i].key, key))
                    continue;
                if (plan->rule_count >= NC_FLOW_QOS_MAX_RULES)
                    break;
                snprintf(plan->rules[plan->rule_count],
                         sizeof(plan->rules[plan->rule_count]),
                         "add rule inet " NC_FLOW_QOS_TABLE " post oifname \"%s\" %s counter ip dscp set %s comment \"dwrt-qos-%s-%s\"",
                         plan->wan_ifnames[wi], g_nc_flow_qos_signatures[i].match,
                         nc_flow_dscp_for_priority(priority), key, plan->wan_ids[wi]);
                plan->rule_count++;
            }
        }
        sqlite3_finalize(st);
        st = NULL;
    }

    if (!enabled) {
        snprintf(plan->reason, sizeof(plan->reason), "qos_disabled");
        snprintf(plan->message, sizeof(plan->message),
                 "flow QoS is switched off; enable it before applying");
        return -1;
    }
    if (plan->download_mbps <= 0 || plan->upload_mbps <= 0) {
        /*
         * cake without a rate cannot control the queue: the bottleneck stays at
         * the modem where we have no visibility, so prioritisation would appear
         * configured and do nothing.
         */
        snprintf(plan->reason, sizeof(plan->reason), "bandwidth_not_calibrated");
        snprintf(plan->message, sizeof(plan->message),
                 "set total_download_mbps and total_upload_mbps first; cake cannot shape without a rate");
        return -1;
    }
    if (strcmp(plan->scheduler, "cake")) {
        snprintf(plan->reason, sizeof(plan->reason), "scheduler_not_supported");
        snprintf(plan->message, sizeof(plan->message),
                 "only the cake scheduler is wired to the DSCP path; '%s' is configured",
                 plan->scheduler);
        return -1;
    }
    if (!plan->rule_count) {
        snprintf(plan->reason, sizeof(plan->reason), "classifier_not_wired");
        snprintf(plan->message, sizeof(plan->message),
                 "no category can be matched from the transport tuple; per-flow category marking needs a kernel module update");
        return -1;
    }
    snprintf(plan->reason, sizeof(plan->reason), "ready");
    snprintf(plan->message, sizeof(plan->message),
             "%d DSCP rules over %d WAN-category pairs, cake %s on %d WANs",
             plan->rule_count, plan->category_count, plan->diffserv, plan->wan_count);
    return 0;
}

static struct json_object *nc_flow_qos_plan_json(const struct nc_flow_qos_apply *plan)
{
    struct json_object *o = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    int i;

    for (i = 0; i < plan->rule_count; i++)
        json_object_array_add(arr, json_object_new_string(plan->rules[i]));
    json_object_object_add(o, "nft_rules", arr);
    json_object_object_add(o, "nft_table", json_object_new_string(NC_FLOW_QOS_TABLE));
    json_object_object_add(o, "dscp_to_tin",
                           json_object_new_string("cs5=Voice af41=Video cs0=Best Effort cs1=Bulk"));
    json_object_object_add(o, "kernel_category_marking_available",
                           json_object_new_boolean(1));
    json_object_object_add(o, "kernel_category_marking_blocked_by",
                           json_object_new_string("kernel_category_marking_runtime_probe_required"));
    return o;
}

static int nc_flow_qos_restore_qdisc(struct nc_flow_qos_apply *plan,
                                     const char *previous)
{
    char cmd[192];
    char restored[64] = "unknown";

    if (!previous || !previous[0] || !strcmp(previous, "unknown"))
        return -1;
    snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s root %s 2>/dev/null",
             plan->ifname, previous);
    if (nc_run_quiet(cmd) != 0)
        return -1;
    nc_flow_qos_read_running_qdisc(restored, sizeof(restored), plan->ifname);
    if (strcmp(restored, previous))
        return -1;
    snprintf(plan->running_qdisc, sizeof(plan->running_qdisc), "%s", restored);
    return 0;
}

static int nc_flow_qos_restore_all_qdiscs(struct nc_flow_qos_apply *plan, int count)
{
    int i;
    int ok = 1;

    for (i = count - 1; i >= 0; i--) {
        char cmd[192];
        char restored[64] = "unknown";

        if (!plan->wan_ifnames[i][0] || !plan->wan_previous_qdisc[i][0]) {
            ok = 0;
            continue;
        }
        snprintf(cmd, sizeof(cmd), "tc qdisc replace dev %s root %s 2>/dev/null",
                 plan->wan_ifnames[i], plan->wan_previous_qdisc[i]);
        if (nc_run_quiet(cmd) != 0) {
            ok = 0;
            continue;
        }
        nc_flow_qos_read_running_qdisc(restored, sizeof(restored), plan->wan_ifnames[i]);
        if (strcmp(restored, plan->wan_previous_qdisc[i]))
            ok = 0;
    }
    return ok ? 0 : -1;
}

static struct json_object *nc_flow_qos_runtime_json(void)
{
    struct json_object *runtime = json_object_new_object();
    sqlite3_stmt *st = NULL;
    int rule_count = 0;

    if (nc_prepare(&st, "SELECT COUNT(*) FROM flow_smart_priority") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW)
            rule_count = sqlite3_column_int(st, 0) *
                         (int)(sizeof(g_nc_flow_qos_signatures) /
                               sizeof(g_nc_flow_qos_signatures[0]));
        sqlite3_finalize(st);
        st = NULL;
    }

    if (nc_prepare(&st, "SELECT id FROM wan WHERE enabled=1 ORDER BY id") != 0)
        return runtime;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *wan = (const char *)sqlite3_column_text(st, 0);
        char ifname[64] = "";
        char qdisc[64] = "unknown";
        struct json_object *row;
        int resolved;

        if (!wan || !wan[0])
            continue;
        resolved = nc_wan_runtime_l3_device(wan, ifname, sizeof(ifname)) == 0;
        if (resolved)
            nc_flow_qos_read_running_qdisc(qdisc, sizeof(qdisc), ifname);
        row = json_object_new_object();
        json_object_object_add(row, "configured", json_object_new_boolean(1));
        json_object_object_add(row, "effective", json_object_new_boolean(resolved && !strcmp(qdisc, "cake")));
        json_object_object_add(row, "runtime_applied", json_object_new_boolean(resolved && !strcmp(qdisc, "cake")));
        json_object_object_add(row, "runtime_reason", json_object_new_string(
            !resolved ? "egress_interface_unresolved" :
            !strcmp(qdisc, "cake") ? "cake_readback_matches" : "cake_readback_mismatch"));
        json_object_object_add(row, "ifname", json_object_new_string(ifname));
        json_object_object_add(row, "qdisc", json_object_new_string(qdisc));
        json_object_object_add(row, "rule_count", json_object_new_int(rule_count));
        json_object_object_add(runtime, wan, row);
    }
    sqlite3_finalize(st);
    return runtime;
}

/*
 * Apply, with rollback.
 *
 * Order matters: install the DSCP marking first, then replace the qdisc. If the
 * qdisc swap fails the marking is removed again, so a failed apply leaves the
 * device exactly as it was rather than marking packets nothing acts on.
 *
 * The previous qdisc is captured before the swap and restored on failure. The
 * swap itself is `tc qdisc replace`, which is atomic per interface; it briefly
 * empties the queue but does not tear the link down.
 */
static int nc_flow_qos_apply_runtime(struct nc_flow_qos_apply *plan)
{
    /*
     * Legacy executor disabled after QoS merge.
     *
     * Flowd is now the sole executor. This function is a no-op to prevent
     * the two executors from fighting over the same root qdisc.
     * Actual apply happens through nc_flowd_compile_apply() which calls
     * dreamingwrt.flowd compile via ubus.
     */
    if (plan) {
        snprintf(plan->reason, sizeof(plan->reason), "legacy_executor_disabled");
        snprintf(plan->message, sizeof(plan->message),
                 "legacy executor disabled; use flowd compile for QoS apply");
    }
    return 0;
}

static int nc_flow_type_ok(const char *s){return s&&(!strcmp(s,"app")||!strcmp(s,"domain")||!strcmp(s,"subnet")||!strcmp(s,"client")||!strcmp(s,"protocol")||!strcmp(s,"port")||!strcmp(s,"category"));}
static int nc_flow_action_ok(const char *s){return s&&(!strcmp(s,"route_group")||!strcmp(s,"direct")||!strcmp(s,"vpn")||!strcmp(s,"reject")||!strcmp(s,"split_up_down"));}
static int nc_flow_group_mode_ok(const char *s){return s&&(!strcmp(s,"fixed")||!strcmp(s,"weighted")||!strcmp(s,"primary_backup"));}
static int nc_flow_hash_ok(const char *h){char tmp[128],*save=NULL,*t;if(!h||!h[0])return 1;snprintf(tmp,sizeof(tmp),"%s",h);for(t=strtok_r(tmp,", ",&save);t;t=strtok_r(NULL,", ",&save))if(strcmp(t,"src_ip")&&strcmp(t,"dst_ip")&&strcmp(t,"dst_port")&&strcmp(t,"src_port"))return 0;return 1;}

static int nc_flow_target_exists(const char *action, const char *target)
{
    sqlite3_stmt *st = NULL; int ok = 0;
    if (!action) return 0;
    if (!strcmp(action,"direct") || !strcmp(action,"reject")) return 1;
    if (!target || !target[0]) return 0;
    if (!strcmp(action,"split_up_down")) return strstr(target,"up:") && strstr(target,"down:");
    if (nc_prepare(&st,"SELECT 1 FROM flow_groups WHERE id=?1 UNION SELECT 1 FROM wan WHERE id=?1 OR ifname=?1 UNION SELECT 1 FROM vpn_client WHERE id=?1 OR iface=?1 LIMIT 1") == 0) { sqlite3_bind_text(st,1,target,-1,SQLITE_TRANSIENT); ok = sqlite3_step(st) == SQLITE_ROW; sqlite3_finalize(st); }
    if (!ok && (!strncmp(target,"wan",3) || !strncmp(target,"vpn",3) || !strncmp(target,"wg",2) || !strncmp(target,"tun",3))) ok = 1;
    return ok;
}

static int nc_flow_validate(struct json_object *cfg)
{
    struct json_object *arr=NULL,*o=NULL; int i,n,j;
    if(json_object_object_get_ex(cfg,"groups",&arr)&&arr&&json_object_is_type(arr,json_type_array))for(i=0,n=json_object_array_length(arr);i<n;i++){o=json_object_array_get_idx(arr,i);if(!nc_safe_id_ok(nc_json_str_def(o,"id",""))||!nc_flow_group_mode_ok(nc_json_str_def(o,"mode","weighted"))||!nc_flow_hash_ok(nc_json_str_def(o,"hash","")))return -1;}
    if(json_object_object_get_ex(cfg,"rules",&arr)&&arr&&json_object_is_type(arr,json_type_array)){for(i=0,n=json_object_array_length(arr);i<n;i++){int pri; const char *act,*target; o=json_object_array_get_idx(arr,i); act=nc_json_str_def(o,"action",""); target=nc_json_str_def(o,"target",""); if(!nc_safe_id_ok(nc_json_str_def(o,"id",""))||!nc_flow_type_ok(nc_json_str_def(o,"type",""))||!nc_flow_action_ok(act)||!nc_flow_target_exists(act,target))return -1; pri=nc_json_int_def(o,"priority",0); for(j=i+1;j<n;j++) if(pri==nc_json_int_def(json_object_array_get_idx(arr,j),"priority",0)) return -1;}}
    if(json_object_object_get_ex(cfg,"client_limits",&arr)&&arr&&json_object_is_type(arr,json_type_array))for(i=0,n=json_object_array_length(arr);i<n;i++){o=json_object_array_get_idx(arr,i);if(!nc_safe_id_ok(nc_json_str_def(o,"id",""))||nc_json_int_def(o,"upload_kbps",0)<0||nc_json_int_def(o,"download_kbps",0)<0)return -1;}
    return 0;
}

struct json_object *jmx_flow_control_get(void)
{
    struct json_object *data=json_object_new_object(),*g=json_object_new_object(),*q=json_object_new_object(),*classes=json_object_new_array(),*groups=json_object_new_array(),*rules=json_object_new_array(),*limits=json_object_new_array(),*status=json_object_new_object(); sqlite3_stmt *st=NULL,*m=NULL;
    if(jmx_netconfig_db_init()!=0)goto done; nc_flow_db_init();
    if(nc_prepare(&st,"SELECT enabled,mode,default_policy,unknown_policy,dpi_required,log_decisions,sticky_session,apply_state,last_apply_at FROM flow_global WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){json_object_object_add(g,"enabled",json_object_new_boolean(sqlite3_column_int(st,0)));json_object_object_add(g,"engine",json_object_new_string("nft marks + ip rule + tc cake"));nc_add_text(g,"mode",st,1);nc_add_text(g,"default_policy",st,2);nc_add_text(g,"unknown_policy",st,3);json_object_object_add(g,"dpi_required",json_object_new_boolean(sqlite3_column_int(st,4)));json_object_object_add(g,"log_decisions",json_object_new_boolean(sqlite3_column_int(st,5)));json_object_object_add(g,"sticky_session",json_object_new_boolean(sqlite3_column_int(st,6)));nc_add_text(g,"apply_state",st,7);json_object_object_add(g,"last_apply_at",json_object_new_int64(sqlite3_column_int64(st,8)));sqlite3_finalize(st);st=NULL;}
    /* QoS settings: prefer flowd as source of truth, fall back to legacy */
    { int flowd_qos_ok = 0;
      if(nc_prepare(&st,"SELECT enabled,scheduler,ack_filter,fairness,diffserv FROM flowd_qos_settings WHERE id=1")==0 && sqlite3_step(st)==SQLITE_ROW){
        const char *fairness_str = (const char*)sqlite3_column_text(st,3);
        int diffserv_val = sqlite3_column_int(st,4);
        flowd_qos_ok = 1;
        json_object_object_add(q,"enabled",json_object_new_boolean(sqlite3_column_int(st,0)));
        nc_add_text(q,"scheduler",st,1);
        json_object_object_add(q,"ack_filter",json_object_new_boolean(sqlite3_column_int(st,2)));
        json_object_object_add(q,"per_host_fairness",json_object_new_boolean(fairness_str && strcmp(fairness_str,"per_host")==0));
        json_object_object_add(q,"diffserv",json_object_new_string(diffserv_val==0?"none":"diffserv4"));
        sqlite3_finalize(st); st=NULL;
        if(nc_prepare(&st,"SELECT COALESCE(SUM(down_kbps),0),COALESCE(SUM(up_kbps),0) FROM flowd_wan_capacity WHERE enabled=1")==0 && sqlite3_step(st)==SQLITE_ROW){
          json_object_object_add(q,"total_download_mbps",json_object_new_int(sqlite3_column_int(st,0)/1000));
          json_object_object_add(q,"total_upload_mbps",json_object_new_int(sqlite3_column_int(st,1)/1000));
          sqlite3_finalize(st); st=NULL;
        }
        json_object_object_add(q,"latency_target_ms",json_object_new_int(25));
      }
      if(!flowd_qos_ok && nc_prepare(&st,"SELECT enabled,scheduler,total_download_mbps,total_upload_mbps,latency_target_ms,per_host_fairness,ack_filter,diffserv FROM flow_qos WHERE id=1")==0&&sqlite3_step(st)==SQLITE_ROW){json_object_object_add(q,"enabled",json_object_new_boolean(sqlite3_column_int(st,0)));nc_add_text(q,"scheduler",st,1);json_object_object_add(q,"total_download_mbps",json_object_new_int(sqlite3_column_int(st,2)));json_object_object_add(q,"total_upload_mbps",json_object_new_int(sqlite3_column_int(st,3)));json_object_object_add(q,"latency_target_ms",json_object_new_int(sqlite3_column_int(st,4)));json_object_object_add(q,"per_host_fairness",json_object_new_boolean(sqlite3_column_int(st,5)));json_object_object_add(q,"ack_filter",json_object_new_boolean(sqlite3_column_int(st,6)));nc_add_text(q,"diffserv",st,7);sqlite3_finalize(st);st=NULL;}
    }
    /* Classes: prefer flowd as source of truth, fall back to legacy */
    { int cls_ok = 0;
      if(nc_prepare(&st,"SELECT id,name,priority,guarantee_pct,ceiling_pct,latency_ms,color,remark FROM flowd_qos_classes WHERE enabled=1 ORDER BY priority,id")==0 && sqlite3_step(st)==SQLITE_ROW){
        cls_ok = 1;
        sqlite3_finalize(st); st=NULL;
        if(nc_prepare(&st,"SELECT id,name,priority,guarantee_pct,ceiling_pct,latency_ms,color,remark FROM flowd_qos_classes WHERE enabled=1 ORDER BY priority,id")==0){
          while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();
            nc_add_text(o,"id",st,0);nc_add_text(o,"name",st,1);
            json_object_object_add(o,"priority",json_object_new_int(sqlite3_column_int(st,2)/100));
            json_object_object_add(o,"guarantee",json_object_new_int(sqlite3_column_int(st,3)));
            json_object_object_add(o,"ceiling",json_object_new_int(sqlite3_column_int(st,4)));
            json_object_object_add(o,"latency_target",json_object_new_int(sqlite3_column_int(st,5)));
            nc_add_text(o,"examples",st,7);
            nc_add_text(o,"color",st,6);
            json_object_array_add(classes,o);}sqlite3_finalize(st);st=NULL;
        }
      }
      if(!cls_ok && nc_prepare(&st,"SELECT id,name,priority,guarantee,ceiling,latency_target,examples,color FROM flow_classes ORDER BY priority,id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);nc_add_text(o,"name",st,1);json_object_object_add(o,"priority",json_object_new_int(sqlite3_column_int(st,2)));json_object_object_add(o,"guarantee",json_object_new_int(sqlite3_column_int(st,3)));json_object_object_add(o,"ceiling",json_object_new_int(sqlite3_column_int(st,4)));json_object_object_add(o,"latency_target",json_object_new_int(sqlite3_column_int(st,5)));nc_add_text(o,"examples",st,6);nc_add_text(o,"color",st,7);json_object_array_add(classes,o);}sqlite3_finalize(st);}
    }
    if(nc_prepare(&st,"SELECT id,name,carrier,mode,hash,health_check,failback FROM flow_groups WHERE enabled=1 ORDER BY id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object(),*members=json_object_new_array();const char*gid=(const char*)sqlite3_column_text(st,0);const char*gc=(const char*)sqlite3_column_text(st,2);nc_add_text(o,"id",st,0);nc_add_text(o,"name",st,1);nc_add_text(o,"carrier",st,2);nc_add_text(o,"mode",st,3);nc_add_text(o,"hash",st,4);json_object_object_add(o,"health_check",json_object_new_boolean(sqlite3_column_int(st,5)));json_object_object_add(o,"failback",json_object_new_boolean(sqlite3_column_int(st,6)));json_object_object_add(o,"carrier_key",json_object_new_string(gc&&gc[0]?(strcmp(gc,"中国联通")==0||strcmp(gc,"中国联通专线")==0?"unicom":strcmp(gc,"中国电信")==0||strcmp(gc,"中国电信专线")==0?"ctcc":strcmp(gc,"中国移动")==0||strcmp(gc,"中国移动专线")==0?"cmcc":strcmp(gc,"中国教育网")==0?"cernet":"custom"):""));json_object_object_add(o,"carrier_custom",json_object_new_boolean(gc&&gc[0]&&strcmp(gc,"中国联通")!=0&&strcmp(gc,"中国电信")!=0&&strcmp(gc,"中国移动")!=0&&strcmp(gc,"中国教育网")!=0&&strcmp(gc,"中国联通专线")!=0&&strcmp(gc,"中国电信专线")!=0&&strcmp(gc,"中国移动专线")!=0));if(nc_prepare(&m,"SELECT target,weight,role FROM flow_group_members WHERE group_id=?1 ORDER BY sort_order,id")==0){sqlite3_bind_text(m,1,gid,-1,SQLITE_TRANSIENT);while(sqlite3_step(m)==SQLITE_ROW){struct json_object*x=json_object_new_object();nc_add_text(x,"target",m,0);json_object_object_add(x,"weight",json_object_new_int(sqlite3_column_int(m,1)));nc_add_text(x,"role",m,2);json_object_array_add(members,x);}sqlite3_finalize(m);m=NULL;}json_object_object_add(o,"members",members);json_object_array_add(groups,o);}sqlite3_finalize(st);}
    if(nc_prepare(&st,"SELECT r.id,r.enabled,r.priority,r.name,r.type,r.source,r.destination,r.apps,r.protocol,r.action,r.target,r.qos_class,r.schedule,r.fallback,r.sticky,COALESCE((SELECT COUNT(*) FROM flow_runtime_hits h WHERE h.rule_id=r.id),0),r.remark FROM flow_rules r ORDER BY r.priority,r.id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));json_object_object_add(o,"priority",json_object_new_int(sqlite3_column_int(st,2)));nc_add_text(o,"name",st,3);nc_add_text(o,"type",st,4);nc_add_text(o,"source",st,5);nc_add_text(o,"destination",st,6);nc_add_text(o,"apps",st,7);nc_add_text(o,"protocol",st,8);nc_add_text(o,"action",st,9);nc_add_text(o,"target",st,10);nc_add_text(o,"qos_class",st,11);nc_add_text(o,"schedule",st,12);nc_add_text(o,"fallback",st,13);json_object_object_add(o,"sticky",json_object_new_boolean(sqlite3_column_int(st,14)));json_object_object_add(o,"hits",json_object_new_int64(sqlite3_column_int64(st,15)));nc_add_text(o,"remark",st,16);json_object_array_add(rules,o);}sqlite3_finalize(st);}
    if(nc_prepare(&st,"SELECT id,enabled,client,ip,device_group,upload_kbps,download_kbps,mode,remark FROM flow_client_limits ORDER BY id")==0){while(sqlite3_step(st)==SQLITE_ROW){struct json_object*o=json_object_new_object();nc_add_text(o,"id",st,0);json_object_object_add(o,"enabled",json_object_new_boolean(sqlite3_column_int(st,1)));nc_add_text(o,"client",st,2);nc_add_text(o,"ip",st,3);nc_add_text(o,"group",st,4);json_object_object_add(o,"upload_kbps",json_object_new_int(sqlite3_column_int(st,5)));json_object_object_add(o,"download_kbps",json_object_new_int(sqlite3_column_int(st,6)));nc_add_text(o,"mode",st,7);nc_add_text(o,"remark",st,8);json_object_array_add(limits,o);}sqlite3_finalize(st);}
done:
    json_object_object_add(g,"configured_enabled",json_object_new_boolean(nc_json_bool_def(g,"enabled",0)));
    json_object_object_add(g,"runtime_applied",json_object_new_boolean(0));
    json_object_object_add(g,"runtime_reason",json_object_new_string("dataplane_apply_executor_missing"));
    json_object_object_add(q,"configured_enabled",json_object_new_boolean(nc_json_bool_def(q,"enabled",0)));
    /*
     * The QoS block reports what is on the interface, not a fixed answer.
     *
     * These two used to be a hardcoded false / dataplane_apply_executor_missing,
     * which was accurate only while apply refused to run. Now that cake really is
     * installed, leaving them fixed told the UI "no executor" while the device was
     * shaping traffic -- the same "looks unimplemented, behaves implemented"
     * inversion in reverse, and just as misleading.
     */
    {
        struct nc_flow_qos_apply qplan;
        int qrc = nc_flow_qos_plan_load(&qplan);
        int live = qrc == 0 && !strcmp(qplan.running_qdisc, "cake");

        json_object_object_add(q,"runtime_applied",json_object_new_boolean(live));
        json_object_object_add(q,"runtime_reason",
            json_object_new_string(live ? "applied" : qplan.reason));
        json_object_object_add(q,"runtime_qdisc",
            json_object_new_string(qplan.running_qdisc));
        json_object_object_add(q,"runtime_ifname",
            json_object_new_string(qplan.ifname));
    }
    /*
     * Flow status counters.
     *
     * shaped_flows, steered_flows, fallback_flows, queue_delay_ms and
     * dropped_packets used to be literal 0 here. The UI divides
     * steered_flows / active_flows, so it rendered a confident "policy steering
     * 0.0%" while the rules were demonstrably matching. A hardcoded 0 is worse
     * than no answer, because it is indistinguishable from a real measurement of
     * zero.
     *
     * These are reported as null with an explicit *_supported flag and reason
     * instead, so a client can tell "not measured" from "measured as zero".
     * The global block above uses the same convention; the QoS block does not,
     * because QoS apply now really runs and reports the live qdisc.
     *
     * Why not compute them here: the real per-class steering counts live in
     * routed's conntrack fwmark reader (routed/jmx_route.c, route_count_conntrack_marks()),
     * which is static and needs that module's rule payload as input. Exporting it
     * would mean editing routed/, which is outside this change; the route_status
     * path already publishes the real numbers. Duplicating the mark parsing here
     * would create a second implementation free to drift from the first.
     */
    json_object_object_add(status, "active_flows",
        json_object_new_int(nc_vpn_count_table("flow_runtime_hits",
                                               "WHERE ts > strftime('%s','now')-300")));
    json_object_object_add(status, "active_flows_semantics",
        json_object_new_string("flow_runtime_hit_rows_last_300s"));

    /* Shaping/queueing: no data source at all while the dataplane apply executor
     * is missing, which is the same reason the QoS block reports above. */
    json_object_object_add(status, "shaped_flows", NULL);
    json_object_object_add(status, "queue_delay_ms", NULL);
    json_object_object_add(status, "dropped_packets", NULL);
    json_object_object_add(status, "shaped_flows_supported",
                           json_object_new_boolean(0));
    json_object_object_add(status, "shaped_flows_reason",
        json_object_new_string("dataplane_apply_executor_missing"));

    /* Steering: measured, but by routed rather than here. */
    json_object_object_add(status, "steered_flows", NULL);
    json_object_object_add(status, "fallback_flows", NULL);
    json_object_object_add(status, "steered_flows_supported",
                           json_object_new_boolean(0));
    json_object_object_add(status, "steered_flows_reason",
        json_object_new_string("counted_by_routed_use_route_status"));
    json_object_object_add(status, "steered_flows_source",
        json_object_new_string("dreamingwrt.routed route_status policy.steered_flows"));

    /* Smart mode */
    { struct json_object *smart = json_object_new_object();
      if(nc_prepare(&st,"SELECT mode FROM flow_smart WHERE id=1")==0 && sqlite3_step(st)==SQLITE_ROW){ nc_add_text(smart,"mode",st,0); sqlite3_finalize(st); st=NULL; }
      /* Per-line modes */
      { struct json_object *lm = json_object_new_object();
        if(nc_prepare(&st,"SELECT wan_id,mode FROM flow_smart_line_mode")==0){ while(sqlite3_step(st)==SQLITE_ROW){ const char *k=(const char*)sqlite3_column_text(st,0); json_object_object_add(lm,k,json_object_new_string((const char*)sqlite3_column_text(st,1))); } sqlite3_finalize(st); st=NULL; }
        json_object_object_add(smart,"line_modes",lm); }
      /* Priorities */
      { struct json_object *pri = json_object_new_object();
        /* Smart priorities: prefer flowd categories, fall back to legacy */
        { int sp_ok = 0;
          if(nc_prepare(&st,"SELECT category,priority FROM flowd_smart_qos_categories WHERE enabled=1 ORDER BY category")==0 && sqlite3_step(st)==SQLITE_ROW){
            sp_ok = 1;
            sqlite3_finalize(st); st=NULL;
            if(nc_prepare(&st,"SELECT category,priority FROM flowd_smart_qos_categories WHERE enabled=1 ORDER BY category")==0){
              while(sqlite3_step(st)==SQLITE_ROW){ const char *k=(const char*)sqlite3_column_text(st,0); int fpri=sqlite3_column_int(st,1); json_object_object_add(pri,k,json_object_new_int(fpri>=100?(fpri-100)/100:fpri)); } sqlite3_finalize(st); st=NULL;
            }
          }
          if(!sp_ok && nc_prepare(&st,"SELECT app_key,priority FROM flow_smart_priority")==0){ while(sqlite3_step(st)==SQLITE_ROW){ const char *k=(const char*)sqlite3_column_text(st,0); json_object_object_add(pri,k,json_object_new_int(sqlite3_column_int(st,1))); } sqlite3_finalize(st); st=NULL; }
        }
        json_object_object_add(smart,"priorities",pri); }
      { struct json_object *lp = json_object_new_object();
        if(nc_prepare(&st,"SELECT wan_id,app_key,priority FROM flow_smart_line_priority ORDER BY wan_id,app_key")==0){
            while(sqlite3_step(st)==SQLITE_ROW){
                const char *wan=(const char*)sqlite3_column_text(st,0);
                const char *key=(const char*)sqlite3_column_text(st,1);
                struct json_object *row = NULL;
                if (!wan || !key) continue;
                if (!json_object_object_get_ex(lp, wan, &row) || !row) {
                    row = json_object_new_object();
                    json_object_object_add(lp, wan, row);
                }
                json_object_object_add(row, key, json_object_new_int(sqlite3_column_int(st,2)));
            }
            sqlite3_finalize(st); st=NULL;
        }
        json_object_object_add(smart,"line_priorities",lp);
        json_object_object_add(smart,"priority_scope",json_object_new_string("per_wan"));
        json_object_object_add(smart,"priority_runtime",nc_flow_qos_runtime_json());
      }
      json_object_object_add(data,"smart",smart); }

    /* WAN info for line mode assignment */
    { struct json_object *wans = json_object_new_array();
      if(nc_prepare(&st,"SELECT id,name,ifname,carrier,enabled FROM wan ORDER BY id")==0){ while(sqlite3_step(st)==SQLITE_ROW){ struct json_object *w = json_object_new_object(); nc_add_text(w,"id",st,0); nc_add_text(w,"name",st,1); nc_add_text(w,"ifname",st,2); nc_add_text(w,"carrier",st,3); json_object_object_add(w,"enabled",json_object_new_boolean(sqlite3_column_int(st,4))); json_object_object_add(w,"status",json_object_new_string(sqlite3_column_int(st,4)?"ok":"disabled")); json_object_array_add(wans,w); } sqlite3_finalize(st); st=NULL; }
      json_object_object_add(data,"wans",wans); }

    json_object_object_add(data,"ts",json_object_new_int64(nc_now_s()));json_object_object_add(data,"source_of_truth",json_object_new_string("flowd"));json_object_object_add(data,"authoritative_runtime_source",json_object_new_string("dreamingwrt.flowd"));/*
     * Live runtime state instead of a fixed "executor missing": the executor
     * exists now, so the honest answer is whether cake is actually on the egress
     * interface, and if not, which precondition is missing.
     */
    { struct nc_flow_qos_apply st_plan;
      int st_rc = nc_flow_qos_plan_load(&st_plan);
      int st_live = (st_rc == 0) && !strcmp(st_plan.running_qdisc, "cake");
      json_object_object_add(data,"runtime_applied",json_object_new_boolean(st_live));
      json_object_object_add(data,"runtime_reason",json_object_new_string(st_live ? "applied" : st_plan.reason));
      json_object_object_add(data,"runtime_qdisc",json_object_new_string(st_plan.running_qdisc));
      json_object_object_add(data,"categories_writable",json_object_new_int(st_plan.category_count)); }
    json_object_object_add(data,"legacy_config_model",json_object_new_boolean(1));json_object_object_add(data,"global",g);json_object_object_add(data,"qos",q);json_object_object_add(data,"classes",classes);json_object_object_add(data,"groups",groups);json_object_object_add(data,"rules",rules);json_object_object_add(data,"client_limits",limits);json_object_object_add(data,"status",status);return jmx_gen_api_response_data(API_CODE_SUCCESS,data);
}

int jmx_flow_control_set(struct json_object *cfg)
{
    struct json_object *o=NULL,*arr=NULL,*members=NULL; sqlite3_stmt*st=NULL; int rc=0,i,n,j,m;
    if(!cfg||jmx_netconfig_db_init()!=0)return -1; nc_flow_db_init(); if(nc_flow_validate(cfg)!=0)return -1; if(nc_txn_begin()!=0)return -1;
    if(json_object_object_get_ex(cfg,"global",&o)&&o&&nc_prepare(&st,"INSERT INTO flow_global(id,enabled,mode,default_policy,unknown_policy,dpi_required,log_decisions,sticky_session,apply_state,updated_at) VALUES(1,?1,?2,?3,?4,?5,?6,?7,'draft',?8) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,mode=excluded.mode,default_policy=excluded.default_policy,unknown_policy=excluded.unknown_policy,dpi_required=excluded.dpi_required,log_decisions=excluded.log_decisions,sticky_session=excluded.sticky_session,apply_state='draft',updated_at=excluded.updated_at")==0){sqlite3_bind_int(st,1,nc_json_bool_def(o,"enabled",1));sqlite3_bind_text(st,2,nc_json_str_def(o,"mode","smart"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"default_policy","auto"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"unknown_policy","normal"),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,5,nc_json_bool_def(o,"dpi_required",1));sqlite3_bind_int(st,6,nc_json_bool_def(o,"log_decisions",1));sqlite3_bind_int(st,7,nc_json_bool_def(o,"sticky_session",1));sqlite3_bind_int64(st,8,nc_now_s());if(nc_step_done(st)!=0)rc=-1;sqlite3_finalize(st);} 
    if(rc==0&&json_object_object_get_ex(cfg,"qos",&o)&&o&&nc_prepare(&st,"INSERT INTO flow_qos(id,enabled,scheduler,total_download_mbps,total_upload_mbps,latency_target_ms,per_host_fairness,ack_filter,diffserv) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled,scheduler=excluded.scheduler,total_download_mbps=excluded.total_download_mbps,total_upload_mbps=excluded.total_upload_mbps,latency_target_ms=excluded.latency_target_ms,per_host_fairness=excluded.per_host_fairness,ack_filter=excluded.ack_filter,diffserv=excluded.diffserv")==0){sqlite3_bind_int(st,1,nc_json_bool_def(o,"enabled",1));sqlite3_bind_text(st,2,nc_json_str_def(o,"scheduler","cake"),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,nc_json_int_def(o,"total_download_mbps",1000));sqlite3_bind_int(st,4,nc_json_int_def(o,"total_upload_mbps",100));sqlite3_bind_int(st,5,nc_json_int_def(o,"latency_target_ms",25));sqlite3_bind_int(st,6,nc_json_bool_def(o,"per_host_fairness",1));sqlite3_bind_int(st,7,nc_json_bool_def(o,"ack_filter",1));sqlite3_bind_text(st,8,nc_json_str_def(o,"diffserv","diffserv4"),-1,SQLITE_TRANSIENT);if(nc_step_done(st)!=0)rc=-1;sqlite3_finalize(st);} 
    if(rc==0&&json_object_object_get_ex(cfg,"classes",&arr)&&arr){nc_exec("DELETE FROM flow_classes");for(i=0,n=json_object_array_length(arr);i<n;i++){o=json_object_array_get_idx(arr,i);if(nc_prepare(&st,"INSERT INTO flow_classes(id,name,priority,guarantee,ceiling,latency_target,examples,color) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)")==0){sqlite3_bind_text(st,1,nc_json_str_def(o,"id",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,nc_json_str_def(o,"name",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,nc_json_int_def(o,"priority",100));sqlite3_bind_int(st,4,nc_json_int_def(o,"guarantee",0));sqlite3_bind_int(st,5,nc_json_int_def(o,"ceiling",100));sqlite3_bind_int(st,6,nc_json_int_def(o,"latency_target",100));sqlite3_bind_text(st,7,nc_json_str_def(o,"examples",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,8,nc_json_str_def(o,"color",""),-1,SQLITE_TRANSIENT);if(nc_step_done(st)!=0)rc=-1;sqlite3_finalize(st);}}}
    if(rc==0&&json_object_object_get_ex(cfg,"groups",&arr)&&arr){nc_exec("DELETE FROM flow_group_members");nc_exec("DELETE FROM flow_groups");for(i=0,n=json_object_array_length(arr);i<n;i++){o=json_object_array_get_idx(arr,i);if(nc_prepare(&st,"INSERT INTO flow_groups(id,name,carrier,mode,hash,health_check,failback,remark,enabled) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)")==0){sqlite3_bind_text(st,1,nc_json_str_def(o,"id",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,nc_json_str_def(o,"name",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,nc_json_str_def(o,"carrier",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"mode","weighted"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"hash","src_ip,dst_ip,dst_port"),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,6,nc_json_bool_def(o,"health_check",1));sqlite3_bind_int(st,7,nc_json_bool_def(o,"failback",1));sqlite3_bind_text(st,8,nc_json_str_def(o,"remark",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,9,nc_json_bool_def(o,"enabled",1));if(nc_step_done(st)!=0)rc=-1;sqlite3_finalize(st);}if(json_object_object_get_ex(o,"members",&members)&&members){for(j=0,m=json_object_array_length(members);j<m;j++){struct json_object*x=json_object_array_get_idx(members,j);if(nc_prepare(&st,"INSERT INTO flow_group_members(group_id,target,weight,role,sort_order) VALUES(?1,?2,?3,?4,?5)")==0){sqlite3_bind_text(st,1,nc_json_str_def(o,"id",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,nc_json_str_def(x,"target",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,3,nc_json_int_def(x,"weight",100));sqlite3_bind_text(st,4,nc_json_str_def(x,"role","active"),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,5,j);if(nc_step_done(st)!=0)rc=-1;sqlite3_finalize(st);}}}}}
    if(rc==0&&json_object_object_get_ex(cfg,"rules",&arr)&&arr){nc_exec("DELETE FROM flow_rules");for(i=0,n=json_object_array_length(arr);i<n;i++){o=json_object_array_get_idx(arr,i);if(nc_prepare(&st,"INSERT INTO flow_rules(id,enabled,priority,name,type,source,destination,apps,protocol,action,target,qos_class,schedule,fallback,sticky,remark,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)")==0){sqlite3_bind_text(st,1,nc_json_str_def(o,"id",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,nc_json_bool_def(o,"enabled",1));sqlite3_bind_int(st,3,nc_json_int_def(o,"priority",1000));sqlite3_bind_text(st,4,nc_json_str_def(o,"name",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"type",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,nc_json_str_def(o,"source",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,7,nc_json_str_def(o,"destination",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,8,nc_json_str_def(o,"apps",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,9,nc_json_str_def(o,"protocol",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,10,nc_json_str_def(o,"action",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,11,nc_json_str_def(o,"target",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,12,nc_json_str_def(o,"qos_class",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,13,nc_json_str_def(o,"schedule","always"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,14,nc_json_str_def(o,"fallback","auto"),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,15,nc_json_bool_def(o,"sticky",1));sqlite3_bind_text(st,16,nc_json_str_def(o,"remark",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,17,nc_now_s());sqlite3_bind_int64(st,18,nc_now_s());if(nc_step_done(st)!=0)rc=-1;sqlite3_finalize(st);}}}
    if(rc==0&&json_object_object_get_ex(cfg,"client_limits",&arr)&&arr){nc_exec("DELETE FROM flow_client_limits");for(i=0,n=json_object_array_length(arr);i<n;i++){o=json_object_array_get_idx(arr,i);if(nc_prepare(&st,"INSERT INTO flow_client_limits(id,enabled,client,ip,device_group,upload_kbps,download_kbps,mode,remark) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)")==0){sqlite3_bind_text(st,1,nc_json_str_def(o,"id",""),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,2,nc_json_bool_def(o,"enabled",1));sqlite3_bind_text(st,3,nc_json_str_def(o,"client",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,nc_json_str_def(o,"ip",""),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,5,nc_json_str_def(o,"group",nc_json_str_def(o,"device_group","")),-1,SQLITE_TRANSIENT);sqlite3_bind_int(st,6,nc_json_int_def(o,"upload_kbps",0));sqlite3_bind_int(st,7,nc_json_int_def(o,"download_kbps",0));sqlite3_bind_text(st,8,nc_json_str_def(o,"mode","inherit"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,9,nc_json_str_def(o,"remark",""),-1,SQLITE_TRANSIENT);if(nc_step_done(st)!=0)rc=-1;sqlite3_finalize(st);}}}
    /* Smart mode */
    if(rc==0 && json_object_object_get_ex(cfg,"smart",&o) && o) {
        struct json_object *sm = NULL;
        if(json_object_object_get_ex(o,"mode",&sm) && sm) {
            const char *mode = json_object_get_string(sm);
            if(!mode) mode = "custom";
            sqlite3_stmt *smt = NULL;
            if(nc_prepare(&smt,"UPDATE flow_smart SET mode=?1,updated_at=?2 WHERE id=1")==0) {
                sqlite3_bind_text(smt,1,mode,-1,SQLITE_TRANSIENT);
                sqlite3_bind_int64(smt,2,nc_now_s());
                if(nc_step_done(smt)!=0) rc=-1;
                sqlite3_finalize(smt);
            }
        }
        struct json_object *lm = NULL;
        if(json_object_object_get_ex(o,"line_modes",&lm) && lm && json_object_is_type(lm,json_type_object)) {
            json_object_object_foreach(lm, lk, lv) {
                sqlite3_stmt *lmt = NULL;
                if(nc_prepare(&lmt,"INSERT INTO flow_smart_line_mode(wan_id,mode,updated_at) VALUES(?1,?2,?3) ON CONFLICT(wan_id) DO UPDATE SET mode=excluded.mode,updated_at=excluded.updated_at")==0) {
                    sqlite3_bind_text(lmt,1,lk,-1,SQLITE_TRANSIENT);
                    sqlite3_bind_text(lmt,2,json_object_get_string(lv),-1,SQLITE_TRANSIENT);
                    sqlite3_bind_int64(lmt,3,nc_now_s());
                    if(nc_step_done(lmt)!=0) rc=-1;
                    sqlite3_finalize(lmt);
                }
            }
        }
        struct json_object *pri = NULL;
        if(json_object_object_get_ex(o,"priorities",&pri) && pri && json_object_is_type(pri,json_type_object)) {
            json_object_object_foreach(pri, pk, pv) {
                sqlite3_stmt *prt = NULL;
                if(nc_prepare(&prt,"INSERT INTO flow_smart_priority(app_key,priority,updated_at) VALUES(?1,?2,?3) ON CONFLICT(app_key) DO UPDATE SET priority=excluded.priority,updated_at=excluded.updated_at")==0) {
                    sqlite3_bind_text(prt,1,pk,-1,SQLITE_TRANSIENT);
                    sqlite3_bind_int(prt,2,json_object_get_int(pv));
                    sqlite3_bind_int64(prt,3,nc_now_s());
                    if(nc_step_done(prt)!=0) rc=-1;
                    sqlite3_finalize(prt);
                }
            }
        }
    }
    nc_exec(rc==0?"COMMIT":"ROLLBACK"); return rc;
}

/* Smart mode standalone save (POST /flow_control/smart) */
int jmx_flow_control_smart_set(struct json_object *cfg)
{
    if(!cfg||jmx_netconfig_db_init()!=0)return -1; nc_flow_db_init();
    sqlite3_stmt *st=NULL; int rc=0;
    if (nc_txn_begin() != 0) return -1;
    struct json_object *v=NULL;
    if(json_object_object_get_ex(cfg,"mode",&v) && v) {
        if(nc_prepare(&st,"UPDATE flow_smart SET mode=?1,updated_at=?2 WHERE id=1")==0) {
            sqlite3_bind_text(st,1,json_object_get_string(v),-1,SQLITE_TRANSIENT);
            sqlite3_bind_int64(st,2,nc_now_s());
            if(nc_step_done(st)!=0) rc=-1;
            sqlite3_finalize(st);
        }
    }
    if(json_object_object_get_ex(cfg,"line_modes",&v) && v && json_object_is_type(v,json_type_object)) {
        json_object_object_foreach(v, lk, lv) {
            if(nc_prepare(&st,"INSERT INTO flow_smart_line_mode(wan_id,mode,updated_at) VALUES(?1,?2,?3) ON CONFLICT(wan_id) DO UPDATE SET mode=excluded.mode,updated_at=excluded.updated_at")==0) {
                sqlite3_bind_text(st,1,lk,-1,SQLITE_TRANSIENT);
                sqlite3_bind_text(st,2,json_object_get_string(lv),-1,SQLITE_TRANSIENT);
                sqlite3_bind_int64(st,3,nc_now_s());
                if(nc_step_done(st)!=0) rc=-1;
                sqlite3_finalize(st);
            }
        }
    }
    nc_exec(rc==0?"COMMIT":"ROLLBACK"); return rc;
}

/* Priorities standalone save (POST /flow_control/smart/priorities) */
static int g_priority_rollback_attempted;
static int g_priority_rollback_ok;
int jmx_flow_control_priority_last_rollback_attempted(void) { return g_priority_rollback_attempted; }
int jmx_flow_control_priority_last_rollback_ok(void) { return g_priority_rollback_ok; }

int jmx_flow_control_priority_set(struct json_object *cfg)
{
    struct nc_flow_qos_apply old_plan, new_plan;
    char target[64] = "";
    struct json_object *priorities = cfg;
    char old_keys[64][64];
    int old_values[64];
    int old_count = 0;
    char old_global_keys[64][64];
    int old_global_values[64];
    int old_global_count = 0;
    int per_wan = 0;
    sqlite3_stmt *st=NULL; int rc=0; int i;
    g_priority_rollback_attempted = 0;
    g_priority_rollback_ok = 1;
    if(!cfg||jmx_netconfig_db_init()!=0)return -1; nc_flow_db_init();
    {
        struct json_object *v = NULL;
        if (json_object_object_get_ex(cfg, "wan_id", &v) && v &&
            json_object_is_type(v, json_type_string)) {
            snprintf(target, sizeof(target), "%s", json_object_get_string(v));
            if (!target[0])
                return -4;
            per_wan = 1;
            if (!json_object_object_get_ex(cfg, "priorities", &priorities) ||
                !priorities || !json_object_is_type(priorities, json_type_object))
                return -3;
        }
    }
    /*
     * Validate the whole body before opening the transaction.
     *
     * Previously every value went straight to sqlite3_bind_int(): {"game":999}
     * stored 999, and an unknown key silently created a row that no classifier
     * would ever match. The column has no CHECK and the API layer does not
     * validate either, so there was no server-side bound at all -- the old
     * frontend's 0-7 clamp lived in the browser and, per the acceptance handoff,
     * was never even submitted.
     *
     * Rejecting the whole request rather than clamping is deliberate: clamping
     * stores a number the user did not choose and reports success, so the UI
     * shows a value that silently differs from what was asked for.
     */
    json_object_object_foreach(priorities, vk, vv) {
        int pv;

        if (!nc_flow_priority_key_ok(vk))
            return -2;
        if (!vv || !json_object_is_type(vv, json_type_int))
            return -3;
        pv = json_object_get_int(vv);
        if (pv < 0 || pv > 7)
            return -3;
    }
    if (per_wan) {
        if (nc_prepare(&st, "SELECT enabled FROM wan WHERE id=?1") != 0)
            return -1;
        sqlite3_bind_text(st, 1, target, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) != SQLITE_ROW || !sqlite3_column_int(st, 0)) {
            sqlite3_finalize(st);
            return -4;
        }
        sqlite3_finalize(st); st = NULL;
    }
    if (nc_flow_qos_plan_load(&old_plan) != 0)
        memset(&old_plan, 0, sizeof(old_plan));
    if (per_wan) {
        if (nc_prepare(&st, "SELECT app_key,priority FROM flow_smart_line_priority WHERE wan_id=?1") == 0) {
            sqlite3_bind_text(st, 1, target, -1, SQLITE_TRANSIENT);
            while (sqlite3_step(st) == SQLITE_ROW && old_count < 64) {
                snprintf(old_keys[old_count], sizeof(old_keys[0]), "%s",
                         (const char *)sqlite3_column_text(st, 0));
                old_values[old_count] = sqlite3_column_int(st, 1);
                old_count++;
            }
            sqlite3_finalize(st); st = NULL;
        }
    } else if (nc_prepare(&st, "SELECT app_key,priority FROM flow_smart_priority") == 0) {
        while (sqlite3_step(st) == SQLITE_ROW && old_global_count < 64) {
            snprintf(old_global_keys[old_global_count], sizeof(old_global_keys[0]), "%s",
                     (const char *)sqlite3_column_text(st, 0));
            old_global_values[old_global_count] = sqlite3_column_int(st, 1);
            old_global_count++;
        }
        sqlite3_finalize(st); st = NULL;
    } else {
        return -1;
    }
    if (nc_txn_begin() != 0) return -1;
    json_object_object_foreach(priorities, k, v) {
        if (per_wan) {
            if(nc_prepare(&st,"INSERT INTO flow_smart_line_priority(wan_id,app_key,priority,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(wan_id,app_key) DO UPDATE SET priority=excluded.priority,updated_at=excluded.updated_at")==0) {
                sqlite3_bind_text(st,1,target,-1,SQLITE_TRANSIENT);
                sqlite3_bind_text(st,2,k,-1,SQLITE_TRANSIENT);
                sqlite3_bind_int(st,3,json_object_get_int(v));
                sqlite3_bind_int64(st,4,nc_now_s());
                if(nc_step_done(st)!=0) rc=-1;
                sqlite3_finalize(st);
            }
        } else if(nc_prepare(&st,"INSERT INTO flow_smart_priority(app_key,priority,updated_at) VALUES(?1,?2,?3) ON CONFLICT(app_key) DO UPDATE SET priority=excluded.priority,updated_at=excluded.updated_at")==0) {
            sqlite3_bind_text(st,1,k,-1,SQLITE_TRANSIENT);
            sqlite3_bind_int(st,2,json_object_get_int(v));
            sqlite3_bind_int64(st,3,nc_now_s());
            if(nc_step_done(st)!=0) rc=-1;
            sqlite3_finalize(st);
        }
    }
    if (rc != 0) {
        nc_exec("ROLLBACK");
        return rc;
    }
    nc_exec("COMMIT");

    /*
     * Dual-write global priorities to flowd_smart_qos_categories so flowd
     * has the data for its compile/apply path.  Per-WAN priorities stay in
     * the legacy table until flowd gains per-WAN QoS support.
     */
    if (!per_wan) {
        json_object_object_foreach(priorities, dk, dv) {
            int legacy_pri = json_object_get_int(dv);
            int flowd_pri = 100 + legacy_pri * 100;
            char gen_id[64];

            if (flowd_pri > 1000)
                flowd_pri = 1000;
            snprintf(gen_id, sizeof(gen_id), "migrated-%s", dk);
            if (nc_prepare(&st,
                "INSERT INTO flowd_smart_qos_categories"
                "(id,name,enabled,category,priority,qos_class,"
                "latency_target_ms,remark,created_at,updated_at) "
                "VALUES(?1,?2,1,?3,?4,'',0,'dual_write',?5,?5) "
                "ON CONFLICT(id) DO UPDATE SET priority=excluded.priority,"
                "updated_at=excluded.updated_at") == 0) {
                sqlite3_bind_text(st, 1, gen_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 2, dk, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 3, dk, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(st, 4, flowd_pri);
                sqlite3_bind_int64(st, 5, nc_now_s());
                sqlite3_step(st);
                sqlite3_finalize(st);
            }
        }
    }

    /* Apply through flowd's compile (legacy executor is a no-op now) */
    if (nc_flowd_compile_apply() != 0) {
        g_priority_rollback_attempted = 1;
        g_priority_rollback_ok = 0;
        if (per_wan) {
            if (nc_txn_begin() == 0) {
                if (nc_prepare(&st, "DELETE FROM flow_smart_line_priority WHERE wan_id=?1") == 0) {
                    sqlite3_bind_text(st, 1, target, -1, SQLITE_TRANSIENT);
                    sqlite3_step(st);
                    sqlite3_finalize(st);
                }
                for (i = 0; i < old_count; i++) {
                    if (nc_prepare(&st,"INSERT INTO flow_smart_line_priority(wan_id,app_key,priority,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(wan_id,app_key) DO UPDATE SET priority=excluded.priority,updated_at=excluded.updated_at") == 0) {
                        sqlite3_bind_text(st,1,target,-1,SQLITE_TRANSIENT);
                        sqlite3_bind_text(st,2,old_keys[i],-1,SQLITE_TRANSIENT);
                        sqlite3_bind_int(st,3,old_values[i]);
                        sqlite3_bind_int64(st,4,nc_now_s());
                        sqlite3_step(st); sqlite3_finalize(st);
                    }
                }
                if (nc_exec("COMMIT") == 0)
                    g_priority_rollback_ok = 1;
            }
        } else if (nc_txn_begin() == 0) {
            nc_exec("DELETE FROM flow_smart_priority");
            for (i = 0; i < old_global_count; i++) {
                if (nc_prepare(&st, "INSERT INTO flow_smart_priority(app_key,priority,updated_at) VALUES(?1,?2,?3)") == 0) {
                    sqlite3_bind_text(st, 1, old_global_keys[i], -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(st, 2, old_global_values[i]);
                    sqlite3_bind_int64(st, 3, nc_now_s());
                    sqlite3_step(st);
                    sqlite3_finalize(st);
                }
            }
            if (nc_exec("COMMIT") == 0)
                g_priority_rollback_ok = 1;
        }
        return -5;
    }
    return 0;
}

struct json_object *jmx_flow_control_apply(struct json_object *cfg)
{
    struct json_object *data=json_object_new_object(),*summary=json_object_new_object();
    int dry=nc_json_bool_def(cfg,"dry_run",0);
    struct nc_flow_qos_apply plan;
    int rc;

    if(jmx_netconfig_db_init()!=0){json_object_object_add(data,"ok",json_object_new_boolean(0));return jmx_gen_api_response_data(API_CODE_ERROR,data);}
    nc_flow_db_init();
    json_object_object_add(summary,"groups",json_object_new_int(nc_vpn_count_table("flow_groups","WHERE enabled=1")));
    json_object_object_add(summary,"rules",json_object_new_int(nc_vpn_count_table("flow_rules","WHERE enabled=1")));
    json_object_object_add(summary,"client_limits",json_object_new_int(nc_vpn_count_table("flow_client_limits","WHERE enabled=1")));

    rc = nc_flow_qos_plan_load(&plan);
    /*
     * Report the scheduler that is actually on the interface. This used to be the
     * literal string "cake" regardless of reality, which read as "cake is already
     * running" while 30.1 was on fq_codel.
     */
    json_object_object_add(summary,"tc_scheduler",json_object_new_string(plan.running_qdisc));
    json_object_object_add(summary,"tc_scheduler_target",json_object_new_string(plan.scheduler));
    json_object_object_add(summary,"egress_ifname",json_object_new_string(plan.ifname));
    json_object_object_add(summary,"diffserv",json_object_new_string(plan.diffserv));
    json_object_object_add(summary,"categories",json_object_new_int(plan.category_count));
    json_object_object_add(summary,"dscp_rules",json_object_new_int(plan.rule_count));

    json_object_object_add(data,"configured",json_object_new_boolean(1));
    json_object_object_add(data,"dry_run",json_object_new_boolean(dry));
    json_object_object_add(data,"planned",json_object_new_boolean(1));
    json_object_object_add(data,"plan",nc_flow_qos_plan_json(&plan));

    if (rc != 0) {
        /*
         * A blocked plan is reported with the specific reason rather than one
         * capability flag: "no bandwidth figure" and "no egress interface" need
         * different fixes, and collapsing them told the operator nothing.
         */
        json_object_object_add(data,"ok",json_object_new_boolean(dry));
        json_object_object_add(data,"applied",json_object_new_boolean(0));
        json_object_object_add(data,"runtime_applied",json_object_new_boolean(0));
        json_object_object_add(data,"runtime_reason",json_object_new_string(plan.reason));
        json_object_object_add(data,"message",json_object_new_string(plan.message));
        if (!dry)
            json_object_object_add(data,"error",json_object_new_string(plan.reason));
        json_object_object_add(data,"summary",summary);
        return jmx_gen_api_response_data(dry?API_CODE_SUCCESS:API_CODE_ERROR,data);
    }

    if (dry) {
        json_object_object_add(data,"ok",json_object_new_boolean(1));
        json_object_object_add(data,"applied",json_object_new_boolean(0));
        json_object_object_add(data,"runtime_applied",json_object_new_boolean(0));
        json_object_object_add(data,"runtime_reason",json_object_new_string("dry_run_no_mutation"));
        json_object_object_add(data,"message",json_object_new_string("plan only; no nft or tc mutation was performed"));
        json_object_object_add(data,"summary",summary);
        return jmx_gen_api_response_data(API_CODE_SUCCESS,data);
    }

    /* Apply through flowd's compile (legacy executor is a no-op now) */
    rc = nc_flowd_compile_apply();
    json_object_object_add(data,"ok",json_object_new_boolean(rc == 0));
    json_object_object_add(data,"applied",json_object_new_boolean(rc == 0));
    json_object_object_add(data,"runtime_applied",json_object_new_boolean(rc == 0));
    json_object_object_add(data,"runtime_reason",json_object_new_string(rc == 0 ? "applied" : "flowd_compile_failed"));
    json_object_object_add(data,"message",json_object_new_string(rc == 0 ? "applied via flowd compile" : "flowd compile failed"));
    json_object_object_add(data,"rolled_back",json_object_new_boolean(0));
    if (rc != 0)
        json_object_object_add(data,"error",json_object_new_string("flowd_compile_failed"));
    json_object_object_add(summary,"tc_scheduler",json_object_new_string(plan.running_qdisc));
    json_object_object_add(data,"summary",summary);
    return jmx_gen_api_response_data(rc == 0 ? API_CODE_SUCCESS : API_CODE_ERROR,data);
}

struct json_object *jmx_flow_control_rule_test(struct json_object *cfg)
{
    struct json_object *data=json_object_new_object(); sqlite3_stmt*st=NULL; const char*proto=nc_json_str_def(cfg,"protocol",""); const char*dst=nc_json_str_def(cfg,"destination",nc_json_str_def(cfg,"dst",""));
    if(jmx_netconfig_db_init()!=0){json_object_object_add(data,"matched",json_object_new_boolean(0));return jmx_gen_api_response_data(API_CODE_ERROR,data);} nc_flow_db_init();
    if(nc_prepare(&st,"SELECT id,name,action,target,qos_class FROM flow_rules WHERE enabled=1 AND (?1='' OR protocol='' OR instr(protocol,?1)>0) ORDER BY priority,id LIMIT 1")==0){sqlite3_bind_text(st,1,proto,-1,SQLITE_TRANSIENT);if(sqlite3_step(st)==SQLITE_ROW){json_object_object_add(data,"matched",json_object_new_boolean(1));nc_add_text(data,"rule_id",st,0);nc_add_text(data,"rule_name",st,1);nc_add_text(data,"action",st,2);nc_add_text(data,"target",st,3);nc_add_text(data,"qos_class",st,4);json_object_object_add(data,"reason",json_object_new_string("first enabled rule matching protocol"));}else json_object_object_add(data,"matched",json_object_new_boolean(0));sqlite3_finalize(st);} json_object_object_add(data,"dst",json_object_new_string(dst));return jmx_gen_api_response_data(API_CODE_SUCCESS,data);
}

int jmx_flow_control_group_carrier_set(struct json_object *cfg)
{
    if (!cfg || jmx_netconfig_db_init() != 0) return -1;
    nc_flow_db_init();
    struct json_object *arr = NULL;
    if (!json_object_object_get_ex(cfg, "groups", &arr) || !arr || !json_object_is_type(arr, json_type_array)) return -1;
    sqlite3_stmt *st = NULL;
    int rc = 0, i, n;
    if (nc_txn_begin() != 0) return -1;
    for (i = 0, n = json_object_array_length(arr); i < n; i++) {
        struct json_object *o = json_object_array_get_idx(arr, i);
        const char *id = nc_json_str_def(o, "id", "");
        const char *carrier = nc_json_str_def(o, "carrier", "");
        if (!id[0]) { rc = -1; break; }
        if (nc_prepare(&st, "UPDATE flow_groups SET carrier=?1,updated_at=?2 WHERE id=?3") == 0) {
            sqlite3_bind_text(st, 1, carrier, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, nc_now_s());
            sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
            if (nc_step_done(st) != 0) rc = -1;
            sqlite3_finalize(st); st = NULL;
        } else { rc = -1; break; }
    }
    nc_exec(rc == 0 ? "COMMIT" : "ROLLBACK");
    return rc;
}

