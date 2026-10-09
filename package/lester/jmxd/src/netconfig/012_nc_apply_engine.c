/* ══════════════════════════════════════════════════════════════════════
 * Apply engine: SQLite → UCI
 * ══════════════════════════════════════════════════════════════════════ */
/* lightweight UCI file backup/rollback for apply operations */
int nc_copy_file(const char *src, const char *dst)
{
    FILE *in, *out;
    char buf[4096];
    size_t n;
    if (!src || !dst) return -1;
    in = fopen(src, "rb");
    if (!in) return -1;
    out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { fclose(in); fclose(out); return -1; }
    }
    fclose(in);
    fclose(out);
    return 0;
}

int nc_backup_config(const char *pkg, char *bak, size_t bak_len)
{
    char src[256];
    static unsigned long backup_sequence;
    unsigned long sequence;
    if (!pkg || !bak || bak_len == 0) return -1;
    sequence = __sync_add_and_fetch(&backup_sequence, 1);
    snprintf(src, sizeof(src), "/etc/config/%s", pkg);
    snprintf(bak, bak_len, "/tmp/dw-netconfig-%ld-%lu-%s.bak",
             (long)getpid(), sequence, pkg);
    unlink(bak);
    return nc_copy_file(src, bak);
}

void nc_restore_config(const char *pkg, const char *bak)
{
    char dst[256];
    if (!pkg || !bak || !bak[0]) return;
    snprintf(dst, sizeof(dst), "/etc/config/%s", pkg);
    nc_copy_file(bak, dst);
}

void nc_cleanup_backup(const char *bak)
{
    if (bak && bak[0]) unlink(bak);
}
static int nc_reload_network_stack(int include_dhcp, int include_firewall, const char *log_path)
{
    char cmd[512];
    const char *log = (log_path && log_path[0]) ? log_path : "/tmp/dw-netconfig-reload.log";
    snprintf(cmd, sizeof(cmd),
             "export PATH=/sbin:/bin:/usr/sbin:/usr/bin; "
             "{ /bin/ubus call network reload 2>/dev/null || /sbin/ubus call network reload 2>/dev/null || /etc/init.d/network reload; } >%s 2>&1",
             log);
    int rc = nc_run_quiet(cmd);
    if (include_dhcp && access("/etc/init.d/dnsmasq", F_OK) == 0 &&
        nc_run_quiet("/etc/init.d/dnsmasq reload >>/tmp/dw-netconfig-reload.log 2>&1 || /etc/init.d/dnsmasq restart >>/tmp/dw-netconfig-reload.log 2>&1") != 0)
        rc = -1;
    if (include_firewall && access("/etc/init.d/firewall", F_OK) == 0 &&
        nc_run_quiet("/etc/init.d/firewall reload >>/tmp/dw-netconfig-reload.log 2>&1 || /etc/init.d/firewall restart >>/tmp/dw-netconfig-reload.log 2>&1") != 0)
        rc = -1;
    return rc;
}
int nc_run_quiet(const char *cmd)
{
    if(!cmd || !cmd[0]) return -1;
    int rc = system(cmd);
    if(rc == -1) return -1;
    if(WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

#define NC_NETCTL_NFT_RULESET "/etc/dreamingwrt/network_control.nft"
#define NC_NETCTL_NFT_TABLE "dreamingwrt_netctl"
#define NC_NETCTL_EXEC_TIMEOUT_MS 10000
#define NC_NETCTL_CAPTURE_OUTPUT_MAX (256U * 1024U)
#define NC_NETCTL_RUNTIME_DIR "/run/dreamingwrt"

static int nc_netctl_trusted_tool(const char *path)
{
    struct stat st;

    return path && lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_uid == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
           (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
}

static const char *nc_nft_tool_path(void)
{
    if (nc_netctl_trusted_tool("/usr/sbin/nft"))
        return "/usr/sbin/nft";
    if (nc_netctl_trusted_tool("/sbin/nft"))
        return "/sbin/nft";
    return NULL;
}

static int nc_netctl_exec_ok(int rc, const struct jmx_exec_result *result)
{
    if (rc != 0 || !result || result->timed_out || result->truncated ||
        result->term_signal != 0 || result->exit_code != 0)
        return -1;
    return 0;
}

static int nc_nft_capture(const char *path, char *const argv[],
                          struct jmx_exec_result *result)
{
    if (!path || !argv || !result)
        return -1;
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
    return jmx_exec_capture(path, argv, NC_NETCTL_CAPTURE_OUTPUT_MAX,
                            NC_NETCTL_EXEC_TIMEOUT_MS, result);
}

static int nc_netctl_secure_backup_write(const char *data, size_t data_len,
                                         char *path, size_t path_len)
{
    struct stat st;
    int dirfd = -1;
    int fd = -1;
    int attempt;
    char name[96] = {0};

    if (!data || data_len == 0 || !path || path_len == 0)
        return -1;
    path[0] = '\0';
    if (mkdir(NC_NETCTL_RUNTIME_DIR, 0700) != 0 && errno != EEXIST)
        return -1;
    dirfd = open(NC_NETCTL_RUNTIME_DIR,
                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto out;
    for (attempt = 0; attempt < 32; attempt++) {
        unsigned long long nonce = 0;
        ssize_t off = 0;

        if (getrandom(&nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce))
            goto out;
        snprintf(name, sizeof(name), ".netctl-nft-%016llx", nonce);
        fd = openat(dirfd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd < 0) {
            if (errno == EEXIST)
                continue;
            goto out;
        }
        while ((size_t)off < data_len) {
            ssize_t written = write(fd, data + off, data_len - (size_t)off);
            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0)
                goto out;
            off += written;
        }
        if (fsync(fd) != 0 || close(fd) != 0) {
            fd = -1;
            (void)unlinkat(dirfd, name, 0);
            goto out;
        }
        fd = -1;
        {
            int n = snprintf(path, path_len, "%s/%s",
                             NC_NETCTL_RUNTIME_DIR, name);
            if (n < 0 || (size_t)n >= path_len) {
            (void)unlinkat(dirfd, name, 0);
            path[0] = '\0';
            goto out;
            }
        }
        close(dirfd);
        return 0;
    }

out:
    if (fd >= 0) {
        close(fd);
        if (name[0])
            (void)unlinkat(dirfd, name, 0);
    }
    if (dirfd >= 0)
        close(dirfd);
    return -1;
}

static int nc_nft_table_capture(const char *nft,
                                struct jmx_exec_result *result, int *present)
{
    char *list_argv[] = { (char *)nft, "list", "table", "inet",
                          NC_NETCTL_NFT_TABLE, NULL };
    char *tables_argv[] = { (char *)nft, "list", "tables", NULL };
    int rc;

    if (!nft || !result || !present)
        return -1;
    *present = 0;
    rc = nc_nft_capture(nft, list_argv, result);
    if (nc_netctl_exec_ok(rc, result) == 0) {
        if (!result->output ||
            !strstr(result->output, "table inet " NC_NETCTL_NFT_TABLE))
            return -1;
        *present = 1;
        return 0;
    }
    if (rc != 0 || result->timed_out || result->truncated ||
        result->term_signal != 0 || result->exit_code < 0)
        return -1;
    jmx_exec_result_free(result);
    rc = nc_nft_capture(nft, tables_argv, result);
    if (nc_netctl_exec_ok(rc, result) != 0 || !result->output)
        return -1;
    if (strstr(result->output, "table inet " NC_NETCTL_NFT_TABLE))
        return -1;
    *present = 0;
    return 0;
}

static int nc_nft_delete_table(const char *nft)
{
    struct jmx_exec_result result;
    char *argv[] = { (char *)nft, "delete", "table", "inet",
                     NC_NETCTL_NFT_TABLE, NULL };
    int present = 0;
    int rc;

    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    if (nc_nft_table_capture(nft, &result, &present) != 0) {
        jmx_exec_result_free(&result);
        return -1;
    }
    jmx_exec_result_free(&result);
    if (!present)
        return 0;
    rc = jmx_exec_wait(nft, argv, NC_NETCTL_EXEC_TIMEOUT_MS, &result);
    if (nc_netctl_exec_ok(rc, &result) != 0) {
        jmx_exec_result_free(&result);
        return -1;
    }
    jmx_exec_result_free(&result);
    if (nc_nft_table_capture(nft, &result, &present) != 0 || present) {
        jmx_exec_result_free(&result);
        return -1;
    }
    jmx_exec_result_free(&result);
    return 0;
}

static int nc_nft_apply_file(const char *nft, const char *path)
{
    struct jmx_exec_result result;
    char *argv[] = { (char *)nft, "-f", (char *)path, NULL };
    int rc;

    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    rc = jmx_exec_wait(nft, argv, NC_NETCTL_EXEC_TIMEOUT_MS, &result);
    if (nc_netctl_exec_ok(rc, &result) != 0) {
        jmx_exec_result_free(&result);
        return -1;
    }
    jmx_exec_result_free(&result);
    return 0;
}

static int nc_nft_readback_verify(const char *nft)
{
    struct jmx_exec_result result;
    int present = 0;
    int ok;

    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    ok = nc_nft_table_capture(nft, &result, &present) == 0 && present &&
         result.output && strstr(result.output, "chain input") &&
         strstr(result.output, "chain forward_mark") &&
         strstr(result.output, "chain forward");
    jmx_exec_result_free(&result);
    return ok ? 0 : -1;
}

static int nc_nft_rollback(const char *nft, int backup_present,
                           const char *backup_path)
{
    struct jmx_exec_result result;
    int present = 0;

    if (nc_nft_delete_table(nft) != 0)
        return -1;
    if (backup_present) {
        if (!backup_path || !backup_path[0] ||
            nc_nft_apply_file(nft, backup_path) != 0)
            return -1;
        memset(&result, 0, sizeof(result));
        result.exit_code = -1;
        if (nc_nft_table_capture(nft, &result, &present) != 0 || !present ||
            !result.output ||
            !strstr(result.output, "table inet " NC_NETCTL_NFT_TABLE)) {
            jmx_exec_result_free(&result);
            return -1;
        }
        jmx_exec_result_free(&result);
        return 0;
    }
    memset(&result, 0, sizeof(result));
    result.exit_code = -1;
    if (nc_nft_table_capture(nft, &result, &present) != 0 || present) {
        jmx_exec_result_free(&result);
        return -1;
    }
    jmx_exec_result_free(&result);
    return 0;
}

struct nc_nft_transaction {
    char backup_path[256];
    int backup_present;
    int applied;
};

static void nc_nft_transaction_finish(struct nc_nft_transaction *transaction)
{
    if (!transaction)
        return;
    if (transaction->backup_path[0])
        unlink(transaction->backup_path);
    memset(transaction, 0, sizeof(*transaction));
}

static int nc_nft_transaction_restore(struct nc_nft_transaction *transaction)
{
    const char *nft;

    if (!transaction || !transaction->applied)
        return 0;
    nft = nc_nft_tool_path();
    if (!nft || nc_nft_rollback(nft, transaction->backup_present,
                                transaction->backup_path) != 0)
        return -1;
    nc_nft_transaction_finish(transaction);
    return 0;
}

static int nc_nft_guarded_apply(const char *ruleset, char *detail,
                                size_t detail_len,
                                struct nc_nft_transaction *transaction)
{
    struct jmx_exec_result backup;
    struct jmx_exec_result check;
    const char *nft = nc_nft_tool_path();
    char backup_path[256] = {0};
    char *check_argv[] = { (char *)nft, "--check", "--file",
                           (char *)ruleset, NULL };
    int backup_present = 0;
    int mutated = 0;
    int rc;

    if (transaction)
        memset(transaction, 0, sizeof(*transaction));
    if (detail && detail_len)
        detail[0] = '\0';
    if (!ruleset || strcmp(ruleset, NC_NETCTL_NFT_RULESET) != 0 ||
        access(ruleset, R_OK) != 0) {
        if (detail) snprintf(detail, detail_len, "nft_ruleset_missing");
        return -1;
    }
    if (!nft) {
        if (detail) snprintf(detail, detail_len, "nft_binary_missing_or_untrusted");
        return -2;
    }
    check_argv[0] = (char *)nft;
    memset(&check, 0, sizeof(check));
    check.exit_code = -1;
    rc = nc_nft_capture(nft, check_argv, &check);
    if (nc_netctl_exec_ok(rc, &check) != 0) {
        if (detail) snprintf(detail, detail_len, "nft_check_failed");
        jmx_exec_result_free(&check);
        return -3;
    }
    jmx_exec_result_free(&check);

    memset(&backup, 0, sizeof(backup));
    backup.exit_code = -1;
    if (nc_nft_table_capture(nft, &backup, &backup_present) != 0) {
        if (detail) snprintf(detail, detail_len, "nft_backup_read_failed");
        jmx_exec_result_free(&backup);
        return -4;
    }
    if (backup_present &&
        nc_netctl_secure_backup_write(backup.output, backup.output_len,
                                      backup_path, sizeof(backup_path)) != 0) {
        if (detail) snprintf(detail, detail_len, "nft_backup_store_failed");
        jmx_exec_result_free(&backup);
        return -5;
    }
    jmx_exec_result_free(&backup);

    mutated = backup_present;
    if (nc_nft_delete_table(nft) != 0) {
        if (detail) snprintf(detail, detail_len, "nft_delete_failed");
        goto rollback;
    }
    if (nc_nft_apply_file(nft, ruleset) != 0) {
        if (detail) snprintf(detail, detail_len, "nft_apply_failed");
        mutated = 1;
        goto rollback;
    }
    mutated = 1;
    if (nc_nft_readback_verify(nft) != 0) {
        if (detail) snprintf(detail, detail_len, "nft_readback_failed");
        goto rollback;
    }
    if (transaction) {
        transaction->backup_present = backup_present;
        transaction->applied = 1;
        snprintf(transaction->backup_path, sizeof(transaction->backup_path),
                 "%s", backup_path);
        backup_path[0] = '\0';
    }
    if (backup_path[0]) unlink(backup_path);
    if (detail) snprintf(detail, detail_len, "nft_applied_and_verified");
    return 0;

rollback:
    if (mutated && nc_nft_rollback(nft, backup_present, backup_path) != 0) {
        if (detail) snprintf(detail, detail_len, "nft_rollback_failed");
        if (backup_path[0]) unlink(backup_path);
        return -7;
    }
    if (detail) snprintf(detail, detail_len, "nft_apply_failed_rollback_verified");
    if (backup_path[0]) unlink(backup_path);
    return -6;
}

struct nc_tc_plan;
static int nc_tc_plan_count(void);
static int nc_tc_guarded_apply(char *detail, size_t detail_len,
                               struct nc_tc_plan *previous_out);
int nc_uci_set_pkg(struct uci_context *ctx, const char *pkg_name,
                   const char *section, const char *option,
                   const char *value)
{
    struct uci_ptr ptr = {0};
    char buf[768];
    if (!ctx || !pkg_name || !section || !option) return -1;
    if (!value) value = "";
    snprintf(buf, sizeof(buf), "%s.%s.%s=%s", pkg_name, section, option, value);
    if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK) return -1;
    return uci_set(ctx, &ptr);
}

int nc_uci_delete_pkg(struct uci_context *ctx, const char *pkg_name,
                      const char *section, const char *option)
{
    struct uci_ptr ptr = {0};
    char buf[512];
    if (!ctx || !pkg_name || !section || !option) return -1;
    snprintf(buf, sizeof(buf), "%s.%s.%s", pkg_name, section, option);
    if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK || !ptr.o) return 0;
    return uci_delete(ctx, &ptr);
}
static int nc_uci_delete_section_pkg(struct uci_context *ctx, const char *pkg_name,
                                     const char *section)
{
    struct uci_ptr ptr = {0};
    char buf[512];
    if (!ctx || !pkg_name || !section || !section[0]) return -1;
    if ((size_t)snprintf(buf, sizeof(buf), "%s.%s", pkg_name, section) >= sizeof(buf))
        return -1;
    if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK || !ptr.s) return 0;
    return uci_delete(ctx, &ptr);
}

static struct uci_section *nc_uci_find_network_device(struct uci_context *ctx,
                                                       struct uci_package *pkg,
                                                       const char *device_name)
{
    struct uci_element *e;

    if (!ctx || !pkg || !device_name || !device_name[0])
        return NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        struct uci_option *name;

        if (!s || strcmp(s->type, "device"))
            continue;
        name = uci_lookup_option(ctx, s, "name");
        if (name && name->type == UCI_TYPE_STRING && name->v.string &&
            !strcmp(name->v.string, device_name))
            return s;
    }
    return NULL;
}

static int nc_uci_delete_loaded_section(struct uci_context *ctx,
                                         struct uci_package *pkg,
                                         struct uci_section *section)
{
    struct uci_ptr ptr = {0};

    if (!ctx || !pkg || !section)
        return -1;
    ptr.p = pkg;
    ptr.s = section;
    return uci_delete(ctx, &ptr);
}

static int nc_uci_ensure_network_device(struct uci_context *ctx,
                                        struct uci_package *pkg,
                                        const char *device_name,
                                        const char **section_out)
{
    struct uci_section *s;

    if (section_out)
        *section_out = NULL;
    if (!ctx || !pkg || !nc_iface_name_ok(device_name))
        return -1;
    s = nc_uci_find_network_device(ctx, pkg, device_name);
    if (!s) {
        if (uci_add_section(ctx, pkg, "device", &s) != UCI_OK || !s)
            return -1;
        if (nc_uci_set_pkg(ctx, "network", s->e.name, "name", device_name) != UCI_OK) {
            nc_uci_delete_loaded_section(ctx, pkg, s);
            return -1;
        }
    }
    if (section_out)
        *section_out = s->e.name;
    return 0;
}

static int nc_uci_delete_network_device(struct uci_context *ctx,
                                        struct uci_package *pkg,
                                        const char *device_name)
{
    struct uci_section *s;

    if (!ctx || !pkg || !device_name || !device_name[0])
        return -1;
    s = nc_uci_find_network_device(ctx, pkg, device_name);
    if (!s)
        return 0;
    return nc_uci_delete_loaded_section(ctx, pkg, s);
}

void nc_uci_delete_managed_sections(struct uci_context *ctx, struct uci_package *pkg,
                                    const char *pkg_name, const char *type,
                                    const char *prefix)
{
    struct uci_element *e;
    char names[128][96];
    int n = 0, i;
    if (!ctx || !pkg || !pkg_name || !type || !prefix) return;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (!s || strcmp(s->type, type) != 0 || !s->e.name) continue;
        if (strncmp(s->e.name, prefix, strlen(prefix)) != 0) continue;
        snprintf(names[n++], sizeof(names[0]), "%s", s->e.name);
        if (n >= (int)(sizeof(names) / sizeof(names[0]))) break;
    }
    for (i = 0; i < n; i++) nc_uci_delete_section_pkg(ctx, pkg_name, names[i]);
}

int nc_uci_add_list_pkg(struct uci_context *ctx, const char *pkg_name,
                        const char *section, const char *option,
                        const char *value)
{
    struct uci_ptr ptr = {0};
    char buf[768];
    if (!ctx || !pkg_name || !section || !option || !value || !value[0]) return 0;
    snprintf(buf, sizeof(buf), "%s.%s.%s=%s", pkg_name, section, option, value);
    if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK) return -1;
    return uci_add_list(ctx, &ptr);
}

static int nc_uci_del_list_pkg(struct uci_context *ctx, const char *pkg_name,
                               const char *section, const char *option,
                               const char *value)
{
    struct uci_ptr ptr = {0};
    char buf[768];

    if (!ctx || !pkg_name || !section || !option || !value || !value[0]) return 0;
    snprintf(buf, sizeof(buf), "%s.%s.%s=%s", pkg_name, section, option, value);
    if (uci_lookup_ptr(ctx, &ptr, buf, true) != UCI_OK || !ptr.o) return 0;
    return uci_del_list(ctx, &ptr);
}

static int nc_uci_list_has_value(struct uci_section *s, const char *option,
                                 const char *value)
{
    struct uci_option *o;
    struct uci_element *e;

    if (!s || !option || !value) return 0;
    o = uci_lookup_option(s->package->ctx, s, option);
    if (!o) return 0;
    if (o->type == UCI_TYPE_STRING)
        return o->v.string && !strcmp(o->v.string, value);
    if (o->type != UCI_TYPE_LIST) return 0;
    uci_foreach_element(&o->v.list, e) {
        if (e->name && !strcmp(e->name, value)) return 1;
    }
    return 0;
}

static int nc_apply_wan_firewall_zone(struct uci_context *ctx,
                                      struct uci_package *pkg,
                                      const char *wan_id, int enabled)
{
    struct uci_element *e;
    struct uci_section *wan_zone = NULL;
    const char *section;

    if (!ctx || !pkg || !wan_id || !wan_id[0]) return -1;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        struct uci_option *name;

        if (!s || strcmp(s->type, "zone")) continue;
        name = uci_lookup_option(ctx, s, "name");
        if (name && name->type == UCI_TYPE_STRING && name->v.string &&
            !strcmp(name->v.string, "wan")) {
            wan_zone = s;
            break;
        }
    }
    if (!wan_zone) {
        if (nc_uci_ensure_section(ctx, pkg, "firewall", "dw_wan", "zone") != 0)
            return -1;
        nc_uci_set_pkg(ctx, "firewall", "dw_wan", "name", "wan");
        nc_uci_set_pkg(ctx, "firewall", "dw_wan", "input", "REJECT");
        nc_uci_set_pkg(ctx, "firewall", "dw_wan", "output", "ACCEPT");
        nc_uci_set_pkg(ctx, "firewall", "dw_wan", "forward", "REJECT");
        nc_uci_set_pkg(ctx, "firewall", "dw_wan", "masq", "1");
        nc_uci_set_pkg(ctx, "firewall", "dw_wan", "mtu_fix", "1");
        section = "dw_wan";
    } else {
        section = wan_zone->e.name;
    }

    if (enabled) {
        if (!wan_zone || !nc_uci_list_has_value(wan_zone, "network", wan_id))
            return nc_uci_add_list_pkg(ctx, "firewall", section, "network", wan_id);
        return 0;
    }
    if (wan_zone && nc_uci_list_has_value(wan_zone, "network", wan_id))
        return nc_uci_del_list_pkg(ctx, "firewall", section, "network", wan_id);
    return 0;
}

int nc_uci_ensure_section(struct uci_context *ctx, struct uci_package *pkg,
                          const char *pkg_name, const char *section,
                          const char *type)
{
    struct uci_ptr ptr = {0};
    char buf[512];
    if (!ctx || !pkg || !section || !type) return -1;
    snprintf(buf, sizeof(buf), "%s.%s", pkg_name, section);
    if (uci_lookup_ptr(ctx, &ptr, buf, true) == UCI_OK && ptr.s) return 0;
    if (!nc_uci_section_name_ok(section)) return -1;
    struct uci_section *s = NULL;
    if (uci_add_section(ctx, pkg, type, &s) != UCI_OK) return -1;
    char rbuf[512];
    struct uci_ptr rptr = {0};
    snprintf(rbuf, sizeof(rbuf), "%s.@%s[-1]=%s", pkg_name, type, section);
    if (uci_lookup_ptr(ctx, &rptr, rbuf, true) != UCI_OK ||
        uci_rename(ctx, &rptr) != UCI_OK || !s->e.name || strcmp(s->e.name, section)) {
        nc_uci_delete_loaded_section(ctx, pkg, s);
        return -1;
    }
    return 0;
}

static const char *nc_wan_primary_address(const char *wan_id, char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    out[0] = '\0';
    if (nc_prepare(&st, "SELECT ip,prefix FROM wan_address WHERE wan_id=?1 ORDER BY is_primary DESC, sort_order LIMIT 1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *ip = (const char *)sqlite3_column_text(st, 0);
            int prefix = sqlite3_column_int(st, 1);
            if (ip) snprintf(out, out_len, "%s/%d", ip, prefix);
        }
        sqlite3_finalize(st);
    }
    return out;
}

static void nc_apply_wan_addresses(struct uci_context *ctx, const char *wan_id)
{
    sqlite3_stmt *st = NULL;
    nc_uci_delete_pkg(ctx, "network", wan_id, "ipaddr");
    if (nc_prepare(&st, "SELECT ip,prefix FROM wan_address WHERE wan_id=?1 ORDER BY is_primary DESC, sort_order") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *ip = (const char *)sqlite3_column_text(st, 0);
            int prefix = sqlite3_column_int(st, 1);
            char cidr[64];
            if (!ip) continue;
            snprintf(cidr, sizeof(cidr), "%s/%d", ip, prefix);
            nc_uci_add_list_pkg(ctx, "network", wan_id, "ipaddr", cidr);
        }
        sqlite3_finalize(st);
    }
}

static const char *nc_json_string_at(struct json_object *arr, int idx)
{
    if (!arr || !json_object_is_type(arr, json_type_array) || idx < 0 || idx >= (int)json_object_array_length(arr)) return "";
    const char *s = json_object_get_string(json_object_array_get_idx(arr, idx));
    return s ? s : "";
}

static void nc_apply_wan_bond(struct uci_context *ctx, struct uci_package *pkg,
                              const char *wan_id, const char **device_out)
{
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "SELECT enabled,bond_name,mode,hash_policy,members_json FROM wan_bond WHERE wan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            int enabled = sqlite3_column_int(st, 0);
            const char *bond_name = (const char *)sqlite3_column_text(st, 1);
            const char *mode = (const char *)sqlite3_column_text(st, 2);
            const char *hash = (const char *)sqlite3_column_text(st, 3);
            const char *members_json = (const char *)sqlite3_column_text(st, 4);
            struct json_object *members = members_json ? json_tokener_parse(members_json) : NULL;
            int i, n = members && json_object_is_type(members, json_type_array) ? (int)json_object_array_length(members) : 0;
            if (enabled && bond_name && bond_name[0] && n >= 2) {
                const char *section = NULL;
                if (nc_uci_ensure_network_device(ctx, pkg, bond_name, &section) != 0)
                    goto bond_done;
                nc_uci_set_pkg(ctx, "network", section, "type", "bonding");
                nc_uci_set_pkg(ctx, "network", section, "mode", mode && mode[0] ? mode : "802.3ad");
                if (hash && hash[0]) nc_uci_set_pkg(ctx, "network", section, "xmit_hash_policy", hash);
                nc_uci_delete_pkg(ctx, "network", section, "ports");
                nc_uci_delete_pkg(ctx, "network", section, "slaves");
                for (i = 0; i < n; i++) {
                    const char *m = nc_json_string_at(members, i);
                    if (m && m[0]) {
                        nc_uci_add_list_pkg(ctx, "network", section, "ports", m);
                        nc_uci_add_list_pkg(ctx, "network", section, "slaves", m);
                    }
                }
                *device_out = bond_name;
            }
bond_done:
            if (members) json_object_put(members);
        }
        sqlite3_finalize(st);
    }
}

static int nc_prefix_to_netmask(int prefix, char *out, size_t out_len)
{
    uint32_t mask;
    struct in_addr a;
    if (!out || out_len == 0) return -1;
    if (prefix < 0) prefix = 0;
    if (prefix > 32) prefix = 32;
    mask = prefix == 0 ? 0 : (0xFFFFFFFFU << (32 - prefix));
    a.s_addr = htonl(mask);
    snprintf(out, out_len, "%s", inet_ntoa(a));
    return 0;
}

static int nc_get_wan_device(const char *wan_id, char *out, size_t out_len)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (!wan_id || !out || out_len == 0) return -1;
    out[0] = '\0';
    if (nc_prepare(&st, "SELECT device FROM wan WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *d = (const char *)sqlite3_column_text(st, 0);
            if (d && d[0]) { snprintf(out, out_len, "%s", d); rc = 0; }
        }
        sqlite3_finalize(st);
    }
    return rc;
}

static int nc_wan_pppoe_multi_enabled(const char *wan_id, int *timeout_out)
{
    sqlite3_stmt *st = NULL;
    int enabled = 0;
    if (timeout_out) *timeout_out = 5;
    if (!wan_id) return 0;
    if (nc_prepare(&st, "SELECT pppoe_multi_json FROM wan WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *raw = (const char *)sqlite3_column_text(st, 0);
            struct json_object *o = raw ? json_tokener_parse(raw) : NULL;
            if (o && json_object_is_type(o, json_type_object)) {
                enabled = nc_json_bool(o, "enabled", 0);
                if (timeout_out) {
                    int t = nc_json_int(o, "sync_timeout", nc_json_int(o, "syncppp_timeout", nc_json_int(o, "check_interval_min", 5)));
                    *timeout_out = t > 0 ? t : 5;
                }
            }
            if (o) json_object_put(o);
        }
        sqlite3_finalize(st);
    }
    return enabled;
}

static int nc_wan_enabled_pppoe_line_count(const char *wan_id)
{
    sqlite3_stmt *st = NULL;
    int count = 0;
    if (!wan_id) return 0;
    if (nc_prepare(&st,
        "SELECT COUNT(*) FROM hybrid_line WHERE parent_wan_id=?1 AND enabled=1 AND proto='pppoe'") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return count;
}

/* ══════════════════════════════════════════════════════════════════════
 * wan_dns_policy: per-WAN DNS strategy
 * ══════════════════════════════════════════════════════════════════════ */

static int nc_wan_dns_policy_wan_exists(const char *wan_id);

struct json_object *jmx_wan_dns_policy_get(const char *wan_id)
{
    struct json_object *data = json_object_new_object();
    struct json_object *arr = json_object_new_array();
    sqlite3_stmt *st = NULL;

    if (jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "error", json_object_new_string("storage_error"));
        json_object_object_add(data, "wan_id", json_object_new_string(wan_id ? wan_id : ""));
        json_object_object_add(data, "policies", arr);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (!nc_wan_dns_policy_wan_exists(wan_id)) {
        json_object_object_add(data, "error", json_object_new_string("wan_dns_policy_not_found"));
        json_object_object_add(data, "wan_id", json_object_new_string(wan_id ? wan_id : ""));
        json_object_object_add(data, "policies", arr);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    if (nc_prepare(&st,
        "SELECT id,wan_id,upstream_id,mode,dns_servers,domains,enabled,sort_order,updated_at "
        "FROM wan_dns_policy WHERE wan_id=?1 ORDER BY sort_order,id") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            struct json_object *o = json_object_new_object();
            json_object_object_add(o, "id", json_object_new_int(sqlite3_column_int(st, 0)));
            nc_add_text(o, "wan_id", st, 1);
            nc_add_text(o, "upstream_id", st, 2);
            nc_add_text(o, "mode", st, 3);
            {
                const char *sv = (const char *)sqlite3_column_text(st, 4);
                struct json_object *a = sv ? json_tokener_parse(sv) : json_object_new_array();
                if (!a || !json_object_is_type(a, json_type_array)) a = json_object_new_array();
                json_object_object_add(o, "dns_servers", a);
            }
            {
                const char *dv = (const char *)sqlite3_column_text(st, 5);
                struct json_object *a = dv ? json_tokener_parse(dv) : json_object_new_array();
                if (!a || !json_object_is_type(a, json_type_array)) a = json_object_new_array();
                json_object_object_add(o, "domains", a);
            }
            json_object_object_add(o, "enabled", json_object_new_boolean(sqlite3_column_int(st, 6)));
            json_object_object_add(o, "sort_order", json_object_new_int(sqlite3_column_int(st, 7)));
            json_object_object_add(o, "updated_at", json_object_new_int64(sqlite3_column_int64(st, 8)));
            json_object_array_add(arr, o);
        }
        sqlite3_finalize(st);
    }
done:
    json_object_object_add(data, "wan_id", json_object_new_string(wan_id ? wan_id : ""));
    json_object_object_add(data, "policies", arr);
    {
        struct json_object *caps = json_object_new_object();
        json_object_object_add(caps, "read_by_wan", json_object_new_boolean(1));
        json_object_object_add(caps, "read_all", json_object_new_boolean(0));
        json_object_object_add(caps, "service_update", json_object_new_boolean(1));
        json_object_object_add(caps, "apply_readback", json_object_new_boolean(1));
		json_object_object_add(caps, "domains", json_object_new_boolean(1));
		json_object_object_add(caps, "domain_split_ipv4", json_object_new_boolean(1));
		json_object_object_add(caps, "domain_split_ipv6", json_object_new_boolean(0));
		json_object_object_add(caps, "domain_split_runtime", json_object_new_string("dnsmasq_nftset+routed_fwmark"));
        json_object_object_add(data, "capabilities", caps);
    }
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static int nc_wan_dns_policy_wan_exists(const char *wan_id)
{
    sqlite3_stmt *st = NULL;
    int exists = 0;

    if (!wan_id || !nc_uci_section_name_ok(wan_id))
        return 0;
    if (nc_prepare(&st, "SELECT 1 FROM wan WHERE id=?1 LIMIT 1") != 0)
        return 0;
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists;
}

static int nc_wan_dns_domain_owned_elsewhere(const char *wan_id, const char *domain)
{
	sqlite3_stmt *st = NULL;
	int owned = 0;

	if (!wan_id || !domain || !domain[0] ||
	    nc_prepare(&st, "SELECT domains FROM wan_dns_policy WHERE wan_id<>?1 AND enabled=1") != 0)
		return 0;
	sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
	while (!owned && sqlite3_step(st) == SQLITE_ROW) {
		const char *raw = (const char *)sqlite3_column_text(st, 0);
		struct json_object *domains = raw ? json_tokener_parse(raw) : NULL;
		int i;
		if (!domains || !json_object_is_type(domains, json_type_array)) {
			if (domains) json_object_put(domains);
			continue;
		}
		for (i = 0; i < (int)json_object_array_length(domains); i++)
			if (!strcasecmp(domain, json_object_get_string(json_object_array_get_idx(domains, i)))) {
				owned = 1;
				break;
			}
		json_object_put(domains);
	}
	sqlite3_finalize(st);
	return owned;
}

static int nc_wan_dns_policy_validate(const char *wan_id, struct json_object *cfg)
{
    struct json_object *arr = NULL;
    int i, n;
	sqlite3_stmt *route_st = NULL;
	int route_wan_ready = 0;

    if (!wan_id || !cfg || !json_object_is_type(cfg, json_type_object) ||
        !nc_wan_dns_policy_wan_exists(wan_id))
        return -2;
    if (!json_object_object_get_ex(cfg, "policies", &arr) || !arr ||
        !json_object_is_type(arr, json_type_array) ||
        json_object_array_length(arr) > 64)
        return -2;
    n = (int)json_object_array_length(arr);
	if (nc_prepare(&route_st,
		"SELECT 1 FROM route_wan WHERE name=?1 AND fwmark>0 AND table_id>0 LIMIT 1") == 0) {
		sqlite3_bind_text(route_st, 1, wan_id, -1, SQLITE_TRANSIENT);
		route_wan_ready = sqlite3_step(route_st) == SQLITE_ROW;
		sqlite3_finalize(route_st);
	}
    for (i = 0; i < n; i++) {
        struct json_object *o = json_object_array_get_idx(arr, i);
        struct json_object *servers = NULL;
        struct json_object *domains = NULL;
        const char *mode;
        int j, count, domain_count = 0;

        if (!o || !json_object_is_type(o, json_type_object))
            return -2;
        mode = nc_json_str_def(o, "mode", "auto");
        if (strcmp(mode, "auto") && strcmp(mode, "upstream") &&
            strcmp(mode, "custom") && strcmp(mode, "disabled"))
            return -2;
        if (json_object_object_get_ex(o, "domains", &domains) && domains) {
			int k;
			if (!json_object_is_type(domains, json_type_array) ||
			    json_object_array_length(domains) > 128)
				return -2;
			domain_count = (int)json_object_array_length(domains);
			if (domain_count && !route_wan_ready)
				return -3;
			if (domain_count && strcmp(mode, "custom") && strcmp(mode, "upstream"))
				return -2;
			for (k = 0; k < domain_count; k++) {
				const char *domain = json_object_get_string(json_object_array_get_idx(domains, k));
				struct json_object *rule;
				if (!domain || !domain[0]) return -2;
				if (nc_wan_dns_domain_owned_elsewhere(wan_id, domain)) return -2;
				rule = json_object_new_object();
				json_object_object_add(rule, "domain", json_object_new_string(domain));
				json_object_object_add(rule, "type", json_object_new_string("block"));
				if (!nc_dns_valid_domain_rule(rule)) {
					json_object_put(rule);
					return -2;
				}
				json_object_put(rule);
				for (j = 0; j < k; j++)
					if (!strcasecmp(domain, json_object_get_string(
						json_object_array_get_idx(domains, j))))
						return -2;
				for (j = 0; j < i; j++) {
					struct json_object *prev = json_object_array_get_idx(arr, j);
					struct json_object *prev_domains = NULL;
					int p;
					if (!json_object_object_get_ex(prev, "domains", &prev_domains) ||
					    !json_object_is_type(prev_domains, json_type_array)) continue;
					for (p = 0; p < (int)json_object_array_length(prev_domains); p++)
						if (!strcasecmp(domain, json_object_get_string(
							json_object_array_get_idx(prev_domains, p))))
							return -2;
				}
			}
        }
        if (json_object_object_get_ex(o, "dns_servers", &servers) && servers) {
            if (!json_object_is_type(servers, json_type_array) ||
                json_object_array_length(servers) > 8)
                return -2;
            count = (int)json_object_array_length(servers);
            for (j = 0; j < count; j++) {
                const char *server = json_object_get_string(json_object_array_get_idx(servers, j));
                if (!server || !nc_dns_is_ip_literal(server) ||
                    (domain_count && !nc_dns_is_ipv4_literal(server)))
                    return -2;
            }
        }
        if (!strcmp(mode, "custom") &&
            (!servers || json_object_array_length(servers) == 0))
            return -2;
        if (!strcmp(mode, "upstream")) {
            const char *upstream_id = nc_json_str_def(o, "upstream_id", "");
            sqlite3_stmt *st = NULL;
            int supported = 0;
            if (!upstream_id[0] || !nc_valid_name(upstream_id) ||
                nc_prepare(&st, "SELECT address FROM dns_upstream WHERE id=?1 AND enabled=1 "
                                "AND protocol IN ('udp','tcp') LIMIT 1") != 0)
                return -2;
            sqlite3_bind_text(st, 1, upstream_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) == SQLITE_ROW) {
                const char *address = (const char *)sqlite3_column_text(st, 0);
                supported = !domain_count || nc_dns_is_ipv4_literal(address);
            }
            sqlite3_finalize(st);
            if (!supported)
                return -4;
        }
    }
    return 0;
}

#define NC_DNS_ROUTE_BEGIN "# BEGIN DREAMINGWRT DNS DOMAIN ROUTE"
#define NC_DNS_ROUTE_END   "# END DREAMINGWRT DNS DOMAIN ROUTE"

static int nc_dns_route_wan_runtime(const char *wan_id, unsigned *route_id,
				    unsigned *fwmark, unsigned *table_id,
				    char *l3_device, size_t l3_len)
{
	sqlite3_stmt *st = NULL;
	FILE *fp = NULL;
	char command[256], line[8192];
	struct json_object *root = NULL, *value = NULL;
	int rc = -1;

	if (!wan_id || !route_id || !fwmark || !table_id || !l3_device || !l3_len)
		return -1;
	/*
	 * wan_id is pasted into a popen() shell command below, so a name holding
	 * ; | ` $() or whitespace would execute. The routed writer now rejects
	 * such names, but this check is kept independent of it: a row written by
	 * an older build, or any future writer that forgets to validate, must not
	 * turn into command execution here.
	 */
	if (!nc_valid_name(wan_id))
		return -1;
	l3_device[0] = '\0';
	if (nc_prepare(&st, "SELECT id,fwmark,table_id FROM route_wan WHERE name=?1") != 0)
		return -1;
	sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(st) == SQLITE_ROW) {
		*route_id = (unsigned)sqlite3_column_int(st, 0);
		*fwmark = (unsigned)sqlite3_column_int64(st, 1);
		*table_id = (unsigned)sqlite3_column_int(st, 2);
	}
	sqlite3_finalize(st);
	if (!*route_id || !*fwmark || !*table_id)
		return -1;
	snprintf(command, sizeof(command), "ubus -S call network.interface.%s status 2>/dev/null", wan_id);
	fp = popen(command, "r");
	if (fp && fgets(line, sizeof(line), fp))
		root = json_tokener_parse(line);
	if (fp) pclose(fp);
	if (root && json_object_object_get_ex(root, "l3_device", &value) && value) {
		const char *device = json_object_get_string(value);
		if (device && if_nametoindex(device) > 0) {
			snprintf(l3_device, l3_len, "%s", device);
			rc = 0;
		}
	}
	if (root) json_object_put(root);
	return rc;
}

static int nc_dns_route_append_domains(char **text, size_t *len, size_t *cap,
				       struct json_object *domains,
				       const char *server, int port,
				       const char *l3_device)
{
	int i, n;

	if (!domains || !json_object_is_type(domains, json_type_array) ||
	    !server || !server[0] || !l3_device || !l3_device[0])
		return -1;
	n = (int)json_object_array_length(domains);
	for (i = 0; i < n; i++) {
		const char *domain = json_object_get_string(json_object_array_get_idx(domains, i));
		if (!domain || !domain[0] || nc_dhcp_access_append(text, len, cap,
			"server=/%s/%s%s%d@%s\n", domain, server,
			port > 0 ? "#" : "", port > 0 ? port : 53, l3_device) != 0)
			return -1;
	}
	return 0;
}

static int nc_dns_route_apply(void)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_section *dnsmasq;
	struct uci_ptr ptr = {0};
	sqlite3_stmt *st = NULL;
	char *block = NULL, *merged = NULL;
	size_t len = 0, cap = 0, prefix_len, suffix_len, block_len, total;
	const char *current, *begin, *end, *suffix;
	int rc = -1, route_count = 0;

	ctx = uci_alloc_context();
	if (!ctx || uci_load(ctx, "dhcp", &pkg) != UCI_OK || !pkg)
		goto done;
	nc_uci_delete_managed_sections(ctx, pkg, "dhcp", "ipset", "dw_dns_");
	if (nc_prepare(&st,
		"SELECT id,wan_id,upstream_id,mode,dns_servers,domains FROM wan_dns_policy "
		"WHERE enabled=1 AND domains NOT IN ('','[]') ORDER BY wan_id,sort_order,id") != 0)
		goto done;
	while (sqlite3_step(st) == SQLITE_ROW) {
		int policy_id = sqlite3_column_int(st, 0);
		const char *wan_id = (const char *)sqlite3_column_text(st, 1);
		const char *upstream_id = (const char *)sqlite3_column_text(st, 2);
		const char *mode = (const char *)sqlite3_column_text(st, 3);
		const char *servers_json = (const char *)sqlite3_column_text(st, 4);
		const char *domains_json = (const char *)sqlite3_column_text(st, 5);
		struct json_object *servers = NULL, *domains = NULL;
		unsigned route_id = 0, fwmark = 0, table_id = 0;
		char l3_device[IFNAMSIZ] = "", section[64], set_name[64];
		int i, server_count = 0;

		if (nc_dns_route_wan_runtime(wan_id, &route_id, &fwmark, &table_id,
					     l3_device, sizeof(l3_device)) != 0)
			goto done;
		domains = domains_json ? json_tokener_parse(domains_json) : NULL;
		if (!domains || !json_object_is_type(domains, json_type_array)) {
			if (domains) json_object_put(domains);
			goto done;
		}
		if (route_count++ == 0 &&
		    nc_dhcp_access_append(&block, &len, &cap, "%s\n", NC_DNS_ROUTE_BEGIN) != 0) {
			json_object_put(domains);
			goto done;
		}
		snprintf(section, sizeof(section), "dw_dns_%u_%d", route_id, policy_id);
		snprintf(set_name, sizeof(set_name), "wan_%u_v4", route_id);
		if (nc_uci_ensure_section(ctx, pkg, "dhcp", section, "ipset") != 0 ||
		    nc_uci_set_pkg(ctx, "dhcp", section, "table_family", "inet") != 0 ||
		    nc_uci_set_pkg(ctx, "dhcp", section, "table", "dreamingwrt_dns_route") != 0 ||
		    nc_uci_set_pkg(ctx, "dhcp", section, "family", "4") != 0 ||
		    nc_uci_add_list_pkg(ctx, "dhcp", section, "name", set_name) != 0) {
			json_object_put(domains);
			goto done;
		}
		for (i = 0; i < (int)json_object_array_length(domains); i++) {
			const char *domain = json_object_get_string(json_object_array_get_idx(domains, i));
			if (!domain || nc_uci_add_list_pkg(ctx, "dhcp", section, "domain", domain) != 0) {
				json_object_put(domains);
				goto done;
			}
		}
		if (!strcmp(mode, "custom"))
			servers = servers_json ? json_tokener_parse(servers_json) : NULL;
		else if (!strcmp(mode, "upstream") && upstream_id && upstream_id[0]) {
			sqlite3_stmt *us = NULL;
			if (nc_prepare(&us, "SELECT address,port FROM dns_upstream WHERE id=?1 AND enabled=1 AND protocol IN ('udp','tcp')") == 0) {
				sqlite3_bind_text(us, 1, upstream_id, -1, SQLITE_TRANSIENT);
				if (sqlite3_step(us) == SQLITE_ROW) {
					servers = json_object_new_array();
					json_object_array_add(servers, json_object_new_string(
						(const char *)sqlite3_column_text(us, 0)));
					server_count = sqlite3_column_int(us, 1);
				}
				sqlite3_finalize(us);
			}
		} else {
			servers = json_object_new_array();
		}
		if (servers && json_object_is_type(servers, json_type_array)) {
			for (i = 0; i < (int)json_object_array_length(servers); i++) {
				const char *server = json_object_get_string(json_object_array_get_idx(servers, i));
				if (nc_dns_route_append_domains(&block, &len, &cap, domains, server,
							server_count > 0 ? server_count : 53, l3_device) != 0) {
					json_object_put(servers); json_object_put(domains); goto done;
				}
			}
		}
		if (servers) json_object_put(servers);
		json_object_put(domains);
	}
	sqlite3_finalize(st); st = NULL;
	if (route_count > 0) {
		if (nc_dhcp_access_append(&block, &len, &cap, "%s\n", NC_DNS_ROUTE_END) != 0)
			goto done;
	} else {
		block = calloc(1, 1);
		if (!block) goto done;
	}
	dnsmasq = nc_dhcp_dnsmasq_section(pkg);
	if (!dnsmasq) goto done;
	current = uci_lookup_option_string(ctx, dnsmasq, "extraconftext");
	if (!current) current = "";
	begin = strstr(current, NC_DNS_ROUTE_BEGIN);
	end = begin ? strstr(begin, NC_DNS_ROUTE_END) : NULL;
	if (begin && !end) goto done;
	prefix_len = begin ? (size_t)(begin - current) : strlen(current);
	suffix = end ? end + strlen(NC_DNS_ROUTE_END) : current + strlen(current);
	while (*suffix == '\r' || *suffix == '\n') suffix++;
	suffix_len = strlen(suffix); block_len = strlen(block);
	total = prefix_len + block_len + suffix_len + 3;
	merged = calloc(1, total);
	if (!merged) goto done;
	if (prefix_len) memcpy(merged, current, prefix_len);
	if (prefix_len && merged[strlen(merged) - 1] != '\n') strcat(merged, "\n");
	strcat(merged, block);
	if (suffix_len) { if (merged[strlen(merged) - 1] != '\n') strcat(merged, "\n"); strcat(merged, suffix); }
	ptr.p = pkg; ptr.s = dnsmasq; ptr.option = "extraconftext"; ptr.value = merged;
	if (uci_set(ctx, &ptr) != UCI_OK || jmx_uci_commit(ctx, "dhcp") != UCI_OK)
		goto done;
	rc = 0;
done:
	if (st) sqlite3_finalize(st);
	if (ctx) uci_free_context(ctx);
	free(block); free(merged);
	return rc;
}

static int nc_dnsmasq_wait_ready(void)
{
    sqlite3_stmt *st = NULL;
    int enabled = 1;
    int port = 53;

    if (jmx_netconfig_db_init() == 0 &&
        nc_prepare(&st, "SELECT enabled,listen_port FROM dns_service WHERE id=1") == 0) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            enabled = sqlite3_column_int(st, 0);
            port = sqlite3_column_int(st, 1);
        }
        sqlite3_finalize(st);
    }
    return !enabled || nc_dns_runtime_ready(port, 1) ? 0 : -1;
}

static int nc_dnsmasq_process_running(void)
{
    DIR *dir = opendir("/proc");
    struct dirent *entry;
    int running = 0;

    if (!dir)
        return 0;
    while ((entry = readdir(dir)) != NULL) {
        char path[64], comm[32] = "";
        FILE *fp;
        const char *p = entry->d_name;

        if (!p[0]) continue;
        while (*p && isdigit((unsigned char)*p)) p++;
        if (*p) continue;
        if ((size_t)snprintf(path, sizeof(path), "/proc/%s/comm",
                             entry->d_name) >= sizeof(path))
            continue;
        fp = fopen(path, "r");
        if (!fp) continue;
        if (fgets(comm, sizeof(comm), fp))
            comm[strcspn(comm, "\r\n")] = 0;
        fclose(fp);
        if (!strcmp(comm, "dnsmasq")) {
            running = 1;
            break;
        }
    }
    closedir(dir);
    return running;
}

static int nc_dns_query_ready(int port)
{
    static const unsigned char query_tail[] = {
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o',
        's', 't', 0x00, 0x00, 0x01, 0x00, 0x01
    };
    unsigned char query[sizeof(query_tail) + 2];
    unsigned char response[512];
    struct sockaddr_in address;
    struct pollfd pfd;
    uint16_t id;
    int fd, n;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    if (port < 1 || port > 65535)
        return 0;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    id = (uint16_t)(((unsigned)getpid() ^ (unsigned)time(NULL)) & 0xffffU);
    query[0] = (unsigned char)(id >> 8);
    query[1] = (unsigned char)(id & 0xff);
    memcpy(query + 2, query_tail, sizeof(query_tail));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    if (sendto(fd, query, sizeof(query), 0, (struct sockaddr *)&address,
               sizeof(address)) != (ssize_t)sizeof(query)) {
        close(fd);
        return 0;
    }
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 250) <= 0 || !(pfd.revents & POLLIN)) {
        close(fd);
        return 0;
    }
    n = (int)recv(fd, response, sizeof(response), 0);
    close(fd);
    return n >= 12 && response[0] == query[0] && response[1] == query[1] &&
           (response[2] & 0x80) != 0;
}

static int nc_dns_runtime_ready(int port, int wait_for_ready)
{
    struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
    int attempt, attempts = wait_for_ready ? 50 : 1;

    for (attempt = 0; attempt < attempts; attempt++) {
        if (nc_dnsmasq_process_running() && nc_dns_query_ready(port))
            return 1;
        if (attempt + 1 < attempts)
            nanosleep(&delay, NULL);
    }
    return 0;
}

static int nc_dnsmasq_restart_wait(const char *log_path)
{
    if (nc_dnsmasq_restart(log_path) != 0)
        return -1;
    return nc_dnsmasq_wait_ready();
}

static int nc_dnsmasq_restart(const char *log_path)
{
    char command[512];

    if (!log_path || !log_path[0])
        return -1;
    snprintf(command, sizeof(command),
             "/etc/init.d/dnsmasq restart >%s 2>&1", log_path);
    return nc_run_quiet(command);
}

int jmx_wan_dns_policy_set(const char *wan_id, struct json_object *cfg)
{
    sqlite3_stmt *st = NULL;
    struct json_object *arr = NULL;
    int i, n, rc = -1;
    int64_t ts = nc_now_s();

    if (!wan_id || !wan_id[0] || !cfg) return -2;
    if (jmx_netconfig_db_init() != 0) return -1;
    rc = nc_wan_dns_policy_validate(wan_id, cfg);
    if (rc != 0) return rc;

    if (nc_exec("BEGIN IMMEDIATE") != 0) return -1;

    /* Replace this WAN's complete ordered policy set. */
    if (nc_prepare(&st, "DELETE FROM wan_dns_policy WHERE wan_id=?1") != 0) {
        nc_exec("ROLLBACK");
        return -1;
    }
    sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    st = NULL;
    if (json_object_object_get_ex(cfg, "policies", &arr) && arr && json_object_is_type(arr, json_type_array)) {
        n = (int)json_object_array_length(arr);
        for (i = 0; i < n; i++) {
            struct json_object *o = json_object_array_get_idx(arr, i);
            const char *mode = nc_json_str(o, "mode", "auto");
            struct json_object *servers = NULL, *domains = NULL;

            /* validate mode */
            if (strcmp(mode, "auto") && strcmp(mode, "upstream") && strcmp(mode, "custom") && strcmp(mode, "disabled")) {
                rc = -1;
                break;
            }

            json_object_object_get_ex(o, "dns_servers", &servers);
            json_object_object_get_ex(o, "domains", &domains);

            if (nc_prepare(&st,
                "INSERT INTO wan_dns_policy(wan_id,upstream_id,mode,dns_servers,domains,sort_order,enabled,updated_at) "
                "VALUES(?1,?2,?3,?4,?5,?6,?7,?8)") == 0) {
                sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 2, nc_json_str(o, "upstream_id", ""), -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 3, mode, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 4, servers ? json_object_to_json_string(servers) : "[]", -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(st, 5, domains ? json_object_to_json_string(domains) : "[]", -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(st, 6, nc_json_int(o, "sort_order", i));
                sqlite3_bind_int(st, 7, nc_json_bool(o, "enabled", 1));
                sqlite3_bind_int64(st, 8, ts);
                if (nc_step_done(st) != 0) rc = -1;
                sqlite3_finalize(st);
            } else {
                rc = -1;
            }
            if (rc != 0) break;
        }
    }

    if (rc == 0 && nc_exec("COMMIT") != 0) rc = -1;
    if (rc != 0) nc_exec("ROLLBACK");
    return rc;
}

int jmx_wan_dns_policy_delete(int policy_id)
{
    sqlite3_stmt *st = NULL;
    int rc, changed;
    if (policy_id <= 0) return -2;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "DELETE FROM wan_dns_policy WHERE id=?1") != 0) return -1;
    sqlite3_bind_int(st, 1, policy_id);
    rc = nc_step_done(st);
    changed = sqlite3_changes(g_netconfig_db);
    sqlite3_finalize(st);
    return rc == 0 && changed == 1 ? 0 : (rc == 0 ? 1 : -1);
}

static struct json_object *nc_wan_dns_policy_result(const char *wan_id,
                                                     int saved, int applied,
                                                     int rolled_back,
                                                     const char *error)
{
    struct json_object *data = json_object_new_object();
    struct json_object *readback = jmx_wan_dns_policy_get(wan_id ? wan_id : "");
    struct json_object *readback_data = NULL;

    json_object_object_add(data, "ok", json_object_new_boolean(saved == 0 && applied == 0));
    json_object_object_add(data, "saved", json_object_new_boolean(saved == 0));
    json_object_object_add(data, "applied", json_object_new_boolean(saved == 0 && applied == 0));
    json_object_object_add(data, "runtime_rolled_back", json_object_new_boolean(rolled_back));
    json_object_object_add(data, "wan_id", json_object_new_string(wan_id ? wan_id : ""));
    json_object_object_add(data, "apply_state", json_object_new_string(
        error && strstr(error, "_unsupported") ? "unsupported" :
        error && strstr(error, "_not_found") ? "not_found" :
        saved == -2 ? "validation_failed" : saved != 0 ? "save_failed" :
        applied == 0 ? "applied" : "apply_failed_rolled_back"));
    if (error && error[0])
        json_object_object_add(data, "error", json_object_new_string(error));
    if (readback && json_object_object_get_ex(readback, "data", &readback_data) && readback_data)
        json_object_object_add(data, "readback", json_object_get(readback_data));
    if (readback) json_object_put(readback);
    return jmx_gen_api_response_data(saved == 0 && applied == 0 ? API_CODE_SUCCESS : API_CODE_ERROR,
                                     data);
}

static int nc_wan_dns_policies_need_wan_apply(struct json_object *policies)
{
    int i;

    if (!policies || !json_object_is_type(policies, json_type_array))
        return 0;
    for (i = 0; i < (int)json_object_array_length(policies); i++) {
        struct json_object *policy = json_object_array_get_idx(policies, i);
        struct json_object *domains = NULL;
        const char *mode;

        if (!policy || !json_object_is_type(policy, json_type_object) ||
            !nc_json_bool(policy, "enabled", 1))
            continue;
        mode = nc_json_str(policy, "mode", "auto");
        if (strcmp(mode, "custom") && strcmp(mode, "upstream"))
            continue;
        if (!json_object_object_get_ex(policy, "domains", &domains) || !domains ||
            !json_object_is_type(domains, json_type_array) ||
            json_object_array_length(domains) == 0)
            return 1;
    }
    return 0;
}

struct json_object *jmx_wan_dns_policy_save_apply_result(const char *wan_id,
                                                          struct json_object *cfg)
{
    struct json_object *before = NULL;
    struct json_object *before_data = NULL;
    struct json_object *before_policies = NULL;
    struct json_object *after_policies = NULL;
    struct json_object *restore = NULL;
    int saved, applied = -1, rolled_back = 0;
    int need_wan_apply = 0;
    const char *error = NULL;

    if (jmx_netconfig_db_init() != 0)
        return nc_wan_dns_policy_result(wan_id, -1, -1, 0,
                                         "wan_dns_policy_storage_error");
    before = jmx_wan_dns_policy_get(wan_id ? wan_id : "");
    if (before && json_object_object_get_ex(before, "data", &before_data) && before_data &&
        json_object_object_get_ex(before_data, "policies", &before_policies) && before_policies) {
        restore = json_object_new_object();
        json_object_object_add(restore, "policies", json_object_get(before_policies));
    }
    json_object_object_get_ex(cfg, "policies", &after_policies);
    need_wan_apply = nc_wan_dns_policies_need_wan_apply(before_policies) ||
                     nc_wan_dns_policies_need_wan_apply(after_policies);
    saved = jmx_wan_dns_policy_set(wan_id, cfg);
    if (saved == -3)
		error = "wan_dns_policy_route_wan_not_ready";
    else if (saved == -4)
        error = "wan_dns_policy_upstream_unsupported";
    else if (saved == -2)
        error = "wan_dns_policy_validation_failed";
    else if (saved != 0)
        error = "wan_dns_policy_save_failed";
    if (saved == 0) {
		applied = need_wan_apply ? jmx_netconfig_apply_wan(wan_id) : 0;
		if (applied == 0)
			applied = nc_dns_route_apply();
		if (applied == 0) {
			struct json_object *reload = jmx_api_route_reload(NULL);
			struct json_object *code = NULL;
			if (!reload || !json_object_object_get_ex(reload, "code", &code) ||
			    json_object_get_int(code) != API_CODE_SUCCESS)
				applied = -1;
			if (reload) json_object_put(reload);
		}
		if (applied == 0)
			applied = nc_dnsmasq_restart_wait("/tmp/dw-dns-route-reload.log");
        if (applied != 0) {
            error = "wan_dns_policy_apply_failed";
            if (restore && jmx_wan_dns_policy_set(wan_id, restore) == 0) {
				if (need_wan_apply) jmx_netconfig_apply_wan(wan_id);
				nc_dns_route_apply();
				{ struct json_object *reload = jmx_api_route_reload(NULL); if (reload) json_object_put(reload); }
				nc_dnsmasq_restart_wait("/tmp/dw-dns-route-rollback.log");
                rolled_back = 1;
            }
        }
    }
    if (restore) json_object_put(restore);
    if (before) json_object_put(before);
    return nc_wan_dns_policy_result(wan_id, saved, applied, rolled_back, error);
}

struct json_object *jmx_wan_dns_policy_delete_apply_result(int policy_id)
{
    sqlite3_stmt *st = NULL;
    char wan_id[128] = "";
    struct json_object *before = NULL;
    struct json_object *before_data = NULL;
    struct json_object *before_policies = NULL;
    struct json_object *restore = NULL;
    int saved = -1, applied = -1, rolled_back = 0;
    int need_wan_apply = 0;
    const char *error = NULL;

    if (policy_id <= 0 || jmx_netconfig_db_init() != 0)
        return nc_wan_dns_policy_result("", -2, -1, 0,
                                         "wan_dns_policy_validation_failed");
    if (nc_prepare(&st, "SELECT wan_id FROM wan_dns_policy WHERE id=?1") == 0) {
        sqlite3_bind_int(st, 1, policy_id);
        if (sqlite3_step(st) == SQLITE_ROW)
            snprintf(wan_id, sizeof(wan_id), "%s", (const char *)sqlite3_column_text(st, 0));
        sqlite3_finalize(st);
    }
    if (!wan_id[0])
        return nc_wan_dns_policy_result("", 1, -1, 0,
                                         "wan_dns_policy_not_found");
    before = jmx_wan_dns_policy_get(wan_id);
    if (before && json_object_object_get_ex(before, "data", &before_data) && before_data &&
        json_object_object_get_ex(before_data, "policies", &before_policies) && before_policies) {
        restore = json_object_new_object();
        json_object_object_add(restore, "policies", json_object_get(before_policies));
    }
    need_wan_apply = nc_wan_dns_policies_need_wan_apply(before_policies);
    saved = jmx_wan_dns_policy_delete(policy_id);
    if (saved != 0)
        error = "wan_dns_policy_delete_failed";
    if (saved == 0) {
		applied = need_wan_apply ? jmx_netconfig_apply_wan(wan_id) : 0;
		if (applied == 0)
			applied = nc_dns_route_apply();
		if (applied == 0) {
			struct json_object *reload = jmx_api_route_reload(NULL);
			struct json_object *code = NULL;
			if (!reload || !json_object_object_get_ex(reload, "code", &code) ||
			    json_object_get_int(code) != API_CODE_SUCCESS)
				applied = -1;
			if (reload) json_object_put(reload);
		}
		if (applied == 0)
			applied = nc_dnsmasq_restart_wait("/tmp/dw-dns-route-reload.log");
        if (applied != 0) {
            error = "wan_dns_policy_apply_failed";
            if (restore && jmx_wan_dns_policy_set(wan_id, restore) == 0) {
				if (need_wan_apply) jmx_netconfig_apply_wan(wan_id);
				nc_dns_route_apply();
				{ struct json_object *reload = jmx_api_route_reload(NULL); if (reload) json_object_put(reload); }
				nc_dnsmasq_restart_wait("/tmp/dw-dns-route-rollback.log");
                rolled_back = 1;
            }
        }
    }
    if (restore) json_object_put(restore);
    if (before) json_object_put(before);
    return nc_wan_dns_policy_result(wan_id, saved, applied, rolled_back, error);
}

static const char *nc_dns_split_mode_to_policy(const char *mode)
{
    if (!mode) return "disabled";
    if (!strcmp(mode, "custom")) return "custom";
    if (!strcmp(mode, "disabled")) return "disabled";
    return "auto";
}

int jmx_wan_dns_split_save_from_array(struct json_object *wan_dns_arr)
{
    sqlite3_stmt *st = NULL;
    int i, n, rc = -1;
    int64_t ts = nc_now_s();
    if (!wan_dns_arr || !json_object_is_type(wan_dns_arr, json_type_array)) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_exec("BEGIN IMMEDIATE") != 0) return -1;
    /* The aggregate DNS endpoint owns only whole-WAN DNS rows. Domain-scoped
     * policies belong to /services/dns/wan-policy and must survive wan_dns=[]. */
    if (nc_prepare(&st,
        "DELETE FROM wan_dns_policy WHERE domains IS NULL OR domains='' OR domains='[]'") != 0) {
        nc_exec("ROLLBACK");
        return -1;
    }
    rc = nc_step_done(st);
    sqlite3_finalize(st);
    st = NULL;
    n = (int)json_object_array_length(wan_dns_arr);
    for (i = 0; i < n; i++) {
        struct json_object *o = json_object_array_get_idx(wan_dns_arr, i);
        const char *wan_id = nc_json_str(o, "wan_id", nc_json_str(o, "id", ""));
        const char *mode = nc_dns_split_mode_to_policy(nc_json_str(o, "mode", "default"));
        if (!wan_id[0]) continue;
        if (nc_prepare(&st,
            "INSERT INTO wan_dns_policy(wan_id,upstream_id,mode,dns_servers,domains,sort_order,enabled,updated_at) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8)") == 0) {
            sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, nc_json_str(o, "template", ""), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, mode, -1, SQLITE_TRANSIENT);
            struct json_object *servers = json_object_new_array();
            const char *p = nc_json_str(o, "primary", "");
            const char *s = nc_json_str(o, "secondary", "");
            if (p[0]) json_object_array_add(servers, json_object_new_string(p));
            if (s[0]) json_object_array_add(servers, json_object_new_string(s));
            sqlite3_bind_text(st, 4, json_object_to_json_string(servers), -1, SQLITE_TRANSIENT);
            json_object_put(servers);
            sqlite3_bind_text(st, 5, "[]", -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 6, i);
            sqlite3_bind_int(st, 7, nc_json_bool(o, "enabled", 1));
            sqlite3_bind_int64(st, 8, ts);
            if (nc_step_done(st) != 0) rc = -1;
            sqlite3_finalize(st);
        } else {
            rc = -1;
        }
        if (rc != 0) break;
    }
    if (rc == 0 && nc_exec("COMMIT") != 0) rc = -1;
    if (rc != 0) nc_exec("ROLLBACK");
    return rc;
}

static int nc_apply_wan_dns_policy(struct uci_context *ctx, const char *wan_id)
{
    sqlite3_stmt *st = NULL;
    int rc = 0;
    int override_dns = 0;

    if (nc_prepare(&st,
        "SELECT upstream_id,mode,dns_servers,domains FROM wan_dns_policy "
        "WHERE wan_id=?1 AND enabled=1 ORDER BY sort_order,id") != 0)
        return -1;
    {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *upstream_id = (const char *)sqlite3_column_text(st, 0);
            const char *mode = (const char *)sqlite3_column_text(st, 1);
            const char *dns_servers_json = (const char *)sqlite3_column_text(st, 2);
            const char *domains_json = (const char *)sqlite3_column_text(st, 3);
            struct json_object *domains = domains_json ? json_tokener_parse(domains_json) : NULL;
            int domain_scoped = domains && json_object_is_type(domains, json_type_array) &&
                                json_object_array_length(domains) > 0;

            if (domains) json_object_put(domains);
            if (domain_scoped)
                continue;

            if ((!strcmp(mode, "custom") || !strcmp(mode, "upstream")) && !override_dns) {
                if (nc_uci_delete_pkg(ctx, "network", wan_id, "dns") != 0 ||
                    nc_uci_set_pkg(ctx, "network", wan_id, "peerdns", "0") != 0) {
                    rc = -1;
                    break;
                }
                override_dns = 1;
            }
            if (!strcmp(mode, "custom") && dns_servers_json) {
                struct json_object *arr = json_tokener_parse(dns_servers_json);
                if (arr && json_object_is_type(arr, json_type_array)) {
                    int i, n = (int)json_object_array_length(arr);
                    for (i = 0; i < n; i++) {
                        const char *d = json_object_get_string(json_object_array_get_idx(arr, i));
                        if (d && d[0] &&
                            nc_uci_add_list_pkg(ctx, "network", wan_id, "dns", d) != 0) {
                            rc = -1;
                            break;
                        }
                    }
                }
                if (arr) json_object_put(arr);
                if (rc != 0) break;
            }
            if (!strcmp(mode, "upstream") && upstream_id[0]) {
                sqlite3_stmt *us = NULL;
                if (nc_prepare(&us, "SELECT address FROM dns_upstream WHERE id=?1 AND enabled=1 "
                                    "AND protocol IN ('udp','tcp')") == 0) {
                    sqlite3_bind_text(us, 1, upstream_id, -1, SQLITE_TRANSIENT);
                    if (sqlite3_step(us) == SQLITE_ROW) {
                        const char *addr = (const char *)sqlite3_column_text(us, 0);
                        if (!addr || !addr[0] ||
                            nc_uci_add_list_pkg(ctx, "network", wan_id, "dns", addr) != 0)
                            rc = -1;
                    } else {
                        rc = -1;
                    }
                    sqlite3_finalize(us);
                } else {
                    rc = -1;
                }
                if (rc != 0) break;
            }
        }
        sqlite3_finalize(st);
    }
    return rc;
}

static int nc_apply_wan_dns(struct uci_context *ctx, const char *wan_id)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (nc_prepare(&st, "SELECT dns_json FROM wan WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *dns_json = (const char *)sqlite3_column_text(st, 0);
            struct json_object *arr = dns_json ? json_tokener_parse(dns_json) : NULL;
            int i, n;
            if (nc_uci_delete_pkg(ctx, "network", wan_id, "dns") != 0 ||
                nc_uci_delete_pkg(ctx, "network", wan_id, "peerdns") != 0) {
                if (arr) json_object_put(arr);
                sqlite3_finalize(st);
                return -1;
            }
            rc = 0;
            if (arr && json_object_is_type(arr, json_type_array)) {
                n = (int)json_object_array_length(arr);
                for (i = 0; i < n; i++) {
                    const char *d = json_object_get_string(json_object_array_get_idx(arr, i));
                    if (d && d[0] &&
                        nc_uci_add_list_pkg(ctx, "network", wan_id, "dns", d) != 0) {
                        rc = -1;
                        break;
                    }
                }
                if (rc == 0 && n > 0)
                    rc = nc_uci_set_pkg(ctx, "network", wan_id, "peerdns", "0");
            }
            if (arr) json_object_put(arr);
        }
        sqlite3_finalize(st);
    }
    return rc;
}

static void nc_apply_wan_advanced(struct uci_context *ctx, const char *wan_id, const char *access_mode)
{
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st,
        "SELECT dhcp_hostname,dhcp_vendor_class,dhcp_client_id,"
        "pppoe_ac,pppoe_ac_mac,pppoe_service,"
        "health_enabled,health_mode,health_targets_json,failover "
        "FROM wan_advanced WHERE wan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, wan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            const char *dhcp_hostname = (const char *)sqlite3_column_text(st, 0);
            const char *dhcp_vendor = (const char *)sqlite3_column_text(st, 1);
            const char *dhcp_client_id = (const char *)sqlite3_column_text(st, 2);
            const char *pppoe_ac = (const char *)sqlite3_column_text(st, 3);
            const char *pppoe_ac_mac = (const char *)sqlite3_column_text(st, 4);
            const char *pppoe_service = (const char *)sqlite3_column_text(st, 5);
            int health_enabled = sqlite3_column_int(st, 6);
            const char *health_mode = (const char *)sqlite3_column_text(st, 7);
            const char *targets_text = (const char *)sqlite3_column_text(st, 8);
            int failover = sqlite3_column_int(st, 9);
            struct json_object *targets = NULL;
            const char *ping_target = "";
            const char *http_url = "";
            char enabled_text[2] = { health_enabled ? '1' : '0', '\0' };
            char failover_text[2] = { failover ? '1' : '0', '\0' };

            if (targets_text && targets_text[0])
                targets = json_tokener_parse(targets_text);
            if (targets && json_object_is_type(targets, json_type_object)) {
                ping_target = nc_json_str(targets, "ping", "");
                http_url = nc_json_str(targets, "http", "");
            } else if (targets && json_object_is_type(targets, json_type_array) &&
                       json_object_array_length(targets) > 0) {
                ping_target = json_object_get_string(json_object_array_get_idx(targets, 0));
            }
            nc_uci_set_pkg(ctx, "network", wan_id, "check_enable", enabled_text);
            nc_uci_set_pkg(ctx, "network", wan_id, "failover", failover_text);
            nc_uci_set_pkg(ctx, "network", wan_id, "health_mode",
                           health_mode && health_mode[0] ? health_mode : "http_ping_gateway");
            if (ping_target && ping_target[0])
                nc_uci_set_pkg(ctx, "network", wan_id, "check_host", ping_target);
            else
                nc_uci_delete_pkg(ctx, "network", wan_id, "check_host");
            if (http_url && http_url[0])
                nc_uci_set_pkg(ctx, "network", wan_id, "check_url", http_url);
            else
                nc_uci_delete_pkg(ctx, "network", wan_id, "check_url");
            if (targets) json_object_put(targets);
            if (access_mode && strcmp(access_mode, "dhcp") == 0) {
                if (dhcp_hostname && dhcp_hostname[0]) nc_uci_set_pkg(ctx, "network", wan_id, "hostname", dhcp_hostname);
                if (dhcp_vendor && dhcp_vendor[0]) nc_uci_set_pkg(ctx, "network", wan_id, "vendorid", dhcp_vendor);
                if (dhcp_client_id && dhcp_client_id[0]) nc_uci_set_pkg(ctx, "network", wan_id, "clientid", dhcp_client_id);
            } else if (access_mode && strcmp(access_mode, "pppoe") == 0) {
                if (pppoe_ac && pppoe_ac[0]) nc_uci_set_pkg(ctx, "network", wan_id, "ac", pppoe_ac);
                if (pppoe_service && pppoe_service[0]) nc_uci_set_pkg(ctx, "network", wan_id, "service", pppoe_service);
                if (pppoe_ac_mac && pppoe_ac_mac[0]) nc_uci_set_pkg(ctx, "network", wan_id, "pppoe_ac_mac", pppoe_ac_mac);
            }
        }
        sqlite3_finalize(st);
    }
}

int jmx_netconfig_apply_hybrid_line(const char *id)
{
    sqlite3_stmt *st = NULL;
    struct uci_context *uctx = NULL;
    struct uci_package *netpkg = NULL;
    int rc = -1;
    char bak_network[256] = {0};
    const char *parent, *name, *mode, *vlan_id, *mac, *proto, *ip, *gateway, *username, *password_ref, *pppoe_ac, *pppoe_ac_mac, *pppoe_service;
    int enabled, prefix, mtu, mru;
    char parent_dev[64], dev[64], netmask[32];

    if (!id || !id[0]) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "SELECT parent_wan_id,name,mode,vlan_id,mac,proto,enabled,ip,prefix,gateway,username,password_ref,pppoe_ac,pppoe_ac_mac,pppoe_service,mtu,mru FROM hybrid_line WHERE id=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    parent = (const char *)sqlite3_column_text(st, 0);
    name = (const char *)sqlite3_column_text(st, 1);
    mode = (const char *)sqlite3_column_text(st, 2);
    vlan_id = (const char *)sqlite3_column_text(st, 3);
    mac = (const char *)sqlite3_column_text(st, 4);
    proto = (const char *)sqlite3_column_text(st, 5);
    enabled = sqlite3_column_int(st, 6);
    ip = (const char *)sqlite3_column_text(st, 7);
    prefix = sqlite3_column_int(st, 8);
    gateway = (const char *)sqlite3_column_text(st, 9);
    username = (const char *)sqlite3_column_text(st, 10);
    password_ref = (const char *)sqlite3_column_text(st, 11);
    pppoe_ac = (const char *)sqlite3_column_text(st, 12);
    pppoe_ac_mac = (const char *)sqlite3_column_text(st, 13);
    pppoe_service = (const char *)sqlite3_column_text(st, 14);
    mtu = sqlite3_column_int(st, 15);
    mru = sqlite3_column_int(st, 16);
    if (!enabled) { sqlite3_finalize(st); return 0; }
    if (nc_get_wan_device(parent, parent_dev, sizeof(parent_dev)) != 0) snprintf(parent_dev, sizeof(parent_dev), "%s", parent ? parent : "");
    if (mode && strcmp(mode, "hybrid_vlan") == 0 && vlan_id && vlan_id[0]) snprintf(dev, sizeof(dev), "%s.%s", parent_dev, vlan_id);
    else snprintf(dev, sizeof(dev), "mv-%s", name && name[0] ? name : id);

    nc_backup_config("network", bak_network, sizeof(bak_network));
    uctx = uci_alloc_context();
    if (!uctx) goto done;
    if (uci_load(uctx, "network", &netpkg) != UCI_OK) goto done;

    if (mode && strcmp(mode, "hybrid_vlan") == 0) {
        const char *section = NULL;
        if (nc_uci_ensure_network_device(uctx, netpkg, dev, &section) != 0) goto done;
        nc_uci_set_pkg(uctx, "network", section, "type", "8021q");
        if (parent_dev[0]) nc_uci_set_pkg(uctx, "network", section, "ifname", parent_dev);
        if (vlan_id && vlan_id[0]) nc_uci_set_pkg(uctx, "network", section, "vid", vlan_id);
    } else {
        const char *section = NULL;
        if (nc_uci_ensure_network_device(uctx, netpkg, dev, &section) != 0) goto done;
        nc_uci_set_pkg(uctx, "network", section, "type", "macvlan");
        if (parent_dev[0]) nc_uci_set_pkg(uctx, "network", section, "ifname", parent_dev);
        nc_uci_set_pkg(uctx, "network", section, "mode", "bridge");
        if (mac && mac[0]) nc_uci_set_pkg(uctx, "network", section, "macaddr", mac);
    }

    if (nc_uci_ensure_section(uctx, netpkg, "network", id, "interface") != 0) goto done;
    nc_uci_set_pkg(uctx, "network", id, "device", dev);
    nc_uci_set_pkg(uctx, "network", id, "proto", proto && proto[0] ? proto : "dhcp");
    if (gateway && gateway[0]) nc_uci_set_pkg(uctx, "network", id, "gateway", gateway);
    if (proto && strcmp(proto, "pppoe") == 0) {
        nc_uci_delete_pkg(uctx, "network", id, "mtu");
        nc_uci_delete_pkg(uctx, "network", id, "mru");
    } else if (mtu > 0) {
        char b[16]; snprintf(b, sizeof(b), "%d", mtu); nc_uci_set_pkg(uctx, "network", id, "mtu", b);
    }
    if (proto && strcmp(proto, "static") == 0 && ip && ip[0]) {
        nc_uci_delete_pkg(uctx, "network", id, "ipaddr");
        nc_uci_add_list_pkg(uctx, "network", id, "ipaddr", ip);
        nc_prefix_to_netmask(prefix, netmask, sizeof(netmask));
        nc_uci_set_pkg(uctx, "network", id, "netmask", netmask);
    }
    if (proto && strcmp(proto, "pppoe") == 0) {
        int sync_timeout = 5;
        int sync_count = nc_wan_pppoe_multi_enabled(parent, &sync_timeout) ? nc_wan_enabled_pppoe_line_count(parent) : 0;
        if (username && username[0]) nc_uci_set_pkg(uctx, "network", id, "username", username);
        if (password_ref && password_ref[0]) nc_uci_set_pkg(uctx, "network", id, "password", password_ref);
        if (pppoe_ac && pppoe_ac[0]) nc_uci_set_pkg(uctx, "network", id, "ac", pppoe_ac);
        if (pppoe_service && pppoe_service[0]) nc_uci_set_pkg(uctx, "network", id, "service", pppoe_service);
        if (pppoe_ac_mac && pppoe_ac_mac[0]) nc_uci_set_pkg(uctx, "network", id, "pppoe_ac_mac", pppoe_ac_mac);
        if (sync_count > 1) {
            char b[32], group[96];
            snprintf(b, sizeof(b), "%d", sync_count);
            nc_uci_set_pkg(uctx, "network", id, "syncppp", b);
            snprintf(group, sizeof(group), "dwrt_%s", parent && parent[0] ? parent : "wan");
            nc_uci_set_pkg(uctx, "network", id, "syncppp_name", group);
            snprintf(b, sizeof(b), "%d", sync_timeout > 0 ? sync_timeout : 5);
            nc_uci_set_pkg(uctx, "network", id, "syncppp_timeout", b);
        } else {
            nc_uci_delete_pkg(uctx, "network", id, "syncppp");
            nc_uci_delete_pkg(uctx, "network", id, "syncppp_name");
            nc_uci_delete_pkg(uctx, "network", id, "syncppp_timeout");
        }
    }
    if (jmx_uci_commit(uctx, "network") != UCI_OK) goto done;
    if (nc_reload_network_stack(0, 0, "/tmp/dw-wan-netifd-reload.log") != 0)
        LOG_ERROR("hybrid_line_apply reload failed id=%s log=/tmp/dw-wan-netifd-reload.log\n", id ? id : "");
    rc = 0;

done:
    if (rc != 0) { nc_restore_config("network", bak_network); nc_reload_network_stack(0, 0, "/tmp/dw-wan-netifd-rollback.log"); }
    nc_cleanup_backup(bak_network);
    if (st) sqlite3_finalize(st);
    if (uctx) uci_free_context(uctx);
    return rc;
}

static int nc_apply_wan_scoped(const char *id, struct json_object *prepared)
{
    sqlite3_stmt *st = NULL;
    sqlite3_stmt *lines_st = NULL;
    struct uci_context *uctx = NULL;
    struct uci_package *netpkg = NULL, *firepkg = NULL;
    int rc = -1;
    char bak_network[256] = {0}, bak_firewall[256] = {0};
    const char *device, *access_mode, *gateway, *vlan_id, *role, *pppoe_user, *pppoe_pass_ref;
    const char *uci_proto;
    int mtu, metric, vlan_enabled, enabled;

    if (!nc_uci_section_name_ok(id)) return -101;
    if (jmx_netconfig_db_init() != 0) return -102;

    if (nc_prepare(&st, "SELECT device,access_mode,gateway,vlan_enabled,vlan_id,mtu,metric,role,username,password_ref,enabled FROM wan WHERE id=?1") != 0)
        return -103;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return -104; }

    device = (const char *)sqlite3_column_text(st, 0);
    access_mode = (const char *)sqlite3_column_text(st, 1);
    gateway = (const char *)sqlite3_column_text(st, 2);
    vlan_enabled = sqlite3_column_int(st, 3);
    vlan_id = (const char *)sqlite3_column_text(st, 4);
    mtu = sqlite3_column_int(st, 5);
    metric = sqlite3_column_int(st, 6);
    role = (const char *)sqlite3_column_text(st, 7);
    pppoe_user = (const char *)sqlite3_column_text(st, 8);
    pppoe_pass_ref = (const char *)sqlite3_column_text(st, 9);
    enabled = sqlite3_column_int(st, 10);

    if (!prepared) {
        nc_backup_config("network", bak_network, sizeof(bak_network));
        nc_backup_config("firewall", bak_firewall, sizeof(bak_firewall));
    }
    uctx = uci_alloc_context();
    if (!uctx) { rc = -105; goto done; }
    if (uci_load(uctx, "network", &netpkg) != UCI_OK) { rc = -106; goto done; }
    if (uci_load(uctx, "firewall", &firepkg) != UCI_OK) { rc = -110; goto done; }
    if (nc_uci_ensure_section(uctx, netpkg, "network", id, "interface") != 0) { rc = -107; goto done; }
    nc_apply_wan_bond(uctx, netpkg, id, &device);

    uci_proto = access_mode && access_mode[0] ? access_mode : "dhcp";
    if (!strcmp(uci_proto, "hybrid_macvlan") || !strcmp(uci_proto, "hybrid_vlan") || !strcmp(uci_proto, "pppoe_multi"))
        uci_proto = "none";
    nc_uci_set_pkg(uctx, "network", id, "proto", uci_proto);
    if (enabled)
        nc_uci_delete_pkg(uctx, "network", id, "disabled");
    else
        nc_uci_set_pkg(uctx, "network", id, "disabled", "1");
    if (device && device[0]) nc_uci_set_pkg(uctx, "network", id, "device", device);
    if (gateway && gateway[0]) nc_uci_set_pkg(uctx, "network", id, "gateway", gateway);
    else nc_uci_delete_pkg(uctx, "network", id, "gateway");
    if (uci_proto && strcmp(uci_proto, "pppoe") == 0) {
        nc_uci_delete_pkg(uctx, "network", id, "mtu");
    } else if (mtu > 0) {
        char b[16]; snprintf(b, sizeof(b), "%d", mtu); nc_uci_set_pkg(uctx, "network", id, "mtu", b);
    }
    if (metric > 0) { char b[16]; snprintf(b, sizeof(b), "%d", metric); nc_uci_set_pkg(uctx, "network", id, "metric", b); }
    else nc_uci_delete_pkg(uctx, "network", id, "metric");
    if (role && role[0]) nc_uci_set_pkg(uctx, "network", id, "dreamingwrt_role", role);
    if (vlan_enabled && vlan_id && vlan_id[0]) nc_uci_set_pkg(uctx, "network", id, "dreamingwrt_vlan_id", vlan_id);
    if (nc_apply_wan_dns(uctx, id) != 0 ||
        nc_apply_wan_dns_policy(uctx, id) != 0) { rc = -114; goto done; }
    nc_apply_wan_advanced(uctx, id, uci_proto);

    /* Apply PPPoE credentials from wan table */
    if (uci_proto && strcmp(uci_proto, "pppoe") == 0) {
        if (pppoe_user && pppoe_user[0]) nc_uci_set_pkg(uctx, "network", id, "username", pppoe_user);
        if (pppoe_pass_ref && pppoe_pass_ref[0]) nc_uci_set_pkg(uctx, "network", id, "password", pppoe_pass_ref);
    }

    if (uci_proto && strcmp(uci_proto, "static") == 0) {
        nc_apply_wan_addresses(uctx, id);
    }

    if (nc_apply_wan_firewall_zone(uctx, firepkg, id, enabled) != 0) { rc = -111; goto done; }

    if (prepared) {
        rc = nc_tx_prepare_package(uctx, netpkg, prepared);
        if (!rc) rc = nc_tx_prepare_package(uctx, firepkg, prepared);
        goto done;
    }
    if (jmx_uci_commit(uctx, "network") != UCI_OK) { rc = -108; goto done; }
    if (jmx_uci_commit(uctx, "firewall") != UCI_OK) { rc = -112; goto done; }
    if (nc_prepare(&lines_st, "SELECT id FROM hybrid_line WHERE parent_wan_id=?1 AND enabled=1 ORDER BY name,id") == 0) {
        sqlite3_bind_text(lines_st, 1, id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(lines_st) == SQLITE_ROW) {
            const char *line_id = (const char *)sqlite3_column_text(lines_st, 0);
            if (line_id && line_id[0] && jmx_netconfig_apply_hybrid_line(line_id) != 0) {
                sqlite3_finalize(lines_st);
                lines_st = NULL;
                rc = -109;
                goto done;
            }
        }
        sqlite3_finalize(lines_st);
        lines_st = NULL;
    }
    /* Reload netifd so the committed UCI takes effect */
    if (nc_reload_network_stack(0, 1, "/tmp/dw-wan-netifd-reload.log") != 0) {
        LOG_ERROR("wan_apply reload failed id=%s log=/tmp/dw-wan-netifd-reload.log\n", id ? id : "");
        rc = -113;
        goto done;
    }
    rc = 0;

done:
    if (rc != 0) LOG_ERROR("wan_apply failed id=%s rc=%d\n", id ? id : "", rc);
    if (rc != 0 && !prepared) {
        nc_restore_config("network", bak_network);
        nc_restore_config("firewall", bak_firewall);
        nc_reload_network_stack(0, 1, "/tmp/dw-wan-netifd-rollback.log");
    }
    nc_cleanup_backup(bak_network);
    nc_cleanup_backup(bak_firewall);
    if (lines_st) sqlite3_finalize(lines_st);
    if (st) sqlite3_finalize(st);
    if (uctx) uci_free_context(uctx);
    return rc;
}

int jmx_netconfig_apply_wan(const char *id)
{
    return nc_apply_wan_scoped(id, NULL);
}

static void nc_apply_lan_addresses(struct uci_context *ctx, const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    nc_uci_delete_pkg(ctx, "network", lan_id, "ipaddr");
    nc_uci_delete_pkg(ctx, "network", lan_id, "netmask");
    if (nc_prepare(&st, "SELECT ip,prefix FROM lan_address WHERE lan_id=?1 ORDER BY is_primary DESC, sort_order") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *ip = (const char *)sqlite3_column_text(st, 0);
            int prefix = sqlite3_column_int(st, 1);
            char cidr[64];
            if (!ip) continue;
            snprintf(cidr, sizeof(cidr), "%s/%d", ip, prefix);
            nc_uci_add_list_pkg(ctx, "network", lan_id, "ipaddr", cidr);
        }
        sqlite3_finalize(st);
    }
}

static int nc_apply_lan_ports(struct uci_context *ctx, struct uci_package *netpkg,
                              const char *device, const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    const char *section = NULL;
    if (!device || !device[0]) return -1;
    if (nc_uci_ensure_network_device(ctx, netpkg, device, &section) != 0) return -1;
    if (nc_uci_set_pkg(ctx, "network", section, "type", "bridge") != UCI_OK ||
        nc_uci_delete_pkg(ctx, "network", section, "ports") != UCI_OK)
        return -1;
    if (nc_prepare(&st, "SELECT port FROM lan_port WHERE lan_id=?1 ORDER BY sort_order") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *port = (const char *)sqlite3_column_text(st, 0);
            if (port && port[0] &&
                nc_uci_add_list_pkg(ctx, "network", section, "ports", port) != UCI_OK) {
                sqlite3_finalize(st);
                return -1;
            }
        }
        sqlite3_finalize(st);
    } else {
        return -1;
    }
    return 0;
}

static int nc_dhcp_apply_fields(struct uci_context *ctx, struct uci_package *pkg,
                                const char *lan_id, struct json_object *patch)
{
    struct json_object *cfg = nc_dhcp_base_get(lan_id), *v = NULL;
    int rc = -1;
    char b[128];
    if (!cfg) goto done;
    /* A delta must not create a half-configured DHCP service. */
    if (patch) {
        struct uci_ptr ptr = {0};
        char lookup[192];
        snprintf(lookup, sizeof(lookup), "dhcp.%s", lan_id);
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) != UCI_OK || !ptr.s ||
            strcmp(ptr.s->type, "dhcp")) goto done;
    } else if (nc_uci_ensure_section(ctx, pkg, "dhcp", lan_id, "dhcp") != 0) goto done;
    if (!patch && nc_uci_set_pkg(ctx, "dhcp", lan_id, "interface", lan_id) != 0) goto done;
    if ((!patch || json_object_object_get_ex(patch, "enabled", &v)) &&
        nc_uci_set_pkg(ctx, "dhcp", lan_id, "ignore", nc_json_bool(cfg, "enabled", 0) ? "0" : "1") != 0) goto done;
    if (!patch || json_object_object_get_ex(patch, "pool_start", &v) ||
        json_object_object_get_ex(patch, "pool_end", &v)) {
        char ip[64], start_ip[64], end_ip[64];
        int prefix, start, end;
        if (!nc_dhcp_lan_primary(lan_id, ip, sizeof(ip), &prefix) ||
            nc_dhcp_expand_pool_address(nc_json_str(cfg, "pool_start", ""), ip, prefix, start_ip, sizeof(start_ip)) ||
            nc_dhcp_expand_pool_address(nc_json_str(cfg, "pool_end", ""), ip, prefix, end_ip, sizeof(end_ip))) goto done;
        start = nc_dhcp_pool_offset(start_ip, ip, prefix);
        end = nc_dhcp_pool_offset(end_ip, ip, prefix);
        if (start < 1 || end < start) goto done;
        snprintf(b, sizeof(b), "%d", start);
        if (nc_uci_set_pkg(ctx, "dhcp", lan_id, "start", b) != 0) goto done;
        snprintf(b, sizeof(b), "%d", end - start + 1);
        if (nc_uci_set_pkg(ctx, "dhcp", lan_id, "limit", b) != 0) goto done;
    }
    if (!patch || json_object_object_get_ex(patch, "lease_minutes", &v)) {
        snprintf(b, sizeof(b), "%dm", nc_json_int(cfg, "lease_minutes", 120));
        if (nc_uci_set_pkg(ctx, "dhcp", lan_id, "leasetime", b) != 0) goto done;
    }
    int gateway = !patch || json_object_object_get_ex(patch, "gateway", &v);
    int dns = !patch || json_object_object_get_ex(patch, "dns1", &v) || json_object_object_get_ex(patch, "dns2", &v);
    if (gateway || dns) {
        struct uci_ptr ptr = {0};
        struct json_object *keep = json_object_new_array();
        char lookup[192];
        snprintf(lookup, sizeof(lookup), "dhcp.%s.dhcp_option", lan_id);
        if (uci_lookup_ptr(ctx, &ptr, lookup, true) == UCI_OK && ptr.o) {
            struct uci_element *e;
            if (ptr.o->type == UCI_TYPE_LIST) {
                uci_foreach_element(&ptr.o->v.list, e)
                    if (!(gateway && !strncmp(e->name, "3,", 2)) && !(dns && !strncmp(e->name, "6,", 2)))
                        json_object_array_add(keep, json_object_new_string(e->name));
            } else if (ptr.o->type == UCI_TYPE_STRING) {
                const char *s = ptr.o->v.string;
                if (!(gateway && !strncmp(s, "3,", 2)) && !(dns && !strncmp(s, "6,", 2)))
                    json_object_array_add(keep, json_object_new_string(s));
            }
        }
        int failed = nc_uci_delete_pkg(ctx, "dhcp", lan_id, "dhcp_option");
        for (size_t i = 0; !failed && i < json_object_array_length(keep); i++)
            failed = nc_uci_add_list_pkg(ctx, "dhcp", lan_id, "dhcp_option",
                json_object_get_string(json_object_array_get_idx(keep, i)));
        json_object_put(keep);
        if (failed) goto done;
        const char *gw = nc_json_str(cfg, "gateway", ""), *d1 = nc_json_str(cfg, "dns1", ""), *d2 = nc_json_str(cfg, "dns2", "");
        if (gateway && gw[0]) {
            snprintf(b, sizeof(b), "3,%s", gw);
            if (nc_uci_add_list_pkg(ctx, "dhcp", lan_id, "dhcp_option", b)) goto done;
        }
        if (dns && (d1[0] || d2[0])) {
            snprintf(b, sizeof(b), "6,%s%s%s", d1, d1[0] && d2[0] ? "," : "", d2);
            if (nc_uci_add_list_pkg(ctx, "dhcp", lan_id, "dhcp_option", b)) goto done;
        }
    }
    rc = 0;
done:
    if (cfg) json_object_put(cfg);
    return rc;
}

static int nc_dhcp_apply_scoped(const char *lan_id, struct json_object *patch,
                                struct json_object *prepared)
{
    struct uci_context *ctx = uci_alloc_context();
    struct uci_package *pkg = NULL;
    int rc = -1;
    if (ctx && uci_load(ctx, "dhcp", &pkg) == UCI_OK &&
        nc_dhcp_apply_fields(ctx, pkg, lan_id, patch) == 0) {
        if (prepared) rc = nc_tx_prepare_package(ctx, pkg, prepared);
        else if (jmx_uci_commit(ctx, "dhcp") == UCI_OK)
            rc = nc_dnsmasq_restart("/tmp/dw-dhcp-transaction-apply.log");
    }
    if (ctx) uci_free_context(ctx);
    return rc;
}

static int nc_apply_lan_dhcp(struct uci_context *ctx, struct uci_package *dhcppkg, const char *lan_id)
{
    return nc_dhcp_apply_fields(ctx, dhcppkg, lan_id, NULL);
}

static void nc_apply_lan_isolation(struct uci_context *ctx, struct uci_package *pkg, const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "SELECT lan_visit FROM lan WHERE id=?1") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            int lan_visit = sqlite3_column_int(st, 0);
            char zone[96];
            snprintf(zone, sizeof(zone), "dw_%s", lan_id);
            if (nc_uci_ensure_section(ctx, pkg, "firewall", zone, "zone") == 0) {
                nc_uci_set_pkg(ctx, "firewall", zone, "name", zone);
                nc_uci_delete_pkg(ctx, "firewall", zone, "network");
                nc_uci_add_list_pkg(ctx, "firewall", zone, "network", lan_id);
                nc_uci_set_pkg(ctx, "firewall", zone, "input", "ACCEPT");
                nc_uci_set_pkg(ctx, "firewall", zone, "output", "ACCEPT");
                nc_uci_set_pkg(ctx, "firewall", zone, "forward", lan_visit ? "ACCEPT" : "REJECT");
                nc_uci_set_pkg(ctx, "firewall", zone, "dreamingwrt_lan_visit", lan_visit ? "1" : "0");
            }
        }
        sqlite3_finalize(st);
    }
}

static void nc_apply_lan_ipv6(struct uci_context *ctx, const char *lan_id)
{
    sqlite3_stmt *st = NULL;
    if (nc_prepare(&st, "SELECT enabled,mode,dhcpv6,ra_flags,lease_minutes FROM lan_ipv6 WHERE lan_id=?1") == 0) {
        sqlite3_bind_text(st, 1, lan_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            int enabled = sqlite3_column_int(st, 0);
            const char *mode = (const char *)sqlite3_column_text(st, 1);
            int dhcpv6 = sqlite3_column_int(st, 2);
            const char *ra_flags = (const char *)sqlite3_column_text(st, 3);
            int lease = sqlite3_column_int(st, 4);
            char b[32];
            if (!enabled) {
                nc_uci_set_pkg(ctx, "dhcp", lan_id, "ra", "disabled");
                nc_uci_set_pkg(ctx, "dhcp", lan_id, "dhcpv6", "disabled");
            } else {
                nc_uci_set_pkg(ctx, "dhcp", lan_id, "ra", (mode && strcmp(mode, "relay") == 0) ? "relay" : "server");
                nc_uci_set_pkg(ctx, "dhcp", lan_id, "dhcpv6", dhcpv6 ? ((mode && strcmp(mode, "relay") == 0) ? "relay" : "server") : "disabled");
                if (ra_flags && ra_flags[0]) nc_uci_set_pkg(ctx, "dhcp", lan_id, "ra_flags", ra_flags);
                if (lease > 0) { snprintf(b, sizeof(b), "%dm", lease); nc_uci_set_pkg(ctx, "dhcp", lan_id, "leasetime", b); }
            }
        }
        sqlite3_finalize(st);
    }
}

static int nc_apply_lan_scoped(const char *id, int full, struct json_object *prepared)
{
    sqlite3_stmt *st = NULL;
    struct uci_context *uctx = NULL;
    struct uci_package *netpkg = NULL, *dhcppkg = NULL, *firepkg = NULL;
    char bak_network[256] = {0}, bak_dhcp[256] = {0}, bak_firewall[256] = {0};
    int rc = -1;
    int enabled = 1;
    const char *device, *mode, *parent, *vlan_id;

    if (!nc_uci_section_name_ok(id)) return -1;
    if (jmx_netconfig_db_init() != 0) return -1;
    if (nc_prepare(&st, "SELECT device,mode,parent_lan_id,vlan_id,enabled FROM lan WHERE id=?1") != 0) return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    device = (const char *)sqlite3_column_text(st, 0);
    mode = (const char *)sqlite3_column_text(st, 1);
    parent = (const char *)sqlite3_column_text(st, 2);
    vlan_id = (const char *)sqlite3_column_text(st, 3);
    enabled = sqlite3_column_int(st, 4);

    if (!prepared) nc_backup_config("network", bak_network, sizeof(bak_network));
    if (full && !prepared) {
        nc_backup_config("dhcp", bak_dhcp, sizeof(bak_dhcp));
        nc_backup_config("firewall", bak_firewall, sizeof(bak_firewall));
    }
    uctx = uci_alloc_context();
    if (!uctx) goto done;
    if (uci_load(uctx, "network", &netpkg) != UCI_OK) goto done;
    if (full) {
        uci_load(uctx, "dhcp", &dhcppkg);
        uci_load(uctx, "firewall", &firepkg);
    }

    if (full && mode && strcmp(mode, "bridge") == 0) {
        if (nc_apply_lan_ports(uctx, netpkg, device, id) != 0) goto done;
    }
    else if (full && mode && strcmp(mode, "vlan") == 0 && device && device[0]) {
        const char *section = NULL;
        if (nc_uci_ensure_network_device(uctx, netpkg, device, &section) != 0) goto done;
        nc_uci_set_pkg(uctx, "network", section, "type", "8021q");
        if (parent && parent[0]) nc_uci_set_pkg(uctx, "network", section, "ifname", parent);
        if (vlan_id && vlan_id[0]) nc_uci_set_pkg(uctx, "network", section, "vid", vlan_id);
    }

    if (nc_uci_ensure_section(uctx, netpkg, "network", id, "interface") != 0) goto done;
    nc_uci_set_pkg(uctx, "network", id, "proto", "static");
    if (enabled)
        nc_uci_delete_pkg(uctx, "network", id, "disabled");
    else
        nc_uci_set_pkg(uctx, "network", id, "disabled", "1");
    if (device && device[0]) nc_uci_set_pkg(uctx, "network", id, "device", device);
    nc_apply_lan_addresses(uctx, id);
    if (dhcppkg) {
        if (nc_apply_lan_dhcp(uctx, dhcppkg, id) != 0) goto done;
        nc_apply_lan_ipv6(uctx, id);
    }

    if (firepkg) nc_apply_lan_isolation(uctx, firepkg, id);

    if (prepared) {
        rc = nc_tx_prepare_package(uctx, netpkg, prepared);
        if (!rc && dhcppkg) rc = nc_tx_prepare_package(uctx, dhcppkg, prepared);
        if (!rc && firepkg) rc = nc_tx_prepare_package(uctx, firepkg, prepared);
        goto done;
    }
    if (jmx_uci_commit(uctx, "network") != UCI_OK) goto done;
    if (dhcppkg && jmx_uci_commit(uctx, "dhcp") != UCI_OK) goto done;
    if (firepkg && jmx_uci_commit(uctx, "firewall") != UCI_OK) goto done;
    if (nc_reload_network_stack(dhcppkg != NULL, firepkg != NULL, "/tmp/dw-lan-netifd-reload.log") != 0) goto done;
    rc = 0;

done:
    if (rc != 0 && !prepared) { nc_restore_config("network", bak_network); nc_restore_config("dhcp", bak_dhcp); nc_restore_config("firewall", bak_firewall); nc_reload_network_stack(dhcppkg != NULL, firepkg != NULL, "/tmp/dw-lan-netifd-rollback.log"); }
    nc_cleanup_backup(bak_network); nc_cleanup_backup(bak_dhcp); nc_cleanup_backup(bak_firewall);
    if (st) sqlite3_finalize(st);
    if (uctx) uci_free_context(uctx);
    return rc;
}

int jmx_netconfig_apply_lan(const char *id)
{
    return nc_apply_lan_scoped(id, 1, NULL);
}

static struct json_object *nc_result_readback_entity(struct json_object *response,
                                                     const char *entity)
{
    struct json_object *data = NULL;
    struct json_object *value = NULL;

    if (response && entity &&
        json_object_object_get_ex(response, "data", &data) && data &&
        json_object_object_get_ex(data, entity, &value) && value)
        return json_object_get(value);
    return json_object_new_object();
}

static struct json_object *nc_save_apply_result(const char *kind,
                                                struct json_object *config)
{
    struct json_object *data = json_object_new_object();
    struct json_object *read_response = NULL;
    struct json_object *rollback = json_object_new_object();
    const char *id = nc_json_str(config, "id", "");
    int save_rc = -1;
    int apply_rc = -1;
    int commit_rc = -1;
    int tx_started = 0;
    int snapshot_ok = 0;
    int database_rollback_ok = 0;
    int runtime_rollback_ok = 0;
    int is_wan = kind && !strcmp(kind, "wan");
    char bak_network[256] = {0};
    char bak_dhcp[256] = {0};
    char bak_firewall[256] = {0};

    if (!config || !id[0] || jmx_netconfig_db_init() != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "saved", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "apply_state", json_object_new_string("failed"));
        json_object_object_add(data, "error", json_object_new_string("invalid_config"));
        json_object_object_add(data, "rollback", rollback);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    if (nc_backup_config("network", bak_network, sizeof(bak_network)) == 0 &&
        (is_wan || nc_backup_config("dhcp", bak_dhcp, sizeof(bak_dhcp)) == 0) &&
        nc_backup_config("firewall", bak_firewall, sizeof(bak_firewall)) == 0)
        snapshot_ok = 1;
    if (!snapshot_ok || nc_exec("BEGIN IMMEDIATE") != 0) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "saved", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "apply_state", json_object_new_string("failed"));
        json_object_object_add(data, "error", json_object_new_string(
            snapshot_ok ? "config_transaction_begin_failed" : "config_snapshot_failed"));
        json_object_object_add(data, "rollback", rollback);
        nc_cleanup_backup(bak_network);
        nc_cleanup_backup(bak_dhcp);
        nc_cleanup_backup(bak_firewall);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    tx_started = 1;
    save_rc = is_wan ? jmx_netconfig_wan_set(config) : jmx_netconfig_lan_set(config);
    if (save_rc == 0)
        apply_rc = is_wan ? jmx_netconfig_apply_wan(id) : jmx_netconfig_apply_lan(id);
    if (save_rc == 0 && apply_rc == 0)
        commit_rc = nc_exec("COMMIT");

    if (commit_rc == 0) {
        tx_started = 0;
        read_response = is_wan ? jmx_netconfig_wan_get(id) : jmx_netconfig_lan_get(id);
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "id", json_object_new_string(id));
        json_object_object_add(data, "saved", json_object_new_boolean(1));
        json_object_object_add(data, "applied", json_object_new_boolean(1));
        json_object_object_add(data, "apply_state", json_object_new_string("applied"));
        json_object_object_add(data, "readback",
                               nc_result_readback_entity(read_response, kind));
        json_object_object_add(rollback, "attempted", json_object_new_boolean(0));
        json_object_object_add(rollback, "required", json_object_new_boolean(0));
        json_object_object_add(data, "rollback", rollback);
        if (read_response) json_object_put(read_response);
        nc_cleanup_backup(bak_network);
        nc_cleanup_backup(bak_dhcp);
        nc_cleanup_backup(bak_firewall);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }

    if (tx_started) {
        database_rollback_ok = nc_exec("ROLLBACK") == 0;
        tx_started = 0;
    }
    if (save_rc == 0 && snapshot_ok) {
        nc_restore_config("network", bak_network);
        if (!is_wan) nc_restore_config("dhcp", bak_dhcp);
        nc_restore_config("firewall", bak_firewall);
        runtime_rollback_ok = nc_reload_network_stack(!is_wan, 1,
            is_wan ? "/tmp/dw-wan-save-rollback.log" :
                     "/tmp/dw-lan-save-rollback.log") == 0;
    }
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "id", json_object_new_string(id));
    json_object_object_add(data, "saved", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(data, "apply_state", json_object_new_string(
        save_rc == 0 && database_rollback_ok && runtime_rollback_ok ?
        "rolled_back" : "failed"));
    json_object_object_add(data, "error", json_object_new_string(
        save_rc != 0 ? "config_save_failed" :
        apply_rc != 0 ? "runtime_apply_failed" : "config_commit_failed"));
    json_object_object_add(data, "save_error", json_object_new_int(save_rc));
    json_object_object_add(data, "apply_error", json_object_new_int(apply_rc));
    json_object_object_add(rollback, "attempted", json_object_new_boolean(save_rc == 0));
    json_object_object_add(rollback, "database",
                           json_object_new_boolean(database_rollback_ok));
    json_object_object_add(rollback, "runtime", json_object_new_boolean(save_rc == 0));
    json_object_object_add(rollback, "runtime_verified",
                           json_object_new_boolean(runtime_rollback_ok));
    json_object_object_add(data, "rollback", rollback);
    nc_cleanup_backup(bak_network);
    nc_cleanup_backup(bak_dhcp);
    nc_cleanup_backup(bak_firewall);
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

struct json_object *jmx_netconfig_wan_save_apply_result(struct json_object *wan_json)
{
    return nc_save_apply_result("wan", wan_json);
}

struct json_object *jmx_netconfig_wan_delete_result(const char *id)
{
    struct json_object *data = json_object_new_object();
    struct json_object *rollback = json_object_new_object();
    struct json_object *readback = NULL;
    int rc = jmx_netconfig_wan_delete(id);

    if (rc == 0) {
        readback = jmx_netconfig_wan_get(id);
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "id", json_object_new_string(id ? id : ""));
        json_object_object_add(data, "saved", json_object_new_boolean(1));
        json_object_object_add(data, "applied", json_object_new_boolean(1));
        json_object_object_add(data, "deleted", json_object_new_boolean(1));
        json_object_object_add(data, "apply_state", json_object_new_string("applied"));
        json_object_object_add(data, "readback",
                               nc_result_readback_entity(readback, "wan"));
        json_object_object_add(rollback, "attempted", json_object_new_boolean(0));
        json_object_object_add(rollback, "required", json_object_new_boolean(0));
        json_object_object_add(data, "rollback", rollback);
        if (readback) json_object_put(readback);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "id", json_object_new_string(id ? id : ""));
    json_object_object_add(data, "saved", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(data, "deleted", json_object_new_boolean(0));
    json_object_object_add(data, "apply_state", json_object_new_string("failed"));
    json_object_object_add(data, "error", json_object_new_string("not_found_or_delete_failed"));
    json_object_object_add(data, "error_code", json_object_new_int(rc));
    json_object_object_add(rollback, "attempted", json_object_new_boolean(rc == -1));
    json_object_object_add(rollback, "verified", json_object_new_boolean(0));
    json_object_object_add(data, "rollback", rollback);
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

struct json_object *jmx_netconfig_lan_save_apply_result(struct json_object *lan_json)
{
    return nc_save_apply_result("lan", lan_json);
}

static int nc_lan_contains_management_ip(const char *id, const char *client_ip)
{
    sqlite3_stmt *st = NULL;

    if (!id || !id[0] || !client_ip || !client_ip[0] ||
        !nc_is_valid_ip(client_ip) || jmx_netconfig_db_init() != 0)
        return 0;
    if (nc_prepare(&st,
        "SELECT ip,prefix FROM lan_address WHERE lan_id=?1 ORDER BY is_primary DESC") != 0)
        return 0;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        char cidr[96];
        snprintf(cidr, sizeof(cidr), "%s/%d", nc_sql_text(st, 0),
                 sqlite3_column_int(st, 1));
        if (nc_ip_in_subnet(client_ip, cidr)) {
            sqlite3_finalize(st);
            return 1;
        }
    }
    sqlite3_finalize(st);
    return 0;
}

struct json_object *jmx_netconfig_lan_delete_result(const char *id,
                                                     const char *management_client_ip)
{
    struct json_object *data = json_object_new_object();
    struct json_object *rollback = json_object_new_object();
    struct json_object *readback = NULL;
    int rc;
    const char *error = "lan_delete_failed";

    if (nc_lan_contains_management_ip(id, management_client_ip))
        rc = JMX_NETCONFIG_DELETE_MANAGEMENT_PATH;
    else
        rc = jmx_netconfig_lan_delete(id);
    if (rc == 0) {
        readback = jmx_netconfig_lan_get(id);
        json_object_object_add(data, "ok", json_object_new_boolean(1));
        json_object_object_add(data, "id", json_object_new_string(id ? id : ""));
        json_object_object_add(data, "saved", json_object_new_boolean(1));
        json_object_object_add(data, "applied", json_object_new_boolean(1));
        json_object_object_add(data, "deleted", json_object_new_boolean(1));
        json_object_object_add(data, "apply_state", json_object_new_string("applied"));
        json_object_object_add(data, "readback", nc_result_readback_entity(readback, "lan"));
        json_object_object_add(rollback, "attempted", json_object_new_boolean(0));
        json_object_object_add(rollback, "required", json_object_new_boolean(0));
        json_object_object_add(data, "rollback", rollback);
        if (readback) json_object_put(readback);
        return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
    }
    switch (rc) {
    case JMX_NETCONFIG_DELETE_NOT_FOUND: error = "not_found"; break;
    case JMX_NETCONFIG_DELETE_PROTECTED: error = "protected_management_lan"; break;
    case JMX_NETCONFIG_DELETE_LAST_LAN: error = "last_enabled_lan"; break;
    case JMX_NETCONFIG_DELETE_PORTS_ATTACHED: error = "lan_ports_attached"; break;
    case JMX_NETCONFIG_DELETE_CHILD_LAN: error = "child_lans_attached"; break;
    case JMX_NETCONFIG_DELETE_IPAM_ATTACHED: error = "ipam_network_attached"; break;
    case JMX_NETCONFIG_DELETE_SNAPSHOT_FAILED: error = "snapshot_failed"; break;
    case JMX_NETCONFIG_DELETE_MANAGEMENT_PATH: error = "management_reachability_risk"; break;
    default: break;
    }
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "id", json_object_new_string(id ? id : ""));
    json_object_object_add(data, "saved", json_object_new_boolean(0));
    json_object_object_add(data, "applied", json_object_new_boolean(0));
    json_object_object_add(data, "deleted", json_object_new_boolean(0));
    json_object_object_add(data, "apply_state", json_object_new_string("failed"));
    json_object_object_add(data, "error", json_object_new_string(error));
    json_object_object_add(data, "error_code", json_object_new_int(rc));
    json_object_object_add(rollback, "attempted",
                           json_object_new_boolean(rc == -1));
    json_object_object_add(rollback, "verified", json_object_new_boolean(0));
    json_object_object_add(rollback, "required",
                           json_object_new_boolean(rc == -1));
    json_object_object_add(data, "rollback", rollback);
    return jmx_gen_api_response_data(API_CODE_ERROR, data);
}

static struct json_object *nc_batch_response_data(struct json_object *response)
{
    struct json_object *data = NULL;

    if (response && json_object_object_get_ex(response, "data", &data) && data &&
        json_object_is_type(data, json_type_object))
        return json_object_get(data);
    return NULL;
}

static int nc_batch_entity_state(const char *kind, const char *id,
                                 int *exists, int *enabled)
{
    sqlite3_stmt *st = NULL;
    char sql[96];

    if (exists) *exists = 0;
    if (enabled) *enabled = 0;
    if (!kind || !id || !id[0] ||
        (strcmp(kind, "wan") && strcmp(kind, "lan")) ||
        jmx_netconfig_db_init() != 0)
        return -1;
    snprintf(sql, sizeof(sql), "SELECT enabled FROM %s WHERE id=?1", kind);
    if (nc_prepare(&st, sql) != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        if (exists) *exists = 1;
        if (enabled) *enabled = sqlite3_column_int(st, 0) != 0;
    }
    sqlite3_finalize(st);
    return 0;
}

static int nc_batch_enabled_count(const char *kind)
{
    sqlite3_stmt *st = NULL;
    char sql[96];
    int count = -1;

    if (!kind || (strcmp(kind, "wan") && strcmp(kind, "lan")) ||
        jmx_netconfig_db_init() != 0)
        return -1;
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s WHERE enabled=1", kind);
    if (nc_prepare(&st, sql) != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW)
        count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return count;
}

static int nc_batch_lan_delete_dependency(const char *id, const char **error)
{
    sqlite3_stmt *st = NULL;
    int count = 0;

    if (error) *error = NULL;
    if (!strcmp(id, "lan") || !strcmp(id, "default-lan")) {
        if (error) *error = "protected_management_lan";
        return -1;
    }
    if (nc_prepare(&st, "SELECT COUNT(*) FROM lan_port WHERE lan_id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st); st = NULL;
    if (count > 0) {
        if (error) *error = "lan_ports_attached";
        return -1;
    }
    if (nc_prepare(&st, "SELECT COUNT(*) FROM lan WHERE parent_lan_id=?1") != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st); st = NULL;
    if (count > 0) {
        if (error) *error = "child_lans_attached";
        return -1;
    }
    if (nc_table_exists("ipam_network") &&
        nc_prepare(&st, "SELECT COUNT(*) FROM ipam_network WHERE id=?1 OR ifname=?1") == 0) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) count = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        if (count > 0) {
            if (error) *error = "ipam_network_attached";
            return -1;
        }
    }
    return 0;
}

static struct json_object *nc_batch_operations(struct json_object *payload,
                                                const char **error)
{
    struct json_object *operations = NULL;
    struct json_object *ids = NULL;
    struct json_object *normalized = NULL;
    const char *default_action;
    int i, n;

    if (error) *error = NULL;
    if (!payload || !json_object_is_type(payload, json_type_object)) {
        if (error) *error = "payload_must_be_object";
        return NULL;
    }
    if (!json_object_object_get_ex(payload, "operations", &operations) || !operations)
        json_object_object_get_ex(payload, "items", &operations);
    if (!operations && json_object_object_get_ex(payload, "ids", &ids) && ids &&
        json_object_is_type(ids, json_type_array)) {
        default_action = nc_json_str(payload, "action", "");
        normalized = json_object_new_array();
        n = (int)json_object_array_length(ids);
        for (i = 0; i < n; i++) {
            struct json_object *item = json_object_new_object();
            const char *id = json_object_get_string(json_object_array_get_idx(ids, i));

            json_object_object_add(item, "id", json_object_new_string(id ? id : ""));
            json_object_object_add(item, "action", json_object_new_string(default_action));
            json_object_array_add(normalized, item);
        }
        operations = normalized;
    }
    if (!operations || !json_object_is_type(operations, json_type_array)) {
        if (normalized) json_object_put(normalized);
        if (error) *error = "operations_array_required";
        return NULL;
    }
    n = (int)json_object_array_length(operations);
    if (n <= 0 || n > NC_NETWORK_BATCH_MAX) {
        if (normalized) json_object_put(normalized);
        if (error) *error = n <= 0 ? "operations_empty" : "operations_limit_exceeded";
        return NULL;
    }
    return normalized ? normalized : json_object_get(operations);
}

static struct json_object *nc_network_batch_preview(const char *kind,
                                                    struct json_object *payload,
                                                    const char *management_client_ip)
{
    struct json_object *data = json_object_new_object();
    struct json_object *items = json_object_new_array();
    struct json_object *operations;
    const char *payload_error = NULL;
    char seen[NC_NETWORK_BATCH_MAX][96];
    int seen_count = 0;
    int initial_enabled;
    int final_enabled;
    int ready = 1;
    int confirm_required = 0;
    int is_lan = kind && !strcmp(kind, "lan");
    int i, n;

    operations = nc_batch_operations(payload, &payload_error);
    if (!operations) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "ready", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("invalid_batch_payload"));
        json_object_object_add(data, "reason", json_object_new_string(payload_error ? payload_error : "invalid_payload"));
        json_object_object_add(data, "atomic", json_object_new_boolean(0));
        json_object_object_add(data, "partial", json_object_new_boolean(1));
        json_object_object_add(data, "items", items);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    initial_enabled = nc_batch_enabled_count(kind);
    final_enabled = initial_enabled;
    if (initial_enabled < 0) {
        json_object_put(operations);
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "ready", json_object_new_boolean(0));
        json_object_object_add(data, "error", json_object_new_string("batch_state_unavailable"));
        json_object_object_add(data, "atomic", json_object_new_boolean(0));
        json_object_object_add(data, "partial", json_object_new_boolean(1));
        json_object_object_add(data, "items", items);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }

    n = (int)json_object_array_length(operations);
    for (i = 0; i < n; i++) {
        struct json_object *op = json_object_array_get_idx(operations, i);
        struct json_object *item = json_object_new_object();
        const char *id = "";
        const char *action = nc_json_str(payload, "action", "");
        const char *error = NULL;
        int exists = 0, enabled = 0, duplicate = 0, j;

        if (op && json_object_is_type(op, json_type_object)) {
            id = nc_json_str(op, "id", "");
            action = nc_json_str(op, "action", action);
        } else if (op && json_object_is_type(op, json_type_string)) {
            id = json_object_get_string(op);
        } else {
            error = "operation_must_be_object_or_id";
        }
        for (j = 0; !error && j < seen_count; j++)
            if (!strcmp(seen[j], id)) duplicate = 1;
        if (!error && (!id[0] || !nc_valid_name(id))) error = "invalid_id";
        if (!error && nc_batch_entity_state(kind, id, &exists, &enabled) != 0)
            error = "state_unavailable";
        if (!error && !exists) error = "not_found";
        if (!error && duplicate) error = "duplicate_id";
        if (!error && strcmp(action, "enable") && strcmp(action, "disable") &&
            strcmp(action, "delete")) error = "invalid_action";
        if (!error && seen_count < NC_NETWORK_BATCH_MAX)
            snprintf(seen[seen_count++], sizeof(seen[0]), "%s", id);
        if (!error && is_lan && (!strcmp(action, "delete") || !strcmp(action, "disable")) &&
            nc_lan_contains_management_ip(id, management_client_ip))
            error = "management_reachability_risk";
        if (!error && is_lan && !strcmp(action, "delete") &&
            nc_batch_lan_delete_dependency(id, &error) != 0 && !error)
            error = "dependency_check_failed";

        if (!error && enabled && (!strcmp(action, "disable") || !strcmp(action, "delete")))
            final_enabled--;
        else if (!error && !enabled && !strcmp(action, "enable"))
            final_enabled++;

        json_object_object_add(item, "id", json_object_new_string(id ? id : ""));
        json_object_object_add(item, "action", json_object_new_string(action ? action : ""));
        json_object_object_add(item, "exists", json_object_new_boolean(exists));
        json_object_object_add(item, "current_enabled", json_object_new_boolean(enabled));
        json_object_object_add(item, "valid", json_object_new_boolean(error == NULL));
        if (error) {
            json_object_object_add(item, "error", json_object_new_string(error));
            ready = 0;
        }
        json_object_array_add(items, item);
    }
    if (is_lan && final_enabled <= 0) {
        ready = 0;
        for (i = 0; i < n; i++) {
            struct json_object *item = json_object_array_get_idx(items, i);
            const char *action = nc_json_str(item, "action", "");
            if (nc_json_bool(item, "valid", 0) &&
                (!strcmp(action, "disable") || !strcmp(action, "delete"))) {
                json_object_object_add(item, "valid", json_object_new_boolean(0));
                json_object_object_add(item, "error", json_object_new_string("last_enabled_lan"));
            }
        }
    } else if (!is_lan && final_enabled <= 0) {
        confirm_required = 1;
    }

    json_object_put(operations);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "ready", json_object_new_boolean(ready));
    json_object_object_add(data, "kind", json_object_new_string(kind));
    json_object_object_add(data, "atomic", json_object_new_boolean(0));
    json_object_object_add(data, "partial", json_object_new_boolean(1));
    json_object_object_add(data, "semantics", json_object_new_string("ordered_single_item_transactions"));
    json_object_object_add(data, "max_operations", json_object_new_int(NC_NETWORK_BATCH_MAX));
    json_object_object_add(data, "initial_enabled", json_object_new_int(initial_enabled));
    json_object_object_add(data, "final_enabled", json_object_new_int(final_enabled));
    json_object_object_add(data, "confirm_required", json_object_new_boolean(confirm_required));
    if (confirm_required)
        json_object_object_add(data, "warning", json_object_new_string("all_wans_will_be_disabled"));
    json_object_object_add(data, "items", items);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

static struct json_object *nc_network_batch_apply(const char *kind,
                                                  struct json_object *payload,
                                                  const char *management_client_ip)
{
    struct json_object *preview_response = nc_network_batch_preview(kind, payload, management_client_ip);
    struct json_object *preview = nc_batch_response_data(preview_response);
    struct json_object *data = json_object_new_object();
    struct json_object *results = json_object_new_array();
    struct json_object *items = NULL;
    int ready = preview && nc_json_bool(preview, "ready", 0);
    int confirm_required = preview && nc_json_bool(preview, "confirm_required", 0);
    int confirmed = nc_json_bool(payload, "confirm", 0);
    int stop_on_error = nc_json_bool(payload, "stop_on_error", 1);
    int stopped = 0, succeeded = 0, failed = 0, skipped = 0;
    int is_lan = kind && !strcmp(kind, "lan");
    int i, n = 0;

    if (!ready || (confirm_required && !confirmed)) {
        json_object_object_add(data, "ok", json_object_new_boolean(0));
        json_object_object_add(data, "applied", json_object_new_boolean(0));
        json_object_object_add(data, "atomic", json_object_new_boolean(0));
        json_object_object_add(data, "partial", json_object_new_boolean(1));
        json_object_object_add(data, "error", json_object_new_string(
            !ready ? "batch_preflight_failed" : "confirmation_required"));
        if (preview)
            json_object_object_add(data, "preview", preview);
        if (preview_response) json_object_put(preview_response);
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    json_object_object_get_ex(preview, "items", &items);
    if (items && json_object_is_type(items, json_type_array))
        n = (int)json_object_array_length(items);
    for (i = 0; i < n; i++) {
        struct json_object *planned = json_object_array_get_idx(items, i);
        struct json_object *result = json_object_new_object();
        struct json_object *response = NULL;
        struct json_object *result_data = NULL;
        const char *id = nc_json_str(planned, "id", "");
        const char *action = nc_json_str(planned, "action", "");
        int ok = 0;

        json_object_object_add(result, "id", json_object_new_string(id));
        json_object_object_add(result, "action", json_object_new_string(action));
        if (stopped) {
            skipped++;
            json_object_object_add(result, "ok", json_object_new_boolean(0));
            json_object_object_add(result, "skipped", json_object_new_boolean(1));
            json_object_object_add(result, "error", json_object_new_string("stopped_after_error"));
            json_object_array_add(results, result);
            continue;
        }
        if (!strcmp(action, "delete")) {
            response = is_lan ? jmx_netconfig_lan_delete_result(id, management_client_ip) :
                                jmx_netconfig_wan_delete_result(id);
        } else {
            struct json_object *get_response = is_lan ? jmx_netconfig_lan_get(id) :
                                                        jmx_netconfig_wan_get(id);
            struct json_object *config = nc_result_readback_entity(get_response, kind);

            json_object_object_add(config, "enabled",
                                   json_object_new_boolean(!strcmp(action, "enable")));
            response = is_lan ? jmx_netconfig_lan_save_apply_result(config) :
                                jmx_netconfig_wan_save_apply_result(config);
            json_object_put(config);
            if (get_response) json_object_put(get_response);
        }
        result_data = nc_batch_response_data(response);
        ok = result_data && nc_json_bool(result_data, "ok", 0);
        json_object_object_add(result, "ok", json_object_new_boolean(ok));
        json_object_object_add(result, "skipped", json_object_new_boolean(0));
        if (result_data)
            json_object_object_add(result, "result", result_data);
        if (response) json_object_put(response);
        if (ok) succeeded++;
        else {
            failed++;
            if (stop_on_error) stopped = 1;
        }
        json_object_array_add(results, result);
    }

    json_object_object_add(data, "ok", json_object_new_boolean(failed == 0));
    json_object_object_add(data, "applied", json_object_new_boolean(failed == 0));
    json_object_object_add(data, "atomic", json_object_new_boolean(0));
    json_object_object_add(data, "partial", json_object_new_boolean(1));
    json_object_object_add(data, "partially_applied",
                           json_object_new_boolean(succeeded > 0 && (failed > 0 || skipped > 0)));
    json_object_object_add(data, "semantics", json_object_new_string("ordered_single_item_transactions"));
    json_object_object_add(data, "stop_on_error", json_object_new_boolean(stop_on_error));
    json_object_object_add(data, "attempted", json_object_new_int(succeeded + failed));
    json_object_object_add(data, "succeeded", json_object_new_int(succeeded));
    json_object_object_add(data, "failed", json_object_new_int(failed));
    json_object_object_add(data, "skipped", json_object_new_int(skipped));
    json_object_object_add(data, "items", results);
    if (failed > 0)
        json_object_object_add(data, "error", json_object_new_string("partial_apply_failed"));
    json_object_put(preview);
    if (preview_response) json_object_put(preview_response);
    return jmx_gen_api_response_data(failed == 0 ? API_CODE_SUCCESS : API_CODE_ERROR, data);
}

struct json_object *jmx_netconfig_wan_batch_preview(struct json_object *payload,
                                                     const char *management_client_ip)
{
    return nc_network_batch_preview("wan", payload, management_client_ip);
}

struct json_object *jmx_netconfig_wan_batch_apply(struct json_object *payload,
                                                   const char *management_client_ip)
{
    return nc_network_batch_apply("wan", payload, management_client_ip);
}

struct json_object *jmx_netconfig_lan_batch_preview(struct json_object *payload,
                                                     const char *management_client_ip)
{
    return nc_network_batch_preview("lan", payload, management_client_ip);
}

struct json_object *jmx_netconfig_lan_batch_apply(struct json_object *payload,
                                                   const char *management_client_ip)
{
    return nc_network_batch_apply("lan", payload, management_client_ip);
}
