    return nc_lxc_write_disabled(out,
        "lxc_snapshot_async_job_validate_readback_rollback_pending");
}

int jmx_lxc_container_snapshot_restore(const char *name, const char *snap, struct json_object *cfg, struct json_object *out)
{
    (void)name;
    (void)snap;
    (void)cfg;
    return nc_lxc_write_disabled(out,
        "lxc_snapshot_restore_async_job_validate_readback_rollback_pending");
}



int jmx_lxc_container_config_set(const char *name, struct json_object *cfg, struct json_object *out)
{
    return jmx_lxc_config_document_save(name,cfg,out);
}



int jmx_lxc_config_set(struct json_object *cfg, struct json_object *out)
{
    return jmx_lxc_settings_save(cfg,out);
}









/* ═══ Client Rate Limit ═══ */
/* Per-client upload/download speed limit via tc + nft marks.
 * Uses ifb0 (intermediate functional block) for ingress shaping.
 */

#define NC_RATE_LIMIT_DIR "/etc/dreamingwrt/client_rate_limits"
#define NC_RATE_LIMIT_LAN_DEV "br-lan"
#define NC_RATE_LIMIT_IFB_DEV "ifb0"
#define NC_RATE_LIMIT_PARENT_RATE "10000mbit"
#define NC_RATE_LIMIT_INGRESS_PREF 9001
#define NC_RATE_LIMIT_STATE_FILE "/var/run/dreamingwrt-client-rate-limit.state"
#define NC_RATE_LIMIT_RUNTIME_DIR "/run/dreamingwrt"
#define NC_RATE_LIMIT_APPLY_TIMEOUT_MS 30000
#define NC_RATE_LIMIT_PROTO_ANY 0
#define NC_RATE_LIMIT_PROTO_TCP 6
#define NC_RATE_LIMIT_PROTO_UDP 17
#define NC_RATE_LIMIT_PROTO_ICMP 1
#define NC_RATE_LIMIT_PROTO_ICMPV6 58
#define NC_RATE_LIMIT_IP_MAX 63
#define NC_RATE_LIMIT_REMARK_MAX 127
#define NC_RATE_LIMIT_PROTOCOL_MAX 63
#define NC_RATE_LIMIT_KBPS_MAX 10000000

static int nc_rate_limit_ensure_dir(void) {
    return mkdir(NC_RATE_LIMIT_DIR, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static FILE *nc_rate_limit_open_script(void)
{
    struct stat st;
    int dirfd = -1;
    int fd = -1;
    int attempt;
    char name[96];

    if (mkdir(NC_RATE_LIMIT_RUNTIME_DIR, 0700) != 0 && errno != EEXIST)
        return NULL;
    dirfd = open(NC_RATE_LIMIT_RUNTIME_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0 || fstat(dirfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        goto out;

    for (attempt = 0; attempt < 32; attempt++) {
        snprintf(name, sizeof(name), ".client-rate-limit-%ld-%lld-%d",
                 (long)getpid(), (long long)nc_now_s(), attempt);
        fd = openat(dirfd, name,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd >= 0) {
            if (unlinkat(dirfd, name, 0) != 0) {
                close(fd);
                fd = -1;
                goto out;
            }
            break;
        }
        if (errno != EEXIST)
            break;
    }

out:
    if (dirfd >= 0)
        close(dirfd);
    if (fd < 0)
        return NULL;
    {
        FILE *fp = fdopen(fd, "w+");
        if (!fp)
            close(fd);
        return fp;
    }
}

static int nc_rate_limit_run_script(FILE *fp)
{
    pid_t pid;
    int fd;
    int status = 0;
    int64_t deadline;

    if (!fp)
        return -1;
    fd = fileno(fp);
    if (fd < 0 || fflush(fp) != 0 || fsync(fd) != 0 || lseek(fd, 0, SEEK_SET) < 0) {
        fclose(fp);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        fclose(fp);
        return -1;
    }
    if (pid == 0) {
        if (dup2(fd, STDIN_FILENO) < 0)
            _exit(126);
        fclose(fp);
        clearenv();
        setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
        execl("/bin/sh", "sh", "-s", (char *)NULL);
        _exit(127);
    }

    fclose(fp);
    deadline = nc_container_monotonic_ms() + NC_RATE_LIMIT_APPLY_TIMEOUT_MS;
    for (;;) {
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid)
            break;
        if (waited < 0 && errno != EINTR)
            return -1;
        if (nc_container_monotonic_ms() >= deadline) {
            (void)kill(pid, SIGTERM);
            usleep(200000);
            (void)kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            return -1;
        }
        usleep(20000);
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int nc_rate_limit_mac_ok(const char *mac)
{
    int i;
    unsigned int first = 0;

    if (!mac || strlen(mac) != 17)
        return 0;
    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (mac[i] != ':')
                return 0;
        } else if (!isxdigit((unsigned char)mac[i])) {
            return 0;
        }
    }
    if (sscanf(mac, "%2x", &first) != 1 || (first & 1U))
        return 0;
    return strcasecmp(mac, "00:00:00:00:00:00") &&
           strcasecmp(mac, "ff:ff:ff:ff:ff:ff");
}

static int nc_rate_limit_protocol_id(const char *proto)
{
    if (!proto || !proto[0] || !strcmp(proto, "任意") || !strcmp(proto, "全部") ||
        !strcasecmp(proto, "any") || !strcasecmp(proto, "all") || !strcmp(proto, "*"))
        return NC_RATE_LIMIT_PROTO_ANY;
    if (!strcasecmp(proto, "tcp")) return NC_RATE_LIMIT_PROTO_TCP;
    if (!strcasecmp(proto, "udp")) return NC_RATE_LIMIT_PROTO_UDP;
    if (!strcasecmp(proto, "icmp")) return NC_RATE_LIMIT_PROTO_ICMP;
    if (!strcasecmp(proto, "icmpv6") || !strcasecmp(proto, "ipv6-icmp")) return NC_RATE_LIMIT_PROTO_ICMPV6;
    return -1;
}

static int nc_rate_limit_ip_ok(const char *ip)
{
    struct in_addr v4;
    struct in6_addr v6;

    if (!ip || !ip[0])
        return 1;
    return inet_pton(AF_INET, ip, &v4) == 1 || inet_pton(AF_INET6, ip, &v6) == 1;
}

static int nc_rate_limit_json_string(struct json_object *cfg, const char *name,
                                     int required, size_t max_len,
                                     const char *missing_default, const char **value,
                                     const char **reason, const char **field)
{
    struct json_object *item = NULL;
    const char *text;
    size_t text_len;

    if (!json_object_object_get_ex(cfg, name, &item)) {
        if (required) {
            *reason = "missing_required_field";
            *field = name;
            return -1;
        }
        *value = missing_default;
        return 0;
    }
    if (!item || !json_object_is_type(item, json_type_string)) {
        *reason = "invalid_field_type";
        *field = name;
        return -1;
    }
    text = json_object_get_string(item);
    text_len = (size_t)json_object_get_string_len(item);
    if (!text || text_len > max_len) {
        *reason = "field_too_long";
        *field = name;
        return -1;
    }
    if (strlen(text) != text_len) {
        *reason = "invalid_field_value";
        *field = name;
        return -1;
    }
    *value = text;
    return 0;
}

static int nc_rate_limit_json_kbps(struct json_object *cfg, const char *name,
                                   int *value, const char **reason, const char **field)
{
    struct json_object *item = NULL;
    int64_t number;

    if (!json_object_object_get_ex(cfg, name, &item)) {
        *value = 0;
        return 0;
    }
    if (!item || !json_object_is_type(item, json_type_int)) {
        *reason = "invalid_field_type";
        *field = name;
        return -1;
    }
    number = json_object_get_int64(item);
    if (number < 0 || number > NC_RATE_LIMIT_KBPS_MAX) {
        *reason = "field_out_of_range";
        *field = name;
        return -1;
    }
    *value = (int)number;
    return 0;
}

static int nc_rate_limit_json_object(struct json_object *cfg,
                                     const char **reason, const char **field)
{
    if (cfg && json_object_is_type(cfg, json_type_object))
        return 0;
    *reason = "invalid_field_type";
    *field = "data";
    return -1;
}

static void nc_rate_limit_emit_filter(FILE *fp, const char *dev_var, const char *parent,
                                      int major, int pref_base, int classid,
                                      const char *mac, const char *direction, int proto)
{
    const char *mac_dir = (!strcmp(direction, "src")) ? "src" : "dst";

    if (proto == NC_RATE_LIMIT_PROTO_ANY) {
        fprintf(fp,
                "tc filter replace dev \"$%s\" parent %s protocol all pref %d u32 match ether %s %s flowid %d:%d\n",
                dev_var, parent, pref_base, mac_dir, mac, major, classid);
        return;
    }

    if (proto == NC_RATE_LIMIT_PROTO_TCP || proto == NC_RATE_LIMIT_PROTO_UDP || proto == NC_RATE_LIMIT_PROTO_ICMP) {
        fprintf(fp,
                "tc filter replace dev \"$%s\" parent %s protocol ip pref %d u32 match ether %s %s match ip protocol %d 0xff flowid %d:%d\n",
                dev_var, parent, pref_base, mac_dir, mac, proto, major, classid);
    }
    if (proto == NC_RATE_LIMIT_PROTO_TCP || proto == NC_RATE_LIMIT_PROTO_UDP ||
        proto == NC_RATE_LIMIT_PROTO_ICMPV6) {
        fprintf(fp,
                "tc filter replace dev \"$%s\" parent %s protocol ipv6 pref %d u32 match ether %s %s match ip6 protocol %d 0xff flowid %d:%d\n",
                dev_var, parent, pref_base + 5000, mac_dir, mac, proto, major, classid);
    }
}

static void nc_rate_limit_emit_runtime_cleanup(FILE *fp)
{
    fprintf(fp, "if [ -r \"$STATE_FILE\" ]; then\n");
    fprintf(fp, "  LAN_CLSACT_OWNED=0; IFB_EXISTED=1; IFB_WAS_UP=1\n");
    fprintf(fp, "  . \"$STATE_FILE\"\n");
    fprintf(fp, "  CLEANUP_CONFLICT=0; IFB_ROOT_OWNED=0; LAN_ROOT_OWNED=0\n");
    fprintf(fp, "  IFB_ROOT=$(tc qdisc show dev \"$IFB_DEV\" root 2>/dev/null || true)\n");
    fprintf(fp, "  case \"$IFB_ROOT\" in *'qdisc htb 1:'*) IFB_ROOT_OWNED=1 ;; ''|*'qdisc noqueue '*|*'qdisc fq '*) ;; *) CLEANUP_CONFLICT=1 ;; esac\n");
    fprintf(fp, "  LAN_ROOT=$(tc qdisc show dev \"$LAN_DEV\" root 2>/dev/null || true)\n");
    fprintf(fp, "  case \"$LAN_ROOT\" in *'qdisc htb 2:'*) LAN_ROOT_OWNED=1 ;; ''|*'qdisc noqueue '*) ;; *) CLEANUP_CONFLICT=1 ;; esac\n");
    fprintf(fp, "  [ \"$CLEANUP_CONFLICT\" = 0 ] || exit 15\n");
    fprintf(fp, "  [ \"$IFB_ROOT_OWNED\" = 0 ] || tc qdisc del dev \"$IFB_DEV\" root\n");
    fprintf(fp, "  [ \"$LAN_ROOT_OWNED\" = 0 ] || tc qdisc del dev \"$LAN_DEV\" root\n");
    fprintf(fp, "  tc filter del dev \"$LAN_DEV\" ingress pref %d 2>/dev/null || true\n",
            NC_RATE_LIMIT_INGRESS_PREF);
    fprintf(fp, "  if [ \"$LAN_CLSACT_OWNED\" = 1 ] && "
                "! tc filter show dev \"$LAN_DEV\" ingress 2>/dev/null | grep -q . && "
                "! tc filter show dev \"$LAN_DEV\" egress 2>/dev/null | grep -q .; then\n");
    fprintf(fp, "    tc qdisc del dev \"$LAN_DEV\" clsact 2>/dev/null || true\n");
    fprintf(fp, "  fi\n");
    fprintf(fp, "  if [ \"$IFB_EXISTED\" = 0 ]; then\n");
    fprintf(fp, "    ip link set \"$IFB_DEV\" down 2>/dev/null || true\n");
    fprintf(fp, "    ip link del \"$IFB_DEV\" 2>/dev/null || true\n");
    fprintf(fp, "  elif [ \"$IFB_WAS_UP\" = 0 ]; then\n");
    fprintf(fp, "    ip link set \"$IFB_DEV\" down 2>/dev/null || true\n");
    fprintf(fp, "  else\n");
    fprintf(fp, "    ip link set \"$IFB_DEV\" up 2>/dev/null || true\n");
    fprintf(fp, "  fi\n");
    fprintf(fp, "  rm -f \"$STATE_FILE\"\n");
    fprintf(fp, "fi\n");
}

static int nc_rate_limit_apply_all(void) {
    FILE *fp = nc_rate_limit_open_script();
    if (!fp) return -1;
    int count = 0;
    int emitted_header = 0;
    DIR *dir;
    struct dirent *ent;

    fprintf(fp, "#!/bin/sh\n");
    fprintf(fp, "set -eu\n");
    fprintf(fp, "PATH=/sbin:/bin:/usr/sbin:/usr/bin\n");
    fprintf(fp, "LAN_DEV=${DW_CLIENT_LIMIT_LAN_DEV:-%s}\n", NC_RATE_LIMIT_LAN_DEV);
    fprintf(fp, "IFB_DEV=${DW_CLIENT_LIMIT_IFB_DEV:-%s}\n", NC_RATE_LIMIT_IFB_DEV);
    fprintf(fp, "PARENT_RATE=${DW_CLIENT_LIMIT_PARENT_RATE:-%s}\n", NC_RATE_LIMIT_PARENT_RATE);
    fprintf(fp, "STATE_FILE=${DW_CLIENT_LIMIT_STATE_FILE:-%s}\n", NC_RATE_LIMIT_STATE_FILE);
    fprintf(fp, "ip link show \"$LAN_DEV\" >/dev/null 2>&1 || exit 11\n");

    dir = opendir(NC_RATE_LIMIT_DIR);
    if (!dir) {
        nc_rate_limit_emit_runtime_cleanup(fp);
        fprintf(fp, "exit 0\n");
        return nc_rate_limit_run_script(fp);
    }
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char fpath[512];
        snprintf(fpath, sizeof(fpath), "%s/%s", NC_RATE_LIMIT_DIR, ent->d_name);
        FILE *lf = fopen(fpath, "r");
        if (!lf) continue;
        char mac[64] = "", ip[64] = "", remark[128] = "", proto_text[64] = "";
        int up = 0, down = 0, proto_id = NC_RATE_LIMIT_PROTO_ANY;
        char line[256];
        while (fgets(line, sizeof(line), lf)) {
            line[strcspn(line, "\r\n")] = 0;
            if (!strncmp(line, "mac=", 4)) JMX_STRBUF_COPY(mac, line+4);
            else if (!strncmp(line, "ip=", 3)) JMX_STRBUF_COPY(ip, line+3);
            else if (!strncmp(line, "up=", 3)) up = atoi(line+3);
            else if (!strncmp(line, "down=", 5)) down = atoi(line+5);
            else if (!strncmp(line, "protocol=", 9)) JMX_STRBUF_COPY(proto_text, line+9);
            else if (!strncmp(line, "remark=", 7)) JMX_STRBUF_COPY(remark, line+7);
        }
        fclose(lf);
        if (!mac[0] || !nc_rate_limit_mac_ok(mac)) continue;
        proto_id = nc_rate_limit_protocol_id(proto_text);
        if (proto_id < 0) continue;
        count++;
        if (!emitted_header) {
            fprintf(fp, "if [ ! -r \"$STATE_FILE\" ]; then\n");
            fprintf(fp, "  LAN_ROOT=$(tc qdisc show dev \"$LAN_DEV\" root 2>/dev/null)\n");
            fprintf(fp, "  case \"$LAN_ROOT\" in ''|*'qdisc noqueue '*) ;; *) exit 12 ;; esac\n");
            fprintf(fp, "  LAN_CLSACT_OWNED=1\n");
            fprintf(fp, "  tc qdisc show dev \"$LAN_DEV\" 2>/dev/null | grep -q 'qdisc clsact ' && LAN_CLSACT_OWNED=0\n");
            fprintf(fp, "  IFB_EXISTED=0; IFB_WAS_UP=0\n");
            fprintf(fp, "  if ip link show \"$IFB_DEV\" >/dev/null 2>&1; then\n");
            fprintf(fp, "    IFB_EXISTED=1\n");
            fprintf(fp, "    IFB_ROOT=$(tc qdisc show dev \"$IFB_DEV\" root 2>/dev/null)\n");
            fprintf(fp, "    case \"$IFB_ROOT\" in ''|*'qdisc noqueue '*|*'qdisc fq '*) ;; *) exit 13 ;; esac\n");
            fprintf(fp, "    tc filter show dev \"$IFB_DEV\" 2>/dev/null | grep -q . && exit 13\n");
            fprintf(fp, "    ip link show \"$IFB_DEV\" | sed -n 's/.*<\\([^>]*\\)>.*/\\1/p' | tr ',' '\\n' | grep -qx UP && IFB_WAS_UP=1\n");
            fprintf(fp, "  fi\n");
            fprintf(fp, "  tc filter show dev \"$LAN_DEV\" ingress pref %d 2>/dev/null | grep -q . && exit 12\n",
                    NC_RATE_LIMIT_INGRESS_PREF);
            fprintf(fp, "  printf 'LAN_CLSACT_OWNED=%%s\\nIFB_EXISTED=%%s\\nIFB_WAS_UP=%%s\\n' "
                        "\"$LAN_CLSACT_OWNED\" \"$IFB_EXISTED\" \"$IFB_WAS_UP\" >\"$STATE_FILE\" || exit 14\n");
            fprintf(fp, "else\n");
            fprintf(fp, "  LAN_ROOT=$(tc qdisc show dev \"$LAN_DEV\" root 2>/dev/null || true)\n");
            fprintf(fp, "  case \"$LAN_ROOT\" in ''|*'qdisc noqueue '*|*'qdisc htb 2:'*) ;; *) exit 15 ;; esac\n");
            fprintf(fp, "  IFB_ROOT=$(tc qdisc show dev \"$IFB_DEV\" root 2>/dev/null || true)\n");
            fprintf(fp, "  case \"$IFB_ROOT\" in ''|*'qdisc noqueue '*|*'qdisc htb 1:'*) ;; *) exit 15 ;; esac\n");
            fprintf(fp, "fi\n");
            fprintf(fp, "modprobe ifb 2>/dev/null || true\n");
            fprintf(fp, "modprobe sch_htb 2>/dev/null || true\n");
            fprintf(fp, "modprobe sch_ingress 2>/dev/null || true\n");
            fprintf(fp, "modprobe cls_u32 2>/dev/null || true\n");
            fprintf(fp, "modprobe cls_matchall 2>/dev/null || true\n");
            fprintf(fp, "modprobe act_mirred 2>/dev/null || true\n");
            fprintf(fp, "ip link show \"$IFB_DEV\" >/dev/null 2>&1 || ip link add \"$IFB_DEV\" type ifb\n");
            fprintf(fp, "ip link set \"$IFB_DEV\" up\n");
            fprintf(fp, "tc qdisc add dev \"$LAN_DEV\" clsact 2>/dev/null || true\n");
            fprintf(fp, "tc filter del dev \"$LAN_DEV\" ingress pref %d 2>/dev/null || true\n",
                    NC_RATE_LIMIT_INGRESS_PREF);
            fprintf(fp, "tc filter add dev \"$LAN_DEV\" ingress pref %d matchall action mirred egress redirect dev \"$IFB_DEV\"\n",
                    NC_RATE_LIMIT_INGRESS_PREF);
            fprintf(fp, "tc qdisc replace dev \"$IFB_DEV\" root handle 1: htb default 999\n");
            fprintf(fp, "tc class replace dev \"$IFB_DEV\" parent 1: classid 1:1 htb rate $PARENT_RATE ceil $PARENT_RATE\n");
            fprintf(fp, "tc class replace dev \"$IFB_DEV\" parent 1:1 classid 1:999 htb rate $PARENT_RATE ceil $PARENT_RATE\n");
            fprintf(fp, "tc qdisc replace dev \"$LAN_DEV\" root handle 2: htb default 999\n");
            fprintf(fp, "tc class replace dev \"$LAN_DEV\" parent 2: classid 2:1 htb rate $PARENT_RATE ceil $PARENT_RATE\n");
            fprintf(fp, "tc class replace dev \"$LAN_DEV\" parent 2:1 classid 2:999 htb rate $PARENT_RATE ceil $PARENT_RATE\n");
            emitted_header = 1;
        }
        int classid_up = 10 + count;
        int classid_down = 100 + count;
        if (up > 0) {
            fprintf(fp, "tc class replace dev \"$IFB_DEV\" parent 1:1 classid 1:%d htb rate %dkbit ceil %dkbit\n",
                    classid_up, up, up);
            nc_rate_limit_emit_filter(fp, "IFB_DEV", "1:", 1, 10 + count, classid_up, mac, "src", proto_id);
        }
        if (down > 0) {
            fprintf(fp, "tc class replace dev \"$LAN_DEV\" parent 2:1 classid 2:%d htb rate %dkbit ceil %dkbit\n",
                    classid_down, down, down);
            nc_rate_limit_emit_filter(fp, "LAN_DEV", "2:", 2, 10 + count, classid_down, mac, "dst", proto_id);
        }
        if (remark[0]) fprintf(fp, "# %s\n", remark);
    }
    closedir(dir);
    if (!count) {
        nc_rate_limit_emit_runtime_cleanup(fp);
    }
    fprintf(fp, "exit 0\n");
    return nc_rate_limit_run_script(fp);
}

int nc_client_rate_limit_set_ex(const char *mac, const char *ip,
                                 int upload_kbps, int download_kbps,
                                 const char *protocol, const char *remark) {
    int rc;
    int had_previous = 0;
    if (!nc_rate_limit_mac_ok(mac) || nc_rate_limit_protocol_id(protocol) < 0 ||
        !nc_rate_limit_ip_ok(ip) ||
        (ip && strlen(ip) > NC_RATE_LIMIT_IP_MAX) ||
        (protocol && strlen(protocol) > NC_RATE_LIMIT_PROTOCOL_MAX) ||
        (remark && strlen(remark) > NC_RATE_LIMIT_REMARK_MAX) ||
        upload_kbps < 0 || upload_kbps > NC_RATE_LIMIT_KBPS_MAX ||
        download_kbps < 0 || download_kbps > NC_RATE_LIMIT_KBPS_MAX ||
        (remark && (strchr(remark, '\r') || strchr(remark, '\n'))))
        return -1;
    if (nc_rate_limit_ensure_dir() != 0) return -1;
    char safe[64];
    snprintf(safe, sizeof(safe), "%s", mac);
    for (char *p = safe; *p; p++) if (*p == ':') *p = '-';
    char fpath[512];
    char rollback_path[576];
    snprintf(fpath, sizeof(fpath), "%s/%s", NC_RATE_LIMIT_DIR, safe);
    snprintf(rollback_path, sizeof(rollback_path), "%s/.rollback-%s-%ld",
             NC_RATE_LIMIT_DIR, safe, (long)getpid());
    unlink(rollback_path);
    if (rename(fpath, rollback_path) == 0)
        had_previous = 1;
    else if (errno != ENOENT)
        return -1;
    FILE *fp = fopen(fpath, "w");
    if (!fp) {
        if (had_previous)
            (void)rename(rollback_path, fpath);
        return -1;
    }
    fprintf(fp, "mac=%s\n", mac);
    fprintf(fp, "ip=%s\n", ip ? ip : "");
    fprintf(fp, "up=%d\n", upload_kbps);
    fprintf(fp, "down=%d\n", download_kbps);
    fprintf(fp, "protocol=%s\n", protocol ? protocol : "");
    fprintf(fp, "remark=%s\n", remark ? remark : "");
    if (fclose(fp) != 0) {
        unlink(fpath);
        if (had_previous)
            (void)rename(rollback_path, fpath);
        return -1;
    }
    rc = nc_rate_limit_apply_all();
    if (rc != 0) {
        unlink(fpath);
        if (had_previous)
            (void)rename(rollback_path, fpath);
        (void)nc_rate_limit_apply_all();
    } else if (had_previous)
        unlink(rollback_path);
    return rc;
}

int nc_client_rate_limit_set(const char *mac, const char *ip,
                              int upload_kbps, int download_kbps,
                              const char *remark) {
    return nc_client_rate_limit_set_ex(mac, ip, upload_kbps, download_kbps, "", remark);
}

int nc_client_rate_limit_delete(const char *mac) {
    int had_previous = 0;
    int apply_rc;

    if (!nc_rate_limit_mac_ok(mac)) return -1;
    char safe[64];
    snprintf(safe, sizeof(safe), "%s", mac);
    for (char *p = safe; *p; p++) if (*p == ':') *p = '-';
    char fpath[512];
    char rollback_path[576];
    snprintf(fpath, sizeof(fpath), "%s/%s", NC_RATE_LIMIT_DIR, safe);
    snprintf(rollback_path, sizeof(rollback_path), "%s/.rollback-%s-%ld",
             NC_RATE_LIMIT_DIR, safe, (long)getpid());
    unlink(rollback_path);
    if (rename(fpath, rollback_path) == 0)
        had_previous = 1;
    else if (errno != ENOENT)
        return -1;
    apply_rc = nc_rate_limit_apply_all();
    if (apply_rc != 0) {
        if (had_previous)
            (void)rename(rollback_path, fpath);
        (void)nc_rate_limit_apply_all();
    } else if (had_previous)
        unlink(rollback_path);
    return apply_rc;
}

int nc_client_rate_limit_set_json(struct json_object *cfg,
                                  const char **reason, const char **field)
{
    const char *mac = NULL;
    const char *ip = "";
    const char *remark = "app rate limit";
    const char *local_reason = "operation_failed";
    const char *local_field = "";
    int upload_kbps = 0;
    int download_kbps = 0;
    int rc;

    if (!reason)
        reason = &local_reason;
    if (!field)
        field = &local_field;
    *reason = "";
    *field = "";
    if (nc_rate_limit_json_object(cfg, reason, field) != 0 ||
        nc_rate_limit_json_string(cfg, "mac", 1, 17, NULL, &mac, reason, field) != 0 ||
        nc_rate_limit_json_string(cfg, "ip", 0, NC_RATE_LIMIT_IP_MAX, "", &ip,
                                  reason, field) != 0 ||
        nc_rate_limit_json_string(cfg, "remark", 0, NC_RATE_LIMIT_REMARK_MAX,
                                  "app rate limit", &remark, reason, field) != 0 ||
        nc_rate_limit_json_kbps(cfg, "upload_kbps", &upload_kbps, reason, field) != 0 ||
        nc_rate_limit_json_kbps(cfg, "download_kbps", &download_kbps, reason, field) != 0)
        return -1;
    if (!nc_rate_limit_mac_ok(mac)) {
        *reason = "invalid_field_value";
        *field = "mac";
        return -1;
    }
    if (!nc_rate_limit_ip_ok(ip)) {
        *reason = "invalid_field_value";
        *field = "ip";
        return -1;
    }
    if (strchr(remark, '\r') || strchr(remark, '\n')) {
        *reason = "invalid_field_value";
        *field = "remark";
        return -1;
    }
    rc = nc_client_rate_limit_set(mac, ip, upload_kbps, download_kbps, remark);
    if (rc != 0) {
        *reason = "runtime_apply_failed";
        *field = "runtime";
    }
    return rc;
}

int nc_client_rate_limit_delete_json(struct json_object *cfg,
                                     const char **reason, const char **field)
{
    const char *mac = NULL;
    const char *local_reason = "operation_failed";
    const char *local_field = "";
    int rc;

    if (!reason)
        reason = &local_reason;
    if (!field)
        field = &local_field;
    *reason = "";
    *field = "";
    if (nc_rate_limit_json_object(cfg, reason, field) != 0 ||
        nc_rate_limit_json_string(cfg, "mac", 1, 17, NULL, &mac, reason, field) != 0)
        return -1;
    if (!nc_rate_limit_mac_ok(mac)) {
        *reason = "invalid_field_value";
        *field = "mac";
        return -1;
    }
    rc = nc_client_rate_limit_delete(mac);
    if (rc != 0) {
        *reason = "runtime_apply_failed";
        *field = "runtime";
    }
    return rc;
}

/* ═══ Client Control Rule Schedule Runtime ═══ */

struct nc_client_control_rule_row {
    char id[96];
    char mac[40];
    char control_type[64];
    char schedule_mode[48];
    char days_json[512];
    char days_text[256];
    char start_time[24];
    char end_time[24];
    char limit_mode[64];
    char up_unit[32];
    char down_unit[32];
    char line[96];
    char protocol[64];
    char note[256];
    char prev_apply_state[64];
    int enabled;
    int up_limit;
    int down_limit;
    int up_kbps;
    int down_kbps;
    int desired_active;
    int selected;
    int runtime_supported;
    int runtime_apply;
    int last_runtime_enabled;
    int64_t updated_at;
    int64_t last_runtime_apply_at;
    char apply_state[64];
    char apply_reason[192];
};

static int nc_control_limit_to_kbps(int value, const char *unit)
{
    if (value <= 0) return 0;
    if (!unit || !unit[0]) return value * 8;
    if (!strcmp(unit, "Kbps") || !strcmp(unit, "kbps") ||
        !strcmp(unit, "Kb/s") || !strcmp(unit, "kb/s") ||
        !strcmp(unit, "Kbit/s") || !strcmp(unit, "kbit/s"))
        return value;
    if (!strcmp(unit, "Mbps") || !strcmp(unit, "mbps") ||
        !strcmp(unit, "Mb/s") || !strcmp(unit, "mb/s") ||
        !strcmp(unit, "Mbit/s") || !strcmp(unit, "mbit/s"))
        return value * 1024;
    if (!strcmp(unit, "MB/s") || !strcmp(unit, "MBps") ||
        !strcmp(unit, "MByte/s") || !strcmp(unit, "MBytes/s") ||
        !strcasecmp(unit, "MiB/s"))
        return value * 8 * 1024;
    return value * 8;
}

static int nc_control_parse_hhmm(const char *s, int def_min)
{
    int h = 0, m = 0;
    char tail = 0;
    if (!s || !s[0])
        return def_min;
    if (sscanf(s, "%d:%d%c", &h, &m, &tail) < 2)
        return def_min;
    if (h < 0 || h > 23 || m < 0 || m > 59)
        return def_min;
    return h * 60 + m;
}

static int nc_control_blob_contains_token(const char *blob, const char *token)
{
    if (!blob || !blob[0] || !token || !token[0])
        return 0;
    return strstr(blob, token) != NULL;
}

static int nc_control_day_matches(const char *days_json, const char *days_text, int wday)
{
    const char *zh[] = { "日", "一", "二", "三", "四", "五", "六" };
    const char *en_short[] = { "sun", "mon", "tue", "wed", "thu", "fri", "sat" };
    const char *en_long[] = { "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday" };
    char num1[4];
    char num0[4];
    char hay[1024];
    char lower[1024];
    size_t i;

    if ((!days_json || !days_json[0] || !strcmp(days_json, "[]")) &&
        (!days_text || !days_text[0]))
        return 1;
    snprintf(num1, sizeof(num1), "%d", wday == 0 ? 7 : wday);
    snprintf(num0, sizeof(num0), "%d", wday);
    snprintf(hay, sizeof(hay), "%s %s", days_json ? days_json : "", days_text ? days_text : "");
    for (i = 0; i + 1 < sizeof(lower) && hay[i]; i++)
        lower[i] = (char)tolower((unsigned char)hay[i]);
    lower[i] = 0;

    if (nc_control_blob_contains_token(hay, zh[wday]) ||
        (wday == 0 && (nc_control_blob_contains_token(hay, "天") ||
                       nc_control_blob_contains_token(hay, "周日") ||
                       nc_control_blob_contains_token(hay, "星期日"))) ||
        nc_control_blob_contains_token(lower, en_short[wday]) ||
        nc_control_blob_contains_token(lower, en_long[wday]) ||
        nc_control_blob_contains_token(hay, num1) ||
        nc_control_blob_contains_token(hay, num0))
        return 1;
    return 0;
}

static int nc_control_rule_should_be_active(struct nc_client_control_rule_row *r,
                                            const struct tm *lt)
{
    int now_min;
    int start_min;
    int end_min;

    if (!r || !r->enabled)
        return 0;
    if (strcasecmp(r->schedule_mode, "always") &&
        strcasecmp(r->schedule_mode, "all") &&
        strcasecmp(r->schedule_mode, "daily") &&
        strcmp(r->schedule_mode, "每天") &&
        strcmp(r->schedule_mode, "每日") &&
        strcmp(r->schedule_mode, "永久") &&
        strcmp(r->schedule_mode, ""))
    {
        if (!nc_control_day_matches(r->days_json, r->days_text, lt->tm_wday))
            return 0;
    }

    now_min = lt->tm_hour * 60 + lt->tm_min;
    start_min = nc_control_parse_hhmm(r->start_time, 0);
    end_min = nc_control_parse_hhmm(r->end_time, 23 * 60 + 59);
    if (start_min == end_min)
        return 1;
    if (start_min < end_min)
        return now_min >= start_min && now_min <= end_min;
    return now_min >= start_min || now_min <= end_min;
}

static int nc_control_rule_needs_apply(struct nc_client_control_rule_row *r, int desired_enabled, int64_t now)
{
    if (!r)
        return 0;
    if (r->last_runtime_enabled != desired_enabled)
        return 1;
    if (r->last_runtime_apply_at <= 0 || r->last_runtime_apply_at < r->updated_at)
        return 1;
    /* Periodic reconciliation after boot/network reload without hammering tc/nft every tick. */
    if (now - r->last_runtime_apply_at > 300)
        return 1;
    return 0;
}

static int nc_control_update_rule_runtime(struct nc_client_control_rule_row *r,
                                          int runtime_enabled,
                                          int64_t now)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!r || nc_prepare(&st,
        "UPDATE client_control_rules SET runtime_apply=?1,apply_state=?2,apply_reason=?3,"
        "last_runtime_enabled=?4,last_runtime_apply_at=?5,last_runtime_reason=?6 "
        "WHERE id=?7") != 0)
        return -1;
    sqlite3_bind_int(st, 1, r->runtime_apply ? 1 : 0);
    sqlite3_bind_text(st, 2, r->apply_state, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, r->apply_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 4, runtime_enabled);
    sqlite3_bind_int64(st, 5, now);
    sqlite3_bind_text(st, 6, r->apply_reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, r->id, -1, SQLITE_TRANSIENT);
    if (nc_step_done(st) == 0)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

int jmx_client_control_schedule_tick(void)
{
