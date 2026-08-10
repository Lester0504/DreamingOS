
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include "../jmx.h"
#include "check_main.h"

#define INTERNET_CHECK_INTERVAL 30
#define LOG_DIR_PATH "/tmp/log"
#define LOG_DIR_MAX_SIZE_KB 10240
#define LOG_DIR_TARGET_SIZE_KB 8192
#define LOG_DIR_CLEANUP_MAX_PASSES 128
#define WAN_HEALTH_MAX_WANS 8
#define WAN_HEALTH_NAME_LEN 32
#define WAN_HEALTH_DEVICE_LEN 64
#define WAN_HEALTH_PROTO_LEN 16
#define WAN_HEALTH_REASON_LEN 32
#define WAN_HEALTH_TARGET_LEN 64

typedef struct {
    char name[WAN_HEALTH_NAME_LEN];
    char device[WAN_HEALTH_DEVICE_LEN];
    char proto[WAN_HEALTH_PROTO_LEN];
    char target[WAN_HEALTH_TARGET_LEN];
    char reason[WAN_HEALTH_REASON_LEN];
    int disabled;
    int checked;
    int online;
    int latency_ms;
    /*
     * probe_loss_pct is the ping result. It is a 3-packet sample, so its only
     * possible values are 0/33/67/100 and it cannot express a line losing a few
     * percent. It is kept for online/RTT judgement and reported under its own
     * name; it must not be published as the line's packet loss.
     */
    int probe_loss_pct;
    int probe_packets_sent;
    /*
     * Real loss comes from the interface counters, split by direction:
     *   down = rx_drop / rx_packets, up = tx_drop / tx_packets
     * measured as a delta between two samples of /proc/net/dev.
     */
    int counters_valid;
    char counter_ifname[WAN_HEALTH_DEVICE_LEN];
    double up_loss_pct;
    double down_loss_pct;
    uint64_t rx_packets_delta;
    uint64_t rx_drops_delta;
    uint64_t tx_packets_delta;
    uint64_t tx_drops_delta;
    int64_t counter_window_sec;
} health_wan_state_t;

/*
 * Per-interface counter baseline, so a delta can be taken between rounds.
 *
 * The first round after start has no baseline and therefore no loss figure;
 * that case reports null rather than 0, because "no sample yet" and "no loss"
 * are different statements.
 */
typedef struct {
    char ifname[WAN_HEALTH_DEVICE_LEN];
    int used;
    int have_baseline;
    uint64_t rx_packets;
    uint64_t rx_drops;
    uint64_t tx_packets;
    uint64_t tx_drops;
    int64_t ts;
} health_netdev_baseline_t;

static health_netdev_baseline_t g_netdev_baselines[WAN_HEALTH_MAX_WANS];

static struct {
    u_int32_t last_exec_time;    
    int internet;
    int checked;
} g_internet_check_state = {
    .internet = 1,
    .checked = 0,
};

static void health_publish_status_file(FILE *fp, const char *tmp_path,
                                       const char *final_path)
{
    int err = 0;

    if (!fp || !tmp_path || !final_path)
        return;
    if (fflush(fp) != 0)
        err = errno ? errno : EIO;
    if (!err && ferror(fp))
        err = errno ? errno : EIO;
    if (fclose(fp) != 0 && !err)
        err = errno ? errno : EIO;
    if (!err && rename(tmp_path, final_path) == 0)
        return;
    if (!err)
        err = errno ? errno : EIO;
    LOG_WARN("healthd: failed to update %s: %s\n",
             final_path, strerror(err));
    unlink(tmp_path);
}

static void health_write_status(void)
{
    char tmp_path[128];
    FILE *fp;

    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", JMX_HEALTH_STATUS_PATH) >=
        (int)sizeof(tmp_path))
        return;

    fp = fopen(tmp_path, "w");
    if (!fp)
        return;

    fprintf(fp, "internet=%d\nchecked=%d\nupdated_at=%u\n",
            g_internet_check_state.internet ? 1 : 0,
            g_internet_check_state.checked ? 1 : 0,
            g_internet_check_state.last_exec_time);
    health_publish_status_file(fp, tmp_path, JMX_HEALTH_STATUS_PATH);
}

static int resolve_hostname(const char *host, char *ip_str, size_t ip_str_len) {
    struct addrinfo hints, *result = NULL, *rp = NULL;
    int ret = -1;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    ret = getaddrinfo(host, NULL, &hints, &result);
    if (ret != 0) {
        LOG_DEBUG("check_tcp_connect: getaddrinfo() failed for %s: %s\n", host, gai_strerror(ret));
        return -1;
    }
    

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)rp->ai_addr;
            if (inet_ntop(AF_INET, &sin->sin_addr, ip_str, ip_str_len) != NULL) {
                ret = 0;
                break;
            }
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)rp->ai_addr;
            if (inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, ip_str_len) != NULL) {
                ret = 0;
                break;
            }
        }
    }
    
    freeaddrinfo(result);
    
    if (ret != 0) {
        LOG_DEBUG("check_tcp_connect: failed to resolve %s to an IP address\n", host);
        return -1;
    }
    
    LOG_DEBUG("check_tcp_connect: resolved %s to %s\n", host, ip_str);
    return 0;
}


static int check_tcp_connect(const char *host, int port, int timeout_sec) {
    int sockfd = -1;
    struct sockaddr_storage server_addr;
    struct timeval timeout;
    int flags;
    int result = -1;
    char ip_str[INET6_ADDRSTRLEN] = {0};
    const char *target_ip = host;
    int target_family = AF_INET;
    
    LOG_DEBUG("check_tcp_connect: host=%s, port=%d, timeout_sec=%d\n", host, port, timeout_sec);
    

    if (inet_pton(AF_INET, host, &((struct sockaddr_in *)&server_addr)->sin_addr) <= 0 &&
        inet_pton(AF_INET6, host, &((struct sockaddr_in6 *)&server_addr)->sin6_addr) <= 0) {

        if (resolve_hostname(host, ip_str, sizeof(ip_str)) != 0) {
            LOG_DEBUG("check_tcp_connect: failed to resolve hostname %s\n", host);
            return -1;
        }
        target_ip = ip_str;
    }
    

    memset(&server_addr, 0, sizeof(server_addr));
    if (inet_pton(AF_INET, target_ip, &((struct sockaddr_in *)&server_addr)->sin_addr) > 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&server_addr;
        target_family = AF_INET;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
    } else if (inet_pton(AF_INET6, target_ip, &((struct sockaddr_in6 *)&server_addr)->sin6_addr) > 0) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&server_addr;
        target_family = AF_INET6;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
    } else {
        LOG_DEBUG("check_tcp_connect: inet_pton() failed for %s\n", target_ip);
        return -1;
    }

    sockfd = socket(target_family, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOG_DEBUG("check_tcp_connect: socket() failed: %s\n", strerror(errno));
        return -1;
    }

    flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        close(sockfd);
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr,
                target_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) == 0) {

        result = 0;
    } else if (errno == EINPROGRESS) {

        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sockfd, &write_fds);
        
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;
        
        int select_result = select(sockfd + 1, NULL, &write_fds, NULL, &timeout);
        if (select_result > 0 && FD_ISSET(sockfd, &write_fds)) {

            int so_error = 0;
            socklen_t len = sizeof(so_error);
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0) {
                if (so_error == 0) {
                    LOG_DEBUG("check_tcp_connect: tcp connect to %s:%d success\n", host, port);
                    result = 0;  
                }
                else{
                    LOG_DEBUG("check_tcp_connect: tcp connect to %s:%d failed: %s\n", host, port, strerror(so_error));
                }
            }
            else{
                LOG_DEBUG("check_tcp_connect: getsockopt(SO_ERROR) failed for %s:%d: %s\n", host, port, strerror(errno));
            }
        }
    }
    
    close(sockfd);
    return result;
}


static int health_wait_child(pid_t pid, int timeout_sec)
{
    time_t deadline = time(NULL) + timeout_sec;
    int status;

    for (;;) {
        pid_t ret = waitpid(pid, &status, WNOHANG);

        if (ret == pid) {
            if (WIFEXITED(status))
                return WEXITSTATUS(status);
            if (WIFSIGNALED(status))
                return 128 + WTERMSIG(status);
            return -1;
        }
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (time(NULL) >= deadline) {
            kill(pid, SIGTERM);
            usleep(100000);
            if (waitpid(pid, &status, WNOHANG) == 0)
                kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
                ;
            return -1;
        }
        usleep(100000);
    }
}

static int check_ping(const char *host) {
    pid_t pid;

    if (!host || !host[0] || host[0] == '-')
        return -1;

    pid = fork();
    if (pid == 0) {
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        execl("/bin/ping", "ping", "-c", "1", "-W", "1", host, (char *)NULL);
        _exit(127);
    }
    if (pid < 0)
        return -1;
    return health_wait_child(pid, 3) == 0 ? 0 : -1;
}

static char *health_trim(char *s)
{
    char *end;

    if (!s)
        return s;
    while (isspace((unsigned char)*s))
        s++;
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

static void health_copy_string(char *dst, size_t dst_len, const char *src)
{
    size_t len;

    if (!dst || dst_len == 0)
        return;
    if (!src)
        src = "";
    len = strlen(src);
    if (len >= dst_len)
        len = dst_len - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

static int health_netdev_name_ok(const char *dev)
{
    const unsigned char *p = (const unsigned char *)dev;

    if (!dev || !dev[0] || dev[0] == '-' ||
        strlen(dev) >= WAN_HEALTH_DEVICE_LEN)
        return 0;
    for (; *p; p++) {
        if (isalnum(*p) || *p == '_' || *p == '-' ||
            *p == '.' || *p == ':')
            continue;
        return 0;
    }
    return 1;
}

static int health_parse_uci_value(const char *line, const char *keyword,
                                  char *out, size_t out_len)
{
    const char *p;
    const char *start;
    const char *end;
    size_t keyword_len;
    size_t value_len;

    if (!line || !keyword || !out || out_len == 0)
        return -1;
    p = line;
    while (isspace((unsigned char)*p))
        p++;
    keyword_len = strlen(keyword);
    if (strncmp(p, keyword, keyword_len) != 0 ||
        !isspace((unsigned char)p[keyword_len]))
        return -1;
    p += keyword_len;
    while (isspace((unsigned char)*p))
        p++;
    if (*p == '\'' || *p == '"') {
        int quote = *p++;

        start = p;
        while (*p && *p != quote)
            p++;
        end = p;
    } else {
        start = p;
        while (*p && !isspace((unsigned char)*p))
            p++;
        end = p;
    }
    if (end <= start)
        return -1;
    value_len = (size_t)(end - start);
    if (value_len >= out_len)
        value_len = out_len - 1;
    memcpy(out, start, value_len);
    out[value_len] = '\0';
    return 0;
}

static int health_sys_net_exists(const char *dev)
{
    char path[160];

    if (!health_netdev_name_ok(dev))
        return 0;
    if (snprintf(path, sizeof(path), "/sys/class/net/%s", dev) >=
        (int)sizeof(path))
        return 0;
    return access(path, F_OK) == 0;
}

static int health_read_sys_text(const char *dev, const char *leaf,
                                char *buf, size_t buf_len)
{
    char path[192];
    FILE *fp;
    char *trimmed;

    if (!health_netdev_name_ok(dev) || !leaf || !buf || buf_len == 0)
        return -1;
    if (snprintf(path, sizeof(path), "/sys/class/net/%s/%s", dev, leaf) >=
        (int)sizeof(path))
        return -1;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(buf, buf_len, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    trimmed = health_trim(buf);
    if (trimmed != buf)
        memmove(buf, trimmed, strlen(trimmed) + 1);
    return 0;
}

static int health_device_link_up(const char *dev)
{
    char value[32];

    if (!health_sys_net_exists(dev))
        return 0;
    if (health_read_sys_text(dev, "carrier", value, sizeof(value)) == 0)
        return atoi(value) > 0;
    if (health_read_sys_text(dev, "operstate", value, sizeof(value)) == 0)
        return !strcmp(value, "up") || !strcmp(value, "unknown");
    return 1;
}

static int health_lookup_interface_device(const char *iface,
                                          char *out, size_t out_len)
{
    FILE *fp;
    char line_buf[256];
    char candidate[WAN_HEALTH_DEVICE_LEN] = {0};
    int in_match = 0;

    if (!iface || !iface[0] || !out || out_len == 0)
        return -1;
    out[0] = '\0';
    fp = fopen("/etc/config/network", "r");
    if (!fp)
        return -1;
    while (fgets(line_buf, sizeof(line_buf), fp)) {
        char *line = health_trim(line_buf);
        char value[128];

        if (!line[0] || line[0] == '#')
            continue;
        if (health_parse_uci_value(line, "config interface", value, sizeof(value)) == 0) {
            if (in_match)
                break;
            in_match = strcmp(value, iface) == 0;
            candidate[0] = '\0';
            continue;
        }
        if (!in_match)
            continue;
        if (health_parse_uci_value(line, "option device", value, sizeof(value)) == 0 ||
            health_parse_uci_value(line, "option ifname", value, sizeof(value)) == 0) {
            health_copy_string(candidate, sizeof(candidate), value);
        }
    }
    fclose(fp);
    if (!candidate[0])
        return -1;
    health_copy_string(out, out_len, candidate);
    return 0;
}

static int health_resolve_device_ref(const char *iface, char *out,
                                     size_t out_len, int depth)
{
    char candidate[WAN_HEALTH_DEVICE_LEN];

    if (!iface || !iface[0] || !out || out_len == 0 || depth > 4)
        return -1;
    if (health_lookup_interface_device(iface, candidate, sizeof(candidate)) != 0)
        return -1;
    if (candidate[0] == '@' && candidate[1])
        return health_resolve_device_ref(candidate + 1, out, out_len, depth + 1);
    health_copy_string(out, out_len, candidate);
    return 0;
}

static void health_select_wan_device(health_wan_state_t *wan)
{
    char pppoe_dev[WAN_HEALTH_DEVICE_LEN];

    if (!wan || !wan->name[0])
        return;
    if (!strcmp(wan->proto, "pppoe")) {
        snprintf(pppoe_dev, sizeof(pppoe_dev), "pppoe-%s", wan->name);
        if (health_sys_net_exists(pppoe_dev)) {
            health_copy_string(wan->device, sizeof(wan->device), pppoe_dev);
            return;
        }
    }
    if (wan->device[0] && wan->device[0] != '@')
        return;
    if (wan->device[0] == '@' && wan->device[1]) {
        char resolved[WAN_HEALTH_DEVICE_LEN];

        if (health_resolve_device_ref(wan->device + 1, resolved,
                                      sizeof(resolved), 0) == 0 &&
            resolved[0]) {
            health_copy_string(wan->device, sizeof(wan->device), resolved);
            return;
        }
        health_copy_string(wan->device, sizeof(wan->device), wan->device + 1);
        return;
    }
    health_copy_string(wan->device, sizeof(wan->device), wan->name);
}

static int health_is_runtime_wan(const health_wan_state_t *wan)
{
    if (!wan || !wan->name[0])
        return 0;
    if (strncmp(wan->name, "wan", 3) != 0)
        return 0;
    if (!strcmp(wan->proto, "dhcpv6") || !strcmp(wan->proto, "none"))
        return 0;
    return 1;
}

static int health_store_wan(health_wan_state_t *wans, int *count,
                            const health_wan_state_t *cur)
{
    if (!wans || !count || !cur || !cur->name[0] || cur->disabled)
        return -1;
    if (!health_is_runtime_wan(cur))
        return -1;
    if (*count >= WAN_HEALTH_MAX_WANS)
        return -1;
    wans[*count] = *cur;
    health_select_wan_device(&wans[*count]);
    wans[*count].latency_ms = -1;
    wans[*count].probe_loss_pct = -1;
    wans[*count].probe_packets_sent = 0;
    /* -1 means "not sampled", distinct from a genuine 0% loss. */
    wans[*count].counters_valid = 0;
    wans[*count].up_loss_pct = -1;
    wans[*count].down_loss_pct = -1;
    health_copy_string(wans[*count].reason, sizeof(wans[*count].reason), "unmeasured");
    (*count)++;
    return 0;
}

static int health_load_wans(health_wan_state_t *wans, int max_wans)
{
    FILE *fp;
    char line_buf[256];
    health_wan_state_t cur;
    int in_iface = 0;
    int count = 0;

    if (!wans || max_wans <= 0)
        return 0;
    memset(&cur, 0, sizeof(cur));
    fp = fopen("/etc/config/network", "r");
    if (!fp)
        return 0;
    while (fgets(line_buf, sizeof(line_buf), fp)) {
        char *line = health_trim(line_buf);
        char value[128];

        if (!line[0] || line[0] == '#')
            continue;
        if (health_parse_uci_value(line, "config interface", value, sizeof(value)) == 0) {
            if (in_iface)
                health_store_wan(wans, &count, &cur);
            memset(&cur, 0, sizeof(cur));
            health_copy_string(cur.name, sizeof(cur.name), value);
            in_iface = 1;
            if (count >= max_wans)
                break;
            continue;
        }
        if (!in_iface)
            continue;
        if (health_parse_uci_value(line, "option device", value, sizeof(value)) == 0 ||
            health_parse_uci_value(line, "option ifname", value, sizeof(value)) == 0) {
            health_copy_string(cur.device, sizeof(cur.device), value);
        } else if (health_parse_uci_value(line, "option proto", value, sizeof(value)) == 0) {
            health_copy_string(cur.proto, sizeof(cur.proto), value);
        } else if (health_parse_uci_value(line, "option disabled", value, sizeof(value)) == 0) {
            cur.disabled = atoi(value) != 0;
        }
    }
    if (in_iface)
        health_store_wan(wans, &count, &cur);
    fclose(fp);
    return count;
}

static int health_parse_ping_output(const char *path, int *loss, int *latency)
{
    FILE *fp = fopen(path, "r");
    char line[256];
    int got_loss = 0;
    int got_latency = 0;

    if (!fp)
        return -1;
    if (loss)
        *loss = 100;
    if (latency)
        *latency = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = strstr(line, "% packet loss");

        if (p && loss) {
            char *start = p;
            double pct;

            while (start > line &&
                   (isdigit((unsigned char)start[-1]) || start[-1] == '.'))
                start--;
            if (sscanf(start, "%lf", &pct) == 1) {
                if (pct < 0)
                    pct = 0;
                if (pct > 100)
                    pct = 100;
                *loss = (int)(pct + 0.5);
                got_loss = 1;
            }
        }
        p = strstr(line, "min/avg/max");
        if (p && latency) {
            char *eq = strchr(line, '=');
            double avg;

            if (eq && sscanf(eq + 1, "%*f/%lf/%*f", &avg) == 1) {
                *latency = (int)(avg + 0.5);
                got_latency = 1;
            }
        }
    }
    fclose(fp);
    return (got_loss || got_latency) ? 0 : -1;
}

static int health_ping_bound(const char *dev, const char *target,
                             int *loss, int *latency)
{
    char tmp[] = "/tmp/dw_health_ping_XXXXXX";
    pid_t pid;
    int tmpfd;
    int rc;

    if (!target || !target[0] || target[0] == '-')
        return -1;
    tmpfd = mkstemp(tmp);
    if (tmpfd < 0)
        return -1;
    pid = fork();
    if (pid == 0) {
        int fd = open("/dev/null", O_RDONLY);

        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        dup2(tmpfd, STDOUT_FILENO);
        dup2(tmpfd, STDERR_FILENO);
        close(tmpfd);
        if (dev && dev[0] && health_netdev_name_ok(dev))
            execl("/bin/ping", "ping", "-I", dev, "-c", "3", "-W", "1", target, (char *)NULL);
        else
            execl("/bin/ping", "ping", "-c", "3", "-W", "1", target, (char *)NULL);
        _exit(127);
    }
    if (pid < 0) {
        close(tmpfd);
        unlink(tmp);
        return -1;
    }
    close(tmpfd);
    rc = health_wait_child(pid, 6);
    if (health_parse_ping_output(tmp, loss, latency) != 0) {
        if (loss)
            *loss = 100;
        if (latency)
            *latency = 0;
    }
    unlink(tmp);
    return rc == 0 ? 0 : -1;
}

/*
 * Reads rx/tx packet and drop counters for one interface from /proc/net/dev.
 *
 * Field order per line after the colon is:
 *   rx: bytes packets errs drop fifo frame compressed multicast
 *   tx: bytes packets errs drop fifo colls carrier compressed
 */
static int health_read_netdev_counters(const char *ifname, uint64_t *rx_packets,
                                       uint64_t *rx_drops, uint64_t *tx_packets,
                                       uint64_t *tx_drops)
{
    FILE *fp;
    char line[512];
    int found = 0;

    if (!ifname || !ifname[0])
        return -1;
    fp = fopen("/proc/net/dev", "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *colon = strchr(line, ':');
        char *name;
        unsigned long long rb, rp, re, rd, rf, rfr, rc, rm;
        unsigned long long tb, tp, te, td;

        if (!colon)
            continue;
        *colon = '\0';
        name = line;
        while (*name == ' ' || *name == '\t')
            name++;
        if (strcmp(name, ifname) != 0)
            continue;
        if (sscanf(colon + 1,
                   "%llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                   &rb, &rp, &re, &rd, &rf, &rfr, &rc, &rm,
                   &tb, &tp, &te, &td) == 12) {
            if (rx_packets) *rx_packets = (uint64_t)rp;
            if (rx_drops)   *rx_drops   = (uint64_t)rd;
            if (tx_packets) *tx_packets = (uint64_t)tp;
            if (tx_drops)   *tx_drops   = (uint64_t)td;
            found = 1;
        }
        break;
    }
    fclose(fp);
    return found ? 0 : -1;
}

static health_netdev_baseline_t *health_netdev_baseline_for(const char *ifname)
{
    int i;
    int free_slot = -1;

    for (i = 0; i < WAN_HEALTH_MAX_WANS; i++) {
        if (g_netdev_baselines[i].used &&
            !strcmp(g_netdev_baselines[i].ifname, ifname))
            return &g_netdev_baselines[i];
        if (!g_netdev_baselines[i].used && free_slot < 0)
            free_slot = i;
    }
    if (free_slot < 0)
        return NULL;
    memset(&g_netdev_baselines[free_slot], 0, sizeof(g_netdev_baselines[free_slot]));
    g_netdev_baselines[free_slot].used = 1;
    health_copy_string(g_netdev_baselines[free_slot].ifname,
                       sizeof(g_netdev_baselines[free_slot].ifname), ifname);
    return &g_netdev_baselines[free_slot];
}

/*
 * Computes real forwarding loss for one WAN from interface counter deltas.
 *
 * A negative delta means the counter wrapped, the interface was recreated, or
 * the WAN redialled. Those are clamped to zero and the round is treated as
 * having no sample instead of producing a nonsense percentage.
 */
static void health_sample_wan_counters(health_wan_state_t *wan)
{
    health_netdev_baseline_t *base;
    uint64_t rx_packets = 0, rx_drops = 0, tx_packets = 0, tx_drops = 0;
    int64_t now = (int64_t)time(NULL);

    if (!wan)
        return;
    wan->counters_valid = 0;
    wan->up_loss_pct = -1;
    wan->down_loss_pct = -1;
    wan->rx_packets_delta = 0;
    wan->rx_drops_delta = 0;
    wan->tx_packets_delta = 0;
    wan->tx_drops_delta = 0;
    wan->counter_window_sec = 0;
    wan->counter_ifname[0] = '\0';

    /*
     * Take counters from the WAN's actual egress device. For PPPoE the pppoe-*
     * interface carries the session's own counters, which differ from the
     * ethernet device underneath it, so the name is reported back for checking.
     */
    if (!wan->device[0] || !health_netdev_name_ok(wan->device))
        return;
    if (health_read_netdev_counters(wan->device, &rx_packets, &rx_drops,
                                    &tx_packets, &tx_drops) != 0)
        return;
    health_copy_string(wan->counter_ifname, sizeof(wan->counter_ifname),
                       wan->device);

    base = health_netdev_baseline_for(wan->device);
    if (!base)
        return;
    if (base->have_baseline &&
        rx_packets >= base->rx_packets && rx_drops >= base->rx_drops &&
        tx_packets >= base->tx_packets && tx_drops >= base->tx_drops &&
        now > base->ts) {
        uint64_t rx_p = rx_packets - base->rx_packets;
        uint64_t rx_d = rx_drops - base->rx_drops;
        uint64_t tx_p = tx_packets - base->tx_packets;
        uint64_t tx_d = tx_drops - base->tx_drops;

        wan->rx_packets_delta = rx_p;
        wan->rx_drops_delta = rx_d;
        wan->tx_packets_delta = tx_p;
        wan->tx_drops_delta = tx_d;
        wan->counter_window_sec = now - base->ts;
        /* Denominator is received+dropped, so loss is a share of offered packets. */
        if (rx_p + rx_d > 0) {
            wan->down_loss_pct = (double)rx_d * 100.0 / (double)(rx_p + rx_d);
            wan->counters_valid = 1;
        }
        if (tx_p + tx_d > 0) {
            wan->up_loss_pct = (double)tx_d * 100.0 / (double)(tx_p + tx_d);
            wan->counters_valid = 1;
        }
    }
    base->rx_packets = rx_packets;
    base->rx_drops = rx_drops;
    base->tx_packets = tx_packets;
    base->tx_drops = tx_drops;
    base->ts = now;
    base->have_baseline = 1;
}

static void health_probe_wan(health_wan_state_t *wan)
{
    static const char * const targets[] = {
        "223.5.5.5",
        "119.29.29.29",
        NULL
    };
    int i;

    if (!wan)
        return;
    wan->checked = 1;
    wan->online = 0;
    wan->latency_ms = 999;
    wan->probe_loss_pct = 100;
    wan->probe_packets_sent = 0;
    wan->target[0] = '\0';
    health_copy_string(wan->reason, sizeof(wan->reason), "probe_failed");

    if (!wan->device[0]) {
        health_copy_string(wan->reason, sizeof(wan->reason), "no_device");
        return;
    }
    if (!health_device_link_up(wan->device)) {
        health_copy_string(wan->reason, sizeof(wan->reason), "link_down");
        return;
    }

    for (i = 0; targets[i]; i++) {
        int loss = 100;
        int latency = 0;

        health_copy_string(wan->target, sizeof(wan->target), targets[i]);
        if (health_ping_bound(wan->device, targets[i], &loss, &latency) == 0 || loss < 100) {
            wan->online = loss < 100;
            wan->latency_ms = latency > 0 ? latency : (loss < 100 ? 1 : 999);
            wan->probe_loss_pct = loss;
            wan->probe_packets_sent = 3;   /* ping -c 3 above */
            if (loss == 0 && wan->latency_ms < 80)
                health_copy_string(wan->reason, sizeof(wan->reason), "ok");
            else if (loss >= 50)
                health_copy_string(wan->reason, sizeof(wan->reason), "packet_loss");
            else if (wan->latency_ms >= 180)
                health_copy_string(wan->reason, sizeof(wan->reason), "high_latency");
            else
                health_copy_string(wan->reason, sizeof(wan->reason), "unstable");
            return;
        }
    }
}

static void health_write_wan_status(health_wan_state_t *wans, int count,
                                    u_int32_t ts)
{
    char tmp_path[128];
    FILE *fp;
    int i;

    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", JMX_WAN_HEALTH_STATUS_PATH) >=
        (int)sizeof(tmp_path))
        return;
    fp = fopen(tmp_path, "w");
    if (!fp)
        return;
    fprintf(fp, "updated_at=%u\nwan_count=%d\n", ts, count);
    for (i = 0; i < count; i++) {
        /*
         * loss= is kept as the probe value for compatibility with readers that
         * still parse it, but it is now also published under probe_loss= so no
         * caller has to guess which measurement it is holding. The real
         * forwarding loss is up_loss=/down_loss=, which are -1 when there is no
         * sample yet rather than a misleading 0.
         */
        fprintf(fp,
                "wan=%s device=%s proto=%s checked=%d online=%d latency=%d loss=%d "
                "probe_loss=%d probe_packets=%d counters_valid=%d counter_ifname=%s "
                "up_loss=%.4f down_loss=%.4f rx_packets_delta=%llu rx_drops_delta=%llu "
                "tx_packets_delta=%llu tx_drops_delta=%llu counter_window=%lld "
                "target=%s reason=%s\n",
                wans[i].name,
                wans[i].device,
                wans[i].proto,
                wans[i].checked ? 1 : 0,
                wans[i].online ? 1 : 0,
                wans[i].latency_ms,
                wans[i].probe_loss_pct,
                wans[i].probe_loss_pct,
                wans[i].probe_packets_sent,
                wans[i].counters_valid ? 1 : 0,
                wans[i].counter_ifname[0] ? wans[i].counter_ifname : "-",
                wans[i].up_loss_pct,
                wans[i].down_loss_pct,
                (unsigned long long)wans[i].rx_packets_delta,
                (unsigned long long)wans[i].rx_drops_delta,
                (unsigned long long)wans[i].tx_packets_delta,
                (unsigned long long)wans[i].tx_drops_delta,
                (long long)wans[i].counter_window_sec,
                wans[i].target,
                wans[i].reason);
    }
    health_publish_status_file(fp, tmp_path, JMX_WAN_HEALTH_STATUS_PATH);
}

static void check_wan_health(void)
{
    health_wan_state_t wans[WAN_HEALTH_MAX_WANS];
    int count;
    int i;

    memset(wans, 0, sizeof(wans));
    count = health_load_wans(wans, WAN_HEALTH_MAX_WANS);
    for (i = 0; i < count; i++) {
        health_probe_wan(&wans[i]);
        /*
         * Counter sampling is deliberately independent of the probe: an
         * unreachable ping target must not zero or invalidate real loss, and a
         * clean ping must not hide it.
         */
        health_sample_wan_counters(&wans[i]);
    }
    health_write_wan_status(wans, count, (u_int32_t)time(NULL));
}

static int check_any_ping(const char * const *hosts)
{
    int i;

    if (!hosts)
        return -1;
    for (i = 0; hosts[i]; i++) {
        if (check_ping(hosts[i]) == 0)
            return 0;
    }
    return -1;
}

static int check_any_tcp_connect(const char * const *hosts, int port, int timeout_sec)
{
    int i;

    if (!hosts)
        return -1;
    for (i = 0; hosts[i]; i++) {
        if (check_tcp_connect(hosts[i], port, timeout_sec) == 0)
            return 0;
    }
    return -1;
}

static int __check_internet_connectivity(void) {
    static const char * const internet_hosts[] = {
        "www.baidu.com",
        "www.qq.com",
        NULL
    };

    if (check_any_ping(internet_hosts) == 0) {
			return 1;
    }
    
    if (check_any_tcp_connect(internet_hosts, 443, 2) == 0) {
			return 1;
    }
		return 0;
}


static void check_internet_connectivity(void) {
	static int fail_count = 0;
	static int last_internet = -1;
	int status = __check_internet_connectivity();
	g_internet_check_state.checked = 1;
	if (status){
		g_internet_check_state.internet = 1;
		fail_count = 0;
	}
	else{
		fail_count++;
		if (fail_count > 2){
			g_internet_check_state.internet = 0;
		}
	}
	if (last_internet != -1 && last_internet != g_internet_check_state.internet){
		LOG_WARN("internet change %d--->%d\n", last_internet, g_internet_check_state.internet);
	}	
	last_internet = g_internet_check_state.internet;
}

static unsigned long long health_stat_bytes(const struct stat *st)
{
    if (!st)
        return 0;
    if (st->st_blocks > 0)
        return (unsigned long long)st->st_blocks * 512ULL;
    return (unsigned long long)st->st_size;
}

static int health_path_size_bytes(const char *path, unsigned long long *bytes)
{
    struct stat st;
    DIR *dir;
    struct dirent *ent;

    if (!path || !bytes || lstat(path, &st) != 0)
        return -1;

    *bytes += health_stat_bytes(&st);
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
        return 0;

    dir = opendir(path);
    if (!dir)
        return -1;
    while ((ent = readdir(dir)) != NULL) {
        char child[512];

        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path, ent->d_name) >= (int)sizeof(child))
            continue;
        (void)health_path_size_bytes(child, bytes);
    }
    closedir(dir);
    return 0;
}

static void health_remove_tree(const char *path)
{
    struct stat st;

    if (!path || lstat(path, &st) != 0)
        return;
    if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
        DIR *dir = opendir(path);
        struct dirent *ent;

        if (dir) {
            while ((ent = readdir(dir)) != NULL) {
                char child[512];

                if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                    continue;
                if (snprintf(child, sizeof(child), "%s/%s", path, ent->d_name) >= (int)sizeof(child))
                    continue;
                health_remove_tree(child);
            }
            closedir(dir);
        }
        rmdir(path);
    } else {
        unlink(path);
    }
}

static int health_find_oldest_log_entry(const char *path, char *out, size_t out_len)
{
    DIR *dir = opendir(path);
    struct dirent *ent;
    time_t oldest = 0;
    int found = 0;

    if (!dir)
        return -1;
    while ((ent = readdir(dir)) != NULL) {
        char child[512];
        struct stat st;

        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path, ent->d_name) >= (int)sizeof(child))
            continue;
        if (lstat(child, &st) != 0)
            continue;
        if (!found || st.st_mtime < oldest) {
            if (snprintf(out, out_len, "%s", child) >= (int)out_len)
                continue;
            oldest = st.st_mtime;
            found = 1;
        }
    }
    closedir(dir);
    return found ? 0 : -1;
}

static void check_and_cleanup_log_dir(void) {
    unsigned long long bytes = 0;
    int size_kb;
    int pass;

    if (health_path_size_bytes(LOG_DIR_PATH, &bytes) != 0)
        return;
    size_kb = (int)((bytes + 1023ULL) / 1024ULL);
    LOG_INFO("check_and_cleanup_log_dir: log dir size = %d KB\n", size_kb);
    if (size_kb <= LOG_DIR_MAX_SIZE_KB)
        return;

    for (pass = 0; pass < LOG_DIR_CLEANUP_MAX_PASSES && size_kb > LOG_DIR_TARGET_SIZE_KB; pass++) {
        char oldest[512];

        if (health_find_oldest_log_entry(LOG_DIR_PATH, oldest, sizeof(oldest)) != 0)
            break;
        LOG_WARN("check_and_cleanup_log_dir: removing old log entry %s (%d KB > %d KB)\n",
                 oldest, size_kb, LOG_DIR_MAX_SIZE_KB);
        health_remove_tree(oldest);
        bytes = 0;
        if (health_path_size_bytes(LOG_DIR_PATH, &bytes) != 0)
            break;
        size_kb = (int)((bytes + 1023ULL) / 1024ULL);
    }
}

int jmx_health_run(volatile sig_atomic_t *stop) {
    LOG_DEBUG("healthd: worker started\n");

    check_internet_connectivity();
    check_wan_health();
    check_and_cleanup_log_dir();
    g_internet_check_state.last_exec_time = time(NULL);
    health_write_status();

    while (!stop || !*stop) {
        unsigned int i;

        for (i = 0; i < INTERNET_CHECK_INTERVAL; i++) {
            if (stop && *stop)
                break;
            sleep(1);
        }

        if (!stop || !*stop) {
            check_internet_connectivity();
            check_wan_health();
            check_and_cleanup_log_dir();
            g_internet_check_state.last_exec_time = time(NULL);
            health_write_status();
        }
    }

    LOG_DEBUG("healthd: worker exited\n");
    return 0;
}
