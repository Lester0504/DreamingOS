/*
 * jmx_dhcp_sniff.c - DHCP option 55/60 sniffer
 *
 * Captures DHCP DISCOVER/REQUEST on LAN, extracts option 55
 * (Parameter Request List) and option 60 (Vendor Class).
 * Stores results for Huginn-Muninn lookup.
 *
 * Uses AF_PACKET + ETH_P_IP to avoid conflicting with dnsmasq.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "jmx_dhcp_sniff.h"
#include "jmx.h"

/* Ring buffer for captured DHCP signals */
#define DHCP_RING_SIZE 128
#define DHCP_OPT55_MAX 128
#define DHCP_OPT60_MAX 64
#define DHCP_IFACE "br-lan"

static dhcp_signal_t g_ring[DHCP_RING_SIZE];
static int g_ring_head = 0;
static int g_ring_count = 0;
static pthread_mutex_t g_ring_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_sniff_thread;
static int g_sniff_running = 0;
/*
 * 1 only after the AF_PACKET socket is bound and the capture loop is live.
 * dhcp_sniff_active() must not claim observation while the socket failed to
 * open (no br-lan, missing CAP_NET_RAW, ...), otherwise the DHCP capability
 * would report a detector that never sees a packet.
 */
static int g_sniff_capture_ok = 0;

/*
 * Observed DHCP server table (rogue DHCP detection).
 * Kept as a small retained set rather than a consume-once ring: a rogue
 * server must stay visible across polls for as long as it keeps answering.
 */
#define DHCP_SERVER_MAX 32
static dhcp_server_obs_t g_servers[DHCP_SERVER_MAX];
static int g_server_count = 0;
static pthread_mutex_t g_server_lock = PTHREAD_MUTEX_INITIALIZER;

/* Cache of this host's own IPv4 addresses, refreshed periodically. */
#define DHCP_SELF_ADDR_MAX 32
static uint32_t g_self_addrs[DHCP_SELF_ADDR_MAX];
static int g_self_addr_count = 0;
static time_t g_self_addr_ts = 0;
static pthread_mutex_t g_self_lock = PTHREAD_MUTEX_INITIALIZER;

static void dhcp_refresh_self_addrs(void)
{
    struct ifaddrs *ifa = NULL, *p;
    int n = 0;

    if (getifaddrs(&ifa) != 0 || !ifa)
        return;
    for (p = ifa; p && n < DHCP_SELF_ADDR_MAX; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET)
            continue;
        g_self_addrs[n++] =
            ((struct sockaddr_in *)p->ifa_addr)->sin_addr.s_addr;
    }
    freeifaddrs(ifa);
    g_self_addr_count = n;
    g_self_addr_ts = time(NULL);
}

/* 1 if addr belongs to this router (i.e. an authorized DHCP server). */
static int dhcp_addr_is_self(uint32_t addr)
{
    int i, self = 0;
    time_t now = time(NULL);

    pthread_mutex_lock(&g_self_lock);
    if (g_self_addr_count == 0 || now - g_self_addr_ts > 30)
        dhcp_refresh_self_addrs();
    for (i = 0; i < g_self_addr_count; i++) {
        if (g_self_addrs[i] == addr) {
            self = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_self_lock);
    return self;
}

/* Record a DHCP server seen answering on the LAN. */
static void dhcp_note_server(const unsigned char *mac, uint32_t server_ip,
                             uint32_t offered_ip, int local_origin)
{
    uint32_t now = (uint32_t)time(NULL);
    int authorized = dhcp_addr_is_self(server_ip);
    int i, oldest = 0;

    /* A reply we emitted ourselves is authorized by definition. */
    if (local_origin)
        authorized = 1;

    pthread_mutex_lock(&g_server_lock);
    for (i = 0; i < g_server_count; i++) {
        if (g_servers[i].server_ip == server_ip &&
            !memcmp(g_servers[i].mac, mac, 6)) {
            g_servers[i].last_seen = now;
            g_servers[i].offered_ip = offered_ip;
            g_servers[i].authorized = authorized;
            g_servers[i].local_origin = local_origin;
            if (g_servers[i].hits < 0xFFFFFFFFu)
                g_servers[i].hits++;
            pthread_mutex_unlock(&g_server_lock);
            return;
        }
        if (g_servers[i].last_seen < g_servers[oldest].last_seen)
            oldest = i;
    }
    if (g_server_count < DHCP_SERVER_MAX)
        i = g_server_count++;
    else
        i = oldest; /* evict least recently seen */
    memset(&g_servers[i], 0, sizeof(g_servers[i]));
    memcpy(g_servers[i].mac, mac, 6);
    g_servers[i].server_ip = server_ip;
    g_servers[i].offered_ip = offered_ip;
    g_servers[i].first_seen = now;
    g_servers[i].last_seen = now;
    g_servers[i].hits = 1;
    g_servers[i].authorized = authorized;
    g_servers[i].local_origin = local_origin;
    pthread_mutex_unlock(&g_server_lock);
    if (!authorized) {
        char ipbuf[INET_ADDRSTRLEN] = "";
        struct in_addr a; a.s_addr = server_ip;
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        LOG_WARN("dhcp_sniff: rogue DHCP server %s "
                 "(%02x:%02x:%02x:%02x:%02x:%02x) answering on %s\n",
                 ipbuf, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                 DHCP_IFACE);
    }
}

int dhcp_sniff_servers_snapshot(dhcp_server_obs_t *out, int max_out)
{
    int count = 0, i;

    if (!out || max_out < 1)
        return 0;
    pthread_mutex_lock(&g_server_lock);
    for (i = 0; i < g_server_count && count < max_out; i++)
        memcpy(&out[count++], &g_servers[i], sizeof(dhcp_server_obs_t));
    pthread_mutex_unlock(&g_server_lock);
    return count;
}

int dhcp_sniff_active(void)
{
    return (g_sniff_running && g_sniff_capture_ok) ? 1 : 0;
}

/* DHCP magic cookie: 0x63825363 */
#define DHCP_MAGIC 0x63825363

/* Parse DHCP options from packet payload */
static void parse_dhcp_options(const unsigned char *opts, int opts_len,
                               char *opt55, int opt55_sz,
                               char *opt60, int opt60_sz)
{
    opt55[0] = '\0';
    opt60[0] = '\0';
    int pos = 0;
    while (pos < opts_len) {
        unsigned char code = opts[pos];
        if (code == 0xFF) break;  /* end */
        if (code == 0x00) { pos++; continue; }  /* pad */
        if (pos + 1 >= opts_len) break;
        unsigned char len = opts[pos + 1];
        if (pos + 2 + len > opts_len) break;
        const unsigned char *data = opts + pos + 2;

        if (code == 55 && len > 0 && len < opt55_sz) {
            /* Build comma-separated list */
            int off = 0;
            for (int i = 0; i < len && off < opt55_sz - 4; i++) {
                if (i > 0) opt55[off++] = ',';
                off += snprintf(opt55 + off, opt55_sz - off, "%u", data[i]);
            }
            opt55[off] = '\0';
        }
        if (code == 60 && len > 0) {
            int copy_len = len < opt60_sz - 1 ? len : opt60_sz - 1;
            memcpy(opt60, data, copy_len);
            opt60[copy_len] = '\0';
        }
        pos += 2 + len;
    }
}

/* Store a captured DHCP signal into the ring buffer */
static void store_signal(const unsigned char *mac,
                         const char *opt55, const char *opt60)
{
    pthread_mutex_lock(&g_ring_lock);
    dhcp_signal_t *slot = &g_ring[g_ring_head];
    memcpy(slot->mac, mac, 6);
    snprintf(slot->option55, sizeof(slot->option55), "%s", opt55);
    snprintf(slot->vendor_class, sizeof(slot->vendor_class), "%s", opt60);
    slot->timestamp = (uint32_t)time(NULL);
    g_ring_head = (g_ring_head + 1) % DHCP_RING_SIZE;
    if (g_ring_count < DHCP_RING_SIZE) g_ring_count++;
    pthread_mutex_unlock(&g_ring_lock);
}

/* Sniffer thread */
static void *sniff_thread(void *arg)
{
    (void)arg;
    int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0) {
        LOG_ERROR("dhcp_sniff: socket() failed\n");
        return NULL;
    }

    /*
     * 性能优化（PM-to-Backend-perf-ac-mem-core-cpu）：内核侧 BPF 过滤器。
     * 没有它时，绑到 br-lan 的 AF_PACKET/ETH_P_IP socket 会把 LAN 上*每一个* IP 包
     * 都递到 userspace，capture 线程为每个网页/视频包唤醒一次（实测每秒 60-130 次），
     * core 收下再自己丢弃非 DHCP 的。装上经典 "udp and (port 67 or port 68)" 过滤器后，
     * 内核侧丢掉 ~99.9%，userspace 只为真正的 DHCP 帧醒来 —— 看到的 DHCP 数据完全一样
     * （DISCOVER/REQUEST 的 dport 67、OFFER/ACK 的 sport 67 双向都覆盖），这是
     * tcpdump/DHCP 探测器的标准做法，零功能变更。
     *
     * 字节码由 `tcpdump -y EN10MB -dd 'udp and (port 67 or port 68)'` 生成
     * （31.6 与 31.250 输出一致）。AF_PACKET 的 socket filter 从链路层头开始运行，
     * 故过滤器含 14 字节以太网偏移；同时保留 IPv6(0x86dd) 分支（本 socket 只绑
     * ETH_P_IP，该分支恒不命中，无害）。在 bind 前 attach，避免绑定后到过滤前的窗口。
     */
    {
        static struct sock_filter dhcp_bpf[] = {
            { 0x28, 0, 0,  0x0000000c },
            { 0x15, 0, 10, 0x00000800 },
            { 0x30, 0, 0,  0x00000017 },
            { 0x15, 0, 18, 0x00000011 },
            { 0x28, 0, 0,  0x00000014 },
            { 0x45, 16, 0, 0x00001fff },
            { 0xb1, 0, 0,  0x0000000e },
            { 0x48, 0, 0,  0x0000000e },
            { 0x15, 12, 0, 0x00000043 },
            { 0x15, 11, 0, 0x00000044 },
            { 0x48, 0, 0,  0x00000010 },
            { 0x15, 9, 8,  0x00000043 },
            { 0x15, 0, 9,  0x000086dd },
            { 0x30, 0, 0,  0x00000014 },
            { 0x15, 0, 7,  0x00000011 },
            { 0x28, 0, 0,  0x00000036 },
            { 0x15, 4, 0,  0x00000043 },
            { 0x15, 3, 0,  0x00000044 },
            { 0x28, 0, 0,  0x00000038 },
            { 0x15, 1, 0,  0x00000043 },
            { 0x15, 0, 1,  0x00000044 },
            { 0x6, 0, 0,   0x00040000 },
            { 0x6, 0, 0,   0x00000000 },
        };
        struct sock_fprog prog = {
            .len = (unsigned short)(sizeof(dhcp_bpf) / sizeof(dhcp_bpf[0])),
            .filter = dhcp_bpf,
        };
        /*
         * Best-effort: a kernel without CONFIG_PACKET_FILTER (or a hardened
         * seccomp view) simply keeps the pre-filter behaviour — the loop still
         * discards non-DHCP frames in userspace, so capture correctness is
         * unaffected either way. Only the CPU win is lost.
         */
        if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
                       &prog, sizeof(prog)) < 0)
            LOG_WARN("dhcp_sniff: SO_ATTACH_FILTER failed; "
                     "falling back to userspace filtering\n");
    }

    /* Bind to LAN interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = if_nametoindex(DHCP_IFACE);
    if (sll.sll_ifindex == 0) {
        LOG_ERROR("dhcp_sniff: iface %s not found\n", DHCP_IFACE);
        close(fd);
        return NULL;
    }
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_ERROR("dhcp_sniff: bind(%s) failed\n", DHCP_IFACE);
        close(fd);
        return NULL;
    }

    /* Set 1s receive timeout */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    g_sniff_capture_ok = 1;

    unsigned char buf[1500];
    while (g_sniff_running) {
        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        ssize_t n;

        memset(&from, 0, sizeof(from));
        /*
         * recvfrom() so the true L2 source is available: with SOCK_DGRAM the
         * ethernet header is stripped, and the DHCP chaddr field carries the
         * *client* MAC, never the responding server's.
         */
        n = recvfrom(fd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&from, &fromlen);
        if (n <= 0) {
            if (!g_sniff_running) break;
            usleep(100000);  /* 100ms */
            continue;
        }
        if (n < (ssize_t)(sizeof(struct iphdr) + sizeof(struct udphdr) + 236 + 4)) continue;

        struct iphdr *iph = (struct iphdr *)buf;
        if (iph->protocol != IPPROTO_UDP) continue;

        int ip_hdr_len = iph->ihl * 4;
        struct udphdr *udph = (struct udphdr *)(buf + ip_hdr_len);
        uint16_t dport = ntohs(udph->uh_dport);
        uint16_t sport = ntohs(udph->uh_sport);
        /*
         * Two directions are interesting:
         *   dport 67  client→server DISCOVER/REQUEST (fingerprint options)
         *   sport 67  server→client OFFER/ACK        (rogue server detection)
         */
        if (dport != 67 && sport != 67) continue;

        int udp_payload_off = ip_hdr_len + sizeof(struct udphdr);
        int udp_payload_len = n - udp_payload_off;
        if (udp_payload_len < 236 + 4) continue;

        const unsigned char *dhcp = buf + udp_payload_off;

        /* Verify magic cookie before trusting any offsets. */
        {
            uint32_t cookie;
            memcpy(&cookie, dhcp + 236, 4);
            if (ntohl(cookie) != DHCP_MAGIC) continue;
        }

        /*
         * op=2 (BOOTREPLY) arriving from UDP/67 means some host on the LAN is
         * acting as a DHCP server. Record it; the caller decides whether the
         * source is one of our own addresses or a rogue.
         */
        if (dhcp[0] == 2 && sport == 67) {
            uint32_t yiaddr;
            unsigned char smac[6] = {0};
            /*
             * PACKET_OUTGOING means this router emitted the reply, in which
             * case sll_addr holds the *destination* (client) MAC, not a source.
             * Do not attribute it as a peer server MAC.
             */
            int local_origin = (from.sll_pkttype == PACKET_OUTGOING);
            memcpy(&yiaddr, dhcp + 16, 4);
            if (!local_origin && from.sll_halen >= 6)
                memcpy(smac, from.sll_addr, 6);
            dhcp_note_server(smac, iph->saddr, yiaddr, local_origin);
            continue;
        }

        /* op=1 is BOOTREQUEST (client fingerprint path) */
        if (dhcp[0] != 1 || dport != 67) continue;

        /* Extract MAC from chaddr (offset 28, 16 bytes, we use 6) */
        const unsigned char *mac = dhcp + 28;

        /* Parse options (offset 240 to end of UDP payload) */
        char opt55[DHCP_OPT55_MAX] = {0};
        char opt60[DHCP_OPT60_MAX] = {0};
        parse_dhcp_options(dhcp + 240, udp_payload_len - 240,
                           opt55, sizeof(opt55), opt60, sizeof(opt60));

        if (opt55[0]) {
            store_signal(mac, opt55, opt60);
        }
    }
    close(fd);
    g_sniff_capture_ok = 0;
    return NULL;
}

void dhcp_sniff_init(void)
{
    if (g_sniff_running) return;
    g_sniff_running = 1;
    if (pthread_create(&g_sniff_thread, NULL, sniff_thread, NULL) != 0) {
        LOG_ERROR("dhcp_sniff: pthread_create failed\n");
        g_sniff_running = 0;
    }
}

void dhcp_sniff_stop(void)
{
    g_sniff_running = 0;
    pthread_join(g_sniff_thread, NULL);
}

int dhcp_sniff_consume(dhcp_signal_t *out, int max_out)
{
    int count = 0;
    pthread_mutex_lock(&g_ring_lock);
    while (g_ring_count > 0 && count < max_out) {
        int idx = (g_ring_head - g_ring_count + DHCP_RING_SIZE) % DHCP_RING_SIZE;
        memcpy(&out[count], &g_ring[idx], sizeof(dhcp_signal_t));
        g_ring_count--;
        count++;
    }
    pthread_mutex_unlock(&g_ring_lock);
    return count;
}
