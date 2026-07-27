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
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

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

    unsigned char buf[1500];
    while (g_sniff_running) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
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
        /* Only DHCP: client→server on port 67 */
        if (dport != 67) continue;

        int udp_payload_off = ip_hdr_len + sizeof(struct udphdr);
        int udp_payload_len = n - udp_payload_off;
        if (udp_payload_len < 236 + 4) continue;

        const unsigned char *dhcp = buf + udp_payload_off;
        /* op=1 is BOOTREQUEST */
        if (dhcp[0] != 1) continue;

        /* Extract MAC from chaddr (offset 28, 16 bytes, we use 6) */
        const unsigned char *mac = dhcp + 28;

        /* Check magic cookie */
        uint32_t magic;
        memcpy(&magic, dhcp + 236, 4);
        if (ntohl(magic) != DHCP_MAGIC) continue;

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
