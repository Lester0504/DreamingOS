#ifndef JMX_DHCP_SNIFF_H
#define JMX_DHCP_SNIFF_H

#include <stdint.h>

typedef struct {
    unsigned char mac[6];
    char option55[128];
    char vendor_class[64];
    uint32_t timestamp;
} dhcp_signal_t;

/*
 * Observed DHCP server (from server->client OFFER/ACK on the LAN).
 * Any server whose identity is not one of this router's own LAN addresses
 * is a rogue/unauthorized DHCP server. Detection is purely passive.
 */
typedef struct {
    unsigned char mac[6];        /* L2 source of the OFFER/ACK        */
    uint32_t server_ip;          /* network byte order                */
    uint32_t offered_ip;         /* yiaddr, network byte order        */
    uint32_t first_seen;
    uint32_t last_seen;
    uint32_t hits;
    int authorized;              /* 1 = one of our own LAN addresses  */
    int local_origin;            /* 1 = emitted by this router itself  */
} dhcp_server_obs_t;

/* Start DHCP sniffer thread (captures on br-lan, UDP port 67) */
void dhcp_sniff_init(void);

/* Stop sniffer thread */
void dhcp_sniff_stop(void);

/* Consume captured signals into caller's buffer. Returns count. */
int dhcp_sniff_consume(dhcp_signal_t *out, int max_out);

/*
 * Snapshot observed DHCP servers (non-destructive: the table is retained so
 * repeated polls keep reporting a rogue server that is still active).
 * Returns the number of entries written.
 */
int dhcp_sniff_servers_snapshot(dhcp_server_obs_t *out, int max_out);

/* 1 if the passive server observation path is running. */
int dhcp_sniff_active(void);

#endif
