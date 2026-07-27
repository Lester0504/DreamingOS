#ifndef JMX_DHCP_SNIFF_H
#define JMX_DHCP_SNIFF_H

#include <stdint.h>

typedef struct {
    unsigned char mac[6];
    char option55[128];
    char vendor_class[64];
    uint32_t timestamp;
} dhcp_signal_t;

/* Start DHCP sniffer thread (captures on br-lan, UDP port 67) */
void dhcp_sniff_init(void);

/* Stop sniffer thread */
void dhcp_sniff_stop(void);

/* Consume captured signals into caller's buffer. Returns count. */
int dhcp_sniff_consume(dhcp_signal_t *out, int max_out);

#endif
