/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Native dnsmasq integration. Included after dnsmasq.h. */
#ifndef DWRT_DNS_POLICY_H
#define DWRT_DNS_POLICY_H
#ifndef DWRT_DNS_POLICY_DIR
#define DWRT_DNS_POLICY_DIR "/var/run/dreamingwrt/ad-dns"
#endif
#define DWRT_DNS_POLICY_FILE DWRT_DNS_POLICY_DIR "/policy"
#define DWRT_DNS_POLICY_LOG DWRT_DNS_POLICY_DIR "/queries.log"
#define FREC_DWRT_ALLOW 1024
int dwrt_dns_decide(union mysockaddr *source, const char *name, time_t now);
void dwrt_dns_uncache(struct dns_header *header, size_t size);
size_t dwrt_dns_block(struct dns_header *header, size_t size, size_t capacity);
size_t dwrt_dns_probe(struct dns_header *header, size_t size, size_t capacity,
                     union mysockaddr *source, time_t now);
void dwrt_dns_query(struct dns_header *header, size_t size,
                    union mysockaddr *source, unsigned int serial, time_t now);
void dwrt_dns_reply(struct dns_header *header, size_t size,
                    union mysockaddr *source, unsigned int serial, time_t now);
#endif
