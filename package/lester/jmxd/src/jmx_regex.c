/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_regex.c - NFQUEUE regex matching engine for jmxd
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "jmx_regex.h"
#include "jmx_exec.h"
#include "jmx_rule.h"
#include "jmx_netlink.h"
#include "jmx_proto_decode.h"
#include "jmx_audit.h"
#include "jmx_domain.h"
#include "jmx_hosttype.h"
#include "jmx_domain.h"
#include "jmx_hosttype.h"

/* ── Constants ── */

#define JMX_NFQUEUE_NUM        0
#define JMX_MAX_REGEX_RULES    16384
#define JMX_REGEX_MATCH_LIMIT  100000
#define JMX_REGEX_OVECTOR_SIZE 30
#define JMX_DNS_CACHE_DEBUG    0
#define JMX_REGEX_NFT_PATH     "/usr/sbin/nft"
#define JMX_REGEX_NFT_TIMEOUT_MS 5000
#define JMX_REGEX_NFT_OUTPUT_MAX (256U * 1024U)
#define JMX_REGEX_NFT_MAX_HANDLES 64
#define JMX_REGEX_NFT_FORWARD_COMMENT "dreamingwrt-regex-forward"
#define JMX_REGEX_NFT_MARK_COMMENT "dreamingwrt-regex-output-mark"
#define JMX_REGEX_NFT_QUEUE_COMMENT "dreamingwrt-regex-output-queue"

/* ── Compiled regex rule ── */

typedef struct {
	uint32_t appid;
	uint32_t priority;
	uint8_t  proto;
	uint8_t  dir;
	uint8_t  port_count;
	uint16_t ports_min[JMX_MAX_PORT_RANGES];
	uint16_t ports_max[JMX_MAX_PORT_RANGES];
	uint32_t pkt_seq;
	pcre2_code *re;
} regex_rule_t;

/* ── State ── */

static regex_rule_t *g_rules;
static int g_rule_count;
static int g_running;
static const jmx_rule_set_t *g_rule_set;  /* for NR lookup */

void jmx_regex_set_rule_set(const jmx_rule_set_t *rs) { g_rule_set = rs; }
static pthread_t g_thread;
static struct nfq_handle *g_nfq_h;
static struct nfq_q_handle *g_qh;
static int g_nl_fd;
static int g_netlink_fd;  /* netlink fd for sending results to kernel */
static pcre2_compile_context *g_compile_ctx;
static pcre2_match_context  *g_match_ctx;

static uint64_t g_stat_packets;
static uint64_t g_stat_matched;
static uint64_t g_stat_no_match;

static uint32_t match_high_conf_host_fallback(const char *hostname, int hostname_len,
					     uint8_t l4_proto, uint16_t dport);
static uint32_t match_domain_to_app(const jmx_rule_set_t *rs, const char *hostname,
				    int hostname_len, uint8_t l4_proto, uint16_t dport);

#define JMX_DNS_APP_CACHE_SIZE 8192
#define JMX_DNS_APP_CACHE_TTL 600

typedef struct {
	uint8_t af;
	uint32_t ip;
	uint8_t ip6[16];
	uint32_t appid;
	uint8_t app_proto;
	time_t expires;
	char host[128];
} dns_app_cache_entry_t;

static dns_app_cache_entry_t g_dns_app_cache[JMX_DNS_APP_CACHE_SIZE];
static unsigned int g_dns_app_cache_pos;
static pthread_mutex_t g_dns_app_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static int is_valid_host_char(int c)
{
	return isalnum((unsigned char)c) || c == '-' || c == '.' || c == '_';
}

static int dns_read_name(const unsigned char *pkt, int pkt_len, int off,
				 char *out, int out_len, int *next_off)
{
	int pos = off, out_pos = 0, jumped = 0, jumps = 0;
	int after = off;

	if (!pkt || !out || out_len <= 1 || off < 0 || off >= pkt_len)
		return -1;

	while (pos < pkt_len && jumps < 16) {
		unsigned char len = pkt[pos];
		if (len == 0) {
			pos++;
			if (!jumped) after = pos;
			if (out_pos > 0 && out[out_pos - 1] == '.') out_pos--;
			out[out_pos] = '\0';
			if (next_off) *next_off = jumped ? after : pos;
			return out_pos;
		}
		if ((len & 0xC0) == 0xC0) {
			int ptr;
			if (pos + 1 >= pkt_len) return -1;
			ptr = ((len & 0x3F) << 8) | pkt[pos + 1];
			if (!jumped) after = pos + 2;
			if (ptr < 0 || ptr >= pkt_len) return -1;
			pos = ptr;
			jumped = 1;
			jumps++;
			continue;
		}
		if (len & 0xC0) return -1;
		pos++;
		if (pos + len > pkt_len) return -1;
		if (out_pos && out_pos < out_len - 1) out[out_pos++] = '.';
		for (int i = 0; i < len && out_pos < out_len - 1; i++) {
			unsigned char ch = pkt[pos + i];
			if (!is_valid_host_char(ch)) return -1;
			out[out_pos++] = (char)tolower(ch);
		}
		pos += len;
		if (!jumped) after = pos;
	}
	return -1;
}

static void dns_app_cache_put_ex(uint8_t af, uint32_t ip, const uint8_t *ip6,
				     uint32_t appid, const char *host, uint8_t app_proto)
{
	dns_app_cache_entry_t *e;
	size_t hlen;
#if JMX_DNS_CACHE_DEBUG
	static int debug_left = 32;
#endif

	if (!appid || !host || !host[0]) return;
	if (af == AF_INET) {
		if (!ip) return;
	} else if (af == AF_INET6) {
		if (!ip6) return;
	} else {
		return;
	}

#if JMX_DNS_CACHE_DEBUG
	if (debug_left-- > 0) {
		char abuf[INET6_ADDRSTRLEN] = {0};
		if (af == AF_INET) {
			struct in_addr ia;
			ia.s_addr = ip;
			inet_ntop(AF_INET, &ia, abuf, sizeof(abuf));
		} else {
			inet_ntop(AF_INET6, ip6, abuf, sizeof(abuf));
		}
		fprintf(stderr, "jmx_regex: dns cache learn %s -> %s appid=%u proto=%u\n",
			host, abuf, appid, app_proto);
	}
#endif

	pthread_mutex_lock(&g_dns_app_cache_lock);
	for (int i = 0; i < JMX_DNS_APP_CACHE_SIZE; i++) {
		e = &g_dns_app_cache[i];
		if (e->af != af) continue;
		if ((af == AF_INET && e->ip == ip) ||
		    (af == AF_INET6 && memcmp(e->ip6, ip6, 16) == 0))
			goto fill;
	}
	e = &g_dns_app_cache[g_dns_app_cache_pos++ % JMX_DNS_APP_CACHE_SIZE];
fill:
	memset(e, 0, sizeof(*e));
	e->af = af;
	e->ip = ip;
	if (ip6) memcpy(e->ip6, ip6, 16);
	e->appid = appid;
	e->app_proto = app_proto;
	e->expires = time(NULL) + JMX_DNS_APP_CACHE_TTL;
	hlen = strlen(host);
	if (hlen > sizeof(e->host) - 1) hlen = sizeof(e->host) - 1;
	memcpy(e->host, host, hlen);
	e->host[hlen] = '\0';
	pthread_mutex_unlock(&g_dns_app_cache_lock);
}

static void dns_app_cache_put(uint32_t ip, uint32_t appid, const char *host, uint8_t app_proto)
{
	dns_app_cache_put_ex(AF_INET, ip, NULL, appid, host, app_proto);
}

static uint32_t dns_app_cache_get_ex(uint8_t af, uint32_t ip, const uint8_t *ip6,
				     char *host, int host_len, uint8_t *app_proto)
{
	time_t now = time(NULL);
	uint32_t appid = 0;

	if (af == AF_INET) {
		if (!ip) return 0;
	} else if (af == AF_INET6) {
		if (!ip6) return 0;
	} else {
		return 0;
	}

	pthread_mutex_lock(&g_dns_app_cache_lock);
	for (int i = 0; i < JMX_DNS_APP_CACHE_SIZE; i++) {
		dns_app_cache_entry_t *e = &g_dns_app_cache[i];
		if (e->af == af && e->appid && e->expires >= now &&
		    ((af == AF_INET && e->ip == ip) ||
		     (af == AF_INET6 && memcmp(e->ip6, ip6, 16) == 0))) {
#if JMX_DNS_CACHE_DEBUG
			static int debug_hit_left = 32;
#endif
			appid = e->appid;
#if JMX_DNS_CACHE_DEBUG
			if (debug_hit_left-- > 0) {
				char abuf[INET6_ADDRSTRLEN] = {0};
				if (af == AF_INET) {
					struct in_addr ia;
					ia.s_addr = ip;
					inet_ntop(AF_INET, &ia, abuf, sizeof(abuf));
				} else {
					inet_ntop(AF_INET6, ip6, abuf, sizeof(abuf));
				}
				fprintf(stderr, "jmx_regex: dns cache hit %s appid=%u host=%s\n",
					abuf, e->appid, e->host);
			}
#endif
			if (host && host_len > 0) {
				strncpy(host, e->host, host_len - 1);
				host[host_len - 1] = '\0';
			}
			if (app_proto) *app_proto = e->app_proto;
			break;
		}
	}
	pthread_mutex_unlock(&g_dns_app_cache_lock);
	return appid;
}

static uint32_t dns_app_cache_get(uint32_t ip, char *host, int host_len, uint8_t *app_proto)
{
	return dns_app_cache_get_ex(AF_INET, ip, NULL, host, host_len, app_proto);
}

static uint32_t domain_to_app_for_dns_cache(const char *host, int host_len)
{
	uint32_t appid = 0;
	if (!g_rule_set || !host || host_len <= 0) return 0;

	/* Exact legacy-compatible APP hosts win over broad DreamingWrt DB domain rules.
	 * Example: www.baidu.com must stay 8001, not a generic/adjacent baidu app. */
	appid = match_high_conf_host_fallback(host, host_len, 17, 443);
	if (!appid) appid = match_high_conf_host_fallback(host, host_len, 6, 443);
	if (!appid) appid = match_high_conf_host_fallback(host, host_len, 6, 80);
	if (!appid) appid = match_domain_to_app(g_rule_set, host, host_len, 17, 443);
	if (!appid) appid = match_domain_to_app(g_rule_set, host, host_len, 6, 443);
	if (!appid) appid = match_domain_to_app(g_rule_set, host, host_len, 6, 80);
	return appid;
}

static void dns_app_cache_learn(const unsigned char *dns, int len)
{
	uint16_t flags, qd, an;
	int off;
	char qname[128] = {0};
	char cname[128] = {0};
	int qname_len = 0;
	uint32_t appid;

	if (!dns || len < 12) return;
	flags = ((uint16_t)dns[2] << 8) | dns[3];
	if ((flags & 0x8000) == 0) return;
	qd = ((uint16_t)dns[4] << 8) | dns[5];
	an = ((uint16_t)dns[6] << 8) | dns[7];
	if (qd == 0 || an == 0 || qd > 4 || an > 32) return;

	off = 12;
	for (int qi = 0; qi < qd; qi++) {
		char name[128] = {0};
		int next = 0;
		int nl = dns_read_name(dns, len, off, name, sizeof(name), &next);
		if (nl <= 0 || next + 4 > len) return;
		if (qi == 0) {
			strncpy(qname, name, sizeof(qname) - 1);
			qname_len = nl;
		}
		off = next + 4;
	}
	if (qname_len <= 0) return;
	appid = domain_to_app_for_dns_cache(qname, qname_len);
	if (!appid) return;

	for (int ai = 0; ai < an && off < len; ai++) {
		char name[128] = {0};
		int next = 0;
		uint16_t type, class_, rdlen;
		if (dns_read_name(dns, len, off, name, sizeof(name), &next) < 0) return;
		if (next + 10 > len) return;
		type = ((uint16_t)dns[next] << 8) | dns[next + 1];
		class_ = ((uint16_t)dns[next + 2] << 8) | dns[next + 3];
		rdlen = ((uint16_t)dns[next + 8] << 8) | dns[next + 9];
		off = next + 10;
		if (off + rdlen > len) return;
		if (type == 5 && class_ == 1 && rdlen > 0) {
			char target[128] = {0};
			int dummy = 0;
			if (dns_read_name(dns, len, off, target, sizeof(target), &dummy) > 0)
				strncpy(cname, target, sizeof(cname) - 1);
		} else if (type == 1 && class_ == 1 && rdlen == 4) {
			uint32_t ip;
			memcpy(&ip, dns + off, 4);
			/* Keep original queried host for display.  A records often arrive under
			 * CNAME owner names, but the user-facing APP mapping came from qname. */
			dns_app_cache_put(ip, appid, qname, 2);
		} else if (type == 28 && class_ == 1 && rdlen == 16) {
			dns_app_cache_put_ex(AF_INET6, 0, dns + off, appid, qname, 2);
		}
		off += rdlen;
	}
	(void)cname;
}


static int cmp_regex_prio(const void *a, const void *b)
{
	return (int)((const regex_rule_t *)a)->priority -
	       (int)((const regex_rule_t *)b)->priority;
}

/* ── nftables rule management ── */
static int remove_nftables_rule(void);

static int regex_nft_result_ok(const struct jmx_exec_result *result)
{
	return result && !result->timed_out && !result->truncated &&
	       result->term_signal == 0 && result->exit_code == 0;
}

static int regex_nft_wait(char *const argv[])
{
	struct jmx_exec_result result;
	int ok;

	if (jmx_exec_wait(argv[0], argv, JMX_REGEX_NFT_TIMEOUT_MS, &result) != 0)
		return -1;
	ok = regex_nft_result_ok(&result);
	jmx_exec_result_free(&result);
	return ok ? 0 : -1;
}

static int regex_nft_capture_chain(const char *chain,
				   struct jmx_exec_result *result)
{
	char *argv[] = { JMX_REGEX_NFT_PATH, "-a", "list", "chain",
			 "inet", "fw4", (char *)chain, NULL };

	if (!chain || !result ||
	    (strcmp(chain, "forward") && strcmp(chain, "mangle_output")))
		return -1;
	if (jmx_exec_capture(argv[0], argv, JMX_REGEX_NFT_OUTPUT_MAX,
			     JMX_REGEX_NFT_TIMEOUT_MS, result) != 0)
		return -1;
	if (!regex_nft_result_ok(result)) {
		jmx_exec_result_free(result);
		return -1;
	}
	return 0;
}

static int regex_nft_line_owned(const char *chain, const char *line)
{
	if (!chain || !line)
		return 0;
	if (strstr(line, JMX_REGEX_NFT_FORWARD_COMMENT) ||
	    strstr(line, JMX_REGEX_NFT_MARK_COMMENT) ||
	    strstr(line, JMX_REGEX_NFT_QUEUE_COMMENT))
		return 1;
	if (!strstr(line, "udp sport 53") ||
	    !strstr(line, "0x1f000001"))
		return 0;
	if (!strcmp(chain, "forward"))
		return strstr(line, "queue") &&
		       (strstr(line, "num 0") || strstr(line, "to 0"));
	if (!strcmp(chain, "mangle_output"))
		return strstr(line, "meta mark set") ||
		       (strstr(line, "queue") &&
		        (strstr(line, "num 0") || strstr(line, "to 0")));
	return 0;
}

static int regex_nft_line_handle(const char *line, char *handle,
				 size_t handle_len)
{
	const char *tag;
	const char *end;
	char *parse_end = NULL;
	unsigned long long value;
	size_t len;

	if (!line || !handle || handle_len == 0)
		return -1;
	tag = strstr(line, "handle " );
	if (!tag)
		return -1;
	tag += strlen("handle " );
	if (!isdigit((unsigned char)*tag))
		return -1;
	errno = 0;
	value = strtoull(tag, &parse_end, 10);
	if (errno != 0 || parse_end == tag || value == 0)
		return -1;
	end = parse_end;
	while (*end && isspace((unsigned char)*end))
		end++;
	if (*end != '\0')
		return -1;
	len = (size_t)(parse_end - tag);
	if (len >= handle_len)
		return -1;
	memcpy(handle, tag, len);
	handle[len] = '\0';
	return 0;
}

static int regex_nft_delete_chain_rules(const char *chain)
{
	struct jmx_exec_result result;
	char *line;
	char *saveptr = NULL;
	unsigned int deleted = 0;
	int rc = 0;

	if (regex_nft_capture_chain(chain, &result) != 0)
		return -1;
	for (line = strtok_r(result.output, "\n", &saveptr); line;
	     line = strtok_r(NULL, "\n", &saveptr)) {
		char handle[32];
		char *argv[] = { JMX_REGEX_NFT_PATH, "delete", "rule", "inet",
				 "fw4", (char *)chain, "handle", handle, NULL };

		if (!regex_nft_line_owned(chain, line))
			continue;
		if (deleted >= JMX_REGEX_NFT_MAX_HANDLES ||
		    regex_nft_line_handle(line, handle, sizeof(handle)) != 0 ||
		    regex_nft_wait(argv) != 0) {
			rc = -1;
			break;
		}
		deleted++;
	}
	jmx_exec_result_free(&result);
	return rc;
}

static int regex_nft_chain_has_comment(const char *chain, const char *comment)
{
	struct jmx_exec_result result;
	int found;

	if (regex_nft_capture_chain(chain, &result) != 0)
		return 0;
	found = result.output && strstr(result.output, comment) != NULL;
	jmx_exec_result_free(&result);
	return found;
}

static int setup_nftables_rule(void)
{
	char *forward_argv[] = {
		JMX_REGEX_NFT_PATH, "insert", "rule", "inet", "fw4", "forward",
		"udp", "sport", "53", "meta", "mark", "0x1f000001",
		"queue", "num", "0", "bypass", "comment",
		JMX_REGEX_NFT_FORWARD_COMMENT, NULL
	};
	char *mark_argv[] = {
		JMX_REGEX_NFT_PATH, "insert", "rule", "inet", "fw4",
		"mangle_output", "udp", "sport", "53", "meta", "mark",
		"set", "0x1f000001", "comment", JMX_REGEX_NFT_MARK_COMMENT, NULL
	};
	char *queue_argv[] = {
		JMX_REGEX_NFT_PATH, "insert", "rule", "inet", "fw4",
		"mangle_output", "udp", "sport", "53", "meta", "mark",
		"0x1f000001", "queue", "num", "0", "bypass", "comment",
		JMX_REGEX_NFT_QUEUE_COMMENT, NULL
	};

	/* First clean any stale queue rules from previous runs */
	if (remove_nftables_rule() != 0) {
		fprintf(stderr, "jmx_regex: stale nftables rule cleanup failed\n");
		return -1;
	}

	/* Queue only forwarded DNS responses for best-effort DNS->IP learning.
	 * Do not queue every regex mark in FORWARD: TLS ClientHello packets can
	 * otherwise wait on jmxd and make upstream HTTPS appear hung. */
	if (regex_nft_wait(forward_argv) == 0 &&
	    regex_nft_wait(queue_argv) == 0 &&
	    regex_nft_wait(mark_argv) == 0 &&
	    regex_nft_chain_has_comment("forward", JMX_REGEX_NFT_FORWARD_COMMENT) &&
	    regex_nft_chain_has_comment("mangle_output", JMX_REGEX_NFT_MARK_COMMENT) &&
	    regex_nft_chain_has_comment("mangle_output", JMX_REGEX_NFT_QUEUE_COMMENT)) {
		fprintf(stderr, "jmx_regex: nftables NFQUEUE rules verified OK\n");
		return 0;
	}
	(void)remove_nftables_rule();
	fprintf(stderr, "jmx_regex: nftables rule verification failed\n");
	return -1;
}

static int remove_nftables_rule(void)
{
	int forward_rc = regex_nft_delete_chain_rules("forward");
	int output_rc = regex_nft_delete_chain_rules("mangle_output");

	return forward_rc == 0 && output_rc == 0 ? 0 : -1;
}

/* ── Packet callback ── */


/* ── Phase 5: Payload extraction helpers ── */

/* Extract SNI hostname from TLS ClientHello */
static int extract_sni(const unsigned char *pkt, int pkt_len,
		       char *hostname, int hostname_size)
{
	int pos, name_len;
	uint16_t ext_type, ext_size, list_len;
	uint8_t name_type;

	if (pkt_len < 6) return -1;
	if (pkt[0] != 0x16 || pkt[5] != 0x01) return -1;

	pos = 5 + 4 + 2 + 32;
	if (pos + 1 > pkt_len) return -1;
	int sid_len = pkt[pos++];
	pos += sid_len;
	if (pos + 2 > pkt_len) return -1;
	uint16_t cs_len = (pkt[pos] << 8) | pkt[pos + 1];
	pos += 2 + cs_len;
	if (pos + 1 > pkt_len) return -1;
	int cm_len = pkt[pos++];
	pos += cm_len;
	if (pos + 2 > pkt_len) return -1;
	int ext_total = (pkt[pos] << 8) | pkt[pos + 1];
	pos += 2;
	int ext_end = pos + ext_total;
	if (ext_end > pkt_len) ext_end = pkt_len;

	while (pos + 4 <= ext_end) {
		ext_type = (pkt[pos] << 8) | pkt[pos + 1];
		ext_size = (pkt[pos + 2] << 8) | pkt[pos + 3];
		pos += 4;
		if (pos + ext_size > ext_end) return -1;
		if (ext_type == 0x0000) {
			int sni_end = pos + ext_size;
			if (pos + 2 > sni_end) return -1;
			list_len = (pkt[pos] << 8) | pkt[pos + 1];
			pos += 2;
			if (pos + list_len > sni_end) return -1;
			while (pos + 3 <= sni_end) {
				name_type = pkt[pos];
				name_len = (pkt[pos + 1] << 8) | pkt[pos + 2];
				pos += 3;
				if (pos + name_len > sni_end) return -1;
				if (name_type == 0x00 && name_len > 0 && name_len < hostname_size) {
					memcpy(hostname, pkt + pos, name_len);
					hostname[name_len] = '\0';
					return name_len;
				}
				pos += name_len;
			}
			return -1;
		}
		pos += ext_size;
	}
	return -1;
}

static int extract_http_host(const unsigned char *pkt, int pkt_len,
			     char *host, int host_size)
{
	for (int i = 0; i < pkt_len - 6; i++) {
		if (pkt[i] == 'H' && pkt[i+1] == 'o' && pkt[i+2] == 's' &&
		    pkt[i+3] == 't' && pkt[i+4] == ':' && pkt[i+5] == ' ') {
			int start = i + 6, end = start;
			while (end < pkt_len && pkt[end] != '\r' && pkt[end] != '\n') end++;
			int len = end - start;
			if (len > 0 && len < host_size) {
				memcpy(host, pkt + start, len);
				host[len] = '\0';
				return len;
			}
		}
	}
	return -1;
}

static int extract_http_ua(const unsigned char *pkt, int pkt_len,
			   char *ua, int ua_size)
{
	for (int i = 0; i < pkt_len - 11; i++) {
		if (pkt[i] == 'U' && pkt[i+1] == 's' && pkt[i+2] == 'e' &&
		    pkt[i+3] == 'r' && pkt[i+4] == '-' && pkt[i+5] == 'A' &&
		    pkt[i+6] == 'g' && pkt[i+7] == 'e' && pkt[i+8] == 'n' &&
		    pkt[i+9] == 't' && pkt[i+10] == ':') {
			int start = i + 11;
			while (start < pkt_len && pkt[start] == ' ') start++;
			int end = start;
			while (end < pkt_len && pkt[end] != '\r' && pkt[end] != '\n') end++;
			int len = end - start;
			if (len > 0 && len < ua_size) {
				memcpy(ua, pkt + start, len);
				ua[len] = '\0';
				return len;
			}
		}
	}
	return -1;
}


/* Domain-based app matching: check SNI/host against BM_STR and EXACT rules */
static int has_regex_meta(const char *s, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        char c = s[i];
        if (c == '(' || c == ')' || c == '[' || c == ']' ||
            c == '{' || c == '}' || c == '.' || c == '*' ||
            c == '+' || c == '?' || c == '|' || c == '^' ||
            c == '$' || c == '\\')
            return 1;
    }
    return 0;
}

static int is_safe_domain_rule(const char *s, int len)
{
    int i, has_plain_dot = 0, has_alpha = 0, has_bad_ctrl = 0;
    int regex_meta;

    if (!s || len < 4)
        return 0;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
            has_alpha = 1;
        if (c == '.')
            has_plain_dot = 1;
        if (c < 0x20 || c >= 0x7f)
            has_bad_ctrl = 1;
    }

    if (!has_alpha || has_bad_ctrl)
        return 0;

    regex_meta = has_regex_meta(s, len);

    /* For regex rules, require an escaped domain dot.  A payload regex like
     * ^[^\x00].+[^\x00]$ contains '.' as a wildcard and would match every
     * hostname if treated as a domain rule. */
    if (regex_meta) {
        if (!strstr(s, "\\."))
            return 0;
        if (strstr(s, "\\x"))
            return 0;
        return 1;
    }

    /* Plain BM/EXACT host rules may use literal dots. */
    return has_plain_dot;
}

static int domain_rule_port_match(const jmx_match_rule_t *r, uint16_t dport)
{
    int i;
    if (!r || r->port_count == 0)
        return 1;
    for (i = 0; i < r->port_count; i++) {
        if (dport >= r->ports[i].min_port && dport <= r->ports[i].max_port)
            return 1;
    }
    return 0;
}


static int host_eq(const char *h, int hlen, const char *s)
{
    int slen = (int)strlen(s);
    return hlen == slen && strncasecmp(h, s, slen) == 0;
}

static int host_suffix(const char *h, int hlen, const char *suffix)
{
    int slen = (int)strlen(suffix);
    if (hlen < slen)
        return 0;
    return strncasecmp(h + hlen - slen, suffix, slen) == 0;
}

static uint32_t match_high_conf_host_fallback(const char *hostname, int hostname_len,
                                              uint8_t l4_proto, uint16_t dport)
{
    if (!hostname || hostname_len <= 0)
        return 0;
    if (l4_proto != 6 && l4_proto != 17)
        return 0;
    if (l4_proto == 17 && dport != 443)
        return 0;

    /* Minimal legacy-compatible host fallback.  This is intentionally limited
     * to already-extracted HTTP Host / TLS SNI or DNS-learned hostname, never
     * raw payload regex. */
    if (host_eq(hostname, hostname_len, "www.baidu.com") ||
        host_eq(hostname, hostname_len, "m.baidu.com"))
        return 8001;   /* 百度, matches 30.1 legacy fwx behaviour */

    if (host_suffix(hostname, hostname_len, ".alidns.com") ||
        host_eq(hostname, hostname_len, "alidns.com"))
        return 100000071; /* 阿里HTTPDNS */

    if (host_suffix(hostname, hostname_len, ".weixin.qq.com") ||
        host_eq(hostname, hostname_len, "weixin.qq.com") ||
        host_suffix(hostname, hostname_len, ".wechat.com") ||
        host_eq(hostname, hostname_len, "wechat.com"))
        return 100000243; /* 微信，使用签名库权威 app_id */

    return 0;
}

static uint32_t match_domain_to_app(const jmx_rule_set_t *rs,
				     const char *hostname, int hostname_len,
				     uint8_t l4_proto, uint16_t dport)
{
    if (!rs || !hostname || hostname_len <= 0)
        return 0;

    uint32_t best_appid = 0;
    uint32_t best_priority = 0xFFFFFFFFU;

    int b;
    for (b = 0; b < JMX_HASH_BUCKETS; b++) {
        const jmx_match_rule_t *r;
        for (r = rs->match_buckets[b]; r; r = r->next) {
            if (r->method != JMX_MATCH_BM_STR &&
                r->method != JMX_MATCH_EXACT &&
                r->method != JMX_MATCH_REGEX)
                continue;
            if (r->match_len == 0)
                continue;
            if (r->proto == JMX_PROTO_TCP && l4_proto != 6)
                continue;
            if (r->proto == JMX_PROTO_UDP && l4_proto != 17)
                continue;
            if (!domain_rule_port_match(r, dport))
                continue;
            if (!is_safe_domain_rule(r->match_str, r->match_len))
                continue;
            if (r->priority >= best_priority)
                continue;

            int found = 0;
            if (r->method == JMX_MATCH_EXACT) {
                if (r->match_len == hostname_len &&
                    memcmp(r->match_str, hostname, r->match_len) == 0)
                    found = 1;
            } else if (has_regex_meta(r->match_str, r->match_len)) {
                int errcode = 0;
                PCRE2_SIZE erroff = 0;
                /* Rules with regex metacharacters: use PCRE2 */
                pcre2_code *re = pcre2_compile(
                    (PCRE2_SPTR)r->match_str, r->match_len,
                    PCRE2_CASELESS | PCRE2_DOTALL,
                    &errcode, &erroff, NULL);
                if (re) {
                    char hbuf[320];
                    int hlen;
                    pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, NULL);
                    /* iKuai domain regexes are matched against HTTP Host/SNI-like
                     * strings, but some rules encode a non-domain boundary before
                     * the domain (e.g. [^0-9a-zA-Z\-\.]baidu\.com). Add cheap
                     * sentinels so those rules can match without letting random
                     * payload regex back in. */
                    hlen = snprintf(hbuf, sizeof(hbuf), " %.*s ", hostname_len, hostname);
                    if (hlen > 0 && hlen < (int)sizeof(hbuf)) {
                        int rc = pcre2_match(re, (PCRE2_SPTR)hbuf, hlen,
                                             0, 0, md, NULL);
                        if (rc >= 0) found = 1;
                    }
                    pcre2_match_data_free(md);
                    pcre2_code_free(re);
                }
            } else {
                /* Plain string: substring match */
                if (r->match_len <= hostname_len) {
                    int j;
                    for (j = 0; j <= hostname_len - r->match_len; j++) {
                        if (hostname[j] == r->match_str[0] &&
                            memcmp(hostname + j, r->match_str, r->match_len) == 0) {
                            found = 1;
                            break;
                        }
                    }
                }
            }
            if (found) {
                best_priority = r->priority;
                best_appid = r->appid;
            }
        }
    }
    return best_appid;
}

static int nfqueue_cb(struct nfq_q_handle *qh,
		      struct nfgenmsg *nfmsg,
		      struct nfq_data *nfa,
		      void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	uint32_t id = 0;
	unsigned char *payload = NULL;
	unsigned char *l4_payload = NULL;
	int payload_len;
	int l4_payload_len = 0;
	uint16_t dport = 0, sport = 0;
	uint8_t proto = 0;
	uint8_t af = AF_INET;
	uint32_t src_ip = 0, dst_ip = 0;
	uint8_t src_ip6[16] = {0}, dst_ip6[16] = {0};
	int matched = 0;
	uint32_t best_appid = 0, best_priority = 0xFFFFFFFFU;
	char sni_hostname[128] = {0};
	char http_host[256] = {0};
	char http_ua[512] = {0};
	char matched_host[128] = {0};
	uint8_t matched_app_proto = 0;
	uint16_t domain_group_id = 0;

	(void)nfmsg; (void)data;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) id = ntohl(ph->packet_id);

	payload_len = nfq_get_payload(nfa, &payload);

	g_stat_packets++;

	if (payload_len < 20) goto verdict;

	/* Parse IPv4/IPv6 header and point to real L4 payload. NFQUEUE gives us the
	 * whole IP packet, while TLS/HTTP extractors and DreamingWrt DB payload regex
	 * expect TCP/UDP payload. */
	{
		uint8_t version = payload[0] >> 4;
		int l4off = 0;

		if (version == 4) {
			uint8_t ihl;
			af = AF_INET;
			ihl = (payload[0] & 0x0F) * 4;
			if (ihl < 20 || payload_len < ihl)
				goto verdict;
			proto = payload[9];
			memcpy(&src_ip, payload + 12, 4);
			memcpy(&dst_ip, payload + 16, 4);
			l4off = ihl;
		} else if (version == 6) {
			af = AF_INET6;
			if (payload_len < 40)
				goto verdict;
			proto = payload[6];
			memcpy(src_ip6, payload + 8, 16);
			memcpy(dst_ip6, payload + 24, 16);
			l4off = 40;
			/* Minimal extension-header walk for common IPv6 forwarding packets. */
			while ((proto == 0 || proto == 43 || proto == 44 || proto == 60) && payload_len >= l4off + 8) {
				uint8_t next = payload[l4off];
				int hdr_len;
				if (proto == 44)
					hdr_len = 8;
				else
					hdr_len = (payload[l4off + 1] + 1) * 8;
				if (hdr_len <= 0 || payload_len < l4off + hdr_len)
					goto verdict;
				proto = next;
				l4off += hdr_len;
			}
		} else {
			goto verdict;
		}

		if (proto == 6 && payload_len >= l4off + 20) {
			uint8_t doff;
			memcpy(&sport, payload + l4off, 2);
			memcpy(&dport, payload + l4off + 2, 2);
			sport = ntohs(sport);
			dport = ntohs(dport);
			doff = (payload[l4off + 12] >> 4) * 4;
			if (doff < 20 || payload_len < l4off + doff)
				goto verdict;
			l4_payload = payload + l4off + doff;
			l4_payload_len = payload_len - l4off - doff;
		} else if (proto == 17 && payload_len >= l4off + 8) {
			memcpy(&sport, payload + l4off, 2);
			memcpy(&dport, payload + l4off + 2, 2);
			sport = ntohs(sport);
			dport = ntohs(dport);
			l4_payload = payload + l4off + 8;
			l4_payload_len = payload_len - l4off - 8;
		}
	}

	if (!l4_payload || l4_payload_len <= 0)
		goto verdict;

	if (proto == 17 && sport == 53)
		dns_app_cache_learn(l4_payload, l4_payload_len);

	/* For all non-DNS traffic, try DNS cache lookup first.
	 * This covers QUIC (443), HTTPS (443), and any other app traffic.
	 * DNS cache provides more accurate app identification than broad
	 * payload/domain signature rules, especially for CDN IPs shared by multiple apps. */
	if (sport != 53 && dport != 53) {
		char cache_host[128] = {0};
		uint8_t cache_app_proto = 2;
		uint32_t cache_appid = 0;

		/* Check both directions: dst_ip (outbound) and src_ip (inbound reply) */
		if (af == AF_INET) {
			cache_appid = dns_app_cache_get(dst_ip, cache_host, sizeof(cache_host), &cache_app_proto);
			if (!cache_appid)
				cache_appid = dns_app_cache_get(src_ip, cache_host, sizeof(cache_host), &cache_app_proto);
		} else if (af == AF_INET6) {
			cache_appid = dns_app_cache_get_ex(AF_INET6, 0, dst_ip6, cache_host, sizeof(cache_host), &cache_app_proto);
			if (!cache_appid)
				cache_appid = dns_app_cache_get_ex(AF_INET6, 0, src_ip6, cache_host, sizeof(cache_host), &cache_app_proto);
		}
		if (cache_appid) {
			int copy_len = strlen(cache_host);
			if (copy_len > (int)sizeof(matched_host) - 1)
				copy_len = sizeof(matched_host) - 1;
			memcpy(matched_host, cache_host, copy_len);
			matched_host[copy_len] = '\0';
			matched_app_proto = cache_app_proto;
			matched = 1;
			best_appid = cache_appid;
			goto verdict;
		}

		/* QUIC Initial Packet: try to extract CRYPTO frame with TLS ClientHello SNI.
		 * QUIC Long Header: first byte has form 0b1CRRRRRR (C=1 for Initial).
		 * After header fields, there's a CRYPTO frame with TLS handshake. */
		if (dport == 443 && l4_payload_len > 20) {
			uint8_t first = l4_payload[0];
			if ((first & 0x80) && (first & 0x30)) {
				/* Long header: skip version(4) + DCID len(1) + DCID + SCID len(1) + SCID */
				int pos = 5;
				if (pos >= l4_payload_len) goto skip_quic;
				int dcid_len = l4_payload[pos++];
				pos += dcid_len;
				if (pos >= l4_payload_len) goto skip_quic;
				int scid_len = l4_payload[pos++];
				pos += scid_len;
				if (first == 0xC0 || first == 0xC1 || first == 0xC2 || first == 0xC3) {
					/* Initial packet: skip token length + token */
					if (pos >= l4_payload_len) goto skip_quic;
					int token_len = l4_payload[pos++];
					if (token_len > 0) {
						/* Variable-length token length for long tokens */
						if (token_len >= 0x40) {
							token_len = (token_len & 0x3F);
							if (pos < l4_payload_len)
								token_len = (token_len << 8) | l4_payload[pos++];
						}
						pos += token_len;
					}
				}
				/* Skip length field (2 bytes) */
				pos += 2;
				/* Now at payload: look for CRYPTO frame (type 0x06) */
				if (pos + 4 < l4_payload_len && l4_payload[pos] == 0x06) {
					int crypto_off = pos + 1;
					/* Skip crypto offset (variable length) */
					if (crypto_off < l4_payload_len && l4_payload[crypto_off] >= 0x40)
						crypto_off += 2;
					else
						crypto_off += 1;
					/* Skip crypto length */
					if (crypto_off < l4_payload_len && l4_payload[crypto_off] >= 0x40)
						crypto_off += 2;
					else
						crypto_off += 1;
					/* Try to extract SNI from the TLS ClientHello inside */
					if (crypto_off < l4_payload_len) {
						int quic_sni_l = extract_sni(l4_payload + crypto_off,
							l4_payload_len - crypto_off,
							sni_hostname, sizeof(sni_hostname));
						if (quic_sni_l > 0) {
							uint32_t quic_domain_appid =
								match_high_conf_host_fallback(sni_hostname, quic_sni_l, 17, 443);
							if (!quic_domain_appid)
								quic_domain_appid = match_domain_to_app(g_rule_set, sni_hostname, quic_sni_l, 17, 443);
							if (quic_domain_appid > 0) {
								int copy_len = quic_sni_l;
								if (copy_len > (int)sizeof(matched_host) - 1)
									copy_len = sizeof(matched_host) - 1;
								memcpy(matched_host, sni_hostname, copy_len);
								matched_host[copy_len] = '\0';
								matched_app_proto = 2;
								matched = 1;
								best_appid = quic_domain_appid;
								goto verdict;
							}
						}
					}
				}
			}
			skip_quic:;
		}
	}

	/* Prefer SNI/HTTP Host matching. Do not let generic payload regex rules
	 * write active apps by themselves: legacy payload databases contain many very weak payload
	 * patterns (single letters or TLS header bytes) that iKuai likely combines
	 * with extra context we have not decoded yet. */
	{
		int sni_l = extract_sni(l4_payload, l4_payload_len, sni_hostname, sizeof(sni_hostname));
		if (sni_l <= 0)
			extract_http_host(l4_payload, l4_payload_len, http_host, sizeof(http_host));
		if (sni_hostname[0] || http_host[0]) {
			const char *hostname = sni_hostname[0] ? sni_hostname : http_host;
			int hostname_len = sni_hostname[0] ? sni_l : (int)strlen(http_host);
			uint32_t domain_appid = match_high_conf_host_fallback(hostname, hostname_len, proto, dport);
			if (domain_appid == 0)
				domain_appid = match_domain_to_app(g_rule_set, hostname, hostname_len, proto, dport);
			if (domain_appid > 0) {
				int copy_len = hostname_len;
				if (copy_len > (int)sizeof(matched_host) - 1)
					copy_len = sizeof(matched_host) - 1;
				memcpy(matched_host, hostname, copy_len);
				matched_host[copy_len] = '\0';
				matched_app_proto = sni_hostname[0] ? 2 : 1;
				matched = 1;
				best_appid = domain_appid;
				goto verdict;
			}
		}
	}

	/* Payload regex matching is intentionally disabled for classification for
	 * now. Many payload regex rules are weak one-byte/binary hints; using them
	 * alone reintroduces the false positives we just removed. */
	if (0) {
		uint8_t v2_proto = 0;
		if (proto == 6) v2_proto = 1;
		else if (proto == 17) v2_proto = 2;

		int i;
		for (i = 0; i < g_rule_count; i++) {
			regex_rule_t *r = &g_rules[i];

			if (r->proto != 0 && r->proto != v2_proto)
				continue;

			if (r->port_count > 0) {
				int m, port_match = 0;
				for (m = 0; m < r->port_count; m++) {
					if (dport >= r->ports_min[m] &&
					    dport <= r->ports_max[m]) {
						port_match = 1;
						break;
					}
				}
				if (!port_match) continue;
			}

			pcre2_match_data *md = pcre2_match_data_create(JMX_REGEX_OVECTOR_SIZE, NULL);
			int rc = pcre2_match(r->re,
					     (PCRE2_SPTR)l4_payload, l4_payload_len,
					     0, 0, md, g_match_ctx);

			if (rc >= 0) {
				if (r->priority < best_priority) {
					best_priority = r->priority;
					best_appid = r->appid;
				}
				matched = 1;
			}
			pcre2_match_data_free(md);

			if (matched) break;
		}
	}

verdict:
	if (matched) {
		g_stat_matched++;
		jmx_nl_send_regex_result_ex(g_netlink_fd, af,
					    src_ip, dst_ip, src_ip6, dst_ip6,
					    sport, dport, proto, best_appid,
					    matched_app_proto, matched_host);

		/* Account extraction: optional; DreamingWrt DB currently ships no legacy NR rules. */
		if (g_rule_set && g_rule_set->nr_count > 0 && best_appid > 0) {
			char account[JMX_AUDIT_MAX_ACCOUNT_LEN] = {0};
			uint8_t v2_proto_nr = (proto == 6) ? 1 : (proto == 17) ? 2 : 0;
			uint8_t v2_dir = 0;  /* NFQUEUE doesn't know direction */
			const char *app_name;

			if (jmx_nr_match_and_extract(g_rule_set, best_appid,
						     l4_payload, l4_payload_len,
						     v2_proto_nr, v2_dir,
						     account, sizeof(account)) > 0) {
				jmx_audit_event_t ev;
				memset(&ev, 0, sizeof(ev));
				clock_gettime(CLOCK_REALTIME, &ev.ts);
				ev.appid = best_appid;
				app_name = jmx_rule_set_app_name(g_rule_set, best_appid);
				if (app_name)
					strncpy(ev.app_name, app_name,
						JMX_AUDIT_MAX_APP_NAME_LEN - 1);
				strncpy(ev.account, account,
					JMX_AUDIT_MAX_ACCOUNT_LEN - 1);
				ev.src_ip = src_ip;
				ev.dst_ip = dst_ip;
				ev.src_port = sport;
				ev.dst_port = dport;
				ev.proto = proto;

				/* Phase 5: domain + hosttype → audit fields */
				{
					char sni_buf[128] = {0}, host_buf[256] = {0}, ua_buf[512] = {0};
					int sni_l = extract_sni(l4_payload, l4_payload_len, sni_buf, sizeof(sni_buf));
					if (sni_l <= 0) {
						extract_http_host(l4_payload, l4_payload_len, host_buf, sizeof(host_buf));
						extract_http_ua(l4_payload, l4_payload_len, ua_buf, sizeof(ua_buf));
					}
					ev.domain_group_id = 0;
					ev.hosttype_cat = 0;
					ev.sni[0] = '\0';
					ev.user_agent[0] = '\0';
					if (sni_l > 0) {
						ev.domain_group_id = jmx_domain_match(sni_buf, sni_l);
						strncpy(ev.sni, sni_buf, sizeof(ev.sni) - 1);
					} else if (host_buf[0]) {
						ev.domain_group_id = jmx_domain_match(host_buf, strlen(host_buf));
						strncpy(ev.sni, host_buf, sizeof(ev.sni) - 1);
					}
					if (ua_buf[0]) {
						strncpy(ev.user_agent, ua_buf, sizeof(ev.user_agent) - 1);
						ev.hosttype_cat = jmx_ht_match_ua(ua_buf, strlen(ua_buf),
								NULL, 0, NULL, 0, NULL, 0);
					}
				}
				jmx_audit_log(&ev);
			}
		}

		nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	} else {
		g_stat_no_match++;
		/* Phase 5: try domain-based matching for unmatched packets */
		{
			char sni_buf[128] = {0}, host_buf[256] = {0};
			int sni_l = extract_sni(l4_payload, l4_payload_len, sni_buf, sizeof(sni_buf));
			if (sni_l <= 0)
				extract_http_host(l4_payload, l4_payload_len, host_buf, sizeof(host_buf));

			const char *hostname = sni_buf[0] ? sni_buf : host_buf;
			int hostname_len = sni_buf[0] ? sni_l : (int)strlen(host_buf);

			if (hostname_len > 0 && g_rule_set) {
				uint32_t domain_appid = match_high_conf_host_fallback(hostname, hostname_len, proto, dport);
				if (domain_appid == 0)
					domain_appid = match_domain_to_app(g_rule_set, hostname, hostname_len, proto, dport);
				if (domain_appid > 0) {
					uint8_t app_proto = sni_buf[0] ? 2 : 1;
					jmx_nl_send_regex_result_ex(g_netlink_fd, af,
								    src_ip, dst_ip, src_ip6, dst_ip6,
								    sport, dport, proto, domain_appid,
								    app_proto, hostname);
					nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
					return 0;
				}
			}
			if (hostname_len > 0) {
				uint16_t dgid = jmx_domain_match(hostname, hostname_len);
				if (dgid > 0)
					fprintf(stderr, "domain[nomatch]: %s -> group %u (%s)\n",
						hostname, dgid,
						jmx_domain_group_name(dgid) ?: "?");
			}
		}
		nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}

	return 0;
}

/* ── Thread ── */

static void *nfqueue_thread(void *arg)
{
	char buf[65535] __attribute__((aligned));
	int rv;

	(void)arg;

	while (g_running) {
		rv = recv(g_nl_fd, buf, sizeof(buf), 0);
		if (rv < 0) {
			if (errno == EINTR) continue;
			if (!g_running) break;
			perror("jmx_regex: recv");
			break;
		}
		nfq_handle_packet(g_nfq_h, buf, rv);
	}

	return NULL;
}

/* ── Public API ── */

int jmx_regex_init(const jmx_rule_set_t *rs)
{
	jmx_match_rule_t *r;
	int count = 0, i, idx = 0;

	if (!rs) return -1;

	for (i = 0; i < JMX_HASH_BUCKETS; i++)
		for (r = rs->match_buckets[i]; r; r = r->next)
			if (r->method == JMX_MATCH_REGEX && r->match_len > 0)
				count++;

	if (count == 0) {
		fprintf(stderr, "jmx_regex: no REGEX rules\n");
		return 0;
	}
	if (count > JMX_MAX_REGEX_RULES) count = JMX_MAX_REGEX_RULES;

	g_rules = calloc(count, sizeof(regex_rule_t));
	if (!g_rules) return -1;

	g_compile_ctx = pcre2_compile_context_create(NULL);
	g_match_ctx = pcre2_match_context_create(NULL);
	pcre2_set_match_limit(g_match_ctx, JMX_REGEX_MATCH_LIMIT);
	pcre2_set_recursion_limit(g_match_ctx, JMX_REGEX_MATCH_LIMIT / 10);

	for (i = 0; i < JMX_HASH_BUCKETS && idx < count; i++) {
		for (r = rs->match_buckets[i]; r; r = r->next) {
			int errcode, j;
			PCRE2_SIZE erroff;
			pcre2_code *re;

			if (r->method != JMX_MATCH_REGEX || r->match_len == 0)
				continue;
			if (idx >= count) break;

			re = pcre2_compile((PCRE2_SPTR)r->match_str,
					   r->match_len,
					   PCRE2_DOTALL | PCRE2_NO_AUTO_CAPTURE,
					   &errcode, &erroff,
					   g_compile_ctx);

			if (!re) {
				PCRE2_UCHAR errbuf[256];
				pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
				fprintf(stderr, "jmx_regex: PCRE2 fail appid=%u: %s (at %zu)\n",
					r->appid, errbuf, erroff);
				continue;
			}

			g_rules[idx].appid = r->appid;
			g_rules[idx].priority = r->priority;
			g_rules[idx].proto = r->proto;
			g_rules[idx].dir = r->dir;
			g_rules[idx].port_count = r->port_count;
			g_rules[idx].pkt_seq = r->pkt_seq;
			g_rules[idx].re = re;
			for (j = 0; j < r->port_count; j++) {
				g_rules[idx].ports_min[j] = r->ports[j].min_port;
				g_rules[idx].ports_max[j] = r->ports[j].max_port;
			}
			idx++;
		}
	}
	g_rule_count = idx;

	qsort(g_rules, g_rule_count, sizeof(regex_rule_t), cmp_regex_prio);

	/* Debug: print proto distribution */
    {
        int tc = 0, uc = 0, ac = 0;
        for (int di = 0; di < g_rule_count; di++) {
            if (g_rules[di].proto == 1) tc++;
            else if (g_rules[di].proto == 2) uc++;
            else ac++;
        }
        fprintf(stderr, "jmx_regex: proto dist tcp=%d udp=%d any=%d\n", tc, uc, ac);
    }
    fprintf(stderr, "jmx_regex: compiled %d/%d REGEX rules\n",
		g_rule_count, count);
	return 0;
}

void jmx_regex_exit(void)
{
	int i;
	for (i = 0; i < g_rule_count; i++)
		if (g_rules[i].re) pcre2_code_free(g_rules[i].re);
	free(g_rules);
	g_rules = NULL;
	g_rule_count = 0;
	if (g_match_ctx) pcre2_match_context_free(g_match_ctx);
	if (g_compile_ctx) pcre2_compile_context_free(g_compile_ctx);
	g_match_ctx = NULL;
	g_compile_ctx = NULL;
}

int jmx_regex_start(void)
{
	if (g_running) return 0;
	if (g_rule_count == 0) return 0;

	g_nfq_h = nfq_open();
	if (!g_nfq_h) { perror("jmx_regex: nfq_open"); return -1; }

	if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0)
		fprintf(stderr, "jmx_regex: nfq_unbind warning\n");
	if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
		perror("jmx_regex: nfq_bind");
		nfq_close(g_nfq_h);
		return -1;
	}

	g_qh = nfq_create_queue(g_nfq_h, JMX_NFQUEUE_NUM, &nfqueue_cb, NULL);
	if (!g_qh) {
		perror("jmx_regex: nfq_create_queue");
		nfq_close(g_nfq_h);
		return -1;
	}

	if (nfq_set_mode(g_qh, NFQNL_COPY_PACKET, 65535) < 0)
		perror("jmx_regex: nfq_set_mode");

	g_nl_fd = nfq_fd(g_nfq_h);
	if (setup_nftables_rule() != 0) {
		nfq_destroy_queue(g_qh);
		nfq_close(g_nfq_h);
		g_qh = NULL;
		g_nfq_h = NULL;
		g_nl_fd = -1;
		return -1;
	}

	g_running = 1;
	if (pthread_create(&g_thread, NULL, nfqueue_thread, NULL) != 0) {
		perror("jmx_regex: pthread_create");
		g_running = 0;
		(void)remove_nftables_rule();
		nfq_destroy_queue(g_qh);
		nfq_close(g_nfq_h);
		g_qh = NULL;
		g_nfq_h = NULL;
		g_nl_fd = -1;
		return -1;
	}

	fprintf(stderr, "jmx_regex: NFQUEUE started on queue %d with %d rules\n",
		JMX_NFQUEUE_NUM, g_rule_count);
	return 0;
}

void jmx_regex_stop(void)
{
	if (!g_running) return;
	g_running = 0;
	pthread_join(g_thread, NULL);
	if (g_qh) nfq_destroy_queue(g_qh);
	if (g_nfq_h) nfq_close(g_nfq_h);
	g_qh = NULL;
	g_nfq_h = NULL;
	(void)remove_nftables_rule();
	fprintf(stderr, "jmx_regex: stopped (pkts=%llu matched=%llu miss=%llu)\n",
		(unsigned long long)g_stat_packets,
		(unsigned long long)g_stat_matched,
		(unsigned long long)g_stat_no_match);
}

uint64_t jmx_regex_stat_packets(void) { return g_stat_packets; }
uint64_t jmx_regex_stat_matched(void) { return g_stat_matched; }
uint64_t jmx_regex_stat_miss(void) { return g_stat_no_match; }

int jmx_regex_count(void) { return g_rule_count; }

/* Set netlink fd for sending results to kernel */
void jmx_regex_set_netlink_fd(int fd) { g_netlink_fd = fd; }
