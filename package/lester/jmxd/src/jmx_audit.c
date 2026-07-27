// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_audit.c - Audit log system for NR account extraction
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "jmx_audit.h"

/* ── State ── */

static FILE *g_log_fp;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_total_events;
static uint64_t g_dropped_events;
static char g_log_path[256] = JMX_AUDIT_LOG_PATH;

/* Ring buffer for recent events (for ubus query) */
#define JMX_AUDIT_RING_SIZE 256
static jmx_audit_event_t g_ring[JMX_AUDIT_RING_SIZE];
static int g_ring_head;
static int g_ring_count;
static pthread_mutex_t g_ring_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Log rotation ── */

static void rotate_log(void)
{
	struct stat st;
	char old_path[288];

	if (!g_log_fp) return;

	fflush(g_log_fp);

	if (stat(g_log_path, &st) == 0 && st.st_size > JMX_AUDIT_LOG_MAX_SIZE) {
		fclose(g_log_fp);
		g_log_fp = NULL;

		/* Rotate: .2 -> delete, .1 -> .2, current -> .1 */
		snprintf(old_path, sizeof(old_path), "%s.2", g_log_path);
		unlink(old_path);
		snprintf(old_path, sizeof(old_path), "%s.1", g_log_path);
		rename(old_path, old_path + 4);  /* .1 -> .2 — actually just rename */
		rename(old_path, old_path);  /* fix: rename current -> .1 */
		snprintf(old_path, sizeof(old_path), "%s.1", g_log_path);
		rename(g_log_path, old_path);

		g_log_fp = fopen(g_log_path, "a");
	}
}

/* ── Init / Exit ── */

int jmx_audit_init(void)
{
	pthread_mutex_lock(&g_log_lock);
	g_log_fp = fopen(g_log_path, "a");
	if (!g_log_fp) {
		/* Try creating directory */
		char dir[256];
		snprintf(dir, sizeof(dir), "%s", g_log_path);
		char *slash = strrchr(dir, '/');
		if (slash) {
			*slash = '\0';
			mkdir(dir, 0755);
			g_log_fp = fopen(g_log_path, "a");
		}
	}
	pthread_mutex_unlock(&g_log_lock);

	g_total_events = 0;
	g_dropped_events = 0;
	g_ring_head = 0;
	g_ring_count = 0;

	return g_log_fp ? 0 : -1;
}

void jmx_audit_exit(void)
{
	pthread_mutex_lock(&g_log_lock);
	if (g_log_fp) {
		fclose(g_log_fp);
		g_log_fp = NULL;
	}
	pthread_mutex_unlock(&g_log_lock);
}

/* ── Logging ── */

int jmx_audit_log(const jmx_audit_event_t *ev)
{
	char ip_str[32], dst_str[32];
	char json_buf[512];
	int len;

	if (!ev) return -1;

	/* Add to ring buffer */
	pthread_mutex_lock(&g_ring_lock);
	g_ring[g_ring_head] = *ev;
	g_ring_head = (g_ring_head + 1) % JMX_AUDIT_RING_SIZE;
	if (g_ring_count < JMX_AUDIT_RING_SIZE)
		g_ring_count++;
	pthread_mutex_unlock(&g_ring_lock);

	/* Format JSON line */
	inet_ntop(AF_INET, &ev->src_ip, ip_str, sizeof(ip_str));
	inet_ntop(AF_INET, &ev->dst_ip, dst_str, sizeof(dst_str));

	len = snprintf(json_buf, sizeof(json_buf),
		"{\"ts\":%ld.%09ld,\"appid\":%u,\"app\":\"%s\","
		"\"account\":\"%s\",\"src\":\"%s:%u\",\"dst\":\"%s:%u\","
		"\"proto\":%u,\"dir\":%u,\"domain_group\":%u,\"hosttype\":%u,"
		"\"sni\":\"%s\",\"ua\":\"%s\"}\n",
		(long)ev->ts.tv_sec, ev->ts.tv_nsec,
		ev->appid, ev->app_name,
		ev->account,
		ip_str, ev->src_port,
		dst_str, ev->dst_port,
		ev->proto, ev->direction,
		ev->domain_group_id, ev->hosttype_cat,
		ev->sni, ev->user_agent);

	/* Write to log file */
	pthread_mutex_lock(&g_log_lock);
	if (g_log_fp) {
		if (fwrite(json_buf, 1, len, g_log_fp) == (size_t)len) {
			fflush(g_log_fp);
			g_total_events++;
			rotate_log();
		} else {
			g_dropped_events++;
		}
	} else {
		g_dropped_events++;
	}
	pthread_mutex_unlock(&g_log_lock);

	return 0;
}

/* ── Query for ubus ── */

int jmx_audit_query_json(char *buf, size_t buf_size, int max_events)
{
	int written = 0;
	int count, i, idx;

	if (!buf || buf_size < 4) return 0;

	pthread_mutex_lock(&g_ring_lock);

	count = g_ring_count < max_events ? g_ring_count : max_events;
	if (count > JMX_AUDIT_RING_SIZE)
		count = JMX_AUDIT_RING_SIZE;

	written += snprintf(buf + written, buf_size - written, "[");

	/* Read from ring buffer (newest first) */
	for (i = 0; i < count && written < (int)buf_size - 64; i++) {
		char ip_str[32], dst_str[32];
		idx = (g_ring_head - 1 - i + JMX_AUDIT_RING_SIZE) % JMX_AUDIT_RING_SIZE;
		const jmx_audit_event_t *ev = &g_ring[idx];

		inet_ntop(AF_INET, &ev->src_ip, ip_str, sizeof(ip_str));
		inet_ntop(AF_INET, &ev->dst_ip, dst_str, sizeof(dst_str));

		if (i > 0)
			written += snprintf(buf + written, buf_size - written, ",");

		written += snprintf(buf + written, buf_size - written,
			"{\"ts\":%ld,\"appid\":%u,\"app\":\"%s\","
			"\"account\":\"%s\",\"src\":\"%s:%u\","
			"\"dst\":\"%s:%u\",\"proto\":%u,\"dir\":%u,"
			"\"domain_group\":%u,\"hosttype\":%u,\"sni\":\"%s\"}",
			(long)ev->ts.tv_sec, ev->appid, ev->app_name,
			ev->account, ip_str, ev->src_port,
			dst_str, ev->dst_port,
			ev->proto, ev->direction,
			ev->domain_group_id, ev->hosttype_cat,
			ev->sni);
	}

	written += snprintf(buf + written, buf_size - written, "]");
	pthread_mutex_unlock(&g_ring_lock);

	return written;
}

uint64_t jmx_audit_total_events(void) { return g_total_events; }
uint64_t jmx_audit_dropped_events(void) { return g_dropped_events; }
