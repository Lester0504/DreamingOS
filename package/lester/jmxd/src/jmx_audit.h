/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_audit.h - Audit log system for NR account extraction
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_AUDIT_H__
#define __JMX_AUDIT_H__

#include <stdint.h>
#include <time.h>

#define JMX_AUDIT_MAX_ACCOUNT_LEN 128
#define JMX_AUDIT_MAX_APP_NAME_LEN 64
#define JMX_AUDIT_LOG_PATH "/var/log/jmx_audit.jsonl"
#define JMX_AUDIT_LOG_MAX_SIZE (10 * 1024 * 1024)  /* 10MB rotation */
#define JMX_AUDIT_LOG_KEEP_OLD 2

/* Single audit event */
typedef struct {
	struct timespec ts;
	uint32_t appid;
	char     app_name[JMX_AUDIT_MAX_APP_NAME_LEN];
	char     account[JMX_AUDIT_MAX_ACCOUNT_LEN];
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t  proto;       /* 6=TCP, 17=UDP */
	uint8_t  direction;   /* 1=original, 2=reply */
	uint16_t domain_group_id;  /* Phase 5: domain classification */
	uint16_t hosttype_cat;     /* Phase 5: host type category */
	char     sni[128];         /* Phase 5: SNI hostname or HTTP Host */
	char     user_agent[256];  /* Phase 5: HTTP User-Agent */
} jmx_audit_event_t;

/* Initialize audit log system */
int jmx_audit_init(void);

/* Shutdown audit log system */
void jmx_audit_exit(void);

/* Log an audit event (thread-safe, non-blocking) */
int jmx_audit_log(const jmx_audit_event_t *ev);

/* Query recent events via ubus (returns JSON array) */
int jmx_audit_query_json(char *buf, size_t buf_size, int max_events);

/* Get stats */
uint64_t jmx_audit_total_events(void);
uint64_t jmx_audit_dropped_events(void);

#endif /* __JMX_AUDIT_H__ */
