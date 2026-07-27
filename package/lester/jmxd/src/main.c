// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include "jmx_user.h"
#include "jmx_netlink.h"
#include "jmx_ubus.h"
#include "jmx_config.h"
#include "jmx_dreamingwrt_api.h"
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "jmx.h"
#include "jmx_rule.h"
#include "jmx_signature_db.h"
#include "jmx_nl_push.h"
#include "jmx_v3_gate.h"
#include "jmx_regex.h"
#include "jmx_audit.h"
#include "jmx_domain.h"
#include "jmx_hosttype.h"
#include <stdio.h>
#include <pthread.h>
#include "jmx_utils.h"
#include "jmx_app_filter.h"
#include "jmx_route.h"
#include "jmx_db.h"
#include "jmx_huginn.h"
#include "jmx_dhcp_sniff.h"
#include "jmx_system.h"
#include "jmx_events.h"
#include "jmx_netconfig_db.h"
#include "jmx_flow_event.h"
#include "jmx_topology_history.h"
#include "jmx_storage_guard.h"
#include "jmx_core_watchdog.h"
#include "jmx_system_data_path.h"

int current_log_level = LOG_LEVEL_WARN;
#define CMD_GET_LAN_IP_FMT   "ifconfig %s | grep 'inet addr' | awk '{print $2}' | awk -F: '{print $2}'"
#define CMD_GET_LAN_MASK_FMT "ifconfig %s | grep 'inet addr' | awk '{print $4}' | awk -F: '{print $2}'"
#define JMX_CORE_HEALTH_STATUS_PATH "/tmp/dreamingwrt-health.status"
#define JMX_CORE_HEALTH_STATUS_STALE_SEC 120
int g_jmx_config_chage = 1;
int g_hnat_init = 0;
int g_feature_update = 0;
extern void collect_interface_traffic_rate(void);

/*
 * Split workers now own periodic metrics, route health, identity collection,
 * and maintenance scheduling. Keep the old in-core scheduler as an explicit
 * fallback only; running both doubles ubus/DB work and causes dashboard stalls.
 */
static int jmx_core_legacy_scheduler_enabled(void)
{
    const char *v = getenv("DREAMINGWRT_CORE_LEGACY_SCHEDULER");

    return v && (!strcmp(v, "1") || !strcasecmp(v, "true") ||
                 !strcasecmp(v, "yes") || !strcasecmp(v, "on"));
}

static int jmx_core_legacy_netlink_enabled(void)
{
    const char *v = getenv("DREAMINGWRT_CORE_LEGACY_NETLINK");

    return v && (!strcmp(v, "1") || !strcasecmp(v, "true") ||
                 !strcasecmp(v, "yes") || !strcasecmp(v, "on"));
}

typedef enum {
    JMX_CORE_STAGE_PROCESS_START = 0,
    JMX_CORE_STAGE_BASE_TABLES,
    JMX_CORE_STAGE_DB_INIT,
    JMX_CORE_STAGE_UBUS_READY,
    JMX_CORE_STAGE_FINGERPRINT_CATALOG,
    JMX_CORE_STAGE_STARTUP_SIGNATURE_MATCH,
    JMX_CORE_STAGE_AUXILIARY_PROBES,
    JMX_CORE_STAGE_HOSTTYPE_OUI,
    JMX_CORE_STAGE_SIGNATURE_LOADING,
    JMX_CORE_STAGE_READY,
    JMX_CORE_STAGE_FAILED
} jmx_core_stage_t;

typedef struct {
    jmx_core_stage_t stage;
    int ready;
    int degraded;
    int signature_loading;
    int signature_loaded;
    int signature_failed;
    int signature_unavailable;
    int signature_rules;
    int signature_regex_rules;
    int hosttype_oui_loaded;
    int hosttype_oui_count;
    int fingerprint_catalog_done;
    int fingerprint_catalog_available;
    int startup_sig_match_done;
    int ubus_ready;
    int last_error_code;
    char last_error[128];
    char signature_path[256];
    time_t started_at;
    time_t ready_at;
    time_t updated_at;
    time_t signature_started_at;
    time_t signature_finished_at;
    int64_t started_mono_ms;
    int64_t ready_mono_ms;
} jmx_core_runtime_t;

static jmx_core_runtime_t g_core_runtime = {
    .stage = JMX_CORE_STAGE_PROCESS_START,
};
static pthread_mutex_t g_core_runtime_lock = PTHREAD_MUTEX_INITIALIZER;
static struct uloop_timeout jmx_startup_tm;

static int64_t jmx_core_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static const char *jmx_core_stage_name(jmx_core_stage_t stage)
{
    switch (stage) {
    case JMX_CORE_STAGE_PROCESS_START: return "process_start";
    case JMX_CORE_STAGE_BASE_TABLES: return "base_tables";
    case JMX_CORE_STAGE_DB_INIT: return "db_init";
    case JMX_CORE_STAGE_UBUS_READY: return "ubus_ready";
    case JMX_CORE_STAGE_FINGERPRINT_CATALOG: return "fingerprint_catalog";
    case JMX_CORE_STAGE_STARTUP_SIGNATURE_MATCH: return "startup_signature_match";
    case JMX_CORE_STAGE_AUXILIARY_PROBES: return "auxiliary_probes";
    case JMX_CORE_STAGE_HOSTTYPE_OUI: return "hosttype_oui";
    case JMX_CORE_STAGE_SIGNATURE_LOADING: return "signature_loading";
    case JMX_CORE_STAGE_READY: return "ready";
    case JMX_CORE_STAGE_FAILED: return "failed";
    default: return "unknown";
    }
}

static void jmx_core_set_stage(jmx_core_stage_t stage)
{
    pthread_mutex_lock(&g_core_runtime_lock);
    g_core_runtime.stage = stage;
    g_core_runtime.updated_at = time(NULL);
    if (stage == JMX_CORE_STAGE_READY) {
        g_core_runtime.ready = 1;
        if (!g_core_runtime.ready_mono_ms)
            g_core_runtime.ready_mono_ms = jmx_core_monotonic_ms();
        if (!g_core_runtime.ready_at)
            g_core_runtime.ready_at = g_core_runtime.updated_at;
    } else if (stage == JMX_CORE_STAGE_FAILED) {
        g_core_runtime.ready = 0;
    }
    pthread_mutex_unlock(&g_core_runtime_lock);
    LOG_WARN("core startup stage=%s\n", jmx_core_stage_name(stage));
}

static void jmx_core_set_error(const char *error, int code)
{
    pthread_mutex_lock(&g_core_runtime_lock);
    g_core_runtime.degraded = 1;
    g_core_runtime.last_error_code = code;
    snprintf(g_core_runtime.last_error, sizeof(g_core_runtime.last_error),
             "%s", error ? error : "");
    g_core_runtime.updated_at = time(NULL);
    pthread_mutex_unlock(&g_core_runtime_lock);
}

struct json_object *jmx_core_status_json(void)
{
    jmx_core_runtime_t snap;
    struct json_object *data = json_object_new_object();
    time_t now = time(NULL);
    int64_t now_mono_ms = jmx_core_monotonic_ms();
    int64_t uptime_ms = 0;
    int64_t startup_ms = 0;
    time_t effective_started_at;
    time_t effective_ready_at;

    pthread_mutex_lock(&g_core_runtime_lock);
    snap = g_core_runtime;
    pthread_mutex_unlock(&g_core_runtime_lock);

    if (snap.started_mono_ms > 0 && now_mono_ms >= snap.started_mono_ms)
        uptime_ms = now_mono_ms - snap.started_mono_ms;
    if (snap.ready_mono_ms >= snap.started_mono_ms && snap.started_mono_ms > 0)
        startup_ms = snap.ready_mono_ms - snap.started_mono_ms;
    effective_started_at = uptime_ms > 0 ? now - (time_t)(uptime_ms / 1000) : snap.started_at;
    effective_ready_at = snap.ready_mono_ms > 0 ?
        effective_started_at + (time_t)(startup_ms / 1000) : 0;

    json_object_object_add(data, "ok", json_object_new_boolean(1));
    json_object_object_add(data, "state",
                           json_object_new_string(snap.ready ? "ready" :
                                                  (snap.stage == JMX_CORE_STAGE_FAILED ?
                                                   "failed" : "starting")));
    json_object_object_add(data, "ready", json_object_new_boolean(snap.ready));
    json_object_object_add(data, "degraded", json_object_new_boolean(snap.degraded));
    json_object_object_add(data, "stage", json_object_new_string(jmx_core_stage_name(snap.stage)));
    json_object_object_add(data, "stage_id", json_object_new_int((int)snap.stage));
    json_object_object_add(data, "started_at", json_object_new_int64(effective_started_at));
    json_object_object_add(data, "ready_at", json_object_new_int64(effective_ready_at));
    json_object_object_add(data, "updated_at", json_object_new_int64(snap.updated_at));
    json_object_object_add(data, "uptime_sec", json_object_new_int64(uptime_ms / 1000));
    json_object_object_add(data, "startup_duration_ms",
                           json_object_new_int64(startup_ms));
    json_object_object_add(data, "ubus_ready", json_object_new_boolean(snap.ubus_ready));
    json_object_object_add(data, "fingerprint_catalog_done", json_object_new_boolean(snap.fingerprint_catalog_done));
    json_object_object_add(data, "startup_sig_match_done", json_object_new_boolean(snap.startup_sig_match_done));
    json_object_object_add(data, "hosttype_oui_loaded", json_object_new_boolean(snap.hosttype_oui_loaded));
    json_object_object_add(data, "hosttype_oui_count", json_object_new_int(snap.hosttype_oui_count));
    json_object_object_add(data, "signature_loading", json_object_new_boolean(snap.signature_loading));
    json_object_object_add(data, "signature_loaded", json_object_new_boolean(snap.signature_loaded));
    json_object_object_add(data, "signature_failed", json_object_new_boolean(snap.signature_failed));
    json_object_object_add(data, "signature_state",
                           json_object_new_string(snap.signature_loaded ? "ready" :
                                                  (snap.signature_unavailable ? "unavailable" :
                                                   (snap.signature_failed ? "failed" : "pending"))));
    json_object_object_add(data, "fingerprint_catalog_state",
                           json_object_new_string(!snap.fingerprint_catalog_done ? "pending" :
                                                  (snap.fingerprint_catalog_available ?
                                                   "ready" : "unavailable")));
    json_object_object_add(data, "signature_rules", json_object_new_int(snap.signature_rules));
    json_object_object_add(data, "signature_regex_rules", json_object_new_int(snap.signature_regex_rules));
    json_object_object_add(data, "signature_path", json_object_new_string(snap.signature_path));
    json_object_object_add(data, "signature_started_at", json_object_new_int64(snap.signature_started_at));
    json_object_object_add(data, "signature_finished_at", json_object_new_int64(snap.signature_finished_at));
    json_object_object_add(data, "last_error", json_object_new_string(snap.last_error));
    json_object_object_add(data, "last_error_code", json_object_new_int(snap.last_error_code));
    json_object_object_add(data, "source", json_object_new_string("dreamingwrt-core"));
    jmx_core_watchdog_append_status(data);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}

jmx_status_t g_jmx_status = {
    .internet = 1  
};

void jmx_refresh_health_status(void)
{
    FILE *fp;
    char line[128];
    int internet = -1;
    int checked = 0;
    long updated_at = 0;
    time_t now = time(NULL);

    fp = fopen(JMX_CORE_HEALTH_STATUS_PATH, "r");
    if (!fp)
        return;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "internet=%d", &internet) == 1)
            continue;
        if (sscanf(line, "checked=%d", &checked) == 1)
            continue;
        if (sscanf(line, "updated_at=%ld", &updated_at) == 1)
            continue;
    }
    fclose(fp);

    if (!checked || internet < 0 || updated_at <= 0)
        return;
    if (now > 0 && updated_at > 0 &&
        now - (time_t)updated_at > JMX_CORE_HEALTH_STATUS_STALE_SEC)
        return;

    g_jmx_status.internet = internet ? 1 : 0;
}

void jmx_timeout_handler(struct uloop_timeout *t);


struct uloop_timeout jmx_tm = {
    .cb = jmx_timeout_handler};

static struct uloop_fd jmx_nl_fd = {
    .cb = jmx_netlink_handler,
};


/* ── v2 protobuf rule loader ── */

static jmx_rule_set_t g_v2_rules;
static int g_v2_rules_loaded = 0;
static uint32_t g_v2_version = 1;
static int g_v2_nl_fd = -1;
static pthread_mutex_t g_signature_runtime_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * v3 is opt-in.  Keep the userspace copy that produced the active kernel
 * generation so a failed reload can leave both the old generation and its
 * lifecycle state untouched.
 */
static jmx_chain_rule_set_t g_v3_chain_rules;
static int g_v3_chain_rules_loaded = 0;
/* A failed bounded probe is indeterminate: old kernels are silent, but a
 * modern kernel can also be transiently busy.  Retry only on a later explicit
 * signature reload; once support is observed, keep that capability snapshot. */
static int g_v3_probe_state = 0; /* 0=not probed, 1=supported, -1=retry later */
static uint32_t g_v3_probe_attempts = 0;
static uint32_t g_v3_next_generation = 1;
static jmx_v3_kernel_status_t g_v3_kernel_status;

static const char *jmx_v3_mode_name(uint8_t mode)
{
	switch (mode) {
	case JMX_V3_MODE_SHADOW:
		return "shadow";
	case JMX_V3_MODE_ACTIVE:
		return "active";
	default:
		return "off";
	}
}

static uint8_t jmx_v3_configured_mode(void)
{
	static int initialized;
	static uint8_t mode = JMX_V3_MODE_OFF;
	uint8_t requested_mode = JMX_V3_MODE_OFF;
	const char *value;

	if (initialized)
		return mode;
	initialized = 1;
	value = getenv("DREAMINGWRT_DPI_CHAIN_MODE");
	if (value && !strcasecmp(value, "shadow"))
		requested_mode = JMX_V3_MODE_SHADOW;
	else if (value && !strcasecmp(value, "active"))
		requested_mode = JMX_V3_MODE_ACTIVE;
	else if (value && value[0] && strcasecmp(value, "off"))
		LOG_WARN("v3: invalid DREAMINGWRT_DPI_CHAIN_MODE='%.*s'; using off\n",
			 32, value);
	mode = jmx_v3_effective_mode(requested_mode);
	if (requested_mode != JMX_V3_MODE_OFF && mode == JMX_V3_MODE_OFF)
		LOG_WARN("v3: requested chain mode=%s but production gate is closed; using off\n",
			 jmx_v3_mode_name(requested_mode));
	LOG_WARN("v3: configured chain mode=%s\n", jmx_v3_mode_name(mode));
	return mode;
}

static uint32_t jmx_v3_reserve_generation(void)
{
	uint32_t generation = g_v3_next_generation;

	if (!generation)
		generation = 1;
	g_v3_next_generation = generation == UINT32_MAX ? 1 : generation + 1;
	return generation;
}

static void jmx_v3_probe_if_needed(void)
{
	jmx_v3_kernel_status_t status;
	int saved_errno;

	if (g_v3_probe_state > 0)
		return;
	if (g_v2_nl_fd < 0) {
		g_v2_nl_fd = jmx_v2_netlink_init();
		if (g_v2_nl_fd < 0) {
			LOG_WARN("v3: netlink unavailable; deferring finite capability probe\n");
			return;
		}
	}

	g_v3_probe_attempts++;
	memset(&status, 0, sizeof(status));
	errno = 0;
	if (jmx_nl_v3_probe(g_v2_nl_fd, &status) != 0) {
		saved_errno = errno;
		g_v3_probe_state = -1;
		LOG_WARN("v3: capability probe attempt=%u indeterminate reason=%u detail=%u error=%s; using pure v2 for this load and retrying on the next reload\n",
			 g_v3_probe_attempts, status.reason, status.detail,
			 saved_errno ? strerror(saved_errno) : "no status ACK");
		return;
	}

	g_v3_probe_state = 1;
	g_v3_kernel_status = status;
	g_v3_next_generation = status.active_generation == UINT32_MAX ?
		1 : status.active_generation + 1;
	if (!g_v3_next_generation)
		g_v3_next_generation = 1;
	LOG_WARN("v3: kernel supported caps=0x%08x active_generation=%u mode=%s rules=%u\n",
		 status.engine_capabilities, status.active_generation,
		 jmx_v3_mode_name((uint8_t)status.active_mode), status.active_rules);
}

static void jmx_core_note_signature_start(const char *path)
{
	pthread_mutex_lock(&g_core_runtime_lock);
	g_core_runtime.stage = JMX_CORE_STAGE_SIGNATURE_LOADING;
	g_core_runtime.ready = 0;
	g_core_runtime.signature_loading = 1;
	g_core_runtime.signature_loaded = 0;
	g_core_runtime.signature_failed = 0;
	g_core_runtime.signature_unavailable = 0;
	g_core_runtime.signature_started_at = time(NULL);
	g_core_runtime.updated_at = g_core_runtime.signature_started_at;
	if (path)
		snprintf(g_core_runtime.signature_path, sizeof(g_core_runtime.signature_path), "%s", path);
	pthread_mutex_unlock(&g_core_runtime_lock);
}

#define JMX_SIGNATURE_UNAVAILABLE 1

static void jmx_core_note_signature_unavailable(void)
{
	pthread_mutex_lock(&g_core_runtime_lock);
	g_core_runtime.stage = JMX_CORE_STAGE_READY;
	g_core_runtime.ready = 1;
	g_core_runtime.degraded = 1;
	g_core_runtime.signature_loading = 0;
	g_core_runtime.signature_loaded = 0;
	g_core_runtime.signature_failed = 0;
	g_core_runtime.signature_unavailable = 1;
	g_core_runtime.signature_finished_at = time(NULL);
	g_core_runtime.updated_at = g_core_runtime.signature_finished_at;
	g_core_runtime.last_error_code = -ENOENT;
	snprintf(g_core_runtime.last_error, sizeof(g_core_runtime.last_error), "%s",
		 "signature_database_unavailable");
	if (!g_core_runtime.ready_mono_ms)
		g_core_runtime.ready_mono_ms = jmx_core_monotonic_ms();
	if (!g_core_runtime.ready_at)
		g_core_runtime.ready_at = g_core_runtime.signature_finished_at;
	pthread_mutex_unlock(&g_core_runtime_lock);
}

static void jmx_core_note_signature_done(const char *path, int rc)
{
	pthread_mutex_lock(&g_core_runtime_lock);
	g_core_runtime.signature_loading = 0;
	g_core_runtime.signature_loaded = rc == 0 ? 1 : 0;
	g_core_runtime.signature_failed = rc == 0 ? 0 : 1;
	g_core_runtime.signature_finished_at = time(NULL);
	g_core_runtime.signature_rules = g_v2_rules.total_rules;
	g_core_runtime.signature_regex_rules = jmx_regex_count();
	if (path && path[0])
		snprintf(g_core_runtime.signature_path, sizeof(g_core_runtime.signature_path), "%s", path);
	if (rc != 0) {
		g_core_runtime.degraded = 1;
		g_core_runtime.last_error_code = rc;
		snprintf(g_core_runtime.last_error, sizeof(g_core_runtime.last_error), "%s", "signature_runtime_load_failed");
		g_core_runtime.stage = JMX_CORE_STAGE_FAILED;
		g_core_runtime.ready = 0;
	} else {
		g_core_runtime.stage = JMX_CORE_STAGE_READY;
		g_core_runtime.ready = 1;
		if (!g_core_runtime.ready_mono_ms)
			g_core_runtime.ready_mono_ms = jmx_core_monotonic_ms();
		if (!g_core_runtime.ready_at)
			g_core_runtime.ready_at = g_core_runtime.signature_finished_at;
	}
	g_core_runtime.updated_at = g_core_runtime.signature_finished_at;
	pthread_mutex_unlock(&g_core_runtime_lock);
}

static int jmx_v2_push_snapshot(const jmx_rule_set_t *rules,
				const char *phase)
{
	uint32_t version;

	if (g_v2_nl_fd < 0) {
		g_v2_nl_fd = jmx_v2_netlink_init();
		LOG_WARN("v2: %s netlink init fd=%d\n", phase, g_v2_nl_fd);
	}
	if (g_v2_nl_fd < 0) {
		LOG_WARN("v2: %s cannot commit without netlink\n", phase);
		return -1;
	}

	version = g_v2_version ? g_v2_version : 1;
	if (jmx_nl_push_rules(g_v2_nl_fd, rules, version) != 0) {
		LOG_WARN("v2: %s kernel commit failed version=%u rules=%u\n",
			 phase, version, rules->total_rules);
		return -1;
	}
	g_v2_version = version == UINT32_MAX ? 1 : version + 1;
	LOG_WARN("v2: %s kernel commit succeeded version=%u rules=%u\n",
		 phase, version, rules->total_rules);
	return 0;
}

static int jmx_regex_start_snapshot(const jmx_rule_set_t *rules)
{
	if (jmx_regex_init(rules) != 0) {
		LOG_WARN("v2: regex compile allocation failed\n");
		return -1;
	}
	jmx_regex_set_netlink_fd(g_v2_nl_fd);
	jmx_regex_set_rule_set(rules);
	if (jmx_regex_count() > 0) {
		if (jmx_regex_start() != 0) {
			jmx_regex_exit();
			LOG_WARN("v2: regex runtime start failed\n");
			return -1;
		}
	}
	return 0;
}

static void jmx_regex_stop_snapshot(void)
{
	jmx_regex_stop();
	jmx_regex_exit();
}

static int jmx_restore_legacy_snapshot(jmx_rule_set_t *old_rules,
				       int old_rules_loaded)
{
	jmx_rule_set_t failed_rules = g_v2_rules;
	int kernel_rc;
	int regex_rc;

	jmx_regex_stop_snapshot();
	g_v2_rules = *old_rules;
	memset(old_rules, 0, sizeof(*old_rules));
	g_v2_rules_loaded = old_rules_loaded;
	kernel_rc = jmx_v2_push_snapshot(&g_v2_rules, "rollback");
	regex_rc = jmx_regex_start_snapshot(&g_v2_rules);
	jmx_rule_set_free(&failed_rules);
	if (kernel_rc != 0 || regex_rc != 0) {
		LOG_ERROR("v2: rollback incomplete kernel_rc=%d regex_rc=%d\n",
			  kernel_rc, regex_rc);
		return -1;
	}
	LOG_WARN("v2: rollback restored previous legacy snapshot\n");
	return 0;
}

int jmx_runtime_reload_signature_db(const char *path)
{
	char resolved_path[512];
	char resolve_error[64] = {0};
	enum jmx_system_db_source source;
	jmx_rule_set_t new_rules;
	jmx_rule_set_t old_rules;
	jmx_chain_rule_set_t new_chain;
	jmx_chain_rule_set_t old_chain;
	jmx_v3_kernel_status_t chain_status_ack;
	const char *loaded_path = NULL;
	uint32_t engine_caps = 0;
	uint32_t generation = 0;
	uint8_t configured_mode;
	int chain_schema_status = 0;
	int chain_committed = 0;
	int old_rules_loaded;
	int explicit_path = path && path[0];
	int candidate_exists = explicit_path && access(path, F_OK) == 0;
	int ret = -1;

	pthread_mutex_lock(&g_signature_runtime_lock);
	configured_mode = jmx_v3_configured_mode();
	jmx_v3_probe_if_needed();
	if (g_v3_probe_state > 0)
		engine_caps = g_v3_kernel_status.engine_capabilities;
	memset(&new_rules, 0, sizeof(new_rules));
	memset(&new_chain, 0, sizeof(new_chain));
	memset(&old_chain, 0, sizeof(old_chain));
	memset(&chain_status_ack, 0, sizeof(chain_status_ack));
	if (explicit_path && candidate_exists && access(path, R_OK) == 0 &&
	    jmx_load_signature_db_with_chain(path, &new_rules, &new_chain,
					     engine_caps,
					     &chain_schema_status) == 0) {
		loaded_path = path;
		ret = 0;
	}
	if (ret < 0 && !explicit_path &&
	    jmx_system_db_resolve(JMX_SYSTEM_DB_SIGNATURE, resolved_path,
				       sizeof(resolved_path), &source,
				       resolve_error, sizeof(resolve_error)) == 0) {
		jmx_rule_set_free(&new_rules);
		jmx_chain_rule_set_free(&new_chain);
		if (jmx_load_signature_db_with_chain(resolved_path, &new_rules,
						     &new_chain, engine_caps,
						     &chain_schema_status) == 0) {
			loaded_path = resolved_path;
			ret = 0;
		}
	}
	if (ret < 0) {
		jmx_rule_set_free(&new_rules);
		jmx_chain_rule_set_free(&new_chain);
		if (!candidate_exists && !explicit_path &&
		    !strcmp(resolve_error, "path_not_found")) {
			LOG_WARN("signature: no bundled or runtime database; continuing in degraded mode\n");
			jmx_core_note_signature_unavailable();
			pthread_mutex_unlock(&g_signature_runtime_lock);
			return JMX_SIGNATURE_UNAVAILABLE;
		}
		if (explicit_path && !candidate_exists)
			LOG_WARN("signature: requested database does not exist: %s\n", path);
		LOG_WARN("signature: runtime reload failed, no valid dreamingwrt_signatures.db (%s)\n",
			 resolve_error[0] ? resolve_error : "load_failed");
		jmx_core_note_signature_done(path,
			explicit_path && !candidate_exists ? -ENOENT : -1);
		pthread_mutex_unlock(&g_signature_runtime_lock);
		return explicit_path && !candidate_exists ? -ENOENT : -1;
	}
	jmx_core_note_signature_start(loaded_path);
	if (g_v3_probe_state > 0 && configured_mode != JMX_V3_MODE_OFF &&
	    chain_schema_status != 0) {
		LOG_WARN("v3: schema rejected for %s in requested mode=%s; preserving the complete old v2/regex/v3 snapshot\n",
			 loaded_path, jmx_v3_mode_name(configured_mode));
		jmx_rule_set_free(&new_rules);
		jmx_chain_rule_set_free(&new_chain);
		jmx_core_note_signature_done(loaded_path, -1);
		pthread_mutex_unlock(&g_signature_runtime_lock);
		return -1;
	}

	/* Keep the old userspace and regex snapshot live until the candidate has
	 * committed to the v2 kernel generation. */
	if (jmx_v2_push_snapshot(&new_rules, "reload") != 0) {
		jmx_rule_set_free(&new_rules);
		jmx_chain_rule_set_free(&new_chain);
		jmx_core_note_signature_done(loaded_path, -1);
		pthread_mutex_unlock(&g_signature_runtime_lock);
		return -1;
	}

	old_rules = g_v2_rules;
	old_rules_loaded = g_v2_rules_loaded;
	jmx_regex_stop_snapshot();
	g_v2_rules = new_rules;
	memset(&new_rules, 0, sizeof(new_rules));
	g_v2_rules_loaded = 1;
	if (jmx_regex_start_snapshot(&g_v2_rules) != 0) {
		(void)jmx_restore_legacy_snapshot(&old_rules, old_rules_loaded);
		jmx_chain_rule_set_free(&new_chain);
		jmx_core_note_signature_done(loaded_path, -1);
		pthread_mutex_unlock(&g_signature_runtime_lock);
		return -1;
	}
	LOG_WARN("v2: runtime reloaded signatures from %s, rules=%u regex=%d\n", loaded_path, g_v2_rules.total_rules, jmx_regex_count());

	if (g_v3_probe_state <= 0) {
		LOG_WARN("v3: pure v2 fallback for this load; chain generation unchanged\n");
	} else {
		if (configured_mode == JMX_V3_MODE_OFF && chain_schema_status != 0)
			LOG_WARN("v3: schema rejected but mode=off; submitting explicit empty OFF generation\n");
		if (configured_mode == JMX_V3_MODE_ACTIVE &&
		    new_chain.stats.chain_ready_rules == 0)
			LOG_WARN("v3: requested mode=active but ready_rules=0; safely downgrading this generation to OFF without enabling unresolved rules\n");
		generation = jmx_v3_reserve_generation();
		if (jmx_nl_push_chain_rules(g_v2_nl_fd, &new_chain, generation,
					    configured_mode,
					    &chain_status_ack) == 0) {
			old_chain = g_v3_chain_rules;
			g_v3_chain_rules = new_chain;
			memset(&new_chain, 0, sizeof(new_chain));
			g_v3_chain_rules_loaded = 1;
			g_v3_kernel_status = chain_status_ack;
			chain_committed = 1;
			LOG_WARN("v3: committed generation=%u requested_mode=%s active_mode=%s rules=%u steps=%u ports=%u\n",
				 chain_status_ack.active_generation,
				 jmx_v3_mode_name(configured_mode),
				 jmx_v3_mode_name((uint8_t)chain_status_ack.active_mode),
				 chain_status_ack.active_rules,
				 chain_status_ack.active_steps,
				 chain_status_ack.active_ports);
		} else {
			LOG_WARN("v3: generation=%u commit failed reason=%u detail=%u; preserving active generation=%u\n",
				 generation, chain_status_ack.reason,
				 chain_status_ack.detail,
				 g_v3_kernel_status.active_generation);
			(void)jmx_restore_legacy_snapshot(&old_rules,
						 old_rules_loaded);
			jmx_chain_rule_set_free(&new_chain);
			jmx_core_note_signature_done(loaded_path, -1);
			pthread_mutex_unlock(&g_signature_runtime_lock);
			return -1;
		}
	}

	if (chain_committed && g_v3_chain_rules_loaded)
		jmx_chain_rule_set_free(&old_chain);
	jmx_rule_set_free(&old_rules);
	jmx_chain_rule_set_free(&new_chain);
	jmx_core_note_signature_done(loaded_path, 0);
	pthread_mutex_unlock(&g_signature_runtime_lock);
	return 0;
}

static int try_load_signature_db(void)
{
	int rc = jmx_runtime_reload_signature_db(NULL);
	if (rc == JMX_SIGNATURE_UNAVAILABLE)
		return 0;
	if (rc != 0)
		LOG_WARN("v2: no dreamingwrt_signatures.db found, signature rules not loaded\n");
	return rc;
}

static void jmx_deferred_startup_cb(struct uloop_timeout *t)
{
	static int step = 0;

	switch (step) {
	case 0: {
		int fingerprint_rc;

		jmx_core_set_stage(JMX_CORE_STAGE_FINGERPRINT_CATALOG);
		fingerprint_rc = db_try_import_fingerprint_catalog();
		pthread_mutex_lock(&g_core_runtime_lock);
		g_core_runtime.fingerprint_catalog_done = 1;
		g_core_runtime.fingerprint_catalog_available = fingerprint_rc >= 0;
		g_core_runtime.updated_at = time(NULL);
		pthread_mutex_unlock(&g_core_runtime_lock);
		step++;
		uloop_timeout_set(t, 100);
		return;
	}
	case 1:
		jmx_core_set_stage(JMX_CORE_STAGE_STARTUP_SIGNATURE_MATCH);
		db_startup_sig_match();
		pthread_mutex_lock(&g_core_runtime_lock);
		g_core_runtime.startup_sig_match_done = 1;
		g_core_runtime.updated_at = time(NULL);
		pthread_mutex_unlock(&g_core_runtime_lock);
		step++;
		uloop_timeout_set(t, 100);
		return;
	case 2:
		jmx_core_set_stage(JMX_CORE_STAGE_AUXILIARY_PROBES);
		huginn_init();
		dhcp_sniff_init();
		step++;
		uloop_timeout_set(t, 100);
		return;
	case 3: {
		int nrc;

		jmx_core_set_stage(JMX_CORE_STAGE_HOSTTYPE_OUI);
		jmx_hosttype_init();
		nrc = jmx_hosttype_load_nmap("/usr/share/nmap/nmap-mac-prefixes");
		pthread_mutex_lock(&g_core_runtime_lock);
		g_core_runtime.hosttype_oui_loaded = (nrc == 0);
		g_core_runtime.hosttype_oui_count = (int)jmx_ht_oui_count();
		g_core_runtime.updated_at = time(NULL);
		pthread_mutex_unlock(&g_core_runtime_lock);
		if (nrc == 0)
			fprintf(stderr, "hosttype: OUI table loaded (%u entries)\n", jmx_ht_oui_count());
		else {
			fprintf(stderr, "hosttype: failed to load nmap-mac-prefixes\n");
			jmx_core_set_error("hosttype_oui_load_failed", nrc);
		}
		step++;
		uloop_timeout_set(t, 100);
		return;
	}
	case 4:
		jmx_core_set_stage(JMX_CORE_STAGE_SIGNATURE_LOADING);
		if (try_load_signature_db() == 0)
			jmx_core_set_stage(JMX_CORE_STAGE_READY);
		else
			jmx_core_set_stage(JMX_CORE_STAGE_FAILED);
		return;
	default:
		return;
	}
}

void update_lan_ip(void){
    char ip_str[32] = {0};
	char mask_str[32] = {0};
    struct in_addr addr;
	struct in_addr mask_addr;
    char cmd_buf[128] = {0};
    u_int32_t lan_ip = 0;
	u_int32_t lan_mask = 0;
    char lan_ifname[32] = {0};
    char ip_cmd_buf[128] = {0};
    char mask_cmd_buf[128] = {0};
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx)
        return;
	
    int ret = jmx_uci_get_value(ctx, "appfilter.global.lan_ifname", lan_ifname, sizeof(lan_ifname) - 1);
    if (ret != 0){
        strcpy(lan_ifname, "br-lan");
    }
    sprintf(ip_cmd_buf, CMD_GET_LAN_IP_FMT, lan_ifname);
    sprintf(mask_cmd_buf, CMD_GET_LAN_MASK_FMT , lan_ifname);

    exec_with_result_line(ip_cmd_buf, ip_str, sizeof(ip_str));
    if (strlen(ip_str) < MIN_INET_ADDR_LEN){
        update_jmx_proc_u32_value("lan_ip", 0);
    }
    else{
        inet_aton(ip_str, &addr);
        lan_ip = addr.s_addr;
        update_jmx_proc_u32_value("lan_ip", lan_ip);
    }

    exec_with_result_line(mask_cmd_buf, mask_str, sizeof(mask_str));

    if (strlen(mask_str) < MIN_INET_ADDR_LEN){
        update_jmx_proc_u32_value("lan_mask", 0);
    }
    else{
        inet_aton(mask_str, &mask_addr);
        lan_mask = mask_addr.s_addr;
        update_jmx_proc_u32_value("lan_mask", lan_mask);
    }
	uci_free_context(ctx);
}


void daily_archive_handle(void){
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    if (tm_info) {
        static int last_mday = -1;
        int current_mday = tm_info->tm_mday;
        LOG_INFO("current_mday: %d, last_mday: %d\n", current_mday, last_mday);
        
        if (last_mday != -1 && last_mday != current_mday) {
            LOG_INFO("date changed, need to archive\n");
            if (!jmx_storage_guard_allow(get_client_data_base_dir(),
                                         JMX_STORAGE_WRITE_BULK, NULL)) {
                LOG_WARN("daily archive deferred by storage pressure: %s\n",
                         get_client_data_base_dir());
                return;
            }
            check_and_archive_all_clients();
        }
        else{
            LOG_INFO("date not changed, no need to archive\n");
        }
        
        last_mday = current_mday;
    }
}



void jmx_timeout_handler(struct uloop_timeout *t)
{
    static int count = 0;
    int legacy_scheduler = jmx_core_legacy_scheduler_enabled();
    int legacy_netlink = jmx_core_legacy_netlink_enabled();
    jmx_docker_jobs_reap_workers();
    count++;
    if (legacy_scheduler && count % 10 == 0){
        update_client_list();
        jmx_db_sync_clients_from_memory();
        move_expired_online_visit_to_offline();
    }
    if (legacy_scheduler && count % 20 == 0){
        daily_archive_handle();
        update_lan_ip();
        if (check_client_expire()){
            flush_expire_client_node();
        }
        dump_client_list();
        cleanup_expired_hourly_stats();
        check_and_cleanup_history_data_by_size();
    }
    
    if (legacy_scheduler && count % 2 == 0) {
        collect_interface_traffic_rate();
    }

    if (legacy_scheduler && count % 30 == 0) {
        jmx_route_health_tick();
    }

    /* line_health: refresh WAN session + health bucket every 2s */
    if (legacy_scheduler && count % 2 == 0) {
        dw_update_wan_health();
    }
    /* ipv6_load: sample nft counters every 2s (rate needs two samples) */
    if (legacy_scheduler && count % 2 == 0) {
        dw_collect_ipv6_load();
    }
    /* flush health buckets to DB every 5 min */
    if (legacy_scheduler && count % 300 == 0) {
        jmx_db_flush_health_buckets();
    }
    /* System status event for SSE (every 30s) */
    if (legacy_scheduler && count % 30 == 0) {
        struct json_object *sys = get_system_status();
        struct json_object *sys_data = NULL;
        if (sys && json_object_object_get_ex(sys, "data", &sys_data)) {
            struct json_object *sys_obj = NULL;
            if (json_object_object_get_ex(sys_data, "system", &sys_obj))
                jmx_events_emit("system.status", "updated", sys_obj);
        }
        if (sys) json_object_put(sys);
    }
    /* prune old rows + WAL checkpoint every hour, VACUUM daily at 3am */
    if (legacy_scheduler && count % 3600 == 0) {
        jmx_db_prune_and_vacuum();
    }
    /* refresh WAN profile config from UCI every 10 min */
    if (legacy_scheduler && count % 600 == 0) {
        dw_update_wan_profiles();
    }

    /*
     * Legacy kernel netlink telemetry belongs to the old monolithic jmxd data
     * path. On busy routers it can keep the main uloop runnable and starve ubus
     * control-plane requests. Split workers now own runtime sampling, so keep
     * this receive path opt-in only.
     */
    if (legacy_netlink && jmx_nl_fd.fd < 0){
        jmx_nl_fd.fd = jmx_netlink_init();
        if (jmx_nl_fd.fd > 0){
            uloop_fd_add(&jmx_nl_fd, ULOOP_READ);

            system("killall -9 rule_manager");
            LOG_INFO("netlink connect success\n");
        }
    }

    if (g_feature_update == 1){
        g_feature_update = 0;
        /* Load DreamingWrt SQLite signature rules through the v2 netlink path. */
        if (try_load_signature_db() == 0)
            jmx_core_set_stage(JMX_CORE_STAGE_READY);
        else
            jmx_core_set_stage(JMX_CORE_STAGE_FAILED);
    }

    uloop_timeout_set(t, 1000);
}

void init_system_config_to_proc(void) {
    jmx_legacy_settings_t settings;
    int work_mode = 0;
    int traffic_record_enabled = 1;
    char identification_mode[32] = "device_and_traffic";

    memset(&settings, 0, sizeof(settings));
    if (jmx_legacy_settings_get(&settings) != 0)
        snprintf(settings.lan_ifname, sizeof(settings.lan_ifname), "%s", "br-lan");
    update_jmx_proc_value("lan_ifname", settings.lan_ifname);
    if (jmx_work_mode_config_get(&work_mode, NULL, 0, NULL, 0) != 0)
        work_mode = 0;
    update_jmx_proc_u32_value("work_mode", work_mode);
    if (jmx_identification_mode_get(identification_mode,
                                    sizeof(identification_mode),
                                    &traffic_record_enabled) != 0)
        traffic_record_enabled = settings.record_enabled ? 1 : 0;
    update_jmx_proc_u32_value("record_enable", traffic_record_enabled);
}

void jmx_handle_sigusr1(int sig) {
    LOG_INFO("Received SIGUSR1 signal\n");
    g_feature_update = 1;
}

void jmx_handle_sigusr2(int sig) {
    LOG_INFO("Received SIGUSR2 signal\n");
	if (current_log_level < LOG_LEVEL_DEBUG)
   		current_log_level++;
	else
		current_log_level = LOG_LEVEL_WARN;

	LOG_WARN("change log level to %d\n", current_log_level);
}

static void jmx_handle_stop(int sig)
{
	(void)sig;
	uloop_end();
}

static void jmx_signature_runtime_close(void)
{
	pthread_mutex_lock(&g_signature_runtime_lock);
	jmx_regex_stop();
	jmx_regex_exit();
	jmx_regex_set_rule_set(NULL);
	jmx_regex_set_netlink_fd(-1);
	jmx_rule_set_free(&g_v2_rules);
	jmx_chain_rule_set_free(&g_v3_chain_rules);
	g_v2_rules_loaded = 0;
	g_v3_chain_rules_loaded = 0;
	if (g_v2_nl_fd >= 0) {
		close(g_v2_nl_fd);
		g_v2_nl_fd = -1;
	}
	pthread_mutex_unlock(&g_signature_runtime_lock);
}


void jmx_handle_sigsegv(int sig) {
    const char msg[] = "\n!!! JMXD SIGSEGV received - check dmesg for details !!!\n";
    (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
    signal(sig, SIG_DFL);
    raise(sig);
}

int main(int argc, char **argv)
{
    int ret = 0;
if (argc == 3 && !strcmp(argv[1], "--container-job-worker"))
    return jmx_docker_job_worker(argv[2]);
LOG_INFO("jmx start");
g_feature_update = 0;
pthread_mutex_lock(&g_core_runtime_lock);
g_core_runtime.started_at = time(NULL);
g_core_runtime.started_mono_ms = jmx_core_monotonic_ms();
g_core_runtime.updated_at = g_core_runtime.started_at;
pthread_mutex_unlock(&g_core_runtime_lock);
jmx_core_set_stage(JMX_CORE_STAGE_BASE_TABLES);

/* 先初始化用户态 app/class 名称表，避免 UBUS 提前访问时 get_app_name_by_id() 返回 NULL */
init_app_name_table();
init_app_class_name_table();

uloop_init();
signal(SIGINT, jmx_handle_stop);
signal(SIGTERM, jmx_handle_stop);
signal(SIGUSR1, jmx_handle_sigusr1);
signal(SIGUSR2, jmx_handle_sigusr2);
signal(SIGSEGV, jmx_handle_sigsegv);
init_client_list();
load_app_valid_time_config();
init_system_config_to_proc();
jmx_route_sync_config();
jmx_core_set_stage(JMX_CORE_STAGE_DB_INIT);
jmx_db_init();
jmx_netconfig_physical_port_apply_saved_all();
/* Probe ctnetlink conntrack events for future exact flow lifecycle accounting. */
jmx_flow_event_collector_start();

    if (jmx_ubus_init() < 0)
    {
        jmx_core_set_error("ubus_init_failed", -1);
        LOG_ERROR("Failed to connect to ubus\n");
        return 1;
    }
    pthread_mutex_lock(&g_core_runtime_lock);
    g_core_runtime.ubus_ready = 1;
    g_core_runtime.updated_at = time(NULL);
    pthread_mutex_unlock(&g_core_runtime_lock);
    jmx_core_set_stage(JMX_CORE_STAGE_UBUS_READY);

    jmx_nl_fd.fd = -1;
    jmx_core_watchdog_start();
    jmx_startup_tm.cb = jmx_deferred_startup_cb;
    uloop_timeout_set(&jmx_startup_tm, 100);
    uloop_timeout_set(&jmx_tm, 5000);
    uloop_run();
    uloop_timeout_cancel(&jmx_startup_tm);
    uloop_timeout_cancel(&jmx_tm);
    jmx_core_watchdog_stop();
    jmx_flow_event_collector_stop();
    jmx_signature_runtime_close();
    jmx_topology_history_close();
    jmx_db_close();
    uloop_done();
    return 0;
}
