// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_TOOLKIT_INTERNAL_H
#define DREAMINGWRT_TOOLKIT_INTERNAL_H

#include <json-c/json.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>

#define TOOLKIT_CONFIG_DB "/etc/dreamingwrt/config.db"
#define TOOLKIT_RUNTIME_DIR "/tmp/dreamingwrt/toolkit"
#define TOOLKIT_TC_PREF 49152

extern sqlite3 *g_toolkit_db;

int64_t toolkit_now_s(void);
const char *toolkit_json_str(struct json_object *o, const char *key, const char *def);
int toolkit_json_int(struct json_object *o, const char *key, int def);
int toolkit_json_bool(struct json_object *o, const char *key, int def);
struct json_object *toolkit_error(const char *code, const char *message);
struct json_object *toolkit_success(struct json_object *data, const char *source);
int toolkit_token_ok(const char *s, size_t max_len);
int toolkit_ifname_ok(const char *ifname);
int toolkit_mac_parse(const char *text, unsigned char mac[6]);
int toolkit_exec_wait(char *const argv[], int timeout_ms, char *output,
                      size_t output_len, int *exit_code);
int toolkit_runtime_dir_ready(void);

int toolkit_db_init(void);
void toolkit_db_close(void);
struct json_object *toolkit_port_mirror_list(void);
struct json_object *toolkit_port_mirror_set(struct json_object *payload);
struct json_object *toolkit_port_mirror_delete(struct json_object *payload);
void toolkit_port_mirror_restore(void);
struct json_object *toolkit_ddns_list(void);
struct json_object *toolkit_ddns_set(struct json_object *payload);
struct json_object *toolkit_ddns_delete(struct json_object *payload);
struct json_object *toolkit_ddns_update(struct json_object *payload);
char *toolkit_ddns_secret_for_id(const char *id, char **provider, char **hostname,
                                 char **ifname, char **config_json);
void toolkit_ddns_record_result(const char *id, int ok, const char *address,
                                const char *error);

struct json_object *toolkit_status(void);
struct json_object *toolkit_router_check(void);
struct json_object *toolkit_wake_on_lan(struct json_object *payload);
struct json_object *toolkit_throughput_start(struct json_object *payload);
struct json_object *toolkit_throughput_status(struct json_object *payload);
struct json_object *toolkit_throughput_stop(struct json_object *payload);

#endif
