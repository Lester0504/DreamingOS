// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_NETBOOT_INTERNAL_H
#define DREAMINGWRT_NETBOOT_INTERNAL_H
#define _GNU_SOURCE
#include "netboot.h"
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#ifndef NB_DB_PATH
#define NB_DB_PATH "/etc/dreamingwrt/config.db"
#endif
#ifndef NB_RUN_DIR
#define NB_RUN_DIR "/run/dreamingwrt/netboot"
#endif
#ifndef NB_BOOT_DIR
#define NB_BOOT_DIR "/usr/share/dreamingwrt/netboot"
#endif

#define NB_MAX_IMAGES 128
#define NB_MAX_CLIENTS 1024
#define NB_MAX_EVENTS 256

struct json_object *nb_value(struct json_object *o, const char *key);
const char *nb_string(struct json_object *o, const char *key);
int64_t nb_number(struct json_object *o, const char *key);
int nb_bool(struct json_object *o, const char *key);
struct json_object *nb_clone(struct json_object *o);
void nb_text(struct json_object *o, const char *key, const char *value);
void nb_int(struct json_object *o, const char *key, int64_t value);
void nb_flag(struct json_object *o, const char *key, int value);
struct json_object *nb_error(int http, const char *code, const char *field);
struct json_object *nb_reply(struct json_object *data);
struct json_object *nb_load(sqlite3 *db);
/* writing borrows the main-loop authority handle; only close readonly handles. */
sqlite3 *nb_open(int writing);
int nb_store(sqlite3 *db, struct json_object *config);
struct json_object *nb_find(struct json_object *array, const char *id);
int nb_mac(const char *input, char output[18]);
int nb_safe_text(const char *s, size_t maximum);
int nb_password_set(struct json_object *settings, const char *password);
int nb_password_check(struct json_object *settings, const char *password);
struct json_object *nb_interfaces(sqlite3 *db);
struct json_object *nb_resources(void);
struct json_object *nb_preflight(sqlite3 *db, struct json_object *config);
int nb_image_probe(struct json_object *image, int remount, int overwrite);
void nb_image_observe(struct json_object *image);
int nb_image_unmount(const char *id);
int nb_image_unmount_known(struct json_object *image);
int nb_image_open(struct json_object *image, const char *relative);
struct json_object *nb_runtime_status(struct json_object *config);
int nb_runtime_apply(struct json_object *config, struct json_object *previous,
                     struct json_object *result);
void nb_runtime_boot(void);
void nb_event(const char *type, const char *mac, const char *image, const char *reason);
struct json_object *nb_events(int offset, int limit);
void nb_events_clear(void);
struct json_object *nb_observed_clients(void);
void nb_observe_client(const char *mac, const char *ip, const char *arch, const char *platform);
int nb_http_start(struct json_object *config, struct json_object *interface);
void nb_http_stop(void);
int nb_http_ready(const char *address, int port);
int nb_http_busy(const char *image_id);
char *nb_dhcp_block(struct json_object *config, struct json_object *interface);
struct json_object *nb_config_snapshot(void);
void nb_config_publish(struct json_object *config);
int nb_image_register(struct json_object *image);
int nb_image_detect_at(struct json_object *image, int rootfd);
int nb_exec(char *const argv[], int timeout_ms);
int nb_id_valid(const char *id);
int nb_dhcp_loaded(struct json_object *config, struct json_object *interface);
extern struct json_object *nb_apply_candidate; /* uloop thread only */

#endif
