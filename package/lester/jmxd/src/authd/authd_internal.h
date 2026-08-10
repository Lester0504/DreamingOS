// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AUTHD_INTERNAL_H
#define DREAMINGWRT_AUTHD_INTERNAL_H

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubus.h>

#define AUTHD_CONFIG_DB_PATH "/etc/dreamingwrt/config.db"
#define AUTHD_SECRET_KEY_PATH "/etc/dreamingwrt/authd.key"
#define AUTHD_SCHEMA_VERSION 4
#define AUTHD_DEFAULT_LIMIT 100
#define AUTHD_MAX_LIMIT 500

extern sqlite3 *g_authd_db;
extern struct ubus_context *g_authd_ubus;
extern struct blob_buf g_authd_blob;
extern int64_t g_authd_started_at;

int64_t authd_now_s(void);
const char *authd_sqlite_text(sqlite3_stmt *st, int col, const char *def);
struct json_object *authd_json_from_blob(struct blob_attr *msg);
struct json_object *authd_capabilities_json(void);
struct json_object *authd_envelope(struct json_object *data);
struct json_object *authd_error(const char *error, const char *message);

int authd_db_init(void);
void authd_db_close(void);
struct json_object *authd_status_json(void);
struct json_object *authd_aggregate_json(void);
struct json_object *authd_web_json(void);
struct json_object *authd_portal_json(void);
struct json_object *authd_online_users_json(struct json_object *query);
struct json_object *authd_packages_json(struct json_object *query);
struct json_object *authd_accounts_json(struct json_object *query);
struct json_object *authd_ledger_json(struct json_object *query);
struct json_object *authd_account_management_json(struct json_object *query);
struct json_object *authd_vouchers_json(struct json_object *query);
struct json_object *authd_delegated_json(struct json_object *query);
/*
 * Delegated dialing has to name a real WAN. Both helpers read the shared
 * config.db `wan` table so the picker the UI offers and the value the write
 * path accepts can never drift apart.
 */
struct json_object *authd_delegated_interface_options(void);
int authd_delegated_interface_default(char *out, size_t out_len);
struct json_object *authd_notifications_json(void);
struct json_object *authd_package_upsert(struct json_object *request);
struct json_object *authd_package_delete(struct json_object *request);
struct json_object *authd_account_upsert(struct json_object *request);
struct json_object *authd_account_delete(struct json_object *request);
struct json_object *authd_accounts_bulk(struct json_object *request);
struct json_object *authd_accounts_import(struct json_object *request);
struct json_object *authd_password_policy_set(struct json_object *request);
struct json_object *authd_web_set(struct json_object *request);
struct json_object *authd_portal_set(struct json_object *request);
struct json_object *authd_access_rule_upsert(struct json_object *request);
struct json_object *authd_access_rule_delete(struct json_object *request);
struct json_object *authd_delegated_upsert(struct json_object *request);
struct json_object *authd_delegated_delete(struct json_object *request);
struct json_object *authd_delegated_import(struct json_object *request);
struct json_object *authd_notification_set(struct json_object *request);
struct json_object *authd_notification_preview(struct json_object *request);
struct json_object *authd_notification_schedule_upsert(struct json_object *request);
struct json_object *authd_notification_schedule_delete(struct json_object *request);
struct json_object *authd_ledger_upsert(struct json_object *request);
struct json_object *authd_ledger_delete(struct json_object *request);
struct json_object *authd_voucher_create(struct json_object *request);
struct json_object *authd_voucher_update(struct json_object *request);
struct json_object *authd_voucher_delete(struct json_object *request);
struct json_object *authd_vouchers_expired_delete(struct json_object *request);

int authd_ubus_start(void);
void authd_ubus_stop(void);
char *authd_html_sanitize(const char *input, size_t max_output);

#endif
