// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __DREAMINGWRT_WEBD_SESSION_IDLE_H__
#define __DREAMINGWRT_WEBD_SESSION_IDLE_H__

#include <stddef.h>
#include <stdint.h>

#include <sqlite3.h>

#define WEBD_SESSION_IDLE_DEFAULT_MIN 60
#define WEBD_SESSION_IDLE_MIN_MIN 1
#define WEBD_SESSION_IDLE_MAX_MIN 1440
#define WEBD_SESSION_IDLE_TOUCH_INTERVAL_S 30
#define WEBD_SESSION_IDLE_ERROR "web_session_idle_timeout"

enum webd_session_idle_result {
    WEBD_SESSION_IDLE_OK = 0,
    WEBD_SESSION_IDLE_TOKEN_INVALID = 1,
    WEBD_SESSION_IDLE_TIMEOUT = 2,
    WEBD_SESSION_IDLE_USER_NOT_FOUND = 3,
    WEBD_SESSION_IDLE_INVALID_ARGUMENT = -1,
    WEBD_SESSION_IDLE_DB_ERROR = -2,
};

struct webd_session_idle_info {
    char username[65];
    char session_id[129];
    int timeout_min;
    int64_t last_activity_at;
    int64_t idle_deadline_at;
};

/* Idempotent migration for config.db:web_users and apid.db:web_sessions. */
int webd_session_idle_migrate(sqlite3 *config_db, sqlite3 *app_db);

int webd_session_idle_timeout_get(sqlite3 *config_db, const char *username,
                                  int *timeout_min);
int webd_session_idle_timeout_set(sqlite3 *config_db, const char *username,
                                  int timeout_min, int64_t now);

/* Inserts one access/refresh login family atomically. */
int webd_session_idle_login_insert(sqlite3 *app_db, const char *access_token,
                                   int64_t access_expires_at,
                                   const char *refresh_token,
                                   int64_t refresh_expires_at,
                                   const char *username,
                                   const char *session_id, int64_t now);

/*
 * Checks an access token against the user's current timeout. Normal HTTP
 * requests pass record_activity=1. Passive WebSocket/SSE rechecks pass 0 so
 * a connection does not keep itself alive merely by running its timer.
 */
int webd_session_idle_access_check(sqlite3 *config_db, sqlite3 *app_db,
                                   const char *access_token, int64_t now,
                                   int record_activity,
                                   struct webd_session_idle_info *info);

/* Checks refresh idleness and inserts the replacement access token atomically. */
int webd_session_idle_refresh_issue(sqlite3 *config_db, sqlite3 *app_db,
                                    const char *refresh_token,
                                    const char *new_access_token,
                                    int64_t access_expires_at, int64_t now,
                                    struct webd_session_idle_info *info);

const char *webd_session_idle_error(int result);

#endif
