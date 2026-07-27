// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt structured power schedules and guarded power actions. */
#define _GNU_SOURCE

#include "power.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef JMX_SYSTEM_POWER_DB_PATH
#define JMX_SYSTEM_POWER_DB_PATH "/etc/dreamingwrt/config.db"
#endif
#ifndef JMX_SYSTEM_POWER_REBOOT_PATH
#define JMX_SYSTEM_POWER_REBOOT_PATH "/sbin/reboot"
#endif
#ifndef JMX_SYSTEM_POWER_SHUTDOWN_PATH
#define JMX_SYSTEM_POWER_SHUTDOWN_PATH "/sbin/poweroff"
#endif

#define POWER_API_OK 2000
#define POWER_API_ERROR 4000
#define POWER_SCHEMA_VERSION 1
#define POWER_DB_BUSY_TIMEOUT_MS 5000
#define POWER_DISPATCH_DELAY_SECONDS 2
#define POWER_DISPATCH_HANDSHAKE_TIMEOUT_MS 2000
#define POWER_ACTION_LOCK_SECONDS 120
#define POWER_ACTION_RATE_LIMIT_SECONDS 30
#define POWER_CLAIM_SECONDS 120
#define POWER_MAX_NAME 80
#define POWER_MAX_NOTE 256
#define POWER_MAX_ID 80
#define POWER_MAX_OWNER 128
#define POWER_MAX_SOURCE_IP 64

struct power_schedule {
    char id[POWER_MAX_ID + 1];
    char name[POWER_MAX_NAME + 1];
    char event[16];
    char period[16];
    char run_date[11];
    char run_time[6];
    int weekdays[7];
    size_t weekday_count;
    int month_day;
    char note[POWER_MAX_NOTE + 1];
    int enabled;
    int revision;
    int64_t next_run_at;
    int64_t last_run_at;
    char last_result[32];
    char claim_token[POWER_MAX_ID + 1];
    int64_t claim_until;
    int64_t created_at;
    int64_t updated_at;
    int64_t archived_at;
};

struct power_exec_result {
    pid_t dispatcher_pid;
    int release_fd;
    int dry_run;
};

enum power_lock_result {
    POWER_LOCK_OK = 0,
    POWER_LOCK_PENDING = 1,
    POWER_LOCK_RATE_LIMITED = 2,
    POWER_LOCK_ERROR = -1
};

static int64_t power_now_s(void)
{
#ifdef JMX_SYSTEM_POWER_TESTING
    const char *override = getenv("JMX_SYSTEM_POWER_TEST_NOW");
    char *end = NULL;
    long long value;

    if (override && override[0]) {
        errno = 0;
        value = strtoll(override, &end, 10);
        if (!errno && end && !*end && value > 0)
            return (int64_t)value;
    }
#endif
    return (int64_t)time(NULL);
}

static struct json_object *power_envelope(int code, struct json_object *data)
{
    struct json_object *root = json_object_new_object();

    if (!root) {
        if (data)
            json_object_put(data);
        return NULL;
    }
    json_object_object_add(root, "code", json_object_new_int(code));
    json_object_object_add(root, "data", data ? data : json_object_new_object());
    return root;
}

static void power_add_contract(struct json_object *data)
{
    json_object_object_add(data, "contract_version",
                           json_object_new_string(JMX_SYSTEM_POWER_CONTRACT_VERSION));
}

static struct json_object *power_success(struct json_object *data)
{
    if (!data)
        data = json_object_new_object();
    power_add_contract(data);
    json_object_object_add(data, "ok", json_object_new_boolean(1));
    return power_envelope(POWER_API_OK, data);
}

static struct json_object *power_error_code(int code, const char *error,
                                             const char *reason)
{
    struct json_object *data = json_object_new_object();

    power_add_contract(data);
    json_object_object_add(data, "ok", json_object_new_boolean(0));
    json_object_object_add(data, "error",
                           json_object_new_string(error ? error : "internal_error"));
    json_object_object_add(data, "reason",
                           json_object_new_string(reason ? reason : "internal_error"));
    return power_envelope(code, data);
}

static struct json_object *power_error(const char *error, const char *reason)
{
    return power_error_code(POWER_API_ERROR, error, reason);
}

static int power_sql_exec(sqlite3 *db, const char *sql)
{
    char *message = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &message);

    sqlite3_free(message);
    return rc == SQLITE_OK ? 0 : -1;
}

static int power_prepare(sqlite3 *db, sqlite3_stmt **st, const char *sql)
{
    return sqlite3_prepare_v2(db, sql, -1, st, NULL) == SQLITE_OK ? 0 : -1;
}

static int power_step_done(sqlite3_stmt *st)
{
    return sqlite3_step(st) == SQLITE_DONE ? 0 : -1;
}

static const char *power_sql_text(sqlite3_stmt *st, int column)
{
    const unsigned char *value = sqlite3_column_text(st, column);

    return value ? (const char *)value : "";
}

static int power_schema_create(sqlite3 *db)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS power_schedule_meta("
        "id INTEGER PRIMARY KEY CHECK(id=1),"
        "schema_version INTEGER NOT NULL,"
        "contract_version TEXT NOT NULL,"
        "revision INTEGER NOT NULL DEFAULT 0,"
        "pending_action_id TEXT NOT NULL DEFAULT '',"
        "pending_action TEXT NOT NULL DEFAULT '',"
        "pending_owner TEXT NOT NULL DEFAULT '',"
        "pending_since INTEGER NOT NULL DEFAULT 0,"
        "pending_expires_at INTEGER NOT NULL DEFAULT 0,"
        "last_action_at INTEGER NOT NULL DEFAULT 0,"
        "last_action TEXT NOT NULL DEFAULT '',"
        "last_action_result TEXT NOT NULL DEFAULT '',"
        "last_tick_at INTEGER NOT NULL DEFAULT 0,"
        "updated_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS power_schedule("
        "id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL,"
        "event TEXT NOT NULL CHECK(event IN('reboot','shutdown')),"
        "period TEXT NOT NULL CHECK(period IN('once','daily','weekly','monthly')),"
        "run_date TEXT NOT NULL DEFAULT '',"
        "run_time TEXT NOT NULL,"
        "weekdays_json TEXT NOT NULL DEFAULT '[]',"
        "month_day INTEGER NOT NULL DEFAULT 0 CHECK(month_day BETWEEN 0 AND 31),"
        "note TEXT NOT NULL DEFAULT '',"
        "enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),"
        "revision INTEGER NOT NULL DEFAULT 1,"
        "next_run_at INTEGER NOT NULL DEFAULT 0,"
        "last_run_at INTEGER NOT NULL DEFAULT 0,"
        "last_result TEXT NOT NULL DEFAULT '',"
        "claim_token TEXT NOT NULL DEFAULT '',"
        "claim_until INTEGER NOT NULL DEFAULT 0,"
        "created_at INTEGER NOT NULL,"
        "updated_at INTEGER NOT NULL,"
        "archived_at INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS power_schedule_due_idx "
        "ON power_schedule(enabled,next_run_at,claim_until);"
        "CREATE TABLE IF NOT EXISTS power_schedule_history("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "action_id TEXT NOT NULL UNIQUE,"
        "schedule_id TEXT NOT NULL DEFAULT '',"
        "source TEXT NOT NULL CHECK(source IN('schedule','immediate')),"
        "event TEXT NOT NULL CHECK(event IN('reboot','shutdown')),"
        "planned_at INTEGER NOT NULL,"
        "claimed_at INTEGER NOT NULL,"
        "completed_at INTEGER NOT NULL DEFAULT 0,"
        "result TEXT NOT NULL DEFAULT 'pending',"
        "error TEXT NOT NULL DEFAULT '',"
        "actor TEXT NOT NULL DEFAULT '',"
        "source_ip TEXT NOT NULL DEFAULT '',"
        "executor_pid INTEGER NOT NULL DEFAULT 0);"
        "CREATE INDEX IF NOT EXISTS power_schedule_history_schedule_idx "
        "ON power_schedule_history(schedule_id,claimed_at DESC);";
    sqlite3_stmt *st = NULL;
    int64_t now = power_now_s();

    if (power_sql_exec(db, schema) != 0 ||
        power_prepare(db, &st,
            "INSERT OR IGNORE INTO power_schedule_meta"
            "(id,schema_version,contract_version,updated_at) VALUES(1,?1,?2,?3)") != 0)
        return -1;
    sqlite3_bind_int(st, 1, POWER_SCHEMA_VERSION);
    sqlite3_bind_text(st, 2, JMX_SYSTEM_POWER_CONTRACT_VERSION, -1, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, now);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (power_prepare(db, &st,
            "UPDATE power_schedule_meta SET schema_version=?1,contract_version=?2 "
            "WHERE id=1 AND (schema_version<>?1 OR contract_version<>?2)") != 0)
        return -1;
    sqlite3_bind_int(st, 1, POWER_SCHEMA_VERSION);
    sqlite3_bind_text(st, 2, JMX_SYSTEM_POWER_CONTRACT_VERSION, -1, SQLITE_STATIC);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

static int power_schema_is_current(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    int current = 0;

    if (power_prepare(db, &st,
            "SELECT schema_version,contract_version FROM power_schedule_meta WHERE id=1") != 0)
        return 0;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_int(st, 0) == POWER_SCHEMA_VERSION &&
        !strcmp(power_sql_text(st, 1), JMX_SYSTEM_POWER_CONTRACT_VERSION))
        current = 1;
    sqlite3_finalize(st);
    return current;
}

static int power_db_open(sqlite3 **db_out)
{
    sqlite3 *db = NULL;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;

    if (!db_out)
        return -1;
    *db_out = NULL;
    if (sqlite3_open_v2(JMX_SYSTEM_POWER_DB_PATH, &db, flags, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, POWER_DB_BUSY_TIMEOUT_MS);
    if (power_sql_exec(db, "PRAGMA foreign_keys=ON") != 0 ||
        (!power_schema_is_current(db) && power_schema_create(db) != 0)) {
        sqlite3_close(db);
        return -1;
    }
    *db_out = db;
    return 0;
}

static int power_random_id(const char *prefix, char *out, size_t out_size)
{
    unsigned char raw[16];
    size_t used = 0;
    int fd;

    if (!prefix || !out || out_size < strlen(prefix) + 34)
        return -1;
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    while (used < sizeof(raw)) {
        ssize_t got = read(fd, raw + used, sizeof(raw) - used);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0) {
            close(fd);
            return -1;
        }
        used += (size_t)got;
    }
    close(fd);
    if (snprintf(out, out_size,
            "%s-%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            prefix, raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]) >=
        (int)out_size)
        return -1;
    return 0;
}

static struct json_object *power_payload(struct json_object *request)
{
    struct json_object *data = NULL;

    if (request && json_object_is_type(request, json_type_object) &&
        json_object_object_get_ex(request, "data", &data) && data &&
        json_object_is_type(data, json_type_object))
        return data;
    return request;
}

static int power_json_bool(struct json_object *obj, const char *key,
                           int *value, int *present)
{
    struct json_object *item = NULL;

    *present = 0;
    if (!obj || !json_object_is_type(obj, json_type_object) ||
        !json_object_object_get_ex(obj, key, &item))
        return 0;
    *present = 1;
    if (!json_object_is_type(item, json_type_boolean))
        return -1;
    *value = json_object_get_boolean(item) ? 1 : 0;
    return 0;
}

static int power_json_int(struct json_object *obj, const char *key,
                          int64_t *value, int *present)
{
    struct json_object *item = NULL;

    *present = 0;
    if (!obj || !json_object_is_type(obj, json_type_object) ||
        !json_object_object_get_ex(obj, key, &item))
        return 0;
    *present = 1;
    if (!json_object_is_type(item, json_type_int))
        return -1;
    *value = json_object_get_int64(item);
    return 0;
}

static int power_json_string(struct json_object *obj, const char *key,
                             const char **value, int *present)
{
    struct json_object *item = NULL;

    *present = 0;
    if (!obj || !json_object_is_type(obj, json_type_object) ||
        !json_object_object_get_ex(obj, key, &item))
        return 0;
    *present = 1;
    if (!json_object_is_type(item, json_type_string))
        return -1;
    *value = json_object_get_string(item);
    return 0;
}

static int power_text_ok(const char *value, size_t maximum, int required)
{
    const unsigned char *p = (const unsigned char *)value;
    size_t length;

    if (!value)
        return !required;
    length = strlen(value);
    if ((required && length == 0) || length > maximum)
        return 0;
    while (*p) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
        p++;
    }
    return 1;
}

static int power_id_ok(const char *id)
{
    const unsigned char *p = (const unsigned char *)id;
    size_t length;

    if (!id)
        return 0;
    length = strlen(id);
    if (length < 4 || length > POWER_MAX_ID)
        return 0;
    for (; *p; p++)
        if (!isalnum(*p) && *p != '-' && *p != '_')
            return 0;
    return 1;
}

static int power_event_ok(const char *event)
{
    return event && (!strcmp(event, "reboot") || !strcmp(event, "shutdown"));
}

static int power_period_ok(const char *period)
{
    return period && (!strcmp(period, "once") || !strcmp(period, "daily") ||
                      !strcmp(period, "weekly") || !strcmp(period, "monthly"));
}

static int power_parse_time(const char *value, int *hour, int *minute)
{
    if (!value || strlen(value) != 5 || value[2] != ':' ||
        !isdigit((unsigned char)value[0]) || !isdigit((unsigned char)value[1]) ||
        !isdigit((unsigned char)value[3]) || !isdigit((unsigned char)value[4]))
        return -1;
    *hour = (value[0] - '0') * 10 + value[1] - '0';
    *minute = (value[3] - '0') * 10 + value[4] - '0';
    return *hour <= 23 && *minute <= 59 ? 0 : -1;
}

static int power_leap_year(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

static int power_days_in_month(int year, int month)
{
    static const int days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    if (month < 1 || month > 12)
        return 0;
    return month == 2 && power_leap_year(year) ? 29 : days[month - 1];
}

static int power_parse_date(const char *value, int *year, int *month, int *day)
{
    if (!value || strlen(value) != 10 || value[4] != '-' || value[7] != '-' ||
        !isdigit((unsigned char)value[0]) || !isdigit((unsigned char)value[1]) ||
        !isdigit((unsigned char)value[2]) || !isdigit((unsigned char)value[3]) ||
        !isdigit((unsigned char)value[5]) || !isdigit((unsigned char)value[6]) ||
        !isdigit((unsigned char)value[8]) || !isdigit((unsigned char)value[9]))
        return -1;
    *year = (value[0] - '0') * 1000 + (value[1] - '0') * 100 +
            (value[2] - '0') * 10 + value[3] - '0';
    *month = (value[5] - '0') * 10 + value[6] - '0';
    *day = (value[8] - '0') * 10 + value[9] - '0';
    if (*year < 1970 || *year > 9999 || *month < 1 || *month > 12 ||
        *day < 1 || *day > power_days_in_month(*year, *month))
        return -1;
    return 0;
}

static int power_local_candidate(int year, int month, int day, int hour, int minute,
                                 int64_t *epoch)
{
    struct tm requested, actual;
    time_t value;

    memset(&requested, 0, sizeof(requested));
    requested.tm_year = year - 1900;
    requested.tm_mon = month - 1;
    requested.tm_mday = day;
    requested.tm_hour = hour;
    requested.tm_min = minute;
    requested.tm_isdst = -1;
    value = mktime(&requested);
    if (value == (time_t)-1 || !localtime_r(&value, &actual))
        return -1;
    /* A DST gap may be normalized to another wall-clock time; skip it. */
    if (actual.tm_year != year - 1900 || actual.tm_mon != month - 1 ||
        actual.tm_mday != day || actual.tm_hour != hour || actual.tm_min != minute)
        return -1;
    *epoch = (int64_t)value;
    return 0;
}

static int power_weekday_selected(const struct power_schedule *schedule, int weekday)
{
    size_t i;

    for (i = 0; i < schedule->weekday_count; i++)
        if (schedule->weekdays[i] == weekday)
            return 1;
    return 0;
}

static int power_next_run(const struct power_schedule *schedule, int64_t after,
                          int64_t *next_run)
{
    struct tm base;
    time_t after_time = (time_t)after;
    int hour, minute;

    *next_run = 0;
    if (!schedule || power_parse_time(schedule->run_time, &hour, &minute) != 0 ||
        !localtime_r(&after_time, &base))
        return -1;
    if (!strcmp(schedule->period, "once")) {
        int year, month, day;
        int64_t candidate;

        if (power_parse_date(schedule->run_date, &year, &month, &day) != 0 ||
            power_local_candidate(year, month, day, hour, minute, &candidate) != 0)
            return -1;
        if (candidate > after)
            *next_run = candidate;
        return 0;
    }
    if (!strcmp(schedule->period, "daily") || !strcmp(schedule->period, "weekly")) {
        int offset;

        for (offset = 0; offset <= 370; offset++) {
            struct tm day = base, normalized;
            time_t day_time;
            int64_t candidate;

            day.tm_hour = 12;
            day.tm_min = 0;
            day.tm_sec = 0;
            day.tm_mday += offset;
            day.tm_isdst = -1;
            day_time = mktime(&day);
            if (day_time == (time_t)-1 || !localtime_r(&day_time, &normalized))
                continue;
            if (!strcmp(schedule->period, "weekly") &&
                !power_weekday_selected(schedule, normalized.tm_wday))
                continue;
            if (power_local_candidate(normalized.tm_year + 1900, normalized.tm_mon + 1,
                                      normalized.tm_mday, hour, minute, &candidate) == 0 &&
                candidate > after) {
                *next_run = candidate;
                return 0;
            }
        }
        return -1;
    }
    if (!strcmp(schedule->period, "monthly")) {
        int year = base.tm_year + 1900;
        int month = base.tm_mon + 1;
        int offset;

        for (offset = 0; offset < 1200; offset++) {
            int candidate_year = year + (month - 1 + offset) / 12;
            int candidate_month = (month - 1 + offset) % 12 + 1;
            int64_t candidate;

            /* Do not clamp 29/30/31 to month end; search the next valid month. */
            if (schedule->month_day > power_days_in_month(candidate_year, candidate_month))
                continue;
            if (power_local_candidate(candidate_year, candidate_month, schedule->month_day,
                                      hour, minute, &candidate) == 0 && candidate > after) {
                *next_run = candidate;
                return 0;
            }
        }
        return -1;
    }
    return -1;
}

static int power_weekdays_from_json(struct json_object *payload,
                                    struct power_schedule *schedule, int *present)
{
    struct json_object *array = NULL;
    int seen[7] = {0};
    size_t i, length;

    *present = 0;
    if (!payload || !json_object_is_type(payload, json_type_object) ||
        !json_object_object_get_ex(payload, "weekdays", &array))
        return 0;
    *present = 1;
    if (!array || json_object_is_type(array, json_type_null)) {
        schedule->weekday_count = 0;
        return 0;
    }
    if (!json_object_is_type(array, json_type_array))
        return -1;
    length = json_object_array_length(array);
    if (length > 7)
        return -1;
    schedule->weekday_count = 0;
    for (i = 0; i < length; i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        int value;

        if (!item || !json_object_is_type(item, json_type_int))
            return -1;
        value = json_object_get_int(item);
        if (value < 0 || value > 6 || seen[value])
            return -1;
        seen[value] = 1;
    }
    for (i = 0; i < 7; i++)
        if (seen[i])
            schedule->weekdays[schedule->weekday_count++] = (int)i;
    return 0;
}

static int power_weekdays_parse_text(const char *text, struct power_schedule *schedule)
{
    struct json_object *array = json_tokener_parse(text ? text : "[]");
    size_t i, length;
    int seen[7] = {0};

    schedule->weekday_count = 0;
    if (!array || !json_object_is_type(array, json_type_array)) {
        if (array)
            json_object_put(array);
        return -1;
    }
    length = json_object_array_length(array);
    for (i = 0; i < length; i++) {
        struct json_object *item = json_object_array_get_idx(array, i);
        int value;

        if (!item || !json_object_is_type(item, json_type_int)) {
            json_object_put(array);
            return -1;
        }
        value = json_object_get_int(item);
        if (value < 0 || value > 6 || seen[value]) {
            json_object_put(array);
            return -1;
        }
        seen[value] = 1;
    }
    for (i = 0; i < 7; i++)
        if (seen[i])
            schedule->weekdays[schedule->weekday_count++] = (int)i;
    json_object_put(array);
    return 0;
}

static char *power_weekdays_json(const struct power_schedule *schedule)
{
    struct json_object *array = json_object_new_array();
    const char *serialized;
    char *copy;
    size_t i;

    if (!array)
        return NULL;
    for (i = 0; i < schedule->weekday_count; i++)
        json_object_array_add(array, json_object_new_int(schedule->weekdays[i]));
    serialized = json_object_to_json_string_ext(array, JSON_C_TO_STRING_PLAIN);
    copy = serialized ? strdup(serialized) : NULL;
    json_object_put(array);
    return copy;
}

static int power_schedule_from_stmt(sqlite3_stmt *st, struct power_schedule *schedule)
{
    memset(schedule, 0, sizeof(*schedule));
    snprintf(schedule->id, sizeof(schedule->id), "%s", power_sql_text(st, 0));
    snprintf(schedule->name, sizeof(schedule->name), "%s", power_sql_text(st, 1));
    snprintf(schedule->event, sizeof(schedule->event), "%s", power_sql_text(st, 2));
    snprintf(schedule->period, sizeof(schedule->period), "%s", power_sql_text(st, 3));
    snprintf(schedule->run_date, sizeof(schedule->run_date), "%s", power_sql_text(st, 4));
    snprintf(schedule->run_time, sizeof(schedule->run_time), "%s", power_sql_text(st, 5));
    if (power_weekdays_parse_text(power_sql_text(st, 6), schedule) != 0)
        return -1;
    schedule->month_day = sqlite3_column_int(st, 7);
    snprintf(schedule->note, sizeof(schedule->note), "%s", power_sql_text(st, 8));
    schedule->enabled = sqlite3_column_int(st, 9);
    schedule->revision = sqlite3_column_int(st, 10);
    schedule->next_run_at = sqlite3_column_int64(st, 11);
    schedule->last_run_at = sqlite3_column_int64(st, 12);
    snprintf(schedule->last_result, sizeof(schedule->last_result), "%s", power_sql_text(st, 13));
    snprintf(schedule->claim_token, sizeof(schedule->claim_token), "%s", power_sql_text(st, 14));
    schedule->claim_until = sqlite3_column_int64(st, 15);
    schedule->created_at = sqlite3_column_int64(st, 16);
    schedule->updated_at = sqlite3_column_int64(st, 17);
    schedule->archived_at = sqlite3_column_int64(st, 18);
    return 0;
}

static const char power_schedule_columns[] =
    "id,name,event,period,run_date,run_time,weekdays_json,month_day,note,enabled,"
    "revision,next_run_at,last_run_at,last_result,claim_token,claim_until,"
    "created_at,updated_at,archived_at";

static int power_schedule_load(sqlite3 *db, const char *id,
                               struct power_schedule *schedule)
{
    sqlite3_stmt *st = NULL;
    char sql[512];
    int rc = 0;

    if (snprintf(sql, sizeof(sql), "SELECT %s FROM power_schedule WHERE id=?1",
                 power_schedule_columns) >= (int)sizeof(sql) ||
        power_prepare(db, &st, sql) != 0)
        return -1;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW)
        rc = power_schedule_from_stmt(st, schedule) == 0 ? 1 : -1;
    sqlite3_finalize(st);
    return rc;
}

static struct json_object *power_schedule_json(const struct power_schedule *schedule)
{
    struct json_object *item = json_object_new_object();
    struct json_object *weekdays = json_object_new_array();
    size_t i;

    json_object_object_add(item, "id", json_object_new_string(schedule->id));
    json_object_object_add(item, "name", json_object_new_string(schedule->name));
    json_object_object_add(item, "event", json_object_new_string(schedule->event));
    json_object_object_add(item, "period", json_object_new_string(schedule->period));
    if (schedule->run_date[0])
        json_object_object_add(item, "date", json_object_new_string(schedule->run_date));
    else
        json_object_object_add(item, "date", json_object_new_null());
    json_object_object_add(item, "time", json_object_new_string(schedule->run_time));
    for (i = 0; i < schedule->weekday_count; i++)
        json_object_array_add(weekdays, json_object_new_int(schedule->weekdays[i]));
    json_object_object_add(item, "weekdays", weekdays);
    if (schedule->month_day)
        json_object_object_add(item, "month_day", json_object_new_int(schedule->month_day));
    else
        json_object_object_add(item, "month_day", json_object_new_null());
    json_object_object_add(item, "note", json_object_new_string(schedule->note));
    json_object_object_add(item, "enabled", json_object_new_boolean(schedule->enabled));
    json_object_object_add(item, "revision", json_object_new_int(schedule->revision));
    json_object_object_add(item, "next_run_at", json_object_new_int64(schedule->next_run_at));
    json_object_object_add(item, "last_run_at", json_object_new_int64(schedule->last_run_at));
    json_object_object_add(item, "last_result", json_object_new_string(schedule->last_result));
    json_object_object_add(item, "created_at", json_object_new_int64(schedule->created_at));
    json_object_object_add(item, "updated_at", json_object_new_int64(schedule->updated_at));
    json_object_object_add(item, "archived", json_object_new_boolean(schedule->archived_at > 0));
    return item;
}

static int power_schedule_validate(struct power_schedule *schedule, int64_t now,
                                   const char **error, const char **reason)
{
    int hour, minute, year, month, day;
    int64_t next_run = 0;

    if (!power_text_ok(schedule->name, POWER_MAX_NAME, 1)) {
        *error = "invalid_name"; *reason = "name_must_be_nonempty_safe_text"; return -1;
    }
    if (!power_event_ok(schedule->event)) {
        *error = "invalid_event"; *reason = "event_must_be_reboot_or_shutdown"; return -1;
    }
    if (!power_period_ok(schedule->period)) {
        *error = "invalid_period"; *reason = "period_must_be_once_daily_weekly_or_monthly"; return -1;
    }
    if (power_parse_time(schedule->run_time, &hour, &minute) != 0) {
        *error = "invalid_time"; *reason = "time_must_be_local_hh_mm"; return -1;
    }
    if (!power_text_ok(schedule->note, POWER_MAX_NOTE, 0)) {
        *error = "invalid_note"; *reason = "note_contains_invalid_text"; return -1;
    }
    if (!strcmp(schedule->period, "once")) {
        if (power_parse_date(schedule->run_date, &year, &month, &day) != 0) {
            *error = "invalid_date"; *reason = "once_date_must_be_valid_yyyy_mm_dd"; return -1;
        }
        if (schedule->weekday_count || schedule->month_day) {
            *error = "invalid_schedule"; *reason = "once_disallows_weekdays_and_month_day"; return -1;
        }
    } else if (schedule->run_date[0]) {
        *error = "invalid_schedule"; *reason = "recurring_period_disallows_date"; return -1;
    }
    if (!strcmp(schedule->period, "weekly")) {
        if (schedule->weekday_count == 0) {
            *error = "invalid_weekdays"; *reason = "weekly_requires_at_least_one_weekday"; return -1;
        }
        if (schedule->month_day) {
            *error = "invalid_schedule"; *reason = "weekly_disallows_month_day"; return -1;
        }
    } else if (schedule->weekday_count) {
        *error = "invalid_weekdays"; *reason = "weekdays_only_allowed_for_weekly"; return -1;
    }
    if (!strcmp(schedule->period, "monthly")) {
        if (schedule->month_day < 1 || schedule->month_day > 31) {
            *error = "invalid_month_day"; *reason = "monthly_requires_day_between_1_and_31"; return -1;
        }
    } else if (schedule->month_day) {
        *error = "invalid_month_day"; *reason = "month_day_only_allowed_for_monthly"; return -1;
    }
    if (schedule->enabled) {
        if (power_next_run(schedule, now, &next_run) != 0) {
            *error = "invalid_time"; *reason = "local_time_has_no_valid_future_occurrence"; return -1;
        }
        if (!next_run) {
            *error = "invalid_time"; *reason = "once_schedule_must_be_in_the_future"; return -1;
        }
    }
    schedule->next_run_at = schedule->enabled ? next_run : 0;
    return 0;
}

static int power_request_confirmed(struct json_object *payload)
{
    int value = 0, present = 0;

    return power_json_bool(payload, "confirm", &value, &present) == 0 &&
           present && value;
}

static int power_nullable_string(struct json_object *payload, const char *key,
                                 const char **value, int *present)
{
    struct json_object *item = NULL;

    *present = 0;
    if (!payload || !json_object_is_type(payload, json_type_object) ||
        !json_object_object_get_ex(payload, key, &item))
        return 0;
    *present = 1;
    if (!item || json_object_is_type(item, json_type_null)) {
        *value = "";
        return 0;
    }
    if (!json_object_is_type(item, json_type_string))
        return -1;
    *value = json_object_get_string(item);
    return 0;
}

static int power_nullable_int(struct json_object *payload, const char *key,
                              int64_t *value, int *present)
{
    struct json_object *item = NULL;

    *present = 0;
    if (!payload || !json_object_is_type(payload, json_type_object) ||
        !json_object_object_get_ex(payload, key, &item))
        return 0;
    *present = 1;
    if (!item || json_object_is_type(item, json_type_null)) {
        *value = 0;
        return 0;
    }
    if (!json_object_is_type(item, json_type_int))
        return -1;
    *value = json_object_get_int64(item);
    return 0;
}

static int power_apply_payload(struct power_schedule *schedule,
                               struct json_object *payload, int create,
                               const char **error, const char **reason)
{
    const char *text = NULL;
    int present = 0, boolean_value = 0;
    int64_t integer_value = 0;

#define POWER_READ_TEXT(key, field, maximum, required) \
    do { \
        if (power_json_string(payload, key, &text, &present) != 0 || \
            ((create && required) && !present) || \
            (present && !power_text_ok(text, maximum, required))) { \
            *error = "invalid_" key; *reason = key "_invalid"; return -1; \
        } \
        if (present) snprintf(schedule->field, sizeof(schedule->field), "%s", text); \
    } while (0)
    POWER_READ_TEXT("name", name, POWER_MAX_NAME, 1);
    POWER_READ_TEXT("event", event, 15, 1);
    POWER_READ_TEXT("period", period, 15, 1);
    POWER_READ_TEXT("time", run_time, 5, 1);
    POWER_READ_TEXT("note", note, POWER_MAX_NOTE, 0);
#undef POWER_READ_TEXT
    if (power_nullable_string(payload, "date", &text, &present) != 0) {
        *error = "invalid_date"; *reason = "date_must_be_yyyy_mm_dd_or_null"; return -1;
    }
    if (present)
        snprintf(schedule->run_date, sizeof(schedule->run_date), "%s", text);
    if (power_weekdays_from_json(payload, schedule, &present) != 0) {
        *error = "invalid_weekdays"; *reason = "weekdays_must_be_unique_values_zero_to_six"; return -1;
    }
    if (power_nullable_int(payload, "month_day", &integer_value, &present) != 0 ||
        (present && (integer_value < 0 || integer_value > 31))) {
        *error = "invalid_month_day"; *reason = "month_day_must_be_null_or_one_to_31"; return -1;
    }
    if (present)
        schedule->month_day = (int)integer_value;
    if (power_json_bool(payload, "enabled", &boolean_value, &present) != 0) {
        *error = "invalid_enabled"; *reason = "enabled_must_be_boolean"; return -1;
    }
    if (present)
        schedule->enabled = boolean_value;
    return 0;
}

static int power_meta_bump(sqlite3 *db, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (power_prepare(db, &st,
            "UPDATE power_schedule_meta SET revision=revision+1,updated_at=?1 WHERE id=1") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    rc = power_step_done(st);
    sqlite3_finalize(st);
    return rc;
}

static int power_history_expired_reconcile(sqlite3 *db, int64_t now)
{
    sqlite3_stmt *st = NULL;
    char pending_id[POWER_MAX_ID + 1] = "";
    int64_t expires_at = 0;

    if (power_prepare(db, &st,
            "SELECT pending_action_id,pending_expires_at FROM power_schedule_meta WHERE id=1") != 0)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(pending_id, sizeof(pending_id), "%s", power_sql_text(st, 0));
        expires_at = sqlite3_column_int64(st, 1);
    }
    sqlite3_finalize(st);
    if (!pending_id[0] || expires_at > now)
        return 0;
    if (power_prepare(db, &st,
            "UPDATE power_schedule_history SET completed_at=?1,result='unknown',"
            "error='unknown_after_lease_expiry' WHERE action_id=?2 "
            "AND result IN('pending','accepted','dispatched')") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, pending_id, -1, SQLITE_TRANSIENT);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    if (power_prepare(db, &st,
            "UPDATE power_schedule SET enabled=0,next_run_at=0,last_result='unknown',"
            "claim_token='',claim_until=0,revision=revision+1,updated_at=?1 "
            "WHERE claim_token=?2") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, pending_id, -1, SQLITE_TRANSIENT);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    if (power_prepare(db, &st,
            "UPDATE power_schedule_meta SET pending_action_id='',pending_action='',"
            "pending_owner='',pending_since=0,pending_expires_at=0,"
            "last_action_result='unknown_after_lease_expiry',updated_at=?1 WHERE id=1") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

static enum power_lock_result power_action_lock_acquire(
    sqlite3 *db, const char *action_id, const char *action, const char *owner,
    const char *source, const char *schedule_id, const char *actor,
    const char *source_ip, int64_t planned_at, int64_t now)
{
    sqlite3_stmt *st = NULL;
    char pending_id[POWER_MAX_ID + 1] = "";
    int64_t pending_expires = 0, last_action_at = 0;

    if (power_history_expired_reconcile(db, now) != 0 ||
        power_prepare(db, &st,
            "SELECT pending_action_id,pending_expires_at,last_action_at "
            "FROM power_schedule_meta WHERE id=1") != 0)
        return POWER_LOCK_ERROR;
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(pending_id, sizeof(pending_id), "%s", power_sql_text(st, 0));
        pending_expires = sqlite3_column_int64(st, 1);
        last_action_at = sqlite3_column_int64(st, 2);
    }
    sqlite3_finalize(st);
    st = NULL;
    if (pending_id[0] && pending_expires > now)
        return POWER_LOCK_PENDING;
    if (last_action_at > 0 && now >= last_action_at &&
        now - last_action_at < POWER_ACTION_RATE_LIMIT_SECONDS)
        return POWER_LOCK_RATE_LIMITED;
    if (power_prepare(db, &st,
            "INSERT INTO power_schedule_history"
            "(action_id,schedule_id,source,event,planned_at,claimed_at,result,actor,source_ip,executor_pid)"
            " VALUES(?1,?2,?3,?4,?5,?6,'accepted',?7,?8,?9)") != 0)
        return POWER_LOCK_ERROR;
    sqlite3_bind_text(st, 1, action_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, schedule_id ? schedule_id : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, source, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 5, planned_at);
    sqlite3_bind_int64(st, 6, now);
    sqlite3_bind_text(st, 7, actor ? actor : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, source_ip ? source_ip : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 9, (int)getpid());
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return POWER_LOCK_ERROR;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (power_prepare(db, &st,
            "UPDATE power_schedule_meta SET pending_action_id=?1,pending_action=?2,"
            "pending_owner=?3,pending_since=?4,pending_expires_at=?5,last_action_at=?4,"
            "last_action=?2,last_action_result='accepted',updated_at=?4 WHERE id=1") != 0)
        return POWER_LOCK_ERROR;
    sqlite3_bind_text(st, 1, action_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, action, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, owner, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, now);
    sqlite3_bind_int64(st, 5, now + POWER_ACTION_LOCK_SECONDS);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return POWER_LOCK_ERROR;
    }
    sqlite3_finalize(st);
    return POWER_LOCK_OK;
}

static int power_action_lock_finish(sqlite3 *db, const char *action_id,
                                    const char *result, const char *error,
                                    int64_t now)
{
    sqlite3_stmt *st = NULL;

    if (power_prepare(db, &st,
            "UPDATE power_schedule_history SET completed_at=?1,result=?2,error=?3 "
            "WHERE action_id=?4 AND result IN('pending','accepted','dispatched')") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, result, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, action_id, -1, SQLITE_TRANSIENT);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (power_prepare(db, &st,
            "UPDATE power_schedule SET last_result=?1,updated_at=?2 "
            "WHERE id=(SELECT schedule_id FROM power_schedule_history "
            "WHERE action_id=?3 AND schedule_id<>'')") != 0)
        return -1;
    sqlite3_bind_text(st, 1, result, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, action_id, -1, SQLITE_TRANSIENT);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (power_prepare(db, &st,
            "UPDATE power_schedule_meta SET pending_action_id='',pending_action='',"
            "pending_owner='',pending_since=0,pending_expires_at=0,last_action_result=?1,"
            "updated_at=?2 WHERE id=1 AND pending_action_id=?3") != 0)
        return -1;
    sqlite3_bind_text(st, 1, result, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, now);
    sqlite3_bind_text(st, 3, action_id, -1, SQLITE_TRANSIENT);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st);
        return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

static int power_action_mark_dispatched(const char *action_id, pid_t executor_pid)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int64_t now = power_now_s();
    int rc = -1;

    if (power_db_open(&db) != 0 || power_sql_exec(db, "BEGIN IMMEDIATE") != 0)
        goto out;
    if (power_prepare(db, &st,
            "UPDATE power_schedule_history SET result='dispatched',executor_pid=?1 "
            "WHERE action_id=?2 AND result='accepted'") != 0)
        goto rollback;
    sqlite3_bind_int(st, 1, (int)executor_pid);
    sqlite3_bind_text(st, 2, action_id, -1, SQLITE_TRANSIENT);
    if (power_step_done(st) != 0 || sqlite3_changes(db) != 1)
        goto rollback;
    sqlite3_finalize(st); st = NULL;
    if (power_prepare(db, &st,
            "UPDATE power_schedule SET last_result='dispatched',updated_at=?1 "
            "WHERE id=(SELECT schedule_id FROM power_schedule_history "
            "WHERE action_id=?2 AND schedule_id<>'')") != 0)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, action_id, -1, SQLITE_TRANSIENT);
    if (power_step_done(st) != 0)
        goto rollback;
    sqlite3_finalize(st); st = NULL;
    if (power_prepare(db, &st,
            "UPDATE power_schedule_meta SET last_action_result='dispatched',updated_at=?1 "
            "WHERE id=1 AND pending_action_id=?2") != 0)
        goto rollback;
    sqlite3_bind_int64(st, 1, now);
    sqlite3_bind_text(st, 2, action_id, -1, SQLITE_TRANSIENT);
    if (power_step_done(st) != 0 || sqlite3_changes(db) != 1 ||
        power_sql_exec(db, "COMMIT") != 0)
        goto rollback;
    rc = 0;
    goto out;
rollback:
    if (st) { sqlite3_finalize(st); st = NULL; }
    (void)power_sql_exec(db, "ROLLBACK");
out:
    if (st) sqlite3_finalize(st);
    if (db) sqlite3_close(db);
    return rc;
}

static void power_detached_exec_failure(const char *action_id)
{
    sqlite3 *db = NULL;
    int64_t now = power_now_s();

    if (power_db_open(&db) != 0 || power_sql_exec(db, "BEGIN IMMEDIATE") != 0)
        goto out;
    if (power_action_lock_finish(db, action_id, "failed", "execv_failed", now) != 0 ||
        power_sql_exec(db, "COMMIT") != 0)
        (void)power_sql_exec(db, "ROLLBACK");
out:
    if (db) sqlite3_close(db);
}

static int power_read_uptime(int64_t *uptime)
{
    FILE *fp;
    double seconds;

    *uptime = 0;
    fp = fopen("/proc/uptime", "r");
    if (!fp)
        return -1;
    if (fscanf(fp, "%lf", &seconds) != 1 || seconds < 0) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *uptime = (int64_t)seconds;
    return 0;
}

static void power_add_capabilities(struct json_object *data)
{
    struct json_object *capabilities = json_object_new_object();
    int reboot_available = access(JMX_SYSTEM_POWER_REBOOT_PATH, X_OK) == 0;
    int shutdown_available = access(JMX_SYSTEM_POWER_SHUTDOWN_PATH, X_OK) == 0;

#ifdef JMX_SYSTEM_POWER_TESTING
    reboot_available = 1;
    shutdown_available = 1;
#endif
    json_object_object_add(capabilities, "reboot",
                           json_object_new_boolean(reboot_available));
    json_object_object_add(capabilities, "shutdown",
                           json_object_new_boolean(shutdown_available));
    json_object_object_add(capabilities, "schedule_create", json_object_new_boolean(1));
    json_object_object_add(capabilities, "schedule_update", json_object_new_boolean(1));
    json_object_object_add(capabilities, "schedule_delete", json_object_new_boolean(1));
    json_object_object_add(capabilities, "optimistic_revision",
                           json_object_new_boolean(1));
    json_object_object_add(capabilities, "persistent_action_lock",
                           json_object_new_boolean(1));
    json_object_object_add(data, "capabilities", capabilities);
}

struct json_object *jmx_system_power_get(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *data = NULL, *schedules = NULL, *history = NULL;
    char sql[640], timezone[64] = "local";
    int64_t now = power_now_s(), uptime = 0;
    int64_t meta_revision = 0, pending_since = 0, pending_expires_at = 0;
    char pending_id[POWER_MAX_ID + 1] = "", pending_action[16] = "";
    char last_action[16] = "", last_result[64] = "";
    int rc;

    if (power_db_open(&db) != 0)
        return power_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (power_sql_exec(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return power_error("storage_unavailable", "power_state_transaction_failed");
    }
    if (power_history_expired_reconcile(db, now) != 0 ||
        power_sql_exec(db, "COMMIT") != 0) {
        (void)power_sql_exec(db, "ROLLBACK");
        sqlite3_close(db);
        return power_error("storage_unavailable", "power_state_reconcile_failed");
    }
    data = json_object_new_object();
    schedules = json_object_new_array();
    history = json_object_new_array();
    if (!data || !schedules || !history)
        goto allocation_failure;
    if (power_read_uptime(&uptime) == 0)
        json_object_object_add(data, "uptime", json_object_new_int64(uptime));
    else
        json_object_object_add(data, "uptime", json_object_new_null());
    power_add_capabilities(data);
    tzset();
    {
        struct tm local_tm;
        time_t now_time = (time_t)now;
        if (localtime_r(&now_time, &local_tm))
            (void)strftime(timezone, sizeof(timezone), "%Z%z", &local_tm);
    }
    json_object_object_add(data, "timezone", json_object_new_string(timezone));
    if (snprintf(sql, sizeof(sql),
            "SELECT %s FROM power_schedule WHERE archived_at=0 ORDER BY next_run_at=0,next_run_at,id",
            power_schedule_columns) >= (int)sizeof(sql) ||
        power_prepare(db, &st, sql) != 0)
        goto storage_failure;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        struct power_schedule schedule;
        if (power_schedule_from_stmt(st, &schedule) != 0)
            goto storage_failure;
        json_object_array_add(schedules, power_schedule_json(&schedule));
    }
    if (rc != SQLITE_DONE)
        goto storage_failure;
    sqlite3_finalize(st); st = NULL;
    if (power_prepare(db, &st,
            "SELECT action_id,schedule_id,source,event,planned_at,claimed_at,completed_at,"
            "result,error,actor,source_ip FROM power_schedule_history "
            "ORDER BY claimed_at DESC,id DESC LIMIT 100") != 0)
        goto storage_failure;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        json_object_object_add(item, "action_id", json_object_new_string(power_sql_text(st, 0)));
        json_object_object_add(item, "schedule_id", json_object_new_string(power_sql_text(st, 1)));
        json_object_object_add(item, "source", json_object_new_string(power_sql_text(st, 2)));
        json_object_object_add(item, "event", json_object_new_string(power_sql_text(st, 3)));
        json_object_object_add(item, "planned_at", json_object_new_int64(sqlite3_column_int64(st, 4)));
        json_object_object_add(item, "claimed_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
        json_object_object_add(item, "completed_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
        json_object_object_add(item, "result", json_object_new_string(power_sql_text(st, 7)));
        json_object_object_add(item, "error", json_object_new_string(power_sql_text(st, 8)));
        json_object_object_add(item, "actor", json_object_new_string(power_sql_text(st, 9)));
        json_object_object_add(item, "source_ip", json_object_new_string(power_sql_text(st, 10)));
        json_object_array_add(history, item);
    }
    if (rc != SQLITE_DONE)
        goto storage_failure;
    sqlite3_finalize(st); st = NULL;
    if (power_prepare(db, &st,
            "SELECT revision,pending_action_id,pending_action,pending_since,pending_expires_at,"
            "last_action,last_action_result FROM power_schedule_meta WHERE id=1") != 0 ||
        sqlite3_step(st) != SQLITE_ROW)
        goto storage_failure;
    meta_revision = sqlite3_column_int64(st, 0);
    snprintf(pending_id, sizeof(pending_id), "%s", power_sql_text(st, 1));
    snprintf(pending_action, sizeof(pending_action), "%s", power_sql_text(st, 2));
    pending_since = sqlite3_column_int64(st, 3);
    pending_expires_at = sqlite3_column_int64(st, 4);
    snprintf(last_action, sizeof(last_action), "%s", power_sql_text(st, 5));
    snprintf(last_result, sizeof(last_result), "%s", power_sql_text(st, 6));
    sqlite3_finalize(st); st = NULL;
    json_object_object_add(data, "revision", json_object_new_int64(meta_revision));
    json_object_object_add(data, "schedules", schedules); schedules = NULL;
    json_object_object_add(data, "history", history); history = NULL;
    {
        struct json_object *runtime = json_object_new_object();
        json_object_object_add(runtime, "pending", json_object_new_boolean(pending_id[0] != '\0'));
        json_object_object_add(runtime, "pending_action_id", json_object_new_string(pending_id));
        json_object_object_add(runtime, "pending_action", json_object_new_string(pending_action));
        json_object_object_add(runtime, "pending_since", json_object_new_int64(pending_since));
        json_object_object_add(runtime, "pending_expires_at", json_object_new_int64(pending_expires_at));
        json_object_object_add(runtime, "last_action", json_object_new_string(last_action));
        json_object_object_add(runtime, "last_result", json_object_new_string(last_result));
        json_object_object_add(runtime, "rate_limit_seconds",
                               json_object_new_int(POWER_ACTION_RATE_LIMIT_SECONDS));
        json_object_object_add(data, "runtime", runtime);
    }
    sqlite3_close(db);
    return power_success(data);
storage_failure:
    if (st) sqlite3_finalize(st);
    if (schedules) json_object_put(schedules);
    if (history) json_object_put(history);
    if (data) json_object_put(data);
    sqlite3_close(db);
    return power_error("storage_unavailable", "power_state_read_failed");
allocation_failure:
    if (schedules) json_object_put(schedules);
    if (history) json_object_put(history);
    if (data) json_object_put(data);
    sqlite3_close(db);
    return power_error("storage_unavailable", "json_allocation_failed");
}

struct json_object *jmx_system_power_schedule_upsert(
    const char *schedule_id, struct json_object *request)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *payload = power_payload(request), *data;
    struct power_schedule schedule;
    const char *error = NULL, *reason = NULL;
    char generated_id[POWER_MAX_ID + 1], *weekdays_json = NULL;
    int create = !schedule_id || !schedule_id[0], load_rc, present;
    int64_t expected_revision = 0, now = power_now_s();

    if (!payload || !json_object_is_type(payload, json_type_object))
        return power_error("invalid_request", "request_object_required");
    if (!power_request_confirmed(payload))
        return power_error("confirmation_required", "confirm_true_required");
    if (!create && !power_id_ok(schedule_id))
        return power_error("invalid_id", "schedule_id_invalid");
    if (!create && (power_json_int(payload, "revision", &expected_revision, &present) != 0 ||
                    !present || expected_revision < 1))
        return power_error("revision_required", "update_requires_positive_revision");
    if (power_db_open(&db) != 0)
        return power_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (power_sql_exec(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return power_error("storage_unavailable", "power_schedule_transaction_failed");
    }
    memset(&schedule, 0, sizeof(schedule));
    if (create) {
        if (power_random_id("power", generated_id, sizeof(generated_id)) != 0) {
            error = "storage_unavailable"; reason = "secure_random_id_unavailable"; goto rollback;
        }
        schedule_id = generated_id;
        schedule.enabled = 1;
        schedule.revision = 1;
        schedule.created_at = now;
    } else {
        load_rc = power_schedule_load(db, schedule_id, &schedule);
        if (load_rc <= 0) {
            error = load_rc == 0 ? "schedule_not_found" : "storage_unavailable";
            reason = load_rc == 0 ? "power_schedule_not_found" : "power_schedule_read_failed";
            goto rollback;
        }
        if (schedule.revision != expected_revision) {
            error = "schedule_conflict"; reason = "revision_does_not_match_current_schedule";
            goto rollback;
        }
    }
    snprintf(schedule.id, sizeof(schedule.id), "%s", schedule_id);
    if (power_apply_payload(&schedule, payload, create, &error, &reason) != 0 ||
        power_schedule_validate(&schedule, now, &error, &reason) != 0)
        goto rollback;
    weekdays_json = power_weekdays_json(&schedule);
    if (!weekdays_json) {
        error = "storage_unavailable"; reason = "weekdays_serialization_failed"; goto rollback;
    }
    if (create) {
        if (power_prepare(db, &st,
                "INSERT INTO power_schedule"
                "(id,name,event,period,run_date,run_time,weekdays_json,month_day,note,enabled,"
                "revision,next_run_at,created_at,updated_at)"
                " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?12,?12)") != 0) {
            error = "storage_unavailable"; reason = "schedule_insert_prepare_failed"; goto rollback;
        }
    } else {
        if (power_prepare(db, &st,
                "UPDATE power_schedule SET name=?2,event=?3,period=?4,run_date=?5,run_time=?6,"
                "weekdays_json=?7,month_day=?8,note=?9,enabled=?10,revision=revision+1,"
                "next_run_at=?11,updated_at=?12 WHERE id=?1 AND revision=?13") != 0) {
            error = "storage_unavailable"; reason = "schedule_update_prepare_failed"; goto rollback;
        }
    }
    sqlite3_bind_text(st, 1, schedule.id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, schedule.name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, schedule.event, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, schedule.period, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, schedule.run_date, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, schedule.run_time, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, weekdays_json, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 8, schedule.month_day);
    sqlite3_bind_text(st, 9, schedule.note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 10, schedule.enabled);
    sqlite3_bind_int64(st, 11, schedule.next_run_at);
    sqlite3_bind_int64(st, 12, now);
    if (!create)
        sqlite3_bind_int64(st, 13, expected_revision);
    if (power_step_done(st) != 0) {
        sqlite3_finalize(st); st = NULL;
        error = "storage_unavailable"; reason = "power_schedule_write_failed"; goto rollback;
    }
    sqlite3_finalize(st); st = NULL;
    if (!create && sqlite3_changes(db) != 1) {
        error = "schedule_conflict"; reason = "revision_changed_during_update"; goto rollback;
    }
    if (power_meta_bump(db, now) != 0 ||
        power_schedule_load(db, schedule.id, &schedule) != 1 ||
        power_sql_exec(db, "COMMIT") != 0) {
        error = "storage_unavailable"; reason = "power_schedule_commit_failed"; goto rollback;
    }
    free(weekdays_json);
    sqlite3_close(db);
    data = json_object_new_object();
    json_object_object_add(data, "created", json_object_new_boolean(create));
    json_object_object_add(data, "changed", json_object_new_boolean(1));
    json_object_object_add(data, "schedule", power_schedule_json(&schedule));
    return power_success(data);
rollback:
    if (st) sqlite3_finalize(st);
    free(weekdays_json);
    (void)power_sql_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return power_error(error ? error : "storage_unavailable",
                       reason ? reason : "power_schedule_upsert_failed");
}

struct json_object *jmx_system_power_schedule_delete(
    const char *schedule_id, struct json_object *request)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *payload = power_payload(request), *data;
    int present, exists;
    int64_t revision = 0, now = power_now_s();

    if (!payload || !json_object_is_type(payload, json_type_object))
        return power_error("invalid_request", "request_object_required");
    if (!power_request_confirmed(payload))
        return power_error("confirmation_required", "confirm_true_required");
    if (!power_id_ok(schedule_id))
        return power_error("invalid_id", "schedule_id_invalid");
    if (power_json_int(payload, "revision", &revision, &present) != 0 ||
        !present || revision < 1)
        return power_error("revision_required", "delete_requires_positive_revision");
    if (power_db_open(&db) != 0)
        return power_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (power_sql_exec(db, "BEGIN IMMEDIATE") != 0 ||
        power_prepare(db, &st,
            "DELETE FROM power_schedule WHERE id=?1 AND revision=?2 AND claim_token=''") != 0)
        goto storage_failure;
    sqlite3_bind_text(st, 1, schedule_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, revision);
    if (power_step_done(st) != 0)
        goto storage_failure;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_changes(db) != 1) {
        struct power_schedule current;
        exists = power_schedule_load(db, schedule_id, &current);
        (void)power_sql_exec(db, "ROLLBACK");
        sqlite3_close(db);
        return power_error(exists == 0 ? "schedule_not_found" :
                           (exists > 0 && current.claim_token[0] ? "schedule_pending" :
                            "schedule_conflict"),
                           exists == 0 ? "power_schedule_not_found" :
                           (exists > 0 && current.claim_token[0] ? "schedule_has_pending_action" :
                            "revision_does_not_match_current_schedule"));
    }
    if (power_meta_bump(db, now) != 0 || power_sql_exec(db, "COMMIT") != 0)
        goto storage_failure;
    sqlite3_close(db);
    data = json_object_new_object();
    json_object_object_add(data, "id", json_object_new_string(schedule_id));
    json_object_object_add(data, "deleted", json_object_new_boolean(1));
    return power_success(data);
storage_failure:
    if (st) sqlite3_finalize(st);
    (void)power_sql_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return power_error("storage_unavailable", "power_schedule_delete_failed");
}

static int power_harness_mode(void)
{
#ifdef JMX_SYSTEM_POWER_TESTING
    return 1;
#else
    const char *value = getenv("JMX_SYSTEM_POWER_HARNESS");

    return value && !strcmp(value, "1") && getuid() == geteuid();
#endif
}

static int power_request_execute_mode(struct json_object *payload, int *execute,
                                      int *explicit_value)
{
    int value = 1, present = 0;

    if (power_json_bool(payload, "execute", &value, &present) != 0)
        return -1;
    *explicit_value = present;
    *execute = present ? value : 1;
    if (present && !value && !power_harness_mode())
        return -2;
    return 0;
}

static int power_exec_fixed(const char *action, const char *action_id, int execute,
                            struct power_exec_result *result)
{
    char *reboot_argv[] = { (char *)JMX_SYSTEM_POWER_REBOOT_PATH, NULL };
    char *shutdown_argv[] = { (char *)JMX_SYSTEM_POWER_SHUTDOWN_PATH, NULL };
    char **argv;
    int handshake[2] = {-1, -1};
    int release_gate[2] = {-1, -1};
    pid_t dispatcher, detached = -1;
    struct pollfd pfd;
    ssize_t got;
    int status;

    memset(result, 0, sizeof(*result));
    result->release_fd = -1;
    if (!power_event_ok(action))
        return -1;
    if (!execute) {
        result->dry_run = 1;
        return 0;
    }
    argv = !strcmp(action, "reboot") ? reboot_argv : shutdown_argv;
    if (access(argv[0], X_OK) != 0)
        return -1;
    if (pipe2(handshake, O_CLOEXEC) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, release_gate) != 0) {
        close(handshake[0]); close(handshake[1]);
        return -1;
    }
    dispatcher = fork();
    if (dispatcher < 0) {
        close(handshake[0]); close(handshake[1]);
        close(release_gate[0]); close(release_gate[1]);
        return -1;
    }
    if (dispatcher == 0) {
        long open_max;
        int fd;
        char release = '\0';

        close(handshake[0]);
        close(release_gate[1]);
        if (setsid() < 0) {
            (void)write(handshake[1], &detached, sizeof(detached));
            _exit(126);
        }
        detached = fork();
        if (detached != 0) {
            close(release_gate[0]);
            (void)write(handshake[1], &detached, sizeof(detached));
            _exit(detached > 0 ? 0 : 126);
        }
        close(handshake[1]);
        open_max = sysconf(_SC_OPEN_MAX);
        if (open_max < 0 || open_max > 65536)
            open_max = 65536;
        for (fd = 3; fd < open_max; fd++)
            if (fd != release_gate[0])
                close(fd);
        do {
            got = read(release_gate[0], &release, 1);
        } while (got < 0 && errno == EINTR);
        close(release_gate[0]);
        if (got != 1 || release != '1')
            _exit(125);
        sleep(POWER_DISPATCH_DELAY_SECONDS);
        execv(argv[0], argv);
        power_detached_exec_failure(action_id);
        _exit(127);
    }
    close(release_gate[0]); release_gate[0] = -1;
    close(handshake[1]); handshake[1] = -1;
    pfd.fd = handshake[0];
    pfd.events = POLLIN | POLLHUP;
    if (poll(&pfd, 1, POWER_DISPATCH_HANDSHAKE_TIMEOUT_MS) <= 0) {
        close(handshake[0]);
        close(release_gate[1]);
        (void)kill(dispatcher, SIGKILL);
        while (waitpid(dispatcher, &status, 0) < 0 && errno == EINTR) {}
        return -1;
    }
    do {
        got = read(handshake[0], &detached, sizeof(detached));
    } while (got < 0 && errno == EINTR);
    close(handshake[0]);
    while (waitpid(dispatcher, &status, 0) < 0 && errno == EINTR) {}
    if (got != (ssize_t)sizeof(detached) || detached <= 0 ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        close(release_gate[1]);
        return -1;
    }
    result->dispatcher_pid = detached;
    result->release_fd = release_gate[1];
    return 0;
}

static int power_exec_release(struct power_exec_result *result)
{
    char release = '1';
    ssize_t written;

    if (!result || result->release_fd < 0)
        return -1;
    do {
        written = send(result->release_fd, &release, 1, MSG_NOSIGNAL);
    } while (written < 0 && errno == EINTR);
    close(result->release_fd);
    result->release_fd = -1;
    return written == 1 ? 0 : -1;
}

static void power_exec_cancel(struct power_exec_result *result)
{
    if (result && result->release_fd >= 0) {
        close(result->release_fd);
        result->release_fd = -1;
    }
}

static void power_request_audit_fields(struct json_object *payload,
                                       char *actor, size_t actor_size,
                                       char *source_ip, size_t source_ip_size)
{
    const char *value = NULL;
    int present = 0;

    actor[0] = '\0';
    source_ip[0] = '\0';
    if (power_json_string(payload, "actor", &value, &present) == 0 && present &&
        power_text_ok(value, POWER_MAX_OWNER, 0))
        snprintf(actor, actor_size, "%s", value);
    if (power_json_string(payload, "source_ip", &value, &present) == 0 && present &&
        power_text_ok(value, POWER_MAX_SOURCE_IP, 0))
        snprintf(source_ip, source_ip_size, "%s", value);
}

static struct json_object *power_lock_error(enum power_lock_result lock_result)
{
    if (lock_result == POWER_LOCK_PENDING)
        return power_error("immediate_action_pending", "another_power_action_lease_is_active");
    if (lock_result == POWER_LOCK_RATE_LIMITED)
        return power_error("rate_limited", "power_actions_require_30_second_cooldown");
    return power_error("storage_unavailable", "power_action_lock_failed");
}

struct json_object *jmx_system_power_immediate_action(
    const char *action, struct json_object *request)
{
    sqlite3 *db = NULL;
    struct json_object *payload = power_payload(request), *data;
    struct power_exec_result exec_result;
    enum power_lock_result lock_result;
    char action_id[POWER_MAX_ID + 1], owner[POWER_MAX_OWNER + 1];
    char actor[POWER_MAX_OWNER + 1], source_ip[POWER_MAX_SOURCE_IP + 1];
    int execute = 1, explicit_execute = 0, execute_rc, dispatch_rc;
    int64_t now = power_now_s();

    if (!power_event_ok(action))
        return power_error("invalid_action", "action_must_be_reboot_or_shutdown");
    if (!payload || !json_object_is_type(payload, json_type_object))
        return power_error("invalid_request", "request_object_required");
    if (!power_request_confirmed(payload))
        return power_error("confirmation_required", "confirm_true_required");
    execute_rc = power_request_execute_mode(payload, &execute, &explicit_execute);
    if (execute_rc == -1)
        return power_error("invalid_execute", "execute_must_be_boolean");
    if (execute_rc == -2)
        return power_error("execute_override_forbidden",
                           "production_requests_cannot_disable_power_execution");
    (void)explicit_execute;
    if (!execute) {
        (void)power_exec_fixed(action, "dry-run", 0, &exec_result);
        data = json_object_new_object();
        json_object_object_add(data, "action", json_object_new_string(action));
        json_object_object_add(data, "accepted", json_object_new_boolean(0));
        json_object_object_add(data, "dispatched", json_object_new_boolean(0));
        json_object_object_add(data, "executed", json_object_new_boolean(0));
        json_object_object_add(data, "dry_run", json_object_new_boolean(1));
        json_object_object_add(data, "result", json_object_new_string("dry_run"));
        return power_success(data);
    }
    if (power_random_id("action", action_id, sizeof(action_id)) != 0)
        return power_error("storage_unavailable", "secure_action_id_unavailable");
    snprintf(owner, sizeof(owner), "immediate:%ld", (long)getpid());
    power_request_audit_fields(payload, actor, sizeof(actor), source_ip, sizeof(source_ip));
    if (power_db_open(&db) != 0)
        return power_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (power_sql_exec(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return power_error("storage_unavailable", "power_action_transaction_failed");
    }
    lock_result = power_action_lock_acquire(db, action_id, action, owner,
        "immediate", "", actor, source_ip, now, now);
    if (lock_result != POWER_LOCK_OK) {
        (void)power_sql_exec(db, "ROLLBACK");
        sqlite3_close(db);
        return power_lock_error(lock_result);
    }
    if (power_sql_exec(db, "COMMIT") != 0) {
        (void)power_sql_exec(db, "ROLLBACK");
        sqlite3_close(db);
        return power_error("storage_unavailable", "power_action_claim_commit_failed");
    }
    sqlite3_close(db); db = NULL;
    dispatch_rc = power_exec_fixed(action, action_id, 1, &exec_result);
    if (dispatch_rc != 0) {
        int64_t failed_at = power_now_s();
        if (power_db_open(&db) == 0 && power_sql_exec(db, "BEGIN IMMEDIATE") == 0 &&
            power_action_lock_finish(db, action_id, "failed", "dispatch_failed", failed_at) == 0 &&
            power_sql_exec(db, "COMMIT") == 0) {
            sqlite3_close(db);
            return power_error("action_dispatch_failed", "detached_dispatch_could_not_start");
        }
        if (db) {
            (void)power_sql_exec(db, "ROLLBACK");
            sqlite3_close(db);
        }
        return power_error("storage_unavailable", "power_action_result_persist_failed");
    }
    if (power_action_mark_dispatched(action_id, exec_result.dispatcher_pid) != 0) {
        power_exec_cancel(&exec_result);
        return power_error("storage_unavailable", "power_action_dispatch_state_failed");
    }
    if (power_exec_release(&exec_result) != 0) {
        int64_t failed_at = power_now_s();

        if (power_db_open(&db) == 0 && power_sql_exec(db, "BEGIN IMMEDIATE") == 0 &&
            power_action_lock_finish(db, action_id, "failed", "dispatch_release_failed",
                                     failed_at) == 0 &&
            power_sql_exec(db, "COMMIT") == 0)
            sqlite3_close(db);
        else if (db) {
            (void)power_sql_exec(db, "ROLLBACK");
            sqlite3_close(db);
        }
        return power_error("action_dispatch_failed", "detached_dispatch_release_failed");
    }
    data = json_object_new_object();
    json_object_object_add(data, "action_id", json_object_new_string(action_id));
    json_object_object_add(data, "action", json_object_new_string(action));
    json_object_object_add(data, "accepted", json_object_new_boolean(1));
    json_object_object_add(data, "dispatched", json_object_new_boolean(1));
    json_object_object_add(data, "executed", json_object_new_boolean(0));
    json_object_object_add(data, "dry_run", json_object_new_boolean(0));
    json_object_object_add(data, "result", json_object_new_string("dispatched"));
    json_object_object_add(data, "dispatch_delay_seconds",
                           json_object_new_int(POWER_DISPATCH_DELAY_SECONDS));
    return power_success(data);
}

static struct json_object *power_scheduler_preview(sqlite3 *db, int64_t now)
{
    sqlite3_stmt *st = NULL;
    struct json_object *data = json_object_new_object();
    struct json_object *due = json_object_new_array();
    int rc;

    if (!data || !due || power_prepare(db, &st,
            "SELECT id,event,next_run_at,revision FROM power_schedule "
            "WHERE enabled=1 AND archived_at=0 AND next_run_at>0 AND next_run_at<=?1 "
            "AND (claim_token='' OR claim_until<=?1) ORDER BY next_run_at,id") != 0) {
        if (data) json_object_put(data);
        if (due) json_object_put(due);
        return power_error("storage_unavailable", "scheduler_preview_failed");
    }
    sqlite3_bind_int64(st, 1, now);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        struct json_object *item = json_object_new_object();
        json_object_object_add(item, "id", json_object_new_string(power_sql_text(st, 0)));
        json_object_object_add(item, "event", json_object_new_string(power_sql_text(st, 1)));
        json_object_object_add(item, "next_run_at", json_object_new_int64(sqlite3_column_int64(st, 2)));
        json_object_object_add(item, "revision", json_object_new_int(sqlite3_column_int(st, 3)));
        json_object_array_add(due, item);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        json_object_put(data);
        json_object_put(due);
        return power_error("storage_unavailable", "scheduler_preview_read_failed");
    }
    json_object_object_add(data, "preview", json_object_new_boolean(1));
    json_object_object_add(data, "executed", json_object_new_boolean(0));
    json_object_object_add(data, "now", json_object_new_int64(now));
    json_object_object_add(data, "due", due);
    return power_success(data);
}

static int power_scheduler_has_work(sqlite3 *db, int64_t now)
{
    sqlite3_stmt *st = NULL;
    int has_work = -1;

    if (power_prepare(db, &st,
            "SELECT 1 FROM power_schedule_meta WHERE id=1 AND pending_action_id<>'' "
            "AND pending_expires_at<=?1 UNION ALL "
            "SELECT 1 FROM power_schedule WHERE enabled=1 AND archived_at=0 "
            "AND next_run_at>0 AND next_run_at<=?1 "
            "AND (claim_token='' OR claim_until<=?1) LIMIT 1") != 0)
        return -1;
    sqlite3_bind_int64(st, 1, now);
    if (sqlite3_step(st) == SQLITE_ROW)
        has_work = 1;
    else
        has_work = 0;
    sqlite3_finalize(st);
    return has_work;
}

struct json_object *jmx_system_power_scheduler_tick(int64_t now_epoch, int execute)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    struct json_object *data;
    struct power_schedule schedule;
    struct power_exec_result exec_result;
    enum power_lock_result lock_result;
    char sql[640], action_id[POWER_MAX_ID + 1], owner[POWER_MAX_OWNER + 1];
    int rc, dispatch_rc;
    int64_t now = now_epoch > 0 ? now_epoch : power_now_s();
    int64_t next_run = 0;

    if (power_db_open(&db) != 0)
        return power_error("storage_unavailable", "config_db_open_or_schema_failed");
    if (!execute) {
        data = power_scheduler_preview(db, now);
        sqlite3_close(db);
        return data;
    }
    rc = power_scheduler_has_work(db, now);
    if (rc < 0) {
        sqlite3_close(db);
        return power_error("storage_unavailable", "scheduler_precheck_failed");
    }
    if (rc == 0) {
        sqlite3_close(db);
        data = json_object_new_object();
        json_object_object_add(data, "executed", json_object_new_boolean(0));
        json_object_object_add(data, "due", json_object_new_boolean(0));
        json_object_object_add(data, "now", json_object_new_int64(now));
        return power_success(data);
    }
    if (power_sql_exec(db, "BEGIN IMMEDIATE") != 0) {
        sqlite3_close(db);
        return power_error("storage_unavailable", "scheduler_transaction_failed");
    }
    if (power_history_expired_reconcile(db, now) != 0)
        goto storage_failure;
    if (snprintf(sql, sizeof(sql),
            "SELECT %s FROM power_schedule WHERE enabled=1 AND archived_at=0 "
            "AND next_run_at>0 AND next_run_at<=?1 AND (claim_token='' OR claim_until<=?1) "
            "ORDER BY next_run_at,id LIMIT 1", power_schedule_columns) >= (int)sizeof(sql) ||
        power_prepare(db, &st, sql) != 0)
        goto storage_failure;
    sqlite3_bind_int64(st, 1, now);
    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(st); st = NULL;
        /* Empty scheduler ticks are read-only to avoid config.db WAL churn. */
        if (power_sql_exec(db, "COMMIT") != 0)
            goto storage_failure;
        sqlite3_close(db);
        data = json_object_new_object();
        json_object_object_add(data, "executed", json_object_new_boolean(0));
        json_object_object_add(data, "due", json_object_new_boolean(0));
        json_object_object_add(data, "now", json_object_new_int64(now));
        return power_success(data);
    }
    if (rc != SQLITE_ROW || power_schedule_from_stmt(st, &schedule) != 0)
        goto storage_failure;
    sqlite3_finalize(st); st = NULL;
    if (power_random_id("action", action_id, sizeof(action_id)) != 0)
        goto storage_failure;
    snprintf(owner, sizeof(owner), "scheduler:%ld:%s", (long)getpid(), schedule.id);
    lock_result = power_action_lock_acquire(db, action_id, schedule.event, owner,
        "schedule", schedule.id, "scheduler", "local", schedule.next_run_at, now);
    if (lock_result != POWER_LOCK_OK) {
        (void)power_sql_exec(db, "ROLLBACK");
        sqlite3_close(db);
        return power_lock_error(lock_result);
    }
    if (strcmp(schedule.period, "once") &&
        power_next_run(&schedule, now, &next_run) != 0)
        next_run = 0;
    /*
     * Advance or archive before dispatch. A successful reboot may prevent any
     * post-dispatch code from running, so the old due time must already be gone.
     */
    if (power_prepare(db, &st,
            "UPDATE power_schedule SET enabled=?1,next_run_at=?2,last_run_at=?3,"
            "last_result='accepted',claim_token='',claim_until=0,revision=revision+1,"
            "updated_at=?3,archived_at=?4 WHERE id=?5 AND revision=?6 "
            "AND (claim_token='' OR claim_until<=?3)") != 0)
        goto storage_failure;
    sqlite3_bind_int(st, 1, strcmp(schedule.period, "once") != 0 && next_run > 0);
    sqlite3_bind_int64(st, 2, next_run);
    sqlite3_bind_int64(st, 3, now);
    sqlite3_bind_int64(st, 4, !strcmp(schedule.period, "once") ? now : 0);
    sqlite3_bind_text(st, 5, schedule.id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, schedule.revision);
    if (power_step_done(st) != 0 || sqlite3_changes(db) != 1)
        goto storage_failure;
    sqlite3_finalize(st); st = NULL;
    if (power_prepare(db, &st,
            "UPDATE power_schedule_meta SET last_tick_at=?1,updated_at=?1 WHERE id=1") != 0)
        goto storage_failure;
    sqlite3_bind_int64(st, 1, now);
    if (power_step_done(st) != 0 || power_meta_bump(db, now) != 0 ||
        power_sql_exec(db, "COMMIT") != 0)
        goto storage_failure;
    sqlite3_finalize(st); st = NULL;
    sqlite3_close(db); db = NULL;

    dispatch_rc = power_exec_fixed(schedule.event, action_id, 1, &exec_result);
    if (dispatch_rc != 0) {
        int64_t failed_at = power_now_s();
        if (power_db_open(&db) == 0 && power_sql_exec(db, "BEGIN IMMEDIATE") == 0 &&
            power_action_lock_finish(db, action_id, "failed", "dispatch_failed", failed_at) == 0 &&
            power_sql_exec(db, "COMMIT") == 0) {
            sqlite3_close(db);
            return power_error("action_dispatch_failed", "detached_dispatch_could_not_start");
        }
        if (db) {
            (void)power_sql_exec(db, "ROLLBACK");
            sqlite3_close(db);
        }
        return power_error("storage_unavailable", "scheduler_dispatch_result_persist_failed");
    }
    if (power_action_mark_dispatched(action_id, exec_result.dispatcher_pid) != 0) {
        power_exec_cancel(&exec_result);
        return power_error("storage_unavailable", "scheduler_dispatch_state_failed");
    }
    if (power_exec_release(&exec_result) != 0) {
        int64_t failed_at = power_now_s();

        if (power_db_open(&db) == 0 && power_sql_exec(db, "BEGIN IMMEDIATE") == 0 &&
            power_action_lock_finish(db, action_id, "failed", "dispatch_release_failed",
                                     failed_at) == 0 &&
            power_sql_exec(db, "COMMIT") == 0)
            sqlite3_close(db);
        else if (db) {
            (void)power_sql_exec(db, "ROLLBACK");
            sqlite3_close(db);
        }
        return power_error("action_dispatch_failed", "detached_dispatch_release_failed");
    }
    data = json_object_new_object();
    json_object_object_add(data, "accepted", json_object_new_boolean(1));
    json_object_object_add(data, "dispatched", json_object_new_boolean(1));
    json_object_object_add(data, "executed", json_object_new_boolean(0));
    json_object_object_add(data, "action_id", json_object_new_string(action_id));
    json_object_object_add(data, "schedule_id", json_object_new_string(schedule.id));
    json_object_object_add(data, "action", json_object_new_string(schedule.event));
    json_object_object_add(data, "result", json_object_new_string("dispatched"));
    json_object_object_add(data, "next_run_at", json_object_new_int64(next_run));
    json_object_object_add(data, "archived", json_object_new_boolean(!strcmp(schedule.period, "once")));
    json_object_object_add(data, "dispatch_delay_seconds",
                           json_object_new_int(POWER_DISPATCH_DELAY_SECONDS));
    return power_success(data);
storage_failure:
    if (st) sqlite3_finalize(st);
    (void)power_sql_exec(db, "ROLLBACK");
    sqlite3_close(db);
    return power_error("storage_unavailable", "scheduler_claim_or_advance_failed");
}
