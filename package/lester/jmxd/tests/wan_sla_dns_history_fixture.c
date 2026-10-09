// SPDX-License-Identifier: GPL-2.0-or-later
/* CLI adapter around production history functions and an extracted HTTP branch. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flowd/wan_sla_history.h"
#include "webd/api/api_request.h"

static const char *history_path;
static unsigned ubus_calls;
static struct json_object *forwarded;

static void sqlite_diagnostic(void *context, int code, const char *message)
{
    (void)context;
    fprintf(stderr, "sqlite(%d): %s\n", code, message);
}

static struct json_object *field(struct json_object *o, const char *name)
{
    struct json_object *value = NULL;
    if (o) json_object_object_get_ex(o, name, &value);
    return value;
}

/* Transport is stubbed; all history parsing, SQL and URL decoding are production. */
static struct json_object *app_ubus_object_or_error(const char *object,
                                                   const char *method,
                                                   struct json_object *body)
{
    ubus_calls++;
    if (strcmp(object, "dreamingwrt.flowd") || strcmp(method, "wan_sla_history")) {
        fprintf(stderr, "unexpected ubus destination: %s.%s\n", object, method);
        exit(3);
    }
    forwarded = json_object_get(body);
    return wan_sla_history_query(history_path, body);
}

static int app_routed_http_status(struct json_object *body, int fallback)
{
    struct json_object *status = field(body, "http_status");
    return status ? json_object_get_int(status) : fallback;
}

static struct json_object *webd_error(const char *code, const char *message,
                                     const char *location, const char *origin)
{
    struct json_object *out = json_object_new_object();
    (void)message; (void)location; (void)origin;
    json_object_object_add(out, "ok", json_object_new_boolean(0));
    json_object_object_add(out, "error", json_object_new_string(code));
    return out;
}

static struct json_object *http_request(const char *method, const char *query,
                                        struct json_object *body_json)
{
    const struct { const char *path, *method, *query; } req = {
        "/api/v1/network/wan-slas/dns-history", method, query
    };
    struct json_object *resp = NULL, *out = json_object_new_object();
    int status = 200;

    if (0) {}
#include "wan_sla_dns_http_branch.inc"
    else {
        status = 404;
        resp = webd_error("not_found", "", "", "");
    }
    json_object_object_add(out, "status", json_object_new_int(status));
    json_object_object_add(out, "ubus_calls", json_object_new_int((int)ubus_calls));
    json_object_object_add(out, "forwarded", forwarded);
    json_object_object_add(out, "response", resp);
    return out;
}

int main(int argc, char **argv)
{
    sqlite3 *db = NULL;
    struct json_object *input = NULL, *out = NULL;
    int rc = 0;

    if (getenv("DNS_FIXTURE_SQLITE_LOG"))
        sqlite3_config(SQLITE_CONFIG_LOG, sqlite_diagnostic, NULL);

    if (argc < 3) {
        fprintf(stderr, "usage: fixture init|record|query|restore|delete-state|http DB [args]\n");
        return 2;
    }
    history_path = argv[2];
    if (!strcmp(argv[1], "http")) {
        if (argc < 5) return 2;
        input = argc > 5 ? json_tokener_parse(argv[5]) : json_object_new_object();
        if (!input) return 2;
        out = http_request(argv[3], argv[4], input);
    } else if (!strcmp(argv[1], "query")) {
        if (argc != 4 || !(input = json_tokener_parse(argv[3]))) return 2;
        out = wan_sla_history_query(history_path, input);
    } else {
        if (wan_sla_history_open(history_path, &db)) return 3;
        if (!strcmp(argv[1], "record")) {
            if (argc != 4 || !(input = json_tokener_parse(argv[3]))) return 2;
            rc = wan_sla_history_record(db, field(input, "runtime"),
                                       field(input, "samples"), field(input, "events"));
            out = json_object_new_int(rc);
        } else if (!strcmp(argv[1], "restore")) {
            if (argc != 4) return 2;
            out = wan_sla_history_restore(db, argv[3]);
        } else if (!strcmp(argv[1], "delete-state")) {
            sqlite3_stmt *statement = NULL;
            if (argc != 4) return 2;
            if (sqlite3_prepare_v2(db, "DELETE FROM flowd_wan_sla_state WHERE sla_id=?1",
                                   -1, &statement, NULL) != SQLITE_OK) return 3;
            sqlite3_bind_text(statement, 1, argv[3], -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(statement) == SQLITE_DONE ? 0 : -1;
            sqlite3_finalize(statement);
            out = json_object_new_int(rc);
        } else if (!strcmp(argv[1], "init")) out = json_object_new_boolean(1);
        else return 2;
        sqlite3_close(db);
    }
    puts(out ? json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN) : "null");
    if (out) json_object_put(out);
    if (input) json_object_put(input);
    return rc ? 3 : 0;
}
