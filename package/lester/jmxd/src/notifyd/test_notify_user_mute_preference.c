/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Executable contract test for the per-user notification mute preference
 * (Handoff: Front-to-Backend-notification-user-mute-preference).
 *
 * This runs the real notifyd code against real SQLite files rather than
 * grepping the source: the acceptance criteria are about stored state and
 * delivery outcome, and a source assertion cannot tell whether a timed mute
 * actually lapses or whether an outbox row really lands in `suppressed`.
 *
 * notifyd_delivery.c is #included rather than linked so the recipient
 * resolution path, which is static, can be exercised directly. The matching
 * object file must therefore be left out of this binary's link line.
 */
#include "notifyd_delivery.c"

#include <assert.h>
#include <libgen.h>

static int g_checks;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        g_checks++;                                                            \
        if (!(cond)) {                                                         \
            fprintf(stderr, "FAIL %s (%s:%d)\n", (label), __FILE__, __LINE__); \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static struct json_object *obj_from(const char *json)
{
    struct json_object *o = json_tokener_parse(json);

    assert(o && json_object_is_type(o, json_type_object));
    return o;
}

static const char *str_of(struct json_object *o, const char *key)
{
    return notifyd_json_str(o, key, "<missing>");
}

static void exec_or_die(sqlite3 *db, const char *sql)
{
    char *err = NULL;

    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql failed: %s (%s)\n", err ? err : "?", sql);
        exit(1);
    }
}

/* webd owns web_users, so notifyd_db_init() does not create it. The mute
 * feature reads it for eligibility and for reverse-resolving addresses. */
static void seed_directory(void)
{
    exec_or_die(g_notify_config_db,
        "CREATE TABLE IF NOT EXISTS web_users ("
        " username TEXT PRIMARY KEY, email TEXT NOT NULL DEFAULT '',"
        " role TEXT NOT NULL DEFAULT 'viewer', status TEXT NOT NULL DEFAULT 'enabled')");
    exec_or_die(g_notify_config_db,
        "INSERT OR REPLACE INTO web_users(username,email,role,status) VALUES"
        " ('lester','lester@example.test','owner','enabled'),"
        " ('quiet','quiet@example.test','admin','enabled'),"
        " ('loud','loud@example.test','admin','enabled'),"
        " ('shareda','ops@example.test','admin','enabled'),"
        " ('sharedb','ops@example.test','admin','enabled'),"
        " ('retired','retired@example.test','viewer','disabled')");
    exec_or_die(g_notify_config_db,
        "INSERT OR REPLACE INTO notifyd_channels(id,name,type,enabled,options_json,created_at,updated_at) VALUES"
        " ('mail','Mail','email',1,'{}',0,0),"
        " ('mail2','Mail 2','email',1,'{}',0,0),"
        " ('hook','Hook','webhook',1,'{}',0,0)");
}

static struct json_object *pref_get(const char *username)
{
    struct json_object *body = json_object_new_object();
    struct json_object *resp;

    json_object_object_add(body, "username", json_object_new_string(username));
    resp = notifyd_preferences_get(body);
    json_object_put(body);
    return resp;
}

static struct json_object *pref_set(const char *json)
{
    struct json_object *body = obj_from(json);
    struct json_object *resp = notifyd_preferences_update(body);

    json_object_put(body);
    return resp;
}

/* Criterion 1: an untouched account reads as explicitly not muted. */
static void test_default_is_unmuted(void)
{
    struct json_object *resp = pref_get("lester");

    CHECK(notifyd_json_bool(resp, "ok", 0), "default ok");
    CHECK(!notifyd_json_bool(resp, "muted", 1), "default not muted");
    CHECK(!notifyd_json_bool(resp, "stored", 1), "default not stored");
    CHECK(!strcmp(str_of(resp, "mute_mode"), "off"), "default mode off");
    CHECK(notifyd_json_i64(resp, "muted_until", -1) == 0, "default until 0");
    CHECK(notifyd_json_i64(resp, "updated_at", -1) == 0, "default revision 0");
    CHECK(!strcmp(str_of(resp, "username"), "lester"), "default echoes username");
    json_object_put(resp);
}

/* Criterion 2: permanent, timed and cleared mutes all save and read back. */
static void test_permanent_timed_and_clear_roundtrip(void)
{
    int64_t now = notifyd_now_s();
    struct json_object *resp;
    int64_t rev_permanent, rev_timed;
    char buf[256];

    resp = pref_set("{\"username\":\"lester\",\"muted\":true}");
    CHECK(notifyd_json_bool(resp, "ok", 0), "permanent save ok");
    CHECK(notifyd_json_bool(resp, "muted", 0), "permanent muted");
    CHECK(!strcmp(str_of(resp, "mute_mode"), "permanent"), "permanent mode");
    CHECK(notifyd_json_i64(resp, "muted_until", -1) == 0, "permanent has no expiry");
    rev_permanent = notifyd_json_i64(resp, "updated_at", 0);
    CHECK(rev_permanent >= now, "permanent revision advanced");
    json_object_put(resp);

    resp = pref_get("lester");
    CHECK(notifyd_json_bool(resp, "muted", 0), "permanent readback muted");
    CHECK(notifyd_json_bool(resp, "stored", 0), "permanent readback stored");
    CHECK(notifyd_json_i64(resp, "updated_at", 0) == rev_permanent,
          "permanent readback revision matches");
    json_object_put(resp);

    snprintf(buf, sizeof(buf),
             "{\"username\":\"lester\",\"muted\":true,\"muted_until\":%lld,"
             "\"expected_updated_at\":%lld}",
             (long long)(now + 3600), (long long)rev_permanent);
    resp = pref_set(buf);
    CHECK(notifyd_json_bool(resp, "ok", 0), "timed save ok");
    CHECK(!strcmp(str_of(resp, "mute_mode"), "until"), "timed mode");
    CHECK(notifyd_json_i64(resp, "muted_until", 0) == now + 3600, "timed expiry kept");
    CHECK(!notifyd_json_bool(resp, "expired", 1), "timed not yet expired");
    rev_timed = notifyd_json_i64(resp, "updated_at", 0);
    CHECK(rev_timed > rev_permanent, "timed revision advanced");
    json_object_put(resp);

    snprintf(buf, sizeof(buf),
             "{\"username\":\"lester\",\"muted\":false,\"expected_updated_at\":%lld}",
             (long long)rev_timed);
    resp = pref_set(buf);
    CHECK(notifyd_json_bool(resp, "ok", 0), "unmute ok");
    CHECK(!notifyd_json_bool(resp, "muted", 1), "unmute clears muted");
    /* The old window must not survive an unmute, or the next mute silently
     * inherits a deadline the user did not pick this time. */
    CHECK(notifyd_json_i64(resp, "muted_until", -1) == 0, "unmute clears expiry");
    CHECK(!strcmp(str_of(resp, "mute_mode"), "off"), "unmute mode off");
    json_object_put(resp);
}

/* Criterion 4: expiry is evaluated on read, with no timer and no client clock. */
static void test_timed_mute_lapses_without_a_timer(void)
{
    int64_t now = notifyd_now_s();
    struct json_object *resp;
    char sql[256];

    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO notifyd_user_preferences"
             "(username,muted,muted_until,channel_ids_json,created_at,updated_at)"
             " VALUES('quiet',1,%lld,'[]',%lld,%lld)",
             (long long)(now - 60), (long long)(now - 7200), (long long)(now - 120));
    exec_or_die(g_notify_config_db, sql);

    resp = pref_get("quiet");
    CHECK(!notifyd_json_bool(resp, "muted", 1), "lapsed mute is not effective");
    CHECK(notifyd_json_bool(resp, "muted_stored", 0), "lapsed mute keeps stored intent");
    CHECK(notifyd_json_bool(resp, "expired", 0), "lapsed mute reports expired");
    CHECK(!strcmp(str_of(resp, "mute_mode"), "off"), "lapsed mute mode off");
    json_object_put(resp);
    CHECK(!notifyd_user_mute_active("quiet", "mail"),
          "lapsed mute does not suppress delivery");

    exec_or_die(g_notify_config_db,
        "DELETE FROM notifyd_user_preferences WHERE username='quiet'");
}

static void test_revision_guard(void)
{
    struct json_object *resp;
    int64_t current;

    resp = pref_set("{\"username\":\"lester\",\"muted\":true,\"expected_updated_at\":1}");
    CHECK(!notifyd_json_bool(resp, "ok", 1), "stale revision rejected");
    CHECK(!strcmp(str_of(resp, "error"),
                  "notification_preference_revision_conflict"), "conflict code");
    CHECK(!strcmp(str_of(resp, "field"), "expected_updated_at"), "conflict field");
    current = notifyd_json_i64(resp, "current_updated_at", -1);
    CHECK(current > 1, "conflict reports the current revision");
    json_object_put(resp);

    /* Omitting the guard entirely still works, so a first write does not need
     * a revision it cannot know yet. */
    resp = pref_set("{\"username\":\"lester\",\"muted\":false}");
    CHECK(notifyd_json_bool(resp, "ok", 0), "guardless write allowed");
    json_object_put(resp);
}

static void test_channel_scope_validation(void)
{
    struct json_object *resp;

    resp = pref_set("{\"username\":\"lester\",\"muted\":true,\"channel_ids\":[\"mail\"]}");
    CHECK(notifyd_json_bool(resp, "ok", 0), "email channel accepted");
    CHECK(!strcmp(str_of(resp, "scope"), "channels"), "scope reports channels");
    json_object_put(resp);

    /* A webhook or noop channel is one shared destination, so a personal mute
     * there would silence everybody else too. */
    resp = pref_set("{\"username\":\"lester\",\"muted\":true,\"channel_ids\":[\"hook\"]}");
    CHECK(!notifyd_json_bool(resp, "ok", 1), "webhook channel rejected");
    CHECK(!strcmp(str_of(resp, "error"),
                  "notification_preference_channel_invalid"), "channel error code");
    CHECK(!strcmp(str_of(resp, "reason"), "channel_type_not_user_addressable"),
          "channel error reason");
    json_object_put(resp);

    resp = pref_set("{\"username\":\"lester\",\"muted\":true,\"channel_ids\":[\"ghost\"]}");
    CHECK(!strcmp(str_of(resp, "error"),
                  "notification_preference_channel_invalid"), "unknown channel rejected");
    json_object_put(resp);

    /* Omitting channel_ids must keep the stored scope rather than widening it. */
    resp = pref_set("{\"username\":\"lester\",\"muted\":true}");
    CHECK(notifyd_json_bool(resp, "ok", 0), "scope-preserving write ok");
    CHECK(!strcmp(str_of(resp, "scope"), "channels"), "omitted channel_ids keeps scope");
    json_object_put(resp);

    resp = pref_set("{\"username\":\"lester\",\"muted\":true,\"channel_ids\":[]}");
    CHECK(!strcmp(str_of(resp, "scope"), "all_channels"), "empty list means all channels");
    json_object_put(resp);
}

static void test_input_and_identity_rejections(void)
{
    struct json_object *resp;
    char buf[256];

    resp = pref_set("{\"username\":\"lester\"}");
    CHECK(!strcmp(str_of(resp, "error"), "notification_preference_invalid"),
          "missing muted rejected");
    CHECK(!strcmp(str_of(resp, "reason"), "field_required"), "missing muted reason");
    json_object_put(resp);

    resp = pref_set("{\"username\":\"lester\",\"muted\":\"yes\"}");
    CHECK(!strcmp(str_of(resp, "reason"), "boolean_required"), "muted must be boolean");
    json_object_put(resp);

    snprintf(buf, sizeof(buf),
             "{\"username\":\"lester\",\"muted\":true,\"muted_until\":%lld}",
             (long long)(notifyd_now_s() - 10));
    resp = pref_set(buf);
    CHECK(!strcmp(str_of(resp, "reason"), "already_elapsed"), "past expiry rejected");
    json_object_put(resp);

    snprintf(buf, sizeof(buf),
             "{\"username\":\"lester\",\"muted\":true,\"muted_until\":%lld}",
             (long long)(notifyd_now_s() + NOTIFYD_USER_MUTE_MAX_DURATION_S + 60));
    resp = pref_set(buf);
    CHECK(!strcmp(str_of(resp, "reason"), "exceeds_max_duration"), "over-long mute rejected");
    json_object_put(resp);

    /* An identity string is not a username: notifyd must not accept the raw
     * "web:<user>" form webd carries internally. */
    resp = pref_set("{\"username\":\"web:lester\",\"muted\":true}");
    CHECK(!strcmp(str_of(resp, "error"), "notification_preference_forbidden"),
          "identity string rejected");
    json_object_put(resp);

    resp = pref_set("{\"username\":\"nobody\",\"muted\":true}");
    CHECK(!strcmp(str_of(resp, "error"), "notification_preference_forbidden"),
          "unknown user rejected");
    CHECK(!strcmp(str_of(resp, "reason"), "user_not_eligible"), "unknown user reason");
    json_object_put(resp);

    resp = pref_set("{\"username\":\"retired\",\"muted\":true}");
    CHECK(!strcmp(str_of(resp, "error"), "notification_preference_forbidden"),
          "disabled user rejected");
    json_object_put(resp);
}

static void test_mute_active_scope(void)
{
    struct json_object *resp;

    resp = pref_set("{\"username\":\"quiet\",\"muted\":true,\"channel_ids\":[]}");
    json_object_put(resp);
    CHECK(notifyd_user_mute_active("quiet", "mail"), "global mute covers mail");
    CHECK(notifyd_user_mute_active("quiet", "mail2"), "global mute covers mail2");

    resp = pref_set("{\"username\":\"quiet\",\"muted\":true,\"channel_ids\":[\"mail\"]}");
    json_object_put(resp);
    CHECK(notifyd_user_mute_active("quiet", "mail"), "scoped mute covers named channel");
    CHECK(!notifyd_user_mute_active("quiet", "mail2"),
          "scoped mute leaves other channels alone");
    CHECK(!notifyd_user_mute_active("loud", "mail"), "unmuted user unaffected");
}

/*
 * Criterion 3: one recipient's mute must not silence the others.
 */
static void test_only_the_muting_recipient_is_dropped(void)
{
    struct notifyd_outbox_item item;
    struct json_object *options = json_object_new_object();
    char recipients[64][256];
    char warning[256];
    int count = 0;
    int suppressed = -1;
    int resolved;
    struct json_object *resp;

    /* Start from a known audience: an earlier case left `lester` muted, and a
     * suppression count is only meaningful against a fixed set of recipients. */
    exec_or_die(g_notify_config_db, "DELETE FROM notifyd_user_preferences");
    resp = pref_set("{\"username\":\"quiet\",\"muted\":true,\"channel_ids\":[]}");
    json_object_put(resp);

    memset(&item, 0, sizeof(item));
    snprintf(item.id, sizeof(item.id), "%s", "ob-test-1");
    snprintf(item.channel_id, sizeof(item.channel_id), "%s", "mail");
    snprintf(item.delivery_options_json, sizeof(item.delivery_options_json), "%s",
             "{\"receivers\":{\"mode\":\"users\",\"user_ids\":[\"quiet\",\"loud\"]}}");

    resolved = notifyd_mail_resolve_route_recipients(&item, options, recipients,
                                                    &count, warning, sizeof(warning),
                                                    &suppressed);
    CHECK(resolved, "mixed audience still resolves");
    CHECK(count == 1, "exactly one recipient survives");
    CHECK(!strcmp(recipients[0], "loud@example.test"), "the unmuted user is kept");
    CHECK(suppressed == 1, "the muted user is counted as suppressed");
    CHECK(!warning[0], "a mute is not a resolution warning");

    /* Everyone muted is a suppression, not an unresolved-recipient failure. */
    snprintf(item.delivery_options_json, sizeof(item.delivery_options_json), "%s",
             "{\"receivers\":{\"mode\":\"users\",\"user_ids\":[\"quiet\"]}}");
    count = 0;
    suppressed = -1;
    resolved = notifyd_mail_resolve_route_recipients(&item, options, recipients,
                                                     &count, warning, sizeof(warning),
                                                     &suppressed);
    CHECK(!resolved && count == 0, "all-muted audience resolves to nobody");
    CHECK(suppressed == 1, "all-muted audience reports the suppression");
    CHECK(!warning[0], "all-muted audience raises no warning");

    /* admins mode resolves through a different query and must honour the mute
     * the same way. */
    snprintf(item.delivery_options_json, sizeof(item.delivery_options_json), "%s",
             "{\"receivers\":{\"mode\":\"admins\"}}");
    count = 0;
    suppressed = -1;
    resolved = notifyd_mail_resolve_route_recipients(&item, options, recipients,
                                                     &count, warning, sizeof(warning),
                                                     &suppressed);
    CHECK(resolved, "admins mode still has recipients");
    CHECK(suppressed == 1, "admins mode drops the muted admin");
    {
        int i, found_quiet = 0, found_loud = 0;

        for (i = 0; i < count; i++) {
            if (!strcmp(recipients[i], "quiet@example.test")) found_quiet = 1;
            if (!strcmp(recipients[i], "loud@example.test")) found_loud = 1;
        }
        CHECK(!found_quiet, "admins mode excludes the muted address");
        CHECK(found_loud, "admins mode keeps the unmuted address");
    }

    /*
     * A shared mailbox claimed by two accounts must not be silenced when only
     * one of them mutes: the other still expects mail at that address.
     */
    resp = pref_set("{\"username\":\"shareda\",\"muted\":true,\"channel_ids\":[]}");
    json_object_put(resp);
    snprintf(item.delivery_options_json, sizeof(item.delivery_options_json), "%s",
             "{\"receivers\":{\"mode\":\"emails\",\"recipients\":[\"ops@example.test\"]}}");
    count = 0;
    suppressed = -1;
    resolved = notifyd_mail_resolve_route_recipients(&item, options, recipients,
                                                     &count, warning, sizeof(warning),
                                                     &suppressed);
    CHECK(resolved && count == 1, "ambiguous shared address is still delivered");
    CHECK(suppressed == 0, "ambiguous shared address is not treated as muted");

    /* An address that belongs to exactly one account does honour that mute. */
    snprintf(item.delivery_options_json, sizeof(item.delivery_options_json), "%s",
             "{\"receivers\":{\"mode\":\"emails\",\"recipients\":"
             "[\"quiet@example.test\",\"loud@example.test\"]}}");
    count = 0;
    suppressed = -1;
    resolved = notifyd_mail_resolve_route_recipients(&item, options, recipients,
                                                     &count, warning, sizeof(warning),
                                                     &suppressed);
    CHECK(resolved && count == 1, "unambiguous muted address is dropped");
    CHECK(!strcmp(recipients[0], "loud@example.test"), "the other address survives");
    CHECK(suppressed == 1, "unambiguous muted address counts as suppressed");

    json_object_put(options);
    exec_or_die(g_notify_config_db,
        "DELETE FROM notifyd_user_preferences WHERE username IN ('quiet','shareda')");
}

/*
 * Suppression must be a terminal outcome that neither burns a retry nor reads
 * as a service fault.
 */
static void test_suppressed_outbox_bookkeeping(void)
{
    struct notifyd_outbox_item item;
    sqlite3_stmt *st;
    struct json_object *status;
    char state[32] = "";
    char last_error[256] = "";
    char last_warning[256] = "";
    int attempts = -1;

    memset(&item, 0, sizeof(item));
    snprintf(item.id, sizeof(item.id), "%s", "ob-suppress-1");
    snprintf(item.channel_id, sizeof(item.channel_id), "%s", "mail");
    item.attempts = 1;
    item.max_attempts = 3;

    exec_or_die(g_notify_db,
        "INSERT OR REPLACE INTO notify_outbox"
        "(id,channel_id,payload_json,state,attempts,max_attempts,next_attempt_at,created_at,updated_at)"
        " VALUES('ob-suppress-1','mail','{}','pending',1,3,0,1,1)");

    CHECK(notifyd_mark_delivery_result(&item, NOTIFYD_DELIVERY_SUPPRESSED, 0,
                                       "preference_suppressed_all_recipients:1",
                                       12, 1),
          "suppressed result saves");

    st = notifyd_prepare("SELECT state,attempts,last_error,last_warning "
                         "FROM notify_outbox WHERE id='ob-suppress-1'");
    CHECK(st != NULL, "outbox row readable");
    if (sqlite3_step(st) == SQLITE_ROW) {
        snprintf(state, sizeof(state), "%s", notifyd_sqlite_text(st, 0, ""));
        attempts = sqlite3_column_int(st, 1);
        snprintf(last_error, sizeof(last_error), "%s", notifyd_sqlite_text(st, 2, ""));
        snprintf(last_warning, sizeof(last_warning), "%s", notifyd_sqlite_text(st, 3, ""));
    }
    sqlite3_finalize(st);

    CHECK(!strcmp(state, "suppressed"), "state is suppressed");
    CHECK(attempts == 1, "suppression does not consume a retry attempt");
    CHECK(!last_error[0], "suppression leaves last_error clear");
    CHECK(strstr(last_warning, "preference_suppressed") != NULL,
          "suppression detail lands in last_warning");
    CHECK(!strstr(last_warning, "@"), "suppression detail carries no address");

    /* A suppressed row is a real outcome but must not make notifyd degraded. */
    status = notifyd_status_json();
    CHECK(notifyd_json_int(status, "suppressed", -1) == 1, "status counts suppressed");
    CHECK(notifyd_json_int(status, "failed", -1) == 0, "suppressed is not failed");
    CHECK(!notifyd_json_bool(status, "degraded", 1), "suppressed does not degrade");
    json_object_put(status);

    /* And the audit row records it as its own outcome rather than a failure. */
    st = notifyd_prepare("SELECT ok,outcome,suppressed_recipients,error,warning "
                         "FROM notify_deliveries WHERE outbox_id='ob-suppress-1'");
    CHECK(st != NULL, "delivery row readable");
    if (sqlite3_step(st) == SQLITE_ROW) {
        CHECK(sqlite3_column_int(st, 0) == 1, "suppressed delivery is not ok=0");
        CHECK(!strcmp(notifyd_sqlite_text(st, 1, ""), "suppressed"), "outcome recorded");
        CHECK(sqlite3_column_int(st, 2) == 1, "suppressed recipient count recorded");
        CHECK(!notifyd_sqlite_text(st, 3, "")[0], "suppressed delivery has no error");
        CHECK(strstr(notifyd_sqlite_text(st, 4, ""), "preference_suppressed") != NULL,
              "suppressed delivery carries the warning");
    } else {
        CHECK(0, "delivery row present");
    }
    sqlite3_finalize(st);

    /* A partially suppressed success keeps only a count, never an address. */
    snprintf(item.id, sizeof(item.id), "%s", "ob-partial-1");
    item.attempts = 0;
    exec_or_die(g_notify_db,
        "INSERT OR REPLACE INTO notify_outbox"
        "(id,channel_id,payload_json,state,attempts,max_attempts,next_attempt_at,created_at,updated_at)"
        " VALUES('ob-partial-1','mail','{}','pending',0,3,0,1,1)");
    CHECK(notifyd_mark_delivery_result(&item, NOTIFYD_DELIVERY_OK, 0, "", 8, 2),
          "partial suppression saves");
    st = notifyd_prepare("SELECT state,attempts,last_warning "
                         "FROM notify_outbox WHERE id='ob-partial-1'");
    if (st && sqlite3_step(st) == SQLITE_ROW) {
        CHECK(!strcmp(notifyd_sqlite_text(st, 0, ""), "delivered"),
              "partial suppression still delivers");
        CHECK(sqlite3_column_int(st, 1) == 1, "partial suppression consumes an attempt");
        CHECK(!strcmp(notifyd_sqlite_text(st, 2, ""),
                      "preference_suppressed_recipients:2"),
              "partial suppression records the count");
    } else {
        CHECK(0, "partial row present");
    }
    if (st) sqlite3_finalize(st);

    /* Criterion 5: suppressed rows are not due for delivery, so a mute cannot
     * turn into a redelivery loop. */
    st = notifyd_prepare("SELECT COUNT(*) FROM notify_outbox "
                         "WHERE state IN ('pending','retry') AND id='ob-suppress-1'");
    if (st && sqlite3_step(st) == SQLITE_ROW)
        CHECK(sqlite3_column_int(st, 0) == 0, "suppressed row is not redelivered");
    if (st) sqlite3_finalize(st);

    /* But an operator can still requeue it, which is how a user who unmutes
     * gets the notification they asked to see again. */
    {
        struct json_object *body = obj_from("{\"id\":\"ob-suppress-1\"}");
        struct json_object *resp = notifyd_outbox_retry(body);

        CHECK(notifyd_json_bool(resp, "ok", 0), "suppressed row can be retried");
        json_object_put(resp);
        json_object_put(body);
    }
    {
        struct json_object *body = obj_from("{\"state\":\"suppressed\"}");
        struct json_object *resp = notifyd_outbox_list(body);

        CHECK(notifyd_json_bool(resp, "ok", 0), "suppressed is a listable state");
        json_object_put(resp);
        json_object_put(body);
    }
}

/* Criterion 5: none of this touches the global switch or route/channel state. */
static void test_global_semantics_untouched(void)
{
    struct json_object *settings;
    struct json_object *resp;
    sqlite3_stmt *st;
    int enabled_before = -1, enabled_after = -1;

    settings = notifyd_settings_json();
    enabled_before = notifyd_json_bool(settings, "enabled", -1);
    json_object_put(settings);

    resp = pref_set("{\"username\":\"lester\",\"muted\":true,\"channel_ids\":[]}");
    json_object_put(resp);

    settings = notifyd_settings_json();
    enabled_after = notifyd_json_bool(settings, "enabled", -1);
    json_object_put(settings);
    CHECK(enabled_before == enabled_after, "global enabled unchanged");

    st = notifyd_config_prepare("SELECT COUNT(*) FROM notifyd_channels WHERE enabled=0");
    if (st && sqlite3_step(st) == SQLITE_ROW)
        CHECK(sqlite3_column_int(st, 0) == 0, "no channel was disabled");
    if (st) sqlite3_finalize(st);

    /* The preference lives in its own table, not in settings/route/channel
     * options, which the handoff forbids. */
    st = notifyd_config_prepare(
        "SELECT COUNT(*) FROM notifyd_user_preferences WHERE username='lester'");
    if (st && sqlite3_step(st) == SQLITE_ROW)
        CHECK(sqlite3_column_int(st, 0) == 1, "preference stored in its own table");
    if (st) sqlite3_finalize(st);

    settings = notifyd_settings_json();
    CHECK(!strstr(json_object_to_json_string(settings), "muted"),
          "settings payload carries no mute state");
    json_object_put(settings);
}

static void test_capability_is_advertised(void)
{
    struct json_object *status = notifyd_status_json();
    struct json_object *caps = NULL, *mute = NULL;

    CHECK(json_object_object_get_ex(status, "capabilities", &caps) && caps,
          "status has capabilities");
    CHECK(json_object_object_get_ex(caps, "user_mute_preference", &mute) && mute,
          "capability advertised");
    CHECK(notifyd_json_int(mute, "max_duration_s", 0) == NOTIFYD_USER_MUTE_MAX_DURATION_S,
          "capability states the max duration");
    CHECK(notifyd_json_bool(mute, "revision_guard", 0), "capability states revision guard");
    CHECK(notifyd_json_bool(caps, "outbox_suppressed_state", 0),
          "capability states the suppressed outbox state");
    json_object_put(status);
}

int main(void)
{
    if (notifyd_db_init() != 0) {
        fprintf(stderr, "notifyd_db_init failed; run under a sandbox that provides "
                        "a writable /etc/dreamingwrt\n");
        return 2;
    }
    seed_directory();

    test_default_is_unmuted();
    test_permanent_timed_and_clear_roundtrip();
    test_timed_mute_lapses_without_a_timer();
    test_revision_guard();
    test_channel_scope_validation();
    test_input_and_identity_rejections();
    test_mute_active_scope();
    test_only_the_muting_recipient_is_dropped();
    test_suppressed_outbox_bookkeeping();
    test_global_semantics_untouched();
    test_capability_is_advertised();

    notifyd_db_close();
    printf("ok: %d checks passed\n", g_checks);
    return 0;
}
