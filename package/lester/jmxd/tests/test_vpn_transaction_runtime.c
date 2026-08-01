#include <assert.h>
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>

#include "../src/webd/webd_vpn_aggregate.h"

enum test_mode {
    MODE_SUCCESS,
    MODE_SAVE_FAIL,
    MODE_SAVE_MISMATCH,
    MODE_APPLY_FAIL_ROLLBACK_OK,
    MODE_RUNTIME_FAIL_ROLLBACK_OK,
    MODE_ROLLBACK_FAIL,
};

struct fixture {
    enum test_mode mode;
    struct json_object *current;
    int save_calls;
    int apply_calls;
    int runtime_calls;
};

static struct json_object *result_boolean(const char *key, int value)
{
    struct json_object *result = json_object_new_object();

    json_object_object_add(result, key, json_object_new_boolean(value));
    return result;
}

static struct json_object *config_get(void *opaque)
{
    struct fixture *fixture = opaque;

    return fixture->current ? json_object_get(fixture->current) : NULL;
}

static struct json_object *config_save(struct json_object *config, void *opaque)
{
    struct fixture *fixture = opaque;
    struct json_object *result;

    fixture->save_calls++;
    if (fixture->mode == MODE_SAVE_FAIL && fixture->save_calls == 1)
        return result_boolean("saved", 0);
    if (fixture->current)
        json_object_put(fixture->current);
    if (fixture->mode == MODE_SAVE_MISMATCH && fixture->save_calls == 1)
        fixture->current = json_tokener_parse("{\"revision\":99}");
    else
        fixture->current = json_object_get(config);
    result = result_boolean("saved", 1);
    return result;
}

static struct json_object *config_apply(struct json_object *config, void *opaque)
{
    struct fixture *fixture = opaque;
    struct json_object *result = json_object_new_object();
    struct json_object *revision = NULL;
    int applied = 1;

    fixture->apply_calls++;
    if ((fixture->mode == MODE_APPLY_FAIL_ROLLBACK_OK ||
         fixture->mode == MODE_ROLLBACK_FAIL) && fixture->apply_calls == 1)
        applied = 0;
    if (fixture->mode == MODE_ROLLBACK_FAIL && fixture->apply_calls > 1)
        applied = 0;
    json_object_object_add(result, "applied", json_object_new_boolean(applied));
    json_object_object_add(result, "health_checked", json_object_new_boolean(applied));
    json_object_object_add(result, "healthy", json_object_new_boolean(applied));
    if (json_object_object_get_ex(config, "revision", &revision) && revision)
        json_object_object_add(result, "generation", json_object_get(revision));
    return result;
}

static struct json_object *runtime_get(void *opaque)
{
    struct fixture *fixture = opaque;
    struct json_object *runtime = json_object_new_object();
    struct json_object *revision = NULL;
    int generation = 0;

    fixture->runtime_calls++;
    if (fixture->current &&
        json_object_object_get_ex(fixture->current, "revision", &revision) &&
        revision)
        generation = json_object_get_int(revision);
    if (fixture->mode == MODE_RUNTIME_FAIL_ROLLBACK_OK &&
        fixture->runtime_calls == 1)
        generation = 999;
    json_object_object_add(runtime, "generation", json_object_new_int(generation));
    return runtime;
}

static int boolean(struct json_object *object, const char *key)
{
    struct json_object *value = NULL;

    assert(json_object_object_get_ex(object, key, &value));
    return json_object_get_boolean(value);
}

static const char *string(struct json_object *object, const char *key)
{
    struct json_object *value = NULL;

    assert(json_object_object_get_ex(object, key, &value));
    return json_object_get_string(value);
}

static void run_case(enum test_mode mode, const char *expected_state,
                     const char *expected_error, int expected_revision,
                     int rollback_attempted, int rollback_succeeded)
{
    struct webd_vpn_transaction_ops ops = {
        .config_get = config_get,
        .config_save = config_save,
        .config_apply = config_apply,
        .runtime_get = runtime_get,
    };
    struct fixture fixture = {
        .mode = mode,
        .current = json_tokener_parse("{\"revision\":1}"),
    };
    struct json_object *candidate = json_tokener_parse("{\"revision\":2}");
    struct json_object *response =
        webd_vpn_transaction_execute(candidate, &ops, &fixture);
    struct json_object *revision = NULL;

    assert(response);
    assert(!strcmp(string(response, "state"), expected_state));
    assert(boolean(response, "rollback_attempted") == rollback_attempted);
    assert(boolean(response, "rollback_succeeded") == rollback_succeeded);
    if (expected_error)
        assert(!strcmp(string(response, "error"), expected_error));
    else {
        struct json_object *error = NULL;
        assert(json_object_object_get_ex(response, "error", &error));
        assert(!error || json_object_is_type(error, json_type_null));
    }
    assert(json_object_object_get_ex(fixture.current, "revision", &revision));
    assert(json_object_get_int(revision) == expected_revision);
    if (mode == MODE_SUCCESS) {
        assert(boolean(response, "saved"));
        assert(boolean(response, "persisted"));
        assert(boolean(response, "applied"));
        assert(boolean(response, "readback_verified"));
    } else {
        assert(!boolean(response, "persisted"));
        assert(!boolean(response, "applied"));
        assert(!boolean(response, "readback_verified"));
    }
    json_object_put(response);
    json_object_put(candidate);
    json_object_put(fixture.current);
}

int main(void)
{
    run_case(MODE_SUCCESS, "committed", NULL, 2, 0, 0);
    run_case(MODE_SAVE_FAIL, "failed", "save_failed", 1, 0, 0);
    run_case(MODE_SAVE_MISMATCH, "rolled_back", "save_readback_mismatch",
             1, 1, 1);
    run_case(MODE_APPLY_FAIL_ROLLBACK_OK, "rolled_back", "apply_failed",
             1, 1, 1);
    run_case(MODE_RUNTIME_FAIL_ROLLBACK_OK, "rolled_back",
             "runtime_readback_failed", 1, 1, 1);
    run_case(MODE_ROLLBACK_FAIL, "rollback_failed", "rollback_failed",
             1, 1, 0);
    puts("ok: VPN writes commit only after apply health/readback and roll back failures");
    return 0;
}
