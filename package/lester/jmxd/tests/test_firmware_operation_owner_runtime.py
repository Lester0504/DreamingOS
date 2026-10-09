#!/usr/bin/env python3
"""Check firmware ownership after volatile upload metadata is gone."""
import os
from pathlib import Path
import subprocess
import tempfile

from otad_test_deps import find_host_dependencies
from webd_sources import webd_function_text

ROOT = Path(__file__).resolve().parents[1]

PREAMBLE = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <json-c/json.h>
#include "webd_upload_staging.h"

static int metadata_present = 1;
static struct json_object *operation;
static char forwarded_owner[128];

static const char *app_nc_json_str(struct json_object *o, const char *key,
                                    const char *fallback)
{
    struct json_object *v;
    return o && json_object_object_get_ex(o, key, &v) &&
        json_object_is_type(v, json_type_string) ?
        json_object_get_string(v) : fallback;
}
static int app_nc_json_bool(struct json_object *o, const char *key, int fallback)
{
    struct json_object *v;
    return o && json_object_object_get_ex(o, key, &v) ?
        json_object_get_boolean(v) : fallback;
}
static int app_nc_json_has(struct json_object *o, const char *key)
{
    struct json_object *v;
    return o && json_object_object_get_ex(o, key, &v);
}
static struct json_object *webd_error(const char *code, const char *message,
                                      const char *field, const char *source)
{
    (void)message; (void)field; (void)source;
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "ok", json_object_new_boolean(0));
    json_object_object_add(o, "error", json_object_new_string(code));
    return o;
}
static struct json_object *webd_upload_error(const char *code, int *status)
{
    *status = 404;
    return webd_error(code, "", "", "");
}
int webd_upload_get(const char *owner, const char *id, struct webd_upload_meta *meta,
                    char *err, size_t len)
{
    (void)id;
    if (!metadata_present || strcmp(owner, "web:alice")) {
        snprintf(err, len, "upload_not_found");
        return -1;
    }
    strcpy(meta->upload_type, "firmware");
    strcpy(meta->status, "finalized");
    return 0;
}
int webd_upload_open_final_readonly(const char *owner, const char *id,
                                    char *err, size_t len)
{
    (void)owner; (void)id; (void)err; (void)len;
    return dup(STDIN_FILENO);
}
static struct json_object *app_ubus_invoke_object_timeout(const char *object,
    const char *method, struct json_object *params, int timeout)
{
    (void)object; (void)timeout;
    if (!strcmp(method, "verify"))
        snprintf(forwarded_owner, sizeof(forwarded_owner), "%s",
                 app_nc_json_str(params, "owner_id", ""));
    return json_tokener_parse(json_object_to_json_string(operation));
}
static int app_response_status(struct json_object *o, int fallback)
{
    return app_nc_json_bool(o, "ok", 0) ? fallback : 400;
}
'''

CASES = r'''
static void lookup(const char *owner, int expected)
{
    int status = 0;
    struct json_object *response =
        webd_firmware_operation_lookup(owner, "ota-test", &status);
    assert(status == expected);
    assert(app_nc_json_bool(response, "ok", 0) == (expected == 200));
    json_object_put(response);
}

int main(void)
{
    operation = json_tokener_parse(
        "{\"ok\":true,\"operation_id\":\"ota-test\",\"kind\":\"firmware\","
        "\"upload_id\":\"upl-test\",\"state\":\"success\"}");
    lookup("web:alice", 200);
    lookup("web:bob", 404);
    metadata_present = 0;
    lookup("web:alice", 404);

    json_object_object_add(operation, "owner_id", json_object_new_string("web:alice"));
    /* A reboot loses /tmp, not the operation's already verified ownership. */
    lookup("web:alice", 200);
    lookup("web:bob", 404);
    lookup("", 404);
    lookup(NULL, 404);
    metadata_present = 1;
    lookup("web:bob", 404);

    struct json_object *body = json_tokener_parse(
        "{\"upload_id\":\"upl-test\",\"owner_id\":\"web:mallory\"}");
    int status = 0;
    struct json_object *response =
        webd_firmware_verify_response("web:alice", body, &status);
    assert(status == 200);
    assert(!strcmp(forwarded_owner, "web:alice"));
    json_object_put(response);
    json_object_put(body);
    json_object_put(operation);
    puts("ok: persisted firmware owner, legacy isolation, and server-bound verify owner");
    return 0;
}
'''


def main():
    deps = find_host_dependencies(ROOT)
    functions = (
        "webd_firmware_operation_error", "webd_firmware_body_forbidden",
        "webd_firmware_upload_owned", "webd_firmware_operation_lookup",
        "webd_firmware_verify_response",
    )
    source = PREAMBLE + "\n".join(
        webd_function_text("api_maintenance.c", name) for name in functions
    ) + CASES
    with tempfile.TemporaryDirectory(prefix="firmware-owner-") as directory:
        temp = Path(directory)
        harness = temp / "harness.c"
        harness.write_text(source)
        binary = temp / "harness"
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
            "-Werror=implicit-function-declaration",
            "-I", str(deps.json_include), "-I", str(ROOT / "src/webd"),
            str(harness), str(deps.json_library), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
