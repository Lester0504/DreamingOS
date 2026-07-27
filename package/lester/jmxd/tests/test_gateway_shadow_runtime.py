#!/usr/bin/env python3
"""Runtime state-machine test for Gateway Shadow phase one."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/jmx_gateway_shadow.c"
HEADER = ROOT / "src/jmx_gateway_shadow.h"
JSON_PREFIX = Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19")

HARNESS = r'''
#include <assert.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jmx_gateway_shadow.h"

struct json_object *jmx_gen_api_response_data(int code, struct json_object *data)
{
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "code", json_object_new_int(code));
    json_object_object_add(root, "data", data ? data : json_object_new_object());
    return root;
}
static struct json_object *child(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    assert(obj && json_object_object_get_ex(obj, key, &value) && value);
    return value;
}
static int boolean(struct json_object *obj, const char *key)
{ return json_object_get_boolean(child(obj, key)); }
static const char *string(struct json_object *obj, const char *key)
{ return json_object_get_string(child(obj, key)); }
int main(void)
{
    struct json_object *cfg = json_object_new_object();
    struct json_object *response, *data, *readback, *cap;
    assert(jmx_gateway_shadow_schema_ensure() == 0);

    json_object_object_add(cfg, "enabled", json_object_new_boolean(0));
    json_object_object_add(cfg, "role", json_object_new_string("primary"));
    json_object_object_add(cfg, "lan_interface", json_object_new_string("lo0"));
    json_object_object_add(cfg, "heartbeat_interface", json_object_new_string("shadow-test0"));
    json_object_object_add(cfg, "heartbeat_local_ip", json_object_new_string("169.254.30.1"));
    json_object_object_add(cfg, "heartbeat_peer_ip", json_object_new_string("169.254.30.2"));
    json_object_object_add(cfg, "virtual_ipv4", json_object_new_string("192.0.2.1/24"));
    json_object_object_add(cfg, "virtual_router_id", json_object_new_int(51));
    json_object_object_add(cfg, "priority", json_object_new_int(150));
    json_object_object_add(cfg, "advert_interval_seconds", json_object_new_int(1));
    json_object_object_add(cfg, "preempt", json_object_new_boolean(0));
    json_object_object_add(cfg, "connection_sync", json_object_new_boolean(1));

    response = jmx_gateway_shadow_save(cfg);
    assert(json_object_get_int(child(response, "code")) == 2000);
    data = child(response, "data");
    assert(boolean(data, "persisted"));
    assert(!boolean(data, "applied"));
    json_object_put(response);

    response = jmx_gateway_shadow_get();
    data = child(response, "data");
    readback = child(data, "config");
    assert(!strcmp(string(readback, "heartbeat_interface"), "shadow-test0"));
    assert(!strcmp(string(readback, "virtual_ipv4"), "192.0.2.1/24"));
    cap = child(data, "capabilities");
    assert(!boolean(cap, "pairing_supported"));
    assert(!boolean(cap, "apply_supported"));
    assert(boolean(cap, "secrets_write_only"));
    assert(!strcmp(string(cap, "session_continuity"), "best_effort"));
    json_object_put(response);

    response = jmx_gateway_shadow_preflight(NULL);
    data = child(response, "data");
    assert(!boolean(data, "ready"));
    assert(!strcmp(string(data, "reason"),
                   "mutual_authenticated_peer_pairing_pending"));
    json_object_put(response);

    response = jmx_gateway_shadow_apply(NULL);
    assert(json_object_get_int(child(response, "code")) == 4000);
    data = child(response, "data");
    assert(!boolean(data, "applied"));
    assert(!boolean(data, "changed"));
    assert(!boolean(data, "rollback_available"));
    assert(!boolean(data, "preflight_ready"));
    assert(!strcmp(string(data, "error"), "capability_disabled"));
    json_object_put(response);

    response = jmx_gateway_shadow_status();
    data = child(response, "data");
    assert(!strcmp(string(data, "state"), "blocked"));
    assert(!strcmp(string(data, "runtime_role"), "disabled"));
    assert(!strcmp(string(data, "session_continuity"), "best_effort"));
    assert(!boolean(data, "paired"));
    json_object_put(response);

    response = jmx_gateway_shadow_disable(NULL);
    data = child(response, "data");
    assert(boolean(data, "persisted"));
    assert(boolean(data, "applied"));
    assert(!strcmp(string(data, "state"), "inactive"));
    json_object_put(response);
    json_object_put(cfg);
    return 0;
}
'''


def test_gateway_shadow_runtime_state_machine() -> None:
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    assert compiler
    with tempfile.TemporaryDirectory(prefix="gateway-shadow-runtime-") as raw:
        directory = Path(raw)
        harness = directory / "fixture.c"
        executable = directory / "fixture"
        database = directory / "config.db"
        harness.write_text(HARNESS, encoding="utf-8")
        command = [compiler, "-std=gnu11", "-D_GNU_SOURCE", "-I", str(ROOT / "src")]
        if JSON_PREFIX.exists():
            command += ["-I", str(JSON_PREFIX / "include")]
        command += [str(SOURCE), str(harness), "-lsqlite3"]
        if (JSON_PREFIX / "lib/libjson-c.a").is_file():
            command += [str(JSON_PREFIX / "lib/libjson-c.a")]
        else:
            command += ["-ljson-c"]
        command += ["-o", str(executable)]
        subprocess.run(command, check=True)
        environment = os.environ.copy()
        environment["DREAMINGWRT_CONFIG_DB"] = str(database)
        subprocess.run([str(executable)], env=environment, check=True)


if __name__ == "__main__":
    test_gateway_shadow_runtime_state_machine()
    print("ok: Gateway Shadow runtime state machine")
