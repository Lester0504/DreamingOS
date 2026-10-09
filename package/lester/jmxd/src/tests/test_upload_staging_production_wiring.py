#!/usr/bin/env python3
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEBD_MAIN = (ROOT / "webd" / "webd_main.c").read_text(encoding="utf-8")
STAGING = (ROOT / "webd" / "webd_upload_staging.c").read_text(encoding="utf-8")
FIRMWARE = (ROOT / "otad" / "otad_firmware.c").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def c_function(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


HARNESS = r'''
#define _GNU_SOURCE 1
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "webd_upload_staging.h"

#define OTAD_OPERATION_ID_LEN 36
#define OTAD_UPLOAD_ID_LEN 36

struct otad_operation_work {
    char operation_id[OTAD_OPERATION_ID_LEN + 1];
    char kind[32];
    char action[32];
    char upload_id[OTAD_UPLOAD_ID_LEN + 1];
    char state[32];
};

static struct otad_operation_work g_work;

int otad_operation_id_ok(const char *id) {
    return id && strlen(id) == OTAD_OPERATION_ID_LEN && !strncmp(id, "op-", 3);
}

int otad_upload_id_ok(const char *id) {
    return id && strlen(id) == OTAD_UPLOAD_ID_LEN && !strncmp(id, "upl-", 4);
}

int otad_operation_get_work(const char *operation_id,
                            struct otad_operation_work *work) {
    if (!operation_id || strcmp(operation_id, g_work.operation_id))
        return -1;
    *work = g_work;
    return 0;
}

#define DREAMINGWRT_OTAD_INTERNAL_H
#include "otad_upload_lifecycle.c"

static void set_work(const char *state, const char *upload_id) {
    memset(&g_work, 0, sizeof(g_work));
    snprintf(g_work.operation_id, sizeof(g_work.operation_id),
             "op-000000000000000000000000000000000");
    snprintf(g_work.kind, sizeof(g_work.kind), "firmware");
    snprintf(g_work.action, sizeof(g_work.action), "apply");
    snprintf(g_work.state, sizeof(g_work.state), "%s", state);
    snprintf(g_work.upload_id, sizeof(g_work.upload_id), "%s",
             upload_id ? upload_id : "");
}

static void create_upload(struct webd_upload_meta *meta) {
    char error[96];
    int rc = webd_upload_begin("web:test", "browser", "firmware", "fw.bin",
                               0, 64, 60, meta, error, sizeof(error));
    if (rc != 0)
        fprintf(stderr, "create_upload failed: %s\n", error);
    assert(rc == 0);
}

int main(int argc, char **argv) {
    struct webd_upload_meta success, failed, reconnecting, unrelated, got;
    char error[96];
    int deleted = -1;

    assert(argc == 2);
    assert(webd_upload_staging_set_root_for_tests(argv[1]) == 0);
    create_upload(&success);
    create_upload(&failed);
    create_upload(&reconnecting);
    create_upload(&unrelated);

    set_work("failed", failed.upload_id);
    assert(otad_consumed_upload_cleanup(g_work.operation_id, &deleted,
                                        error, sizeof(error)) == 1);
    assert(deleted == 0);
    assert(webd_upload_get("web:test", failed.upload_id, &got,
                           error, sizeof(error)) == 0);

    set_work("reconnecting", reconnecting.upload_id);
    assert(otad_consumed_upload_cleanup(g_work.operation_id, &deleted,
                                        error, sizeof(error)) == 1);
    assert(webd_upload_get("web:test", reconnecting.upload_id, &got,
                           error, sizeof(error)) == 0);

    set_work("success", success.upload_id);
    assert(otad_consumed_upload_cleanup(g_work.operation_id, &deleted,
                                        error, sizeof(error)) == 0);
    assert(deleted == 1);
    assert(webd_upload_get("web:test", success.upload_id, &got,
                           error, sizeof(error)) != 0);
    assert(webd_upload_get("web:test", unrelated.upload_id, &got,
                           error, sizeof(error)) == 0);

    deleted = -1;
    assert(otad_consumed_upload_cleanup(g_work.operation_id, &deleted,
                                        error, sizeof(error)) == 0);
    assert(deleted == 0);

    set_work("success", "");
    assert(otad_consumed_upload_cleanup(g_work.operation_id, &deleted,
                                        error, sizeof(error)) == 0);
    assert(webd_upload_get("web:test", unrelated.upload_id, &got,
                           error, sizeof(error)) == 0);
    puts("upload_staging_production_wiring: PASS");
    return 0;
}
'''


def main() -> None:
    begin = c_function(STAGING, "int webd_upload_begin(")
    confirm = c_function(FIRMWARE, "struct json_object *otad_confirm_boot(")
    reconcile = c_function(FIRMWARE, "void otad_reconcile_boot_state(")
    rollback = c_function(FIRMWARE, "struct json_object *otad_firmware_rollback(")

    assert "webd_upload_cleanup_expired(now" in begin
    assert "webd_upload_gc_run(&g_upload_gc_timer);" in WEBD_MAIN
    assert "uloop_timeout_set(timer, WEBD_UPLOAD_GC_INTERVAL_MS);" in WEBD_MAIN
    assert "otad/otad_upload_lifecycle.o" in MAKEFILE
    assert "webd/webd_upload_staging.o" in MAKEFILE.split("OTAD_OBJS :=", 1)[1].splitlines()[0]
    assert confirm.index("otad_operation_complete_confirmed_boot(") < confirm.index(
        "otad_consumed_upload_cleanup("
    )
    assert "if (operation_rc == 0 && completed_operation_id[0])" in confirm
    assert "otad_consumed_upload_cleanup(" in reconcile
    assert "otad_consumed_upload_cleanup(" not in rollback

    with tempfile.TemporaryDirectory(prefix="upload-production-wiring-") as td:
        source = Path(td) / "fixture.c"
        binary = Path(td) / "fixture"
        staging_root = (Path(td) / "staging").resolve()
        source.write_text(HARNESS, encoding="utf-8")
        cc = os.environ.get("CC", "cc")
        cflags = subprocess.check_output(
            ["pkg-config", "--cflags", "openssl"], text=True
        ).split()
        libs = subprocess.check_output(
            ["pkg-config", "--libs", "openssl"], text=True
        ).split()
        subprocess.run(
            [
                cc,
                "-Wall",
                "-Wextra",
                "-Werror",
                *cflags,
                "-I",
                str(ROOT / "webd"),
                "-I",
                str(ROOT / "otad"),
                str(source),
                str(ROOT / "webd" / "webd_upload_staging.c"),
                "-o",
                str(binary),
                *libs,
            ],
            check=True,
        )
        subprocess.run([str(binary), str(staging_root)], check=True)

    print("upload_staging_production_wiring: PASS")


if __name__ == "__main__":
    main()
