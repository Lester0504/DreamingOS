#!/usr/bin/env python3
"""Run the production single-slot preparation/worker against temporary files."""
import os
from pathlib import Path
import subprocess
import tempfile

from otad_test_deps import find_host_dependencies

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/otad/otad_firmware.c").read_text()
HEADER = (ROOT / "src/otad/otad_internal.h").read_text()
STAGING = (ROOT / "src/webd/webd_upload_staging.c").read_text()


def section(text, start, end):
    return text[text.index(start):text.index(end, text.index(start))]


PREAMBLE = r'''
#define _GNU_SOURCE 1
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#define OTAD_MAX_PATH 512
#define OTAD_MAX_TEXT 512
#define OTAD_FIRMWARE_HEADER_BYTES (1024U * 1024U)
#define OTAD_UPLOAD_ID_LEN 36
#define OTAD_OPERATION_ID_LEN 36
#define OTAD_OPERATION_OPTIONS_MAX 1024
#define OTAD_TRUST_KEY_ID_MAX 128
'''

STUBS = r'''
static struct otad_payload_info fixture_payload;
static struct otad_operation_work fixture_work;
static char fixture_sha[65], final_state[32], global_state[32], final_error[160];
static struct json_object *last_result;
static uint64_t fixture_size;
static int trust_fail, capacity_fail, persist_fail;
static unsigned phases;
static struct json_object *boot_operation;
static const char *running_build = "test-build";

const char *otad_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *value;
    return o && json_object_object_get_ex(o, key, &value) ?
        json_object_get_string(value) : def;
}
int otad_operation_find_active_firmware_apply(char *id)
{
    strcpy(id, "operation");
    return boot_operation ? 0 : 1;
}
struct json_object *otad_operation_status_by_id(const char *id)
{
    (void)id;
    return json_object_get(boot_operation);
}
int otad_release_metadata_read(struct json_object **release, const char **path,
                               char *err, size_t len)
{
    (void)path; (void)err; (void)len;
    *release = json_object_new_object();
    json_object_object_add(*release, "build_id", json_object_new_string(running_build));
    json_object_object_add(*release, "dreamingwrt_version", json_object_new_string("v1"));
    return 0;
}

void otad_json_add_string(struct json_object *o, const char *k, const char *v)
{
    json_object_object_add(o, k, json_object_new_string(v));
}

int otad_state_set(const char *key, const char *value)
{
    if (!strcmp(key, "state"))
        snprintf(global_state, sizeof(global_state), "%s", value);
    return 0;
}
int otad_state_get(const char *key, char *value, size_t len, const char *def)
{
    (void)key; (void)def;
    snprintf(value, len, "%s", global_state);
    return 0;
}

int otad_operation_update(const char *id, const char *state, int progress,
                          const char *code, const char *message,
                          struct json_object *result)
{
    (void)id; (void)progress; (void)message;
    snprintf(final_state, sizeof(final_state), "%s", state);
    snprintf(final_error, sizeof(final_error), "%s", code);
    if (last_result) json_object_put(last_result);
    last_result = result ? json_tokener_parse(json_object_to_json_string(result)) : NULL;
    struct json_object *phase;
    if (result && json_object_object_get_ex(result, "phase", &phase)) {
        const char *p = json_object_get_string(phase);
        if (!strcmp(p, "preparing_sysupgrade")) phases |= 1;
        if (!strcmp(p, "checking_platform")) phases |= 2;
        if (!strcmp(p, "starting_sysupgrade")) phases |= 4;
        if (!strcmp(p, "rebooting")) phases |= 8;
    }
    return 0;
}

int otad_db_persist_now(void) { return persist_fail ? -1 : 0; }
int otad_mkdir_p(const char *path, mode_t mode)
{
    return mkdir(path, mode) == 0 || errno == EEXIST ? 0 : -1;
}
int webd_upload_staging_check_capacity(uint64_t bytes, char *err, size_t len)
{
    assert(bytes == 0);
    if (capacity_fail) snprintf(err, len, "staging_insufficient_space");
    return capacity_fail ? -1 : 0;
}
int otad_operation_reverify_trust_binding(int fd, uint64_t size,
    const struct otad_operation_work *work, char *err, size_t len)
{
    (void)fd; (void)size; (void)work;
    if (trust_fail) snprintf(err, len, "trust_changed");
    return trust_fail ? -1 : 0;
}
int otad_firmware_header_read_fd(int fd, uint64_t size,
    struct otad_firmware_info *info, char *err, size_t len)
{
    (void)fd; (void)size; (void)err; (void)len;
    info->is_single_slot = 1;
    strcpy(info->build_id, "test-build");
    info->sysupgrade = fixture_payload;
    return 0;
}
int otad_staged_upload_open(const char *id, struct otad_staged_upload *u,
                            char *err, size_t len)
{
    (void)id; (void)err; (void)len;
    u->rootfd = u->lockfd = -1;
    u->dirfd = open(TEST_ROOT "/upload", O_RDONLY | O_DIRECTORY);
    u->fd = openat(u->dirfd, "data.bin", O_RDONLY);
    u->size = fixture_size;
    snprintf(u->sha256, sizeof(u->sha256), "%s", fixture_sha);
    assert(u->fd >= 0);
    return 0;
}
'''

TESTS = r'''
static void setup(void)
{
    unsigned char buf[65536];
    int fd = open(TEST_ROOT "/upload/data.bin", O_RDWR | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    fixture_payload.offset = OTAD_FIRMWARE_HEADER_BYTES + 19;
    fixture_payload.size = 3 * sizeof(buf) + 77;
    fixture_size = fixture_payload.offset + fixture_payload.size + 211;
    for (uint64_t off = 0; off < fixture_size;) {
        size_t n = fixture_size - off < sizeof(buf) ? fixture_size - off : sizeof(buf);
        for (size_t j = 0; j < n; j++) buf[j] = (off + j) * 17 % 251;
        assert(write(fd, buf, n) == (ssize_t)n);
        off += n;
    }
    assert(otad_hash_range_fd(fd, fixture_payload.offset, fixture_payload.size,
                             fixture_payload.md5, fixture_payload.sha256) == 0);
    char md5[33];
    assert(otad_hash_range_fd(fd, 0, fixture_size, md5, fixture_sha) == 0);
    close(fd);
    memset(&fixture_work, 0, sizeof(fixture_work));
    strcpy(fixture_work.kind, "firmware");
    strcpy(fixture_work.action, "apply");
    strcpy(fixture_work.state, "writing");
    fixture_work.authenticity_verified = fixture_work.target_compatible = 1;
    fixture_work.trust_policy_version = 1;
    strcpy(fixture_work.signing_key_id, "test-key");
    fixture_work.source_size = fixture_size;
    strcpy(fixture_work.source_sha256, fixture_sha);
    trust_fail = capacity_fail = persist_fail = 0;
    phases = 0;
    setenv("CHECK_RC", "0", 1);
    setenv("START_RC", "0", 1);
    unlink(TEST_ROOT "/calls");
}

static int prepared_count(int clean)
{
    DIR *dir = opendir(TEST_ROOT);
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir))) {
        if (strncmp(entry->d_name, "otad-sysupgrade-", 16)) continue;
        char path[1024], directory[1024];
        snprintf(directory, sizeof(directory), "%s/%s", TEST_ROOT, entry->d_name);
        snprintf(path, sizeof(path), "%s/%s/sysupgrade.bin", TEST_ROOT, entry->d_name);
        assert(access(path, F_OK) == 0);
        count++;
        if (clean) { assert(unlink(path) == 0); assert(rmdir(directory) == 0); }
    }
    closedir(dir);
    return count;
}

static int consumed_result(void)
{
    struct json_object *value;
    assert(json_object_object_get_ex(last_result, "upload_consumed", &value));
    return json_object_get_boolean(value);
}

int main(void)
{
    char err[160], output[64];
    struct otad_staged_upload upload;
    struct stat before, after;
    int consumed;
    assert(mkdir(TEST_ROOT "/upload", 0700) == 0);
    setup();
    assert(otad_staged_upload_open("", &upload, err, sizeof(err)) == 0);
    assert(fstat(upload.fd, &before) == 0);
    assert(otad_single_slot_prepare(&upload, &fixture_payload, TEST_ROOT "/fit.bin",
                                    &consumed, err, sizeof(err)) == 0);
    assert(consumed && access(TEST_ROOT "/upload/data.bin", F_OK) != 0);
    assert(stat(TEST_ROOT "/fit.bin", &after) == 0);
    assert(before.st_ino == after.st_ino && before.st_dev == after.st_dev);
    assert(after.st_size == (off_t)fixture_payload.size);
    assert(after.st_blocks <= before.st_blocks);
    otad_staged_upload_close(&upload);
    unlink(TEST_ROOT "/fit.bin");

    /* An invalid range must not consume or change the finalized source. */
    setup();
    assert(otad_staged_upload_open("", &upload, err, sizeof(err)) == 0);
    fixture_payload.size = fixture_size + 1;
    assert(otad_single_slot_prepare(&upload, &fixture_payload, TEST_ROOT "/fit.bin",
                                    &consumed, err, sizeof(err)) != 0);
    assert(!consumed && access(TEST_ROOT "/upload/data.bin", F_OK) == 0);
    otad_staged_upload_close(&upload);

    /* Real fork/exec, bounded output, nonzero exit and missing executable. */
    char *loud[] = {"/bin/sh", "-c",
        "i=0; while [ $i -lt 1000 ]; do echo diagnostic >&2; i=$((i+1)); done; exit 7", NULL};
    assert(otad_single_slot_run(loud, output, sizeof(output)) == 7);
    assert(strlen(output) == sizeof(output) - 1);
    char *missing[] = { TEST_ROOT "/missing", NULL };
    assert(otad_single_slot_run(missing, output, sizeof(output)) == 127);

    setup();
    setenv("CHECK_RC", "1", 1);
    assert(otad_single_slot_apply_worker("operation", &fixture_work) != 0);
    assert(!strcmp(final_error, "sysupgrade_check_failed"));
    assert(!strcmp(final_state, "failed") && !strcmp(global_state, "failed"));
    assert(phases == 3 && consumed_result() && prepared_count(0) == 0);
    struct json_object *diagnostic;
    assert(json_object_object_get_ex(last_result, "native_check_output", &diagnostic));
    assert(strstr(json_object_get_string(diagnostic), "image 1.1, device 1.0"));

    setup();
    setenv("START_RC", "9", 1);
    assert(otad_single_slot_apply_worker("operation", &fixture_work) != 0);
    assert(!strcmp(final_error, "sysupgrade_start_failed"));
    assert(phases == 7 && consumed_result() && prepared_count(0) == 0);

    setup();
    assert(otad_single_slot_apply_worker("operation", &fixture_work) == 0);
    assert(!strcmp(final_state, "rebooting") && phases == 15);
    assert(consumed_result() && prepared_count(1) == 1);

    for (int scenario = 0; scenario < 5; scenario++) {
        setup();
        if (scenario == 0) fixture_work.source_size++;
        if (scenario == 1) trust_fail = 1;
        if (scenario == 2) capacity_fail = 1;
        if (scenario == 3) fixture_payload.sha256[0] ^= 1;
        if (scenario == 4) persist_fail = 1;
        assert(otad_single_slot_apply_worker("operation", &fixture_work) != 0);
        assert(!strcmp(final_state, "failed") && !strcmp(global_state, "failed"));
        assert(prepared_count(0) == 0);
        assert(consumed_result() == (scenario == 3));
        assert(access(TEST_ROOT "/calls", F_OK) != 0);
    }
    json_object_put(last_result);
    last_result = NULL;
    /* Boot confirmation cannot confuse a daemon restart with a device reboot. */
    for (int scenario = 0; scenario < 4; scenario++) {
        boot_operation = json_tokener_parse("{\"target_slot\":\"S\","
            "\"state\":\"writing\",\"to_version\":\"v1\",\"result\":{"
            "\"phase\":\"starting_sysupgrade\",\"source_boot_id\":\"old-boot\","
            "\"expected_build_id\":\"test-build\"}}");
        struct json_object *result;
        json_object_object_get_ex(boot_operation, "result", &result);
        running_build = scenario == 2 ? "wrong-build" : "test-build";
        if (scenario == 0)
            otad_json_add_string(result, "source_boot_id",
                                 "00000000-0000-0000-0000-000000000001");
        if (scenario == 3)
            otad_json_add_string(result, "phase", "checking_platform");
        final_state[0] = '\0';
        otad_single_slot_reconcile_boot();
        assert(!strcmp(final_state, scenario == 0 ? "" :
            scenario == 1 ? "success" : "failed"));
        json_object_put(boot_operation);
    }
    boot_operation = NULL;
    strcpy(global_state, "applying_sysupgrade");
    otad_single_slot_reconcile_boot();
    assert(!strcmp(global_state, "failed"));
    if (last_result) json_object_put(last_result);
    puts("ok: single-inode FIT, bounds, native diagnostics, reject/start/accept, cleanup and trust gates");
    return 0;
}
'''


def main():
    deps = find_host_dependencies(ROOT)
    with tempfile.TemporaryDirectory(prefix="otad-single-slot-") as temp:
        tmp = Path(temp)
        native = tmp / "sysupgrade"
        native.write_text(
            '#!/bin/sh\n'
            f'echo "$*" >> "{tmp}/calls"\n'
            'if [ "$1" = "-T" ]; then\n'
            '  test "$#" = 2 || exit 99\n'
            '  echo "image 1.1, device 1.0: config incompatible" >&2\n'
            '  exit "$CHECK_RC"\n'
            'fi\n'
            'test "$#" = 1 || exit 99\n'
            'echo "native handoff"\n'
            'exit "$START_RC"\n'
        )
        native.chmod(0o700)
        code = PREAMBLE + f'\n#define TEST_ROOT "{tmp}"\n'
        code += section(SOURCE, "struct otad_payload_info {", "struct uloop_timeout")
        code += section(HEADER, "struct otad_staged_upload {", "struct otad_trust_binding {")
        code += section(SOURCE, "static int otad_payload_range_valid(", "static int otad_firmware_header_read_fd(")
        code += section(SOURCE, "static void otad_firmware_info_done(", "static int otad_gzip_rootfs_stream(")
        code += section(SOURCE, "void otad_staged_upload_close(", "int otad_staged_upload_open(")
        code += STUBS
        code += section(SOURCE, "static int otad_single_slot_compact(", "#endif /* OTAD_SINGLE_SLOT_SUPPORTED */")
        code += TESTS
        code = code.replace('"/sbin/sysupgrade"', f'"{native}"')
        boot_id = tmp / "boot_id"
        boot_id.write_text("00000000-0000-0000-0000-000000000001\n")
        code = code.replace('"/proc/sys/kernel/random/boot_id"', f'"{boot_id}"')
        code = code.replace('"/tmp/dreamingwrt', f'"{tmp}')
        harness = tmp / "test.c"
        harness.write_text(code)
        binary = tmp / "test"
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra",
            "-Werror=implicit-function-declaration", f"-I{deps.json_include}",
            f"-I{deps.openssl_include}", str(harness), str(deps.json_library),
            f"-L{deps.openssl_library_dir}", f"-Wl,-rpath,{deps.openssl_library_dir}",
            "-lcrypto", "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True, timeout=30)
    capacity = section(STAGING, "static int upload_capacity(", "static int open_upload_dir_at(")
    assert "required += expected" not in capacity
    worker = section(SOURCE, "static int otad_single_slot_apply_worker(", "#endif /* OTAD_SINGLE_SLOT_SUPPORTED */")
    assert '"-F"' not in worker and '"-n"' not in worker
    assert "otad_copy_range(" not in worker
    assert worker.index("otad_operation_reverify_trust_binding") < worker.index("otad_single_slot_prepare")


if __name__ == "__main__":
    main()
