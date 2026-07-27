#!/usr/bin/env python3
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "jmx_system.c"
HDR = ROOT / "jmx_system.h"

HARNESS = r'''
#define JMX_SYSTEM_MOUNT_CONTRACT_ONLY 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "jmx_system.h"

static size_t write_cap;
static int inject_write_eintr;
static int fail_next_write;
static int write_calls;
static int write_eintr_seen;
static int regular_fsync_calls;
static int directory_fsync_calls;
static int fail_directory_fsync_call;
static int readback_fault_mode;

ssize_t jmx_system_mount_contract_write(int fd, const void *buf, size_t len) {
    write_calls++;
    if (fail_next_write) {
        fail_next_write = 0;
        errno = EIO;
        return -1;
    }
    if (inject_write_eintr) {
        inject_write_eintr = 0;
        write_eintr_seen = 1;
        errno = EINTR;
        return -1;
    }
    if (write_cap && len > write_cap)
        len = write_cap;
    return write(fd, buf, len);
}

int jmx_system_mount_contract_fsync(int fd) {
    struct stat st;
    assert(fstat(fd, &st) == 0);
    if (S_ISDIR(st.st_mode)) {
        directory_fsync_calls++;
        if (fail_directory_fsync_call == directory_fsync_calls) {
            errno = EIO;
            return -1;
        }
    } else {
        regular_fsync_calls++;
    }
    return fsync(fd);
}

void jmx_system_mount_contract_before_readback(const char *path) {
    static const char corrupt[] = "# forced readback mismatch\n";
    int fd;
    ssize_t n;

    if (!readback_fault_mode)
        return;
    fd = open(path, O_WRONLY | O_TRUNC);
    assert(fd >= 0);
    n = write(fd, corrupt, sizeof(corrupt) - 1);
    assert(n == (ssize_t)(sizeof(corrupt) - 1));
    assert(fsync(fd) == 0);
    assert(close(fd) == 0);
    if (readback_fault_mode == 2)
        fail_next_write = 1;
    readback_fault_mode = 0;
}

static void reset_io_hooks(void) {
    write_cap = 0;
    inject_write_eintr = 0;
    fail_next_write = 0;
    write_calls = 0;
    write_eintr_seen = 0;
    regular_fsync_calls = 0;
    directory_fsync_calls = 0;
    fail_directory_fsync_call = 0;
    readback_fault_mode = 0;
}

static size_t read_file(const char *path, char *buf, size_t buf_len) {
    FILE *fp = fopen(path, "rb");
    size_t n;

    assert(fp);
    n = fread(buf, 1, buf_len - 1, fp);
    assert(!ferror(fp));
    assert(fclose(fp) == 0);
    buf[n] = '\0';
    return n;
}

static struct jmx_system_mount_spec good_spec(void) {
    struct jmx_system_mount_spec s;
    memset(&s, 0, sizeof(s));
    snprintf(s.source, sizeof(s.source), "UUID=12345678-1234-1234-1234-123456789abc");
    snprintf(s.target, sizeof(s.target), "/mnt/dwrt-usb1");
    snprintf(s.fstype, sizeof(s.fstype), "ext4");
    snprintf(s.options, sizeof(s.options), "rw,noatime,nodev,nosuid,noexec");
    s.enabled = 1;
    s.check_fs = 0;
    return s;
}

static void require_invalid_source(void) {
    char err[160];
    assert(jmx_system_mount_validate_source("UUID=1234;reboot", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_source("LABEL=usb disk", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_source("/dev/sda1;touch/tmp/pwn", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_source("/tmp/file.img", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_source("/dev/disk/by-label/usb/.", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_source("/dev/disk/by-label/nested/usb", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_source("/dev/disk/by-uuid/nested/12345678", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_source("/dev/sda1/..", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_source("/dev/./sda1", err, sizeof(err)) != 0);
}

static void require_dangerous_targets_rejected(void) {
    char err[160];
    assert(jmx_system_mount_validate_target("/", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/data", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/data-slot", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/etc/config", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/../etc", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/foo/.", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/foo/..", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/./foo", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/foo/../bar", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/foo/../../etc", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/media/foo/.", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/media/foo/..", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/foo//bar", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/foo/", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_target("/mnt/foo.bar/disk-1", err, sizeof(err)) == 0);
}

static void require_options_injection_rejected(void) {
    char err[160];
    assert(jmx_system_mount_validate_options("rw,noatime;reboot", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_options("rw,$(touch/tmp/pwn)", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_options("bind", err, sizeof(err)) != 0);
    assert(jmx_system_mount_validate_options("rw,,noatime", err, sizeof(err)) != 0);
}

static void require_idempotent_save(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;
    char buf[4096];
    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    assert(jmx_system_mount_save_point(&s, &o, &r) == 0);
    assert(r.changed == 1);
    assert(jmx_system_mount_save_point(&s, &o, &r) == 0);
    assert(r.changed == 0);
    read_file(path, buf, sizeof(buf));
    assert(strstr(buf, "config mount"));
    assert(strstr(buf, "UUID=12345678-1234-1234-1234-123456789abc"));
    assert(strstr(buf, "/mnt/dwrt-usb1"));
}

static void require_partial_write_and_durable_backup(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;
    struct stat st;
    char original[4096];
    char backup[4096];
    size_t original_len;
    size_t backup_len;

    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    remove(path);
    reset_io_hooks();
    write_cap = 7;
    inject_write_eintr = 1;
    assert(jmx_system_mount_save_point(&s, &o, &r) == 0);
    assert(write_eintr_seen == 1);
    assert(write_calls > 2);
    assert(regular_fsync_calls >= 1);
    assert(directory_fsync_calls >= 1);
    assert(stat(path, &st) == 0);
    assert((st.st_mode & 0777) == 0600);
    original_len = read_file(path, original, sizeof(original));

    reset_io_hooks();
    snprintf(s.options, sizeof(s.options), "rw,noatime,nodev,nosuid,noexec,nofail");
    assert(jmx_system_mount_save_point(&s, &o, &r) == 0);
    assert(r.changed == 1);
    assert(r.backup_path[0] != '\0');
    assert(regular_fsync_calls >= 2);
    assert(directory_fsync_calls >= 2);
    assert(stat(r.backup_path, &st) == 0);
    assert((st.st_mode & 0777) == 0600);
    backup_len = read_file(r.backup_path, backup, sizeof(backup));
    assert(backup_len == original_len);
    assert(memcmp(backup, original, original_len) == 0);
}

static void require_dry_run(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;
    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    o.dry_run = 1;
    o.execute_mount = 1;
    remove(path);
    assert(jmx_system_mount_save_point(&s, &o, &r) == 0);
    assert(r.changed == 1);
    assert(r.executed == 0);
    assert(access(path, F_OK) != 0);
}

static void require_delete_dry_run_not_executed(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;

    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    o.dry_run = 1;
    o.execute_umount = 1;
    assert(jmx_system_mount_delete_point(&s, &o, &r) == 0);
    assert(r.executed == 0);
}

static void require_rollback_on_mount_failure(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;
    FILE *fp;
    char buf[512];
    size_t n;
    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    o.mount_bin = "/bin/false";
    o.execute_mount = 1;
    fp = fopen(path, "wb");
    assert(fp);
    fputs("# original\n", fp);
    fclose(fp);
    reset_io_hooks();
    assert(jmx_system_mount_save_point(&s, &o, &r) != 0);
    assert(r.rolled_back == 1);
    assert(regular_fsync_calls >= 3);
    assert(directory_fsync_calls >= 3);
    fp = fopen(path, "rb");
    assert(fp);
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    assert(strcmp(buf, "# original\n") == 0);
}

static void require_readback_mismatch_rollback(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;
    FILE *fp;
    char buf[512];

    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    fp = fopen(path, "wb");
    assert(fp);
    assert(fputs("# original before readback\n", fp) >= 0);
    assert(fclose(fp) == 0);
    reset_io_hooks();
    readback_fault_mode = 1;
    assert(jmx_system_mount_save_point(&s, &o, &r) == JMX_SYSTEM_MOUNT_ERR_IO);
    assert(r.changed == 1);
    assert(r.rolled_back == 1);
    assert(strcmp(r.error, "readback_mismatch") == 0);
    assert(regular_fsync_calls >= 3);
    assert(directory_fsync_calls >= 3);
    read_file(path, buf, sizeof(buf));
    assert(strcmp(buf, "# original before readback\n") == 0);
}

static void require_readback_mismatch_removes_new_file(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;

    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    remove(path);
    reset_io_hooks();
    readback_fault_mode = 1;
    assert(jmx_system_mount_save_point(&s, &o, &r) == JMX_SYSTEM_MOUNT_ERR_IO);
    assert(r.changed == 1);
    assert(r.rolled_back == 1);
    assert(strcmp(r.error, "readback_mismatch") == 0);
    assert(access(path, F_OK) != 0);
    assert(directory_fsync_calls >= 2);
}

static void require_parent_fsync_failure_rollback(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;
    FILE *fp;
    char buf[512];

    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    fp = fopen(path, "wb");
    assert(fp);
    assert(fputs("# original before parent fsync\n", fp) >= 0);
    assert(fclose(fp) == 0);
    reset_io_hooks();
    fail_directory_fsync_call = 2;
    assert(jmx_system_mount_save_point(&s, &o, &r) == JMX_SYSTEM_MOUNT_ERR_IO);
    assert(r.changed == 1);
    assert(r.rolled_back == 1);
    assert(strcmp(r.error, "write_fstab_failed") == 0);
    assert(regular_fsync_calls >= 3);
    assert(directory_fsync_calls >= 3);
    read_file(path, buf, sizeof(buf));
    assert(strcmp(buf, "# original before parent fsync\n") == 0);
}

static void require_pre_rename_failure_not_rollback(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;
    FILE *fp;
    char buf[512];

    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    o.mount_bin = "/bin/false";
    o.execute_mount = 1;
    fp = fopen(path, "wb");
    assert(fp);
    assert(fputs("# original before failed backup\n", fp) >= 0);
    assert(fclose(fp) == 0);
    reset_io_hooks();
    fail_next_write = 1;
    assert(jmx_system_mount_save_point(&s, &o, &r) == JMX_SYSTEM_MOUNT_ERR_IO);
    assert(r.changed == 1);
    assert(r.executed == 0);
    assert(r.rolled_back == 0);
    assert(strcmp(r.error, "backup_fstab_failed") == 0);
    read_file(path, buf, sizeof(buf));
    assert(strcmp(buf, "# original before failed backup\n") == 0);
}

static void require_rollback_success_threshold(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;
    FILE *fp;

    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    fp = fopen(path, "wb");
    assert(fp);
    assert(fputs("# original rollback threshold\n", fp) >= 0);
    assert(fclose(fp) == 0);
    reset_io_hooks();
    readback_fault_mode = 2;
    assert(jmx_system_mount_save_point(&s, &o, &r) == JMX_SYSTEM_MOUNT_ERR_ROLLBACK);
    assert(r.changed == 1);
    assert(r.rolled_back == 0);
    assert(strcmp(r.error, "readback_rollback_failed") == 0);
    assert(fail_next_write == 0);
}

static void require_delete_point(const char *path) {
    struct jmx_system_mount_spec s = good_spec();
    struct jmx_system_mount_txn_opts o;
    struct jmx_system_mount_txn_result r;
    FILE *fp;
    char buf[512];
    size_t n;
    memset(&o, 0, sizeof(o));
    o.fstab_path = path;
    assert(jmx_system_mount_save_point(&s, &o, &r) == 0);
    assert(jmx_system_mount_delete_point(&s, &o, &r) == 0);
    assert(r.changed == 1);
    fp = fopen(path, "rb");
    assert(fp);
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    assert(!strstr(buf, "/mnt/dwrt-usb1"));
}

int main(int argc, char **argv) {
    char path[512];
    char partial_path[512];
    char readback_path[512];
    char readback_new_path[512];
    char parent_fsync_path[512];
    char pre_rename_path[512];
    char threshold_path[512];
    assert(argc == 2);
    snprintf(path, sizeof(path), "%s/fstab", argv[1]);
    snprintf(partial_path, sizeof(partial_path), "%s/fstab-partial", argv[1]);
    snprintf(readback_path, sizeof(readback_path), "%s/fstab-readback", argv[1]);
    snprintf(readback_new_path, sizeof(readback_new_path), "%s/fstab-readback-new", argv[1]);
    snprintf(parent_fsync_path, sizeof(parent_fsync_path), "%s/fstab-parent-fsync", argv[1]);
    snprintf(pre_rename_path, sizeof(pre_rename_path), "%s/fstab-pre-rename", argv[1]);
    snprintf(threshold_path, sizeof(threshold_path), "%s/fstab-threshold", argv[1]);
    require_invalid_source();
    require_dangerous_targets_rejected();
    require_options_injection_rejected();
    require_dry_run(path);
    require_delete_dry_run_not_executed(path);
    require_idempotent_save(path);
    require_partial_write_and_durable_backup(partial_path);
    require_rollback_on_mount_failure(path);
    require_readback_mismatch_rollback(readback_path);
    require_readback_mismatch_removes_new_file(readback_new_path);
    require_parent_fsync_failure_rollback(parent_fsync_path);
    require_pre_rename_failure_not_rollback(pre_rename_path);
    require_rollback_success_threshold(threshold_path);
    require_delete_point(path);
    puts("system_mount_contract: PASS");
    return 0;
}
'''

def main():
    src_text = SRC.read_text(encoding="utf-8")
    assert not re.search(r"(?<![A-Za-z0-9_])system\s*\(", src_text), \
        "mount helper must not use shell system()"
    assert not re.search(r"(?<![A-Za-z0-9_])popen\s*\(", src_text), \
        "mount helper must not use shell popen()"
    assert "mkstemp(" in src_text, "atomic temp creation must use mkstemp/O_EXCL semantics"
    assert ".tmp.%ld" not in src_text, "predictable PID temp names are forbidden"
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "system_mount_harness.c"
        exe = Path(td) / "system_mount_harness"
        h.write_text(HARNESS, encoding="utf-8")
        cmd = [
            os.environ.get("CC", "cc"),
            "-Wall", "-Wextra", "-Werror", "-DJMX_SYSTEM_MOUNT_CONTRACT_ONLY=1",
            "-DJMX_SYSTEM_MOUNT_TEST_HOOKS=1",
            "-I", str(ROOT),
            str(h), str(SRC),
            "-o", str(exe),
        ]
        subprocess.run(cmd, check=True)
        subprocess.run([str(exe), td], check=True)

if __name__ == "__main__":
    main()
