#!/usr/bin/env python3
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "webd" / "webd_upload_staging.c"
HDR_DIR = ROOT / "webd"

HARNESS = r'''
#define _GNU_SOURCE 1
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "webd_upload_staging.h"

#define OWNER_A "web:owner-a"
#define OWNER_B "web:owner-b"
#define BEGIN(type, filename, expected, maximum, ttl, out, err, err_len) \
    webd_upload_begin(OWNER_A, "browser", type, filename, expected, maximum, \
                      ttl, out, err, err_len)
#define APPEND(id, offset, data, len, out, err, err_len) \
    webd_upload_append(OWNER_A, id, offset, data, len, out, err, err_len)
#define FINALIZE(id, sha, out, err, err_len) \
    webd_upload_finalize(OWNER_A, id, sha, out, err, err_len)
#define GET(id, out, err, err_len) \
    webd_upload_get(OWNER_A, id, out, err, err_len)
#define DELETE(id, err, err_len) \
    webd_upload_delete(OWNER_A, id, err, err_len)
#define OPEN_FINAL(id, err, err_len) \
    webd_upload_open_final_readonly(OWNER_A, id, err, err_len)

static void require_begin_rejects_paths_and_types(const char *root) {
    struct webd_upload_meta m;
    char err[128];
    assert(webd_upload_staging_set_root_for_tests(root) == 0);
    assert(BEGIN("../firmware", "x.bin", 10, 0, 60, &m, err, sizeof(err)) != 0);
    assert(BEGIN("firmware", "../../etc/passwd", 4, 16, 60, &m, err, sizeof(err)) != 0);
    assert(BEGIN("firmware", "fw.bin", 4, 16, 60, &m, err, sizeof(err)) == 0);
    assert(strcmp(m.owner_id, OWNER_A) == 0);
    assert(strcmp(m.origin, "browser") == 0);
    assert(!strchr(m.original_filename, '/'));
    assert(!strchr(m.original_filename, '\\'));
    assert(strcmp(m.original_filename, "fw.bin") == 0);
    assert(strncmp(m.upload_id, "upl-", 4) == 0);
    assert(strlen(m.upload_id) == 36);
    assert(DELETE(m.upload_id, err, sizeof(err)) == 0);
}

static void require_lifecycle(const char *root) {
    struct webd_upload_meta m, got;
    struct webd_upload_list list;
    char err[128];
    const char *a = "hello";
    const char *b = "world";
    assert(webd_upload_staging_set_root_for_tests(root) == 0);
    assert(BEGIN("backup", "config.tar.gz", 10, 20, 60, &m, err, sizeof(err)) == 0);
    assert(APPEND(m.upload_id, 1, a, 5, &got, err, sizeof(err)) != 0);
    assert(APPEND(m.upload_id, 0, a, 5, &got, err, sizeof(err)) == 0);
    assert(got.size_bytes == 5);
    assert(APPEND(m.upload_id, 5, b, 5, &got, err, sizeof(err)) == 0);
    assert(FINALIZE(m.upload_id, "0000000000000000000000000000000000000000000000000000000000000000", &got, err, sizeof(err)) != 0);
    assert(GET(m.upload_id, &got, err, sizeof(err)) == 0);
    assert(strcmp(got.status, "rejected") == 0);
    assert(DELETE(m.upload_id, err, sizeof(err)) == 0);

    assert(BEGIN("backup", "config.tar.gz", 10, 20, 60, &m, err, sizeof(err)) == 0);
    assert(APPEND(m.upload_id, 0, "helloworld", 10, &got, err, sizeof(err)) == 0);
    assert(FINALIZE(m.upload_id, "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af", &got, err, sizeof(err)) == 0);
    assert(strcmp(got.status, "finalized") == 0);
    assert(strcmp(got.sha256, "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af") == 0);
    int fd = OPEN_FINAL(m.upload_id, err, sizeof(err));
    assert(fd >= 0);
    close(fd);
    assert(webd_upload_list_all(&list, err, sizeof(err)) == 0);
    assert(list.count >= 1);
    webd_upload_list_free(&list);
    assert(DELETE(m.upload_id, err, sizeof(err)) == 0);
}

static void require_limits_and_ttl(const char *root) {
    struct webd_upload_meta m, got;
    size_t deleted = 0;
    char err[128];
    assert(webd_upload_staging_set_root_for_tests(root) == 0);
    assert(BEGIN("signature", "sig.bin", 0, 3, 1, &m, err, sizeof(err)) == 0);
    assert(APPEND(m.upload_id, 0, "abcd", 4, &got, err, sizeof(err)) != 0);
    assert(APPEND("../../etc/passwd", 0, "x", 1, &got, err, sizeof(err)) != 0);
    assert(BEGIN("signature", "sig.bin", 0, 999999999, 60, &got, err, sizeof(err)) != 0);
    assert(BEGIN("signature", "sig.bin", 0, 4, 24 * 3600 + 1, &got, err, sizeof(err)) != 0);
    assert(webd_upload_cleanup_expired(m.expires_at + 1, &deleted, err, sizeof(err)) == 0);
    assert(deleted >= 1);
    assert(GET(m.upload_id, &got, err, sizeof(err)) != 0);
}

static void require_symlink_defense(const char *root) {
    struct webd_upload_meta m, got;
    char err[128], linkpath[512];
    assert(webd_upload_staging_set_root_for_tests(root) == 0);
    assert(BEGIN("firmware", "fw.bin", 0, 32, 60, &m, err, sizeof(err)) == 0);
    snprintf(linkpath, sizeof(linkpath), "%s/%s/data.bin", root, m.upload_id);
    assert(unlink(linkpath) == 0);
    assert(symlink("/etc/passwd", linkpath) == 0);
    assert(APPEND(m.upload_id, 0, "x", 1, &got, err, sizeof(err)) != 0);
    unlink(linkpath);
    assert(DELETE(m.upload_id, err, sizeof(err)) == 0);
}

static void require_tamper_and_corrupt_meta_rejected(const char *root) {
    struct webd_upload_meta m, got;
    char err[128], path[512];
    FILE *fp;
    assert(webd_upload_staging_set_root_for_tests(root) == 0);
    assert(BEGIN("backup", "ok.tar", 3, 8, 60, &m, err, sizeof(err)) == 0);
    assert(APPEND(m.upload_id, 0, "abc", 3, &got, err, sizeof(err)) == 0);
    assert(FINALIZE(m.upload_id, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", &got, err, sizeof(err)) == 0);
    snprintf(path, sizeof(path), "%s/%s/data.bin", root, m.upload_id);
    fp = fopen(path, "ab");
    assert(fp);
    fputs("x", fp);
    fclose(fp);
    int fd = OPEN_FINAL(m.upload_id, err, sizeof(err));
    assert(fd < 0);
    assert(DELETE(m.upload_id, err, sizeof(err)) == 0);

    assert(BEGIN("backup", "bad.tar", 0, 8, 60, &m, err, sizeof(err)) == 0);
    snprintf(path, sizeof(path), "%s/%s/meta.txt", root, m.upload_id);
    fp = fopen(path, "wb");
    assert(fp);
    fputs("version=1\nupload_id=upl-00000000000000000000000000000000\nupload_type=backup\nfilename_hex=6261642e746172\nstatus=open\nsize_bytes=-1\nexpected_size_bytes=0\nmax_size_bytes=8\ncreated_at=1\nupdated_at=1\nexpires_at=2\nsha256=\nerror=\n", fp);
    fclose(fp);
    assert(GET(m.upload_id, &got, err, sizeof(err)) != 0);
    /* Ownership cannot be authenticated from corrupt metadata. HTTP deletion
     * must fail closed; the privileged TTL/root cleanup path owns reclamation. */
    assert(DELETE(m.upload_id, err, sizeof(err)) != 0);
}

static void require_lock_serializes_append_delete(const char *root) {
    struct webd_upload_meta m, got;
    char err[128];
    assert(webd_upload_staging_set_root_for_tests(root) == 0);
    assert(BEGIN("signature", "race.bin", 0, 128, 60, &m, err, sizeof(err)) == 0);
    for (int i = 0; i < 16; i++) {
        assert(APPEND(m.upload_id, (uint64_t)i, "x", 1, &got, err, sizeof(err)) == 0);
    }
    assert(got.size_bytes == 16);
    assert(DELETE(m.upload_id, err, sizeof(err)) == 0);
}

static void require_owner_isolation(const char *root) {
    struct webd_upload_meta m, got;
    struct webd_upload_list list;
    char err[128];
    assert(webd_upload_staging_set_root_for_tests(root) == 0);
    assert(BEGIN("backup", "private.dwrt-config", 3, 8, 60, &m, err, sizeof(err)) == 0);
    assert(webd_upload_get(OWNER_B, m.upload_id, &got, err, sizeof(err)) != 0);
    assert(strcmp(err, "upload_not_found") == 0);
    assert(webd_upload_append(OWNER_B, m.upload_id, 0, "abc", 3, &got, err, sizeof(err)) != 0);
    assert(webd_upload_finalize(OWNER_B, m.upload_id, NULL, &got, err, sizeof(err)) != 0);
    assert(webd_upload_open_final_readonly(OWNER_B, m.upload_id, err, sizeof(err)) < 0);
    assert(webd_upload_delete(OWNER_B, m.upload_id, err, sizeof(err)) != 0);
    assert(webd_upload_list_owner(OWNER_B, &list, err, sizeof(err)) == 0);
    assert(list.count == 0);
    webd_upload_list_free(&list);
    assert(APPEND(m.upload_id, 0, "abc", 3, &got, err, sizeof(err)) == 0);
    assert(FINALIZE(m.upload_id, NULL, &got, err, sizeof(err)) == 0);
    assert(DELETE(m.upload_id, err, sizeof(err)) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    require_begin_rejects_paths_and_types(argv[1]);
    require_lifecycle(argv[1]);
    require_limits_and_ttl(argv[1]);
    require_symlink_defense(argv[1]);
    require_tamper_and_corrupt_meta_rejected(argv[1]);
    require_lock_serializes_append_delete(argv[1]);
    require_owner_isolation(argv[1]);
    puts("upload_staging_contract: PASS");
    return 0;
}
'''

def main():
    text = SRC.read_text(encoding="utf-8")
    forbidden = ["system(", "popen(", "wordexp("]
    for needle in forbidden:
        assert needle not in text, f"upload staging must not use shell helper {needle}"
    assert "openat(" in text, "upload staging must use openat"
    assert "O_NOFOLLOW" in text, "upload staging must reject symlink traversal"
    assert "0600" in text, "upload files must be mode 0600"
    assert "flock(" in text, "upload mutations must take an exclusive lock"
    assert "../" not in text, "implementation should not build traversal paths"
    with tempfile.TemporaryDirectory() as td:
        h = Path(td) / "upload_staging_harness.c"
        exe = Path(td) / "upload_staging_harness"
        root = Path(td).resolve() / "staging"
        h.write_text(HARNESS, encoding="utf-8")
        cc = os.environ.get("CC", "cc")
        cmd = [
            cc,
            "-Wall", "-Wextra", "-Werror",
            "-I", str(HDR_DIR),
            str(h), str(SRC),
            "-o", str(exe),
        ]
        try:
            cflags = subprocess.check_output(
                ["pkg-config", "--cflags", "openssl"], text=True
            ).split()
            libs = subprocess.check_output(
                ["pkg-config", "--libs", "openssl"], text=True
            ).split()
            cmd = [
                cc, "-Wall", "-Wextra", "-Werror", *cflags,
                "-I", str(HDR_DIR), str(h), str(SRC),
                "-o", str(exe), *libs,
            ]
        except Exception:
            pass
        subprocess.run(cmd, check=True)
        subprocess.run([str(exe), str(root)], check=True)

if __name__ == "__main__":
    main()
