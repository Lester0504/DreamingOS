#!/usr/bin/env python3
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "jmx_system.c"

HARNESS = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "jmx_system.h"

static void write_file(const char *path, const char *text, mode_t mode) {
    FILE *fp = fopen(path, "wb");
    assert(fp);
    assert(fwrite(text, 1, strlen(text), fp) == strlen(text));
    assert(fclose(fp) == 0);
    assert(chmod(path, mode) == 0);
}

static void read_file(const char *path, char *out, size_t out_len) {
    FILE *fp = fopen(path, "rb");
    size_t n;
    assert(fp);
    n = fread(out, 1, out_len - 1, fp);
    assert(!ferror(fp));
    assert(fclose(fp) == 0);
    out[n] = '\0';
}

static mode_t file_mode(const char *path) {
    struct stat st;
    assert(stat(path, &st) == 0);
    return st.st_mode & 07777;
}

static void require_valid(const char *text) {
    char err[160] = {0};
    size_t line = 99;
    assert(jmx_system_crontab_validate_text(text, &line, err, sizeof(err)) == 0);
    assert(line == 0);
}

static void require_invalid(const char *text, size_t expected_line, const char *expected_error) {
    char err[160] = {0};
    size_t line = 0;
    assert(jmx_system_crontab_validate_text(text, &line, err, sizeof(err)) != 0);
    assert(line == expected_line);
    assert(strcmp(err, expected_error) == 0);
}

static void validate_cron_syntax(void) {
    require_valid("# comment\nPATH=/usr/sbin:/usr/bin\n*/5 0-23 * jan,dec mon-fri /bin/run % payload\n");
    require_valid("MAILTO=\nSHELL=/bin/sh\n0 0 1 1 * /bin/true\n");
    require_invalid("0 24 * * * /bin/false\n", 1, "invalid_cron_field");
    require_invalid("*/0 * * * * /bin/false\n", 1, "invalid_cron_field");
    require_invalid("* * * foo * /bin/false\n", 1, "invalid_cron_field");
    require_invalid("* * * * *\n", 1, "cron_command_required");
    require_invalid("FOO=bar\n", 1, "unsupported_cron_environment");
    require_invalid("PATH=/bin extra\n", 1, "unsupported_cron_environment");
    require_invalid("? * * * * /bin/false\n", 1, "invalid_cron_field");
#if JMX_CROND_SPECIAL_TIMES
    assert(jmx_system_crontab_special_times_supported() == 1);
    require_valid("@reboot /bin/true\n@daily /bin/task\n");
#else
    assert(jmx_system_crontab_special_times_supported() == 0);
    require_invalid("@reboot /bin/true\n", 1, "cron_special_times_unsupported");
#endif
}

static void make_script(const char *path, const char *body) {
    char text[2048];
    snprintf(text, sizeof(text), "#!/bin/sh\n%s\n", body);
    write_file(path, text, 0755);
}

static struct jmx_system_text_apply_opts opts_for(const char *path, const char *backup,
                                                   const char *reload, mode_t mode) {
    struct jmx_system_text_apply_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.path = path;
    opts.backup_path = backup;
    opts.reload_bin = reload;
    opts.reload_action = "restart";
    opts.reload_timeout_ms = 1500;
    opts.max_bytes = 65536;
    opts.mode = mode;
    return opts;
}

static void require_success_and_mode_only(const char *dir) {
    char path[1024], backup[1024], script[1024], content[256];
    struct jmx_system_text_apply_opts opts;
    struct jmx_system_text_apply_result result;

    snprintf(path, sizeof(path), "%s/root-cron", dir);
    snprintf(backup, sizeof(backup), "%s/root-cron.bak", dir);
    snprintf(script, sizeof(script), "%s/reload-ok", dir);
    make_script(script, "exit 0");
    write_file(path, "old\n", 0644);
    opts = opts_for(path, backup, script, 0600);
    {
        int rc = jmx_system_text_apply("new\n", &opts, &result);
        if (rc != 0)
            fprintf(stderr, "success diagnostic rc=%d error=%s rollback=%d/%d\n",
                    rc, result.error, result.rollback_attempted,
                    result.rollback_succeeded);
        assert(rc == 0);
    }
    assert(result.changed == 1 && result.reloaded == 1);
    assert(strcmp(result.backup_path, backup) == 0);
    read_file(path, content, sizeof(content));
    assert(strcmp(content, "new\n") == 0 && file_mode(path) == 0600);
    read_file(backup, content, sizeof(content));
    assert(strcmp(content, "old\n") == 0 && file_mode(backup) == 0600);

    assert(chmod(path, 0644) == 0);
    assert(jmx_system_text_apply("new\n", &opts, &result) == 0);
    assert(result.changed == 1 && file_mode(path) == 0600);
    assert(jmx_system_text_apply("new\n", &opts, &result) == 0);
    assert(result.changed == 0 && result.reloaded == 0);

    assert(chmod(path, 0644) == 0);
    opts.dry_run = 1;
    assert(jmx_system_text_apply("new\n", &opts, &result) == 0);
    assert(result.changed == 1 && file_mode(path) == 0644);
}

static void require_reload_failure_rollback(const char *dir, int timeout) {
    char path[1024], backup[1024], script[1024], marker[1024], body[4096], content[256];
    struct jmx_system_text_apply_opts opts;
    struct jmx_system_text_apply_result result;

    snprintf(path, sizeof(path), "%s/fail-%d", dir, timeout);
    snprintf(backup, sizeof(backup), "%s/fail-%d.bak", dir, timeout);
    snprintf(script, sizeof(script), "%s/reload-fail-%d", dir, timeout);
    snprintf(marker, sizeof(marker), "%s/reload-fail-%d.marker", dir, timeout);
    if (timeout)
        snprintf(body, sizeof(body), "if [ ! -e '%s' ]; then touch '%s'; sleep 5; exit 1; fi\nexit 0", marker, marker);
    else
        snprintf(body, sizeof(body), "if [ ! -e '%s' ]; then touch '%s'; exit 1; fi\nexit 0", marker, marker);
    make_script(script, body);
    write_file(path, "before\n", 0640);
    opts = opts_for(path, backup, script, 0600);
    if (timeout)
        opts.reload_timeout_ms = 500;
    assert(jmx_system_text_apply("after\n", &opts, &result) != 0);
    if (!result.rollback_succeeded)
        fprintf(stderr, "rollback diagnostic timeout=%d attempted=%d error=%s mode=%04o\n",
                timeout, result.rollback_attempted, result.error,
                (unsigned)file_mode(path));
    assert(result.changed == 1 && result.rollback_attempted == 1);
    assert(result.rollback_succeeded == 1);
    assert(strcmp(result.error, "reload_failed") == 0);
    read_file(path, content, sizeof(content));
    assert(strcmp(content, "before\n") == 0 && file_mode(path) == 0640);
}

static void require_new_file_removed_on_failure(const char *dir) {
    char path[1024], script[1024], marker[1024], body[4096];
    struct jmx_system_text_apply_opts opts;
    struct jmx_system_text_apply_result result;

    snprintf(path, sizeof(path), "%s/new-file", dir);
    snprintf(script, sizeof(script), "%s/reload-new-fail", dir);
    snprintf(marker, sizeof(marker), "%s/reload-new-fail.marker", dir);
    snprintf(body, sizeof(body), "if [ ! -e '%s' ]; then touch '%s'; exit 1; fi\nexit 0", marker, marker);
    make_script(script, body);
    opts = opts_for(path, NULL, script, 0755);
    assert(jmx_system_text_apply("#!/bin/sh\nexit 0\n", &opts, &result) != 0);
    assert(result.rollback_attempted == 1 && result.rollback_succeeded == 1);
    assert(access(path, F_OK) != 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    validate_cron_syntax();
    require_success_and_mode_only(argv[1]);
    require_reload_failure_rollback(argv[1], 0);
    require_reload_failure_rollback(argv[1], 1);
    require_new_file_removed_on_failure(argv[1]);
    puts("system_startup_cron_transaction_contract: PASS");
    return 0;
}
'''


def compile_and_run(temp_dir: Path, special_times: int) -> None:
    harness = temp_dir / f"harness-{special_times}.c"
    binary = temp_dir / f"harness-{special_times}"
    run_dir = temp_dir / f"run-{special_times}"
    run_dir.mkdir()
    harness.write_text(HARNESS, encoding="utf-8")
    subprocess.run([
        os.environ.get("CC", "cc"),
        "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-D_GNU_SOURCE",
        "-DJMX_SYSTEM_MOUNT_CONTRACT_ONLY=1",
        f"-DJMX_CROND_SPECIAL_TIMES={special_times}",
        "-I", str(ROOT), str(harness), str(SRC), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary), str(run_dir)], check=True, timeout=10)


def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        compile_and_run(root, 0)
        compile_and_run(root, 1)


if __name__ == "__main__":
    main()
