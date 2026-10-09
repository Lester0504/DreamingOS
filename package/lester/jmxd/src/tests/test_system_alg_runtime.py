#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "system" / "system_alg_runtime.c"

HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "system/system_alg_runtime.h"

struct fixture {
    char root[4096];
    char sys_module[4096];
    char module_root[4096];
    char proc_modules[4096];
    char conntrack[4096];
    char auto_helper[4096];
    char modules_dir[4096];
    int available_ct;
    int available_nat;
    int fail_load_ct;
    int fail_load_nat;
    int fail_unload_ct;
    int fail_unload_nat;
    int fail_nft;
    int nft_reference;
    int nft_declared_only;
    unsigned int nat_refs;
};

static void join(char *out, size_t len, const char *a, const char *b) {
    assert(snprintf(out, len, "%s/%s", a, b) < (int)len);
}

static void mkdir_ok(const char *path) {
    assert(mkdir(path, 0755) == 0 || errno == EEXIST);
}

static void write_text(const char *path, const char *text) {
    FILE *fp = fopen(path, "w");
    assert(fp);
    assert(fputs(text, fp) >= 0);
    assert(fclose(fp) == 0);
}

static char *read_text(const char *path) {
    FILE *fp = fopen(path, "r");
    long length;
    char *data;
    assert(fp);
    assert(fseek(fp, 0, SEEK_END) == 0);
    length = ftell(fp);
    assert(length >= 0 && fseek(fp, 0, SEEK_SET) == 0);
    data = calloc((size_t)length + 1, 1);
    assert(data);
    assert(fread(data, 1, (size_t)length, fp) == (size_t)length);
    fclose(fp);
    return data;
}

static void module_set(struct fixture *f, const char *module, int loaded,
                       const char *ports, int writable) {
    char path[4096], params[4096], ports_path[4096];
    join(path, sizeof(path), f->sys_module, module);
    if (!loaded) {
        if (ports) {
            join(ports_path, sizeof(ports_path), path, "parameters/ports");
            unlink(ports_path);
            join(params, sizeof(params), path, "parameters");
            rmdir(params);
        }
        rmdir(path);
        return;
    }
    mkdir_ok(path);
    if (ports) {
        join(params, sizeof(params), path, "parameters");
        mkdir_ok(params);
        join(ports_path, sizeof(ports_path), params, "ports");
        write_text(ports_path, ports);
        assert(chmod(ports_path, writable ? 0644 : 0444) == 0);
    }
}

static void proc_modules_write(struct fixture *f, int ct, int nat,
                               unsigned int ct_refs, const char *ct_users) {
    char text[2048] = "";
    size_t used = 0;
    if (nat)
        used += (size_t)snprintf(text + used, sizeof(text) - used,
            "nf_nat_ftp 12288 %u - Live 0x0\n", f->nat_refs);
    if (ct)
        used += (size_t)snprintf(text + used, sizeof(text) - used,
            "nf_conntrack_ftp 16384 %u %s Live 0x0\n",
            ct_refs, ct_users ? ct_users : "-");
    write_text(f->proc_modules, text);
}

static void fixture_init(struct fixture *f, const char *root) {
    memset(f, 0, sizeof(*f));
    snprintf(f->root, sizeof(f->root), "%s", root);
    join(f->sys_module, sizeof(f->sys_module), root, "sys_module");
    join(f->module_root, sizeof(f->module_root), root, "module_root");
    join(f->proc_modules, sizeof(f->proc_modules), root, "proc_modules");
    join(f->conntrack, sizeof(f->conntrack), root, "nf_conntrack");
    join(f->auto_helper, sizeof(f->auto_helper), root, "auto_helper");
    join(f->modules_dir, sizeof(f->modules_dir), root, "modules.d");
    mkdir_ok(f->sys_module);
    mkdir_ok(f->module_root);
    mkdir_ok(f->modules_dir);
    write_text(f->proc_modules, "");
    write_text(f->conntrack, "");
    write_text(f->auto_helper, "0\n");
    {
        char path[4096];
        join(path, sizeof(path), f->module_root, "nf_conntrack_ftp.ko");
        write_text(path, "module");
        join(path, sizeof(path), f->module_root, "nf_nat_ftp.ko");
        write_text(path, "module");
    }
}

static int arg_has(char *const argv[], const char *value) {
    size_t i;
    for (i = 0; argv[i]; i++) {
        if (!strcmp(argv[i], value)) return 1;
    }
    return 0;
}

/* strdup is not visible under a strict -std=c11 glibc build. */
static char *dup_text(const char *text) {
    size_t len = strlen(text);
    char *copy = malloc(len + 1);
    assert(copy != NULL);
    memcpy(copy, text, len + 1);
    return copy;
}

static int fake_runner(void *context, const char *path, char *const argv[],
                       size_t output_limit, int timeout_ms,
                       struct jmx_system_alg_command_result *result) {
    struct fixture *f = context;
    const char *module = argv[1];
    int dry_run = arg_has(argv, "-n");
    (void)output_limit;
    (void)timeout_ms;
    memset(result, 0, sizeof(*result));
    result->exit_code = 0;
    if (strstr(path, "nft")) {
        if (f->fail_nft) result->exit_code = 1;
        else result->output = dup_text(f->nft_reference ?
            "ct helper ftp { type ftp protocol tcp; }\n"
            "tcp dport 21 ct helper set \"ftp\"\n" : "table inet fw4 {}\n");
        if (f->nft_declared_only) {
            free(result->output);
            result->output = dup_text("ct helper ftp { type ftp protocol tcp; }\n");
        }
        result->output_len = result->output ? strlen(result->output) : 0;
        return 0;
    }
    if (dry_run) {
        module = argv[3];
        if ((!strcmp(module, "nf_conntrack_ftp") && !f->available_ct) ||
            (!strcmp(module, "nf_nat_ftp") && !f->available_nat))
            result->exit_code = 1;
        return 0;
    }
    if (strstr(path, "modprobe")) {
        const char *ports = NULL;
        module = argv[1];
        if (argv[2] && !strncmp(argv[2], "ports=", 6)) ports = argv[2] + 6;
        if (!strcmp(module, "nf_conntrack_ftp")) {
            if (f->fail_load_ct) result->exit_code = 1;
            else module_set(f, module, 1, ports ? ports : "21", 0);
        } else if (!strcmp(module, "nf_nat_ftp")) {
            if (f->fail_load_nat) result->exit_code = 1;
            else module_set(f, module, 1, NULL, 0);
        }
        {
            char ct[4096], nat[4096];
            join(ct, sizeof(ct), f->sys_module, "nf_conntrack_ftp");
            join(nat, sizeof(nat), f->sys_module, "nf_nat_ftp");
            proc_modules_write(f, access(ct, F_OK) == 0, access(nat, F_OK) == 0,
                               access(nat, F_OK) == 0 ? 1 : 0,
                               access(nat, F_OK) == 0 ? "nf_nat_ftp," : "-");
        }
        return 0;
    }
    if (strstr(path, "rmmod")) {
        module = argv[1];
        if (!strcmp(module, "nf_conntrack_ftp")) {
            if (f->fail_unload_ct) result->exit_code = 1;
            else module_set(f, module, 0, "21", 0);
        } else if (!strcmp(module, "nf_nat_ftp")) {
            if (f->fail_unload_nat) result->exit_code = 1;
            else module_set(f, module, 0, NULL, 0);
        }
        {
            char ct[4096], nat[4096];
            join(ct, sizeof(ct), f->sys_module, "nf_conntrack_ftp");
            join(nat, sizeof(nat), f->sys_module, "nf_nat_ftp");
            proc_modules_write(f, access(ct, F_OK) == 0, access(nat, F_OK) == 0,
                               access(nat, F_OK) == 0 ? 1 : 0,
                               access(nat, F_OK) == 0 ? "nf_nat_ftp," : "-");
        }
        return 0;
    }
    result->exit_code = 127;
    return 0;
}

static void fake_free(void *context, struct jmx_system_alg_command_result *result) {
    (void)context;
    free(result->output);
    memset(result, 0, sizeof(*result));
}

static struct jmx_system_alg_options options_for(struct fixture *f) {
    struct jmx_system_alg_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.sys_module_root = f->sys_module;
    opts.module_root = f->module_root;
    opts.proc_modules_path = f->proc_modules;
    opts.conntrack_path = f->conntrack;
    opts.auto_helper_path = f->auto_helper;
    opts.modules_dir = f->modules_dir;
    opts.modprobe_path = "/fake/modprobe";
    opts.rmmod_path = "/fake/rmmod";
    opts.nft_path = "/fake/nft";
    opts.runner = fake_runner;
    opts.runner_free = fake_free;
    opts.runner_context = f;
    return opts;
}

static void startup_write(struct fixture *f, const char *text) {
    char path[4096];
    join(path, sizeof(path), f->modules_dir, "nf-nathelper");
    write_text(path, text);
}

static int startup_exists(struct fixture *f) {
    char path[4096];
    join(path, sizeof(path), f->modules_dir, "nf-nathelper");
    return access(path, F_OK) == 0;
}

static void test_missing_helper(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 1, "2121" };
    struct jmx_system_alg_result result;
    fixture_init(&f, root);
    {
        char path[4096];
        join(path, sizeof(path), f.module_root, "nf_conntrack_ftp.ko");
        unlink(path);
    }
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == JMX_SYSTEM_ALG_ERR_NOT_FOUND);
    assert(!startup_exists(&f));
    assert(!strcmp(result.failure_stage, "preflight"));
}

static void test_enable_and_readback(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 1, " 2121, 2021 " };
    struct jmx_system_alg_result result;
    char *persisted;
    fixture_init(&f, root);
    f.nft_reference = 1;
    startup_write(&f, "# keep this\nother_module\n");
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == 0);
    assert(result.persisted && result.applied && !result.reboot_required);
    assert(result.after.conntrack_loaded && result.after.nat_loaded);
    assert(!strcmp(result.after.ports, "2121,2021"));
    {
        char path[4096];
        join(path, sizeof(path), f.modules_dir, "nf-nathelper");
        persisted = read_text(path);
        assert(strstr(persisted, "# keep this\nother_module\n"));
        assert(strstr(persisted, "nf_conntrack_ftp ports=2121,2021\n"));
        free(persisted);
    }
}

static void test_reenable_replaces_existing_startup_lines(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 1, "2121" };
    struct jmx_system_alg_result result;
    char *persisted;
    fixture_init(&f, root);
    f.nft_reference = 1;
    startup_write(&f, "nf_conntrack_ftp ports=21\nnf_nat_ftp\nsch_cake\n");
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == 0);
    assert(result.persisted && result.applied);
    {
        char path[4096], *hit;
        join(path, sizeof(path), f.modules_dir, "nf-nathelper");
        persisted = read_text(path);
        hit = strstr(persisted, "nf_conntrack_ftp");
        assert(hit && !strstr(hit + 1, "nf_conntrack_ftp"));
        assert(!strstr(persisted, "ports=21\n"));
        assert(strstr(persisted, "nf_conntrack_ftp ports=2121\n"));
        assert(strstr(persisted, "sch_cake\n"));
        free(persisted);
    }
}

static void test_enable_without_runtime_reference_is_not_applied(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 1, "2121" };
    struct jmx_system_alg_result result;
    fixture_init(&f, root);
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == 0);
    assert(result.persisted && !result.applied && !result.running);
    assert(result.after.conntrack_loaded && result.after.nat_loaded);
}

static void test_loaded_readonly_ports_pending_reboot(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 1, "2121" };
    struct jmx_system_alg_result result;
    fixture_init(&f, root);
    module_set(&f, "nf_conntrack_ftp", 1, "21", 0);
    module_set(&f, "nf_nat_ftp", 1, NULL, 0);
    proc_modules_write(&f, 1, 1, 1, "nf_nat_ftp,");
    startup_write(&f, "nf_conntrack_ftp\nnf_nat_ftp\n");
    f.nft_reference = 1;
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == 0);
    assert(result.persisted && !result.applied && result.reboot_required);
    assert(!strcmp(result.after.ports, "21"));
    assert(!strcmp(result.after.persisted_ports, "2121"));
}

static void test_referenced_disable_refused(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 0, NULL };
    struct jmx_system_alg_result result;
    fixture_init(&f, root);
    module_set(&f, "nf_conntrack_ftp", 1, "21", 0);
    module_set(&f, "nf_nat_ftp", 1, NULL, 0);
    proc_modules_write(&f, 1, 1, 3, "nf_nat_ftp,");
    startup_write(&f, "nf_conntrack_ftp\nnf_nat_ftp\n");
    f.nft_reference = 1;
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == JMX_SYSTEM_ALG_ERR_BUSY);
    assert(startup_exists(&f));
    assert(!strcmp(result.failure_stage, "preflight_references"));
}

static void test_declared_only_disable_allowed(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 0, NULL };
    struct jmx_system_alg_result result;
    fixture_init(&f, root);
    module_set(&f, "nf_conntrack_ftp", 1, "21", 0);
    module_set(&f, "nf_nat_ftp", 1, NULL, 0);
    proc_modules_write(&f, 1, 1, 1, "nf_nat_ftp,");
    startup_write(&f, "nf_conntrack_ftp\nnf_nat_ftp\n");
    f.nft_declared_only = 1;
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == 0);
    assert(!result.persisted && result.applied);
    assert(!result.after.conntrack_loaded && !result.after.nat_loaded);
}

static void test_disable_preserves_unrelated_startup_lines(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 0, NULL };
    struct jmx_system_alg_result result;
    char *remaining;
    fixture_init(&f, root);
    module_set(&f, "nf_conntrack_ftp", 1, "21", 0);
    module_set(&f, "nf_nat_ftp", 1, NULL, 0);
    proc_modules_write(&f, 1, 1, 1, "nf_nat_ftp,");
    startup_write(&f, "# provided by kmod package\nifb numifbs=0\n"
                      "nf_conntrack_ftp ports=21\nnf_nat_ftp\nsch_cake\n");
    f.nft_declared_only = 1;
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == 0);
    assert(!result.persisted && result.applied);
    assert(startup_exists(&f));
    {
        char path[4096];
        join(path, sizeof(path), f.modules_dir, "nf-nathelper");
        remaining = read_text(path);
        assert(!strcmp(remaining,
            "# provided by kmod package\nifb numifbs=0\nsch_cake\n"));
        free(remaining);
    }
}

static void test_nat_dependency_refuses_disable(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 0, NULL };
    struct jmx_system_alg_result result;
    fixture_init(&f, root);
    module_set(&f, "nf_conntrack_ftp", 1, "21", 0);
    module_set(&f, "nf_nat_ftp", 1, NULL, 0);
    proc_modules_write(&f, 1, 1, 0, "-");
    startup_write(&f, "nf_conntrack_ftp\nnf_nat_ftp\n");
    f.nat_refs = 1;
    proc_modules_write(&f, 1, 1, 0, "-");
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == JMX_SYSTEM_ALG_ERR_BUSY);
    assert(!strcmp(result.failure_stage, "preflight_references"));
}

static void test_usage_probe_fail_closed(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 0, NULL };
    struct jmx_system_alg_result result;
    fixture_init(&f, root);
    module_set(&f, "nf_conntrack_ftp", 1, "21", 0);
    module_set(&f, "nf_nat_ftp", 1, NULL, 0);
    proc_modules_write(&f, 1, 1, 1, "nf_nat_ftp,");
    unlink(f.conntrack);
    f.fail_nft = 1;
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == JMX_SYSTEM_ALG_ERR_PROBE);
    assert(!strcmp(result.failure_stage, "preflight_usage_probe"));
}

static void test_nat_load_failure_rolls_back(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 1, "2121" };
    struct jmx_system_alg_result result;
    fixture_init(&f, root);
    f.fail_load_nat = 1;
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == JMX_SYSTEM_ALG_ERR_EXEC);
    assert(result.rollback_attempted && result.rollback_succeeded);
    assert(!result.after.conntrack_loaded && !result.after.nat_loaded);
    assert(!startup_exists(&f));
}

static void test_unload_failure_rolls_back(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 0, NULL };
    struct jmx_system_alg_result result;
    char *original;
    fixture_init(&f, root);
    module_set(&f, "nf_conntrack_ftp", 1, "21", 0);
    module_set(&f, "nf_nat_ftp", 1, NULL, 0);
    proc_modules_write(&f, 1, 1, 1, "nf_nat_ftp,");
    startup_write(&f, "# original\nnf_conntrack_ftp ports=21\nnf_nat_ftp\n");
    f.fail_unload_ct = 1;
    opts = options_for(&f);
    assert(jmx_system_alg_apply(&opts, &req, &result) == JMX_SYSTEM_ALG_ERR_EXEC);
    assert(result.rollback_attempted && result.rollback_succeeded);
    assert(result.after.conntrack_loaded && result.after.nat_loaded);
    assert(!strcmp(result.after.ports, "21"));
    {
        char path[4096];
        join(path, sizeof(path), f.modules_dir, "nf-nathelper");
        original = read_text(path);
        assert(!strcmp(original,
            "# original\nnf_conntrack_ftp ports=21\nnf_nat_ftp\n"));
        free(original);
    }
}

static void test_persist_failure_restores_runtime(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_FTP, 1, "2121" };
    struct jmx_system_alg_result result;
    fixture_init(&f, root);
    opts = options_for(&f);
    assert(chmod(f.modules_dir, 0555) == 0);
    assert(jmx_system_alg_apply(&opts, &req, &result) == JMX_SYSTEM_ALG_ERR_IO);
    assert(result.rollback_attempted && result.rollback_succeeded);
    assert(!strcmp(result.failure_stage, "persist"));
    assert(!result.after.conntrack_loaded && !result.after.nat_loaded);
}

static void test_h323_ports_unsupported(const char *root) {
    struct fixture f;
    struct jmx_system_alg_options opts;
    struct jmx_system_alg_request req = { JMX_SYSTEM_ALG_H323, 1, "1720" };
    struct jmx_system_alg_result result;
    struct jmx_system_alg_state state;
    char error[160] = "";
    fixture_init(&f, root);
    opts = options_for(&f);
    assert(jmx_system_alg_probe(&opts, JMX_SYSTEM_ALG_H323, &state,
                                error, sizeof(error)) == 0);
    assert(!state.ports_supported && !state.ports[0]);
    assert(jmx_system_alg_apply(&opts, &req, &result) ==
           JMX_SYSTEM_ALG_ERR_UNSUPPORTED);
    assert(!strcmp(result.error, "module_has_no_ports_parameter"));
}

int main(int argc, char **argv) {
    char path[4096];
    assert(argc == 2);
#define RUN_TEST(name) do { \
    assert(snprintf(path, sizeof(path), "%s/%s", argv[1], #name) < (int)sizeof(path)); \
    mkdir_ok(path); \
    name(path); \
} while (0)
    RUN_TEST(test_missing_helper);
    RUN_TEST(test_enable_and_readback);
    RUN_TEST(test_reenable_replaces_existing_startup_lines);
    RUN_TEST(test_enable_without_runtime_reference_is_not_applied);
    RUN_TEST(test_loaded_readonly_ports_pending_reboot);
    RUN_TEST(test_referenced_disable_refused);
    RUN_TEST(test_declared_only_disable_allowed);
    RUN_TEST(test_disable_preserves_unrelated_startup_lines);
    RUN_TEST(test_nat_dependency_refuses_disable);
    RUN_TEST(test_usage_probe_fail_closed);
    RUN_TEST(test_nat_load_failure_rolls_back);
    RUN_TEST(test_unload_failure_rolls_back);
    RUN_TEST(test_persist_failure_restores_runtime);
    RUN_TEST(test_h323_ports_unsupported);
    puts("system_alg_runtime: PASS");
    return 0;
}
'''


def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        temp = Path(td)
        harness = temp / "system_alg_runtime_harness.c"
        binary = temp / "system_alg_runtime_harness"
        fixture = temp / "fixture"
        fixture.mkdir()
        harness.write_text(HARNESS, encoding="utf-8")
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror"]
        if sys.platform.startswith("linux"):
            flags.append("-Wno-format-truncation")
        subprocess.run([
            os.environ.get("CC", "cc"), *flags, "-I", str(ROOT),
            str(harness), str(SRC), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary), str(fixture)], check=True)


if __name__ == "__main__":
    main()
