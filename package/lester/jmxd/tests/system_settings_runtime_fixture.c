// SPDX-License-Identifier: GPL-2.0-or-later
#define _POSIX_C_SOURCE 200809L

#include "system/system_settings_runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FIXTURE_CRON_BEGIN "# BEGIN DREAMINGWRT NTP SYNC"

struct fake_runtime {
    const char *proc_swaps;
    const char *zram_device;
    int sysntpd_running;
    int log_running;
    int cron_running;
    int reload_calls;
    int fail_reload_call;
    const char *fail_action;
    int fail_action_once;
};

static void fail(const char *message)
{
    fprintf(stderr, "fixture failure: %s\n", message);
    exit(1);
}

static void mkdir_p(const char *path)
{
    char buffer[1024];
    char *p;

    if (snprintf(buffer, sizeof(buffer), "%s", path) >= (int)sizeof(buffer))
        fail("path too long");
    for (p = buffer + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buffer, 0755) != 0 && errno != EEXIST)
            fail("mkdir");
        *p = '/';
    }
    if (mkdir(buffer, 0755) != 0 && errno != EEXIST)
        fail("mkdir final");
}

static void write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    size_t length = strlen(text);

    if (fd < 0 || write(fd, text, length) != (ssize_t)length || close(fd) != 0)
        fail("write fixture file");
}

static char *read_text(const char *path)
{
    FILE *fp = fopen(path, "rb");
    long length = 0;
    char *data;

    if (!fp || fseek(fp, 0, SEEK_END) != 0 || (length = ftell(fp)) < 0 ||
        fseek(fp, 0, SEEK_SET) != 0) {
        if (fp)
            fclose(fp);
        fail("read fixture file");
    }
    data = calloc((size_t)length + 1U, 1U);
    if (!data || fread(data, 1, (size_t)length, fp) != (size_t)length ||
        fclose(fp) != 0)
        fail("read fixture data");
    return data;
}

static void expect(int condition, const char *message)
{
    if (!condition)
        fail(message);
}

static void expect_contains(const char *haystack, const char *needle,
                            const char *message)
{
    expect(haystack && needle && strstr(haystack, needle) != NULL, message);
}

static void expect_not_contains(const char *haystack, const char *needle,
                                const char *message)
{
    expect(!haystack || !needle || strstr(haystack, needle) == NULL, message);
}

static int fake_command(void *opaque, const char *const argv[], const char *input,
                        char *output, size_t output_len)
{
    struct fake_runtime *fake = opaque;
    const char *action;
    (void)input;

    if (!fake || !argv || !argv[0] || !argv[1])
        return -1;
    action = argv[1];
    if (!strcmp(action, "reload")) {
        fake->reload_calls++;
        if (fake->fail_reload_call == fake->reload_calls)
            return -1;
        if (strstr(argv[0], "sysntpd"))
            fake->sysntpd_running = 1;
        else if (strstr(argv[0], "/log"))
            fake->log_running = 1;
        else if (strstr(argv[0], "/cron"))
            fake->cron_running = 1;
        return 0;
    }
    if (!strcmp(action, "start") || !strcmp(action, "stop")) {
        int running = !strcmp(action, "start");

        if (strstr(argv[0], "sysntpd"))
            fake->sysntpd_running = running;
        else if (strstr(argv[0], "/log"))
            fake->log_running = running;
        else if (strstr(argv[0], "/cron"))
            fake->cron_running = running;
        return 0;
    }
    if (!strcmp(action, "status")) {
        int running = fake->sysntpd_running;

        if (strstr(argv[0], "/log"))
            running = fake->log_running;
        else if (strstr(argv[0], "/cron"))
            running = fake->cron_running;
        if (output && output_len)
            snprintf(output, output_len, "%s\n", running ? "running" : "stopped");
        return running ? 0 : 1;
    }
    if (strstr(argv[0], "busybox")) {
        if (fake->fail_action && !strcmp(fake->fail_action, action) &&
            fake->fail_action_once > 0) {
            fake->fail_action_once--;
            return -1;
        }
        if (!strcmp(action, "swapoff")) {
            write_text(fake->proc_swaps,
                       "Filename\tType\tSize\tUsed\tPriority\n");
            return 0;
        }
        if (!strcmp(action, "swapon")) {
            const char *priority = argv[4] ? argv[4] : "100";
            char line[256];

            snprintf(line, sizeof(line),
                     "Filename\tType\tSize\tUsed\tPriority\n%s\tfile\t262144\t0\t%s\n",
                     fake->zram_device, priority);
            write_text(fake->proc_swaps, line);
            return 0;
        }
        if (!strcmp(action, "mkswap"))
            return 0;
    }
    return -1;
}

static void fixture_paths(const char *root, struct ssr_paths *paths)
{
    char *system_config = NULL;
    char *root_crontab = NULL;
    char *zoneinfo = NULL;
    char *meminfo = NULL;
    char *proc_swaps = NULL;
    char *zram_sysfs = NULL;
    char *zram_device = NULL;
    char *uci = NULL;
    char *init_system = NULL;
    char *init_sysntpd = NULL;
    char *init_log = NULL;
    char *init_cron = NULL;
    char *busybox = NULL;
    char *ntpd = NULL;

#define P(name, suffix) do { \
    name = malloc(strlen(root) + strlen(suffix) + 1U); \
    if (!name) fail("alloc path"); \
    sprintf(name, "%s%s", root, suffix); \
} while (0)
    P(system_config, "/etc/config/system");
    P(root_crontab, "/etc/crontabs/root");
    P(zoneinfo, "/usr/share/zoneinfo");
    P(meminfo, "/proc/meminfo");
    P(proc_swaps, "/proc/swaps");
    P(zram_sysfs, "/sys/block/zram0");
    P(zram_device, "/dev/zram0");
    P(uci, "/sbin/uci");
    P(init_system, "/etc/init.d/system");
    P(init_sysntpd, "/etc/init.d/sysntpd");
    P(init_log, "/etc/init.d/log");
    P(init_cron, "/etc/init.d/cron");
    P(busybox, "/bin/busybox");
    P(ntpd, "/usr/sbin/ntpd");
#undef P
    memset(paths, 0, sizeof(*paths));
    paths->system_config = system_config;
    paths->root_crontab = root_crontab;
    paths->zoneinfo_dir = zoneinfo;
    paths->meminfo = meminfo;
    paths->proc_swaps = proc_swaps;
    paths->zram_sysfs = zram_sysfs;
    paths->zram_device = zram_device;
    paths->uci = uci;
    paths->init_system = init_system;
    paths->init_sysntpd = init_sysntpd;
    paths->init_log = init_log;
    paths->init_cron = init_cron;
    paths->busybox = busybox;
    paths->ntpd = ntpd;
}

static void setup_fixture(const char *root, struct ssr_paths *paths,
                          struct fake_runtime *fake, struct ssr_executor *executor)
{
    char path[1024];

    fixture_paths(root, paths);
    snprintf(path, sizeof(path), "%s/etc/config", root);
    mkdir_p(path);
    snprintf(path, sizeof(path), "%s/etc/crontabs", root);
    mkdir_p(path);
    mkdir_p(paths->zoneinfo_dir);
    mkdir_p(paths->zram_sysfs);
    snprintf(path, sizeof(path), "%s/dev", root);
    mkdir_p(path);
    snprintf(path, sizeof(path), "%s/proc", root);
    mkdir_p(path);
    write_text(paths->system_config,
                "config system\n"
                "\toption zonename 'UTC'\n"
                "\toption log_buffer_size '131072'\n"
                "\toption conloglevel '4'\n"
                "\toption cronloglevel '3'\n"
                "\toption log_remote '0'\n"
                "\toption log_port '514'\n"
                "\toption log_proto 'udp'\n"
                "\toption log_file '/tmp/old.log'\n"
                "\toption zram_size_mb '256'\n"
                "\toption zram_comp_algo 'lzo'\n"
                "\nconfig timeserver 'ntp'\n"
                "\toption enabled '1'\n"
                "\toption enable_server '0'\n"
                "\toption use_dhcp '0'\n"
                "\tlist server 'old.ntp.example'\n");
    write_text(paths->root_crontab, "0 2 * * * /usr/bin/keep-me\n");
    snprintf(path, sizeof(path), "%s/UTC", paths->zoneinfo_dir);
    write_text(path, "fixture zone\n");
    snprintf(path, sizeof(path), "%s/Asia", paths->zoneinfo_dir);
    mkdir_p(path);
    snprintf(path, sizeof(path), "%s/Asia/Shanghai", paths->zoneinfo_dir);
    write_text(path, "fixture zone\n");
    write_text(paths->meminfo, "MemTotal:       1024000 kB\n");
    {
        char swaps[512];

        snprintf(swaps, sizeof(swaps),
                 "Filename\tType\tSize\tUsed\tPriority\n"
                 "%s\tfile\t262144\t0\t5\n", paths->zram_device);
        write_text(paths->proc_swaps, swaps);
    }
    snprintf(path, sizeof(path), "%s/comp_algorithm", paths->zram_sysfs);
    write_text(path, "[lzo] lz4 zstd\n");
    snprintf(path, sizeof(path), "%s/disksize", paths->zram_sysfs);
    write_text(path, "268435456\n");
    snprintf(path, sizeof(path), "%s/reset", paths->zram_sysfs);
    write_text(path, "0\n");
    write_text(paths->zram_device, "zram\n");
    memset(fake, 0, sizeof(*fake));
    fake->proc_swaps = paths->proc_swaps;
    fake->zram_device = paths->zram_device;
    fake->sysntpd_running = 1;
    fake->log_running = 1;
    fake->cron_running = 1;
    executor->command = fake_command;
    executor->opaque = fake;
}

static void test_time_success_and_rollback(const char *root)
{
    struct ssr_paths paths;
    struct fake_runtime fake;
    struct ssr_executor executor;
    struct ssr_time_settings settings;
    struct ssr_result result;
    char *before;
    char *after;
    char path[1024];

    setup_fixture(root, &paths, &fake, &executor);
    before = read_text(paths.system_config);
    memset(&settings, 0, sizeof(settings));
    snprintf(settings.timezone, sizeof(settings.timezone), "Asia/Shanghai");
    settings.client_enabled = 1;
    settings.use_dhcp = 0;
    snprintf(settings.interval, sizeof(settings.interval), "1h");
    settings.server_count = 1;
    snprintf(settings.servers[0], sizeof(settings.servers[0]), "pool.ntp.org");
    expect(ssr_time_apply(&paths, &executor, &settings, &result) == 0,
           "time success path");
    expect(result.ok && result.fields[0].persisted && result.fields[0].applied &&
           result.fields[0].running && !result.rollback_attempted,
           "time result flags");
    after = read_text(paths.system_config);
    expect_contains(after, "option zonename 'Asia/Shanghai'", "timezone persisted");
    expect_contains(after, "list server 'pool.ntp.org'", "ntp list persisted");
    expect_not_contains(after, "old.ntp.example", "old ntp removed");
    free(after);
    snprintf(path, sizeof(path), "%s/etc/crontabs/root", root);
    after = read_text(path);
    expect_contains(after, FIXTURE_CRON_BEGIN, "fixed interval cron block");
    expect_contains(after, "0 * * * * /usr/sbin/ntpd -n -q -p pool.ntp.org", "cron command");
    free(after);
    setup_fixture(root, &paths, &fake, &executor);
    free(before);
    before = read_text(paths.system_config);
    fake.fail_reload_call = 1;
    expect(ssr_time_apply(&paths, &executor, &settings, &result) != 0,
           "time failure path");
    expect(result.rollback_attempted && result.rollback_ok &&
           result.fields[0].rollback, "time rollback flags");
    after = read_text(paths.system_config);
    expect(!strcmp(before, after), "time config restored");
    free(after);
    free(before);
}

static void test_time_empty_servers_and_service_restore(const char *root)
{
    struct ssr_paths paths;
    struct fake_runtime fake;
    struct ssr_executor executor;
    struct ssr_time_settings settings;
    struct ssr_result result;
    char *before;
    char *after;
    char path[1024];

    /* Empty server list with DHCP must drop the stale `list server`. */
    setup_fixture(root, &paths, &fake, &executor);
    memset(&settings, 0, sizeof(settings));
    snprintf(settings.timezone, sizeof(settings.timezone), "UTC");
    settings.client_enabled = 1;
    settings.use_dhcp = 1;
    snprintf(settings.interval, sizeof(settings.interval), "auto");
    settings.server_count = 0;
    expect(ssr_time_apply(&paths, &executor, &settings, &result) == 0,
           "time empty-server success path");
    after = read_text(paths.system_config);
    expect_not_contains(after, "list server", "empty server list cleared");
    expect_not_contains(after, "old.ntp.example", "stale ntp server removed");
    free(after);
    snprintf(path, sizeof(path), "%s/etc/crontabs/root", root);
    after = read_text(path);
    expect_not_contains(after, FIXTURE_CRON_BEGIN, "auto interval writes no cron block");
    free(after);

    /* Rollback must restore the cron service to its captured (stopped) state. */
    setup_fixture(root, &paths, &fake, &executor);
    fake.cron_running = 0;
    before = read_text(paths.system_config);
    memset(&settings, 0, sizeof(settings));
    snprintf(settings.timezone, sizeof(settings.timezone), "Asia/Shanghai");
    settings.client_enabled = 1;
    settings.use_dhcp = 0;
    snprintf(settings.interval, sizeof(settings.interval), "1h");
    settings.server_count = 1;
    snprintf(settings.servers[0], sizeof(settings.servers[0]), "pool.ntp.org");
    fake.fail_reload_call = 1;
    expect(ssr_time_apply(&paths, &executor, &settings, &result) != 0,
           "time failure with stopped cron");
    expect(result.rollback_attempted && result.rollback_ok,
           "time rollback with stopped cron");
    expect(fake.cron_running == 0, "cron service restored to stopped");
    after = read_text(paths.system_config);
    expect(!strcmp(before, after), "time config restored with stopped cron");
    free(after);
    free(before);
}

static void test_log_success_and_validation(const char *root)
{
    struct ssr_paths paths;
    struct fake_runtime fake;
    struct ssr_executor executor;
    struct ssr_log_settings settings;
    struct ssr_result result;
    char *before;
    char *after;

    setup_fixture(root, &paths, &fake, &executor);
    memset(&settings, 0, sizeof(settings));
    snprintf(settings.kernel_level, sizeof(settings.kernel_level), "warning");
    snprintf(settings.cron_level, sizeof(settings.cron_level), "error");
    settings.buffer_kib = 256;
    settings.remote_enabled = 1;
    snprintf(settings.remote_host, sizeof(settings.remote_host), "192.0.2.1");
    settings.remote_port = 1514;
    snprintf(settings.remote_protocol, sizeof(settings.remote_protocol), "tcp");
    snprintf(settings.file_path, sizeof(settings.file_path), "/tmp/system.log");
    expect(ssr_log_apply(&paths, &executor, &settings, &result) == 0,
           "log success path");
    expect(result.ok && result.fields[0].persisted && result.fields[0].applied &&
           result.fields[0].running, "log result flags");
    after = read_text(paths.system_config);
    expect_contains(after, "option log_buffer_size '262144'", "log buffer persisted");
    expect_contains(after, "option log_proto 'tcp'", "log protocol persisted");
    expect_contains(after, "option log_file '/tmp/system.log'", "log path persisted");
    free(after);
    before = read_text(paths.system_config);
    settings.local_level[0] = 'i';
    settings.local_level[1] = 'n';
    settings.local_level[2] = 'f';
    settings.local_level[3] = 'o';
    expect(ssr_log_apply(&paths, &executor, &settings, &result) != 0,
           "unsupported local log level rejected");
    expect(!result.rollback_attempted && !result.fields[0].persisted,
           "validation has no partial write");
    after = read_text(paths.system_config);
    expect(!strcmp(before, after), "invalid log config unchanged");
    free(after);
    free(before);
}

static void test_log_reload_failure_rollback(const char *root)
{
    struct ssr_paths paths;
    struct fake_runtime fake;
    struct ssr_executor executor;
    struct ssr_log_settings settings;
    struct ssr_result result;
    char *before;
    char *after;

    setup_fixture(root, &paths, &fake, &executor);
    fake.log_running = 0;
    before = read_text(paths.system_config);
    memset(&settings, 0, sizeof(settings));
    snprintf(settings.kernel_level, sizeof(settings.kernel_level), "warning");
    snprintf(settings.cron_level, sizeof(settings.cron_level), "error");
    settings.buffer_kib = 256;
    settings.remote_enabled = 0;
    settings.remote_port = 514;
    snprintf(settings.remote_protocol, sizeof(settings.remote_protocol), "udp");
    snprintf(settings.file_path, sizeof(settings.file_path), "/tmp/system.log");
    fake.fail_reload_call = 1;
    expect(ssr_log_apply(&paths, &executor, &settings, &result) != 0,
           "log reload failure path");
    expect(result.rollback_attempted && result.rollback_ok &&
           result.fields[0].rollback, "log rollback flags");
    expect(fake.log_running == 0, "log service restored to stopped");
    after = read_text(paths.system_config);
    expect(!strcmp(before, after), "log config restored after reload failure");
    free(after);
    free(before);
}

static void test_zram_success_and_failure(const char *root)
{
    struct ssr_paths paths;
    struct fake_runtime fake;
    struct ssr_executor executor;
    struct ssr_zram_settings settings;
    struct ssr_result result;
    char path[1024];
    char *data;

    setup_fixture(root, &paths, &fake, &executor);
    memset(&settings, 0, sizeof(settings));
    settings.size_mib = 128;
    snprintf(settings.algorithm, sizeof(settings.algorithm), "zstd");
    expect(ssr_zram_apply(&paths, &executor, &settings, &result) == 0,
           "zram success path");
    expect(result.ok && result.fields[0].persisted && result.fields[0].applied &&
           result.fields[0].running, "zram result flags");
    snprintf(path, sizeof(path), "%s/disksize", paths.zram_sysfs);
    data = read_text(path);
    expect_contains(data, "134217728", "zram size applied");
    free(data);
    data = read_text(paths.proc_swaps);
    expect_contains(data, "\t5\n", "zram priority preserved");
    free(data);
    setup_fixture(root, &paths, &fake, &executor);
    fake.fail_action = "swapon";
    fake.fail_action_once = 1;
    settings.size_mib = 64;
    snprintf(settings.algorithm, sizeof(settings.algorithm), "lz4");
    expect(ssr_zram_apply(&paths, &executor, &settings, &result) != 0,
           "zram activation failure path");
    expect(result.rollback_attempted && result.rollback_ok &&
           result.fields[0].rollback, "zram rollback flags");
    snprintf(path, sizeof(path), "%s/disksize", paths.zram_sysfs);
    data = read_text(path);
    expect_contains(data, "268435456", "zram size restored");
    free(data);
    data = read_text(paths.proc_swaps);
    expect_contains(data, "\t5\n", "zram priority restored");
    free(data);
    fake.fail_action = "invalid";
    settings.size_mib = 64;
    snprintf(settings.algorithm, sizeof(settings.algorithm), "not-supported");
    expect(ssr_zram_apply(&paths, &executor, &settings, &result) != 0,
           "invalid zram algorithm rejected");
    expect(!result.rollback_attempted, "invalid zram no partial write");
}

int main(int argc, char **argv)
{
    char root[1024];

    if (argc != 2)
        return fprintf(stderr, "usage: %s <temp-root>\n", argv[0]), 2;
    if (snprintf(root, sizeof(root), "%s", argv[1]) >= (int)sizeof(root))
        return 2;
    mkdir_p(root);
    test_time_success_and_rollback(root);
    test_time_empty_servers_and_service_restore(root);
    test_log_success_and_validation(root);
    test_log_reload_failure_rollback(root);
    test_zram_success_and_failure(root);
    puts("ok");
    return 0;
}
