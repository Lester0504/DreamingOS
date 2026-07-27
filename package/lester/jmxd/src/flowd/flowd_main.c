// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt flowd: flow policy workers and GeoIP country routing control plane. */
#include "flowd_internal.h"

#define FLOWD_GEOIP_AUTO_IMPORT_INITIAL_MS 15000
#define FLOWD_GEOIP_AUTO_IMPORT_RETRY_MS 300000
#define FLOWD_GEOIP_AUTO_IMPORT_MAX_ATTEMPTS 6

static struct uloop_timeout g_geoip_auto_import_timer;
static struct uloop_process g_geoip_auto_import_proc;
static const char *g_flowd_argv0;
static int g_geoip_auto_import_attempts;
static int g_geoip_auto_import_running;

static void flowd_geoip_auto_import_kill(pid_t pid)
{
    int i;

    if (pid <= 0)
        return;
    kill(pid, SIGTERM);
    for (i = 0; i < 20; i++) {
        pid_t r = waitpid(pid, NULL, WNOHANG);

        if (r == pid || (r < 0 && errno == ECHILD))
            return;
        usleep(50000);
    }
    kill(pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;
}

static void flowd_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

static void flowd_geoip_auto_import_schedule(int msec)
{
    if (g_geoip_auto_import_attempts >= FLOWD_GEOIP_AUTO_IMPORT_MAX_ATTEMPTS)
        return;
    uloop_timeout_set(&g_geoip_auto_import_timer, msec);
}

static void flowd_geoip_auto_import_done(struct uloop_process *p, int ret)
{
    int ok = WIFEXITED(ret) && WEXITSTATUS(ret) == 0;

    (void)p;
    g_geoip_auto_import_running = 0;
    if (!ok && flowd_geoip_auto_import_enabled())
        flowd_geoip_auto_import_schedule(FLOWD_GEOIP_AUTO_IMPORT_RETRY_MS);
}

static void flowd_geoip_auto_import_cb(struct uloop_timeout *t)
{
    pid_t pid;

    (void)t;
    if (g_geoip_auto_import_running || !flowd_geoip_auto_import_enabled())
        return;
    g_geoip_auto_import_attempts++;
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[dreamingwrt-flowd] geoip auto import fork failed: %s\n", strerror(errno));
        flowd_geoip_auto_import_schedule(FLOWD_GEOIP_AUTO_IMPORT_RETRY_MS);
        return;
    }
    if (pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        execlp(g_flowd_argv0 ? g_flowd_argv0 : "dreamingwrt-flowd",
               g_flowd_argv0 ? g_flowd_argv0 : "dreamingwrt-flowd",
               "--geoip-auto-import-once", NULL);
        fprintf(stderr, "[dreamingwrt-flowd] geoip auto import exec failed: %s\n", strerror(errno));
        _exit(127);
    }
    memset(&g_geoip_auto_import_proc, 0, sizeof(g_geoip_auto_import_proc));
    g_geoip_auto_import_proc.pid = pid;
    g_geoip_auto_import_proc.cb = flowd_geoip_auto_import_done;
    if (uloop_process_add(&g_geoip_auto_import_proc) != 0) {
        g_geoip_auto_import_running = 0;
        flowd_geoip_auto_import_kill(pid);
        fprintf(stderr, "[dreamingwrt-flowd] geoip auto import watch failed pid=%ld\n", (long)pid);
        return;
    }
    g_geoip_auto_import_running = 1;
}

static void flowd_geoip_auto_import_start(void)
{
    memset(&g_geoip_auto_import_timer, 0, sizeof(g_geoip_auto_import_timer));
    g_geoip_auto_import_timer.cb = flowd_geoip_auto_import_cb;
    if (flowd_geoip_auto_import_enabled())
        flowd_geoip_auto_import_schedule(FLOWD_GEOIP_AUTO_IMPORT_INITIAL_MS);
}

static int flowd_geoip_auto_import_command(void)
{
    int rc;

    if (flowd_db_init() != 0)
        return 1;
    rc = flowd_geoip_auto_import_once();
    flowd_db_close();
    return rc == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--geoip-auto-import-once"))
        return flowd_geoip_auto_import_command();

    g_flowd_argv0 = (argv && argv[0] && argv[0][0]) ? argv[0] : "dreamingwrt-flowd";
    signal(SIGINT, flowd_handle_signal);
    signal(SIGTERM, flowd_handle_signal);

    if (flowd_db_init() != 0)
        return 1;
    uloop_init();
    if (flowd_ubus_start() != 0) {
        uloop_done();
        flowd_db_close();
        return 1;
    }
    flowd_geoip_auto_import_start();

    fprintf(stderr, "[dreamingwrt-flowd] started config=%s\n", FLOWD_CONFIG_DB_PATH);
    uloop_run();

    uloop_timeout_cancel(&g_geoip_auto_import_timer);
    if (g_geoip_auto_import_running) {
        uloop_process_delete(&g_geoip_auto_import_proc);
        flowd_geoip_auto_import_kill(g_geoip_auto_import_proc.pid);
    }
    flowd_ubus_stop();
    uloop_done();
    flowd_db_close();
    return 0;
}
