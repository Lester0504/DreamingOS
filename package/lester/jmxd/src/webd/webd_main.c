// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt Web Console BFF/API daemon. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <execinfo.h>
#include <libubox/uloop.h>

#include "jmx_app_api.h"
#include "webd_upload_staging.h"
#include "jmx_feature_registry.h"
#include "api/api_ad_analyzer.h"

#define WEBD_UPLOAD_GC_INTERVAL_MS (10 * 60 * 1000)

static struct uloop_timeout g_upload_gc_timer;

static void webd_upload_gc_run(struct uloop_timeout *timer)
{
    struct webd_upload_cleanup_status status;
    char error[96] = "";

    (void)webd_upload_cleanup_expired(time(NULL), NULL, error, sizeof(error));
    webd_upload_cleanup_status_get(&status);
    if (status.deleted_count || status.recovered_count || status.failed_count) {
        fprintf(stderr,
                "[dreamingwrt-webd] upload-gc scanned=%zu deleted=%zu "
                "recovered=%zu busy=%zu failed=%zu error=%s\n",
                status.scanned_count, status.deleted_count,
                status.recovered_count, status.busy_count,
                status.failed_count, error[0] ? error : "none");
    }
    if (timer)
        uloop_timeout_set(timer, WEBD_UPLOAD_GC_INTERVAL_MS);
}

static void webd_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

static const char *sig_name(int s)
{
    switch (s) {
    case SIGSEGV: return "SIGSEGV";
    case SIGABRT: return "SIGABRT";
    case SIGBUS:  return "SIGBUS";
    case SIGFPE:  return "SIGFPE";
    default:      return "UNKNOWN";
    }
}

static void webd_crash_handler(int signo, siginfo_t *info, void *ucontext)
{
    void *bt[32];
    int frames;
    char buf[256];
    int fd = STDERR_FILENO;
    (void)ucontext;

    snprintf(buf, sizeof(buf),
             "\n[webd-CRASH] %s (signal %d) at address %p\n",
             sig_name(signo), signo, info ? info->si_addr : NULL);
    /*
     * Crash path: async-signal-safe writes only, and nothing sensible to do if
     * stderr is gone. The result is discarded through (void)! because a plain
     * (void) cast does not satisfy warn_unused_result.
     */
    (void)!write(fd, buf, strlen(buf));

    frames = backtrace(bt, 32);
    snprintf(buf, sizeof(buf),
             "[webd-CRASH] backtrace (%d frames):\n", frames);
    (void)!write(fd, buf, strlen(buf));
    backtrace_symbols_fd(bt, frames, fd);
    (void)!write(fd, "\n", 1);

    /* Re-raise with default handler to generate core dump if available */
    signal(signo, SIG_DFL);
    raise(signo);
}

static void webd_install_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = webd_handle_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, NULL);

    /* Crash diagnostics: log backtrace on fatal signals */
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = webd_crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
}

int main(int argc, char **argv)
{
    int port = 0;
    const char *bind_addr = NULL;

    if (argc > 1)
        port = atoi(argv[1]);
    if (argc > 2)
        bind_addr = argv[2];

    /* Webd owns child reaping. ubus_connect() calls uloop_init() again, so
     * resetting SIGCHLD alone cannot keep uloop from stealing worker exits. */
    uloop_handle_sigchld = false;
    uloop_init();
    webd_install_signal_handlers();

    if (jmx_app_api_init(bind_addr, port) < 0) {
        fprintf(stderr, "[dreamingwrt-webd] failed to start API listener\n");
        uloop_done();
        return 1;
    }

    if (feature_registry_ubus_start() < 0) {
        fprintf(stderr,
                "[dreamingwrt-webd] feature registry start failed (non-fatal)\n");
    }

    g_upload_gc_timer.cb = webd_upload_gc_run;
    webd_upload_gc_run(&g_upload_gc_timer);
    ad_analyzer_start();

    uloop_run();
    uloop_timeout_cancel(&g_upload_gc_timer);
    ad_analyzer_stop();
    feature_registry_ubus_stop();
    jmx_app_api_done();
    uloop_done();
    return 0;
}
