// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Run real startup without listeners, UCI, databases or live ubus.
 * Build against target headers/libraries with -Isrc -Isrc/webd -lubus -lubox.
 */
#include <assert.h>
#include <errno.h>
#include <sys/wait.h>
#include <libubus.h>

#define main fixture_webd_main
#include "../src/webd/webd_main.c"
#undef main

static pid_t fixture_child;
static int fixture_reaped;
static int fixture_errno;
static struct uloop_timeout fixture_timer;

static void fixture_reap(struct uloop_timeout *timer)
{
    int status = 0;
    pid_t result;

    (void)timer;
    result = waitpid(fixture_child, &status, WNOHANG);
    fixture_errno = result < 0 ? errno : 0;
    fixture_reaped = result == fixture_child &&
                     WIFEXITED(status) && WEXITSTATUS(status) == 23;
    uloop_end();
}

int jmx_app_api_init(const char *bind_addr, int port)
{
    (void)bind_addr;
    (void)port;
    fixture_child = fork();
    assert(fixture_child >= 0);
    if (fixture_child == 0) {
        usleep(50000);
        _exit(23);
    }
    fixture_timer.cb = fixture_reap;
    assert(uloop_timeout_set(&fixture_timer, 250) == 0);
    return 0;
}

void jmx_app_api_done(void)
{
    if (!fixture_reaped && fixture_errno != ECHILD) {
        kill(fixture_child, SIGKILL);
        while (waitpid(fixture_child, NULL, 0) < 0 && errno == EINTR) {}
    }
}

int feature_registry_ubus_start(void)
{
    char missing_socket[128];
    struct ubus_context *ctx;

    /* ubus_connect initializes uloop again even when no server is reachable. */
    snprintf(missing_socket, sizeof(missing_socket),
             "/tmp/webd-reaper-fixture-%ld.sock", (long)getpid());
    assert(access(missing_socket, F_OK) != 0 && errno == ENOENT);
    ctx = ubus_connect(missing_socket);
    assert(!ctx);
    return 0;
}
void feature_registry_ubus_stop(void) {}

int webd_upload_cleanup_expired(time_t now, size_t *deleted_count,
                               char *error, size_t error_size)
{
    (void)now;
    (void)deleted_count;
    (void)error;
    (void)error_size;
    return 0;
}

void webd_upload_cleanup_status_get(struct webd_upload_cleanup_status *status)
{
    memset(status, 0, sizeof(*status));
}

int main(void)
{
    char *argv[] = { "webd-reaper-fixture", NULL };
    int result = fixture_webd_main(1, argv);

    printf("webd_startup_child_reaper result=%d owned_exit=%d errno=%d\n",
           result, fixture_reaped, fixture_errno);
    return result == 0 && fixture_reaped ? 0 : 1;
}
