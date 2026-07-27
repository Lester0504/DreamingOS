// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt Web Console BFF/API daemon. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/uloop.h>

#include "jmx_app_api.h"

static void webd_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
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
}

int main(int argc, char **argv)
{
    int port = 0;
    const char *bind_addr = NULL;

    if (argc > 1)
        port = atoi(argv[1]);
    if (argc > 2)
        bind_addr = argv[2];

    uloop_init();
    webd_install_signal_handlers();

    if (jmx_app_api_init(bind_addr, port) < 0) {
        fprintf(stderr, "[dreamingwrt-webd] failed to start API listener\n");
        uloop_done();
        return 1;
    }

    uloop_run();
    jmx_app_api_done();
    uloop_done();
    return 0;
}
