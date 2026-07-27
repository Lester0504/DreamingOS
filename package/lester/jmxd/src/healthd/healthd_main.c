// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#include <signal.h>
#include <unistd.h>

#include "../jmx.h"
#include "check_main.h"

int current_log_level = LOG_LEVEL_WARN;

static volatile sig_atomic_t healthd_stop = 0;

static void healthd_handle_stop(int sig)
{
    (void)sig;
    healthd_stop = 1;
}

static void healthd_handle_sigusr2(int sig)
{
    (void)sig;
    if (current_log_level < LOG_LEVEL_DEBUG)
        current_log_level++;
    else
        current_log_level = LOG_LEVEL_WARN;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    signal(SIGTERM, healthd_handle_stop);
    signal(SIGINT, healthd_handle_stop);
    signal(SIGUSR2, healthd_handle_sigusr2);

    return jmx_health_run(&healthd_stop);
}
