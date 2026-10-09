// SPDX-License-Identifier: GPL-2.0-or-later
#define _POSIX_C_SOURCE 200809L
#include "webd_support.h"
#include <curl/curl.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t stopping;
static void stop(int signal_number) { (void)signal_number; stopping = 1; }
int main(void)
{
    umask(0077); signal(SIGTERM, stop); signal(SIGINT, stop); signal(SIGPIPE, SIG_IGN);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    while (!stopping) {
        struct support_config config;
        if (!support_config_load(&config)) {
            if (!mkdir(SUPPORT_STATE_DIR, 0700) || access(SUPPORT_STATE_DIR, W_OK) == 0)
                (void)support_sync_step(&config);
        }
        struct timespec wait = {1, 0}; nanosleep(&wait, NULL);
    }
    curl_global_cleanup(); return 0;
}
