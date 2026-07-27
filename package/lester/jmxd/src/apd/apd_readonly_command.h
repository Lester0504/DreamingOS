// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_READONLY_COMMAND_H
#define DREAMINGWRT_APD_READONLY_COMMAND_H

#include <stddef.h>

#ifndef APD_READONLY_COMMAND_TIMEOUT_MS
#define APD_READONLY_COMMAND_TIMEOUT_MS 2500
#endif

struct apd_command_result {
    char *text;
    size_t length;
    char *stderr_text;
    size_t stderr_length;
    int exit_status;
    int timed_out;
    int output_limited;
    int stderr_limited;
    const char *path;
};

int apd_readonly_command(const char *path, char *const argv[],
                         struct apd_command_result *result);
int apd_readonly_command_bounded(const char *path, char *const argv[],
                                 int timeout_ms, size_t output_limit,
                                 struct apd_command_result *result);
void apd_command_result_free(struct apd_command_result *result);

#endif
