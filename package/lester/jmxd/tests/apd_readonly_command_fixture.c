// SPDX-License-Identifier: GPL-2.0-or-later
#include "apd/apd_readonly_command.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int child_mode(const char *mode)
{
    if (!strcmp(mode, "child-ok")) {
        fputs("fixture-ok", stdout);
        return 0;
    }
    if (!strcmp(mode, "child-fail"))
        return 3;
    if (!strcmp(mode, "child-sleep")) {
        sleep(2);
        return 0;
    }
    if (!strcmp(mode, "child-large")) {
        char block[1024];
        int i;

        memset(block, 'x', sizeof(block));
        for (i = 0; i < 16; i++)
            fwrite(block, 1, sizeof(block), stdout);
        return ferror(stdout) ? 1 : 0;
    }
    return 2;
}

int main(int argc, char **argv)
{
    struct apd_command_result result = { 0 };
    char *child_argv[3];
    const char *child;
    int rc;

    if (argc != 2)
        return 2;
    if (!strncmp(argv[1], "child-", 6))
        return child_mode(argv[1]);
    if (!strcmp(argv[1], "success"))
        child = "child-ok";
    else if (!strcmp(argv[1], "failure"))
        child = "child-fail";
    else if (!strcmp(argv[1], "timeout"))
        child = "child-sleep";
    else if (!strcmp(argv[1], "large"))
        child = "child-large";
    else if (!strcmp(argv[1], "ignored")) {
        signal(SIGCHLD, SIG_IGN);
        child = "child-ok";
    } else {
        return 2;
    }
    child_argv[0] = argv[0];
    child_argv[1] = (char *)child;
    child_argv[2] = NULL;
    rc = apd_readonly_command(argv[0], child_argv, &result);
    printf("rc=%d exit=%d timeout=%d output_limited=%d length=%zu text=%s\n", rc,
           result.exit_status, result.timed_out, result.output_limited, result.length,
           result.text ? result.text : "");
    apd_command_result_free(&result);
    return 0;
}
