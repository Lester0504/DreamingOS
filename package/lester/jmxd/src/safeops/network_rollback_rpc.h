// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DWRT_SAFEOPS_NETWORK_ROLLBACK_RPC_H
#define DWRT_SAFEOPS_NETWORK_ROLLBACK_RPC_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sqlite3.h>
#include <json-c/json.h>

/* -2: legacy task, 0: full DB+UCI rollback, -1: explicit failure. No shell. */
static inline int safeops_network_rollback_rpc(sqlite3 *db, int task_id,
                                                char *error, size_t error_size)
{
    sqlite3_stmt *st = NULL;
    int owned = 0, fd[2], status = 0, ok = 0;
    pid_t pid;
    char payload[64], output[2048];
    size_t used = 0;
    struct json_object *reply = NULL, *v = NULL;
    if (sqlite3_prepare_v2(db, "SELECT apply_executor FROM config_apply_tasks WHERE id=?1",
                           -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(st, 1, task_id);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *executor = (const char *)sqlite3_column_text(st, 0);
        owned = executor && !strcmp(executor, "netconfig_guarded_v1");
    }
    sqlite3_finalize(st);
    if (!owned) return -2;
    snprintf(error, error_size, "network_rollback_rpc_failed");
    snprintf(payload, sizeof(payload), "{\"task_id\":%d}", task_id);
    if (pipe(fd) != 0) return -1;
    pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); return -1; }
    if (pid == 0) {
        char *const argv[] = {"/bin/ubus", "-t", "45", "call", "dreamingwrt",
                              "network_transaction_rollback", payload, NULL};
        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);
        close(fd[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(fd[1]);
    for (;;) {
        char chunk[512];
        ssize_t n = read(fd[0], chunk, sizeof(chunk));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        if (used + (size_t)n < sizeof(output)) {
            memcpy(output + used, chunk, (size_t)n);
            used += (size_t)n;
        } else used = sizeof(output) - 1;
    }
    close(fd[0]);
    output[used] = '\0';
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) reply = json_tokener_parse(output);
    if (reply) {
        ok = json_object_object_get_ex(reply, "ok", &v) && json_object_get_boolean(v);
        ok = ok && json_object_object_get_ex(reply, "rollback_applied", &v) &&
            json_object_get_boolean(v);
        if (!ok && json_object_object_get_ex(reply, "error", &v))
            snprintf(error, error_size, "%s", json_object_get_string(v));
        json_object_put(reply);
    }
    if (ok && error_size) error[0] = '\0';
    return ok ? 0 : -1;
}
#endif
