// SPDX-License-Identifier: GPL-2.0-or-later
#include "toolkit_internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

sqlite3 *g_toolkit_db;

int64_t toolkit_now_s(void) { return (int64_t)time(NULL); }

const char *toolkit_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *v = NULL;
    if (o && key && json_object_object_get_ex(o, key, &v) && v &&
        json_object_is_type(v, json_type_string) && json_object_get_string(v))
        return json_object_get_string(v);
    return def ? def : "";
}

int toolkit_json_int(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && v ? json_object_get_int(v) : def;
}

int toolkit_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *v = NULL;
    return o && json_object_object_get_ex(o, key, &v) && v ? json_object_get_boolean(v) : def;
}

struct json_object *toolkit_error(const char *code, const char *message)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "ok", json_object_new_boolean(0));
    json_object_object_add(o, "error", json_object_new_string(code ? code : "error"));
    json_object_object_add(o, "message", json_object_new_string(message ? message : ""));
    json_object_object_add(o, "source", json_object_new_string("dreamingwrt-toolkit"));
    return o;
}

struct json_object *toolkit_success(struct json_object *data, const char *source)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "ok", json_object_new_boolean(1));
    json_object_object_add(o, "data", data ? data : json_object_new_object());
    json_object_object_add(o, "source", json_object_new_string(source ? source : "dreamingwrt-toolkit"));
    json_object_object_add(o, "generated_at", json_object_new_int64(toolkit_now_s()));
    return o;
}

int toolkit_token_ok(const char *s, size_t max_len)
{
    if (!s || !s[0] || strlen(s) > max_len) return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '_' && *s != '-' && *s != '.' &&
            *s != ':' && *s != '/') return 0;
    return 1;
}

int toolkit_ifname_ok(const char *ifname)
{
    char path[256];
    if (!toolkit_token_ok(ifname, 15) || strchr(ifname, '/')) return 0;
    snprintf(path, sizeof(path), "/sys/class/net/%s", ifname);
    return access(path, F_OK) == 0;
}

int toolkit_mac_parse(const char *text, unsigned char mac[6])
{
    unsigned int b[6];
    char tail;
    if (!text || sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c",
                        &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (unsigned char)b[i];
    return 0;
}

int toolkit_runtime_dir_ready(void)
{
    if ((mkdir("/tmp/dreamingwrt", 0755) != 0 && errno != EEXIST) ||
        (mkdir(TOOLKIT_RUNTIME_DIR, 0700) != 0 && errno != EEXIST)) return -1;
    return chmod(TOOLKIT_RUNTIME_DIR, 0700);
}

int toolkit_exec_wait(char *const argv[], int timeout_ms, char *output,
                      size_t output_len, int *exit_code)
{
    int pipefd[2], status = 0, elapsed = 0;
    pid_t pid;
    size_t used = 0;
    if (!argv || !argv[0] || pipe(pipefd) != 0) return -1;
    pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]); close(pipefd[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);
    while (1) {
        ssize_t got;
        if (output && output_len > 1 && used < output_len - 1) {
            got = read(pipefd[0], output + used, output_len - used - 1);
            if (got > 0) used += (size_t)got;
        } else {
            char discard[512];
            got = read(pipefd[0], discard, sizeof(discard));
        }
        if (waitpid(pid, &status, WNOHANG) == pid) break;
        if (timeout_ms > 0 && elapsed >= timeout_ms) {
            kill(pid, SIGTERM); usleep(100000); kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            close(pipefd[0]);
            if (output && output_len) output[used] = 0;
            if (exit_code) *exit_code = 124;
            return -2;
        }
        usleep(20000); elapsed += 20;
    }
    while (output && output_len > 1 && used < output_len - 1) {
        ssize_t got = read(pipefd[0], output + used, output_len - used - 1);
        if (got <= 0) break;
        used += (size_t)got;
    }
    close(pipefd[0]);
    if (output && output_len) output[used] = 0;
    if (exit_code) *exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}
