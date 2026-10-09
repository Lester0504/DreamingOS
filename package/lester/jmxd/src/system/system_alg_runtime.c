// SPDX-License-Identifier: GPL-2.0-or-later
#define _POSIX_C_SOURCE 200809L

#include "system_alg_runtime.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ALG_DEFAULT_SYS_MODULE_ROOT "/sys/module"
#define ALG_DEFAULT_MODULE_ROOT "/lib/modules"
#define ALG_DEFAULT_PROC_MODULES "/proc/modules"
#define ALG_DEFAULT_CONNTRACK "/proc/net/nf_conntrack"
#define ALG_DEFAULT_AUTO_HELPER "/proc/sys/net/netfilter/nf_conntrack_helper"
#define ALG_DEFAULT_MODULES_DIR "/etc/modules.d"
#define ALG_DEFAULT_MODPROBE "/sbin/modprobe"
#define ALG_DEFAULT_RMMOD "/sbin/rmmod"
#define ALG_DEFAULT_NFT "/usr/sbin/nft"
#define ALG_DEFAULT_TIMEOUT_MS 10000

struct alg_definition {
    const char *name;
    const char *conntrack_module;
    const char *nat_module;
    const char *startup_file;
    const char *nft_names[3];
    size_t nft_name_count;
    int ports_supported;
};

static const struct alg_definition alg_definitions[JMX_SYSTEM_ALG_HELPER_COUNT] = {
    { "ftp", "nf_conntrack_ftp", "nf_nat_ftp", "nf-nathelper",
      { "ftp", NULL, NULL }, 1, 1 },
    { "tftp", "nf_conntrack_tftp", "nf_nat_tftp", "nf-nathelper-tftp",
      { "tftp", NULL, NULL }, 1, 1 },
    { "sip", "nf_conntrack_sip", "nf_nat_sip", "nf-nathelper-sip",
      { "sip", NULL, NULL }, 1, 1 },
    { "h323", "nf_conntrack_h323", "nf_nat_h323", "nf-nathelper-h323",
      { "ras", "q.931", NULL }, 2, 0 }
};

struct alg_paths {
    const char *sys_module_root;
    const char *module_root;
    const char *proc_modules_path;
    const char *conntrack_path;
    const char *auto_helper_path;
    const char *modules_dir;
    const char *modprobe_path;
    const char *rmmod_path;
    const char *nft_path;
    int timeout_ms;
};

struct alg_file_snapshot {
    int exists;
    mode_t mode;
    char *data;
    size_t length;
};

struct alg_transaction_snapshot {
    struct jmx_system_alg_state state;
    struct alg_file_snapshot startup;
};

static void alg_set_error(char *out, size_t out_len, const char *format, ...)
{
    va_list args;

    if (!out || out_len == 0)
        return;
    va_start(args, format);
    vsnprintf(out, out_len, format, args);
    va_end(args);
}

static int alg_valid_helper(enum jmx_system_alg_helper helper)
{
    return helper >= JMX_SYSTEM_ALG_FTP &&
           helper < JMX_SYSTEM_ALG_HELPER_COUNT;
}

const char *jmx_system_alg_helper_name(enum jmx_system_alg_helper helper)
{
    return alg_valid_helper(helper) ? alg_definitions[helper].name : NULL;
}

int jmx_system_alg_helper_parse(const char *name,
                                enum jmx_system_alg_helper *helper_out)
{
    size_t i;

    if (!name || !helper_out)
        return JMX_SYSTEM_ALG_ERR_INVALID;
    for (i = 0; i < JMX_SYSTEM_ALG_HELPER_COUNT; i++) {
        if (strcmp(name, alg_definitions[i].name) == 0) {
            *helper_out = (enum jmx_system_alg_helper)i;
            return JMX_SYSTEM_ALG_OK;
        }
    }
    return JMX_SYSTEM_ALG_ERR_NOT_FOUND;
}

static void alg_resolve_paths(const struct jmx_system_alg_options *options,
                              struct alg_paths *paths)
{
    memset(paths, 0, sizeof(*paths));
    paths->sys_module_root = options && options->sys_module_root ?
        options->sys_module_root : ALG_DEFAULT_SYS_MODULE_ROOT;
    paths->module_root = options && options->module_root ?
        options->module_root : ALG_DEFAULT_MODULE_ROOT;
    paths->proc_modules_path = options && options->proc_modules_path ?
        options->proc_modules_path : ALG_DEFAULT_PROC_MODULES;
    paths->conntrack_path = options && options->conntrack_path ?
        options->conntrack_path : ALG_DEFAULT_CONNTRACK;
    paths->auto_helper_path = options && options->auto_helper_path ?
        options->auto_helper_path : ALG_DEFAULT_AUTO_HELPER;
    paths->modules_dir = options && options->modules_dir ?
        options->modules_dir : ALG_DEFAULT_MODULES_DIR;
    paths->modprobe_path = options && options->modprobe_path ?
        options->modprobe_path : ALG_DEFAULT_MODPROBE;
    paths->rmmod_path = options && options->rmmod_path ?
        options->rmmod_path : ALG_DEFAULT_RMMOD;
    paths->nft_path = options && options->nft_path ?
        options->nft_path : ALG_DEFAULT_NFT;
    paths->timeout_ms = options && options->command_timeout_ms > 0 ?
        options->command_timeout_ms : ALG_DEFAULT_TIMEOUT_MS;
}

static int64_t alg_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void jmx_system_alg_command_result_free(
    struct jmx_system_alg_command_result *result)
{
    if (!result)
        return;
    free(result->output);
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
}

static int alg_default_runner(void *context, const char *path,
                              char *const argv[], size_t output_limit,
                              int timeout_ms,
                              struct jmx_system_alg_command_result *result)
{
    int pipefd[2] = { -1, -1 };
    pid_t child;
    char *output = NULL;
    size_t used = 0;
    int status = 0, child_done = 0, eof = 0;
    int64_t deadline;

    (void)context;
    if (!path || !argv || !result || output_limit == 0 ||
        output_limit > JMX_SYSTEM_ALG_COMMAND_OUTPUT_MAX)
        return -1;
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
    output = calloc(output_limit + 1, 1);
    if (!output || pipe(pipefd) != 0) {
        free(output);
        return -1;
    }
    child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        free(output);
        return -1;
    }
    if (child == 0) {
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(path, argv);
        _exit(127);
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    (void)fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
    deadline = alg_now_ms() + (timeout_ms > 0 ? timeout_ms : ALG_DEFAULT_TIMEOUT_MS);
    while (!child_done || !eof) {
        struct pollfd pfd;
        int wait_ms = 20;
        ssize_t n;
        pid_t waited;

        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = pipefd[0];
        pfd.events = POLLIN | POLLHUP;
        if (deadline > 0) {
            int64_t remaining = deadline - alg_now_ms();
            if (remaining <= 0 && !child_done) {
                result->timed_out = 1;
                (void)kill(child, SIGKILL);
            } else if (remaining > 0 && remaining < wait_ms) {
                wait_ms = (int)remaining;
            }
        }
        (void)poll(&pfd, 1, wait_ms);
        for (;;) {
            char buffer[4096];

            n = read(pipefd[0], buffer, sizeof(buffer));
            if (n > 0) {
                size_t copy = (size_t)n;
                if (copy > output_limit - used) {
                    copy = output_limit - used;
                    result->truncated = 1;
                }
                if (copy > 0) {
                    memcpy(output + used, buffer, copy);
                    used += copy;
                }
                if ((size_t)n > copy)
                    result->truncated = 1;
                continue;
            }
            if (n == 0)
                eof = 1;
            break;
        }
        if (!child_done) {
            waited = waitpid(child, &status, WNOHANG);
            if (waited == child)
                child_done = 1;
        }
        if (result->timed_out && !child_done) {
            if (waitpid(child, &status, 0) == child)
                child_done = 1;
        }
    }
    close(pipefd[0]);
    output[used] = 0;
    result->output = output;
    result->output_len = used;
    if (WIFEXITED(status))
        result->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        result->term_signal = WTERMSIG(status);
    return 0;
}

static void alg_runner_free(const struct jmx_system_alg_options *options,
                            struct jmx_system_alg_command_result *result)
{
    if (options && options->runner_free)
        options->runner_free(options->runner_context, result);
    else
        jmx_system_alg_command_result_free(result);
}

static int alg_run(const struct jmx_system_alg_options *options,
                   const struct alg_paths *paths, const char *path,
                   char *const argv[], size_t output_limit,
                   struct jmx_system_alg_command_result *result)
{
    jmx_system_alg_runner_fn runner = options && options->runner ?
        options->runner : alg_default_runner;

    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
    if (runner(options ? options->runner_context : NULL, path, argv,
               output_limit, paths->timeout_ms, result) != 0)
        return -1;
    if (result->timed_out || result->truncated || result->term_signal != 0 ||
        result->exit_code != 0)
        return -1;
    return 0;
}

static int alg_join_path(char *out, size_t out_len, const char *left,
                         const char *right)
{
    int n;

    if (!out || out_len == 0 || !left || !right)
        return -1;
    n = snprintf(out, out_len, "%s/%s", left, right);
    return n >= 0 && (size_t)n < out_len ? 0 : -1;
}

static int alg_read_file(const char *path, char **data_out, size_t *length_out,
                         size_t limit)
{
    FILE *fp;
    char *data;
    size_t used = 0;

    if (!path || !data_out || !length_out || limit == 0)
        return -1;
    *data_out = NULL;
    *length_out = 0;
    fp = fopen(path, "rb");
    if (!fp)
        return -1;
    data = calloc(limit + 1, 1);
    if (!data) {
        fclose(fp);
        return -1;
    }
    while (used < limit) {
        size_t n = fread(data + used, 1, limit - used, fp);
        used += n;
        if (n == 0)
            break;
    }
    if (ferror(fp) || (!feof(fp) && used == limit)) {
        free(data);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    data[used] = 0;
    *data_out = data;
    *length_out = used;
    return 0;
}

static int alg_read_line(const char *path, char *out, size_t out_len)
{
    FILE *fp;

    if (!path || !out || out_len < 2)
        return -1;
    out[0] = 0;
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(out, out_len, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    out[strcspn(out, "\r\n")] = 0;
    return 0;
}

static int alg_file_snapshot_take(const char *path,
                                  struct alg_file_snapshot *snapshot)
{
    struct stat st;

    memset(snapshot, 0, sizeof(*snapshot));
    if (stat(path, &st) != 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    if (!S_ISREG(st.st_mode))
        return -1;
    snapshot->exists = 1;
    snapshot->mode = st.st_mode & 07777;
    if (alg_read_file(path, &snapshot->data, &snapshot->length, 64 * 1024) != 0)
        return -1;
    return 0;
}

static void alg_file_snapshot_free(struct alg_file_snapshot *snapshot)
{
    if (!snapshot)
        return;
    free(snapshot->data);
    memset(snapshot, 0, sizeof(*snapshot));
}

static int alg_fsync_directory(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY);
    int rc;

    if (fd < 0)
        return -1;
    rc = fsync(fd);
    close(fd);
    return rc;
}

static int alg_write_all(int fd, const char *data, size_t length)
{
    size_t written = 0;

    while (written < length) {
        ssize_t n = write(fd, data + written, length - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        written += (size_t)n;
    }
    return 0;
}

static int alg_atomic_write(const char *directory, const char *path,
                            const char *data, size_t length, mode_t mode)
{
    char temp[PATH_MAX];
    int fd = -1, rc = -1;
    unsigned int attempt;

    for (attempt = 0; attempt < 32; attempt++) {
        int n = snprintf(temp, sizeof(temp), "%s.tmp.%ld.%u", path,
                         (long)getpid(), attempt);
        if (n < 0 || (size_t)n >= sizeof(temp))
            return -1;
        fd = open(temp, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            return -1;
    }
    if (fd < 0)
        return -1;
    if (alg_write_all(fd, data, length) == 0 &&
        fchmod(fd, mode ? mode : 0644) == 0 && fsync(fd) == 0 &&
        close(fd) == 0) {
        fd = -1;
        if (rename(temp, path) == 0 && alg_fsync_directory(directory) == 0)
            rc = 0;
    }
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlink(temp);
    return rc;
}

static int alg_atomic_remove(const char *directory, const char *path)
{
    if (unlink(path) != 0 && errno != ENOENT)
        return -1;
    return alg_fsync_directory(directory);
}

static int alg_file_snapshot_restore(const char *directory, const char *path,
                                     const struct alg_file_snapshot *snapshot)
{
    if (snapshot->exists)
        return alg_atomic_write(directory, path, snapshot->data,
                                snapshot->length, snapshot->mode);
    return alg_atomic_remove(directory, path);
}

static int alg_module_loaded(const struct alg_paths *paths, const char *module)
{
    char path[PATH_MAX];
    struct stat st;

    return alg_join_path(path, sizeof(path), paths->sys_module_root, module) == 0 &&
           stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int alg_module_file_name(const char *name, const char *module)
{
    char expected[128];
    if (!name || !module)
        return 0;
    if (snprintf(expected, sizeof(expected), "%s.ko", module) < 0)
        return 0;
    if (!strcmp(name, expected))
        return 1;
    if (strncmp(name, expected, strlen(expected)) != 0)
        return 0;
    return name[strlen(expected)] == '.' &&
           (!strcmp(name + strlen(expected), ".gz") ||
            !strcmp(name + strlen(expected), ".xz") ||
            !strcmp(name + strlen(expected), ".zst"));
}

static int alg_module_file_available_at(const char *directory,
                                        const char *module, unsigned int depth)
{
    DIR *dir;
    struct dirent *entry;

    if (!directory || !module || depth > 8)
        return 0;
    dir = opendir(directory);
    if (!dir)
        return 0;
    while ((entry = readdir(dir)) != NULL) {
        char path[PATH_MAX];
        struct stat st;

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (alg_join_path(path, sizeof(path), directory, entry->d_name) != 0 ||
            lstat(path, &st) != 0)
            continue;
        if (S_ISREG(st.st_mode) &&
            alg_module_file_name(entry->d_name, module)) {
            closedir(dir);
            return 1;
        }
        if (S_ISDIR(st.st_mode) &&
            alg_module_file_available_at(path, module, depth + 1)) {
            closedir(dir);
            return 1;
        }
    }
    closedir(dir);
    return 0;
}

static int alg_module_available(const struct alg_paths *paths,
                                const char *module)
{
    return alg_module_loaded(paths, module) ||
           alg_module_file_available_at(paths->module_root, module, 0);
}

static int alg_parse_proc_modules(const struct alg_paths *paths,
                                  const struct alg_definition *definition,
                                  struct jmx_system_alg_state *state)
{
    FILE *fp = fopen(paths->proc_modules_path, "r");
    char line[4096];

    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char module[128] = "", users[2048] = "";
        unsigned long size = 0;
        unsigned int refcount = 0;
        int matched;

        matched = sscanf(line, "%127s %lu %u %2047s", module, &size,
                         &refcount, users);
        if (matched < 3)
            continue;
        if (strcmp(module, definition->conntrack_module) == 0) {
            char *save = NULL, *user;
            state->conntrack_refcount = refcount;
            if (matched >= 4 && strcmp(users, "-") != 0) {
                user = strtok_r(users, ",", &save);
                while (user) {
                    if (strcmp(user, definition->nat_module) != 0)
                        state->external_module_users++;
                    user = strtok_r(NULL, ",", &save);
                }
            }
        } else if (strcmp(module, definition->nat_module) == 0) {
            state->nat_refcount = refcount;
        }
    }
    fclose(fp);
    return 0;
}

static int alg_ports_path(const struct alg_paths *paths,
                          const struct alg_definition *definition,
                          char *out, size_t out_len)
{
    int n = snprintf(out, out_len, "%s/%s/parameters/ports",
                     paths->sys_module_root, definition->conntrack_module);
    return n >= 0 && (size_t)n < out_len ? 0 : -1;
}

static int alg_ports_read(const struct alg_paths *paths,
                          const struct alg_definition *definition,
                          char *out, size_t out_len, int *writable_out)
{
    char path[PATH_MAX];
    struct stat st;

    if (alg_ports_path(paths, definition, path, sizeof(path)) != 0 ||
        stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;
    if (writable_out)
        *writable_out = (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) != 0;
    return alg_read_line(path, out, out_len);
}

static char *alg_lower_copy(const char *input)
{
    size_t i, length;
    char *copy;

    if (!input)
        return NULL;
    length = strlen(input);
    copy = malloc(length + 1);
    if (!copy)
        return NULL;
    for (i = 0; i < length; i++)
        copy[i] = (char)tolower((unsigned char)input[i]);
    copy[length] = 0;
    return copy;
}

static void alg_probe_nft(const struct jmx_system_alg_options *options,
                          const struct alg_paths *paths,
                          const struct alg_definition *definition,
                          struct jmx_system_alg_state *state)
{
    struct jmx_system_alg_command_result result;
    char *argv[] = { (char *)paths->nft_path, "list", "ruleset", NULL };
    char *lower;
    size_t i;

    if (alg_run(options, paths, paths->nft_path, argv,
                JMX_SYSTEM_ALG_COMMAND_OUTPUT_MAX, &result) != 0) {
        alg_runner_free(options, &result);
        return;
    }
    lower = alg_lower_copy(result.output ? result.output : "");
    if (!lower) {
        alg_runner_free(options, &result);
        return;
    }
    state->nft_probe_ok = 1;
    for (i = 0; i < definition->nft_name_count; i++) {
        char declared[96], assigned_quoted[96], assigned_plain[96];
        const char *name = definition->nft_names[i];

        snprintf(declared, sizeof(declared), "ct helper %s", name);
        snprintf(assigned_quoted, sizeof(assigned_quoted),
                 "ct helper set \"%s\"", name);
        snprintf(assigned_plain, sizeof(assigned_plain),
                 "ct helper set %s", name);
        if (strstr(lower, declared))
            state->nft_declared = 1;
        if (strstr(lower, assigned_quoted) || strstr(lower, assigned_plain))
            state->nft_assigned = 1;
    }
    free(lower);
    alg_runner_free(options, &result);
}

static void alg_probe_conntrack(const struct alg_paths *paths,
                                const struct alg_definition *definition,
                                struct jmx_system_alg_state *state)
{
    FILE *fp = fopen(paths->conntrack_path, "r");
    char line[8192];

    if (!fp)
        return;
    state->conntrack_probe_ok = 1;
    while (fgets(line, sizeof(line), fp)) {
        char *lower = alg_lower_copy(line);
        size_t i;

        if (!lower) {
            state->conntrack_probe_ok = 0;
            break;
        }
        for (i = 0; i < definition->nft_name_count; i++) {
            char marker[64];
            snprintf(marker, sizeof(marker), "helper=%s",
                     definition->nft_names[i]);
            if (strstr(lower, marker)) {
                state->conntrack_active++;
                break;
            }
        }
        free(lower);
    }
    fclose(fp);
}

static void alg_probe_auto_helper(const struct alg_paths *paths,
                                  struct jmx_system_alg_state *state)
{
    char value[32];

    if (alg_read_line(paths->auto_helper_path, value, sizeof(value)) == 0) {
        state->auto_helper_known = 1;
        state->auto_helper_enabled = atoi(value) != 0;
    }
}

static int alg_line_module(const char *line, size_t length, const char *module,
                           char *ports, size_t ports_len)
{
    const char *cursor = line, *end = line + length;
    size_t module_len = strlen(module);

    while (cursor < end && isspace((unsigned char)*cursor))
        cursor++;
    if (cursor == end || *cursor == '#')
        return 0;
    if ((size_t)(end - cursor) < module_len ||
        strncmp(cursor, module, module_len) != 0 ||
        (cursor + module_len < end &&
         !isspace((unsigned char)cursor[module_len])))
        return 0;
    cursor += module_len;
    while (cursor < end) {
        const char *token, *token_end;
        while (cursor < end && isspace((unsigned char)*cursor))
            cursor++;
        token = cursor;
        while (cursor < end && !isspace((unsigned char)*cursor))
            cursor++;
        token_end = cursor;
        if (ports && ports_len > 0 && (size_t)(token_end - token) > 6 &&
            strncmp(token, "ports=", 6) == 0) {
            size_t copy = (size_t)(token_end - token - 6);
            if (copy >= ports_len)
                copy = ports_len - 1;
            memcpy(ports, token + 6, copy);
            ports[copy] = 0;
        }
    }
    return 1;
}

static void alg_probe_persistence(const struct alg_paths *paths,
                                  const struct alg_definition *definition,
                                  struct jmx_system_alg_state *state)
{
    char path[PATH_MAX];
    char *data = NULL, *cursor, *end;
    size_t length = 0;
    int have_conntrack = 0, have_nat = 0;

    if (alg_join_path(path, sizeof(path), paths->modules_dir,
                      definition->startup_file) != 0)
        return;
    if (alg_read_file(path, &data, &length, 64 * 1024) != 0) {
        if (errno == ENOENT) {
            state->persisted_known = 1;
            state->persisted = 0;
        }
        return;
    }
    state->persisted_known = 1;
    cursor = data;
    end = data + length;
    while (cursor < end) {
        char *line_end = memchr(cursor, '\n', (size_t)(end - cursor));
        size_t line_len = line_end ? (size_t)(line_end - cursor) :
                                     (size_t)(end - cursor);
        if (alg_line_module(cursor, line_len, definition->conntrack_module,
                            state->persisted_ports,
                            sizeof(state->persisted_ports)))
            have_conntrack = 1;
        if (alg_line_module(cursor, line_len, definition->nat_module,
                            NULL, 0))
            have_nat = 1;
        cursor = line_end ? line_end + 1 : end;
    }
    state->persisted = have_conntrack && have_nat;
    state->persisted_partial = have_conntrack != have_nat;
    free(data);
}

int jmx_system_alg_probe(const struct jmx_system_alg_options *options,
                         enum jmx_system_alg_helper helper,
                         struct jmx_system_alg_state *state,
                         char *error, size_t error_len)
{
    const struct alg_definition *definition;
    struct alg_paths paths;

    if (error && error_len)
        error[0] = 0;
    if (!state || !alg_valid_helper(helper)) {
        alg_set_error(error, error_len, "invalid_helper");
        return JMX_SYSTEM_ALG_ERR_INVALID;
    }
    memset(state, 0, sizeof(*state));
    definition = &alg_definitions[helper];
    alg_resolve_paths(options, &paths);
    state->helper = helper;
    snprintf(state->name, sizeof(state->name), "%s", definition->name);
    snprintf(state->conntrack_module, sizeof(state->conntrack_module), "%s",
             definition->conntrack_module);
    snprintf(state->nat_module, sizeof(state->nat_module), "%s",
             definition->nat_module);
    state->ports_supported = definition->ports_supported;
    state->conntrack_loaded = alg_module_loaded(&paths,
                                                definition->conntrack_module);
    state->nat_loaded = alg_module_loaded(&paths, definition->nat_module);
    state->conntrack_available = alg_module_available(&paths,
                                                      definition->conntrack_module);
    state->nat_available = alg_module_available(&paths,
                                                definition->nat_module);
    if (alg_parse_proc_modules(&paths, definition, state) != 0 &&
        (state->conntrack_loaded || state->nat_loaded)) {
        alg_set_error(error, error_len, "proc_modules_unavailable");
        return JMX_SYSTEM_ALG_ERR_PROBE;
    }
    if (state->ports_supported && state->conntrack_loaded)
        (void)alg_ports_read(&paths, definition, state->ports,
                             sizeof(state->ports), &state->ports_writable);
    alg_probe_nft(options, &paths, definition, state);
    alg_probe_conntrack(&paths, definition, state);
    alg_probe_auto_helper(&paths, state);
    alg_probe_persistence(&paths, definition, state);
    state->running_known = state->nft_probe_ok || state->conntrack_probe_ok ||
                           state->auto_helper_known;
    state->running = state->conntrack_loaded && state->nat_loaded &&
        (state->nft_assigned || state->conntrack_active > 0 ||
         state->auto_helper_enabled);
    return JMX_SYSTEM_ALG_OK;
}

static int alg_normalize_ports(const char *input, char *out, size_t out_len)
{
    const char *cursor;
    size_t used = 0;
    unsigned int count = 0;

    if (!input || !out || out_len < 2)
        return -1;
    cursor = input;
    while (*cursor) {
        unsigned long value = 0;
        const char *start;
        char token[8];
        int n;

        while (isspace((unsigned char)*cursor))
            cursor++;
        start = cursor;
        while (isdigit((unsigned char)*cursor)) {
            value = value * 10 + (unsigned long)(*cursor - '0');
            if (value > 65535)
                return -1;
            cursor++;
        }
        if (cursor == start || value == 0)
            return -1;
        while (isspace((unsigned char)*cursor))
            cursor++;
        if (*cursor && *cursor != ',')
            return -1;
        n = snprintf(token, sizeof(token), "%lu", value);
        if (n <= 0 || (size_t)n >= sizeof(token) ||
            used + (count ? 1U : 0U) + (size_t)n >= out_len)
            return -1;
        if (count)
            out[used++] = ',';
        memcpy(out + used, token, (size_t)n);
        used += (size_t)n;
        out[used] = 0;
        count++;
        if (*cursor == ',') {
            cursor++;
            if (!*cursor)
                return -1;
        }
    }
    return count > 0 ? 0 : -1;
}

static int alg_module_command(const struct jmx_system_alg_options *options,
                              const struct alg_paths *paths, int load,
                              const char *module, const char *ports)
{
    struct jmx_system_alg_command_result result;
    char argument[JMX_SYSTEM_ALG_PORTS_MAX + 8];
    char *load_argv[] = { (char *)paths->modprobe_path, (char *)module,
                          NULL, NULL };
    char *unload_argv[] = { (char *)paths->rmmod_path, (char *)module, NULL };
    int rc;

    if (load && ports && ports[0]) {
        if (snprintf(argument, sizeof(argument), "ports=%s", ports) >=
            (int)sizeof(argument))
            return -1;
        load_argv[2] = argument;
    }
    rc = alg_run(options, paths,
                 load ? paths->modprobe_path : paths->rmmod_path,
                 load ? load_argv : unload_argv, 64 * 1024, &result);
    alg_runner_free(options, &result);
    return rc;
}

static int alg_write_runtime_ports(const struct alg_paths *paths,
                                   const struct alg_definition *definition,
                                   const char *ports)
{
    char path[PATH_MAX], readback[JMX_SYSTEM_ALG_PORTS_MAX];
    int fd;

    if (alg_ports_path(paths, definition, path, sizeof(path)) != 0)
        return -1;
    fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    if (alg_write_all(fd, ports, strlen(ports)) != 0 || close(fd) != 0)
        return -1;
    if (alg_read_line(path, readback, sizeof(readback)) != 0 ||
        strcmp(readback, ports) != 0)
        return -1;
    return 0;
}

static int alg_write_persistence(const struct alg_paths *paths,
                                 const struct alg_definition *definition,
                                 int enabled, const char *ports,
                                 mode_t previous_mode)
{
    char path[PATH_MAX];
    char *original = NULL;
    char *content = NULL;
    size_t original_length = 0, content_length = 0;
    size_t capacity;
    const char *cursor, *end;
    int rc = -1;

    if (alg_join_path(path, sizeof(path), paths->modules_dir,
                      definition->startup_file) != 0)
        return -1;

    if (alg_read_file(path, &original, &original_length, 64 * 1024) != 0 &&
        errno != ENOENT)
        return -1;
    /* Preserved lines never exceed the original, so the extra room only has to
     * cover the two lines this helper contributes. */
    capacity = original_length + 512;
    content = calloc(capacity, 1);
    if (!content) {
        free(original);
        return -1;
    }
    cursor = original ? original : "";
    end = cursor + original_length;
    while (cursor < end) {
        const char *line_end = memchr(cursor, '\n', (size_t)(end - cursor));
        size_t line_length = line_end ? (size_t)(line_end - cursor) :
                                        (size_t)(end - cursor);
        int is_helper_line =
            alg_line_module(cursor, line_length, definition->conntrack_module,
                            NULL, 0) ||
            alg_line_module(cursor, line_length, definition->nat_module,
                            NULL, 0);

        if (!is_helper_line) {
            size_t copy_length = line_length + (line_end ? 1U : 0U);
            memcpy(content + content_length, cursor, copy_length);
            content_length += copy_length;
        }
        cursor = line_end ? line_end + 1 : end;
    }
    if (enabled) {
        size_t remaining;
        int n;

        if (content_length > 0 && content[content_length - 1] != '\n')
            content[content_length++] = '\n';
        remaining = capacity - content_length;
        if (definition->ports_supported && ports && ports[0])
            n = snprintf(content + content_length, remaining,
                         "%s ports=%s\n%s\n", definition->conntrack_module,
                         ports, definition->nat_module);
        else
            n = snprintf(content + content_length, remaining,
                         "%s\n%s\n", definition->conntrack_module,
                         definition->nat_module);
        if (n < 0 || (size_t)n >= remaining)
            goto out;
        content_length += (size_t)n;
    }
    if (content_length == 0)
        rc = alg_atomic_remove(paths->modules_dir, path);
    else
        rc = alg_atomic_write(paths->modules_dir, path, content,
                              content_length, previous_mode ? previous_mode : 0644);

out:
    free(content);
    free(original);
    return rc;
}

static int alg_take_snapshot(const struct jmx_system_alg_options *options,
                             enum jmx_system_alg_helper helper,
                             const struct alg_paths *paths,
                             struct alg_transaction_snapshot *snapshot,
                             char *error, size_t error_len)
{
    char path[PATH_MAX];
    const struct alg_definition *definition = &alg_definitions[helper];
    int rc;

    memset(snapshot, 0, sizeof(*snapshot));
    rc = jmx_system_alg_probe(options, helper, &snapshot->state,
                              error, error_len);
    if (rc != JMX_SYSTEM_ALG_OK)
        return rc;
    if (alg_join_path(path, sizeof(path), paths->modules_dir,
                      definition->startup_file) != 0 ||
        alg_file_snapshot_take(path, &snapshot->startup) != 0) {
        alg_set_error(error, error_len, "persistence_snapshot_failed");
        return JMX_SYSTEM_ALG_ERR_IO;
    }
    return JMX_SYSTEM_ALG_OK;
}

static int alg_restore_runtime(const struct jmx_system_alg_options *options,
                               const struct alg_paths *paths,
                               const struct alg_definition *definition,
                               const struct jmx_system_alg_state *before)
{
    int ok = 1;
    int ct_loaded = alg_module_loaded(paths, definition->conntrack_module);
    int nat_loaded = alg_module_loaded(paths, definition->nat_module);

    if (before->conntrack_loaded && !ct_loaded) {
        if (alg_module_command(options, paths, 1,
                               definition->conntrack_module,
                               before->ports_supported ? before->ports : NULL) != 0)
            ok = 0;
        ct_loaded = alg_module_loaded(paths, definition->conntrack_module);
    }
    if (before->nat_loaded && !nat_loaded) {
        if (!ct_loaded || alg_module_command(options, paths, 1,
                                             definition->nat_module, NULL) != 0)
            ok = 0;
        nat_loaded = alg_module_loaded(paths, definition->nat_module);
    }
    if (!before->nat_loaded && nat_loaded) {
        if (alg_module_command(options, paths, 0,
                               definition->nat_module, NULL) != 0)
            ok = 0;
        nat_loaded = alg_module_loaded(paths, definition->nat_module);
    }
    if (!before->conntrack_loaded && ct_loaded) {
        if (nat_loaded || alg_module_command(options, paths, 0,
                                             definition->conntrack_module,
                                             NULL) != 0)
            ok = 0;
    }
    if (before->conntrack_loaded && before->ports_supported &&
        before->ports_writable && before->ports[0]) {
        char current[JMX_SYSTEM_ALG_PORTS_MAX] = "";
        int writable = 0;
        if (alg_ports_read(paths, definition, current, sizeof(current),
                           &writable) != 0 || !writable ||
            (strcmp(current, before->ports) != 0 &&
             alg_write_runtime_ports(paths, definition, before->ports) != 0))
            ok = 0;
    }
    return ok ? 0 : -1;
}

static int alg_rollback(const struct jmx_system_alg_options *options,
                        const struct alg_paths *paths,
                        const struct alg_definition *definition,
                        const struct alg_transaction_snapshot *snapshot)
{
    char path[PATH_MAX];
    int persist_ok, runtime_ok;

    if (alg_join_path(path, sizeof(path), paths->modules_dir,
                      definition->startup_file) != 0)
        return -1;
    persist_ok = alg_file_snapshot_restore(paths->modules_dir, path,
                                           &snapshot->startup) == 0;
    runtime_ok = alg_restore_runtime(options, paths, definition,
                                     &snapshot->state) == 0;
    return persist_ok && runtime_ok ? 0 : -1;
}

static int alg_apply_failed(const struct jmx_system_alg_options *options,
                            const struct alg_paths *paths,
                            const struct alg_definition *definition,
                            const struct alg_transaction_snapshot *snapshot,
                            struct jmx_system_alg_result *result,
                            int rc, const char *stage, const char *error)
{
    result->rollback_attempted = 1;
    snprintf(result->failure_stage, sizeof(result->failure_stage), "%s", stage);
    snprintf(result->error, sizeof(result->error), "%s", error);
    if (alg_rollback(options, paths, definition, snapshot) == 0) {
        result->rollback_succeeded = 1;
    } else {
        result->rollback_succeeded = 0;
        snprintf(result->error, sizeof(result->error), "%s_rollback_failed", error);
        rc = JMX_SYSTEM_ALG_ERR_ROLLBACK;
    }
    (void)jmx_system_alg_probe(options, result->before.helper, &result->after,
                               NULL, 0);
    result->persisted = result->after.persisted == result->before.persisted;
    result->running = result->after.running;
    result->running_known = result->after.running_known;
    return rc;
}

int jmx_system_alg_apply(const struct jmx_system_alg_options *options,
                         const struct jmx_system_alg_request *request,
                         struct jmx_system_alg_result *result)
{
    struct alg_paths paths;
    struct alg_transaction_snapshot snapshot;
    const struct alg_definition *definition;
    char ports[JMX_SYSTEM_ALG_PORTS_MAX] = "";
    const char *target_ports = NULL;
    char error[JMX_SYSTEM_ALG_ERROR_MAX] = "";
    int rc, runtime_ports_pending = 0;

    if (!result)
        return JMX_SYSTEM_ALG_ERR_INVALID;
    memset(result, 0, sizeof(*result));
    if (!request || !alg_valid_helper(request->helper) ||
        (request->enabled != 0 && request->enabled != 1)) {
        snprintf(result->failure_stage, sizeof(result->failure_stage), "validate");
        snprintf(result->error, sizeof(result->error), "invalid_request");
        return JMX_SYSTEM_ALG_ERR_INVALID;
    }
    definition = &alg_definitions[request->helper];
    if (!definition->ports_supported && request->ports) {
        snprintf(result->failure_stage, sizeof(result->failure_stage), "validate");
        snprintf(result->error, sizeof(result->error),
                 "module_has_no_ports_parameter");
        return JMX_SYSTEM_ALG_ERR_UNSUPPORTED;
    }
    if (request->ports && alg_normalize_ports(request->ports, ports,
                                               sizeof(ports)) != 0) {
        snprintf(result->failure_stage, sizeof(result->failure_stage), "validate");
        snprintf(result->error, sizeof(result->error), "invalid_ports");
        return JMX_SYSTEM_ALG_ERR_INVALID;
    }
    alg_resolve_paths(options, &paths);
    rc = alg_take_snapshot(options, request->helper, &paths, &snapshot,
                           error, sizeof(error));
    if (rc != JMX_SYSTEM_ALG_OK) {
        snprintf(result->failure_stage, sizeof(result->failure_stage), "snapshot");
        snprintf(result->error, sizeof(result->error), "%s",
                 error[0] ? error : "snapshot_failed");
        return rc;
    }
    result->before = snapshot.state;
    if (request->enabled &&
        (!snapshot.state.conntrack_available || !snapshot.state.nat_available)) {
        snprintf(result->failure_stage, sizeof(result->failure_stage), "preflight");
        snprintf(result->error, sizeof(result->error), "helper_module_unavailable");
        alg_file_snapshot_free(&snapshot.startup);
        return JMX_SYSTEM_ALG_ERR_NOT_FOUND;
    }
    if (!request->enabled && (snapshot.state.conntrack_loaded ||
                              snapshot.state.nat_loaded)) {
        if (!snapshot.state.nft_probe_ok || !snapshot.state.conntrack_probe_ok) {
            snprintf(result->failure_stage, sizeof(result->failure_stage),
                     "preflight_usage_probe");
            snprintf(result->error, sizeof(result->error),
                     "helper_usage_probe_incomplete");
            alg_file_snapshot_free(&snapshot.startup);
            return JMX_SYSTEM_ALG_ERR_PROBE;
        }
        if (snapshot.state.nft_assigned ||
            snapshot.state.conntrack_active > 0 ||
            snapshot.state.external_module_users > 0 ||
            snapshot.state.nat_refcount > 0) {
            snprintf(result->failure_stage, sizeof(result->failure_stage),
                     "preflight_references");
            snprintf(result->error, sizeof(result->error),
                     "helper_is_referenced");
            alg_file_snapshot_free(&snapshot.startup);
            return JMX_SYSTEM_ALG_ERR_BUSY;
        }
    }
    if (request->ports)
        target_ports = ports;
    else if (snapshot.state.ports[0])
        target_ports = snapshot.state.ports;
    else if (snapshot.state.persisted_ports[0])
        target_ports = snapshot.state.persisted_ports;

    if (request->enabled) {
        if (!snapshot.state.conntrack_loaded &&
            alg_module_command(options, &paths, 1,
                               definition->conntrack_module,
                               target_ports) != 0) {
            rc = alg_apply_failed(options, &paths, definition, &snapshot,
                                  result, JMX_SYSTEM_ALG_ERR_EXEC,
                                  "load_conntrack", "conntrack_load_failed");
            goto out;
        }
        if (!snapshot.state.nat_loaded &&
            alg_module_command(options, &paths, 1,
                               definition->nat_module, NULL) != 0) {
            rc = alg_apply_failed(options, &paths, definition, &snapshot,
                                  result, JMX_SYSTEM_ALG_ERR_EXEC,
                                  "load_nat", "nat_load_failed");
            goto out;
        }
        if (request->ports && snapshot.state.conntrack_loaded &&
            strcmp(snapshot.state.ports, target_ports) != 0) {
            if (snapshot.state.ports_writable) {
                if (alg_write_runtime_ports(&paths, definition,
                                            target_ports) != 0) {
                    rc = alg_apply_failed(options, &paths, definition, &snapshot,
                                          result, JMX_SYSTEM_ALG_ERR_IO,
                                          "write_ports", "ports_write_failed");
                    goto out;
                }
            } else {
                runtime_ports_pending = 1;
            }
        }
    } else {
        if (snapshot.state.nat_loaded &&
            alg_module_command(options, &paths, 0,
                               definition->nat_module, NULL) != 0) {
            rc = alg_apply_failed(options, &paths, definition, &snapshot,
                                  result, JMX_SYSTEM_ALG_ERR_EXEC,
                                  "unload_nat", "nat_unload_failed");
            goto out;
        }
        if (snapshot.state.conntrack_loaded &&
            alg_module_command(options, &paths, 0,
                               definition->conntrack_module, NULL) != 0) {
            rc = alg_apply_failed(options, &paths, definition, &snapshot,
                                  result, JMX_SYSTEM_ALG_ERR_EXEC,
                                  "unload_conntrack",
                                  "conntrack_unload_failed");
            goto out;
        }
    }
    if (alg_write_persistence(&paths, definition, request->enabled,
                              target_ports, snapshot.startup.mode) != 0) {
        rc = alg_apply_failed(options, &paths, definition, &snapshot,
                              result, JMX_SYSTEM_ALG_ERR_IO,
                              "persist", "persistence_write_failed");
        goto out;
    }
    if (jmx_system_alg_probe(options, request->helper, &result->after,
                             error, sizeof(error)) != JMX_SYSTEM_ALG_OK) {
        rc = alg_apply_failed(options, &paths, definition, &snapshot,
                              result, JMX_SYSTEM_ALG_ERR_READBACK,
                              "readback", "readback_failed");
        goto out;
    }
    if (result->after.persisted != request->enabled ||
        (request->enabled &&
         (!result->after.conntrack_loaded || !result->after.nat_loaded)) ||
        (!request->enabled &&
         (result->after.conntrack_loaded || result->after.nat_loaded))) {
        rc = alg_apply_failed(options, &paths, definition, &snapshot,
                              result, JMX_SYSTEM_ALG_ERR_READBACK,
                              "readback", "readback_mismatch");
        goto out;
    }
    if (request->enabled && request->ports &&
        strcmp(result->after.persisted_ports, target_ports) != 0) {
        rc = alg_apply_failed(options, &paths, definition, &snapshot,
                              result, JMX_SYSTEM_ALG_ERR_READBACK,
                              "readback_persistence",
                              "persisted_ports_mismatch");
        goto out;
    }
    result->persisted = result->after.persisted;
    result->reboot_required = runtime_ports_pending;
    result->applied = runtime_ports_pending ? 0 :
        (request->enabled ? result->after.running : !result->after.running);
    result->running = result->after.running;
    result->running_known = result->after.running_known;
    rc = JMX_SYSTEM_ALG_OK;

out:
    alg_file_snapshot_free(&snapshot.startup);
    return rc;
}
