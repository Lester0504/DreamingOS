// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Transactional runtime for the ordinary system-settings page.
 *
 * This file deliberately has no dependency on the shared settings database or
 * daemon build lists.  The stage-2 integration layer supplies the real paths
 * and consumes the field-level result.  The config writer edits only the
 * system/timeserver UCI sections, and the service runner never invokes a
 * shell: both properties are important when this code is called with values
 * originating in an HTTP request.
 */
#define _POSIX_C_SOURCE 200809L

#include "system_settings_runtime.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define SSR_FILE_MAX (512U * 1024U)
#define SSR_LINE_MAX 1024U
#define SSR_CONFIG_ASSIGNMENTS_MAX 32U
#define SSR_CRON_BEGIN "# BEGIN DREAMINGWRT NTP SYNC"
#define SSR_CRON_END "# END DREAMINGWRT NTP SYNC"

struct ssr_assignment {
    const char *type;
    const char *name;
    const char *key;
    const char *value;
    int list;
    int remove_only;
};

struct ssr_config_section {
    char type[32];
    char name[64];
    int active;
};

static void ssr_error(char *error, size_t error_len, const char *message)
{
    if (!error || !error_len)
        return;
    snprintf(error, error_len, "%s", message ? message : "runtime_error");
}

static void ssr_copy(char *dst, size_t dst_len, const char *src)
{
    size_t i;

    if (!dst || !dst_len)
        return;
    if (!src)
        src = "";
    /* Explicit bounded copy: intentional truncation, and unlike
     * snprintf("%s") it does not trip -Wformat-truncation on GCC. */
    for (i = 0; i + 1U < dst_len && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

static int ssr_file_exists(const char *path)
{
    struct stat st;

    return path && stat(path, &st) == 0;
}

static int ssr_dir_exists(const char *path)
{
    struct stat st;

    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static void ssr_trim(char *value)
{
    char *start;
    char *end;

    if (!value)
        return;
    start = value;
    while (*start && isspace((unsigned char)*start))
        start++;
    if (start != value)
        memmove(value, start, strlen(start) + 1U);
    end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1]))
        *--end = '\0';
}

static int ssr_safe_token(const char *value, size_t max_len, int allow_slash)
{
    size_t i;

    if (!value || !value[0] || strlen(value) > max_len ||
        strchr(value, '\n') || strchr(value, '\r') || strchr(value, '\'') ||
        strchr(value, '"'))
        return 0;
    for (i = 0; value[i]; i++) {
        unsigned char c = (unsigned char)value[i];

        if (isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':' ||
            c == '[' || c == ']' || c == '+')
            continue;
        if (allow_slash && c == '/')
            continue;
        return 0;
    }
    return 1;
}

static int ssr_join(char *out, size_t out_len, const char *left,
                    const char *right)
{
    if (!out || !out_len || !left || !right || right[0] == '/')
        return -1;
    if (snprintf(out, out_len, "%s/%s", left, right) >= (int)out_len)
        return -1;
    return 0;
}

static int ssr_read_file(const char *path, char **data, size_t *length,
                         mode_t *mode, int *existed)
{
    int fd = -1;
    struct stat st;
    char *buffer = NULL;
    size_t used = 0;

    if (!data || !length || !mode || !existed || !path)
        return -1;
    *data = NULL;
    *length = 0;
    *mode = 0644;
    *existed = 0;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT)
            return 0;
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (uintmax_t)st.st_size > SSR_FILE_MAX) {
        close(fd);
        return -1;
    }
    buffer = calloc((size_t)st.st_size + 1U, 1U);
    if (!buffer) {
        close(fd);
        return -1;
    }
    while (used < (size_t)st.st_size) {
        ssize_t got = read(fd, buffer + used, (size_t)st.st_size - used);

        if (got <= 0) {
            free(buffer);
            close(fd);
            return -1;
        }
        used += (size_t)got;
    }
    close(fd);
    *data = buffer;
    *length = used;
    *mode = st.st_mode & 0777;
    *existed = 1;
    return 0;
}

static int ssr_parent_dir(const char *path, char *out, size_t out_len)
{
    const char *slash;
    size_t length;

    if (!path || !out || !out_len)
        return -1;
    slash = strrchr(path, '/');
    if (!slash)
        return ssr_copy(out, out_len, "."), 0;
    length = (size_t)(slash - path);
    if (!length)
        length = 1U;
    if (length >= out_len)
        return -1;
    memcpy(out, path, length);
    out[length] = '\0';
    return 0;
}

static int ssr_sync_parent(const char *path)
{
    char parent[SSR_PATH_MAX];
    int fd;

    if (ssr_parent_dir(path, parent, sizeof(parent)) != 0)
        return -1;
    fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fsync(fd) != 0) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int ssr_atomic_write(const char *path, const char *data, size_t length,
                            mode_t mode)
{
    char temporary[SSR_PATH_MAX];
    int fd = -1;
    int rc = -1;
    size_t written = 0;

    if (!path || !data || strlen(path) >= sizeof(temporary) - 40U)
        return -1;
    snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path,
             (long)getpid());
    unlink(temporary);
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
              mode ? mode : 0644);
    if (fd < 0)
        return -1;
    while (written < length) {
        ssize_t count = write(fd, data + written, length - written);

        if (count <= 0)
            goto out;
        written += (size_t)count;
    }
    if (fsync(fd) != 0 || close(fd) != 0) {
        fd = -1;
        goto out;
    }
    fd = -1;
    if (rename(temporary, path) != 0 || ssr_sync_parent(path) != 0)
        goto out;
    rc = 0;
out:
    if (fd >= 0)
        close(fd);
    if (rc != 0)
        unlink(temporary);
    return rc;
}

static int ssr_restore_file(const char *path, const struct ssr_file_snapshot *snap)
{
    if (!path || !snap)
        return -1;
    if (!snap->existed) {
        if (unlink(path) != 0 && errno != ENOENT)
            return -1;
        return ssr_sync_parent(path);
    }
    return ssr_atomic_write(path, snap->data ? snap->data : "", snap->length,
                            snap->mode);
}

static int ssr_snapshot_file(const char *path, struct ssr_file_snapshot *snap)
{
    if (!snap)
        return -1;
    memset(snap, 0, sizeof(*snap));
    return ssr_read_file(path, &snap->data, &snap->length, &snap->mode,
                         &snap->existed);
}

static void ssr_snapshot_file_clear(struct ssr_file_snapshot *snap)
{
    if (!snap)
        return;
    free(snap->data);
    memset(snap, 0, sizeof(*snap));
}

static int ssr_default_command(void *opaque, const char *const argv[],
                               const char *input, char *output,
                               size_t output_len)
{
    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    pid_t pid;
    int status;
    size_t sent = 0;
    (void)opaque;

    if (!argv || !argv[0])
        return -1;
    if (pipe(out_pipe) != 0)
        return -1;
    if (input && pipe(in_pipe) != 0) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        return -1;
    }
    pid = fork();
    if (pid < 0)
        goto fail;
    if (pid == 0) {
        int nullfd;

        if (input) {
            dup2(in_pipe[0], STDIN_FILENO);
            close(in_pipe[0]);
            close(in_pipe[1]);
        } else {
            nullfd = open("/dev/null", O_RDONLY);
            if (nullfd >= 0) {
                dup2(nullfd, STDIN_FILENO);
                close(nullfd);
            }
        }
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(out_pipe[1], STDERR_FILENO);
        close(out_pipe[0]);
        close(out_pipe[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(out_pipe[1]);
    out_pipe[1] = -1;
    if (input) {
        close(in_pipe[0]);
        in_pipe[0] = -1;
        while (sent < strlen(input)) {
            ssize_t count = write(in_pipe[1], input + sent, strlen(input) - sent);

            if (count <= 0)
                break;
            sent += (size_t)count;
        }
        close(in_pipe[1]);
        in_pipe[1] = -1;
    }
    if (output && output_len)
        output[0] = '\0';
    if (output && output_len > 1U) {
        size_t used = 0;

        while (used + 1U < output_len) {
            ssize_t count = read(out_pipe[0], output + used,
                                 output_len - used - 1U);

            if (count <= 0)
                break;
            used += (size_t)count;
            output[used] = '\0';
        }
    } else {
        char discard[256];
        while (read(out_pipe[0], discard, sizeof(discard)) > 0)
            ;
    }
    close(out_pipe[0]);
    out_pipe[0] = -1;
    if (waitpid(pid, &status, 0) != pid)
        return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
fail:
    if (in_pipe[0] >= 0)
        close(in_pipe[0]);
    if (in_pipe[1] >= 0)
        close(in_pipe[1]);
    if (out_pipe[0] >= 0)
        close(out_pipe[0]);
    if (out_pipe[1] >= 0)
        close(out_pipe[1]);
    return -1;
}

static int ssr_command(const struct ssr_executor *executor,
                       const char *const argv[], const char *input,
                       char *output, size_t output_len)
{
    ssr_command_fn fn = executor && executor->command ? executor->command :
                        ssr_default_command;

    return fn(executor ? executor->opaque : NULL, argv, input, output,
              output_len);
}

static int ssr_service_reload(const struct ssr_executor *executor,
                              const char *path)
{
    const char *argv[] = {path, "reload", NULL};

    return path && path[0] ? ssr_command(executor, argv, NULL, NULL, 0U) : -1;
}

static int ssr_service_set_state(const struct ssr_executor *executor,
                                 const char *path, int running)
{
    const char *argv[] = {path, running ? "start" : "stop", NULL};

    return path && path[0] ? ssr_command(executor, argv, NULL, NULL, 0U) : -1;
}

static int ssr_service_status(const struct ssr_executor *executor,
                              const char *path, int *running)
{
    const char *argv[] = {path, "status", NULL};
    char output[SSR_OUTPUT_MAX];
    int rc;

    if (!path || !path[0] || !running)
        return -1;
    output[0] = '\0';
    rc = ssr_command(executor, argv, NULL, output, sizeof(output));
    if (strstr(output, "stopped") || strstr(output, "inactive") ||
        strstr(output, "not running"))
        *running = 0;
    else if (strstr(output, "running") || strstr(output, "active") ||
             strstr(output, "started"))
        *running = 1;
    else if (rc != 0)
        return -1;
    else
        *running = 0;
    return 0;
}

static int ssr_parse_uci_header(const char *line, struct ssr_config_section *section)
{
    char type[32] = "";
    char name[64] = "";
    const char *p;
    char quote;
    size_t i = 0;

    if (!line || !section)
        return 0;
    while (isspace((unsigned char)*line))
        line++;
    if (strncmp(line, "config", 6U) != 0 || !isspace((unsigned char)line[6]))
        return 0;
    p = line + 6U;
    while (isspace((unsigned char)*p))
        p++;
    while (*p && !isspace((unsigned char)*p) && i + 1U < sizeof(type))
        type[i++] = *p++;
    type[i] = '\0';
    while (isspace((unsigned char)*p))
        p++;
    if (!*p) {
        ssr_copy(name, sizeof(name), "");
    } else {
        quote = (*p == '\'' || *p == '"') ? *p++ : '\0';
        i = 0;
        while (*p && ((quote && *p != quote) || (!quote && !isspace((unsigned char)*p))) &&
               i + 1U < sizeof(name))
            name[i++] = *p++;
        name[i] = '\0';
    }
    ssr_copy(section->type, sizeof(section->type), type);
    ssr_copy(section->name, sizeof(section->name), name);
    section->active = 1;
    return 1;
}

static int ssr_section_matches(const struct ssr_config_section *section,
                               const char *type, const char *name)
{
    if (!section || !section->active || strcmp(section->type, type))
        return 0;
    return !strcmp(section->name, name) || !section->name[0];
}

static int ssr_parse_uci_option(const char *line, char *kind, size_t kind_len,
                                char *key, size_t key_len, char *value,
                                size_t value_len)
{
    const char *p;
    size_t i = 0;
    char quote = '\0';

    if (!line || !kind || !key || !value)
        return 0;
    while (isspace((unsigned char)*line))
        line++;
    if (strncmp(line, "option", 6U) == 0 && isspace((unsigned char)line[6]))
        ssr_copy(kind, kind_len, "option");
    else if (strncmp(line, "list", 4U) == 0 && isspace((unsigned char)line[4]))
        ssr_copy(kind, kind_len, "list");
    else
        return 0;
    p = line + strlen(kind);
    while (isspace((unsigned char)*p))
        p++;
    while (*p && !isspace((unsigned char)*p) && i + 1U < key_len)
        key[i++] = *p++;
    key[i] = '\0';
    while (isspace((unsigned char)*p))
        p++;
    if (*p == '\'' || *p == '"') {
        quote = *p++;
        i = 0;
        while (*p && *p != quote && i + 1U < value_len) {
            if (*p == '\\' && p[1])
                p++;
            value[i++] = *p++;
        }
        value[i] = '\0';
    } else {
        ssr_copy(value, value_len, p);
        ssr_trim(value);
    }
    return key[0] != '\0';
}

static int ssr_append(char *out, size_t out_len, size_t *used,
                      const char *text)
{
    size_t len;

    if (!out || !used || !text)
        return -1;
    len = strlen(text);
    if (*used + len + 1U > out_len)
        return -1;
    memcpy(out + *used, text, len);
    *used += len;
    out[*used] = '\0';
    return 0;
}

static int ssr_append_option(char *out, size_t out_len, size_t *used,
                             const struct ssr_assignment *assignment)
{
    char line[SSR_LINE_MAX];
    char quoted[SSR_SERVER_MAX + SSR_PATH_MAX + 32U];
    size_t i;
    size_t quoted_len = 0;

    if (assignment && assignment->remove_only)
        return 0;
    if (!assignment || !assignment->value ||
        strlen(assignment->value) >= sizeof(quoted) - 3U)
        return -1;
    quoted[quoted_len++] = '\'';
    for (i = 0; assignment->value[i] && quoted_len + 2U < sizeof(quoted); i++) {
        if (assignment->value[i] == '\\' || assignment->value[i] == '\'')
            quoted[quoted_len++] = '\\';
        quoted[quoted_len++] = assignment->value[i];
    }
    quoted[quoted_len++] = '\'';
    quoted[quoted_len] = '\0';
    if (snprintf(line, sizeof(line), "\t%s %s %s\n",
                 assignment->list ? "list" : "option", assignment->key,
                 quoted) >= (int)sizeof(line))
        return -1;
    return ssr_append(out, out_len, used, line);
}

static int ssr_flush_assignments(char *out, size_t out_len, size_t *used,
                                 const struct ssr_assignment *assignments,
                                 size_t count, const char *type,
                                 const char *name)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (strcmp(assignments[i].type, type) ||
            (strcmp(assignments[i].name, name) && name[0]))
            continue;
        if (ssr_append_option(out, out_len, used, &assignments[i]) != 0)
            return -1;
    }
    return 0;
}

static int ssr_rewrite_config(const char *old_data,
                              const struct ssr_assignment *assignments,
                              size_t count, char **new_data)
{
    char *out;
    char *copy;
    char *saveptr = NULL;
    char *line;
    struct ssr_config_section section = {{0}, {0}, 0};
    size_t used = 0;
    size_t i;

    if (!new_data || count > SSR_CONFIG_ASSIGNMENTS_MAX)
        return -1;
    out = calloc(SSR_FILE_MAX + 1U, 1U);
    copy = strdup(old_data ? old_data : "");
    if (!out || !copy) {
        free(out);
        free(copy);
        return -1;
    }
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        struct ssr_config_section next = {{0}, {0}, 0};
        char kind[8];
        char key[64];
        char value[SSR_PATH_MAX + SSR_SERVER_MAX];
        if (ssr_parse_uci_header(line, &next)) {
            if (section.active && ssr_flush_assignments(
                    out, SSR_FILE_MAX + 1U, &used, assignments, count,
                    section.type, section.name) != 0)
                goto fail;
            section = next;
        }
        if (section.active && ssr_parse_uci_option(line, kind, sizeof(kind),
                                                   key, sizeof(key), value,
                                                   sizeof(value))) {
            for (i = 0; i < count; i++) {
                if (strcmp(assignments[i].type, section.type) ||
                    (strcmp(assignments[i].name, section.name) &&
                     section.name[0]) ||
                    strcmp(assignments[i].key, key))
                    continue;
                (void)kind;
                goto skip_line;
            }
        }
        if (ssr_append(out, SSR_FILE_MAX + 1U, &used, line) != 0 ||
            ssr_append(out, SSR_FILE_MAX + 1U, &used, "\n") != 0)
            goto fail;
skip_line:
        ;
    }
    if (section.active && ssr_flush_assignments(
            out, SSR_FILE_MAX + 1U, &used, assignments, count, section.type,
            section.name) != 0)
        goto fail;
    for (i = 0; i < count; i++) {
        int found = 0;
        size_t prior;
        char *scan;
        char *sp = NULL;
        char *ln;
        struct ssr_config_section sec = {{0}, {0}, 0};

        if (assignments[i].remove_only)
            continue;
        scan = strdup(old_data ? old_data : "");
        if (!scan)
            goto fail;
        for (ln = strtok_r(scan, "\n", &sp); ln;
             ln = strtok_r(NULL, "\n", &sp)) {
            struct ssr_config_section next = {{0}, {0}, 0};

            if (ssr_parse_uci_header(ln, &next))
                sec = next;
            if (ssr_section_matches(&sec, assignments[i].type,
                                    assignments[i].name)) {
                found = 1;
                break;
            }
        }
        free(scan);
        if (!found) {
            for (prior = 0; prior < i; prior++) {
                if (!strcmp(assignments[prior].type, assignments[i].type) &&
                    !strcmp(assignments[prior].name, assignments[i].name)) {
                    found = 1;
                    break;
                }
            }
        }
        if (!found) {
            char header[128];

            if (used && out[used - 1U] != '\n' &&
                ssr_append(out, SSR_FILE_MAX + 1U, &used, "\n") != 0)
                goto fail;
            if (snprintf(header, sizeof(header), "\nconfig %s '%s'\n",
                         assignments[i].type, assignments[i].name) >=
                (int)sizeof(header) ||
                ssr_append(out, SSR_FILE_MAX + 1U, &used, header) != 0 ||
                ssr_flush_assignments(out, SSR_FILE_MAX + 1U, &used,
                                      assignments, count, assignments[i].type,
                                      assignments[i].name) != 0)
                goto fail;
        }
    }
    free(copy);
    *new_data = out;
    return 0;
fail:
    free(copy);
    free(out);
    return -1;
}

static int ssr_config_value(const char *data, const char *type, const char *name,
                            const char *key, char *value, size_t value_len,
                            size_t occurrence)
{
    char *copy;
    char *saveptr = NULL;
    char *line;
    struct ssr_config_section section = {{0}, {0}, 0};
    size_t found = 0;

    if (!value || !value_len)
        return -1;
    value[0] = '\0';
    copy = strdup(data ? data : "");
    if (!copy)
        return -1;
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        struct ssr_config_section next = {{0}, {0}, 0};
        char kind[8];
        char parsed_key[64];
        char parsed_value[SSR_PATH_MAX + SSR_SERVER_MAX];

        if (ssr_parse_uci_header(line, &next))
            section = next;
        if (!ssr_section_matches(&section, type, name) ||
            !ssr_parse_uci_option(line, kind, sizeof(kind), parsed_key,
                                  sizeof(parsed_key), parsed_value,
                                  sizeof(parsed_value)) || strcmp(parsed_key, key))
            continue;
        if (found++ != occurrence)
            continue;
        ssr_copy(value, value_len, parsed_value);
        free(copy);
        return 0;
    }
    free(copy);
    return -1;
}

static int ssr_write_config(const struct ssr_paths *paths,
                            const struct ssr_assignment *assignments,
                            size_t count, mode_t mode)
{
    char *old_data = NULL;
    char *new_data = NULL;
    size_t length = 0;
    int existed = 0;
    int rc;

    if (!paths || !paths->system_config)
        return -1;
    if (ssr_read_file(paths->system_config, &old_data, &length, &mode,
                      &existed) != 0)
        return -1;
    rc = ssr_rewrite_config(old_data, assignments, count, &new_data);
    if (rc == 0)
        rc = ssr_atomic_write(paths->system_config, new_data, strlen(new_data),
                              mode ? mode : 0644);
    free(old_data);
    free(new_data);
    (void)existed;
    return rc;
}

static int ssr_cron_rewrite(const char *path, const struct ssr_time_settings *settings)
{
    char *old_data = NULL;
    char *copy = NULL;
    char *out = NULL;
    char *saveptr = NULL;
    char *line;
    mode_t mode = 0644;
    int existed = 0;
    int in_block = 0;
    size_t used = 0;
    char schedule[32] = "";
    size_t i;

    if (!path || !settings)
        return -1;
    if (ssr_read_file(path, &old_data, &i, &mode, &existed) != 0)
        return -1;
    out = calloc(SSR_FILE_MAX + 1U, 1U);
    copy = strdup(old_data ? old_data : "");
    if (!out || !copy)
        goto fail;
    for (line = strtok_r(copy, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        if (!strcmp(line, SSR_CRON_BEGIN)) {
            in_block = 1;
            continue;
        }
        if (in_block && !strcmp(line, SSR_CRON_END)) {
            in_block = 0;
            continue;
        }
        if (!in_block && (ssr_append(out, SSR_FILE_MAX + 1U, &used, line) != 0 ||
                          ssr_append(out, SSR_FILE_MAX + 1U, &used, "\n") != 0))
            goto fail;
    }
    if (!strcmp(settings->interval, "15m"))
        ssr_copy(schedule, sizeof(schedule), "*/15 * * * *");
    else if (!strcmp(settings->interval, "1h"))
        ssr_copy(schedule, sizeof(schedule), "0 * * * *");
    else if (!strcmp(settings->interval, "6h"))
        ssr_copy(schedule, sizeof(schedule), "0 */6 * * *");
    else if (!strcmp(settings->interval, "24h"))
        ssr_copy(schedule, sizeof(schedule), "0 0 * * *");
    if (settings->client_enabled && strcmp(settings->interval, "auto")) {
        if (used && out[used - 1U] != '\n')
            ssr_append(out, SSR_FILE_MAX + 1U, &used, "\n");
        if (ssr_append(out, SSR_FILE_MAX + 1U, &used, SSR_CRON_BEGIN "\n") != 0)
            goto fail;
        if (snprintf(out + used, SSR_FILE_MAX + 1U - used, "%s /usr/sbin/ntpd -n -q",
                     schedule) >= (int)(SSR_FILE_MAX + 1U - used))
            goto fail;
        used += strlen(out + used);
        for (i = 0; i < settings->server_count; i++) {
            if (snprintf(out + used, SSR_FILE_MAX + 1U - used, " -p %s",
                         settings->servers[i]) >= (int)(SSR_FILE_MAX + 1U - used))
                goto fail;
            used += strlen(out + used);
        }
        if (ssr_append(out, SSR_FILE_MAX + 1U, &used, "\n" SSR_CRON_END "\n") != 0)
            goto fail;
    }
    if (ssr_atomic_write(path, out, used, mode ? mode : 0644) != 0)
        goto fail;
    free(old_data);
    free(copy);
    free(out);
    (void)existed;
    return 0;
fail:
    free(old_data);
    free(copy);
    free(out);
    return -1;
}

static int ssr_cron_managed(const char *data)
{
    return data && strstr(data, SSR_CRON_BEGIN) && strstr(data, SSR_CRON_END);
}

static int ssr_read_mem_mib(const char *path, uint64_t *mib)
{
    char *data = NULL;
    size_t length = 0;
    char *line;
    char *saveptr = NULL;
    int rc = -1;

    if (!mib || ssr_read_file(path, &data, &length, &(mode_t){0}, &(int){0}) != 0)
        return -1;
    for (line = strtok_r(data, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        unsigned long long kb;

        if (sscanf(line, "MemTotal: %llu kB", &kb) == 1) {
            *mib = kb / 1024U;
            rc = 0;
            break;
        }
    }
    free(data);
    (void)length;
    return rc;
}

static int ssr_server_valid(const char *server)
{
    const char *start = server;
    const char *end;
    const char *colon = NULL;
    char host[SSR_SERVER_MAX + 1U];
    char port_text[8];
    unsigned long port;
    size_t length;
    size_t i;

    if (!server || !server[0] || strlen(server) > SSR_SERVER_MAX ||
        strchr(server, '/') || strchr(server, '\\') || strchr(server, '\n'))
        return 0;
    if (server[0] == '[') {
        end = strchr(server, ']');
        if (!end || end == server + 1 || end[1] == '\0')
            return 0;
        if (end[1] == ':')
            colon = end + 1;
        else if (end[1] != '\0')
            return 0;
        length = (size_t)(end - server - 1);
        memcpy(host, server + 1, length);
        host[length] = '\0';
    } else {
        end = strrchr(server, ':');
        if (end && strchr(server, ':') == end)
            colon = end;
        length = colon ? (size_t)(colon - server) : strlen(server);
        if (!length || length >= sizeof(host))
            return 0;
        memcpy(host, server, length);
        host[length] = '\0';
    }
    if (colon) {
        ssr_copy(port_text, sizeof(port_text), colon + 1);
        if (!port_text[0] || strlen(port_text) > 5U)
            return 0;
        port = strtoul(port_text, NULL, 10);
        if (port == 0 || port > 65535U)
            return 0;
    }
    if (!host[0] || host[0] == '.' || host[strlen(host) - 1U] == '.')
        return 0;
    for (i = 0; host[i]; i++) {
        unsigned char c = (unsigned char)host[i];

        if (!(isalnum(c) || c == '.' || c == '-' || c == ':' || c == '%'))
            return 0;
    }
    (void)start;
    return 1;
}

static int ssr_timezone_valid(const struct ssr_paths *paths, const char *timezone)
{
    char zone_path[SSR_PATH_MAX];

    if (!ssr_safe_token(timezone, 63U, 1) || strstr(timezone, "..") ||
        timezone[0] == '/' || !paths || !paths->zoneinfo_dir)
        return 0;
    if (ssr_join(zone_path, sizeof(zone_path), paths->zoneinfo_dir, timezone) != 0)
        return 0;
    return ssr_file_exists(zone_path);
}

static int ssr_interval_valid(const char *interval)
{
    return interval && (!strcmp(interval, "auto") || !strcmp(interval, "15m") ||
                        !strcmp(interval, "1h") || !strcmp(interval, "6h") ||
                        !strcmp(interval, "24h"));
}

static int ssr_level_value(const char *level)
{
    static const char *const names[] = {
        "emergency", "alert", "critical", "error", "warning", "notice",
        "info", "debug"
    };
    size_t i;

    if (!level || !level[0])
        return -1;
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (!strcmp(level, names[i]))
            return (int)i;
    return -1;
}

static int ssr_cron_level_value(const char *level)
{
    if (!strcmp(level, "disabled"))
        return 0;
    if (!strcmp(level, "error"))
        return 3;
    if (!strcmp(level, "all"))
        return 8;
    return -1;
}

static int ssr_log_path_allowed(const char *path)
{
    if (!path || path[0] != '/' || strlen(path) >= SSR_PATH_MAX ||
        strstr(path, "..") || strchr(path, '\n') || strchr(path, '\r') ||
        strchr(path, '\'') || strchr(path, '"'))
        return 0;
    return !strncmp(path, "/tmp/", 5U) || !strncmp(path, "/var/log/", 9U) ||
           !strncmp(path, "/mnt/", 5U) || !strncmp(path, "/media/", 7U);
}

static int ssr_result_field(struct ssr_result *result, const char *field)
{
    struct ssr_field_result *out;

    if (!result || result->field_count >= SSR_RESULT_FIELDS_MAX)
        return -1;
    out = &result->fields[result->field_count++];
    memset(out, 0, sizeof(*out));
    ssr_copy(out->field, sizeof(out->field), field);
    return (int)(result->field_count - 1U);
}

void ssr_paths_default(struct ssr_paths *paths)
{
    if (!paths)
        return;
    memset(paths, 0, sizeof(*paths));
    paths->system_config = "/etc/config/system";
    paths->root_crontab = "/etc/crontabs/root";
    paths->zoneinfo_dir = "/usr/share/zoneinfo";
    paths->meminfo = "/proc/meminfo";
    paths->proc_swaps = "/proc/swaps";
    paths->zram_sysfs = "/sys/block/zram0";
    paths->zram_device = "/dev/zram0";
    paths->uci = "/sbin/uci";
    paths->init_system = "/etc/init.d/system";
    paths->init_sysntpd = "/etc/init.d/sysntpd";
    paths->init_log = "/etc/init.d/log";
    paths->init_cron = "/etc/init.d/cron";
    paths->busybox = "/bin/busybox";
    paths->ntpd = "/usr/sbin/ntpd";
}

void ssr_result_reset(struct ssr_result *result)
{
    if (!result)
        return;
    memset(result, 0, sizeof(*result));
    ssr_copy(result->stage, sizeof(result->stage), "validate");
}

int ssr_time_probe(const struct ssr_paths *paths, struct ssr_probe *probe)
{
    if (!paths || !probe)
        return -1;
    memset(probe, 0, sizeof(*probe));
    probe->persistent = ssr_file_exists(paths->system_config);
    probe->apply_supported = paths->init_sysntpd && paths->init_sysntpd[0];
    probe->readback_supported = probe->persistent && probe->apply_supported;
    probe->rollback_supported = probe->persistent;
    probe->available = ssr_dir_exists(paths->zoneinfo_dir) &&
                       probe->apply_supported;
    if (!probe->available)
        ssr_copy(probe->reason, sizeof(probe->reason),
                 "timezone_or_sysntpd_unavailable");
    return 0;
}

int ssr_time_validate(const struct ssr_paths *paths,
                      const struct ssr_time_settings *settings,
                      char *error, size_t error_len)
{
    size_t i;

    if (!paths || !settings) {
        ssr_error(error, error_len, "invalid_argument");
        return -1;
    }
    if (!ssr_timezone_valid(paths, settings->timezone)) {
        ssr_error(error, error_len, "invalid_timezone");
        return -1;
    }
    if (!ssr_interval_valid(settings->interval)) {
        ssr_error(error, error_len, "invalid_sync_interval");
        return -1;
    }
    if (settings->server_count > SSR_TIME_SERVERS_MAX) {
        ssr_error(error, error_len, "too_many_ntp_servers");
        return -1;
    }
    for (i = 0; i < settings->server_count; i++) {
        if (!ssr_server_valid(settings->servers[i])) {
            ssr_error(error, error_len, "invalid_ntp_server");
            return -1;
        }
    }
    if (settings->client_enabled && !settings->use_dhcp &&
        settings->server_count == 0U) {
        ssr_error(error, error_len, "ntp_server_list_required");
        return -1;
    }
    if (settings->client_enabled && strcmp(settings->interval, "auto") &&
        (settings->use_dhcp || settings->server_enabled)) {
        ssr_error(error, error_len, "fixed_interval_conflicts_with_dhcp_or_server");
        return -1;
    }
    if (!strcmp(settings->interval, "auto") && settings->client_enabled == 0 &&
        settings->use_dhcp && !settings->server_enabled) {
        /* A disabled client may retain DHCP preference; it has no runtime effect. */
    }
    return 0;
}

static int ssr_time_read_config(const struct ssr_paths *paths,
                                struct ssr_time_state *state)
{
    char *data = NULL;
    size_t length = 0;
    char value[SSR_PATH_MAX + SSR_SERVER_MAX];
    mode_t mode;
    int existed;
    size_t i;

    if (ssr_read_file(paths->system_config, &data, &length, &mode, &existed) != 0)
        return -1;
    memset(state, 0, sizeof(*state));
    ssr_copy(state->settings.timezone, sizeof(state->settings.timezone), "UTC");
    ssr_copy(state->settings.interval, sizeof(state->settings.interval), "auto");
    state->settings.use_dhcp = 1;
    if (ssr_config_value(data, "system", "system", "zonename", value,
                         sizeof(value), 0U) == 0)
        ssr_copy(state->settings.timezone, sizeof(state->settings.timezone), value);
    if (ssr_config_value(data, "system", "system", "dreamingwrt_ntp_interval",
                         value, sizeof(value), 0U) == 0)
        ssr_copy(state->settings.interval, sizeof(state->settings.interval), value);
    if (ssr_config_value(data, "timeserver", "ntp", "enabled", value,
                         sizeof(value), 0U) == 0)
        state->settings.client_enabled = atoi(value) != 0;
    if (ssr_config_value(data, "timeserver", "ntp", "enable_server", value,
                         sizeof(value), 0U) == 0)
        state->settings.server_enabled = atoi(value) != 0;
    if (ssr_config_value(data, "timeserver", "ntp", "use_dhcp", value,
                         sizeof(value), 0U) == 0)
        state->settings.use_dhcp = atoi(value) != 0;
    for (i = 0; i < SSR_TIME_SERVERS_MAX; i++) {
        if (ssr_config_value(data, "timeserver", "ntp", "server", value,
                             sizeof(value), i) != 0)
            break;
        ssr_copy(state->settings.servers[state->settings.server_count++],
                 sizeof(state->settings.servers[0]), value);
    }
    free(data);
    (void)length;
    (void)mode;
    (void)existed;
    return 0;
}

static int ssr_time_read_cron(const struct ssr_paths *paths,
                              struct ssr_time_state *state)
{
    char *data = NULL;
    size_t length = 0;
    mode_t mode;
    int existed;

    if (ssr_read_file(paths->root_crontab, &data, &length, &mode, &existed) != 0)
        return -1;
    state->cron_managed = ssr_cron_managed(data);
    if (state->cron_managed)
        state->settings.client_enabled = 1;
    free(data);
    (void)length;
    (void)mode;
    (void)existed;
    return 0;
}

int ssr_time_readback(const struct ssr_paths *paths,
                      const struct ssr_executor *executor,
                      struct ssr_time_state *state,
                      char *error, size_t error_len)
{
    int running;
    int cron_running;

    if (!paths || !state || ssr_time_read_config(paths, state) != 0 ||
        ssr_time_read_cron(paths, state) != 0) {
        ssr_error(error, error_len, "time_config_readback_failed");
        return -1;
    }
    if (ssr_service_status(executor, paths->init_sysntpd, &running) != 0) {
        ssr_error(error, error_len, "sysntpd_status_failed");
        return -1;
    }
    state->service_running = running;
    if (ssr_service_status(executor, paths->init_cron, &cron_running) != 0) {
        ssr_error(error, error_len, "cron_status_failed");
        return -1;
    }
    state->cron_service_running = cron_running;
    return 0;
}

int ssr_time_snapshot_capture(const struct ssr_paths *paths,
                              const struct ssr_executor *executor,
                              struct ssr_time_snapshot *snapshot,
                              char *error, size_t error_len)
{
    if (!paths || !snapshot)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    if (ssr_snapshot_file(paths->system_config,
                                                 &snapshot->system_config) != 0 ||
        ssr_snapshot_file(paths->root_crontab, &snapshot->root_crontab) != 0 ||
        ssr_time_readback(paths, executor, &snapshot->state, error, error_len) != 0) {
        ssr_error(error, error_len, "time_snapshot_failed");
        ssr_time_snapshot_clear(snapshot);
        return -1;
    }
    snapshot->valid = 1;
    return 0;
}

static int ssr_time_equal(const struct ssr_time_state *state,
                          const struct ssr_time_settings *settings)
{
    size_t i;

    if (!state || !settings || strcmp(state->settings.timezone, settings->timezone) ||
        state->settings.client_enabled != settings->client_enabled ||
        state->settings.server_enabled != settings->server_enabled ||
        state->settings.use_dhcp != settings->use_dhcp ||
        strcmp(state->settings.interval, settings->interval) ||
        state->settings.server_count != settings->server_count)
        return 0;
    for (i = 0; i < settings->server_count; i++)
        if (strcmp(state->settings.servers[i], settings->servers[i]))
            return 0;
    if (settings->client_enabled && strcmp(settings->interval, "auto") &&
        !state->cron_managed)
        return 0;
    return 1;
}

static int ssr_time_restore(const struct ssr_paths *paths,
                            const struct ssr_executor *executor,
                            const struct ssr_time_snapshot *snapshot)
{
    struct ssr_time_state state;
    char error[SSR_ERROR_MAX] = "";

    if (!snapshot || !snapshot->valid ||
        ssr_restore_file(paths->system_config, &snapshot->system_config) != 0 ||
        ssr_restore_file(paths->root_crontab, &snapshot->root_crontab) != 0 ||
        ssr_service_reload(executor, paths->init_sysntpd) != 0 ||
        ssr_service_set_state(executor, paths->init_cron,
                              snapshot->state.cron_service_running) != 0 ||
        ssr_time_readback(paths, executor, &state, error, sizeof(error)) != 0)
        return -1;
    if (state.service_running != snapshot->state.service_running ||
        state.cron_service_running != snapshot->state.cron_service_running ||
        state.cron_managed != snapshot->state.cron_managed ||
        !ssr_time_equal(&state, &snapshot->state.settings))
        return -1;
    return 0;
}

int ssr_time_apply(const struct ssr_paths *paths,
                   const struct ssr_executor *executor,
                   const struct ssr_time_settings *settings,
                   struct ssr_result *result)
{
    struct ssr_time_snapshot snapshot;
    struct ssr_time_state readback;
    struct ssr_assignment assignments[SSR_CONFIG_ASSIGNMENTS_MAX];
    char enabled[4];
    char server_enabled[4];
    char use_dhcp[4];
    size_t count = 0;
    size_t i;
    char error[SSR_ERROR_MAX];
    int field;

    memset(&snapshot, 0, sizeof(snapshot));
    ssr_result_reset(result);
    field = ssr_result_field(result, "general.time_policy");
    if (field < 0 || ssr_time_validate(paths, settings, error, sizeof(error)) != 0) {
        ssr_copy(result->error, sizeof(result->error), error);
        return -1;
    }
    ssr_copy(result->stage, sizeof(result->stage), "snapshot");
    if (ssr_time_snapshot_capture(paths, executor, &snapshot, error,
                                  sizeof(error)) != 0)
        goto fail;
    snprintf(enabled, sizeof(enabled), "%d", settings->client_enabled &&
             !strcmp(settings->interval, "auto"));
    snprintf(server_enabled, sizeof(server_enabled), "%d", settings->server_enabled);
    snprintf(use_dhcp, sizeof(use_dhcp), "%d", settings->use_dhcp);
    assignments[count++] = (struct ssr_assignment){"system", "system", "zonename",
                                                    settings->timezone, 0, 0};
    assignments[count++] = (struct ssr_assignment){"system", "system",
                                                    "dreamingwrt_ntp_interval",
                                                    settings->interval, 0, 0};
    assignments[count++] = (struct ssr_assignment){"timeserver", "ntp", "enabled",
                                                    enabled, 0, 0};
    assignments[count++] = (struct ssr_assignment){"timeserver", "ntp",
                                                    "enable_server", server_enabled, 0, 0};
    assignments[count++] = (struct ssr_assignment){"timeserver", "ntp", "use_dhcp",
                                                    use_dhcp, 0, 0};
    if (settings->server_count == 0) {
        assignments[count++] = (struct ssr_assignment){"timeserver", "ntp", "server",
                                                        "", 1, 1};
    } else {
        for (i = 0; i < settings->server_count; i++)
            assignments[count++] = (struct ssr_assignment){"timeserver", "ntp",
                                                            "server",
                                                            settings->servers[i], 1, 0};
    }
    ssr_copy(result->stage, sizeof(result->stage), "persist");
    if (ssr_write_config(paths, assignments, count, snapshot.system_config.mode) != 0 ||
        ssr_cron_rewrite(paths->root_crontab, settings) != 0)
        goto fail;
    result->fields[field].persisted = 1;
    ssr_copy(result->stage, sizeof(result->stage), "reload");
    if (ssr_service_reload(executor, paths->init_sysntpd) != 0 ||
        ssr_time_readback(paths, executor, &readback, error, sizeof(error)) != 0 ||
        !ssr_time_equal(&readback, settings))
        goto fail;
    result->fields[field].applied = 1;
    result->fields[field].running = 1;
    result->ok = 1;
    ssr_time_snapshot_clear(&snapshot);
    return 0;
fail:
    ssr_copy(result->error, sizeof(result->error), error[0] ? error :
             "time_apply_failed");
    result->rollback_attempted = 1;
    ssr_copy(result->stage, sizeof(result->stage), "rollback");
    result->rollback_ok = ssr_time_restore(paths, executor, &snapshot) == 0;
    result->fields[field].rollback = result->rollback_ok;
    ssr_time_snapshot_clear(&snapshot);
    return -1;
}

int ssr_time_rollback(const struct ssr_paths *paths,
                      const struct ssr_executor *executor,
                      const struct ssr_time_snapshot *snapshot,
                      struct ssr_result *result)
{
    ssr_result_reset(result);
    if (!snapshot || !snapshot->valid || ssr_time_restore(paths, executor, snapshot) != 0) {
        ssr_copy(result->error, sizeof(result->error), "time_rollback_failed");
        return -1;
    }
    result->ok = 1;
    result->rollback_attempted = 1;
    result->rollback_ok = 1;
    return 0;
}

void ssr_time_snapshot_clear(struct ssr_time_snapshot *snapshot)
{
    if (!snapshot)
        return;
    ssr_snapshot_file_clear(&snapshot->system_config);
    ssr_snapshot_file_clear(&snapshot->root_crontab);
    memset(snapshot, 0, sizeof(*snapshot));
}

int ssr_log_probe(const struct ssr_paths *paths, struct ssr_probe *probe)
{
    if (!paths || !probe)
        return -1;
    memset(probe, 0, sizeof(*probe));
    probe->persistent = ssr_file_exists(paths->system_config);
    probe->apply_supported = paths->init_log && paths->init_log[0] &&
                             paths->init_cron && paths->init_cron[0];
    probe->readback_supported = probe->persistent && probe->apply_supported;
    probe->rollback_supported = probe->persistent;
    probe->available = probe->apply_supported;
    if (!probe->available)
        ssr_copy(probe->reason, sizeof(probe->reason), "log_or_cron_unavailable");
    return 0;
}

int ssr_log_validate(const struct ssr_paths *paths,
                     const struct ssr_log_settings *settings,
                     char *error, size_t error_len)
{
    int level;

    if (!paths || !settings) {
        ssr_error(error, error_len, "invalid_argument");
        return -1;
    }
    if (settings->local_level[0]) {
        ssr_error(error, error_len, "local_log_level_unsupported_by_logd");
        return -1;
    }
    if (settings->kernel_level[0] && ssr_level_value(settings->kernel_level) < 0) {
        ssr_error(error, error_len, "invalid_kernel_log_level");
        return -1;
    }
    if (settings->cron_level[0] && ssr_cron_level_value(settings->cron_level) < 0) {
        ssr_error(error, error_len, "invalid_cron_log_level");
        return -1;
    }
    if (settings->buffer_kib < 16U || settings->buffer_kib > 8192U) {
        ssr_error(error, error_len, "log_buffer_out_of_range");
        return -1;
    }
    if (settings->remote_port == 0U || settings->remote_port > 65535U) {
        ssr_error(error, error_len, "invalid_remote_log_port");
        return -1;
    }
    if (strcmp(settings->remote_protocol, "udp") &&
        strcmp(settings->remote_protocol, "tcp")) {
        ssr_error(error, error_len, "invalid_remote_log_protocol");
        return -1;
    }
    if (settings->remote_enabled && !ssr_server_valid(settings->remote_host)) {
        ssr_error(error, error_len, "invalid_remote_log_host");
        return -1;
    }
    if (!ssr_log_path_allowed(settings->file_path)) {
        ssr_error(error, error_len, "log_file_path_not_allowed");
        return -1;
    }
    level = ssr_level_value(settings->kernel_level);
    if (level > 8) {
        ssr_error(error, error_len, "invalid_kernel_log_level");
        return -1;
    }
    return 0;
}

static int ssr_log_read_config(const struct ssr_paths *paths,
                               struct ssr_log_state *state)
{
    char *data = NULL;
    char value[SSR_PATH_MAX + SSR_SERVER_MAX];
    size_t length = 0;
    mode_t mode;
    int existed;
    unsigned long parsed;

    if (ssr_read_file(paths->system_config, &data, &length, &mode, &existed) != 0)
        return -1;
    memset(state, 0, sizeof(*state));
    ssr_copy(state->settings.remote_protocol, sizeof(state->settings.remote_protocol),
             "udp");
    ssr_copy(state->settings.cron_level, sizeof(state->settings.cron_level),
             "disabled");
    if (ssr_config_value(data, "system", "system", "conloglevel", value,
                         sizeof(value), 0U) == 0) {
        parsed = strtoul(value, NULL, 10);
        if (parsed < 8U) {
            static const char *const names[] = {"emergency", "alert", "critical",
                                                "error", "warning", "notice",
                                                "info", "debug"};
            ssr_copy(state->settings.kernel_level,
                     sizeof(state->settings.kernel_level), names[parsed]);
        }
    }
    if (ssr_config_value(data, "system", "system", "log_buffer_size", value,
                         sizeof(value), 0U) == 0) {
        parsed = strtoul(value, NULL, 10);
        state->settings.buffer_kib = (unsigned int)(parsed / 1024U);
    }
    if (ssr_config_value(data, "system", "system", "cronloglevel", value,
                         sizeof(value), 0U) == 0) {
        parsed = strtoul(value, NULL, 10);
        ssr_copy(state->settings.cron_level,
                 sizeof(state->settings.cron_level), parsed == 3U ? "error" :
                 (parsed >= 8U ? "all" : "disabled"));
    }
    if (ssr_config_value(data, "system", "system", "log_remote", value,
                         sizeof(value), 0U) == 0)
        state->settings.remote_enabled = atoi(value) != 0;
    if (ssr_config_value(data, "system", "system", "log_ip", value,
                         sizeof(value), 0U) == 0)
        ssr_copy(state->settings.remote_host, sizeof(state->settings.remote_host), value);
    if (ssr_config_value(data, "system", "system", "log_port", value,
                         sizeof(value), 0U) == 0)
        state->settings.remote_port = (unsigned int)strtoul(value, NULL, 10);
    else
        state->settings.remote_port = 514U;
    if (ssr_config_value(data, "system", "system", "log_proto", value,
                         sizeof(value), 0U) == 0)
        ssr_copy(state->settings.remote_protocol,
                 sizeof(state->settings.remote_protocol), value);
    if (ssr_config_value(data, "system", "system", "log_file", value,
                         sizeof(value), 0U) == 0)
        ssr_copy(state->settings.file_path, sizeof(state->settings.file_path), value);
    free(data);
    (void)length;
    (void)mode;
    (void)existed;
    return 0;
}

int ssr_log_readback(const struct ssr_paths *paths,
                     const struct ssr_executor *executor,
                     struct ssr_log_state *state,
                     char *error, size_t error_len)
{
    if (!paths || !state || ssr_log_read_config(paths, state) != 0 ||
        ssr_service_status(executor, paths->init_log, &state->log_service_running) != 0 ||
        ssr_service_status(executor, paths->init_cron, &state->cron_service_running) != 0) {
        ssr_error(error, error_len, "log_readback_failed");
        return -1;
    }
    return 0;
}

int ssr_log_snapshot_capture(const struct ssr_paths *paths,
                             const struct ssr_executor *executor,
                             struct ssr_log_snapshot *snapshot,
                             char *error, size_t error_len)
{
    if (!paths || !snapshot)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    if (ssr_snapshot_file(paths->system_config,
                                                 &snapshot->system_config) != 0 ||
        ssr_log_readback(paths, executor, &snapshot->state, error, error_len) != 0) {
        ssr_error(error, error_len, "log_snapshot_failed");
        ssr_log_snapshot_clear(snapshot);
        return -1;
    }
    snapshot->valid = 1;
    return 0;
}

static int ssr_log_equal(const struct ssr_log_state *state,
                         const struct ssr_log_settings *settings)
{
    return state && settings &&
           strcmp(state->settings.kernel_level, settings->kernel_level) == 0 &&
           strcmp(state->settings.cron_level, settings->cron_level) == 0 &&
           state->settings.buffer_kib == settings->buffer_kib &&
           state->settings.remote_enabled == settings->remote_enabled &&
           strcmp(state->settings.remote_host, settings->remote_host) == 0 &&
           state->settings.remote_port == settings->remote_port &&
           strcmp(state->settings.remote_protocol, settings->remote_protocol) == 0 &&
           strcmp(state->settings.file_path, settings->file_path) == 0;
}

static int ssr_log_restore(const struct ssr_paths *paths,
                           const struct ssr_executor *executor,
                           const struct ssr_log_snapshot *snapshot)
{
    struct ssr_log_state state;
    char error[SSR_ERROR_MAX];

    if (!snapshot || !snapshot->valid ||
        ssr_restore_file(paths->system_config, &snapshot->system_config) != 0 ||
        ssr_service_reload(executor, paths->init_log) != 0 ||
        ssr_service_reload(executor, paths->init_cron) != 0 ||
        ssr_service_set_state(executor, paths->init_log,
                              snapshot->state.log_service_running) != 0 ||
        ssr_service_set_state(executor, paths->init_cron,
                              snapshot->state.cron_service_running) != 0 ||
        ssr_log_readback(paths, executor, &state, error, sizeof(error)) != 0)
        return -1;
    if (state.log_service_running != snapshot->state.log_service_running ||
        state.cron_service_running != snapshot->state.cron_service_running ||
        !ssr_log_equal(&state, &snapshot->state.settings))
        return -1;
    return 0;
}

int ssr_log_apply(const struct ssr_paths *paths,
                  const struct ssr_executor *executor,
                  const struct ssr_log_settings *settings,
                  struct ssr_result *result)
{
    struct ssr_log_snapshot snapshot;
    struct ssr_log_state readback;
    struct ssr_assignment assignments[10];
    char kernel[8];
    char cron[8];
    char buffer[32];
    char remote[4];
    char port[8];
    size_t count = 0;
    char error[SSR_ERROR_MAX] = "";
    int field;
    int kernel_value;
    int cron_value;

    memset(&snapshot, 0, sizeof(snapshot));
    ssr_result_reset(result);
    field = ssr_result_field(result, "general.logging");
    if (field < 0 || ssr_log_validate(paths, settings, error, sizeof(error)) != 0) {
        ssr_copy(result->error, sizeof(result->error), error);
        return -1;
    }
    kernel_value = settings->kernel_level[0] ? ssr_level_value(settings->kernel_level) : -1;
    cron_value = ssr_cron_level_value(settings->cron_level);
    snprintf(kernel, sizeof(kernel), "%d", kernel_value < 0 ? 4 : kernel_value);
    snprintf(cron, sizeof(cron), "%d", cron_value < 0 ? 0 : cron_value);
    snprintf(buffer, sizeof(buffer), "%u", settings->buffer_kib * 1024U);
    snprintf(remote, sizeof(remote), "%d", settings->remote_enabled);
    snprintf(port, sizeof(port), "%u", settings->remote_port);
    if (ssr_log_snapshot_capture(paths, executor, &snapshot, error, sizeof(error)) != 0)
        goto fail;
    assignments[count++] = (struct ssr_assignment){"system", "system", "conloglevel",
                                                    kernel, 0, 0};
    assignments[count++] = (struct ssr_assignment){"system", "system", "log_buffer_size",
                                                    buffer, 0, 0};
    assignments[count++] = (struct ssr_assignment){"system", "system", "cronloglevel",
                                                    cron, 0, 0};
    assignments[count++] = (struct ssr_assignment){"system", "system", "log_remote",
                                                    remote, 0, 0};
    assignments[count++] = (struct ssr_assignment){"system", "system", "log_ip",
                                                    settings->remote_host, 0, 0};
    assignments[count++] = (struct ssr_assignment){"system", "system", "log_port",
                                                    port, 0, 0};
    assignments[count++] = (struct ssr_assignment){"system", "system", "log_proto",
                                                    settings->remote_protocol, 0, 0};
    assignments[count++] = (struct ssr_assignment){"system", "system", "log_file",
                                                    settings->file_path, 0, 0};
    ssr_copy(result->stage, sizeof(result->stage), "persist");
    if (ssr_write_config(paths, assignments, count, snapshot.system_config.mode) != 0)
        goto fail;
    result->fields[field].persisted = 1;
    ssr_copy(result->stage, sizeof(result->stage), "reload");
    if (ssr_service_reload(executor, paths->init_log) != 0 ||
        ssr_service_reload(executor, paths->init_cron) != 0 ||
        ssr_log_readback(paths, executor, &readback, error, sizeof(error)) != 0 ||
        !ssr_log_equal(&readback, settings))
        goto fail;
    result->fields[field].applied = 1;
    result->fields[field].running = 1;
    result->ok = 1;
    ssr_log_snapshot_clear(&snapshot);
    return 0;
fail:
    ssr_copy(result->error, sizeof(result->error), error[0] ? error :
             "log_apply_failed");
    result->rollback_attempted = 1;
    ssr_copy(result->stage, sizeof(result->stage), "rollback");
    result->rollback_ok = ssr_log_restore(paths, executor, &snapshot) == 0;
    result->fields[field].rollback = result->rollback_ok;
    ssr_log_snapshot_clear(&snapshot);
    return -1;
}

int ssr_log_rollback(const struct ssr_paths *paths,
                     const struct ssr_executor *executor,
                     const struct ssr_log_snapshot *snapshot,
                     struct ssr_result *result)
{
    ssr_result_reset(result);
    if (!snapshot || !snapshot->valid || ssr_log_restore(paths, executor, snapshot) != 0) {
        ssr_copy(result->error, sizeof(result->error), "log_rollback_failed");
        return -1;
    }
    result->ok = 1;
    result->rollback_attempted = 1;
    result->rollback_ok = 1;
    return 0;
}

void ssr_log_snapshot_clear(struct ssr_log_snapshot *snapshot)
{
    if (!snapshot)
        return;
    ssr_snapshot_file_clear(&snapshot->system_config);
    memset(snapshot, 0, sizeof(*snapshot));
}

int ssr_zram_probe(const struct ssr_paths *paths, struct ssr_probe *probe)
{
    if (!paths || !probe)
        return -1;
    memset(probe, 0, sizeof(*probe));
    probe->persistent = ssr_file_exists(paths->system_config);
    probe->apply_supported = ssr_dir_exists(paths->zram_sysfs) &&
                             ssr_file_exists(paths->zram_device) &&
                             paths->busybox && paths->busybox[0];
    probe->readback_supported = probe->apply_supported &&
                                ssr_file_exists(paths->proc_swaps);
    probe->rollback_supported = probe->persistent && probe->apply_supported;
    probe->available = probe->apply_supported;
    if (!probe->available)
        ssr_copy(probe->reason, sizeof(probe->reason), "zram_device_unavailable");
    return 0;
}

static int ssr_zram_read_text(const struct ssr_paths *paths, const char *name,
                              char *value, size_t value_len)
{
    char path[SSR_PATH_MAX];
    char *data = NULL;
    size_t length = 0;
    mode_t mode;
    int existed;

    if (ssr_join(path, sizeof(path), paths->zram_sysfs, name) != 0 ||
        ssr_read_file(path, &data, &length, &mode, &existed) != 0 || !existed) {
        free(data);
        return -1;
    }
    ssr_copy(value, value_len, data);
    ssr_trim(value);
    free(data);
    (void)length;
    (void)mode;
    return 0;
}

static int ssr_zram_write_text(const struct ssr_paths *paths, const char *name,
                               const char *value)
{
    char path[SSR_PATH_MAX];
    int fd;
    struct stat st;
    size_t length;

    if (!value || ssr_join(path, sizeof(path), paths->zram_sysfs, name) != 0)
        return -1;
    fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && ftruncate(fd, 0) != 0) {
        close(fd);
        return -1;
    }
    length = strlen(value);
    if (write(fd, value, length) != (ssize_t)length || close(fd) != 0)
        return -1;
    return 0;
}

static int ssr_zram_algorithm_supported(const char *available, const char *wanted)
{
    char copy[256];
    char *p;
    char token[64];

    if (!available || !wanted || strlen(available) >= sizeof(copy))
        return 0;
    ssr_copy(copy, sizeof(copy), available);
    for (p = strtok(copy, " \t\r\n[]"); p; p = strtok(NULL, " \t\r\n[]")) {
        ssr_copy(token, sizeof(token), p);
        if (!strcmp(token, wanted))
            return 1;
    }
    return 0;
}

static int ssr_zram_selected_algorithm(const char *available, char *algorithm,
                                       size_t algorithm_len)
{
    const char *start;
    const char *end;
    char value[64];

    if (!available || !algorithm || !algorithm_len)
        return -1;
    start = strchr(available, '[');
    if (start) {
        end = strchr(start + 1, ']');
        if (!end || end == start + 1 || (size_t)(end - start - 1) >= sizeof(value))
            return -1;
        memcpy(value, start + 1, (size_t)(end - start - 1));
        value[end - start - 1] = '\0';
    } else {
        ssr_copy(value, sizeof(value), available);
        ssr_trim(value);
    }
    ssr_copy(algorithm, algorithm_len, value);
    return algorithm[0] ? 0 : -1;
}

static int ssr_zram_read_active(const struct ssr_paths *paths, int *active,
                                int *priority)
{
    char *data = NULL;
    char device[SSR_PATH_MAX];
    char *line;
    char *saveptr = NULL;
    size_t length = 0;
    mode_t mode;
    int existed;
    int found = 0;

    if (!active || !priority || ssr_read_file(paths->proc_swaps, &data, &length,
                                              &mode, &existed) != 0)
        return -1;
    *active = 0;
    *priority = 100;
    ssr_copy(device, sizeof(device), paths->zram_device);
    for (line = strtok_r(data, "\n", &saveptr); line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char filename[SSR_PATH_MAX];
        int parsed_priority;

        if (sscanf(line, "%511s %*s %*u %*u %d", filename, &parsed_priority) == 2 &&
            !strcmp(filename, device)) {
            *active = 1;
            *priority = parsed_priority;
            found = 1;
            break;
        }
    }
    free(data);
    (void)length;
    (void)mode;
    (void)existed;
    return found || !*active ? 0 : -1;
}

int ssr_zram_validate(const struct ssr_paths *paths,
                      const struct ssr_zram_settings *settings,
                      char *error, size_t error_len)
{
    char available[256];
    uint64_t memory_mib;

    if (!paths || !settings) {
        ssr_error(error, error_len, "invalid_argument");
        return -1;
    }
    if (!ssr_dir_exists(paths->zram_sysfs) || !ssr_file_exists(paths->zram_device)) {
        ssr_error(error, error_len, "zram_device_unavailable");
        return -1;
    }
    if (settings->size_mib < 16U || ssr_read_mem_mib(paths->meminfo, &memory_mib) != 0 ||
        settings->size_mib > memory_mib * 2U) {
        ssr_error(error, error_len, "zram_size_out_of_memory_bounds");
        return -1;
    }
    if (!ssr_safe_token(settings->algorithm, sizeof(settings->algorithm) - 1U, 0)) {
        ssr_error(error, error_len, "invalid_zram_algorithm");
        return -1;
    }
    if (ssr_zram_read_text(paths, "comp_algorithm", available,
                           sizeof(available)) != 0 ||
        !ssr_zram_algorithm_supported(available, settings->algorithm)) {
        ssr_error(error, error_len, "zram_algorithm_unsupported");
        return -1;
    }
    return 0;
}

int ssr_zram_readback(const struct ssr_paths *paths,
                      const struct ssr_executor *executor,
                      struct ssr_zram_state *state,
                      char *error, size_t error_len)
{
    char value[256];
    unsigned long long bytes;
    (void)executor;

    if (!paths || !state || ssr_zram_read_text(paths, "comp_algorithm", value,
                                               sizeof(value)) != 0 ||
        ssr_zram_selected_algorithm(value, state->settings.algorithm,
                                    sizeof(state->settings.algorithm)) != 0 ||
        ssr_zram_read_text(paths, "disksize", value, sizeof(value)) != 0 ||
        sscanf(value, "%llu", &bytes) != 1 ||
        ssr_zram_read_active(paths, &state->active, &state->priority) != 0) {
        ssr_error(error, error_len, "zram_readback_failed");
        return -1;
    }
    state->settings.size_mib = bytes / (1024ULL * 1024ULL);
    return 0;
}

int ssr_zram_snapshot_capture(const struct ssr_paths *paths,
                              const struct ssr_executor *executor,
                              struct ssr_zram_snapshot *snapshot,
                              char *error, size_t error_len)
{
    if (!paths || !snapshot)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    if (ssr_snapshot_file(paths->system_config,
                                                 &snapshot->system_config) != 0 ||
        ssr_zram_readback(paths, executor, &snapshot->state, error, error_len) != 0) {
        ssr_error(error, error_len, "zram_snapshot_failed");
        ssr_zram_snapshot_clear(snapshot);
        return -1;
    }
    snapshot->valid = 1;
    return 0;
}

static int ssr_zram_command(const struct ssr_paths *paths,
                            const struct ssr_executor *executor,
                            const char *action, const char *extra,
                            int priority)
{
    char priority_text[16];
    const char *argv[6];

    if (!paths || !paths->busybox || !paths->zram_device)
        return -1;
    argv[0] = paths->busybox;
    argv[1] = action;
    if (!strcmp(action, "swapon")) {
        argv[2] = "-d";
        argv[3] = "-p";
        snprintf(priority_text, sizeof(priority_text), "%d", priority);
        argv[4] = priority_text;
        argv[5] = paths->zram_device;
        return ssr_command(executor, argv, NULL, NULL, 0U);
    }
    argv[2] = extra ? extra : paths->zram_device;
    argv[3] = NULL;
    return ssr_command(executor, argv, NULL, NULL, 0U);
}

static int ssr_zram_restore_runtime(const struct ssr_paths *paths,
                                    const struct ssr_executor *executor,
                                    const struct ssr_zram_state *old)
{
    char size[32];
    int active = 0;
    int priority = 0;

    if (ssr_zram_read_active(paths, &active, &priority) != 0)
        return -1;
    if (active && ssr_zram_command(paths, executor, "swapoff", NULL, 0) != 0)
        return -1;
    if (ssr_zram_write_text(paths, "reset", "1\n") != 0 ||
        ssr_zram_write_text(paths, "comp_algorithm", old->settings.algorithm) != 0) {
        return -1;
    }
    snprintf(size, sizeof(size), "%llu",
             (unsigned long long)(old->settings.size_mib * 1024ULL * 1024ULL));
    if (ssr_zram_write_text(paths, "disksize", size) != 0)
        return -1;
    if (old->active &&
        (ssr_zram_command(paths, executor, "mkswap", NULL, 0) != 0 ||
         ssr_zram_command(paths, executor, "swapon", NULL, old->priority) != 0))
        return -1;
    return 0;
}

static int ssr_zram_restore(const struct ssr_paths *paths,
                            const struct ssr_executor *executor,
                            const struct ssr_zram_snapshot *snapshot)
{
    struct ssr_zram_state state;
    char error[SSR_ERROR_MAX];

    if (!snapshot || !snapshot->valid ||
        ssr_restore_file(paths->system_config, &snapshot->system_config) != 0 ||
        ssr_zram_restore_runtime(paths, executor, &snapshot->state) != 0 ||
        ssr_zram_readback(paths, executor, &state, error, sizeof(error)) != 0)
        return -1;
    return state.active == snapshot->state.active &&
           state.priority == snapshot->state.priority &&
           state.settings.size_mib == snapshot->state.settings.size_mib &&
           !strcmp(state.settings.algorithm, snapshot->state.settings.algorithm) ? 0 : -1;
}

static int ssr_zram_equal(const struct ssr_zram_state *state,
                          const struct ssr_zram_settings *settings)
{
    return state && settings && state->settings.size_mib == settings->size_mib &&
           !strcmp(state->settings.algorithm, settings->algorithm);
}

int ssr_zram_apply(const struct ssr_paths *paths,
                   const struct ssr_executor *executor,
                   const struct ssr_zram_settings *settings,
                   struct ssr_result *result)
{
    struct ssr_zram_snapshot snapshot;
    struct ssr_zram_state readback;
    struct ssr_assignment assignments[2];
    char size[32];
    char error[SSR_ERROR_MAX] = "";
    char algorithm[32];
    int field;
    int active;
    int priority;

    memset(&snapshot, 0, sizeof(snapshot));
    ssr_result_reset(result);
    field = ssr_result_field(result, "advanced.zram");
    if (field < 0 || ssr_zram_validate(paths, settings, error, sizeof(error)) != 0) {
        ssr_copy(result->error, sizeof(result->error), error);
        return -1;
    }
    if (ssr_zram_snapshot_capture(paths, executor, &snapshot, error, sizeof(error)) != 0)
        goto fail;
    if (ssr_zram_read_active(paths, &active, &priority) != 0)
        goto fail;
    snprintf(size, sizeof(size), "%llu", (unsigned long long)settings->size_mib);
    ssr_copy(algorithm, sizeof(algorithm), settings->algorithm);
    assignments[0] = (struct ssr_assignment){"system", "system", "zram_size_mb",
                                              size, 0, 0};
    assignments[1] = (struct ssr_assignment){"system", "system", "zram_comp_algo",
                                              algorithm, 0, 0};
    ssr_copy(result->stage, sizeof(result->stage), "persist");
    if (ssr_write_config(paths, assignments, 2U, snapshot.system_config.mode) != 0)
        goto fail;
    result->fields[field].persisted = 1;
    ssr_copy(result->stage, sizeof(result->stage), "reconfigure");
    if (active && ssr_zram_command(paths, executor, "swapoff", NULL, 0) != 0)
        goto fail;
    if (ssr_zram_write_text(paths, "reset", "1\n") != 0 ||
        ssr_zram_write_text(paths, "comp_algorithm", settings->algorithm) != 0) {
        ssr_copy(error, sizeof(error), "zram_sysfs_write_failed");
        goto fail;
    }
    snprintf(size, sizeof(size), "%llu",
             (unsigned long long)(settings->size_mib * 1024ULL * 1024ULL));
    if (ssr_zram_write_text(paths, "disksize", size) != 0) {
        ssr_copy(error, sizeof(error), "zram_disksize_write_failed");
        goto fail;
    }
    if (active && (ssr_zram_command(paths, executor, "mkswap", NULL, 0) != 0 ||
                   ssr_zram_command(paths, executor, "swapon", NULL, priority) != 0)) {
        ssr_copy(error, sizeof(error), "zram_swap_activation_failed");
        goto fail;
    }
    if (ssr_zram_readback(paths, executor, &readback, error, sizeof(error)) != 0 ||
        !ssr_zram_equal(&readback, settings))
        goto fail;
    result->fields[field].applied = 1;
    result->fields[field].running = 1;
    result->ok = 1;
    ssr_zram_snapshot_clear(&snapshot);
    return 0;
fail:
    ssr_copy(result->error, sizeof(result->error), error[0] ? error :
             "zram_apply_failed");
    result->rollback_attempted = 1;
    ssr_copy(result->stage, sizeof(result->stage), "rollback");
    result->rollback_ok = ssr_zram_restore(paths, executor, &snapshot) == 0;
    result->fields[field].rollback = result->rollback_ok;
    ssr_zram_snapshot_clear(&snapshot);
    return -1;
}

int ssr_zram_rollback(const struct ssr_paths *paths,
                      const struct ssr_executor *executor,
                      const struct ssr_zram_snapshot *snapshot,
                      struct ssr_result *result)
{
    ssr_result_reset(result);
    if (!snapshot || !snapshot->valid || ssr_zram_restore(paths, executor, snapshot) != 0) {
        ssr_copy(result->error, sizeof(result->error), "zram_rollback_failed");
        return -1;
    }
    result->ok = 1;
    result->rollback_attempted = 1;
    result->rollback_ok = 1;
    return 0;
}

void ssr_zram_snapshot_clear(struct ssr_zram_snapshot *snapshot)
{
    if (!snapshot)
        return;
    ssr_snapshot_file_clear(&snapshot->system_config);
    memset(snapshot, 0, sizeof(*snapshot));
}
