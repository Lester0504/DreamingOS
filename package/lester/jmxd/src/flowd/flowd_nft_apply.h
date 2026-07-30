// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_NFT_APPLY_H
#define DREAMINGWRT_FLOWD_NFT_APPLY_H

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>

#define FLOWD_NFT_BINARY "/usr/sbin/nft"
#define FLOWD_NFT_TABLE "dreamingwrt_flowd"
#define FLOWD_NFT_REVISION_PREFIX "flowd-revision:"
#define FLOWD_NFT_OUTPUT_MAX (256U * 1024U)
#define FLOWD_NFT_COMMAND_TIMEOUT_MS 5000
#define FLOWD_NFT_TERM_GRACE_MS 200
#define FLOWD_NFT_RUN_TIMEOUT -2
#define FLOWD_NFT_RUN_OUTPUT_LIMIT -3
#define FLOWD_NFT_RUN_WAIT_FAILED -4

#ifndef FLOWD_NFT_WAITPID
#define FLOWD_NFT_WAITPID waitpid
#endif

#ifndef FLOWD_NFT_REAP_WAITPID
#define FLOWD_NFT_REAP_WAITPID waitpid
#endif

struct flowd_nft_readback {
    int command_ok;
    int present;
    int sentinel_only;
    char revision[128];
    char error[96];
};

struct flowd_nft_apply_result {
    int validated;
    int applied;
    int readback_ok;
    int rolled_back;
    int rollback_ok;
    int previous_present;
    char previous_revision[128];
    char revision[128];
    char apply_path[PATH_MAX];
    char rollback_path[PATH_MAX];
    char error[96];
};

static inline int flowd_nft_write_all(int fd, const void *data, size_t len)
{
    const unsigned char *p = data;
    size_t off = 0;

    while (off < len) {
        ssize_t rc = write(fd, p + off, len - off);

        if (rc < 0 && errno == EINTR)
            continue;
        if (rc <= 0)
            return -1;
        off += (size_t)rc;
    }
    return 0;
}

static inline int flowd_nft_safe_token(const char *s, size_t max_len)
{
    const unsigned char *p;

    if (!s || !s[0] || strlen(s) > max_len)
        return 0;
    for (p = (const unsigned char *)s; *p; p++) {
        if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.'))
            return 0;
    }
    return 1;
}

static inline int flowd_nft_join(char *out, size_t out_len,
                                 const char *dir, const char *leaf)
{
    int n;

    if (!out || !out_len || !dir || dir[0] != '/' || !leaf || strchr(leaf, '/'))
        return -1;
    n = snprintf(out, out_len, "%s%s%s", dir,
                 dir[strlen(dir) - 1] == '/' ? "" : "/", leaf);
    return n > 0 && (size_t)n < out_len ? 0 : -1;
}

static inline int flowd_nft_write_file(const char *path, const char *text)
{
    int fd;
    size_t len;

    if (!path || path[0] != '/' || !text)
        return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return -1;
    len = strlen(text);
    if (flowd_nft_write_all(fd, text, len) != 0) {
        close(fd);
        return -1;
    }
    if (fsync(fd) != 0 || close(fd) != 0)
        return -1;
    return 0;
}

static inline int64_t flowd_nft_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return -1;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static inline int flowd_nft_kill_and_reap(pid_t pid)
{
    int status = 0;
    int64_t deadline = flowd_nft_monotonic_ms() + FLOWD_NFT_TERM_GRACE_MS;

    if (pid <= 0)
        return -1;
    kill(pid, SIGTERM);
    while (flowd_nft_monotonic_ms() < deadline) {
        pid_t rc = FLOWD_NFT_REAP_WAITPID(pid, &status, WNOHANG);

        if (rc == pid)
            return 0;
        if (rc < 0 && errno != EINTR)
            return -1;
        usleep(10000);
    }
    kill(pid, SIGKILL);
    for (;;) {
        pid_t rc = FLOWD_NFT_REAP_WAITPID(pid, &status, 0);

        if (rc == pid)
            return 0;
        if (rc < 0 && errno == EINTR)
            continue;
        return -1;
    }
}

static inline int flowd_nft_run_timeout(const char *binary, char *const argv[],
                                        const char *output_path, int timeout_ms)
{
    struct pollfd pfd;
    char buf[4096];
    pid_t pid;
    int pipefd[2] = { -1, -1 };
    int output_fd = -1;
    int status = 0;
    int child_done = 0;
    int eof = 0;
    int terminal_error = 0;
    size_t output_bytes = 0;
    int64_t deadline;

    if (!binary || binary[0] != '/' || !argv || !argv[0] || !output_path ||
        timeout_ms < 1)
        return -1;
    deadline = flowd_nft_monotonic_ms();
    if (deadline < 0)
        return -1;
    deadline += timeout_ms;
    if (pipe(pipefd) != 0)
        return -1;
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
    output_fd = open(output_path,
                     O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                     0600);
    if (output_fd < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(output_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        close(output_fd);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(126);
        close(pipefd[1]);
        execv(binary, argv);
        _exit(127);
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);
    pfd.fd = pipefd[0];
    pfd.events = POLLIN | POLLHUP;

    while (!child_done || !eof) {
        ssize_t n;
        pid_t wait_rc;
        int64_t now;

        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
            size_t allowed = output_bytes < FLOWD_NFT_OUTPUT_MAX
                ? FLOWD_NFT_OUTPUT_MAX - output_bytes : 0;
            size_t keep = (size_t)n < allowed ? (size_t)n : allowed;

            if (keep > 0 && flowd_nft_write_all(output_fd, buf, keep) != 0) {
                terminal_error = -1;
                break;
            }
            output_bytes += keep;
            if (keep != (size_t)n) {
                terminal_error = FLOWD_NFT_RUN_OUTPUT_LIMIT;
                break;
            }
        }
        if (n == 0)
            eof = 1;
        else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            terminal_error = -1;
        if (terminal_error && !child_done) {
            if (flowd_nft_kill_and_reap(pid) != 0 &&
                terminal_error != FLOWD_NFT_RUN_WAIT_FAILED)
                terminal_error = FLOWD_NFT_RUN_WAIT_FAILED;
            child_done = 1;
        }
        if (!child_done) {
            wait_rc = FLOWD_NFT_WAITPID(pid, &status, WNOHANG);
            if (wait_rc == pid)
                child_done = 1;
            else if (wait_rc < 0 && errno != EINTR) {
                terminal_error = FLOWD_NFT_RUN_WAIT_FAILED;
                flowd_nft_kill_and_reap(pid);
                child_done = 1;
            }
        }
        if (child_done && !eof && n < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK))
            eof = 1;
        now = flowd_nft_monotonic_ms();
        if (!child_done && (now < 0 || now >= deadline)) {
            terminal_error = FLOWD_NFT_RUN_TIMEOUT;
            if (flowd_nft_kill_and_reap(pid) != 0)
                terminal_error = FLOWD_NFT_RUN_WAIT_FAILED;
            child_done = 1;
        }
        if (!child_done || !eof)
            poll(&pfd, 1, 10);
    }
    fsync(output_fd);
    close(output_fd);
    close(pipefd[0]);
    if (terminal_error)
        return terminal_error;
    if (!WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static inline int flowd_nft_run(const char *binary, char *const argv[],
                                const char *output_path)
{
    return flowd_nft_run_timeout(binary, argv, output_path,
                                 FLOWD_NFT_COMMAND_TIMEOUT_MS);
}

static inline struct json_object *flowd_nft_read_json_file(const char *path)
{
    struct stat st;
    struct json_object *obj = NULL;
    char *buf;
    int fd;
    ssize_t off = 0;

    if (!path || stat(path, &st) != 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size > FLOWD_NFT_OUTPUT_MAX)
        return NULL;
    buf = calloc(1, (size_t)st.st_size + 1);
    if (!buf)
        return NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        free(buf);
        return NULL;
    }
    while (off < st.st_size) {
        ssize_t rc = read(fd, buf + off, (size_t)(st.st_size - off));

        if (rc < 0 && errno == EINTR)
            continue;
        if (rc <= 0)
            break;
        off += rc;
    }
    close(fd);
    if (off == st.st_size)
        obj = json_tokener_parse(buf);
    free(buf);
    return obj;
}

static inline int flowd_nft_json_table_present(struct json_object *root)
{
    struct json_object *items = NULL;
    size_t i;

    if (!root || !json_object_object_get_ex(root, "nftables", &items) ||
        !json_object_is_type(items, json_type_array))
        return -1;
    for (i = 0; i < json_object_array_length(items); i++) {
        struct json_object *entry = json_object_array_get_idx(items, i);
        struct json_object *table = NULL;
        struct json_object *family = NULL;
        struct json_object *name = NULL;

        if (!entry || !json_object_object_get_ex(entry, "table", &table))
            continue;
        if (json_object_object_get_ex(table, "family", &family) &&
            json_object_object_get_ex(table, "name", &name) &&
            !strcmp(json_object_get_string(family), "inet") &&
            !strcmp(json_object_get_string(name), FLOWD_NFT_TABLE))
            return 1;
    }
    return 0;
}

static inline int flowd_nft_json_sentinel(struct json_object *root,
                                          struct flowd_nft_readback *out)
{
    struct json_object *items = NULL;
    size_t i;
    int table_count = 0;
    int other_count = 0;

    if (!root || !out || !json_object_object_get_ex(root, "nftables", &items) ||
        !json_object_is_type(items, json_type_array))
        return -1;
    for (i = 0; i < json_object_array_length(items); i++) {
        struct json_object *entry = json_object_array_get_idx(items, i);
        struct json_object *table = NULL;
        struct json_object *meta = NULL;

        if (!entry)
            continue;
        if (json_object_object_get_ex(entry, "metainfo", &meta))
            continue;
        if (json_object_object_get_ex(entry, "table", &table)) {
            struct json_object *family = NULL;
            struct json_object *name = NULL;
            struct json_object *comment = NULL;
            const char *comment_s = "";

            table_count++;
            if (!json_object_object_get_ex(table, "family", &family) ||
                !json_object_object_get_ex(table, "name", &name) ||
                strcmp(json_object_get_string(family), "inet") ||
                strcmp(json_object_get_string(name), FLOWD_NFT_TABLE))
                return -1;
            if (json_object_object_get_ex(table, "comment", &comment))
                comment_s = json_object_get_string(comment);
            if (!comment_s || strncmp(comment_s, FLOWD_NFT_REVISION_PREFIX,
                                      strlen(FLOWD_NFT_REVISION_PREFIX)) != 0)
                return 0;
            snprintf(out->revision, sizeof(out->revision), "%s",
                     comment_s + strlen(FLOWD_NFT_REVISION_PREFIX));
        } else {
            other_count++;
        }
    }
    out->sentinel_only = table_count == 1 && other_count == 0 && out->revision[0];
    return out->sentinel_only ? 1 : 0;
}

static inline int flowd_nft_readback(const char *binary, const char *runtime_dir,
                                     const char *tag,
                                     struct flowd_nft_readback *out)
{
    char list_path[PATH_MAX];
    char table_path[PATH_MAX];
    char leaf[192];
    struct json_object *json = NULL;
    int present;
    int rc;
    char *list_argv[] = { (char *)binary, "-j", "list", "tables", NULL };
    char *table_argv[] = { (char *)binary, "-j", "list", "table", "inet",
                           FLOWD_NFT_TABLE, NULL };

    if (!out || !flowd_nft_safe_token(tag, 120))
        return -1;
    memset(out, 0, sizeof(*out));
    snprintf(leaf, sizeof(leaf), "nft-%s-list.json", tag);
    if (flowd_nft_join(list_path, sizeof(list_path), runtime_dir, leaf) != 0)
        return -1;
    rc = flowd_nft_run(binary, list_argv, list_path);
    if (rc != 0) {
        snprintf(out->error, sizeof(out->error), "nft_list_tables_failed");
        return -1;
    }
    json = flowd_nft_read_json_file(list_path);
    present = flowd_nft_json_table_present(json);
    json_object_put(json);
    if (present < 0) {
        snprintf(out->error, sizeof(out->error), "nft_list_tables_invalid_json");
        return -1;
    }
    out->command_ok = 1;
    out->present = present;
    if (!present)
        return 0;

    snprintf(leaf, sizeof(leaf), "nft-%s-table.json", tag);
    if (flowd_nft_join(table_path, sizeof(table_path), runtime_dir, leaf) != 0)
        return -1;
    rc = flowd_nft_run(binary, table_argv, table_path);
    if (rc != 0) {
        snprintf(out->error, sizeof(out->error), "nft_list_table_failed");
        return -1;
    }
    json = flowd_nft_read_json_file(table_path);
    rc = flowd_nft_json_sentinel(json, out);
    json_object_put(json);
    if (rc <= 0) {
        snprintf(out->error, sizeof(out->error), "%s",
                 rc < 0 ? "nft_table_invalid_json" : "nft_table_ownership_conflict");
        return -1;
    }
    return 0;
}

static inline int flowd_nft_write_batch(const char *path, const char *revision,
                                        int replace, int delete_only)
{
    char text[512];
    int n = 0;

    if (!flowd_nft_safe_token(revision, 120) && !delete_only)
        return -1;
    if (replace || delete_only)
        n = snprintf(text, sizeof(text), "delete table inet %s\n", FLOWD_NFT_TABLE);
    if (!delete_only && n > 0 && (size_t)n < sizeof(text))
        n += snprintf(text + n, sizeof(text) - (size_t)n,
                      "table inet %s {\n  comment \"%s%s\"\n}\n",
                      FLOWD_NFT_TABLE, FLOWD_NFT_REVISION_PREFIX, revision);
    else if (!delete_only)
        n = snprintf(text, sizeof(text),
                     "table inet %s {\n  comment \"%s%s\"\n}\n",
                     FLOWD_NFT_TABLE, FLOWD_NFT_REVISION_PREFIX, revision);
    if (n <= 0 || (size_t)n >= sizeof(text))
        return -1;
    return flowd_nft_write_file(path, text);
}

static inline int flowd_nft_apply_revision(const char *binary,
                                           const char *runtime_dir,
                                           const char *revision,
                                           struct flowd_nft_apply_result *result)
{
    struct flowd_nft_readback before;
    struct flowd_nft_readback after;
    struct flowd_nft_readback rollback;
    char leaf[192];
    char lock_path[PATH_MAX];
    char output_path[PATH_MAX];
    char *check_argv[5];
    char *apply_argv[4];
    char *rollback_check_argv[5];
    char *rollback_argv[4];
    int lock_fd = -1;
    int rc;
    int final_rc = -1;

    if (!result)
        return -1;
    memset(result, 0, sizeof(*result));
    if (!binary || access(binary, X_OK) != 0 ||
        !flowd_nft_safe_token(revision, 120)) {
        snprintf(result->error, sizeof(result->error), "%s",
                 !binary || access(binary, X_OK) != 0
                     ? "nft_binary_unavailable" : "invalid_revision");
        return -1;
    }
    check_argv[0] = (char *)binary;
    check_argv[1] = "-c";
    check_argv[2] = "-f";
    check_argv[3] = result->apply_path;
    check_argv[4] = NULL;
    apply_argv[0] = (char *)binary;
    apply_argv[1] = "-f";
    apply_argv[2] = result->apply_path;
    apply_argv[3] = NULL;
    rollback_check_argv[0] = (char *)binary;
    rollback_check_argv[1] = "-c";
    rollback_check_argv[2] = "-f";
    rollback_check_argv[3] = result->rollback_path;
    rollback_check_argv[4] = NULL;
    rollback_argv[0] = (char *)binary;
    rollback_argv[1] = "-f";
    rollback_argv[2] = result->rollback_path;
    rollback_argv[3] = NULL;
    snprintf(result->revision, sizeof(result->revision), "%s", revision);
    if (flowd_nft_join(lock_path, sizeof(lock_path), runtime_dir,
                       "nft-apply.lock") != 0) {
        snprintf(result->error, sizeof(result->error), "nft_lock_path_invalid");
        return -1;
    }
    lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock_fd < 0) {
        snprintf(result->error, sizeof(result->error), "nft_lock_open_failed");
        return -1;
    }
    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        snprintf(result->error, sizeof(result->error),
                 errno == EWOULDBLOCK ? "nft_apply_busy" : "nft_lock_failed");
        close(lock_fd);
        return -1;
    }
    if (flowd_nft_readback(binary, runtime_dir, "before", &before) != 0) {
        snprintf(result->error, sizeof(result->error), "%s",
                 before.error[0] ? before.error : "nft_readback_before_failed");
        goto out;
    }
    result->previous_present = before.present;
    snprintf(result->previous_revision, sizeof(result->previous_revision), "%s",
             before.revision);
    snprintf(leaf, sizeof(leaf), "nft-%s-apply.nft", revision);
    if (flowd_nft_join(result->apply_path, sizeof(result->apply_path),
                       runtime_dir, leaf) != 0 ||
        flowd_nft_write_batch(result->apply_path, revision, before.present, 0) != 0) {
        snprintf(result->error, sizeof(result->error), "nft_apply_file_write_failed");
        goto out;
    }
    snprintf(leaf, sizeof(leaf), "nft-%s-rollback.nft", revision);
    if (flowd_nft_join(result->rollback_path, sizeof(result->rollback_path),
                       runtime_dir, leaf) != 0 ||
        flowd_nft_write_batch(result->rollback_path, before.revision,
                              1, !before.present) != 0) {
        snprintf(result->error, sizeof(result->error), "nft_rollback_file_write_failed");
        goto out;
    }
    snprintf(leaf, sizeof(leaf), "nft-%s-command.log", revision);
    if (flowd_nft_join(output_path, sizeof(output_path), runtime_dir, leaf) != 0) {
        snprintf(result->error, sizeof(result->error), "nft_output_path_invalid");
        goto out;
    }
    if (flowd_nft_run(binary, check_argv, output_path) != 0) {
        snprintf(result->error, sizeof(result->error), "nft_isolated_validation_failed");
        goto out;
    }
    result->validated = 1;
    if (before.present &&
        flowd_nft_run(binary, rollback_check_argv, output_path) != 0) {
        snprintf(result->error, sizeof(result->error), "nft_rollback_validation_failed");
        goto out;
    }
    rc = flowd_nft_run(binary, apply_argv, output_path);
    if (rc == 0)
        result->applied = 1;
    if (rc == 0 && flowd_nft_readback(binary, runtime_dir, "after", &after) == 0 &&
        after.present && after.sentinel_only && !strcmp(after.revision, revision)) {
        result->readback_ok = 1;
        final_rc = 0;
        goto out;
    }
    snprintf(result->error, sizeof(result->error), "%s",
             rc != 0 ? "nft_apply_failed" : "nft_revision_readback_mismatch");
    result->rolled_back = 1;
    if (!before.present && rc != 0 &&
        flowd_nft_readback(binary, runtime_dir, "failed-apply", &rollback) == 0 &&
        !rollback.present) {
        result->rollback_ok = 1;
        goto out;
    }
    if (!before.present &&
        flowd_nft_run(binary, rollback_check_argv, output_path) != 0) {
        snprintf(result->error, sizeof(result->error), "nft_rollback_validation_failed");
        goto out;
    }
    if (flowd_nft_run(binary, rollback_argv, output_path) == 0 &&
        flowd_nft_readback(binary, runtime_dir, "rollback", &rollback) == 0 &&
        ((!before.present && !rollback.present) ||
         (before.present && rollback.present && rollback.sentinel_only &&
          !strcmp(before.revision, rollback.revision))))
        result->rollback_ok = 1;
    if (!result->rollback_ok)
        snprintf(result->error, sizeof(result->error), "nft_rollback_verification_failed");
out:
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
    return final_rc;
}

#endif
