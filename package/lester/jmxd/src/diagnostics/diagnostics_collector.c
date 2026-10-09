// SPDX-License-Identifier: GPL-2.0-or-later
#define _POSIX_C_SOURCE 200809L

#include "diagnostics_collector.h"

#include "../jmx_storage_guard.h"
#include "../jmx_strbuf.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DW_DIAG_META_FILE "metadata"
#define DW_DIAG_META_TMP "metadata.tmp"
#define DW_DIAG_EVENTS_FILE "events.log"
#define DW_DIAG_PART_FILE ".bundle.part"
#define DW_DIAG_ARCHIVE_FILE "bundle.dwdiag"
#define DW_DIAG_MARKER_FILE "complete"
#define DW_DIAG_MARKER_TMP ".complete.tmp"

enum diag_write_error {
    DIAG_WRITE_OK = 0,
    DIAG_WRITE_STOPPED,
    DIAG_WRITE_TIMEOUT,
    DIAG_WRITE_QUOTA,
    DIAG_WRITE_STORAGE,
    DIAG_WRITE_IO,
};

struct dw_diag_job {
    struct dw_diag_job *next;
    struct dw_diag_manager *manager;
    struct dw_diag_status status;
    char directory[DW_DIAG_JOB_ID_LEN + 5];
    int directory_fd;
    int stop_requested;
    int worker_done;
    int deleting;
    unsigned int api_refs;
    uint64_t base_usage;
};

struct dw_diag_manager {
    char root[PATH_MAX];
    int root_fd;
    pthread_mutex_t lock;
    pthread_cond_t condition;
    int closing;
    unsigned int workers_active;
    struct dw_diag_config config;
    struct dw_diag_collector *collectors;
    struct dw_diag_job *jobs;
    size_t job_count;
};

struct dw_diag_writer {
    struct dw_diag_job *job;
    int fd;
    enum diag_write_error error;
    int private_key_block;
    char pending_line[4096];
    size_t pending_length;
};

static void diag_reason(char *output, size_t output_len, const char *value)
{
    if (output && output_len)
        snprintf(output, output_len, "%s", value ? value : "");
}

static int64_t diag_default_now(void *context)
{
    (void)context;
    return (int64_t)time(NULL);
}

static int64_t diag_now(const struct dw_diag_manager *manager)
{
    return manager->config.now ?
           manager->config.now(manager->config.now_context) :
           diag_default_now(NULL);
}

static int diag_default_storage_allow(const char *root, void *context)
{
    struct jmx_storage_guard_state state;

    (void)context;
    return jmx_storage_guard_allow(root, JMX_STORAGE_WRITE_BULK, &state) == 1;
}

static int diag_storage_allowed(const struct dw_diag_manager *manager)
{
    dw_diag_storage_allow_fn allow = manager->config.storage_allow ?
                                     manager->config.storage_allow :
                                     diag_default_storage_allow;

    return allow(manager->root, manager->config.storage_context) == 1;
}

const char *dw_diag_state_name(enum dw_diag_state state)
{
    switch (state) {
    case DW_DIAG_STATE_QUEUED: return "queued";
    case DW_DIAG_STATE_RUNNING: return "running";
    case DW_DIAG_STATE_STOPPING: return "stopping";
    case DW_DIAG_STATE_COMPLETED: return "completed";
    case DW_DIAG_STATE_STOPPED: return "stopped";
    case DW_DIAG_STATE_FAILED: return "failed";
    case DW_DIAG_STATE_EXPIRED: return "expired";
    default: return "failed";
    }
}

const char *dw_diag_result_name(int result)
{
    switch (result) {
    case DW_DIAG_OK: return "ok";
    case DW_DIAG_FORBIDDEN: return "forbidden";
    case DW_DIAG_INVALID: return "invalid_argument";
    case DW_DIAG_NOT_FOUND: return "job_not_found";
    case DW_DIAG_BUSY: return "job_busy";
    case DW_DIAG_STORAGE: return "storage_pressure";
    case DW_DIAG_QUOTA: return "quota_exceeded";
    case DW_DIAG_IO: return "io_failed";
    case DW_DIAG_CLEANUP: return "cleanup_failed";
    default: return "unknown_error";
    }
}

static int diag_state_from_name(const char *name, enum dw_diag_state *state)
{
    enum dw_diag_state candidate;

    if (!name || !state)
        return -1;
    for (candidate = DW_DIAG_STATE_QUEUED;
         candidate <= DW_DIAG_STATE_EXPIRED; candidate++) {
        if (!strcmp(name, dw_diag_state_name(candidate))) {
            *state = candidate;
            return 0;
        }
    }
    return -1;
}

static int diag_state_terminal(enum dw_diag_state state)
{
    return state == DW_DIAG_STATE_COMPLETED ||
           state == DW_DIAG_STATE_STOPPED ||
           state == DW_DIAG_STATE_FAILED ||
           state == DW_DIAG_STATE_EXPIRED;
}

static int diag_identifier_valid(const char *value)
{
    size_t index;

    if (!value || strlen(value) != DW_DIAG_JOB_ID_LEN)
        return 0;
    for (index = 0; index < DW_DIAG_JOB_ID_LEN; index++)
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f')))
            return 0;
    return 1;
}

static int diag_name_valid(const char *value)
{
    size_t index;

    if (!value || !value[0] || strlen(value) >= DW_DIAG_STAGE_LEN)
        return 0;
    for (index = 0; value[index]; index++)
        if (!(isalnum((unsigned char)value[index]) || value[index] == '_' ||
              value[index] == '-'))
            return 0;
    return 1;
}

static int diag_write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;

    while (length > 0) {
        ssize_t written = write(fd, cursor, length);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        cursor += written;
        length -= (size_t)written;
    }
    return 0;
}

static int diag_mkdir_path(const char *path)
{
    char buffer[PATH_MAX];
    char *cursor;

    if (!path || path[0] != '/' || strlen(path) >= sizeof(buffer))
        return -1;
    snprintf(buffer, sizeof(buffer), "%s", path);
    for (cursor = buffer + 1; ; cursor++) {
        struct stat status;
        char saved = *cursor;

        if (saved != '/' && saved != '\0')
            continue;
        *cursor = '\0';
        if (lstat(buffer, &status) != 0) {
            if (errno != ENOENT || mkdir(buffer, 0700) != 0)
                return -1;
        } else if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) {
            return -1;
        }
        *cursor = saved;
        if (saved == '\0')
            break;
    }
    return 0;
}

static int diag_root_open(const char *path)
{
    struct stat status;
    int fd;

    if (diag_mkdir_path(path) != 0)
        return -1;
    fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &status) != 0 || !S_ISDIR(status.st_mode) ||
        (status.st_mode & 0022) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    return fd;
}

static int diag_file_regular(int directory_fd, const char *name,
                             uint64_t *size)
{
    struct stat status;

    if (fstatat(directory_fd, name, &status, AT_SYMLINK_NOFOLLOW) != 0)
        return 0;
    if (!S_ISREG(status.st_mode))
        return 0;
    if (size)
        *size = (uint64_t)status.st_size;
    return 1;
}

static int diag_metadata_write(struct dw_diag_job *job)
{
    char buffer[2048];
    int length;
    int fd;

    length = snprintf(buffer, sizeof(buffer),
        "version=1\n"
        "job_id=%s\n"
        "state=%s\n"
        "scope_mask=%u\n"
        "progress_percent=%u\n"
        "bytes_written=%llu\n"
        "created_at=%lld\n"
        "started_at=%lld\n"
        "finished_at=%lld\n"
        "downloadable=%d\n"
        "stop_requested=%d\n"
        "audit_reason=%s\n"
        "failure_stage=%s\n",
        job->status.job_id, dw_diag_state_name(job->status.state),
        job->status.scope_mask, job->status.progress_percent,
        (unsigned long long)job->status.bytes_written,
        (long long)job->status.created_at, (long long)job->status.started_at,
        (long long)job->status.finished_at, job->status.downloadable,
        job->status.stop_requested, job->status.audit_reason,
        job->status.failure_stage);
    if (length < 0 || (size_t)length >= sizeof(buffer))
        return -1;
    (void)unlinkat(job->directory_fd, DW_DIAG_META_TMP, 0);
    fd = openat(job->directory_fd, DW_DIAG_META_TMP,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 || diag_write_all(fd, buffer, (size_t)length) != 0 ||
        fsync(fd) != 0 || close(fd) != 0) {
        if (fd >= 0)
            close(fd);
        (void)unlinkat(job->directory_fd, DW_DIAG_META_TMP, 0);
        return -1;
    }
    if (renameat(job->directory_fd, DW_DIAG_META_TMP,
                 job->directory_fd, DW_DIAG_META_FILE) != 0 ||
        fsync(job->directory_fd) != 0) {
        (void)unlinkat(job->directory_fd, DW_DIAG_META_TMP, 0);
        return -1;
    }
    return 0;
}

static void diag_event_append(struct dw_diag_job *job)
{
    char buffer[512];
    int length;
    int fd;

    length = snprintf(buffer, sizeof(buffer),
        "at=%lld state=%s reason=%s stage=%s progress=%u bytes=%llu\n",
        (long long)diag_now(job->manager),
        dw_diag_state_name(job->status.state), job->status.audit_reason,
        job->status.failure_stage, job->status.progress_percent,
        (unsigned long long)job->status.bytes_written);
    if (length < 0 || (size_t)length >= sizeof(buffer))
        return;
    fd = openat(job->directory_fd, DW_DIAG_EVENTS_FILE,
                O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                0600);
    if (fd < 0)
        return;
    if (diag_write_all(fd, buffer, (size_t)length) == 0)
        (void)fsync(fd);
    close(fd);
}

static int diag_transition_locked(struct dw_diag_job *job,
                                  enum dw_diag_state state,
                                  const char *reason, const char *stage)
{
    int64_t now = diag_now(job->manager);

    job->status.state = state;
    job->status.stop_requested = job->stop_requested;
    job->status.downloadable = state == DW_DIAG_STATE_COMPLETED;
    if (state == DW_DIAG_STATE_RUNNING && job->status.started_at == 0)
        job->status.started_at = now;
    if (diag_state_terminal(state) && job->status.finished_at == 0)
        job->status.finished_at = now;
    diag_reason(job->status.audit_reason,
                sizeof(job->status.audit_reason), reason);
    diag_reason(job->status.failure_stage,
                sizeof(job->status.failure_stage), stage);
    if (diag_metadata_write(job) != 0)
        return -1;
    diag_event_append(job);
    return 0;
}

static struct dw_diag_job *diag_job_find_locked(struct dw_diag_manager *manager,
                                                const char *job_id)
{
    struct dw_diag_job *job;

    for (job = manager->jobs; job; job = job->next)
        if (!strcmp(job->status.job_id, job_id))
            return job;
    return NULL;
}

static void diag_job_release_locked(struct dw_diag_manager *manager,
                                    struct dw_diag_job *job)
{
    if (job && job->api_refs > 0) {
        job->api_refs--;
        pthread_cond_broadcast(&manager->condition);
    }
}

static int diag_metadata_read(struct dw_diag_job *job)
{
    char buffer[4096];
    char *line;
    char *save = NULL;
    ssize_t count;
    int fd;
    unsigned int seen = 0;

    fd = openat(job->directory_fd, DW_DIAG_META_FILE,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    count = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (count <= 0 || count >= (ssize_t)sizeof(buffer) - 1)
        return -1;
    buffer[count] = '\0';
    memset(&job->status, 0, sizeof(job->status));
    for (line = strtok_r(buffer, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *equals = strchr(line, '=');
        const char *key;
        const char *value;

        if (!equals)
            return -1;
        *equals = '\0';
        key = line;
        value = equals + 1;
        if (!strcmp(key, "version")) {
            if (strcmp(value, "1"))
                return -1;
            seen |= 1U << 0;
        } else if (!strcmp(key, "job_id")) {
            if (!diag_identifier_valid(value))
                return -1;
            snprintf(job->status.job_id, sizeof(job->status.job_id), "%s",
                     value);
            seen |= 1U << 1;
        } else if (!strcmp(key, "state")) {
            if (diag_state_from_name(value, &job->status.state) != 0)
                return -1;
            seen |= 1U << 2;
        } else if (!strcmp(key, "scope_mask")) {
            job->status.scope_mask = (uint32_t)strtoul(value, NULL, 10);
            seen |= 1U << 3;
        } else if (!strcmp(key, "progress_percent")) {
            job->status.progress_percent = (unsigned int)strtoul(value, NULL, 10);
        } else if (!strcmp(key, "bytes_written")) {
            job->status.bytes_written = (uint64_t)strtoull(value, NULL, 10);
        } else if (!strcmp(key, "created_at")) {
            job->status.created_at = (int64_t)strtoll(value, NULL, 10);
            seen |= 1U << 4;
        } else if (!strcmp(key, "started_at")) {
            job->status.started_at = (int64_t)strtoll(value, NULL, 10);
        } else if (!strcmp(key, "finished_at")) {
            job->status.finished_at = (int64_t)strtoll(value, NULL, 10);
        } else if (!strcmp(key, "downloadable")) {
            job->status.downloadable = atoi(value) == 1;
        } else if (!strcmp(key, "stop_requested")) {
            job->status.stop_requested = atoi(value) == 1;
            job->stop_requested = job->status.stop_requested;
        } else if (!strcmp(key, "audit_reason")) {
            diag_reason(job->status.audit_reason,
                        sizeof(job->status.audit_reason), value);
        } else if (!strcmp(key, "failure_stage")) {
            diag_reason(job->status.failure_stage,
                        sizeof(job->status.failure_stage), value);
        }
    }
    if ((seen & 0x1fU) != 0x1fU ||
        job->status.scope_mask == 0 ||
        (job->status.scope_mask & ~DW_DIAG_SCOPE_ALL) != 0 ||
        job->status.progress_percent > 100)
        return -1;
    return 0;
}

static int diag_default_id(char output[DW_DIAG_JOB_ID_LEN + 1], void *context)
{
    unsigned char bytes[DW_DIAG_JOB_ID_LEN / 2];
    static const char hex[] = "0123456789abcdef";
    size_t index;
    int fd;

    (void)context;
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, bytes, sizeof(bytes)) != (ssize_t)sizeof(bytes)) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    close(fd);
    for (index = 0; index < sizeof(bytes); index++) {
        output[index * 2] = hex[bytes[index] >> 4];
        output[index * 2 + 1] = hex[bytes[index] & 0x0f];
    }
    output[DW_DIAG_JOB_ID_LEN] = '\0';
    return 0;
}

static int diag_job_create(struct dw_diag_manager *manager,
                           uint32_t scope_mask, struct dw_diag_job **output)
{
    dw_diag_id_fn generate = manager->config.id_generate ?
                             manager->config.id_generate : diag_default_id;
    struct dw_diag_job *job;
    unsigned int attempt;

    job = calloc(1, sizeof(*job));
    if (!job)
        return -1;
    job->manager = manager;
    job->directory_fd = -1;
    for (attempt = 0; attempt < 8; attempt++) {
        if (generate(job->status.job_id, manager->config.id_context) != 0 ||
            !diag_identifier_valid(job->status.job_id))
            break;
        snprintf(job->directory, sizeof(job->directory), "job-%s",
                 job->status.job_id);
        if (mkdirat(manager->root_fd, job->directory, 0700) == 0)
            break;
        if (errno != EEXIST)
            break;
    }
    if (attempt == 8 || !diag_identifier_valid(job->status.job_id)) {
        free(job);
        return -1;
    }
    job->directory_fd = openat(manager->root_fd, job->directory,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (job->directory_fd < 0) {
        (void)unlinkat(manager->root_fd, job->directory, AT_REMOVEDIR);
        free(job);
        return -1;
    }
    job->status.state = DW_DIAG_STATE_QUEUED;
    job->status.scope_mask = scope_mask;
    job->status.created_at = diag_now(manager);
    diag_reason(job->status.audit_reason,
                sizeof(job->status.audit_reason), "start_accepted");
    job->next = manager->jobs;
    manager->jobs = job;
    manager->job_count++;
    if (diag_metadata_write(job) != 0) {
        manager->jobs = job->next;
        manager->job_count--;
        close(job->directory_fd);
        (void)unlinkat(manager->root_fd, job->directory, AT_REMOVEDIR);
        free(job);
        return -1;
    }
    diag_event_append(job);
    *output = job;
    return 0;
}

static int diag_scope_supported(const struct dw_diag_manager *manager,
                                uint32_t scope_mask)
{
    uint32_t supported = 0;
    size_t index;

    for (index = 0; index < manager->config.collector_count; index++)
        supported |= manager->collectors[index].scope_bit;
    return scope_mask != 0 && (scope_mask & ~DW_DIAG_SCOPE_ALL) == 0 &&
           (scope_mask & ~supported) == 0;
}

static size_t diag_collector_count(const struct dw_diag_manager *manager,
                                   uint32_t scope_mask)
{
    size_t count = 0;
    size_t index;

    for (index = 0; index < manager->config.collector_count; index++)
        if ((manager->collectors[index].scope_bit & scope_mask) != 0)
            count++;
    return count;
}

static uint64_t diag_completed_usage_locked(struct dw_diag_manager *manager)
{
    struct dw_diag_job *job;
    uint64_t total = 0;

    for (job = manager->jobs; job; job = job->next) {
        uint64_t size = 0;

        if (job->status.state == DW_DIAG_STATE_COMPLETED &&
            diag_file_regular(job->directory_fd, DW_DIAG_ARCHIVE_FILE, &size)) {
            if (UINT64_MAX - total < size)
                return UINT64_MAX;
            total += size;
        }
    }
    return total;
}

static int diag_contains_casefold(const char *haystack, const char *needle)
{
    size_t needle_len = strlen(needle);
    const char *cursor;

    for (cursor = haystack; *cursor; cursor++) {
        size_t index;

        for (index = 0; index < needle_len; index++) {
            if (!cursor[index] ||
                tolower((unsigned char)cursor[index]) !=
                tolower((unsigned char)needle[index]))
                break;
        }
        if (index == needle_len)
            return 1;
    }
    return 0;
}

static int diag_sensitive_line(const char *line)
{
    static const char *const sensitive[] = {
        "password", "passwd", "secret", "token", "authorization",
        "cookie", "session", "credential", "private_key", "private key",
        "api_key", "apikey", "access_key", "refresh_token", "config.db",
        "request_body", "response_body", "user_database", "bearer ",
    };
    size_t index;

    for (index = 0; index < sizeof(sensitive) / sizeof(sensitive[0]); index++)
        if (diag_contains_casefold(line, sensitive[index]))
            return 1;
    return 0;
}

static int diag_writer_check(struct dw_diag_writer *writer, size_t length)
{
    struct dw_diag_job *job = writer->job;
    struct dw_diag_manager *manager = job->manager;
    int stop;
    int64_t now;

    pthread_mutex_lock(&manager->lock);
    stop = job->stop_requested || manager->closing;
    now = diag_now(manager);
    pthread_mutex_unlock(&manager->lock);
    if (stop) {
        writer->error = DIAG_WRITE_STOPPED;
        return -1;
    }
    if (job->status.started_at > 0 &&
        (now < job->status.started_at ||
         (uint64_t)(now - job->status.started_at) >=
             manager->config.max_duration_sec)) {
        writer->error = DIAG_WRITE_TIMEOUT;
        return -1;
    }
    if (length > manager->config.max_job_bytes - job->status.bytes_written ||
        job->base_usage > manager->config.total_quota_bytes ||
        length > manager->config.total_quota_bytes - job->base_usage -
                 job->status.bytes_written) {
        writer->error = DIAG_WRITE_QUOTA;
        return -1;
    }
    if (!diag_storage_allowed(manager)) {
        writer->error = DIAG_WRITE_STORAGE;
        return -1;
    }
    return 0;
}

static int diag_writer_raw(struct dw_diag_writer *writer,
                           const char *text, size_t length)
{
    struct dw_diag_manager *manager = writer->job->manager;

    if (writer->error != DIAG_WRITE_OK ||
        diag_writer_check(writer, length) != 0)
        return -1;
    if (diag_write_all(writer->fd, text, length) != 0) {
        writer->error = DIAG_WRITE_IO;
        return -1;
    }
    pthread_mutex_lock(&manager->lock);
    writer->job->status.bytes_written += length;
    pthread_mutex_unlock(&manager->lock);
    return 0;
}

static int diag_writer_line(struct dw_diag_writer *writer,
                            const char *line, size_t length, int newline)
{
    static const char redacted[] = "[REDACTED_SENSITIVE_LINE]";
    static const char private_key[] = "[REDACTED_PRIVATE_KEY]";
    char buffer[4096];
    const char *output = line;
    size_t output_len = length;

    if (length >= sizeof(buffer)) {
        writer->error = DIAG_WRITE_QUOTA;
        return -1;
    }
    memcpy(buffer, line, length);
    buffer[length] = '\0';
    if (writer->private_key_block) {
        if (diag_contains_casefold(buffer, "-----end ") &&
            diag_contains_casefold(buffer, "private key-----"))
            writer->private_key_block = 0;
        return 0;
    }
    if (diag_contains_casefold(buffer, "-----begin ") &&
        diag_contains_casefold(buffer, "private key-----")) {
        writer->private_key_block = 1;
        output = private_key;
        output_len = sizeof(private_key) - 1;
    } else if (diag_sensitive_line(buffer)) {
        output = redacted;
        output_len = sizeof(redacted) - 1;
    }
    if (diag_writer_raw(writer, output, output_len) != 0)
        return -1;
    return !newline || diag_writer_raw(writer, "\n", 1) == 0 ? 0 : -1;
}

static int diag_writer_flush_pending(struct dw_diag_writer *writer, int newline)
{
    int result;

    if (writer->pending_length == 0)
        return 0;
    result = diag_writer_line(writer, writer->pending_line,
                              writer->pending_length, newline);
    writer->pending_length = 0;
    return result;
}

int dw_diag_writer_text(struct dw_diag_writer *writer, const char *text)
{
    const char *cursor;

    if (!writer || !text)
        return DW_DIAG_INVALID;
    cursor = text;
    while (*cursor) {
        const char *newline = strchr(cursor, '\n');
        size_t length = newline ? (size_t)(newline - cursor) : strlen(cursor);

        if (length > sizeof(writer->pending_line) - 1 -
                     writer->pending_length) {
            writer->error = DIAG_WRITE_QUOTA;
            return DW_DIAG_IO;
        }
        memcpy(writer->pending_line + writer->pending_length, cursor, length);
        writer->pending_length += length;
        writer->pending_line[writer->pending_length] = '\0';
        if (newline && diag_writer_flush_pending(writer, 1) != 0)
            return DW_DIAG_IO;
        cursor += length + (newline ? 1 : 0);
    }
    return writer->error == DIAG_WRITE_OK ? DW_DIAG_OK : DW_DIAG_IO;
}

int dw_diag_writer_key_value(struct dw_diag_writer *writer, const char *key,
                             const char *value)
{
    char line[4096];
    int length;

    if (!writer || !key || !value || !diag_name_valid(key))
        return DW_DIAG_INVALID;
    length = snprintf(line, sizeof(line), "%s=%s\n", key, value);
    if (length < 0 || (size_t)length >= sizeof(line))
        return DW_DIAG_INVALID;
    return dw_diag_writer_text(writer, line);
}

static void diag_partial_remove(struct dw_diag_job *job)
{
    (void)unlinkat(job->directory_fd, DW_DIAG_PART_FILE, 0);
    (void)unlinkat(job->directory_fd, DW_DIAG_ARCHIVE_FILE, 0);
    (void)unlinkat(job->directory_fd, DW_DIAG_MARKER_FILE, 0);
    (void)unlinkat(job->directory_fd, DW_DIAG_MARKER_TMP, 0);
    (void)fsync(job->directory_fd);
}

static void diag_worker_fail_locked(struct dw_diag_writer *writer,
                                    const char *collector)
{
    const char *reason = "collector_failed";

    switch (writer->error) {
    case DIAG_WRITE_STOPPED: reason = "stopped_by_admin"; break;
    case DIAG_WRITE_TIMEOUT: reason = "duration_exceeded"; break;
    case DIAG_WRITE_QUOTA: reason = "quota_exceeded"; break;
    case DIAG_WRITE_STORAGE: reason = "storage_pressure"; break;
    case DIAG_WRITE_IO: reason = "archive_write_failed"; break;
    default: break;
    }
    if (writer->error == DIAG_WRITE_STOPPED)
        (void)diag_transition_locked(writer->job, DW_DIAG_STATE_STOPPED,
                                     reason, collector);
    else
        (void)diag_transition_locked(writer->job, DW_DIAG_STATE_FAILED,
                                     reason, collector);
}

static int diag_archive_commit(struct dw_diag_writer *writer)
{
    struct dw_diag_job *job = writer->job;
    int marker_fd = -1;

    if (diag_writer_check(writer, 0) != 0 || fsync(writer->fd) != 0)
        return -1;
    if (close(writer->fd) != 0) {
        writer->fd = -1;
        writer->error = DIAG_WRITE_IO;
        return -1;
    }
    writer->fd = -1;
    if (renameat(job->directory_fd, DW_DIAG_PART_FILE,
                 job->directory_fd, DW_DIAG_ARCHIVE_FILE) != 0)
        goto io_failed;
    (void)unlinkat(job->directory_fd, DW_DIAG_MARKER_TMP, 0);
    marker_fd = openat(job->directory_fd, DW_DIAG_MARKER_TMP,
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                       0600);
    if (marker_fd < 0 ||
        diag_write_all(marker_fd, "complete\n", 9) != 0 ||
        fsync(marker_fd) != 0 || close(marker_fd) != 0) {
        if (marker_fd >= 0)
            close(marker_fd);
        goto io_failed;
    }
    marker_fd = -1;
    if (renameat(job->directory_fd, DW_DIAG_MARKER_TMP,
                 job->directory_fd, DW_DIAG_MARKER_FILE) != 0 ||
        fsync(job->directory_fd) != 0)
        goto io_failed;
    return 0;

io_failed:
    writer->error = DIAG_WRITE_IO;
    (void)unlinkat(job->directory_fd, DW_DIAG_MARKER_TMP, 0);
    (void)unlinkat(job->directory_fd, DW_DIAG_MARKER_FILE, 0);
    (void)unlinkat(job->directory_fd, DW_DIAG_ARCHIVE_FILE, 0);
    (void)unlinkat(job->directory_fd, DW_DIAG_PART_FILE, 0);
    return -1;
}

static void *diag_worker(void *argument)
{
    struct dw_diag_job *job = argument;
    struct dw_diag_manager *manager = job->manager;
    struct dw_diag_writer writer;
    char header[256];
    size_t selected;
    size_t completed = 0;
    size_t index;
    int header_len;

    memset(&writer, 0, sizeof(writer));
    writer.job = job;
    writer.fd = -1;
    pthread_mutex_lock(&manager->lock);
    (void)diag_transition_locked(job, DW_DIAG_STATE_RUNNING,
                                 "collection_started", "prepare");
    pthread_mutex_unlock(&manager->lock);

    (void)unlinkat(job->directory_fd, DW_DIAG_PART_FILE, 0);
    writer.fd = openat(job->directory_fd, DW_DIAG_PART_FILE,
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                       0600);
    if (writer.fd < 0) {
        writer.error = DIAG_WRITE_IO;
        goto failed;
    }
    header_len = snprintf(header, sizeof(header),
        "DREAMINGWRT-DIAGNOSTICS/1\njob_id=%s\nscope_mask=%u\ncreated_at=%lld\n",
        job->status.job_id, job->status.scope_mask,
        (long long)job->status.created_at);
    if (header_len < 0 || (size_t)header_len >= sizeof(header) ||
        diag_writer_raw(&writer, header, (size_t)header_len) != 0)
        goto failed;

    selected = diag_collector_count(manager, job->status.scope_mask);
    for (index = 0; index < manager->config.collector_count; index++) {
        const struct dw_diag_collector *collector = &manager->collectors[index];
        char section[128];
        int section_len;

        if ((collector->scope_bit & job->status.scope_mask) == 0)
            continue;
        section_len = snprintf(section, sizeof(section),
                               "\n[collector:%s]\n", collector->name);
        if (section_len < 0 || (size_t)section_len >= sizeof(section) ||
            diag_writer_raw(&writer, section, (size_t)section_len) != 0)
            goto failed;
        if (collector->collect(&writer, collector->context) != 0) {
            if (writer.error == DIAG_WRITE_OK)
                writer.error = DIAG_WRITE_IO;
            pthread_mutex_lock(&manager->lock);
            if (writer.error == DIAG_WRITE_IO)
                (void)diag_transition_locked(job, DW_DIAG_STATE_FAILED,
                                             "collector_failed",
                                             collector->name);
            else
                diag_worker_fail_locked(&writer, collector->name);
            pthread_mutex_unlock(&manager->lock);
            goto finish;
        }
        if (diag_writer_flush_pending(&writer, 1) != 0) {
            pthread_mutex_lock(&manager->lock);
            diag_worker_fail_locked(&writer, collector->name);
            pthread_mutex_unlock(&manager->lock);
            goto finish;
        }
        completed++;
        pthread_mutex_lock(&manager->lock);
        job->status.progress_percent = selected ?
            (unsigned int)((completed * 100U) / selected) : 100U;
        diag_reason(job->status.audit_reason,
                    sizeof(job->status.audit_reason), "collector_completed");
        diag_reason(job->status.failure_stage,
                    sizeof(job->status.failure_stage), collector->name);
        (void)diag_metadata_write(job);
        diag_event_append(job);
        pthread_mutex_unlock(&manager->lock);
    }
    if (diag_archive_commit(&writer) != 0)
        goto failed;
    pthread_mutex_lock(&manager->lock);
    if (job->stop_requested || manager->closing) {
        diag_partial_remove(job);
        (void)diag_transition_locked(job, DW_DIAG_STATE_STOPPED,
                                     "stopped_by_admin", "finalize");
    } else {
        job->status.progress_percent = 100;
        (void)diag_transition_locked(job, DW_DIAG_STATE_COMPLETED,
                                     "collection_completed", "finalize");
    }
    pthread_mutex_unlock(&manager->lock);
    goto finish;

failed:
    if (writer.fd >= 0)
        close(writer.fd);
    diag_partial_remove(job);
    pthread_mutex_lock(&manager->lock);
    diag_worker_fail_locked(&writer, "archive");
    pthread_mutex_unlock(&manager->lock);

finish:
    if (writer.fd >= 0)
        close(writer.fd);
    if (job->status.state != DW_DIAG_STATE_COMPLETED)
        diag_partial_remove(job);
    pthread_mutex_lock(&manager->lock);
    job->worker_done = 1;
    if (manager->workers_active > 0)
        manager->workers_active--;
    pthread_cond_broadcast(&manager->condition);
    pthread_mutex_unlock(&manager->lock);
    return NULL;
}

static int diag_job_unknown_entries(struct dw_diag_job *job)
{
    static const char *const known[] = {
        DW_DIAG_META_FILE, DW_DIAG_META_TMP, DW_DIAG_EVENTS_FILE,
        DW_DIAG_PART_FILE, DW_DIAG_ARCHIVE_FILE, DW_DIAG_MARKER_FILE,
        DW_DIAG_MARKER_TMP,
    };
    DIR *directory;
    struct dirent *entry;
    int duplicate_fd;
    int unknown = 0;

    duplicate_fd = dup(job->directory_fd);
    if (duplicate_fd < 0)
        return 1;
    directory = fdopendir(duplicate_fd);
    if (!directory) {
        close(duplicate_fd);
        return 1;
    }
    while ((entry = readdir(directory)) != NULL) {
        size_t index;
        int match = 0;

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        for (index = 0; index < sizeof(known) / sizeof(known[0]); index++)
            if (!strcmp(entry->d_name, known[index])) {
                match = 1;
                break;
            }
        if (!match) {
            unknown = 1;
            break;
        }
    }
    closedir(directory);
    return unknown;
}

static int diag_job_remove_locked(struct dw_diag_manager *manager,
                                  struct dw_diag_job *job)
{
    static const char *const removable[] = {
        DW_DIAG_PART_FILE, DW_DIAG_MARKER_TMP, DW_DIAG_MARKER_FILE,
        DW_DIAG_ARCHIVE_FILE, DW_DIAG_EVENTS_FILE, DW_DIAG_META_TMP,
        DW_DIAG_META_FILE,
    };
    struct dw_diag_job **cursor;
    size_t index;

    if (diag_job_unknown_entries(job))
        goto cleanup_failed;
    for (index = 0; index < sizeof(removable) / sizeof(removable[0]); index++) {
        if (unlinkat(job->directory_fd, removable[index], 0) != 0 &&
            errno != ENOENT)
            goto cleanup_failed;
    }
    if (unlinkat(manager->root_fd, job->directory, AT_REMOVEDIR) != 0)
        goto cleanup_failed;
    for (cursor = &manager->jobs; *cursor; cursor = &(*cursor)->next) {
        if (*cursor == job) {
            *cursor = job->next;
            break;
        }
    }
    manager->job_count--;
    close(job->directory_fd);
    free(job);
    return DW_DIAG_OK;

cleanup_failed:
    job->deleting = 0;
    job->status.downloadable = 0;
    job->status.finished_at = diag_now(manager);
    (void)diag_transition_locked(job, DW_DIAG_STATE_FAILED,
                                 "cleanup_failed", "delete");
    return DW_DIAG_CLEANUP;
}

static int diag_prune_expired_locked(struct dw_diag_manager *manager)
{
    struct dw_diag_job *job = manager->jobs;

    while (job) {
        struct dw_diag_job *next = job->next;

        if (job->worker_done && !job->deleting && job->api_refs == 0 &&
            job->status.state == DW_DIAG_STATE_EXPIRED) {
            job->deleting = 1;
            if (diag_job_remove_locked(manager, job) != DW_DIAG_OK)
                return -1;
        }
        job = next;
    }
    return 0;
}

static int diag_expire_locked(struct dw_diag_job *job, int64_t now)
{
    int failed = 0;

    if (unlinkat(job->directory_fd, DW_DIAG_PART_FILE, 0) != 0 &&
        errno != ENOENT)
        failed = 1;
    if (unlinkat(job->directory_fd, DW_DIAG_ARCHIVE_FILE, 0) != 0 &&
        errno != ENOENT)
        failed = 1;
    if (unlinkat(job->directory_fd, DW_DIAG_MARKER_FILE, 0) != 0 &&
        errno != ENOENT)
        failed = 1;
    if (unlinkat(job->directory_fd, DW_DIAG_MARKER_TMP, 0) != 0 &&
        errno != ENOENT)
        failed = 1;
    job->status.downloadable = 0;
    if (failed) {
        job->status.finished_at = now;
        (void)diag_transition_locked(job, DW_DIAG_STATE_FAILED,
                                     "cleanup_failed", "retention_cleanup");
        return -1;
    }
    job->status.finished_at = now;
    (void)diag_transition_locked(job, DW_DIAG_STATE_EXPIRED,
                                 "retention_expired", "retention_cleanup");
    return 0;
}

static int diag_recover_job(struct dw_diag_manager *manager,
                            const char *directory)
{
    struct dw_diag_job *job;
    const char *job_id = directory + 4;
    uint64_t archive_size = 0;

    if (strncmp(directory, "job-", 4) || !diag_identifier_valid(job_id))
        return 0;
    job = calloc(1, sizeof(*job));
    if (!job)
        return -1;
    job->manager = manager;
    /* diag_identifier_valid above pins job_id at DW_DIAG_JOB_ID_LEN hex digits,
     * so "job-" plus the id is exactly the extent of job->directory. */
    JMX_STRBUF_COPY(job->directory, directory);
    job->directory_fd = openat(manager->root_fd, directory,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (job->directory_fd < 0) {
        free(job);
        return -1;
    }
    if (diag_metadata_read(job) != 0 || strcmp(job->status.job_id, job_id)) {
        memset(&job->status, 0, sizeof(job->status));
        snprintf(job->status.job_id, sizeof(job->status.job_id), "%s", job_id);
        job->status.state = DW_DIAG_STATE_FAILED;
        job->status.scope_mask = DW_DIAG_SCOPE_SYSTEM;
        job->status.created_at = diag_now(manager);
        job->status.finished_at = job->status.created_at;
        diag_reason(job->status.audit_reason,
                    sizeof(job->status.audit_reason), "metadata_corrupt");
        diag_reason(job->status.failure_stage,
                    sizeof(job->status.failure_stage), "restart_recovery");
        job->worker_done = 1;
        diag_partial_remove(job);
        (void)diag_metadata_write(job);
        diag_event_append(job);
    } else if (!diag_state_terminal(job->status.state)) {
        job->stop_requested = 0;
        job->status.stop_requested = 0;
        job->status.downloadable = 0;
        job->status.finished_at = diag_now(manager);
        job->worker_done = 1;
        diag_partial_remove(job);
        (void)diag_transition_locked(job, DW_DIAG_STATE_FAILED,
                                     "interrupted_after_restart",
                                     "restart_recovery");
    } else {
        job->worker_done = 1;
        if (job->status.state == DW_DIAG_STATE_COMPLETED &&
            (!diag_file_regular(job->directory_fd, DW_DIAG_ARCHIVE_FILE,
                                &archive_size) ||
             !diag_file_regular(job->directory_fd, DW_DIAG_MARKER_FILE,
                                NULL))) {
            diag_partial_remove(job);
            job->status.downloadable = 0;
            job->status.finished_at = diag_now(manager);
            (void)diag_transition_locked(job, DW_DIAG_STATE_FAILED,
                                         "incomplete_archive_after_restart",
                                         "restart_recovery");
        } else if (job->status.state == DW_DIAG_STATE_COMPLETED) {
            job->status.bytes_written = archive_size;
            job->status.downloadable = 1;
        }
    }
    job->next = manager->jobs;
    manager->jobs = job;
    manager->job_count++;
    return 0;
}

static int diag_recover_all(struct dw_diag_manager *manager)
{
    DIR *directory;
    struct dirent *entry;
    int duplicate_fd = dup(manager->root_fd);

    if (duplicate_fd < 0)
        return -1;
    directory = fdopendir(duplicate_fd);
    if (!directory) {
        close(duplicate_fd);
        return -1;
    }
    while ((entry = readdir(directory)) != NULL) {
        if (diag_recover_job(manager, entry->d_name) != 0) {
            closedir(directory);
            return -1;
        }
    }
    closedir(directory);
    return 0;
}

int dw_diag_manager_open(struct dw_diag_manager **output,
                         const struct dw_diag_config *config,
                         char *reason, size_t reason_len)
{
    struct dw_diag_manager *manager;
    size_t left;
    size_t right;

    if (!output || !config || !config->root || config->root[0] != '/' ||
        strlen(config->root) >= PATH_MAX || config->max_job_bytes == 0 ||
        config->total_quota_bytes < config->max_job_bytes ||
        config->max_duration_sec == 0 || config->retention_sec == 0 ||
        config->max_jobs == 0 || !config->collectors ||
        config->collector_count == 0) {
        diag_reason(reason, reason_len, "invalid_configuration");
        return DW_DIAG_INVALID;
    }
    for (left = 0; left < config->collector_count; left++) {
        const struct dw_diag_collector *collector = &config->collectors[left];

        if (!collector->collect || !diag_name_valid(collector->name) ||
            collector->scope_bit == 0 ||
            (collector->scope_bit & (collector->scope_bit - 1)) != 0 ||
            (collector->scope_bit & ~DW_DIAG_SCOPE_ALL) != 0) {
            diag_reason(reason, reason_len, "invalid_collector");
            return DW_DIAG_INVALID;
        }
        for (right = left + 1; right < config->collector_count; right++)
            if (!strcmp(collector->name, config->collectors[right].name)) {
                diag_reason(reason, reason_len, "duplicate_collector_name");
                return DW_DIAG_INVALID;
            }
    }
    manager = calloc(1, sizeof(*manager));
    if (!manager) {
        diag_reason(reason, reason_len, "out_of_memory");
        return DW_DIAG_IO;
    }
    manager->root_fd = -1;
    snprintf(manager->root, sizeof(manager->root), "%s", config->root);
    manager->config = *config;
    manager->collectors = calloc(config->collector_count,
                                 sizeof(*manager->collectors));
    if (!manager->collectors)
        goto failed;
    memcpy(manager->collectors, config->collectors,
           config->collector_count * sizeof(*manager->collectors));
    manager->config.collectors = manager->collectors;
    if (pthread_mutex_init(&manager->lock, NULL) != 0)
        goto failed;
    if (pthread_cond_init(&manager->condition, NULL) != 0) {
        pthread_mutex_destroy(&manager->lock);
        goto failed;
    }
    manager->root_fd = diag_root_open(manager->root);
    if (manager->root_fd < 0) {
        pthread_cond_destroy(&manager->condition);
        pthread_mutex_destroy(&manager->lock);
        diag_reason(reason, reason_len, "unsafe_storage_root");
        goto failed;
    }
    if (diag_recover_all(manager) != 0) {
        diag_reason(reason, reason_len, "restart_recovery_failed");
        dw_diag_manager_close(manager);
        return DW_DIAG_IO;
    }
    *output = manager;
    diag_reason(reason, reason_len, "ok");
    return DW_DIAG_OK;

failed:
    free(manager->collectors);
    free(manager);
    return DW_DIAG_IO;
}

void dw_diag_manager_close(struct dw_diag_manager *manager)
{
    struct dw_diag_job *job;

    if (!manager)
        return;
    pthread_mutex_lock(&manager->lock);
    manager->closing = 1;
    for (job = manager->jobs; job; job = job->next) {
        if (!job->worker_done) {
            job->stop_requested = 1;
            job->status.stop_requested = 1;
        }
    }
    while (manager->workers_active > 0)
        pthread_cond_wait(&manager->condition, &manager->lock);
    pthread_mutex_unlock(&manager->lock);
    while ((job = manager->jobs) != NULL) {
        manager->jobs = job->next;
        close(job->directory_fd);
        free(job);
    }
    if (manager->root_fd >= 0)
        close(manager->root_fd);
    pthread_cond_destroy(&manager->condition);
    pthread_mutex_destroy(&manager->lock);
    free(manager->collectors);
    free(manager);
}

int dw_diag_start(struct dw_diag_manager *manager, enum dw_diag_actor actor,
                  uint32_t scope_mask, struct dw_diag_status *status)
{
    struct dw_diag_job *job;
    struct dw_diag_job *cursor;
    pthread_t thread;
    uint64_t usage;

    if (!manager || !status)
        return DW_DIAG_INVALID;
    if (actor != DW_DIAG_ACTOR_ADMIN)
        return DW_DIAG_FORBIDDEN;
    if (!diag_scope_supported(manager, scope_mask))
        return DW_DIAG_INVALID;
    if (!diag_storage_allowed(manager))
        return DW_DIAG_STORAGE;
    pthread_mutex_lock(&manager->lock);
    if (manager->closing) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_BUSY;
    }
    for (cursor = manager->jobs; cursor; cursor = cursor->next) {
        if (!cursor->worker_done ||
            !diag_state_terminal(cursor->status.state)) {
            pthread_mutex_unlock(&manager->lock);
            return DW_DIAG_BUSY;
        }
    }
    if (manager->job_count >= manager->config.max_jobs &&
        diag_prune_expired_locked(manager) != 0) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_CLEANUP;
    }
    if (manager->job_count >= manager->config.max_jobs) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_BUSY;
    }
    usage = diag_completed_usage_locked(manager);
    if (usage == UINT64_MAX ||
        usage > manager->config.total_quota_bytes ||
        manager->config.max_job_bytes >
            manager->config.total_quota_bytes - usage) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_QUOTA;
    }
    if (diag_job_create(manager, scope_mask, &job) != 0) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_IO;
    }
    job->base_usage = usage;
    manager->workers_active++;
    if (pthread_create(&thread, NULL, diag_worker, job) != 0) {
        manager->workers_active--;
        job->worker_done = 1;
        job->status.finished_at = diag_now(manager);
        (void)diag_transition_locked(job, DW_DIAG_STATE_FAILED,
                                     "worker_start_failed", "start");
        *status = job->status;
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_IO;
    }
    (void)pthread_detach(thread);
    *status = job->status;
    pthread_mutex_unlock(&manager->lock);
    return DW_DIAG_OK;
}

int dw_diag_status_get(struct dw_diag_manager *manager,
                       enum dw_diag_actor actor, const char *job_id,
                       struct dw_diag_status *status)
{
    struct dw_diag_job *job;

    if (!manager || !diag_identifier_valid(job_id) || !status ||
        (actor != DW_DIAG_ACTOR_ADMIN && actor != DW_DIAG_ACTOR_VIEWER))
        return DW_DIAG_INVALID;
    pthread_mutex_lock(&manager->lock);
    job = diag_job_find_locked(manager, job_id);
    if (!job) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_NOT_FOUND;
    }
    *status = job->status;
    pthread_mutex_unlock(&manager->lock);
    return DW_DIAG_OK;
}

int dw_diag_stop(struct dw_diag_manager *manager, enum dw_diag_actor actor,
                 const char *job_id, struct dw_diag_status *status)
{
    struct dw_diag_job *job;

    if (!manager || !diag_identifier_valid(job_id) || !status)
        return DW_DIAG_INVALID;
    if (actor != DW_DIAG_ACTOR_ADMIN)
        return DW_DIAG_FORBIDDEN;
    pthread_mutex_lock(&manager->lock);
    job = diag_job_find_locked(manager, job_id);
    if (!job) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_NOT_FOUND;
    }
    if (job->deleting) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_BUSY;
    }
    job->api_refs++;
    if (!job->worker_done) {
        job->stop_requested = 1;
        job->status.stop_requested = 1;
        (void)diag_transition_locked(job, DW_DIAG_STATE_STOPPING,
                                     "stop_requested", "stop");
        while (!job->worker_done)
            pthread_cond_wait(&manager->condition, &manager->lock);
    }
    *status = job->status;
    diag_job_release_locked(manager, job);
    pthread_mutex_unlock(&manager->lock);
    return DW_DIAG_OK;
}

int dw_diag_download_open(struct dw_diag_manager *manager,
                          enum dw_diag_actor actor, const char *job_id,
                          int *fd, uint64_t *size)
{
    struct dw_diag_job *job;
    struct stat status;
    int archive_fd;

    if (!manager || !diag_identifier_valid(job_id) || !fd)
        return DW_DIAG_INVALID;
    *fd = -1;
    if (actor != DW_DIAG_ACTOR_ADMIN)
        return DW_DIAG_FORBIDDEN;
    pthread_mutex_lock(&manager->lock);
    job = diag_job_find_locked(manager, job_id);
    if (!job) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_NOT_FOUND;
    }
    if (job->status.state != DW_DIAG_STATE_COMPLETED ||
        !job->status.downloadable ||
        !diag_file_regular(job->directory_fd, DW_DIAG_MARKER_FILE, NULL)) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_BUSY;
    }
    archive_fd = openat(job->directory_fd, DW_DIAG_ARCHIVE_FILE,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (archive_fd < 0 || fstat(archive_fd, &status) != 0 ||
        !S_ISREG(status.st_mode)) {
        if (archive_fd >= 0)
            close(archive_fd);
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_IO;
    }
    *fd = archive_fd;
    if (size)
        *size = (uint64_t)status.st_size;
    pthread_mutex_unlock(&manager->lock);
    return DW_DIAG_OK;
}

int dw_diag_delete(struct dw_diag_manager *manager, enum dw_diag_actor actor,
                   const char *job_id)
{
    struct dw_diag_job *job;
    int result;

    if (!manager || !diag_identifier_valid(job_id))
        return DW_DIAG_INVALID;
    if (actor != DW_DIAG_ACTOR_ADMIN)
        return DW_DIAG_FORBIDDEN;
    pthread_mutex_lock(&manager->lock);
    job = diag_job_find_locked(manager, job_id);
    if (!job) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_NOT_FOUND;
    }
    if (job->deleting) {
        pthread_mutex_unlock(&manager->lock);
        return DW_DIAG_BUSY;
    }
    job->deleting = 1;
    if (!job->worker_done) {
        job->stop_requested = 1;
        job->status.stop_requested = 1;
        (void)diag_transition_locked(job, DW_DIAG_STATE_STOPPING,
                                     "delete_requested", "delete");
        while (!job->worker_done)
            pthread_cond_wait(&manager->condition, &manager->lock);
    }
    while (job->api_refs > 0)
        pthread_cond_wait(&manager->condition, &manager->lock);
    result = diag_job_remove_locked(manager, job);
    pthread_mutex_unlock(&manager->lock);
    return result;
}

int dw_diag_cleanup_expired(struct dw_diag_manager *manager,
                            enum dw_diag_actor actor, int64_t now,
                            unsigned int *cleaned)
{
    struct dw_diag_job *job;
    unsigned int count = 0;

    if (!manager || !cleaned || now <= 0)
        return DW_DIAG_INVALID;
    if (actor != DW_DIAG_ACTOR_ADMIN)
        return DW_DIAG_FORBIDDEN;
    pthread_mutex_lock(&manager->lock);
    for (job = manager->jobs; job; job = job->next) {
        if (job->worker_done && job->status.finished_at > 0 &&
            job->status.state != DW_DIAG_STATE_EXPIRED &&
            now >= job->status.finished_at &&
            (uint64_t)(now - job->status.finished_at) >=
                manager->config.retention_sec) {
            if (diag_expire_locked(job, now) != 0) {
                pthread_mutex_unlock(&manager->lock);
                *cleaned = count;
                return DW_DIAG_CLEANUP;
            }
            count++;
        }
    }
    pthread_mutex_unlock(&manager->lock);
    *cleaned = count;
    return DW_DIAG_OK;
}
