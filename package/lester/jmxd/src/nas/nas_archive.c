// SPDX-License-Identifier: GPL-2.0-or-later
/* Optional libarchive executor. Called in a job process, never a webd thread. */
#define _GNU_SOURCE
#include "storage/storage_files.h"
#include "nas_archive_contract.h"
#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
static volatile sig_atomic_t cancelled;
static void cancel(int sig) {
    (void)sig;
    cancelled = 1;
}
static const char *get(struct json_object *j, const char *key) {
    struct json_object *v = NULL;
    return j && json_object_object_get_ex(j, key, &v) && json_object_is_type(v, json_type_string)
               ? json_object_get_string(v)
               : "";
}
static struct json_object *object(struct json_object *j, const char *key) {
    struct json_object *v = NULL;
    if (j)
        json_object_object_get_ex(j, key, &v);
    return v;
}
struct json_object *jmx_gen_api_response_data(int code, struct json_object *data) {
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "code", json_object_new_int(code));
    json_object_object_add(o, "data", data);
    return o;
}
static int safe(const char *path) {
    if (!path || !path[0] || path[0] == '/' || strlen(path) >= PATH_MAX)
        return 0;
    char copy[PATH_MAX], *save = NULL;
    snprintf(copy, sizeof(copy), "%s", path);
    int depth = 0;
    for (char *p = strtok_r(copy, "/", &save); p; p = strtok_r(NULL, "/", &save)) {
        if (!strcmp(p, "..") || !strcmp(p, ".") || ++depth > 64)
            return 0;
        for (char *c = p; *c; c++)
            if ((unsigned char)*c < 32 || *c == '\\')
                return 0;
    }
    return 1;
}
static int selected(struct json_object *entries, const char *path) {
    if (!entries || json_object_array_length(entries) == 0)
        return 1;
    for (size_t i = 0; i < json_object_array_length(entries); i++) {
        const char *name = json_object_get_string(json_object_array_get_idx(entries, i));
        size_t n = strlen(name);
        while (n && name[n - 1] == '/') n--;
        if (!strncmp(name, path, n) && (!path[n] || path[n] == '/'))
            return 1;
    }
    return 0;
}
static int parent_dir(int root, const char *path, char leaf[NAME_MAX + 1], dev_t dev) {
    char copy[PATH_MAX], *save = NULL;
    snprintf(copy, sizeof(copy), "%s", path);
    int fd = dup(root);
    if (fd < 0)
        return -1;
    char *part = strtok_r(copy, "/", &save);
    while (part) {
        char *next = strtok_r(NULL, "/", &save);
        if (!next) {
            if (strlen(part) > NAME_MAX) {
                close(fd);
                return -1;
            }
            snprintf(leaf, NAME_MAX + 1, "%s", part);
            return fd;
        }
        if (mkdirat(fd, part, 0755) && errno != EEXIST) {
            close(fd);
            return -1;
        }
        int sub = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat st;
        if (sub < 0 || fstat(sub, &st) || st.st_dev != dev) {
            if (sub >= 0)
                close(sub);
            close(fd);
            return -1;
        }
        close(fd);
        fd = sub;
        part = next;
    }
    close(fd);
    return -1;
}
static void result_item(struct json_object *results, const char *name, const char *state,
                        const char *error) {
    if (json_object_array_length(results) >= 1000)
        return;
    struct json_object *r = json_object_new_object();
    json_object_object_add(r, "path", json_object_new_string(name ? name : ""));
    json_object_object_add(r, "state", json_object_new_string(state));
    if (error)
        json_object_object_add(r, "error", json_object_new_string(error));
    json_object_array_add(results, r);
}
static int create_entry(struct archive *writer, int parent, const char *name, const char *relative,
                        const char *absolute, dev_t dev, int depth, int *count) {
    struct stat st;
    const char *reason = "";
    if (cancelled || depth > 64 || ++*count > 100000 ||
        storage_files_content_denied(absolute, name, &reason) ||
        fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) || st.st_dev != dev)
        return -1;
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
        errno = ENOTSUP;
        return -1;
    }
    int fd = openat(parent, name,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (S_ISDIR(st.st_mode) ? O_DIRECTORY : 0));
    if (fd < 0)
        return -1;
    struct stat opened;
    if (fstat(fd, &opened) || opened.st_ino != st.st_ino || opened.st_dev != dev) {
        close(fd);
        return -1;
    }
    struct archive_entry *e = archive_entry_new();
    archive_entry_set_pathname(e, relative);
    archive_entry_set_perm(e, S_ISDIR(st.st_mode) ? 0755 : 0644);
    archive_entry_set_filetype(e, S_ISDIR(st.st_mode) ? AE_IFDIR : AE_IFREG);
    archive_entry_set_size(e, S_ISREG(st.st_mode) ? st.st_size : 0);
    archive_entry_set_mtime(e, st.st_mtime, 0);
    int rc = archive_write_header(writer, e) < ARCHIVE_OK ? -1 : 0;
    archive_entry_free(e);
    if (!rc && S_ISREG(st.st_mode)) {
        char buffer[65536];
        ssize_t n = 0;
        while (!cancelled && (n = read(fd, buffer, sizeof(buffer))) > 0) {
            size_t offset = 0;
            while (offset < (size_t)n) {
                la_ssize_t written =
                    archive_write_data(writer, buffer + offset, (size_t)n - offset);
                if (written <= 0) {
                    rc = -1;
                    break;
                }
                offset += (size_t)written;
            }
            if (rc)
                break;
        }
        if (cancelled || n < 0)
            rc = -1;
    } else if (!rc) {
        DIR *dir = fdopendir(dup(fd));
        if (!dir)
            rc = -1;
        else {
            struct dirent *item;
            while (!rc && (item = readdir(dir))) {
                if (!strcmp(item->d_name, ".") || !strcmp(item->d_name, ".."))
                    continue;
                char child[PATH_MAX], display[PATH_MAX];
                if (snprintf(child, sizeof(child), "%s/%s", relative, item->d_name) >=
                        (int)sizeof(child) ||
                    snprintf(display, sizeof(display), "%s/%s", absolute, item->d_name) >=
                        (int)sizeof(display)) {
                    rc = -1;
                    break;
                }
                rc = create_entry(writer, fd, item->d_name, child, display, dev, depth + 1, count);
            }
            closedir(dir);
        }
    }
    close(fd);
    return rc;
}
static void reader_formats(struct archive *reader) {
    archive_read_support_format_zip(reader);
    archive_read_support_format_tar(reader);
    archive_read_support_filter_gzip(reader);
    archive_read_support_filter_xz(reader);
    archive_read_support_filter_bzip2(reader);
}
static int writer_format(struct archive *writer, const char *format) {
    if (!strcmp(format, "zip")) return archive_write_set_format_zip(writer);
    if (strncmp(format, "tar", 3)) return ARCHIVE_FATAL;
    if (archive_write_set_format_pax_restricted(writer) < ARCHIVE_OK) return ARCHIVE_FATAL;
    if (!strcmp(format, "tar")) return ARCHIVE_OK;
    if (!strcmp(format, "tar.gz")) return archive_write_add_filter_gzip(writer);
    if (!strcmp(format, "tar.xz")) return archive_write_add_filter_xz(writer);
    if (!strcmp(format, "tar.bz2")) return archive_write_add_filter_bzip2(writer);
    return ARCHIVE_FATAL;
}
static const char *reader_format(struct archive *reader) {
    if ((archive_format(reader) & ARCHIVE_FORMAT_BASE_MASK) == ARCHIVE_FORMAT_ZIP) return "zip";
    if ((archive_format(reader) & ARCHIVE_FORMAT_BASE_MASK) != ARCHIVE_FORMAT_TAR) return NULL;
    switch (archive_filter_code(reader, 0)) {
        case ARCHIVE_FILTER_NONE: return "tar";
        case ARCHIVE_FILTER_GZIP: return "tar.gz";
        case ARCHIVE_FILTER_XZ: return "tar.xz";
        case ARCHIVE_FILTER_BZIP2: return "tar.bz2";
        default: return NULL;
    }
}
static int safe_entry(struct archive_entry *entry) {
    return safe(archive_entry_pathname(entry)) && !archive_entry_symlink(entry) &&
        !archive_entry_hardlink(entry) && archive_entry_is_encrypted(entry) <= 0 &&
        (archive_entry_filetype(entry) == AE_IFREG || archive_entry_filetype(entry) == AE_IFDIR);
}
static int same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static const char *base_name(const char *path) {
    const char *p = strrchr(path, '/');
    return p ? p + 1 : path;
}
static int contains(const char *parent, const char *path) {
    size_t n = strlen(parent);
    while (n && parent[n-1] == '/') n--;
    return !strncmp(parent, path, n) && (!path[n] || path[n] == '/');
}
static int write_source(struct archive *writer, struct json_object *source, const char *archive_path,
                        int *count) {
    const char *path = get(source, "path"), *reason = "", *name = base_name(path);
    char parent[PATH_MAX], display[PATH_MAX];
    if (!safe(name) || strlen(path) >= sizeof(parent) || contains(path, archive_path)) return -1;
    snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (!slash) return -1;
    if (slash == parent) slash[1] = 0; else *slash = 0;
    int fd = storage_files_open_dir(get(source, "root_id"), parent, 0, display, sizeof(display), &reason);
    struct stat st;
    if (fd < 0) return -1;
    int rc = fstat(fd, &st) ? -1 : create_entry(writer, fd, name, name, path, st.st_dev, 0, count);
    close(fd);
    return rc;
}
/* Rewrite in the same directory and commit only after every member was copied.
 * Cancellation, unsafe entries and source conflicts leave the original intact. */
static const char *update_archive(struct json_object *request, struct json_object *results,
                                 int *success, int *skipped) {
    const char *operation = get(request, "operation"), *conflict = get(request, "on_conflict");
    struct json_object *source = object(request, "source"), *entries = object(request, "entries"),
                       *sources = object(request, "sources");
    int adding = !strcmp(operation, "add");
    if ((!adding && (!entries || !json_object_array_length(entries))) ||
        (adding && (!json_object_is_type(sources, json_type_array) ||
                    !json_object_array_length(sources) || json_object_array_length(sources) > 1000)))
        return "invalid_entries";
    size_t sources_count = adding ? json_object_array_length(sources) : 0;
    unsigned char omit[1000] = {0};
    for (size_t i = 0; i < sources_count; i++) {
        const char *name = base_name(get(json_object_array_get_idx(sources, i), "path"));
        if (!safe(name)) return "invalid_source";
        for (size_t j = 0; j < i; j++)
            if (!strcmp(name, base_name(get(json_object_array_get_idx(sources, j), "path"))))
                return "duplicate_source";
    }
    const char *path = get(source, "path"), *reason = "", *failure = NULL;
    char parent[PATH_MAX], canonical[PATH_MAX], temp[80] = "";
    if (!path[0] || strlen(path) >= sizeof(parent) || storage_files_write_denied(path, &reason))
        return "write_protected";
    snprintf(parent, sizeof(parent), "%s", path);
    char *slash = strrchr(parent, '/');
    if (!slash || !slash[1]) return "invalid_source";
    const char *name = base_name(path);
    if (slash == parent) slash[1] = 0; else *slash = 0;
    int dir = storage_files_open_dir(get(source, "root_id"), parent, 1, canonical, sizeof(canonical), &reason);
    if (dir < 0) return "destination_unavailable";
    struct storage_files_stream stream;
    if (storage_files_open_stream(get(source, "root_id"), path, &stream, &reason)) { close(dir); return reason; }
    int fd = -1, status, count = 0, changed = 0;
    struct stat original, current;
    struct archive *reader = archive_read_new(), *writer = archive_write_new();
    struct archive_entry *entry;
    if (fstat(stream.fd, &original)) { failure = "source_unavailable"; goto done_update; }
    reader_formats(reader);
    if (archive_read_open_fd(reader, stream.fd, 65536) < ARCHIVE_OK) { failure = "archive_read_failed"; goto done_update; }
    status = archive_read_next_header(reader, &entry);
    if (status != ARCHIVE_OK && status != ARCHIVE_EOF) { failure = "archive_read_failed"; goto done_update; }
    const char *format = reader_format(reader);
    if (!format || writer_format(writer, format) < ARCHIVE_OK) { failure = "format_unsupported"; goto done_update; }
    snprintf(temp, sizeof(temp), ".dreamingwrt-tx-nas-%ld", (long)getpid());
    fd = openat(dir, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0 || archive_write_open_fd(writer, fd) < ARCHIVE_OK) { failure = "create_failed"; goto done_update; }
    while (!cancelled && status == ARCHIVE_OK) {
        const char *member = archive_entry_pathname(entry);
        if (++count > 100000) { failure = "archive_entry_limit"; break; }
        if (!safe_entry(entry)) { failure = "unsafe_or_unsupported_entry"; break; }
        int drop = !adding && selected(entries, member);
        for (size_t i = 0; i < sources_count; i++) {
            const char *added = base_name(get(json_object_array_get_idx(sources, i), "path"));
            if (!contains(added, member)) continue;
            if (!strcmp(conflict, "skip")) omit[i] = 1;
            else if (!strcmp(conflict, "replace")) drop = 1;
            else { failure = "file_exists"; break; }
        }
        if (failure) break;
        if (drop) {
            changed++;
            if (!adding) result_item(results, member, "succeeded", NULL);
            archive_read_data_skip(reader);
        } else {
            if (archive_write_header(writer, entry) < ARCHIVE_OK) { failure = "write_failed"; break; }
            char buffer[65536]; la_ssize_t n = 0;
            while (!cancelled && (n = archive_read_data(reader, buffer, sizeof(buffer))) > 0) {
                la_ssize_t offset = 0;
                while (offset < n) {
                    la_ssize_t wrote = archive_write_data(writer, buffer + offset, n - offset);
                    if (wrote <= 0) { failure = "write_failed"; break; }
                    offset += wrote;
                }
                if (failure) break;
            }
            if (n < 0) failure = "archive_read_failed";
            if (failure) break;
        }
        status = archive_read_next_header(reader, &entry);
    }
    if (cancelled) failure = "cancelled";
    if (!failure && status != ARCHIVE_EOF) failure = "archive_read_failed";
    if (!failure && !adding && !changed) failure = "entries_not_found";
    for (size_t i = 0; !failure && i < sources_count; i++) {
        struct json_object *input = json_object_array_get_idx(sources, i);
        if (omit[i]) { (*skipped)++; result_item(results, get(input, "path"), "skipped", NULL); continue; }
        if (write_source(writer, input, path, &count)) { failure = cancelled ? "cancelled" : "source_unavailable"; break; }
        (*success)++;
        result_item(results, get(input, "path"), "succeeded", NULL);
    }
    if (archive_write_close(writer) < ARCHIVE_OK && !failure) failure = "write_failed";
    if (!failure && (fchmod(fd, original.st_mode & 0777) || fsync(fd))) failure = "write_failed";
    if (!failure && (fstatat(dir, name, &current, AT_SYMLINK_NOFOLLOW) || !same_file(&original, &current)))
        failure = "revision_conflict";
    if (!failure && renameat(dir, temp, dir, name)) failure = "commit_failed";
    if (!failure) { temp[0] = 0; fsync(dir); if (!adding) *success = changed; }
 done_update:
    archive_read_free(reader); archive_write_free(writer);
    if (fd >= 0) close(fd);
    if (temp[0]) unlinkat(dir, temp, 0);
    close(stream.fd); close(dir);
    if (failure) { *success = 0; json_object_array_del_idx(results, 0, json_object_array_length(results)); }
    return failure;
}
static int utf8_text(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n;) {
        unsigned c = p[i++], value, extra;
        if (c < 128) { if ((c < 32 && c != '\n' && c != '\r' && c != '\t') || c == 127) return 0; continue; }
        if (c >= 0xc2 && c <= 0xdf) { value = c & 31; extra = 1; }
        else if (c >= 0xe0 && c <= 0xef) { value = c & 15; extra = 2; }
        else if (c >= 0xf0 && c <= 0xf4) { value = c & 7; extra = 3; }
        else return 0;
        if (i + extra > n) return 0;
        unsigned length = extra;
        while (extra--) { if ((p[i] & 0xc0) != 0x80) return 0; value = (value << 6) | (p[i++] & 63); }
        if ((length == 2 && value < 0x800) || (length == 3 && value < 0x10000) ||
            (value >= 0xd800 && value <= 0xdfff) || value > 0x10ffff) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    signal(SIGTERM, cancel);
    signal(SIGINT, cancel);
    if (argc != 2)
        return 2;
    /* JSON and filesystem names use UTF-8. The Alpine/glibc image supplies
     * en_US.UTF-8; other glibc targets can use the built-in C.UTF-8 locale. */
    if (!setlocale(LC_CTYPE, "C.UTF-8") && !setlocale(LC_CTYPE, "en_US.UTF-8")) {
        puts("{\"state\":\"failed\",\"error\":\"utf8_locale_unavailable\"}");
        return 1;
    }
    struct json_object *request = json_tokener_parse(argv[1]);
    if (!request)
        return 2;
    const char *operation = get(request, "operation");
    struct json_object *entries = object(request, "entries");
    if (entries && !json_object_is_type(entries, json_type_array)) {
        json_object_put(request);
        puts("{\"state\":\"failed\",\"error\":\"invalid_entries\"}");
        return 1;
    }
    for (size_t i = 0; entries && i < json_object_array_length(entries); i++) {
        struct json_object *value = json_object_array_get_idx(entries, i);
        if (!json_object_is_type(value, json_type_string) || !safe(json_object_get_string(value))) {
            json_object_put(request);
            puts("{\"state\":\"failed\",\"error\":\"invalid_entries\"}");
            return 1;
        }
    }
    struct json_object *out = json_object_new_object(), *results = json_object_new_array();
    int success = 0, failed = 0, skipped = 0;
    const char *failure = NULL;
    struct archive *reader = NULL, *writer = NULL;
    int destination_fd = -1, source_fd = -1;
    char canonical[PATH_MAX] = "", temporary[80] = "";
    struct stat dst;
    if (!strcmp(operation, "capabilities")) {
        json_object_put(out);
        out = json_tokener_parse(NAS_ARCHIVE_CAPABILITIES);
        goto done;
    }
    const char *conflict = get(request, "on_conflict");
    if (*conflict && strcmp(conflict, "error") && strcmp(conflict, "skip") && strcmp(conflict, "replace")) {
        failure = "invalid_conflict";
        goto done;
    }
    if (!strcmp(operation, "add") || !strcmp(operation, "delete")) {
        failure = update_archive(request, results, &success, &skipped);
        goto done;
    }
    if (!strcmp(operation, "create") || !strcmp(operation, "extract")) {
        struct json_object *destination = object(request, "destination");
        const char *reason = "";
        destination_fd = storage_files_open_dir(get(destination, "root_id"), get(destination, "path"), 1,
                                               canonical, sizeof(canonical), &reason);
        if (destination_fd < 0 || fstat(destination_fd, &dst)) {
            failure = "destination_unavailable";
            goto done;
        }
    }
    if (!strcmp(operation, "create")) {
        const char *filename = get(request, "filename"), *format = get(request, "format");
        struct json_object *sources = object(request, "sources");
        char target[PATH_MAX];
        const char *reason = "";
        if (!safe(filename) || strchr(filename, '/') || !sources ||
            !json_object_is_type(sources, json_type_array) || !json_object_array_length(sources) ||
            snprintf(target, sizeof(target), "%s/%s", canonical, filename) >= (int)sizeof(target) ||
            storage_files_write_denied(target, &reason)) {
            failure = "invalid_request";
            goto done;
        }
        writer = archive_write_new();
        if (writer_format(writer, format) < ARCHIVE_OK) {
            failure = "format_unsupported";
            goto done;
        }
        snprintf(temporary, sizeof(temporary), ".dreamingwrt-tx-nas-%ld", (long)getpid());
        int fd = openat(destination_fd, temporary,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0 || archive_write_open_fd(writer, fd) < ARCHIVE_OK) {
            if (fd >= 0)
                close(fd);
            failure = "create_failed";
            goto done;
        }
        int count = 0;
        for (size_t i = 0; i < json_object_array_length(sources); i++) {
            struct json_object *source = json_object_array_get_idx(sources, i);
            const char *path = get(source, "path"), *root = get(source, "root_id");
            char parent[PATH_MAX], display[PATH_MAX];
            snprintf(parent, sizeof(parent), "%s", path);
            char *slash = strrchr(parent, '/');
            if (!slash || !slash[1]) {
                failure = "invalid_source";
                break;
            }
            char name[NAME_MAX + 1];
            if (strlen(slash + 1) > NAME_MAX) {
                failure = "invalid_source";
                break;
            }
            snprintf(name, sizeof(name), "%s", slash + 1);
            if (slash == parent)
                slash[1] = 0;
            else
                *slash = 0;
            int src = storage_files_open_dir(root, parent, 0, display, sizeof(display), &reason);
            struct stat st;
            if (src < 0 || fstat(src, &st)) {
                if (src >= 0)
                    close(src);
                failure = "source_unavailable";
                break;
            }
            size_t source_len = strlen(path);
            if (!strncmp(canonical, path, source_len) &&
                (canonical[source_len] == '/' || canonical[source_len] == 0)) {
                close(src);
                failure = "destination_inside_source";
                break;
            }
            if (create_entry(writer, src, name, name, path, st.st_dev, 0, &count)) {
                close(src);
                failure = cancelled ? "cancelled" : "source_unavailable";
                break;
            }
            close(src);
        }
        if (archive_write_close(writer) < ARCHIVE_OK && !failure)
            failure = "create_failed";
        if (fsync(fd) && !failure)
            failure = "write_failed";
        close(fd);
        if (!failure && syscall(SYS_renameat2, destination_fd, temporary, destination_fd, filename,
                                RENAME_NOREPLACE)) {
            failure = errno == EEXIST ? "file_exists" : "commit_failed";
        }
        if (!failure) {
            temporary[0] = 0;
            fsync(destination_fd);
            success = 1;
            result_item(results, target, "succeeded", NULL);
        }
        goto done;
    }
    if (strcmp(operation, "list") && strcmp(operation, "extract") && strcmp(operation, "preview")) {
        failure = "operation_unsupported";
        goto done;
    }
    struct json_object *source = object(request, "source");
    struct storage_files_stream stream;
    const char *reason = "";
    if (storage_files_open_stream(get(source, "root_id"), get(source, "path"), &stream, &reason)) {
        failure = reason;
        goto done;
    }
    source_fd = stream.fd;
    reader = archive_read_new();
    reader_formats(reader);
    if (archive_read_open_fd(reader, source_fd, 65536) < ARCHIVE_OK) {
        failure = "format_unsupported";
        goto done;
    }
    if (!strcmp(operation, "preview") && (!entries || json_object_array_length(entries) != 1)) {
        failure = "invalid_entries";
        goto done;
    }
    struct archive_entry *entry;
    int status = ARCHIVE_EOF, count = 0, matched = 0;
    while (!cancelled && (status = archive_read_next_header(reader, &entry)) == ARCHIVE_OK) {
        const char *name = archive_entry_pathname(entry);
        if (++count > 100000) {
            failure = "archive_entry_limit";
            break;
        }
        if (!safe_entry(entry)) {
            failed++;
            result_item(results, name, "failed", "unsafe_or_unsupported_entry");
            if (strcmp(operation, "list"))
                break;
            continue;
        }
        if (!selected(object(request, "entries"), name)) {
            archive_read_data_skip(reader);
            continue;
        }
        matched++;
        if (!strcmp(operation, "list")) {
            struct json_object *r = json_object_new_object();
            json_object_object_add(r, "path", json_object_new_string(name));
            json_object_object_add(r, "size_bytes",
                                   json_object_new_int64(archive_entry_size(entry)));
            json_object_object_add(
                r, "is_dir", json_object_new_boolean(archive_entry_filetype(entry) == AE_IFDIR));
            if (json_object_array_length(results) < 1000)
                json_object_array_add(results, r);
            else {
                json_object_put(r);
                failure = "listing_limit";
                break;
            }
            success++;
            archive_read_data_skip(reader);
            continue;
        }
        if (!strcmp(operation, "preview")) {
            if (archive_entry_filetype(entry) != AE_IFREG || strcmp(name, json_object_get_string(json_object_array_get_idx(entries, 0)))) {
                failure = "preview_requires_file";
                break;
            }
            if (storage_files_content_denied(name, base_name(name), &reason)) { failure = "read_protected"; break; }
            unsigned char *buffer = malloc(262145);
            if (!buffer) { failure = "out_of_memory"; break; }
            size_t length = 0; la_ssize_t n = 0;
            while (!cancelled && length < 262145 && (n = archive_read_data(reader, buffer + length, 262145 - length)) > 0) length += n;
            if (cancelled) failure = "cancelled";
            else if (n < 0) failure = "archive_read_failed";
            else if (length > 262144) failure = "preview_too_large";
            else if (!utf8_text(buffer, length)) failure = "preview_not_text";
            else {
                json_object_object_add(out, "text", json_object_new_string_len((char *)buffer, length));
                json_object_object_add(out, "path", json_object_new_string(name));
                success = 1;
            }
            free(buffer);
            status = ARCHIVE_EOF;
            break;
        }
        char display[PATH_MAX];
        if (snprintf(display, sizeof(display), "%s/%s", canonical, name) >= (int)sizeof(display) ||
            storage_files_write_denied(display, &reason)) {
            failed++;
            result_item(results, name, "failed", "write_protected");
            break;
        }
        char leaf[NAME_MAX + 1];
        int parent = parent_dir(destination_fd, name, leaf, dst.st_dev);
        if (parent < 0) {
            failed++;
            result_item(results, name, "failed", "destination_unavailable");
            break;
        }
        if (archive_entry_filetype(entry) == AE_IFDIR) {
            int rc = mkdirat(parent, leaf, 0755);
            if (rc && errno != EEXIST) {
                failed++;
                result_item(results, name, "failed", "mkdir_failed");
                close(parent);
                break;
            }
            int check = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            struct stat st;
            if (check < 0 || fstat(check, &st) || st.st_dev != dst.st_dev) {
                if (check >= 0)
                    close(check);
                close(parent);
                failed++;
                break;
            }
            close(check);
            close(parent);
            continue;
        }
        struct stat exists;
        if (fstatat(parent, leaf, &exists, AT_SYMLINK_NOFOLLOW) == 0) {
            if (!strcmp(get(request, "on_conflict"), "skip")) {
                skipped++;
                result_item(results, name, "skipped", NULL);
                archive_read_data_skip(reader);
                close(parent);
                continue;
            }
            if (strcmp(conflict, "replace") || !S_ISREG(exists.st_mode) || exists.st_dev != dst.st_dev) {
                failed++;
                result_item(results, name, "failed", "file_exists");
                close(parent);
                break;
            }
        }
        char temp[80];
        snprintf(temp, sizeof(temp), ".dreamingwrt-tx-nas-%ld", (long)getpid());
        int fd = openat(parent, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        int rc = fd < 0 ? -1 : 0;
        char buffer[65536];
        la_ssize_t received = 0;
        while (!rc && !cancelled &&
               (received = archive_read_data(reader, buffer, sizeof(buffer))) > 0) {
            size_t offset = 0;
            while (offset < (size_t)received) {
                ssize_t n = write(fd, buffer + offset, (size_t)received - offset);
                if (n < 0 && errno == EINTR && !cancelled)
                    continue;
                if (n <= 0) {
                    rc = -1;
                    break;
                }
                offset += (size_t)n;
            }
        }
        if (received < 0)
            rc = -1;
        if (fd >= 0) {
            if (fsync(fd))
                rc = -1;
            close(fd);
        }
        if (rc < ARCHIVE_OK || cancelled ||
            syscall(SYS_renameat2, parent, temp, parent, leaf, !strcmp(conflict, "replace") ? 0 : RENAME_NOREPLACE)) {
            unlinkat(parent, temp, 0);
            failed++;
            result_item(results, name, "failed", cancelled ? "cancelled" : "extract_failed");
            close(parent);
            break;
        }
        fsync(parent);
        close(parent);
        success++;
        result_item(results, name, "succeeded", NULL);
    }
    if (cancelled)
        failure = "cancelled";
    else if (!failure && !failed && status != ARCHIVE_EOF)
        failure = "archive_read_failed";
    else if (!failure && entries && json_object_array_length(entries) && !matched)
        failure = "entries_not_found";
done:
    if (temporary[0] && destination_fd >= 0)
        unlinkat(destination_fd, temporary, 0);
    if (reader)
        archive_read_free(reader);
    if (writer)
        archive_write_free(writer);
    if (source_fd >= 0)
        close(source_fd);
    if (destination_fd >= 0)
        close(destination_fd);
    json_object_object_add(out, "state",
                           json_object_new_string(failure || failed
                                                      ? (cancelled ? "cancelled" : "failed")
                                                      : "succeeded"));
    json_object_object_add(out, "succeeded", json_object_new_int(success));
    json_object_object_add(out, "failed", json_object_new_int(failed));
    json_object_object_add(out, "skipped", json_object_new_int(skipped));
    json_object_object_add(out, "results", results);
    if (failure)
        json_object_object_add(out, "error", json_object_new_string(failure));
    puts(json_object_to_json_string_ext(out, JSON_C_TO_STRING_PLAIN));
    json_object_put(out);
    json_object_put(request);
    return failure || failed ? 1 : 0;
}
