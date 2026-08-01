// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "storage_blockdev.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BLKDEV_EXEC_OUTPUT_MAX (256U * 1024U)
#define BLKDEV_EXEC_KILL_GRACE_MS 200
#define BLKDEV_LSBLK_TIMEOUT_MS 2500
#define BLKDEV_SFDISK_TIMEOUT_MS 2500
#define BLKDEV_MDADM_TIMEOUT_MS 2500

/* ------------------------------------------------------------------ *
 * Small exec helper: argv-based, capture stdout, hard timeout.        *
 * No shell is invoked, so callers must never pass untrusted argv.     *
 * ------------------------------------------------------------------ */
struct blkdev_exec_result {
    char *output;
    size_t output_len;
    int exit_code;
    int timed_out;
    int truncated;
};

static int64_t blkdev_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void blkdev_exec_free(struct blkdev_exec_result *r)
{
    if (!r)
        return;
    free(r->output);
    memset(r, 0, sizeof(*r));
}

static int blkdev_exec(char *const argv[], int timeout_ms,
                       struct blkdev_exec_result *result)
{
    int pipefd[2] = { -1, -1 };
    pid_t pid;
    int64_t deadline;
    int status = 0, child_done = 0, term_sent = 0;
    size_t output_max = BLKDEV_EXEC_OUTPUT_MAX;

    if (!argv || !argv[0] || !result || timeout_ms < 1)
        return -1;
    memset(result, 0, sizeof(*result));
    result->exit_code = -1;
    result->output = calloc(output_max + 1, 1);
    if (!result->output || pipe(pipefd) != 0)
        goto failed;
    pid = fork();
    if (pid < 0)
        goto failed;
    if (pid == 0) {
        int nullfd;
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        nullfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (nullfd >= 0) {
            dup2(nullfd, STDIN_FILENO);
            close(nullfd);
        }
        execv(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    pipefd[1] = -1;
    fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);
    deadline = blkdev_now_ms() + timeout_ms;
    while (!child_done || pipefd[0] >= 0) {
        struct pollfd pfd;
        int64_t now = blkdev_now_ms();
        int wait_ms = now < deadline ? (int)(deadline - now) : 0;
        int pr;
        if (wait_ms > 50)
            wait_ms = 50;
        pfd.fd = pipefd[0];
        pfd.events = POLLIN | POLLHUP;
        pfd.revents = 0;
        pr = pipefd[0] >= 0 ? poll(&pfd, 1, wait_ms) : 0;
        if (pr > 0 && (pfd.revents & (POLLIN | POLLHUP))) {
            for (;;) {
                char buf[4096];
                ssize_t n = read(pipefd[0], buf, sizeof(buf));
                if (n > 0) {
                    size_t room = output_max - result->output_len;
                    size_t take = (size_t)n < room ? (size_t)n : room;
                    if (take) {
                        memcpy(result->output + result->output_len, buf, take);
                        result->output_len += take;
                        result->output[result->output_len] = '\0';
                    }
                    if (take < (size_t)n)
                        result->truncated = 1;
                } else if (n == 0) {
                    close(pipefd[0]);
                    pipefd[0] = -1;
                    break;
                } else if (errno != EAGAIN && errno != EINTR) {
                    close(pipefd[0]);
                    pipefd[0] = -1;
                    break;
                } else {
                    break;
                }
            }
        }
        if (!child_done) {
            pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid)
                child_done = 1;
        }
        now = blkdev_now_ms();
        if (child_done && pipefd[0] >= 0 && now >= deadline) {
            close(pipefd[0]);
            pipefd[0] = -1;
            result->truncated = 1;
        }
        if (!child_done && now >= deadline && !term_sent) {
            kill(pid, SIGTERM);
            result->timed_out = 1;
            term_sent = 1;
            deadline = now + BLKDEV_EXEC_KILL_GRACE_MS;
        } else if (!child_done && term_sent && now >= deadline) {
            kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
                ;
            child_done = 1;
        }
        if (child_done && pipefd[0] < 0)
            break;
    }
    if (WIFEXITED(status))
        result->exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        result->exit_code = 128 + WTERMSIG(status);
    return 0;

failed:
    if (pipefd[0] >= 0)
        close(pipefd[0]);
    if (pipefd[1] >= 0)
        close(pipefd[1]);
    blkdev_exec_free(result);
    return -1;
}

/* Locate an executable, preferring the canonical OpenWrt path. */
static const char *blkdev_tool_path(const char *name,
                                    const char *const candidates[])
{
    int i;
    (void)name;
    for (i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0)
            return candidates[i];
    }
    return NULL;
}

static const char *blkdev_lsblk_path(void)
{
#ifdef STORAGE_BLOCKDEV_LSBLK_PATH
    return STORAGE_BLOCKDEV_LSBLK_PATH;
#else
    static const char *c[] = { "/usr/bin/lsblk", "/bin/lsblk",
                               "/sbin/lsblk", NULL };
    return blkdev_tool_path("lsblk", c);
#endif
}

static const char *blkdev_sfdisk_path(void)
{
#ifdef STORAGE_BLOCKDEV_SFDISK_PATH
    return STORAGE_BLOCKDEV_SFDISK_PATH;
#else
    static const char *c[] = { "/usr/sbin/sfdisk", "/sbin/sfdisk",
                               "/usr/bin/sfdisk", "/bin/sfdisk", NULL };
    return blkdev_tool_path("sfdisk", c);
#endif
}

static const char *blkdev_mdadm_path(void)
{
    static const char *c[] = { "/sbin/mdadm", "/usr/sbin/mdadm", NULL };
    return blkdev_tool_path("mdadm", c);
}

/* ------------------------------------------------------------------ *
 * sysfs / procfs helpers                                              *
 * ------------------------------------------------------------------ */
static int blkdev_read_text(const char *path, char *out, size_t out_len)
{
    int fd;
    ssize_t n;
    if (!out || out_len < 1)
        return -1;
    out[0] = '\0';
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    n = read(fd, out, out_len - 1);
    close(fd);
    if (n < 0)
        return -1;
    out[n] = '\0';
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r' ||
                     out[n - 1] == ' '))
        out[--n] = '\0';
    return 0;
}

/* Read the mountpoint of a device by scanning /proc/self/mountinfo. */
static int blkdev_mount_of(const char *devnode, char *out, size_t out_len)
{
    FILE *fp;
    char line[1024];
    int found = 0;
    if (!devnode || !*devnode || !out || out_len < 1)
        return -1;
    out[0] = '\0';
    fp = fopen("/proc/self/mountinfo", "re");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        /* mountinfo: 36 35 98:0 / /mnt ... - ext4 /dev/sda1 rw */
        char *sep = strstr(line, " - ");
        char *tok, *save;
        char mountpoint[512] = "";
        int field = 0;
        if (!sep)
            continue;
        /* mount point is field 5 (1-based) before the separator */
        for (tok = strtok_r(line, " ", &save); tok;
             tok = strtok_r(NULL, " ", &save)) {
            field++;
            if (field == 5) {
                snprintf(mountpoint, sizeof(mountpoint), "%s", tok);
                break;
            }
        }
        /* device is the field right after "- <fstype>" */
        {
            char *fs = sep + 3;
            char *fstok, *fsave;
            int fi = 0;
            for (fstok = strtok_r(fs, " ", &fsave); fstok;
                 fstok = strtok_r(NULL, " ", &fsave)) {
                fi++;
                if (fi == 2) {
                    if (!strcmp(fstok, devnode)) {
                        snprintf(out, out_len, "%s", mountpoint);
                        found = 1;
                    }
                    break;
                }
            }
        }
        if (found)
            break;
    }
    fclose(fp);
    return found ? 0 : -1;
}

/* A partition/disk is "system" if it hosts /, /boot, /data or is currently
 * providing the running rootfs. Used only to gate destructive writes. */
static int blkdev_mount_is_protected(const char *mountpoint)
{
    if (!mountpoint || !*mountpoint)
        return 0;
    if (!strcmp(mountpoint, "/") || !strcmp(mountpoint, "/boot") ||
        !strcmp(mountpoint, "/data") ||
        !strncmp(mountpoint, "/boot/", 6))
        return 1;
    return 0;
}

/* ------------------------------------------------------------------ *
 * lsblk JSON parsing (partition inventory)                            *
 * ------------------------------------------------------------------ */
static int64_t blkdev_json_i64(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !v)
        return -1;
    if (json_object_is_type(v, json_type_int))
        return json_object_get_int64(v);
    if (json_object_is_type(v, json_type_string)) {
        const char *s = json_object_get_string(v);
        return s ? strtoll(s, NULL, 10) : -1;
    }
    return -1;
}

static const char *blkdev_json_str(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !v)
        return NULL;
    if (json_object_is_type(v, json_type_string))
        return json_object_get_string(v);
    return NULL;
}

static int blkdev_json_bool(struct json_object *o, const char *key)
{
    struct json_object *v = NULL;
    if (!o || !json_object_object_get_ex(o, key, &v) || !v)
        return 0;
    if (json_object_is_type(v, json_type_boolean))
        return json_object_get_boolean(v);
    if (json_object_is_type(v, json_type_string)) {
        const char *s = json_object_get_string(v);
        return s && (!strcmp(s, "1") || !strcasecmp(s, "true"));
    }
    if (json_object_is_type(v, json_type_int))
        return json_object_get_int(v) != 0;
    return 0;
}

static void blkdev_add_str(struct json_object *o, const char *key,
                           const char *val)
{
    json_object_object_add(o, key,
                           val ? json_object_new_string(val) : NULL);
}

static void blkdev_add_i64(struct json_object *o, const char *key, int64_t v)
{
    if (v >= 0)
        json_object_object_add(o, key, json_object_new_int64(v));
    else
        json_object_object_add(o, key, NULL);
}

static int blkdev_u64_add_ok(uint64_t a, uint64_t b, uint64_t *out)
{
    if (!out || b > UINT64_MAX - a)
        return 0;
    *out = a + b;
    return 1;
}

/* sfdisk computes the usable ranges from the on-disk partition table. This is
 * intentionally not reconstructed as disk-size minus partition sizes: GPT/MBR
 * metadata and alignment gaps are not necessarily allocatable. */
int jmx_storage_unallocated_extents(const char *device, uint64_t disk_bytes,
                                    uint64_t fallback_sector_size,
                                    struct json_object **extents_out,
                                    uint64_t *bytes_out,
                                    const char **reason_out)
{
    const char *sfdisk = blkdev_sfdisk_path();
    struct blkdev_exec_result res;
    struct json_object *parsed = NULL, *table = NULL, *parts = NULL;
    struct json_object *extents = NULL;
    uint64_t sector_size = fallback_sector_size, total = 0, previous_end = 0;
    size_t i, count;
    int rc = -1;

    if (extents_out)
        *extents_out = NULL;
    if (bytes_out)
        *bytes_out = 0;
    if (reason_out)
        *reason_out = "sfdisk_not_installed";
    if (!device || !device[0] || !extents_out || !bytes_out || !reason_out ||
        !sfdisk)
        return -1;
    {
        char *argv[] = { (char *)sfdisk, "--json", "--list-free",
                         (char *)device, NULL };
        if (blkdev_exec(argv, BLKDEV_SFDISK_TIMEOUT_MS, &res) != 0) {
            *reason_out = "sfdisk_exec_failed";
            return -1;
        }
    }
    if (res.timed_out) {
        *reason_out = "sfdisk_timed_out";
        goto out;
    }
    if (res.truncated) {
        *reason_out = "sfdisk_output_truncated";
        goto out;
    }
    if (res.exit_code != 0 || !res.output || !res.output_len) {
        *reason_out = "sfdisk_list_free_failed";
        goto out;
    }
    parsed = json_tokener_parse(res.output);
    if (!parsed || !json_object_object_get_ex(parsed, "partitiontable", &table) ||
        !json_object_is_type(table, json_type_object) ||
        !json_object_object_get_ex(table, "partitions", &parts) ||
        !json_object_is_type(parts, json_type_array)) {
        *reason_out = "sfdisk_list_free_invalid_json";
        goto out;
    }
    {
        int64_t reported = blkdev_json_i64(table, "sectorsize");
        if (reported > 0)
            sector_size = (uint64_t)reported;
    }
    if (!sector_size || sector_size > (1024U * 1024U)) {
        *reason_out = "sfdisk_invalid_sector_size";
        goto out;
    }
    extents = json_object_new_array();
    count = json_object_array_length(parts);
    for (i = 0; i < count; i++) {
        struct json_object *row = json_object_array_get_idx(parts, i);
        int64_t start_i = blkdev_json_i64(row, "start");
        int64_t size_i = blkdev_json_i64(row, "size");
        uint64_t start, sectors, end_exclusive, capacity;
        struct json_object *extent;

        if (start_i < 0 || size_i <= 0) {
            *reason_out = "sfdisk_invalid_free_extent";
            goto out;
        }
        start = (uint64_t)start_i;
        sectors = (uint64_t)size_i;
        if (!blkdev_u64_add_ok(start, sectors, &end_exclusive) ||
            start < previous_end || sectors > UINT64_MAX / sector_size) {
            *reason_out = "sfdisk_invalid_free_extent";
            goto out;
        }
        capacity = sectors * sector_size;
        if (start > INT64_MAX || sectors > INT64_MAX ||
            end_exclusive - 1 > INT64_MAX || capacity > INT64_MAX ||
            (disk_bytes && (start > disk_bytes / sector_size ||
                            end_exclusive > disk_bytes / sector_size ||
                            capacity > disk_bytes - start * sector_size)) ||
            total > UINT64_MAX - capacity) {
            *reason_out = "sfdisk_free_extent_out_of_bounds";
            goto out;
        }
        extent = json_object_new_object();
        json_object_object_add(extent, "start_sector",
                               json_object_new_int64((int64_t)start));
        json_object_object_add(extent, "end_sector",
                               json_object_new_int64((int64_t)(end_exclusive - 1)));
        json_object_object_add(extent, "sector_count",
                               json_object_new_int64((int64_t)sectors));
        json_object_object_add(extent, "capacity_bytes",
                               json_object_new_int64((int64_t)capacity));
        json_object_array_add(extents, extent);
        total += capacity;
        previous_end = end_exclusive;
    }
    *extents_out = extents;
    *bytes_out = total;
    *reason_out = "sfdisk_partition_table_free_regions";
    extents = NULL;
    rc = 0;
out:
    if (extents)
        json_object_put(extents);
    if (parsed)
        json_object_put(parsed);
    blkdev_exec_free(&res);
    return rc;
}

/* Build one partition object from an lsblk child node. */
static struct json_object *blkdev_partition_from_lsblk(struct json_object *node,
                                                       int *protected_out)
{
    struct json_object *part = json_object_new_object();
    const char *path = blkdev_json_str(node, "path");
    const char *name = blkdev_json_str(node, "name");
    char mount[512] = "";
    int mounted = 0, is_protected = 0;

    blkdev_add_str(part, "name", name);
    blkdev_add_str(part, "device", path);
    blkdev_add_str(part, "filesystem", blkdev_json_str(node, "fstype"));
    blkdev_add_str(part, "label", blkdev_json_str(node, "label"));
    blkdev_add_str(part, "partlabel", blkdev_json_str(node, "partlabel"));
    blkdev_add_str(part, "uuid", blkdev_json_str(node, "uuid"));
    blkdev_add_str(part, "partition_type", blkdev_json_str(node, "pttype"));
    blkdev_add_i64(part, "capacity_bytes", blkdev_json_i64(node, "size"));
    json_object_object_add(part, "read_only",
                           json_object_new_boolean(blkdev_json_bool(node, "ro")));

    if (path && blkdev_mount_of(path, mount, sizeof(mount)) == 0 && mount[0]) {
        struct json_object *arr = json_object_new_array();
        struct json_object *m = json_object_new_object();
        mounted = 1;
        is_protected = blkdev_mount_is_protected(mount);
        blkdev_add_str(m, "path", mount);
        json_object_array_add(arr, m);
        json_object_object_add(part, "mounts", arr);
        blkdev_add_str(part, "mount_point", mount);
    }
    /* lsblk MOUNTPOINT fallback */
    if (!mounted) {
        const char *mp = blkdev_json_str(node, "mountpoint");
        if (mp && *mp) {
            mounted = 1;
            is_protected = blkdev_mount_is_protected(mp);
            blkdev_add_str(part, "mount_point", mp);
        }
    }
    json_object_object_add(part, "mounted",
                           json_object_new_boolean(mounted));
    json_object_object_add(part, "system",
                           json_object_new_boolean(is_protected));
    /* per-partition capabilities: honest false for protected/mounted */
    {
        struct json_object *caps = json_object_new_object();
        int writable = !is_protected && !mounted;
        json_object_object_add(caps, "delete",
                               json_object_new_boolean(0)); /* gated globally */
        json_object_object_add(caps, "format",
                               json_object_new_boolean(0));
        json_object_object_add(caps, "resize",
                               json_object_new_boolean(0));
        json_object_object_add(caps, "mount",
                               json_object_new_boolean(0));
        json_object_object_add(caps, "unmount",
                               json_object_new_boolean(0));
        (void)writable;
        json_object_object_add(part, "capabilities", caps);
    }
    if (protected_out && is_protected)
        *protected_out = 1;
    return part;
}

/* Build one disk object (with children partitions) from an lsblk node. */
static struct json_object *blkdev_disk_from_lsblk(struct json_object *node)
{
    struct json_object *disk = json_object_new_object();
    struct json_object *children = NULL;
    struct json_object *parts = json_object_new_array();
    const char *name = blkdev_json_str(node, "name");
    const char *path = blkdev_json_str(node, "path");
    char sys_stable[512] = "";
    int any_protected = 0;
    struct json_object *free_extents = NULL;
    const char *free_reason = NULL;
    int64_t total_bytes_i = blkdev_json_i64(node, "size");
    int64_t sector_size_i = blkdev_json_i64(node, "log-sec");
    uint64_t free_bytes = 0;

    blkdev_add_str(disk, "name", name);
    blkdev_add_str(disk, "device", path);
    blkdev_add_str(disk, "model", blkdev_json_str(node, "model"));
    blkdev_add_str(disk, "serial", blkdev_json_str(node, "serial"));
    blkdev_add_str(disk, "transport", blkdev_json_str(node, "tran"));
    blkdev_add_str(disk, "partition_table", blkdev_json_str(node, "pttype"));
    blkdev_add_i64(disk, "total_bytes", blkdev_json_i64(node, "size"));
    blkdev_add_i64(disk, "logical_sector_size",
                   blkdev_json_i64(node, "log-sec"));
    blkdev_add_i64(disk, "physical_sector_size",
                   blkdev_json_i64(node, "phy-sec"));
    json_object_object_add(disk, "removable",
                           json_object_new_boolean(blkdev_json_bool(node, "rm")));

    /* Stable id from /dev/disk/by-id is not always present; fall back to
     * serial/path. Keep it deterministic so the UI can track selection. */
    if (name && name[0]) {
        snprintf(sys_stable, sizeof(sys_stable), "%s", name);
        blkdev_add_str(disk, "stable_id",
                       blkdev_json_str(node, "serial") ?
                       blkdev_json_str(node, "serial") : path);
    }

    if (json_object_object_get_ex(node, "children", &children) &&
        json_object_is_type(children, json_type_array)) {
        size_t i, n = json_object_array_length(children);
        for (i = 0; i < n; i++) {
            struct json_object *ch = json_object_array_get_idx(children, i);
            const char *ctype = blkdev_json_str(ch, "type");
            if (ctype && !strcmp(ctype, "part")) {
                json_object_array_add(parts,
                    blkdev_partition_from_lsblk(ch, &any_protected));
            }
        }
    }
    json_object_object_add(disk, "partitions", parts);
    json_object_object_add(disk, "system",
                           json_object_new_boolean(any_protected));
    if (jmx_storage_unallocated_extents(
            path, total_bytes_i > 0 ? (uint64_t)total_bytes_i : 0,
            sector_size_i > 0 ? (uint64_t)sector_size_i : 512,
            &free_extents, &free_bytes, &free_reason) == 0) {
        json_object_object_add(disk, "unallocated_space_supported",
                               json_object_new_boolean(1));
        json_object_object_add(disk, "unallocated_bytes",
                               json_object_new_int64((int64_t)free_bytes));
        json_object_object_add(disk, "unallocated_extents", free_extents);
        blkdev_add_str(disk, "unallocated_source", free_reason);
    } else {
        json_object_object_add(disk, "unallocated_space_supported",
                               json_object_new_boolean(0));
        json_object_object_add(disk, "unallocated_bytes", NULL);
        json_object_object_add(disk, "unallocated_extents",
                               json_object_new_array());
        blkdev_add_str(disk, "unallocated_reason", free_reason);
    }
    return disk;
}

/* Build the honest partition-management capability envelope. Destructive
 * partition transactions are gated false until a protected-op contract exists;
 * the read inventory is fully populated. */
static struct json_object *blkdev_partition_capabilities(int have_inventory)
{
    struct json_object *caps = json_object_new_object();
    json_object_object_add(caps, "inventory",
                           json_object_new_boolean(have_inventory));
    json_object_object_add(caps, "transaction_preview",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "transaction_commit",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "partition_create",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "partition_delete",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "partition_format",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "partition_mount",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "partition_unmount",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "partition_resize",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "write_transaction_reason",
        json_object_new_string(
            "partition_write_transaction_contract_pending"));
    return caps;
}

struct json_object *jmx_storage_partitions_get(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *storage = json_object_new_object();
    struct json_object *disks = json_object_new_array();
    const char *lsblk = blkdev_lsblk_path();
    struct blkdev_exec_result res;
    int have_inventory = 0;

    if (lsblk) {
        char *argv[] = {
            (char *)lsblk, "-J", "-b", "-o",
            "NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,UUID,PARTLABEL,PARTUUID,"
            "MOUNTPOINT,MODEL,SERIAL,TRAN,PTTYPE,RM,RO,PHY-SEC,LOG-SEC",
            NULL
        };
        if (blkdev_exec(argv, BLKDEV_LSBLK_TIMEOUT_MS, &res) == 0 &&
            res.exit_code == 0 && res.output && res.output_len) {
            struct json_object *parsed = json_tokener_parse(res.output);
            struct json_object *bd = NULL;
            if (parsed &&
                json_object_object_get_ex(parsed, "blockdevices", &bd) &&
                json_object_is_type(bd, json_type_array)) {
                size_t i, n = json_object_array_length(bd);
                for (i = 0; i < n; i++) {
                    struct json_object *node =
                        json_object_array_get_idx(bd, i);
                    const char *type = blkdev_json_str(node, "type");
                    const char *name = blkdev_json_str(node, "name");
                    /* Only physical disks; skip loop/ram/nbd/optical/md. */
                    if (!type || strcmp(type, "disk"))
                        continue;
                    if (name && (!strncmp(name, "loop", 4) ||
                                 !strncmp(name, "ram", 3) ||
                                 !strncmp(name, "zram", 4) ||
                                 !strncmp(name, "nbd", 3) ||
                                 !strncmp(name, "sr", 2) ||
                                 !strncmp(name, "md", 2)))
                        continue;
                    json_object_array_add(disks,
                        blkdev_disk_from_lsblk(node));
                    have_inventory = 1;
                }
            }
            if (parsed)
                json_object_put(parsed);
        }
        blkdev_exec_free(&res);
    }

    json_object_object_add(storage, "disks", disks);
    json_object_object_add(storage, "contract_version",
                           json_object_new_string("storage-partitions.v1"));
    json_object_object_add(storage, "observed_at",
                           json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(storage, "capabilities",
                           blkdev_partition_capabilities(have_inventory));
    if (!lsblk)
        json_object_object_add(storage, "reason",
                               json_object_new_string("lsblk_not_installed"));
    json_object_object_add(root, "storage", storage);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    return root;
}

/* ------------------------------------------------------------------ *
 * RAID inventory (/proc/mdstat + mdadm --detail)                      *
 * ------------------------------------------------------------------ */
static struct json_object *blkdev_raid_capabilities(int mdadm_present,
                                                    int array_count)
{
    struct json_object *caps = json_object_new_object();
    struct json_object *levels = json_object_new_array();
    json_object_object_add(caps, "inventory",
                           json_object_new_boolean(mdadm_present));
    json_object_object_add(caps, "scan",
                           json_object_new_boolean(mdadm_present));
    /* Destructive create/recover/delete gated until safety contract. */
    json_object_object_add(caps, "raid_create",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "raid_recover",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "raid_delete",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "raid_mount",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "raid_unmount",
                           json_object_new_boolean(0));
    json_object_object_add(caps, "write_transaction_reason",
        json_object_new_string("raid_write_transaction_contract_pending"));
    /* Supported levels advertised from loaded kernel personalities. */
    {
        char buf[512] = "";
        if (blkdev_read_text("/proc/mdstat", buf, sizeof(buf)) == 0) {
            if (strstr(buf, "raid0"))
                json_object_array_add(levels, json_object_new_string("raid0"));
            if (strstr(buf, "raid1"))
                json_object_array_add(levels, json_object_new_string("raid1"));
            if (strstr(buf, "raid10"))
                json_object_array_add(levels, json_object_new_string("raid10"));
            if (strstr(buf, "raid5"))
                json_object_array_add(levels, json_object_new_string("raid5"));
            if (strstr(buf, "raid6"))
                json_object_array_add(levels, json_object_new_string("raid6"));
            if (strstr(buf, "linear"))
                json_object_array_add(levels, json_object_new_string("jbod"));
        }
    }
    json_object_object_add(caps, "supported_levels", levels);
    (void)array_count;
    return caps;
}

/* Parse `mdadm --detail /dev/mdX` output into an array object. */
static struct json_object *blkdev_raid_detail(const char *mdadm,
                                              const char *mddev)
{
    struct json_object *arr = json_object_new_object();
    struct blkdev_exec_result res;
    char *argv[] = { (char *)mdadm, "--detail", (char *)mddev, NULL };
    struct json_object *members = json_object_new_array();

    blkdev_add_str(arr, "device", mddev);
    blkdev_add_str(arr, "id", mddev);
    blkdev_add_str(arr, "name", mddev);

    if (blkdev_exec(argv, BLKDEV_MDADM_TIMEOUT_MS, &res) == 0 &&
        res.output && res.output_len) {
        char *line, *save;
        char *copy = strdup(res.output);
        if (copy) {
            for (line = strtok_r(copy, "\n", &save); line;
                 line = strtok_r(NULL, "\n", &save)) {
                char *colon = strchr(line, ':');
                /* Member device lines start with a leading number + /dev/... */
                char *devp = strstr(line, "/dev/");
                if (devp && (strstr(line, "active") || strstr(line, "spare") ||
                             strstr(line, "faulty") || strstr(line, "sync"))) {
                    struct json_object *m = json_object_new_object();
                    char devbuf[128];
                    char *end = devp;
                    while (*end && !isspace((unsigned char)*end))
                        end++;
                    snprintf(devbuf, sizeof(devbuf), "%.*s",
                             (int)(end - devp), devp);
                    blkdev_add_str(m, "device", devbuf);
                    if (strstr(line, "faulty"))
                        blkdev_add_str(m, "state", "faulty");
                    else if (strstr(line, "spare"))
                        blkdev_add_str(m, "state", "spare");
                    else
                        blkdev_add_str(m, "state", "active");
                    json_object_array_add(members, m);
                    continue;
                }
                if (!colon)
                    continue;
                {
                    char key[64];
                    char *val = colon + 1;
                    size_t klen = (size_t)(colon - line);
                    while (klen && isspace((unsigned char)line[0])) {
                        line++; klen--;
                    }
                    if (klen >= sizeof(key))
                        klen = sizeof(key) - 1;
                    memcpy(key, line, klen);
                    key[klen] = '\0';
                    while (klen && isspace((unsigned char)key[klen - 1]))
                        key[--klen] = '\0';
                    while (*val && isspace((unsigned char)*val))
                        val++;
                    if (!strcmp(key, "Raid Level"))
                        blkdev_add_str(arr, "level", val);
                    else if (!strcmp(key, "Array Size")) {
                        long long kib = strtoll(val, NULL, 10);
                        if (kib > 0)
                            blkdev_add_i64(arr, "size_bytes", kib * 1024);
                    } else if (!strcmp(key, "State"))
                        blkdev_add_str(arr, "status", val);
                    else if (!strcmp(key, "UUID"))
                        blkdev_add_str(arr, "uuid", val);
                    else if (!strcmp(key, "Name"))
                        blkdev_add_str(arr, "label", val);
                }
            }
            free(copy);
        }
    }
    blkdev_exec_free(&res);
    json_object_object_add(arr, "members", members);
    return arr;
}

/* Enumerate active md arrays from /proc/mdstat. */
static void blkdev_raid_collect_active(const char *mdadm,
                                       struct json_object *arrays)
{
    FILE *fp = fopen("/proc/mdstat", "re");
    char line[1024];
    if (!fp)
        return;
    while (fgets(line, sizeof(line), fp)) {
        /* Lines like: md0 : active raid1 sda1[0] sdb1[1] */
        if (strncmp(line, "md", 2) == 0 && strstr(line, " : ")) {
            char mddev[64];
            char *sp = strchr(line, ' ');
            size_t nlen;
            if (!sp)
                continue;
            nlen = (size_t)(sp - line);
            if (nlen >= sizeof(mddev) - 6)
                nlen = sizeof(mddev) - 6;
            snprintf(mddev, sizeof(mddev), "/dev/%.*s", (int)nlen, line);
            if (mdadm)
                json_object_array_add(arrays,
                                      blkdev_raid_detail(mdadm, mddev));
            else {
                struct json_object *a = json_object_new_object();
                blkdev_add_str(a, "device", mddev);
                blkdev_add_str(a, "id", mddev);
                blkdev_add_str(a, "name", mddev);
                blkdev_add_str(a, "status", "active");
                json_object_array_add(arrays, a);
            }
        }
    }
    fclose(fp);
}

struct json_object *jmx_storage_raid_get(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *raid = json_object_new_object();
    struct json_object *arrays = json_object_new_array();
    struct json_object *recoverable = json_object_new_array();
    const char *mdadm = blkdev_mdadm_path();

    blkdev_raid_collect_active(mdadm, arrays);

    json_object_object_add(raid, "arrays", arrays);
    json_object_object_add(raid, "disks", json_object_new_array());
    json_object_object_add(raid, "recoverable", recoverable);
    json_object_object_add(raid, "capabilities",
        blkdev_raid_capabilities(mdadm != NULL,
                                 (int)json_object_array_length(arrays)));
    if (!mdadm)
        json_object_object_add(raid, "reason",
                               json_object_new_string("mdadm_not_installed"));
    json_object_object_add(root, "raid", raid);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    return root;
}

struct json_object *jmx_storage_raid_scan(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *candidates = json_object_new_array();
    const char *mdadm = blkdev_mdadm_path();
    struct blkdev_exec_result res;

    if (mdadm) {
        /* Non-destructive: --examine --scan only reads superblocks. */
        char *argv[] = { (char *)mdadm, "--examine", "--scan", NULL };
        if (blkdev_exec(argv, BLKDEV_MDADM_TIMEOUT_MS, &res) == 0 &&
            res.output) {
            char *line, *save;
            char *copy = strdup(res.output);
            if (copy) {
                for (line = strtok_r(copy, "\n", &save); line;
                     line = strtok_r(NULL, "\n", &save)) {
                    if (strstr(line, "ARRAY")) {
                        struct json_object *c = json_object_new_object();
                        char *devp = strstr(line, "/dev/");
                        char *uuidp = strstr(line, "UUID=");
                        if (devp) {
                            char devbuf[128];
                            char *end = devp;
                            while (*end && !isspace((unsigned char)*end))
                                end++;
                            snprintf(devbuf, sizeof(devbuf), "%.*s",
                                     (int)(end - devp), devp);
                            blkdev_add_str(c, "id", devbuf);
                            blkdev_add_str(c, "device", devbuf);
                            blkdev_add_str(c, "name", devbuf);
                        }
                        if (uuidp) {
                            char ubuf[128];
                            char *u = uuidp + 5;
                            char *end = u;
                            while (*end && !isspace((unsigned char)*end))
                                end++;
                            snprintf(ubuf, sizeof(ubuf), "%.*s",
                                     (int)(end - u), u);
                            blkdev_add_str(c, "uuid", ubuf);
                        }
                        blkdev_add_str(c, "status", "recoverable");
                        json_object_array_add(candidates, c);
                    }
                }
                free(copy);
            }
        }
        blkdev_exec_free(&res);
    }
    json_object_object_add(root, "recoverable", candidates);
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    if (!mdadm)
        json_object_object_add(root, "reason",
                               json_object_new_string("mdadm_not_installed"));
    return root;
}
