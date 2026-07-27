// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE

#include "storage_overview.h"

#include "../jmx.h"
#include "../jmx_db.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define STORAGE_SYS_BLOCK "/sys/block"
#define STORAGE_DISKSTATS "/proc/diskstats"
#define STORAGE_MAX_DISKS 64
#define STORAGE_MAX_PARTITIONS 128
#define STORAGE_MAX_MOUNTS 256
#define STORAGE_SMART_OUTPUT_MAX (128U * 1024U)
#define STORAGE_SMART_TIMEOUT_MS 1500
#define STORAGE_SMART_CACHE_MS (5LL * 60LL * 1000LL)
#define STORAGE_REQUEST_BUDGET_MS 3900
#define STORAGE_REQUEST_GUARD_MS 150
#define STORAGE_EXEC_KILL_GRACE_MS 100
#define STORAGE_HISTORY_RETENTION_SEC (8LL * 24LL * 60LL * 60LL)

struct storage_io_counter {
    unsigned long long reads_completed;
    unsigned long long sectors_read;
    unsigned long long read_ms;
    unsigned long long writes_completed;
    unsigned long long sectors_written;
    unsigned long long write_ms;
    int found;
};

struct storage_mount {
    unsigned int major;
    unsigned int minor;
    char path[PATH_MAX];
    uint64_t total_bytes;
    uint64_t used_bytes;
    uint64_t available_bytes;
    int stat_ok;
};

struct storage_partition {
    char name[64];
    char device[96];
    unsigned int major;
    unsigned int minor;
    uint64_t capacity_bytes;
};

struct storage_smart {
    char status[24];
    char reason[96];
    int temperature_valid;
    int temperature_c;
    int power_on_hours_valid;
    int64_t power_on_hours;
    int reallocated_valid;
    int64_t reallocated_sector_count;
    int exit_code;
    int cached;
    int64_t sampled_at;
};

struct storage_disk {
    char name[64];
    char id[256];
    char device[PATH_MAX];
    char model[256];
    char serial[256];
    char transport[64];
    uint64_t capacity_bytes;
    uint64_t filesystem_bytes;
    uint64_t used_bytes;
    uint64_t available_bytes;
    double used_percent;
    int usage_valid;
    double read_bps;
    double write_bps;
    double read_latency_ms;
    double write_latency_ms;
    int io_valid;
    double io_interval_seconds;
    char io_reason[64];
    int read_latency_valid;
    int write_latency_valid;
    struct storage_partition partitions[STORAGE_MAX_PARTITIONS];
    int partition_count;
    unsigned int major;
    unsigned int minor;
    struct storage_smart smart;
};

struct storage_exec_result {
    char *output;
    size_t output_len;
    int exit_code;
    int timed_out;
    int truncated;
};

struct storage_io_cache_entry {
    int used;
    char disk_id[256];
    struct storage_io_counter counter;
    int64_t sampled_ms;
};

struct storage_smart_cache_entry {
    int used;
    char disk_id[256];
    struct storage_smart smart;
    int64_t cached_ms;
};

static struct storage_io_cache_entry g_storage_io_cache[STORAGE_MAX_DISKS];
static struct storage_smart_cache_entry g_storage_smart_cache[STORAGE_MAX_DISKS];

static int64_t storage_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int storage_format(char *out, size_t out_len, const char *format, ...)
{
    va_list args;
    int written;

    if (!out || !out_len || !format)
        return -1;
    va_start(args, format);
    written = vsnprintf(out, out_len, format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= out_len) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

static int storage_read_text(const char *path, char *out, size_t out_len)
{
    FILE *fp;
    size_t len;

    if (!path || !out || out_len < 2)
        return -1;
    out[0] = '\0';
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    if (!fgets(out, (int)out_len, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    len = strlen(out);
    while (len && isspace((unsigned char)out[len - 1]))
        out[--len] = '\0';
    return 0;
}

static int storage_read_u64(const char *path, uint64_t *out)
{
    char value[64];
    char *end = NULL;
    unsigned long long parsed;

    if (!out || storage_read_text(path, value, sizeof(value)) != 0)
        return -1;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno || end == value || (end && *end))
        return -1;
    *out = (uint64_t)parsed;
    return 0;
}

static int storage_read_dev(const char *path, unsigned int *major_out,
                            unsigned int *minor_out)
{
    char value[64];
    unsigned int major_num, minor_num;

    if (storage_read_text(path, value, sizeof(value)) != 0 ||
        sscanf(value, "%u:%u", &major_num, &minor_num) != 2)
        return -1;
    *major_out = major_num;
    *minor_out = minor_num;
    return 0;
}

static void storage_copy_id_component(char *out, size_t out_len, const char *in)
{
    size_t i, oi = 0;

    if (!out || !out_len)
        return;
    for (i = 0; in && in[i] && oi + 1 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '.' || c == '_' || c == ':' || c == '-')
            out[oi++] = (char)c;
        else if (oi && out[oi - 1] != '_')
            out[oi++] = '_';
    }
    while (oi && out[oi - 1] == '_')
        oi--;
    out[oi] = '\0';
}

static int storage_is_excluded_name(const char *name)
{
    static const char *prefixes[] = { "loop", "zram", "nbd", "ram", "fd", NULL };
    int i;

    if (!name || !name[0] || name[0] == '.')
        return 1;
    for (i = 0; prefixes[i]; i++)
        if (!strncmp(name, prefixes[i], strlen(prefixes[i])))
            return 1;
    return 0;
}

static int storage_is_optical(const char *name)
{
    char path[PATH_MAX], type[32];

    if (!strncmp(name, "sr", 2) || !strncmp(name, "scd", 3))
        return 1;
    snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s/device/type", name);
    return storage_read_text(path, type, sizeof(type)) == 0 && !strcmp(type, "5");
}

static int storage_is_virtual_block(const char *name)
{
    char path[PATH_MAX], resolved[PATH_MAX];

    snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s", name);
    return realpath(path, resolved) != NULL &&
           strstr(resolved, "/devices/virtual/block/") != NULL;
}

static void storage_transport(const char *name, char *out, size_t out_len)
{
    char path[PATH_MAX], resolved[PATH_MAX];
    const char *base;

    snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s", name);
    if (realpath(path, resolved)) {
        if (strstr(resolved, "/usb")) {
            snprintf(out, out_len, "usb");
            return;
        }
        if (strstr(resolved, "/virtio")) {
            snprintf(out, out_len, "virtio");
            return;
        }
    }
    if (!strncmp(name, "nvme", 4)) {
        snprintf(out, out_len, "nvme");
        return;
    }
    if (!strncmp(name, "mmcblk", 6)) {
        snprintf(out, out_len, "mmc");
        return;
    }
    snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s/device/subsystem", name);
    if (realpath(path, resolved)) {
        base = strrchr(resolved, '/');
        snprintf(out, out_len, "%s", base ? base + 1 : resolved);
        return;
    }
    snprintf(out, out_len, "unknown");
}

static int storage_by_id(const char *device, char *out, size_t out_len)
{
    DIR *dir;
    struct dirent *entry;
    char device_real[PATH_MAX];
    int found = -1;

    if (!realpath(device, device_real))
        return -1;
    dir = opendir("/dev/disk/by-id");
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char path[PATH_MAX], target[PATH_MAX];

        if (entry->d_name[0] == '.' || strstr(entry->d_name, "-part"))
            continue;
        if (storage_format(path, sizeof(path), "/dev/disk/by-id/%s",
                           entry->d_name) != 0)
            continue;
        if (!realpath(path, target) || strcmp(target, device_real))
            continue;
        storage_copy_id_component(out, out_len, entry->d_name);
        found = out[0] ? 0 : -1;
        break;
    }
    closedir(dir);
    return found;
}

static void storage_stable_id(struct storage_disk *disk, const char *wwid)
{
    char stable[224] = {0};
    char path[PATH_MAX], resolved[PATH_MAX];
    char *block_component;

    if (storage_by_id(disk->device, stable, sizeof(stable)) == 0) {
        storage_format(disk->id, sizeof(disk->id), "by-id:%s", stable);
        return;
    }
    if (wwid && wwid[0]) {
        storage_copy_id_component(stable, sizeof(stable), wwid);
        storage_format(disk->id, sizeof(disk->id), "wwid:%s", stable);
        return;
    }
    if (disk->serial[0]) {
        storage_copy_id_component(stable, sizeof(stable), disk->serial);
        storage_format(disk->id, sizeof(disk->id), "serial:%s", stable);
        return;
    }
    snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s", disk->name);
    if (realpath(path, resolved)) {
        block_component = strstr(resolved, "/block/");
        if (block_component)
            *block_component = '\0';
        storage_copy_id_component(stable, sizeof(stable), resolved);
    }
    if (stable[0])
        storage_format(disk->id, sizeof(disk->id), "sysfs:%s", stable);
    else
        snprintf(disk->id, sizeof(disk->id), "dev:%u:%u", disk->major, disk->minor);
}

static int storage_add_partitions(struct storage_disk *disk)
{
    DIR *dir;
    struct dirent *entry;
    char disk_path[PATH_MAX];

    snprintf(disk_path, sizeof(disk_path), STORAGE_SYS_BLOCK "/%s", disk->name);
    dir = opendir(disk_path);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL &&
           disk->partition_count < STORAGE_MAX_PARTITIONS) {
        struct storage_partition *part;
        char path[PATH_MAX];
        uint64_t sectors = 0;

        if (entry->d_name[0] == '.')
            continue;
        if (storage_format(path, sizeof(path), "%s/%s/partition",
                           disk_path, entry->d_name) != 0)
            continue;
        if (access(path, R_OK) != 0)
            continue;
        part = &disk->partitions[disk->partition_count];
        memset(part, 0, sizeof(*part));
        if (storage_format(part->name, sizeof(part->name), "%s", entry->d_name) != 0 ||
            storage_format(part->device, sizeof(part->device), "/dev/%s",
                           entry->d_name) != 0 ||
            storage_format(path, sizeof(path), "%s/%s/dev",
                           disk_path, entry->d_name) != 0)
            continue;
        if (storage_read_dev(path, &part->major, &part->minor) != 0)
            continue;
        if (storage_format(path, sizeof(path), "%s/%s/size",
                           disk_path, entry->d_name) != 0)
            continue;
        if (storage_read_u64(path, &sectors) == 0 && sectors <= UINT64_MAX / 512)
            part->capacity_bytes = sectors * 512;
        disk->partition_count++;
    }
    closedir(dir);
    return 0;
}

static int storage_discover_disks(struct storage_disk *disks, int max_disks)
{
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    dir = opendir(STORAGE_SYS_BLOCK);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL && count < max_disks) {
        struct storage_disk *disk;
        char path[PATH_MAX], wwid[256] = {0};
        uint64_t sectors = 0;

        if (storage_is_excluded_name(entry->d_name) ||
            storage_is_optical(entry->d_name) ||
            storage_is_virtual_block(entry->d_name))
            continue;
        snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s/size", entry->d_name);
        if (storage_read_u64(path, &sectors) != 0 || sectors == 0 ||
            sectors > UINT64_MAX / 512)
            continue;

        disk = &disks[count];
        memset(disk, 0, sizeof(*disk));
        if (storage_format(disk->name, sizeof(disk->name), "%s", entry->d_name) != 0 ||
            storage_format(disk->device, sizeof(disk->device), "/dev/%s",
                           entry->d_name) != 0)
            continue;
        disk->capacity_bytes = sectors * 512;
        snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s/dev", entry->d_name);
        if (storage_read_dev(path, &disk->major, &disk->minor) != 0)
            continue;
        snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s/device/model", entry->d_name);
        storage_read_text(path, disk->model, sizeof(disk->model));
        snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s/device/serial", entry->d_name);
        storage_read_text(path, disk->serial, sizeof(disk->serial));
        snprintf(path, sizeof(path), STORAGE_SYS_BLOCK "/%s/device/wwid", entry->d_name);
        storage_read_text(path, wwid, sizeof(wwid));
        storage_stable_id(disk, wwid);
        storage_transport(entry->d_name, disk->transport, sizeof(disk->transport));
        storage_add_partitions(disk);
        count++;
    }
    closedir(dir);
    return count;
}

static void storage_decode_mount_path(char *value)
{
    char *src = value, *dst = value;

    while (*src) {
        if (src[0] == '\\' && isdigit((unsigned char)src[1]) &&
            isdigit((unsigned char)src[2]) && isdigit((unsigned char)src[3])) {
            *dst++ = (char)((src[1] - '0') * 64 + (src[2] - '0') * 8 + (src[3] - '0'));
            src += 4;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static int storage_read_mounts(struct storage_mount *mounts, int max_mounts)
{
    FILE *fp;
    char *line = NULL;
    size_t line_len = 0;
    int count = 0;

    fp = fopen("/proc/self/mountinfo", "r");
    if (!fp)
        return -1;
    while (count < max_mounts && getline(&line, &line_len, fp) >= 0) {
        char dev[64], root[PATH_MAX], mount_path[PATH_MAX];
        struct storage_mount *mount;
        struct statvfs fs;
        unsigned int major_num, minor_num;
        int duplicate = 0, i;

        if (sscanf(line, "%*u %*u %63s %4095s %4095s", dev, root, mount_path) != 3 ||
            sscanf(dev, "%u:%u", &major_num, &minor_num) != 2)
            continue;
        (void)root;
        for (i = 0; i < count; i++)
            if (mounts[i].major == major_num && mounts[i].minor == minor_num)
                duplicate = 1;
        if (duplicate)
            continue;
        storage_decode_mount_path(mount_path);
        mount = &mounts[count++];
        memset(mount, 0, sizeof(*mount));
        mount->major = major_num;
        mount->minor = minor_num;
        snprintf(mount->path, sizeof(mount->path), "%s", mount_path);
        if (statvfs(mount_path, &fs) == 0) {
            uint64_t block_size = fs.f_frsize ? fs.f_frsize : fs.f_bsize;
            mount->total_bytes = block_size * (uint64_t)fs.f_blocks;
            mount->available_bytes = block_size * (uint64_t)fs.f_bavail;
            mount->used_bytes = block_size *
                (uint64_t)(fs.f_blocks >= fs.f_bfree ? fs.f_blocks - fs.f_bfree : 0);
            mount->stat_ok = 1;
        }
    }
    free(line);
    fclose(fp);
    return count;
}

static int storage_disk_owns_dev(const struct storage_disk *disk,
                                 unsigned int major_num, unsigned int minor_num,
                                 const char **partition_name)
{
    int i;

    if (disk->major == major_num && disk->minor == minor_num) {
        if (partition_name)
            *partition_name = disk->name;
        return 1;
    }
    for (i = 0; i < disk->partition_count; i++) {
        if (disk->partitions[i].major == major_num && disk->partitions[i].minor == minor_num) {
            if (partition_name)
                *partition_name = disk->partitions[i].name;
            return 1;
        }
    }
    return 0;
}

static void storage_apply_mount_usage(struct storage_disk *disks, int disk_count,
                                      const struct storage_mount *mounts, int mount_count)
{
    int d, m;

    for (d = 0; d < disk_count; d++) {
        for (m = 0; m < mount_count; m++) {
            if (!mounts[m].stat_ok ||
                !storage_disk_owns_dev(&disks[d], mounts[m].major, mounts[m].minor, NULL))
                continue;
            disks[d].filesystem_bytes += mounts[m].total_bytes;
            disks[d].used_bytes += mounts[m].used_bytes;
            disks[d].available_bytes += mounts[m].available_bytes;
            disks[d].usage_valid = 1;
        }
        if (disks[d].usage_valid && disks[d].filesystem_bytes)
            disks[d].used_percent = 100.0 * (double)disks[d].used_bytes /
                                     (double)disks[d].filesystem_bytes;
    }
}

static int storage_read_diskstats(struct storage_disk *disks, int disk_count,
                                  struct storage_io_counter *counters)
{
    FILE *fp;
    char line[1024];
    int found = 0;

    memset(counters, 0, sizeof(*counters) * (size_t)disk_count);
    fp = fopen(STORAGE_DISKSTATS, "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        unsigned int major_num, minor_num;
        char name[64];
        unsigned long long reads, reads_merged, sectors_read, read_ms;
        unsigned long long writes, writes_merged, sectors_written, write_ms;
        int i;

        if (sscanf(line, "%u %u %63s %llu %llu %llu %llu %llu %llu %llu %llu",
                   &major_num, &minor_num, name, &reads, &reads_merged,
                   &sectors_read, &read_ms, &writes, &writes_merged,
                   &sectors_written, &write_ms) != 11)
            continue;
        (void)reads_merged;
        (void)writes_merged;
        for (i = 0; i < disk_count; i++) {
            if (disks[i].major != major_num || disks[i].minor != minor_num ||
                strcmp(disks[i].name, name))
                continue;
            counters[i].reads_completed = reads;
            counters[i].sectors_read = sectors_read;
            counters[i].read_ms = read_ms;
            counters[i].writes_completed = writes;
            counters[i].sectors_written = sectors_written;
            counters[i].write_ms = write_ms;
            counters[i].found = 1;
            found++;
            break;
        }
    }
    fclose(fp);
    return found;
}

static void storage_measure_io(struct storage_disk *disks, int disk_count)
{
    struct storage_io_counter *current;
    int64_t now_ms;
    int i;

    current = calloc((size_t)disk_count, sizeof(*current));
    if (!current)
        return;
    now_ms = storage_now_ms();
    if (storage_read_diskstats(disks, disk_count, current) < 0 || now_ms <= 0) {
        for (i = 0; i < disk_count; i++)
            snprintf(disks[i].io_reason, sizeof(disks[i].io_reason),
                     "diskstats_unavailable");
        free(current);
        return;
    }
    for (i = 0; i < disk_count; i++) {
        struct storage_io_cache_entry *entry = NULL, *free_entry = NULL;
        uint64_t read_sectors, write_sectors, reads, writes, read_ms, write_ms;
        double elapsed;
        int c;

        snprintf(disks[i].io_reason, sizeof(disks[i].io_reason),
                 current[i].found ? "first_sample" : "diskstats_unavailable");
        if (!current[i].found)
            continue;
        for (c = 0; c < STORAGE_MAX_DISKS; c++) {
            if (g_storage_io_cache[c].used &&
                !strcmp(g_storage_io_cache[c].disk_id, disks[i].id)) {
                entry = &g_storage_io_cache[c];
                break;
            }
            if (!g_storage_io_cache[c].used && !free_entry)
                free_entry = &g_storage_io_cache[c];
        }
        if (!entry) {
            entry = free_entry ? free_entry :
                &g_storage_io_cache[i % STORAGE_MAX_DISKS];
            memset(entry, 0, sizeof(*entry));
            entry->used = 1;
            snprintf(entry->disk_id, sizeof(entry->disk_id), "%s", disks[i].id);
            entry->counter = current[i];
            entry->sampled_ms = now_ms;
            continue;
        }
        if (now_ms <= entry->sampled_ms ||
            current[i].sectors_read < entry->counter.sectors_read ||
            current[i].sectors_written < entry->counter.sectors_written ||
            current[i].reads_completed < entry->counter.reads_completed ||
            current[i].writes_completed < entry->counter.writes_completed ||
            current[i].read_ms < entry->counter.read_ms ||
            current[i].write_ms < entry->counter.write_ms) {
            snprintf(disks[i].io_reason, sizeof(disks[i].io_reason), "counter_reset");
            entry->counter = current[i];
            entry->sampled_ms = now_ms;
            continue;
        }
        elapsed = (double)(now_ms - entry->sampled_ms) / 1000.0;
        read_sectors = current[i].sectors_read - entry->counter.sectors_read;
        write_sectors = current[i].sectors_written - entry->counter.sectors_written;
        reads = current[i].reads_completed - entry->counter.reads_completed;
        writes = current[i].writes_completed - entry->counter.writes_completed;
        read_ms = current[i].read_ms - entry->counter.read_ms;
        write_ms = current[i].write_ms - entry->counter.write_ms;
        disks[i].read_bps = (double)read_sectors * 512.0 / elapsed;
        disks[i].write_bps = (double)write_sectors * 512.0 / elapsed;
        disks[i].io_valid = 1;
        disks[i].io_interval_seconds = elapsed;
        snprintf(disks[i].io_reason, sizeof(disks[i].io_reason),
                 "sampled_counter_delta");
        if (reads) {
            disks[i].read_latency_ms = (double)read_ms / (double)reads;
            disks[i].read_latency_valid = 1;
        }
        if (writes) {
            disks[i].write_latency_ms = (double)write_ms / (double)writes;
            disks[i].write_latency_valid = 1;
        }
        entry->counter = current[i];
        entry->sampled_ms = now_ms;
    }
    free(current);
}

static void storage_exec_result_free(struct storage_exec_result *result)
{
    if (!result)
        return;
    free(result->output);
    memset(result, 0, sizeof(*result));
}

static int storage_exec_capture(char *const argv[], int timeout_ms, size_t output_max,
                                struct storage_exec_result *result)
{
    int pipefd[2] = { -1, -1 };
    pid_t pid;
    int64_t deadline;
    int status = 0, child_done = 0, term_sent = 0;

    if (!argv || !argv[0] || !result || timeout_ms < 1 || output_max < 1)
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
    deadline = storage_now_ms() + timeout_ms;
    while (!child_done || pipefd[0] >= 0) {
        struct pollfd pfd;
        int64_t now = storage_now_ms();
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
        now = storage_now_ms();
        if (child_done && pipefd[0] >= 0 && now >= deadline) {
            close(pipefd[0]);
            pipefd[0] = -1;
            result->truncated = 1;
        }
        if (!child_done && now >= deadline && !term_sent) {
            kill(pid, SIGTERM);
            result->timed_out = 1;
            term_sent = 1;
            deadline = now + STORAGE_EXEC_KILL_GRACE_MS;
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
    storage_exec_result_free(result);
    return -1;
}

static struct json_object *storage_json_path(struct json_object *root,
                                             const char *first, const char *second)
{
    struct json_object *value = NULL;

    if (!root || !json_object_object_get_ex(root, first, &value) || !value)
        return NULL;
    if (!second)
        return value;
    root = value;
    return json_object_object_get_ex(root, second, &value) ? value : NULL;
}

static int storage_json_int64(struct json_object *root, const char *first,
                              const char *second, int64_t *out)
{
    struct json_object *value = storage_json_path(root, first, second);

    if (!value || (!json_object_is_type(value, json_type_int) &&
                   !json_object_is_type(value, json_type_double)))
        return -1;
    *out = json_object_get_int64(value);
    return 0;
}

static void storage_smart_ata_attributes(struct json_object *root,
                                         struct storage_smart *smart)
{
    struct json_object *table = storage_json_path(root, "ata_smart_attributes", "table");
    size_t i;

    if (!table || !json_object_is_type(table, json_type_array))
        return;
    for (i = 0; i < json_object_array_length(table); i++) {
        struct json_object *item = json_object_array_get_idx(table, i);
        struct json_object *name_obj = NULL, *raw = NULL, *raw_value = NULL;
        const char *name;
        int64_t value;

        if (!item || !json_object_object_get_ex(item, "name", &name_obj))
            continue;
        name = json_object_get_string(name_obj);
        if (!name || !json_object_object_get_ex(item, "raw", &raw) || !raw ||
            !json_object_object_get_ex(raw, "value", &raw_value) || !raw_value)
            continue;
        value = json_object_get_int64(raw_value);
        if (!strcasecmp(name, "Power_On_Hours")) {
            smart->power_on_hours = value;
            smart->power_on_hours_valid = 1;
        } else if (!strcasecmp(name, "Reallocated_Sector_Ct") ||
                   !strcasecmp(name, "Reallocated_Event_Count")) {
            if (!smart->reallocated_valid || value > smart->reallocated_sector_count)
                smart->reallocated_sector_count = value;
            smart->reallocated_valid = 1;
        }
    }
}

static void storage_parse_smart(struct storage_disk *disk, const char *output,
                                int exit_code, int timed_out, int truncated)
{
    struct storage_smart *smart = &disk->smart;
    struct json_object *root = NULL, *value = NULL;
    int64_t number;

    memset(smart, 0, sizeof(*smart));
    smart->exit_code = exit_code;
    if (timed_out) {
        snprintf(smart->status, sizeof(smart->status), "TIMEOUT");
        snprintf(smart->reason, sizeof(smart->reason), "smartctl_timeout");
        return;
    }
    if (!output || !output[0]) {
        snprintf(smart->status, sizeof(smart->status), "UNAVAILABLE");
        snprintf(smart->reason, sizeof(smart->reason),
                 exit_code == 127 ? "smartctl_not_installed" : "smartctl_no_output");
        return;
    }
    root = json_tokener_parse(output);
    if (!root || !json_object_is_type(root, json_type_object)) {
        snprintf(smart->status, sizeof(smart->status), "UNAVAILABLE");
        snprintf(smart->reason, sizeof(smart->reason), "smartctl_json_invalid");
        if (root)
            json_object_put(root);
        return;
    }
    if (truncated) {
        snprintf(smart->status, sizeof(smart->status), "UNAVAILABLE");
        snprintf(smart->reason, sizeof(smart->reason), "smartctl_output_truncated");
        json_object_put(root);
        return;
    }
    value = storage_json_path(root, "smart_status", "passed");
    if (value && json_object_is_type(value, json_type_boolean)) {
        snprintf(smart->status, sizeof(smart->status), "%s",
                 json_object_get_boolean(value) ? "PASSED" : "FAILED");
        snprintf(smart->reason, sizeof(smart->reason), "smartctl_json");
    } else {
        value = storage_json_path(root, "smart_support", "available");
        snprintf(smart->status, sizeof(smart->status), "UNSUPPORTED");
        snprintf(smart->reason, sizeof(smart->reason), "%s",
                 value && !json_object_get_boolean(value) ?
                 "smart_not_supported" : "smart_health_unavailable");
    }
    if (storage_json_int64(root, "temperature", "current", &number) == 0 ||
        storage_json_int64(root, "nvme_smart_health_information_log", "temperature", &number) == 0) {
        smart->temperature_c = (int)number;
        smart->temperature_valid = 1;
    }
    if (storage_json_int64(root, "power_on_time", "hours", &number) == 0) {
        smart->power_on_hours = number;
        smart->power_on_hours_valid = 1;
    }
    if (storage_json_int64(root, "nvme_smart_health_information_log", "power_on_hours", &number) == 0) {
        smart->power_on_hours = number;
        smart->power_on_hours_valid = 1;
    }
    storage_smart_ata_attributes(root, smart);
    json_object_put(root);
}

static const char *storage_smartctl_path(void)
{
    static const char *paths[] = {
        "/usr/sbin/smartctl", "/usr/bin/smartctl", "/sbin/smartctl", NULL
    };
    int i;

    for (i = 0; paths[i]; i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return NULL;
}

static struct storage_smart_cache_entry *storage_smart_cache_find(const char *disk_id,
                                                                  int64_t now_ms)
{
    int i;

    for (i = 0; i < STORAGE_MAX_DISKS; i++) {
        if (!g_storage_smart_cache[i].used ||
            strcmp(g_storage_smart_cache[i].disk_id, disk_id))
            continue;
        if (now_ms >= g_storage_smart_cache[i].cached_ms &&
            now_ms - g_storage_smart_cache[i].cached_ms < STORAGE_SMART_CACHE_MS)
            return &g_storage_smart_cache[i];
    }
    return NULL;
}

static void storage_smart_cache_store(const struct storage_disk *disk, int64_t now_ms)
{
    struct storage_smart_cache_entry *entry = NULL;
    int i;

    for (i = 0; i < STORAGE_MAX_DISKS; i++) {
        if (g_storage_smart_cache[i].used &&
            !strcmp(g_storage_smart_cache[i].disk_id, disk->id)) {
            entry = &g_storage_smart_cache[i];
            break;
        }
        if (!g_storage_smart_cache[i].used && !entry)
            entry = &g_storage_smart_cache[i];
    }
    if (!entry)
        entry = &g_storage_smart_cache[0];
    memset(entry, 0, sizeof(*entry));
    entry->used = 1;
    snprintf(entry->disk_id, sizeof(entry->disk_id), "%s", disk->id);
    entry->smart = disk->smart;
    entry->smart.cached = 0;
    entry->cached_ms = now_ms;
}

static void storage_smart_budget_exhausted(struct storage_disk *disk)
{
    memset(&disk->smart, 0, sizeof(disk->smart));
    snprintf(disk->smart.status, sizeof(disk->smart.status), "UNAVAILABLE");
    snprintf(disk->smart.reason, sizeof(disk->smart.reason),
             "probe_budget_exhausted");
    disk->smart.exit_code = -1;
}

static void storage_collect_smart(struct storage_disk *disk, int64_t deadline_ms)
{
    const char *smartctl = storage_smartctl_path();
    struct storage_smart_cache_entry *cached;
    struct storage_exec_result result;
    char *argv[5];
    int64_t now_ms = storage_now_ms();
    int timeout_ms;

    cached = storage_smart_cache_find(disk->id, now_ms);
    if (cached) {
        disk->smart = cached->smart;
        disk->smart.cached = 1;
        return;
    }

    if (!smartctl) {
        memset(&disk->smart, 0, sizeof(disk->smart));
        snprintf(disk->smart.status, sizeof(disk->smart.status), "UNAVAILABLE");
        snprintf(disk->smart.reason, sizeof(disk->smart.reason), "smartctl_not_installed");
        disk->smart.exit_code = 127;
        disk->smart.sampled_at = (int64_t)time(NULL);
        storage_smart_cache_store(disk, now_ms);
        return;
    }
    if (now_ms <= 0 || deadline_ms - now_ms <= STORAGE_REQUEST_GUARD_MS) {
        storage_smart_budget_exhausted(disk);
        return;
    }
    timeout_ms = (int)(deadline_ms - now_ms - STORAGE_REQUEST_GUARD_MS);
    if (timeout_ms > STORAGE_SMART_TIMEOUT_MS)
        timeout_ms = STORAGE_SMART_TIMEOUT_MS;
    if (timeout_ms < 1) {
        storage_smart_budget_exhausted(disk);
        return;
    }
    argv[0] = (char *)smartctl;
    argv[1] = (char *)"-j";
    argv[2] = (char *)"-a";
    argv[3] = disk->device;
    argv[4] = NULL;
    if (storage_exec_capture(argv, timeout_ms,
                             STORAGE_SMART_OUTPUT_MAX, &result) != 0) {
        memset(&disk->smart, 0, sizeof(disk->smart));
        snprintf(disk->smart.status, sizeof(disk->smart.status), "UNAVAILABLE");
        snprintf(disk->smart.reason, sizeof(disk->smart.reason), "smartctl_exec_failed");
        disk->smart.exit_code = -1;
        disk->smart.sampled_at = (int64_t)time(NULL);
        storage_smart_cache_store(disk, storage_now_ms());
        return;
    }
    storage_parse_smart(disk, result.output, result.exit_code,
                        result.timed_out, result.truncated);
    storage_exec_result_free(&result);
    disk->smart.sampled_at = (int64_t)time(NULL);
    storage_smart_cache_store(disk, storage_now_ms());
}

static int storage_db_write_sample(const struct storage_disk *disk, int64_t ts)
{
    sqlite3 *db = jmx_db_handle();
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!db || sqlite3_prepare_v2(db,
        "INSERT INTO storage_disk_sample("
        "ts,disk_id,device,used_percent,read_bps,write_bps,read_latency_ms,write_latency_ms) "
        "VALUES(?1,?2,?3,?4,?5,?6,?7,?8) "
        "ON CONFLICT(ts,disk_id) DO UPDATE SET device=excluded.device,"
        "used_percent=excluded.used_percent,read_bps=excluded.read_bps,"
        "write_bps=excluded.write_bps,read_latency_ms=excluded.read_latency_ms,"
        "write_latency_ms=excluded.write_latency_ms",
        -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, ts);
    sqlite3_bind_text(st, 2, disk->id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, disk->device, -1, SQLITE_TRANSIENT);
    if (disk->usage_valid)
        sqlite3_bind_double(st, 4, disk->used_percent);
    else
        sqlite3_bind_null(st, 4);
    if (disk->io_valid) {
        sqlite3_bind_double(st, 5, disk->read_bps);
        sqlite3_bind_double(st, 6, disk->write_bps);
    } else {
        sqlite3_bind_null(st, 5);
        sqlite3_bind_null(st, 6);
    }
    if (disk->read_latency_valid)
        sqlite3_bind_double(st, 7, disk->read_latency_ms);
    else
        sqlite3_bind_null(st, 7);
    if (disk->write_latency_valid)
        sqlite3_bind_double(st, 8, disk->write_latency_ms);
    else
        sqlite3_bind_null(st, 8);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static int storage_prune_samples(sqlite3 *db, int64_t cutoff)
{
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!db || sqlite3_prepare_v2(db,
            "DELETE FROM storage_disk_sample WHERE ts < ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, cutoff);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
    sqlite3_finalize(st);
    return rc;
}

static int storage_persist_samples(const struct storage_disk *disks, int disk_count,
                                   int64_t ts, int64_t deadline_ms)
{
    sqlite3 *db;
    int i, rc = 0;
    static int64_t last_prune_at;

    if (storage_now_ms() + 50 >= deadline_ms)
        return -1;
    db = jmx_db_handle();
    if (!db || storage_now_ms() + 50 >= deadline_ms)
        return -1;
    sqlite3_busy_timeout(db, 50);
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_busy_timeout(db, 5000);
        return -1;
    }
    for (i = 0; i < disk_count; i++)
        if (storage_db_write_sample(&disks[i], ts) != 0)
            rc = -1;
    if (rc == 0 && sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK)
        rc = -1;
    if (rc != 0)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (rc == 0 && (last_prune_at == 0 || ts - last_prune_at >= 3600)) {
        storage_prune_samples(db, ts - STORAGE_HISTORY_RETENTION_SEC);
        last_prune_at = ts;
    }
    sqlite3_busy_timeout(db, 5000);
    return rc;
}

static struct json_object *storage_nullable_double(int valid, double value)
{
    return valid ? json_object_new_double(value) : json_object_new_null();
}

static struct json_object *storage_partition_json(const struct storage_disk *disk,
                                                  const struct storage_partition *part,
                                                  const struct storage_mount *mounts,
                                                  int mount_count)
{
    struct json_object *object = json_object_new_object();
    struct json_object *mount_array = json_object_new_array();
    int i;

    json_object_object_add(object, "id", json_object_new_string(part->name));
    json_object_object_add(object, "device", json_object_new_string(part->device));
    json_object_object_add(object, "capacity_bytes", json_object_new_int64((int64_t)part->capacity_bytes));
    for (i = 0; i < mount_count; i++) {
        if (mounts[i].major == part->major && mounts[i].minor == part->minor) {
            struct json_object *mount = json_object_new_object();
            json_object_object_add(mount, "path", json_object_new_string(mounts[i].path));
            json_object_object_add(mount, "total_bytes", json_object_new_int64((int64_t)mounts[i].total_bytes));
            json_object_object_add(mount, "used_bytes", json_object_new_int64((int64_t)mounts[i].used_bytes));
            json_object_object_add(mount, "available_bytes", json_object_new_int64((int64_t)mounts[i].available_bytes));
            json_object_array_add(mount_array, mount);
        }
    }
    (void)disk;
    json_object_object_add(object, "mounts", mount_array);
    return object;
}

static struct json_object *storage_smart_json(const struct storage_disk *disk)
{
    struct json_object *object = json_object_new_object();

    json_object_object_add(object, "disk_id", json_object_new_string(disk->id));
    json_object_object_add(object, "device", json_object_new_string(disk->device));
    json_object_object_add(object, "model", json_object_new_string(disk->model));
    json_object_object_add(object, "serial", json_object_new_string(disk->serial));
    json_object_object_add(object, "transport", json_object_new_string(disk->transport));
    json_object_object_add(object, "smart_status", json_object_new_string(disk->smart.status));
    json_object_object_add(object, "reason", json_object_new_string(disk->smart.reason));
    json_object_object_add(object, "cached", json_object_new_boolean(disk->smart.cached));
    json_object_object_add(object, "sampled_at",
                           disk->smart.sampled_at > 0 ?
                           json_object_new_int64(disk->smart.sampled_at) : json_object_new_null());
    json_object_object_add(object, "temperature_c",
                           disk->smart.temperature_valid ?
                           json_object_new_int(disk->smart.temperature_c) : json_object_new_null());
    json_object_object_add(object, "power_on_hours",
                           disk->smart.power_on_hours_valid ?
                           json_object_new_int64(disk->smart.power_on_hours) : json_object_new_null());
    json_object_object_add(object, "reallocated_sector_count",
                           disk->smart.reallocated_valid ?
                           json_object_new_int64(disk->smart.reallocated_sector_count) : json_object_new_null());
    return object;
}

static struct json_object *storage_disk_json(const struct storage_disk *disk,
                                             const struct storage_mount *mounts,
                                             int mount_count)
{
    struct json_object *object = json_object_new_object();
    struct json_object *partitions = json_object_new_array();
    struct json_object *mount_array = json_object_new_array();
    int i;

    json_object_object_add(object, "id", json_object_new_string(disk->id));
    json_object_object_add(object, "name", json_object_new_string(disk->name));
    json_object_object_add(object, "device", json_object_new_string(disk->device));
    json_object_object_add(object, "label", json_object_new_string(disk->model[0] ? disk->model : disk->name));
    json_object_object_add(object, "model", json_object_new_string(disk->model));
    json_object_object_add(object, "serial", json_object_new_string(disk->serial));
    json_object_object_add(object, "transport", json_object_new_string(disk->transport));
    json_object_object_add(object, "type", json_object_new_string("physical"));
    json_object_object_add(object, "total_bytes", json_object_new_int64((int64_t)disk->capacity_bytes));
    json_object_object_add(object, "filesystem_bytes", json_object_new_int64((int64_t)disk->filesystem_bytes));
    json_object_object_add(object, "used_bytes", json_object_new_int64((int64_t)disk->used_bytes));
    json_object_object_add(object, "available_bytes", json_object_new_int64((int64_t)disk->available_bytes));
    json_object_object_add(object, "used_percent", storage_nullable_double(disk->usage_valid, disk->used_percent));
    json_object_object_add(object, "read_bps", storage_nullable_double(disk->io_valid, disk->read_bps));
    json_object_object_add(object, "write_bps", storage_nullable_double(disk->io_valid, disk->write_bps));
    json_object_object_add(object, "io_state",
                           json_object_new_string(disk->io_valid ? "sampled" : "unavailable"));
    json_object_object_add(object, "io_reason", json_object_new_string(disk->io_reason));
    json_object_object_add(object, "io_interval_seconds",
                           storage_nullable_double(disk->io_valid,
                                                   disk->io_interval_seconds));
    json_object_object_add(object, "read_latency_ms", storage_nullable_double(disk->read_latency_valid, disk->read_latency_ms));
    json_object_object_add(object, "write_latency_ms", storage_nullable_double(disk->write_latency_valid, disk->write_latency_ms));
    json_object_object_add(object, "smart_status", json_object_new_string(disk->smart.status));
    json_object_object_add(object, "temperature_c",
                           disk->smart.temperature_valid ? json_object_new_int(disk->smart.temperature_c) : json_object_new_null());
    for (i = 0; i < disk->partition_count; i++)
        json_object_array_add(partitions,
            storage_partition_json(disk, &disk->partitions[i], mounts, mount_count));
    for (i = 0; i < mount_count; i++) {
        const char *partition_name = NULL;
        if (storage_disk_owns_dev(disk, mounts[i].major, mounts[i].minor, &partition_name)) {
            struct json_object *mount = json_object_new_object();
            json_object_object_add(mount, "partition", json_object_new_string(partition_name));
            json_object_object_add(mount, "path", json_object_new_string(mounts[i].path));
            json_object_object_add(mount, "total_bytes", json_object_new_int64((int64_t)mounts[i].total_bytes));
            json_object_object_add(mount, "used_bytes", json_object_new_int64((int64_t)mounts[i].used_bytes));
            json_object_object_add(mount, "available_bytes", json_object_new_int64((int64_t)mounts[i].available_bytes));
            json_object_array_add(mount_array, mount);
        }
    }
    json_object_object_add(object, "partitions", partitions);
    json_object_object_add(object, "mounts", mount_array);
    return object;
}

static void storage_range(const char *requested, const char **range_out,
                          int64_t *seconds_out, int *bucket_out)
{
    if (requested && !strcmp(requested, "1d")) {
        *range_out = "1d";
        *seconds_out = 86400;
        *bucket_out = 300;
    } else if (requested && !strcmp(requested, "7d")) {
        *range_out = "7d";
        *seconds_out = 7 * 86400;
        *bucket_out = 1800;
    } else {
        *range_out = "1h";
        *seconds_out = 3600;
        *bucket_out = 10;
    }
}

static struct json_object *storage_history_json(const char *range, int64_t now,
                                                int64_t deadline_ms)
{
    sqlite3 *db;
    sqlite3_stmt *st = NULL;
    struct json_object *array = json_object_new_array();
    const char *normalized;
    int64_t seconds;
    int bucket;

    storage_range(range, &normalized, &seconds, &bucket);
    (void)normalized;
    if (storage_now_ms() + 50 >= deadline_ms)
        return array;
    db = jmx_db_handle();
    if (!db || storage_now_ms() + 50 >= deadline_ms)
        return array;
    sqlite3_busy_timeout(db, 50);
    if (sqlite3_prepare_v2(db,
        "SELECT (ts/?1)*?1 AS bucket_ts,disk_id,"
        "AVG(used_percent),AVG(read_bps),AVG(write_bps),"
        "AVG(read_latency_ms),AVG(write_latency_ms),COUNT(*) "
        "FROM storage_disk_sample WHERE ts>=?2 AND ts<=?3 "
        "GROUP BY bucket_ts,disk_id ORDER BY bucket_ts ASC,disk_id ASC",
        -1, &st, NULL) != SQLITE_OK) {
        sqlite3_busy_timeout(db, 5000);
        return array;
    }
    sqlite3_bind_int(st, 1, bucket);
    sqlite3_bind_int64(st, 2, now - seconds);
    sqlite3_bind_int64(st, 3, now);
    while (sqlite3_step(st) == SQLITE_ROW) {
        struct json_object *point = json_object_new_object();
        const char *disk_id = (const char *)sqlite3_column_text(st, 1);

        json_object_object_add(point, "ts", json_object_new_int64(sqlite3_column_int64(st, 0)));
        json_object_object_add(point, "disk_id", json_object_new_string(disk_id ? disk_id : ""));
        json_object_object_add(point, "used_percent",
            sqlite3_column_type(st, 2) == SQLITE_NULL ? json_object_new_null() : json_object_new_double(sqlite3_column_double(st, 2)));
        json_object_object_add(point, "read_bps",
            sqlite3_column_type(st, 3) == SQLITE_NULL ? json_object_new_null() : json_object_new_double(sqlite3_column_double(st, 3)));
        json_object_object_add(point, "write_bps",
            sqlite3_column_type(st, 4) == SQLITE_NULL ? json_object_new_null() : json_object_new_double(sqlite3_column_double(st, 4)));
        json_object_object_add(point, "read_latency_ms",
            sqlite3_column_type(st, 5) == SQLITE_NULL ? json_object_new_null() : json_object_new_double(sqlite3_column_double(st, 5)));
        json_object_object_add(point, "write_latency_ms",
            sqlite3_column_type(st, 6) == SQLITE_NULL ? json_object_new_null() : json_object_new_double(sqlite3_column_double(st, 6)));
        json_object_object_add(point, "sample_count", json_object_new_int(sqlite3_column_int(st, 7)));
        json_object_array_add(array, point);
    }
    sqlite3_finalize(st);
    sqlite3_busy_timeout(db, 5000);
    return array;
}

struct json_object *jmx_storage_overview_get(const char *range)
{
    struct storage_disk *disks;
    struct storage_mount *mounts;
    struct json_object *data, *summary, *disk_array, *smart_array, *caps;
    const char *requested_range = range && range[0] ? range : "1h", *normalized_range;
    int64_t range_seconds, now = (int64_t)time(NULL);
    int64_t request_deadline_ms = storage_now_ms() + STORAGE_REQUEST_BUDGET_MS;
    uint64_t total = 0, used = 0, available = 0;
    int disk_count, mount_count, bucket, i, persist_ok;

    storage_range(requested_range, &normalized_range, &range_seconds, &bucket);
    (void)range_seconds;
    (void)bucket;
    disks = calloc(STORAGE_MAX_DISKS, sizeof(*disks));
    mounts = calloc(STORAGE_MAX_MOUNTS, sizeof(*mounts));
    if (!disks || !mounts) {
        free(disks);
        free(mounts);
        data = json_object_new_object();
        json_object_object_add(data, "error", json_object_new_string("out_of_memory"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    disk_count = storage_discover_disks(disks, STORAGE_MAX_DISKS);
    if (disk_count < 0) {
        free(disks);
        free(mounts);
        data = json_object_new_object();
        json_object_object_add(data, "error", json_object_new_string("sys_block_unavailable"));
        return jmx_gen_api_response_data(API_CODE_ERROR, data);
    }
    mount_count = storage_read_mounts(mounts, STORAGE_MAX_MOUNTS);
    if (mount_count > 0)
        storage_apply_mount_usage(disks, disk_count, mounts, mount_count);
    storage_measure_io(disks, disk_count);
    for (i = 0; i < disk_count; i++)
        storage_collect_smart(&disks[i], request_deadline_ms);
    persist_ok = storage_persist_samples(disks, disk_count, now,
                                         request_deadline_ms) == 0;

    data = json_object_new_object();
    summary = json_object_new_object();
    disk_array = json_object_new_array();
    smart_array = json_object_new_array();
    caps = json_object_new_object();
    for (i = 0; i < disk_count; i++) {
        total += disks[i].capacity_bytes;
        used += disks[i].used_bytes;
        available += disks[i].available_bytes;
        json_object_array_add(disk_array, storage_disk_json(&disks[i], mounts, mount_count));
        json_object_array_add(smart_array, storage_smart_json(&disks[i]));
    }
    json_object_object_add(summary, "disk_count", json_object_new_int(disk_count));
    json_object_object_add(summary, "total_bytes", json_object_new_int64((int64_t)total));
    json_object_object_add(summary, "used_bytes", json_object_new_int64((int64_t)used));
    json_object_object_add(summary, "available_bytes", json_object_new_int64((int64_t)available));
    json_object_object_add(data, "contract_version",
                           json_object_new_string("storage-overview.v1"));
    json_object_object_add(data, "range", json_object_new_string(normalized_range));
    json_object_object_add(data, "generated_at", json_object_new_int64(now));
    json_object_object_add(data, "summary", summary);
    json_object_object_add(data, "disks", disk_array);
    json_object_object_add(data, "history",
                           storage_history_json(normalized_range, now,
                                                request_deadline_ms));
    json_object_object_add(data, "smart", smart_array);
    json_object_object_add(caps, "physical_disk_inventory", json_object_new_boolean(1));
    json_object_object_add(caps, "partition_mount_usage", json_object_new_boolean(1));
    json_object_object_add(caps, "diskstats_rate", json_object_new_boolean(1));
    json_object_object_add(caps, "diskstats_latency", json_object_new_boolean(1));
    json_object_object_add(caps, "smart", json_object_new_boolean(storage_smartctl_path() != NULL));
    json_object_object_add(caps, "history", json_object_new_boolean(persist_ok));
    json_object_object_add(data, "capabilities", caps);
    free(disks);
    free(mounts);
    return jmx_gen_api_response_data(API_CODE_SUCCESS, data);
}
