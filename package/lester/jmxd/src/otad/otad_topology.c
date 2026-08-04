// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include "otad_internal.h"
#include <blkid/blkid.h>
#if defined(__linux__)
#include <sys/sysmacros.h>
#endif

#ifndef OTAD_TOPOLOGY_SYS_BLOCK_DIR
#define OTAD_TOPOLOGY_SYS_BLOCK_DIR "/sys/class/block"
#endif
#ifndef OTAD_TOPOLOGY_DEV_DIR
#define OTAD_TOPOLOGY_DEV_DIR "/dev"
#endif
#ifndef OTAD_TOPOLOGY_PARTUUID_DIR
#define OTAD_TOPOLOGY_PARTUUID_DIR "/dev/disk/by-partuuid"
#endif
#ifndef OTAD_TOPOLOGY_CMDLINE_PATH
#define OTAD_TOPOLOGY_CMDLINE_PATH "/proc/cmdline"
#endif
#ifndef OTAD_TOPOLOGY_MOUNTINFO_PATH
#define OTAD_TOPOLOGY_MOUNTINFO_PATH "/proc/self/mountinfo"
#endif
#define OTAD_TOPOLOGY_GRUBENV_MAX 4096U
#define OTAD_TOPOLOGY_GRUBCFG_MAX (1024U * 1024U)
#define OTAD_TOPOLOGY_GRUBENV_SIZE 1024U
#define OTAD_TOPOLOGY_GRUBENV_HEADER "# GRUB Environment Block\n"
#define OTAD_TOPOLOGY_BOOT_MOUNT_OPTIONS \
    "uid=0,gid=0,fmask=0077,dmask=0077"
#ifndef OTAD_TOPOLOGY_MOUNT
#define OTAD_TOPOLOGY_MOUNT mount
#endif
#ifndef OTAD_TOPOLOGY_UMOUNT
#define OTAD_TOPOLOGY_UMOUNT umount2
#endif
#ifndef OTAD_TOPOLOGY_MAJOR
#define OTAD_TOPOLOGY_MAJOR(value) major(value)
#endif
#ifndef OTAD_TOPOLOGY_MINOR
#define OTAD_TOPOLOGY_MINOR(value) minor(value)
#endif

struct topology_partition {
    char path[OTAD_MAX_PATH];
    char name[128];
    char parent[128];
    char partuuid[128];
    char devno[32];
    char fstype[32];
    dev_t rdev;
    uint64_t size;
};

struct topology_mounts {
    char root_devno[32];
    char root_fstype[32];
    char data_devno[32];
    char data_fstype[32];
    unsigned int root_count;
    unsigned int data_count;
    int slot_a_mounted;
    int slot_b_mounted;
    int boot_mounted;
};

struct topology_cmdline {
    char slot[2];
    char root_partuuid[128];
};

static void topology_error(char *error, size_t error_len, const char *value)
{
    if (error && error_len)
        snprintf(error, error_len, "%s", value ? value : "ab_topology_invalid");
}

static int topology_text_file(const char *path, char *out, size_t out_len)
{
    FILE *fp;
    char *end;

    if (!path || !out || out_len < 2)
        return -1;
    out[0] = '\0';
    fp = fopen(path, "r");
    if (!fp || !fgets(out, (int)out_len, fp)) {
        if (fp)
            fclose(fp);
        return -1;
    }
    fclose(fp);
    end = out + strlen(out);
    while (end > out && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' '))
        *--end = '\0';
    return out[0] ? 0 : -1;
}

static int topology_uevent_value(const char *path, const char *key,
                                 char *out, size_t out_len)
{
    FILE *fp;
    char line[512];
    size_t key_len;

    if (!path || !key || !out || out_len < 2)
        return -1;
    key_len = strlen(key);
    fp = fopen(path, "r");
    if (!fp)
        return -1;
    out[0] = '\0';
    while (fgets(line, sizeof(line), fp)) {
        char *end;

        if (strncmp(line, key, key_len) || line[key_len] != '=')
            continue;
        end = line + strlen(line);
        while (end > line && (end[-1] == '\n' || end[-1] == '\r'))
            *--end = '\0';
        if (strlen(line + key_len + 1) >= out_len)
            break;
        snprintf(out, out_len, "%s", line + key_len + 1);
        fclose(fp);
        return out[0] ? 0 : -1;
    }
    fclose(fp);
    return -1;
}

static int topology_devno_bind(const char *major_text, const char *minor_text,
                               dev_t rdev, char *out, size_t out_len)
{
    const char *p;
    char *end = NULL;
    unsigned long major_value;
    unsigned long minor_value;

    if (!major_text || !minor_text || !major_text[0] || !minor_text[0] ||
        !out || out_len == 0)
        return -1;
    for (p = major_text; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return -1;
    }
    for (p = minor_text; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return -1;
    }
    errno = 0;
    major_value = strtoul(major_text, &end, 10);
    if (errno || !end || end == major_text || *end || major_value > UINT_MAX)
        return -1;
    errno = 0;
    minor_value = strtoul(minor_text, &end, 10);
    if (errno || !end || end == minor_text || *end || minor_value > UINT_MAX ||
        major_value != (unsigned long)OTAD_TOPOLOGY_MAJOR(rdev) ||
        minor_value != (unsigned long)OTAD_TOPOLOGY_MINOR(rdev) ||
        snprintf(out, out_len, "%lu:%lu", major_value, minor_value) >=
            (int)out_len)
        return -1;
    return 0;
}

static int topology_partuuid_for_rdev(dev_t rdev, char *out, size_t out_len)
{
    DIR *dir;
    struct dirent *entry;
    int matches = 0;

    if (!out || out_len < 2)
        return -1;
    out[0] = '\0';
    dir = opendir(OTAD_TOPOLOGY_PARTUUID_DIR);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char path[OTAD_MAX_PATH];
        char *resolved;
        struct stat st;

        if (entry->d_name[0] == '.' || strchr(entry->d_name, '/') ||
            snprintf(path, sizeof(path), "%s/%s", OTAD_TOPOLOGY_PARTUUID_DIR,
                     entry->d_name) >= (int)sizeof(path))
            continue;
        resolved = realpath(path, NULL);
        if (!resolved)
            continue;
        if (stat(resolved, &st) == 0 && S_ISBLK(st.st_mode) && st.st_rdev == rdev) {
            if (++matches == 1 && strlen(entry->d_name) < out_len)
                snprintf(out, out_len, "%s", entry->d_name);
        }
        free(resolved);
        if (matches > 1)
            break;
    }
    closedir(dir);
    return matches == 1 && out[0] ? 0 : -1;
}

static int topology_partuuid_probe(const char *path, char *out, size_t out_len)
{
    char *value;

    if (!path || !out || out_len < 2)
        return -1;
    value = blkid_get_tag_value(NULL, "PARTUUID", path);
    if (!value || !value[0] || strlen(value) >= out_len) {
        free(value);
        return -1;
    }
    snprintf(out, out_len, "%s", value);
    free(value);
    return 0;
}

static int topology_fstype_probe(const char *path, char *out, size_t out_len)
{
    char *value;

    if (!path || !out || out_len < 2)
        return -1;
    value = blkid_get_tag_value(NULL, "TYPE", path);
    if (!value || !value[0] || strlen(value) >= out_len) {
        free(value);
        return -1;
    }
    snprintf(out, out_len, "%s", value);
    free(value);
    return 0;
}

static int topology_partuuid_unique(const char *partuuid, dev_t expected_rdev)
{
    DIR *dir;
    struct dirent *entry;
    int matches = 0;
    int expected_matches = 0;

    if (!partuuid || !partuuid[0])
        return -1;
    dir = opendir(OTAD_TOPOLOGY_SYS_BLOCK_DIR);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char partition_path[OTAD_MAX_PATH];
        char uevent_path[OTAD_MAX_PATH];
        char device_path[OTAD_MAX_PATH];
        char candidate[128];
        char devname[128];
        char major_text[16];
        char minor_text[16];
        char devno[32];
        char *resolved;
        struct stat st;

        if (entry->d_name[0] == '.' || strchr(entry->d_name, '/') ||
            snprintf(partition_path, sizeof(partition_path), "%s/%s/partition",
                     OTAD_TOPOLOGY_SYS_BLOCK_DIR, entry->d_name) >=
                (int)sizeof(partition_path) ||
            access(partition_path, R_OK) != 0 ||
            snprintf(uevent_path, sizeof(uevent_path), "%s/%s/uevent",
                     OTAD_TOPOLOGY_SYS_BLOCK_DIR, entry->d_name) >=
                (int)sizeof(uevent_path) ||
            topology_uevent_value(uevent_path, "DEVNAME", devname,
                                  sizeof(devname)) != 0 ||
            snprintf(device_path, sizeof(device_path), "%s/%s",
                     OTAD_TOPOLOGY_DEV_DIR, devname) >= (int)sizeof(device_path))
            continue;
        resolved = realpath(device_path, NULL);
        if (!resolved)
            continue;
        if (stat(resolved, &st) != 0 || !S_ISBLK(st.st_mode) ||
            topology_uevent_value(uevent_path, "MAJOR", major_text,
                                  sizeof(major_text)) != 0 ||
            topology_uevent_value(uevent_path, "MINOR", minor_text,
                                  sizeof(minor_text)) != 0 ||
            topology_devno_bind(major_text, minor_text, st.st_rdev,
                                devno, sizeof(devno)) != 0) {
            free(resolved);
            continue;
        }
        if (topology_uevent_value(uevent_path, "PARTUUID", candidate,
                                  sizeof(candidate)) != 0 &&
            topology_partuuid_probe(resolved, candidate,
                                    sizeof(candidate)) != 0) {
            free(resolved);
            continue;
        }
        if (strcasecmp(candidate, partuuid)) {
            free(resolved);
            continue;
        }
        matches++;
        if (st.st_rdev == expected_rdev)
            expected_matches++;
        free(resolved);
        if (matches > 1)
            break;
    }
    closedir(dir);
    return matches == 1 && expected_matches == 1 ? 0 : -1;
}

static int topology_partition_load(const char *label,
                                   struct topology_partition *part)
{
    DIR *dir;
    struct dirent *entry;
    struct topology_partition match;
    int matches = 0;

    if (!label || !part)
        return -1;
    memset(&match, 0, sizeof(match));
    dir = opendir(OTAD_TOPOLOGY_SYS_BLOCK_DIR);
    if (!dir)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        char partition_path[OTAD_MAX_PATH];
        char uevent_path[OTAD_MAX_PATH];
        char class_path[OTAD_MAX_PATH];
        char device_path[OTAD_MAX_PATH];
        char size_path[OTAD_MAX_PATH];
        char sys_target[OTAD_MAX_PATH];
        char partname[128];
        char devname[128];
        char major_text[16];
        char minor_text[16];
        char sectors_text[64];
        char *resolved = NULL;
        char *slash;
        struct stat st;
        size_t name_len;
        unsigned long long sectors;

        if (entry->d_name[0] == '.' || strchr(entry->d_name, '/'))
            continue;
        if (snprintf(partition_path, sizeof(partition_path),
                     "%s/%s/partition", OTAD_TOPOLOGY_SYS_BLOCK_DIR,
                     entry->d_name) >=
                (int)sizeof(partition_path) ||
            access(partition_path, R_OK) != 0 ||
            snprintf(uevent_path, sizeof(uevent_path),
                     "%s/%s/uevent", OTAD_TOPOLOGY_SYS_BLOCK_DIR,
                     entry->d_name) >=
                (int)sizeof(uevent_path) ||
            topology_uevent_value(uevent_path, "PARTNAME", partname,
                                  sizeof(partname)) != 0 ||
            strcmp(partname, label))
            continue;
        if (++matches > 1)
            break;
        if (topology_uevent_value(uevent_path, "DEVNAME", devname,
                                  sizeof(devname)) != 0 ||
            snprintf(device_path, sizeof(device_path), "%s/%s",
                     OTAD_TOPOLOGY_DEV_DIR, devname) >=
                (int)sizeof(device_path) ||
            !(resolved = realpath(device_path, NULL)) ||
            strlen(resolved) >= sizeof(match.path) ||
            stat(resolved, &st) != 0 || !S_ISBLK(st.st_mode)) {
            free(resolved);
            matches = 2;
            break;
        }
        snprintf(match.path, sizeof(match.path), "%s", resolved);
        free(resolved);
        match.rdev = st.st_rdev;
        if (topology_uevent_value(uevent_path, "MAJOR", major_text,
                                  sizeof(major_text)) != 0 ||
            topology_uevent_value(uevent_path, "MINOR", minor_text,
                                  sizeof(minor_text)) != 0 ||
            topology_devno_bind(major_text, minor_text, match.rdev,
                                match.devno, sizeof(match.devno)) != 0) {
            matches = 2;
            break;
        }
        if (topology_uevent_value(uevent_path, "PARTUUID", match.partuuid,
                                  sizeof(match.partuuid)) != 0 &&
            topology_partuuid_for_rdev(match.rdev, match.partuuid,
                                       sizeof(match.partuuid)) != 0 &&
            topology_partuuid_probe(match.path, match.partuuid,
                                    sizeof(match.partuuid)) != 0) {
            matches = 2;
            break;
        }
        (void)topology_fstype_probe(match.path, match.fstype,
                                    sizeof(match.fstype));
        name_len = strlen(entry->d_name);
        if (name_len >= sizeof(match.name)) {
            matches = 2;
            break;
        }
        memcpy(match.name, entry->d_name, name_len + 1);
        if (snprintf(class_path, sizeof(class_path), "%s/%s",
                     OTAD_TOPOLOGY_SYS_BLOCK_DIR, entry->d_name) >=
                (int)sizeof(class_path) ||
            !(resolved = realpath(class_path, NULL)) ||
            strlen(resolved) >= sizeof(sys_target)) {
            free(resolved);
            matches = 2;
            break;
        }
        snprintf(sys_target, sizeof(sys_target), "%s", resolved);
        free(resolved);
        slash = strrchr(sys_target, '/');
        if (!slash || slash == sys_target) {
            matches = 2;
            break;
        }
        *slash = '\0';
        slash = strrchr(sys_target, '/');
        if (!slash || !slash[1] || strlen(slash + 1) >= sizeof(match.parent)) {
            matches = 2;
            break;
        }
        snprintf(match.parent, sizeof(match.parent), "%s", slash + 1);
        if (snprintf(size_path, sizeof(size_path), "%s/%s/size",
                     OTAD_TOPOLOGY_SYS_BLOCK_DIR, entry->d_name) >=
                (int)sizeof(size_path) ||
            topology_text_file(size_path, sectors_text,
                               sizeof(sectors_text)) != 0) {
            matches = 2;
            break;
        }
        errno = 0;
        sectors = strtoull(sectors_text, &slash, 10);
        if (errno || !slash || *slash || sectors > UINT64_MAX / 512ULL) {
            matches = 2;
            break;
        }
        match.size = (uint64_t)sectors * 512ULL;
    }
    closedir(dir);
    if (matches != 1)
        return -1;
    *part = match;
    return 0;
}

int otad_ab_partlabel_unique(const char *label, char *path, size_t path_len)
{
    struct topology_partition part;

    if (!path || path_len == 0 ||
        topology_partition_load(label, &part) != 0 ||
        strlen(part.path) >= path_len)
        return -1;
    snprintf(path, path_len, "%s", part.path);
    return 0;
}

static int topology_cmdline_read(struct topology_cmdline *cmdline,
                                 char *error, size_t error_len)
{
    FILE *fp;
    char line[4096];
    char *save = NULL;
    char *token;
    unsigned int old_slot_count = 0;
    unsigned int new_slot_count = 0;
    char old_slot = '\0';
    char new_slot = '\0';
    unsigned int root_count = 0;

    if (!cmdline)
        return -1;
    memset(cmdline, 0, sizeof(*cmdline));
    fp = fopen(OTAD_TOPOLOGY_CMDLINE_PATH, "r");
    if (!fp || !fgets(line, sizeof(line), fp)) {
        if (fp)
            fclose(fp);
        topology_error(error, error_len, "cmdline_evidence_unavailable");
        return -1;
    }
    if (!strchr(line, '\n') && !feof(fp)) {
        fclose(fp);
        topology_error(error, error_len, "cmdline_evidence_truncated");
        return -1;
    }
    fclose(fp);
    for (token = strtok_r(line, " \t\r\n", &save); token;
         token = strtok_r(NULL, " \t\r\n", &save)) {
        if (!strncmp(token, "dreamingwrt.slot=", 17) ||
            !strncmp(token, "dreamingos.slot=", 16)) {
            int is_new = !strncmp(token, "dreamingos.slot=", 16);
            const char *value = token + (is_new ? 16 : 17);
            unsigned int *count = is_new ? &new_slot_count : &old_slot_count;
            char *slot = is_new ? &new_slot : &old_slot;

            (*count)++;
            if (*count > 1 ||
                ((value[0] != 'A' && value[0] != 'B') || value[1])) {
                topology_error(error, error_len,
                               "cmdline_slot_missing_or_ambiguous");
                return -1;
            }
            *slot = value[0];
            continue;
        }
        if (!strncmp(token, "root=", 5)) {
            const char *value = token + 5;

            root_count++;
            if (strncmp(value, "PARTUUID=", 9) || !value[9] ||
                strlen(value + 9) >= sizeof(cmdline->root_partuuid) ||
                strchr(value + 9, '/')) {
                topology_error(error, error_len,
                               "cmdline_root_partuuid_missing_or_ambiguous");
                return -1;
            }
            snprintf(cmdline->root_partuuid,
                     sizeof(cmdline->root_partuuid), "%s", value + 9);
        }
    }
    if (!old_slot_count && !new_slot_count) {
        topology_error(error, error_len, "cmdline_slot_missing_or_ambiguous");
        return -1;
    }
    if (old_slot_count && new_slot_count && old_slot != new_slot) {
        topology_error(error, error_len, "cmdline_slot_alias_conflict");
        return -1;
    }
    cmdline->slot[0] = new_slot_count ? new_slot : old_slot;
    cmdline->slot[1] = '\0';
    if (root_count != 1 || !cmdline->root_partuuid[0]) {
        topology_error(error, error_len,
                       "cmdline_root_partuuid_missing_or_ambiguous");
        return -1;
    }
    return 0;
}

static int topology_mounts_read(struct topology_mounts *mounts,
                                const char *slot_a_devno,
                                const char *slot_b_devno,
                                const char *boot_devno)
{
    FILE *fp;
    char line[4096];

    if (!mounts || !slot_a_devno || !slot_b_devno || !boot_devno)
        return -1;
    memset(mounts, 0, sizeof(*mounts));
    fp = fopen(OTAD_TOPOLOGY_MOUNTINFO_PATH, "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        char copy[4096];
        char *separator;
        char *save = NULL;
        char *token;
        char *devno = NULL;
        char *mountpoint = NULL;
        char *post_save = NULL;
        char *fstype;
        int field = 0;

        if (!strchr(line, '\n') && !feof(fp)) {
            fclose(fp);
            return -1;
        }

        snprintf(copy, sizeof(copy), "%s", line);
        separator = strstr(copy, " - ");
        if (!separator)
            continue;
        *separator = '\0';
        for (token = strtok_r(copy, " ", &save); token;
             token = strtok_r(NULL, " ", &save)) {
            field++;
            if (field == 3)
                devno = token;
            else if (field == 5) {
                mountpoint = token;
                break;
            }
        }
        fstype = strtok_r(separator + 3, " ", &post_save);
        if (!devno || !mountpoint || !fstype)
            continue;
        if (!strcmp(devno, slot_a_devno))
            mounts->slot_a_mounted = 1;
        if (!strcmp(devno, slot_b_devno))
            mounts->slot_b_mounted = 1;
        if (!strcmp(devno, boot_devno))
            mounts->boot_mounted = 1;
        if (!strcmp(mountpoint, "/")) {
            mounts->root_count++;
            snprintf(mounts->root_devno, sizeof(mounts->root_devno), "%s", devno);
            snprintf(mounts->root_fstype, sizeof(mounts->root_fstype), "%s", fstype);
        } else if (!strcmp(mountpoint, "/data")) {
            mounts->data_count++;
            snprintf(mounts->data_devno, sizeof(mounts->data_devno), "%s", devno);
            snprintf(mounts->data_fstype, sizeof(mounts->data_fstype), "%s", fstype);
        }
    }
    fclose(fp);
    return mounts->root_count > 0 ? 0 : -1;
}

static int topology_open_boot_file(int root_fd, const char *name,
                                   size_t max_len, char **out)
{
    struct stat st;
    char *data = NULL;
    size_t used = 0;
    int boot_fd = -1;
    int grub_fd = -1;
    int fd = -1;
    int rc = -1;

    if (root_fd < 0 || !name || !out || max_len == 0)
        return -1;
    *out = NULL;
    boot_fd = openat(root_fd, "boot",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (boot_fd < 0)
        goto out;
    grub_fd = openat(boot_fd, "grub",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (grub_fd < 0)
        goto out;
    fd = openat(grub_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0 || (uint64_t)st.st_size > max_len)
        goto out;
    data = calloc(1, (size_t)st.st_size + 1);
    if (!data)
        goto out;
    while (used < (size_t)st.st_size) {
        ssize_t n = read(fd, data + used, (size_t)st.st_size - used);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto out;
        }
        if (n == 0)
            goto out;
        used += (size_t)n;
    }
    if (memchr(data, '\0', used))
        goto out;
    data[used] = '\0';
    *out = data;
    data = NULL;
    rc = 0;

out:
    free(data);
    if (fd >= 0)
        close(fd);
    if (grub_fd >= 0)
        close(grub_fd);
    if (boot_fd >= 0)
        close(boot_fd);
    return rc;
}

static int topology_grubenv_value(const char *text, const char *key,
                                  char *out, size_t out_len)
{
    char *copy;
    char *save = NULL;
    char *line;
    size_t key_len;
    int matches = 0;

    if (!text || !key || !out || out_len == 0)
        return -1;
    out[0] = '\0';
    key_len = strlen(key);
    copy = strdup(text);
    if (!copy)
        return -1;
    for (line = strtok_r(copy, "\r\n", &save); line;
         line = strtok_r(NULL, "\r\n", &save)) {
        const char *value;

        if (line[0] == '#' || strncmp(line, key, key_len) ||
            line[key_len] != '=')
            continue;
        value = line + key_len + 1;
        if (++matches > 1 || strlen(value) >= out_len) {
            free(copy);
            return -1;
        }
        snprintf(out, out_len, "%s", value);
    }
    free(copy);
    return matches == 1 ? 0 : -1;
}

static int topology_grubenv_format_valid(const char *text)
{
    const char *body;
    const char *line;
    const char *end;
    size_t header_len = strlen(OTAD_TOPOLOGY_GRUBENV_HEADER);
    int seen_assignment = 0;

    if (!text || strlen(text) != OTAD_TOPOLOGY_GRUBENV_SIZE ||
        strncmp(text, OTAD_TOPOLOGY_GRUBENV_HEADER, header_len))
        return -1;
    body = text + header_len;
    while (*body) {
        const char *equals;
        const char *p;

        if (*body == '#') {
            /*
             * Two different things start with '#', and conflating them declared
             * the bootloader's own environment malformed: the trailing '#'
             * padding that fills the block, and the leading comment lines
             * grub-editenv writes. A stock file carries
             * "# WARNING: Do not edit this file by tools other than
             * grub-editenv!!!" right after the header. Reading that as the start
             * of padding failed the whole file and left rollback permanently
             * disabled on a healthy system.
             *
             * The layout is header, then comments, then assignments, then
             * padding to the end. So a comment is only accepted before the first
             * assignment, and padding must run unbroken to the end of the block.
             * Allowing a comment anywhere would reopen the real hazard here,
             * which is data hidden behind what looks like padding.
             */
            for (p = body; *p == '#'; p++)
                ;
            if (!*p)
                return seen_assignment ? 0 : -1;
            if (seen_assignment)
                return -1;
            end = strchr(body, '\n');
            if (!end)
                return -1;
            for (p = body; p < end; p++) {
                if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e)
                    return -1;
            }
            body = end + 1;
            continue;
        }
        line = body;
        end = strchr(line, '\n');
        if (!end || end == line)
            return -1;
        equals = memchr(line, '=', (size_t)(end - line));
        if (!equals || equals == line ||
            (!isalpha((unsigned char)line[0]) && line[0] != '_'))
            return -1;
        for (p = line + 1; p < equals; p++) {
            if (!isalnum((unsigned char)*p) && *p != '_')
                return -1;
        }
        for (p = equals + 1; p < end; p++) {
            if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e)
                return -1;
        }
        seen_assignment = 1;
        body = end + 1;
    }
    return -1;
}

static int topology_slot_value(const char *value, int allow_empty,
                               char out[2])
{
    if (!value || !out)
        return -1;
    if (!value[0] && allow_empty) {
        out[0] = '\0';
        out[1] = '\0';
        return 0;
    }
    if ((value[0] != 'A' && value[0] != 'B') || value[1])
        return -1;
    out[0] = value[0];
    out[1] = '\0';
    return 0;
}

static int topology_flag_value(const char *value, int *out)
{
    if (!value || !out || (strcmp(value, "0") && strcmp(value, "1")))
        return -1;
    *out = value[0] == '1';
    return 0;
}

static int topology_uint_value(const char *value, unsigned int max,
                               unsigned int *out)
{
    const char *p;
    char *end = NULL;
    unsigned long parsed;

    if (!value || !value[0] || !out)
        return -1;
    for (p = value; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return -1;
    }
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno || !end || end == value || *end || parsed > max)
        return -1;
    *out = (unsigned int)parsed;
    return 0;
}

static char *topology_grub_line(char **cursor)
{
    char *line;
    char *end;
    char quote = '\0';
    int escaped = 0;

    if (!cursor || !*cursor || !**cursor)
        return NULL;
    line = *cursor;
    end = strchr(line, '\n');
    if (end) {
        *end = '\0';
        *cursor = end + 1;
    } else {
        *cursor = line + strlen(line);
    }
    for (end = line; *end; end++) {
        if (escaped) {
            escaped = 0;
            continue;
        }
        if (*end == '\\') {
            escaped = 1;
            continue;
        }
        if (quote) {
            if (*end == quote)
                quote = '\0';
            continue;
        }
        if (*end == '\'' || *end == '"') {
            quote = *end;
            continue;
        }
        if (*end == '#') {
            *end = '\0';
            break;
        }
    }
    return quote || escaped ? NULL : line;
}

static int topology_grub_braces(const char *line, int *opens, int *closes)
{
    const char *p;
    char quote = '\0';
    int escaped = 0;

    if (!line || !opens || !closes)
        return -1;
    *opens = 0;
    *closes = 0;
    for (p = line; *p; p++) {
        if (escaped) {
            escaped = 0;
            continue;
        }
        if (*p == '\\') {
            escaped = 1;
            continue;
        }
        if (quote) {
            if (*p == quote)
                quote = '\0';
            continue;
        }
        if (*p == '\'' || *p == '"') {
            quote = *p;
        } else if (*p == '{') {
            (*opens)++;
        } else if (*p == '}') {
            (*closes)++;
        }
    }
    return quote || escaped ? -1 : 0;
}

static int topology_grub_linux_line(const char *line, char slot[2],
                                    char *root_partuuid,
                                    size_t root_partuuid_len,
                                    int *is_linux)
{
    char copy[4096];
    char *save = NULL;
    char *token;
    unsigned int root_count = 0;
    unsigned int old_slot_count = 0;
    unsigned int new_slot_count = 0;
    char old_slot[2] = "";
    char new_slot[2] = "";

    if (!line || !slot || !root_partuuid || !is_linux ||
        strlen(line) >= sizeof(copy))
        return -1;
    *is_linux = 0;
    slot[0] = '\0';
    root_partuuid[0] = '\0';
    snprintf(copy, sizeof(copy), "%s", line);
    token = strtok_r(copy, " \t", &save);
    if (!token || (strcmp(token, "linux") && strcmp(token, "linuxefi")))
        return 0;
    *is_linux = 1;
    while ((token = strtok_r(NULL, " \t", &save)) != NULL) {
        if (!strncmp(token, "root=PARTUUID=", 14)) {
            if (++root_count > 1 || !token[14] ||
                strlen(token + 14) >= root_partuuid_len ||
                strchr(token + 14, '/'))
                return -1;
            snprintf(root_partuuid, root_partuuid_len, "%s", token + 14);
        } else if (!strncmp(token, "dreamingwrt.slot=", 17)) {
            if (++old_slot_count > 1 ||
                topology_slot_value(token + 17, 0, old_slot) != 0)
                return -1;
        } else if (!strncmp(token, "dreamingos.slot=", 16)) {
            if (++new_slot_count > 1 ||
                topology_slot_value(token + 16, 0, new_slot) != 0)
                return -1;
        }
    }
    if (root_count != 1 || (!old_slot_count && !new_slot_count) ||
        (old_slot_count && new_slot_count && strcmp(old_slot, new_slot)))
        return -1;
    snprintf(slot, 2, "%s", new_slot_count ? new_slot : old_slot);
    return 0;
}

static int topology_grubcfg_entries(const char *text,
                                    const char *partuuid_a,
                                    const char *partuuid_b,
                                    int *verified_a, int *verified_b)
{
    char *copy;
    char *cursor;
    char *line;
    unsigned int count_a = 0;
    unsigned int count_b = 0;
    unsigned int match_a = 0;
    unsigned int match_b = 0;
    unsigned int entry_linux_count = 0;
    char entry_slot[2] = "";
    char entry_root[128] = "";
    int in_entry = 0;
    int depth = 0;

    if (!text || !partuuid_a || !partuuid_b || !verified_a || !verified_b)
        return -1;
    *verified_a = 0;
    *verified_b = 0;
    copy = strdup(text);
    if (!copy)
        return -1;
    cursor = copy;
    while (*cursor) {
        char slot[2] = "";
        char root_partuuid[128] = "";
        char *trimmed;
        int opens = 0;
        int closes = 0;
        int is_linux = 0;

        line = topology_grub_line(&cursor);
        if (!line || topology_grub_braces(line, &opens, &closes) != 0)
            goto malformed;
        trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t')
            trimmed++;
        if (!in_entry) {
            if (!strncmp(trimmed, "menuentry", 9) &&
                (trimmed[9] == ' ' || trimmed[9] == '\t')) {
                if (opens != 1 || closes != 0)
                    goto malformed;
                in_entry = 1;
                depth = 1;
                entry_linux_count = 0;
                entry_slot[0] = '\0';
                entry_root[0] = '\0';
            }
            continue;
        }
        if (!strncmp(trimmed, "menuentry", 9) &&
            (trimmed[9] == ' ' || trimmed[9] == '\t'))
            goto malformed;
        if (topology_grub_linux_line(trimmed, slot, root_partuuid,
                                     sizeof(root_partuuid), &is_linux) != 0)
            goto malformed;
        if (is_linux) {
            if (++entry_linux_count > 1)
                goto malformed;
            snprintf(entry_slot, sizeof(entry_slot), "%s", slot);
            snprintf(entry_root, sizeof(entry_root), "%s", root_partuuid);
        }
        depth += opens - closes;
        if (depth < 0)
            goto malformed;
        if (depth == 0) {
            if (entry_linux_count == 1) {
                if (entry_slot[0] == 'A') {
                    count_a++;
                    if (!strcasecmp(entry_root, partuuid_a))
                        match_a++;
                } else if (entry_slot[0] == 'B') {
                    count_b++;
                    if (!strcasecmp(entry_root, partuuid_b))
                        match_b++;
                } else {
                    goto malformed;
                }
            }
            in_entry = 0;
        }
    }
    free(copy);
    if (in_entry || count_a != 1 || count_b != 1 ||
        match_a != 1 || match_b != 1)
        return -1;
    *verified_a = 1;
    *verified_b = 1;
    return 0;

malformed:
    free(copy);
    return -1;
}

static int topology_boot_state_parse(struct otad_ab_topology *topology,
                                     const char *grubenv,
                                     const char *grubcfg,
                                     char *error, size_t error_len)
{
    char active[16] = "";
    char pending[16] = "";
    char tries[16] = "";
    char last_good[16] = "";
    char valid_a[16] = "";
    char valid_b[16] = "";
    int current_valid;
    int active_valid;

    if (!topology || !grubenv || !grubcfg ||
        topology_grubenv_format_valid(grubenv) != 0)
        goto malformed;
    if (topology_grubenv_value(grubenv, "active_slot", active,
                               sizeof(active)) != 0 ||
        topology_grubenv_value(grubenv, "pending_slot", pending,
                               sizeof(pending)) != 0 ||
        topology_grubenv_value(grubenv, "tries_left", tries,
                               sizeof(tries)) != 0 ||
        topology_grubenv_value(grubenv, "last_good_slot", last_good,
                               sizeof(last_good)) != 0 ||
        topology_grubenv_value(grubenv, "slot_a_valid", valid_a,
                               sizeof(valid_a)) != 0 ||
        topology_grubenv_value(grubenv, "slot_b_valid", valid_b,
                               sizeof(valid_b)) != 0 ||
        topology_slot_value(active, 0, topology->boot_active_slot) != 0 ||
        topology_slot_value(pending, 1, topology->boot_pending_slot) != 0 ||
        topology_slot_value(last_good, 0,
                            topology->boot_last_good_slot) != 0 ||
        topology_flag_value(valid_a, &topology->slot_a_valid) != 0 ||
        topology_flag_value(valid_b, &topology->slot_b_valid) != 0 ||
        topology_uint_value(tries, 3, &topology->boot_tries_left) != 0)
        goto malformed;
    if (strcmp(topology->boot_active_slot, topology->boot_last_good_slot)) {
        topology_error(error, error_len,
                       "bootloader_active_last_good_mismatch");
        return -1;
    }
    active_valid = topology->boot_active_slot[0] == 'A' ?
        topology->slot_a_valid : topology->slot_b_valid;
    if (!active_valid) {
        topology_error(error, error_len, "bootloader_active_slot_invalid");
        return -1;
    }
    current_valid = topology->current_slot[0] == 'A' ?
        topology->slot_a_valid : topology->slot_b_valid;
    if (!current_valid) {
        topology_error(error, error_len, "bootloader_current_slot_invalid");
        return -1;
    }
    if (topology->boot_pending_slot[0]) {
        int pending_valid = topology->boot_pending_slot[0] == 'A' ?
            topology->slot_a_valid : topology->slot_b_valid;

        if (!strcmp(topology->boot_pending_slot,
                    topology->boot_active_slot)) {
            topology_error(error, error_len,
                           "bootloader_pending_active_slot_conflict");
            return -1;
        }
        if (!pending_valid) {
            topology_error(error, error_len,
                           "bootloader_pending_slot_invalid");
            return -1;
        }
        if (strcmp(topology->current_slot, topology->boot_active_slot) &&
            strcmp(topology->current_slot, topology->boot_pending_slot)) {
            topology_error(error, error_len,
                           "bootloader_current_slot_mismatch");
            return -1;
        }
    } else {
        if (strcmp(topology->current_slot, topology->boot_active_slot)) {
            topology_error(error, error_len,
                           "bootloader_current_slot_mismatch");
            return -1;
        }
        if (topology->boot_tries_left != 0) {
            topology_error(error, error_len,
                           "bootloader_tries_without_pending_slot");
            return -1;
        }
    }
    if ((!topology->root_a_fstype[0] && topology->slot_a_valid) ||
        (!topology->root_b_fstype[0] && topology->slot_b_valid)) {
        topology_error(error, error_len,
                       "bootloader_blank_slot_marked_valid");
        return -1;
    }
    if (topology_grubcfg_entries(
            grubcfg, topology->root_a_partuuid, topology->root_b_partuuid,
            &topology->slot_a_boot_entry_verified,
            &topology->slot_b_boot_entry_verified) != 0) {
        topology_error(error, error_len, "bootloader_slot_entry_mismatch");
        return -1;
    }
    topology->boot_state_verified = 1;
    topology->inactive_slot_bootable_verified = 0;
    return 0;

malformed:
    topology_error(error, error_len, "bootloader_grubenv_invalid");
    return -1;
}

static int topology_unmount_cleanup(const char *mount_dir)
{
    if (!mount_dir)
        return -1;
    if (OTAD_TOPOLOGY_UMOUNT(mount_dir, 0) == 0)
        return 0;
    return OTAD_TOPOLOGY_UMOUNT(mount_dir, MNT_DETACH) == 0 ? 0 : -1;
}

static int topology_inactive_kernel_verify(struct otad_ab_topology *topology,
                                           char *error, size_t error_len)
{
    char mount_dir[] = "/tmp/dreamingwrt-otad-inactive-XXXXXX";
    const char *device;
    const char *fstype;
    int slot_valid;
    int entry_verified;
    int root_fd = -1;
    int boot_fd = -1;
    int kernel_fd = -1;
    int mounted = 0;
    int verified = 0;
    int cleanup_failed = 0;
    struct stat st;

    if (!topology || !topology->inactive_slot[0])
        return 0;
    if (topology->inactive_slot[0] == 'A') {
        device = topology->root_a;
        fstype = topology->root_a_fstype;
        slot_valid = topology->slot_a_valid;
        entry_verified = topology->slot_a_boot_entry_verified;
    } else {
        device = topology->root_b;
        fstype = topology->root_b_fstype;
        slot_valid = topology->slot_b_valid;
        entry_verified = topology->slot_b_boot_entry_verified;
    }
    if (!slot_valid || !entry_verified || strcmp(fstype, "ext4"))
        return 0;
    if (!mkdtemp(mount_dir))
        return 0;
    if (OTAD_TOPOLOGY_MOUNT(
            device, mount_dir, "ext4",
            MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME,
            NULL) != 0)
        goto out;
    mounted = 1;
    root_fd = open(mount_dir,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0)
        goto out;
    boot_fd = openat(root_fd, "boot",
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (boot_fd < 0)
        goto out;
    kernel_fd = openat(boot_fd, "vmlinuz",
                       O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (kernel_fd < 0 || fstat(kernel_fd, &st) != 0 ||
        !S_ISREG(st.st_mode) || st.st_size <= 0)
        goto out;
    verified = 1;

out:
    if (kernel_fd >= 0)
        close(kernel_fd);
    if (boot_fd >= 0)
        close(boot_fd);
    if (root_fd >= 0)
        close(root_fd);
    if (mounted && topology_unmount_cleanup(mount_dir) != 0)
        cleanup_failed = 1;
    if (rmdir(mount_dir) != 0)
        cleanup_failed = 1;
    if (cleanup_failed) {
        topology_error(error, error_len,
                       "inactive_slot_readonly_unmount_failed");
        return -1;
    }
    topology->inactive_slot_bootable_verified = verified;
    return verified;
}

static int topology_boot_state_load(struct otad_ab_topology *topology,
                                    const struct topology_mounts *mounts,
                                    char *error, size_t error_len)
{
    char mount_dir[] = "/tmp/dreamingwrt-otad-boot-XXXXXX";
    char *grubenv = NULL;
    char *grubcfg = NULL;
    int root_fd = -1;
    int mounted = 0;
    int rc = -1;

    if (!topology || !mounts || !topology->boot[0])
        goto invalid;
    if (mounts->boot_mounted) {
        topology_error(error, error_len, "boot_partition_already_mounted");
        return -1;
    }
    if (!mkdtemp(mount_dir)) {
        topology_error(error, error_len,
                       "bootloader_readonly_mountpoint_failed");
        return -1;
    }
    if (OTAD_TOPOLOGY_MOUNT(
            topology->boot, mount_dir, "vfat",
            MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME,
            OTAD_TOPOLOGY_BOOT_MOUNT_OPTIONS) != 0) {
        topology_error(error, error_len, "bootloader_readonly_mount_failed");
        goto out;
    }
    mounted = 1;
    root_fd = open(mount_dir,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0 ||
        topology_open_boot_file(root_fd, "grubenv",
                                OTAD_TOPOLOGY_GRUBENV_MAX, &grubenv) != 0 ||
        topology_open_boot_file(root_fd, "grub.cfg",
                                OTAD_TOPOLOGY_GRUBCFG_MAX, &grubcfg) != 0) {
        topology_error(error, error_len,
                       "bootloader_state_files_unavailable");
        goto out;
    }
    rc = topology_boot_state_parse(topology, grubenv, grubcfg,
                                   error, error_len);

out:
    free(grubenv);
    free(grubcfg);
    if (root_fd >= 0)
        close(root_fd);
    if (mounted && topology_unmount_cleanup(mount_dir) != 0) {
        topology_error(error, error_len,
                       "bootloader_readonly_unmount_failed");
        rc = -1;
    }
    if (rmdir(mount_dir) != 0 && rc == 0) {
        topology_error(error, error_len,
                       "bootloader_mountpoint_cleanup_failed");
        rc = -1;
    }
    if (rc == 0 && topology_inactive_kernel_verify(
                       topology, error, error_len) < 0)
        rc = -1;
    return rc;

invalid:
    topology_error(error, error_len, "ab_topology_contract_invalid");
    return -1;
}

static int topology_digest(struct otad_ab_topology *topology)
{
    struct json_object *o;
    const char *text;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned int i;

    o = otad_ab_topology_json(topology);
    if (!o)
        return -1;
    json_object_object_del(o, "topology_digest");
    text = json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN);
    if (!text || EVP_Digest(text, strlen(text), digest, &digest_len,
                            EVP_sha256(), NULL) != 1 || digest_len != 32) {
        json_object_put(o);
        return -1;
    }
    for (i = 0; i < digest_len; i++)
        snprintf(topology->topology_digest + i * 2,
                 sizeof(topology->topology_digest) - i * 2,
                 "%02x", digest[i]);
    topology->topology_digest[64] = '\0';
    json_object_put(o);
    return 0;
}

static int topology_discover(struct otad_ab_topology *topology,
                             int require_boot_state,
                             char *error, size_t error_len)
{
    struct topology_partition a, b, boot, data;
    struct topology_mounts mounts;
    struct topology_cmdline cmdline;
    const char *current_partuuid;

    if (error && error_len)
        error[0] = '\0';
    if (!topology)
        goto invalid;
    memset(topology, 0, sizeof(*topology));
    if (topology_partition_load(OTAD_SLOT_A_LABEL, &a) != 0 ||
        topology_partition_load(OTAD_SLOT_B_LABEL, &b) != 0 ||
        topology_partition_load(OTAD_BOOT_LABEL, &boot) != 0 ||
        topology_partition_load(OTAD_DATA_LABEL, &data) != 0) {
        topology_error(error, error_len, "ab_partlabel_missing_or_ambiguous");
        return -1;
    }
    if (a.rdev == b.rdev || a.rdev == boot.rdev || a.rdev == data.rdev ||
        b.rdev == boot.rdev || b.rdev == data.rdev || boot.rdev == data.rdev) {
        topology_error(error, error_len, "ab_partition_devices_not_distinct");
        return -1;
    }
    if (topology_partuuid_unique(a.partuuid, a.rdev) != 0 ||
        topology_partuuid_unique(b.partuuid, b.rdev) != 0 ||
        topology_partuuid_unique(boot.partuuid, boot.rdev) != 0 ||
        topology_partuuid_unique(data.partuuid, data.rdev) != 0) {
        topology_error(error, error_len, "ab_partuuid_missing_or_ambiguous");
        return -1;
    }
    if (strcmp(a.parent, b.parent) || strcmp(a.parent, boot.parent) ||
        strcmp(a.parent, data.parent)) {
        topology_error(error, error_len, "ab_partitions_not_on_same_parent_disk");
        return -1;
    }
    if (!a.size || !b.size || !boot.size || !data.size || a.size != b.size) {
        topology_error(error, error_len, "ab_partition_sizes_invalid");
        return -1;
    }
    if ((strcmp(a.fstype, "ext4") && strcmp(b.fstype, "ext4")) ||
        (a.fstype[0] && strcmp(a.fstype, "ext4")) ||
        (b.fstype[0] && strcmp(b.fstype, "ext4")) ||
        (strcmp(boot.fstype, "vfat") && strcmp(boot.fstype, "fat")) ||
        strcmp(data.fstype, "ext4")) {
        topology_error(error, error_len, "ab_partition_filesystems_invalid");
        return -1;
    }
    if (topology_mounts_read(&mounts, a.devno, b.devno, boot.devno) != 0) {
        topology_error(error, error_len, "root_mount_topology_unavailable");
        return -1;
    }
    if (mounts.root_count != 1) {
        topology_error(error, error_len, "root_mount_topology_ambiguous");
        return -1;
    }
    if (!strcmp(mounts.root_devno, a.devno)) {
        topology->current_slot[0] = 'A';
    } else if (!strcmp(mounts.root_devno, b.devno)) {
        topology->current_slot[0] = 'B';
    } else {
        topology_error(error, error_len, "root_device_is_not_dreamingwrt_slot");
        return -1;
    }
    topology->current_slot[1] = '\0';
    topology->inactive_slot[0] = topology->current_slot[0] == 'A' ? 'B' : 'A';
    topology->inactive_slot[1] = '\0';
    if (strcmp(mounts.root_fstype, "ext4")) {
        topology_error(error, error_len, "root_slot_filesystem_unsupported");
        return -1;
    }
    if ((topology->current_slot[0] == 'A' && strcmp(a.fstype, "ext4")) ||
        (topology->current_slot[0] == 'B' && strcmp(b.fstype, "ext4"))) {
        topology_error(error, error_len,
                       "current_slot_block_filesystem_mismatch");
        return -1;
    }
    if (topology_cmdline_read(&cmdline, error, error_len) != 0)
        return -1;
    current_partuuid = topology->current_slot[0] == 'A' ? a.partuuid : b.partuuid;
    if (strcmp(cmdline.slot, topology->current_slot) ||
        strcasecmp(cmdline.root_partuuid, current_partuuid)) {
        topology_error(error, error_len, "cmdline_slot_root_device_mismatch");
        return -1;
    }
    if ((topology->inactive_slot[0] == 'A' && mounts.slot_a_mounted) ||
        (topology->inactive_slot[0] == 'B' && mounts.slot_b_mounted)) {
        topology_error(error, error_len, "inactive_slot_is_mounted");
        return -1;
    }
    if (mounts.data_count != 1) {
        topology_error(error, error_len, "data_mount_missing_or_ambiguous");
        return -1;
    }
    if (strcmp(mounts.data_devno, data.devno) || strcmp(mounts.data_fstype, "ext4")) {
        topology_error(error, error_len, "data_mount_source_mismatch");
        return -1;
    }
#define COPY_PART(dst, src) do { \
    snprintf(topology->dst, sizeof(topology->dst), "%s", (src).path); \
    snprintf(topology->dst##_partuuid, sizeof(topology->dst##_partuuid), "%s", (src).partuuid); \
    snprintf(topology->dst##_devno, sizeof(topology->dst##_devno), "%s", (src).devno); \
    topology->dst##_size = (src).size; \
} while (0)
    COPY_PART(root_a, a);
    COPY_PART(root_b, b);
    COPY_PART(boot, boot);
    COPY_PART(data, data);
#undef COPY_PART
    snprintf(topology->root_a_fstype, sizeof(topology->root_a_fstype),
             "%s", a.fstype);
    snprintf(topology->root_b_fstype, sizeof(topology->root_b_fstype),
             "%s", b.fstype);
    snprintf(topology->inactive_slot_state,
             sizeof(topology->inactive_slot_state), "%s",
             topology->current_slot[0] == 'A' ?
                 (b.fstype[0] ? "initialized_ext4" : "uninitialized_blank") :
                 (a.fstype[0] ? "initialized_ext4" : "uninitialized_blank"));
    snprintf(topology->parent_disk, sizeof(topology->parent_disk), "%s", a.parent);
    if (require_boot_state) {
        if (topology_boot_state_load(topology, &mounts,
                                     error, error_len) != 0)
            return -1;
        if (topology_digest(topology) != 0) {
            topology_error(error, error_len, "ab_topology_digest_failed");
            return -1;
        }
    }
    return 0;

invalid:
    topology_error(error, error_len, "ab_topology_contract_invalid");
    return -1;
}

int otad_ab_topology_readonly_probe(struct otad_ab_topology *topology,
                                    char *error, size_t error_len)
{
    return topology_discover(topology, 0, error, error_len);
}

int otad_ab_topology_discover(struct otad_ab_topology *topology,
                              char *error, size_t error_len)
{
    return topology_discover(topology, 1, error, error_len);
}

int otad_ab_topology_validate_release(const struct otad_ab_topology *topology,
                                      struct json_object *firmware_info,
                                      char *error, size_t error_len)
{
    struct json_object *layout = NULL;
    uint64_t min_slot;
    uint64_t min_data;

    if (!topology || !firmware_info ||
        !json_object_object_get_ex(firmware_info, "ab_layout", &layout) ||
        !layout || !json_object_is_type(layout, json_type_object) ||
        strcmp(otad_json_str(layout, "schema", ""), OTAD_AB_LAYOUT_SCHEMA) ||
        !otad_json_bool(layout, "root_slots_equal_size", 0) ||
        !otad_json_bool(layout, "data_uses_remaining_space", 0)) {
        topology_error(error, error_len, "signed_ab_layout_incompatible");
        return -1;
    }
    min_slot = (uint64_t)json_object_get_int64(
        json_object_object_get(layout, "min_slot_size_mib"));
    min_data = (uint64_t)json_object_get_int64(
        json_object_object_get(layout, "min_data_size_mib"));
    if (!min_slot || !min_data || min_slot > UINT64_MAX / (1024ULL * 1024ULL) ||
        min_data > UINT64_MAX / (1024ULL * 1024ULL) ||
        topology->root_a_size < min_slot * 1024ULL * 1024ULL ||
        topology->root_b_size < min_slot * 1024ULL * 1024ULL ||
        topology->data_size < min_data * 1024ULL * 1024ULL) {
        topology_error(error, error_len, "signed_ab_layout_capacity_mismatch");
        return -1;
    }
    return 0;
}

int otad_ab_boot_state_readonly_verify(const struct otad_ab_topology *topology,
                                       char *error, size_t error_len)
{
    if (!topology || !topology->current_slot[0] ||
        !topology->inactive_slot[0]) {
        topology_error(error, error_len, "ab_topology_contract_invalid");
        return -1;
    }
    if (!topology->boot_state_verified ||
        !topology->slot_a_boot_entry_verified ||
        !topology->slot_b_boot_entry_verified) {
        topology_error(error, error_len,
                       "bootloader_slot_state_not_readonly_verified");
        return -1;
    }
    if (error && error_len)
        error[0] = '\0';
    return 0;
}

struct json_object *otad_ab_topology_json(const struct otad_ab_topology *topology)
{
    struct json_object *o;

    if (!topology)
        return NULL;
    o = json_object_new_object();
    otad_json_add_string(o, "layout", OTAD_AB_LAYOUT_SCHEMA);
    otad_json_add_string(o, "current_slot", topology->current_slot);
    otad_json_add_string(o, "inactive_slot", topology->inactive_slot);
    otad_json_add_string(o, "parent_disk", topology->parent_disk);
    otad_json_add_string(o, "root_a_device", topology->root_a);
    otad_json_add_string(o, "root_b_device", topology->root_b);
    otad_json_add_string(o, "boot_device", topology->boot);
    otad_json_add_string(o, "data_device", topology->data);
    otad_json_add_string(o, "root_a_partuuid", topology->root_a_partuuid);
    otad_json_add_string(o, "root_b_partuuid", topology->root_b_partuuid);
    otad_json_add_string(o, "boot_partuuid", topology->boot_partuuid);
    otad_json_add_string(o, "data_partuuid", topology->data_partuuid);
    otad_json_add_string(o, "root_a_fstype", topology->root_a_fstype);
    otad_json_add_string(o, "root_b_fstype", topology->root_b_fstype);
    otad_json_add_string(o, "inactive_slot_state", topology->inactive_slot_state);
    otad_json_add_string(o, "boot_active_slot", topology->boot_active_slot);
    otad_json_add_string(o, "boot_pending_slot", topology->boot_pending_slot);
    otad_json_add_string(o, "boot_last_good_slot",
                         topology->boot_last_good_slot);
    json_object_object_add(o, "boot_tries_left",
                           json_object_new_int((int)topology->boot_tries_left));
    json_object_object_add(o, "slot_a_valid",
                           json_object_new_boolean(topology->slot_a_valid));
    json_object_object_add(o, "slot_b_valid",
                           json_object_new_boolean(topology->slot_b_valid));
    json_object_object_add(o, "slot_a_boot_entry_verified",
                           json_object_new_boolean(topology->slot_a_boot_entry_verified));
    json_object_object_add(o, "slot_b_boot_entry_verified",
                           json_object_new_boolean(topology->slot_b_boot_entry_verified));
    json_object_object_add(o, "boot_state_verified",
                           json_object_new_boolean(topology->boot_state_verified));
    json_object_object_add(o, "inactive_slot_bootable_verified",
                           json_object_new_boolean(
                               topology->inactive_slot_bootable_verified));
    json_object_object_add(o, "root_mount_verified",
                           json_object_new_boolean(1));
    json_object_object_add(o, "cmdline_slot_verified",
                           json_object_new_boolean(1));
    json_object_object_add(o, "cmdline_root_partuuid_verified",
                           json_object_new_boolean(1));
    json_object_object_add(o, "data_mount_verified",
                           json_object_new_boolean(1));
    json_object_object_add(o, "inactive_unmounted_verified",
                           json_object_new_boolean(1));
    json_object_object_add(o, "root_a_size_bytes",
                           json_object_new_int64((int64_t)topology->root_a_size));
    json_object_object_add(o, "root_b_size_bytes",
                           json_object_new_int64((int64_t)topology->root_b_size));
    json_object_object_add(o, "boot_size_bytes",
                           json_object_new_int64((int64_t)topology->boot_size));
    json_object_object_add(o, "data_size_bytes",
                           json_object_new_int64((int64_t)topology->data_size));
    otad_json_add_string(o, "topology_digest", topology->topology_digest);
    return o;
}
