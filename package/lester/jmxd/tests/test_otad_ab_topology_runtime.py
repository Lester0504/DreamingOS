#!/usr/bin/env python3
"""Run the real A/B topology parser against synthetic sysfs/proc/dev fixtures."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]

STUBS = {
    "libubox/blobmsg.h": "#pragma once\nstruct blob_attr; struct blob_buf { int unused; };\n",
    "libubox/blobmsg_json.h": (
        "#pragma once\n#include <stdbool.h>\nstruct blob_attr;\n"
        "char *blobmsg_format_json(struct blob_attr *, bool);\n"
    ),
    "libubox/uloop.h": (
        "#pragma once\n#include <sys/types.h>\n"
        "struct uloop_timeout { void (*cb)(struct uloop_timeout *); };\n"
        "struct uloop_process { pid_t pid; void (*cb)(struct uloop_process *, int); };\n"
    ),
    "libubox/utils.h": "#pragma once\n#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))\n",
    "libubus.h": "#pragma once\nstruct ubus_context;\n",
    "linux/fs.h": (
        "#pragma once\n#include <sys/ioctl.h>\n"
        "#define BLKGETSIZE64 _IOR(0x12, 114, unsigned long long)\n"
    ),
    "sys/mount.h": (
        "#pragma once\n#define MS_RDONLY 1UL\n#define MS_NOSUID 2UL\n"
        "#define MS_NODEV 4UL\n#define MS_NOEXEC 8UL\n#define MS_NOATIME 1024UL\n"
        "#define MNT_DETACH 2\n"
    ),
    "blkid/blkid.h": (
        "#pragma once\ntypedef void *blkid_cache;\n"
        "char *blkid_get_tag_value(blkid_cache, const char *, const char *);\n"
    ),
}

HARNESS = r'''
#include "otad_internal.h"
#include <blkid/blkid.h>

static int fixture_active_mounts;

static int fixture_write_file(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");

    if (!fp)
        return -1;
    if (fputs(text, fp) < 0 || fclose(fp) != 0)
        return -1;
    return 0;
}

static int fixture_write_grubenv(const char *path, const char *body)
{
    static const char header[] = "# GRUB Environment Block\n";
    char block[1024];
    FILE *fp;
    size_t used;

    if (getenv("OTAD_FIXTURE_GRUBENV_SHORT"))
        return fixture_write_file(path, body);
    memset(block, '#', sizeof(block));
    if (getenv("OTAD_FIXTURE_GRUBENV_BAD_HEADER"))
        memcpy(block, "# forged environment block\n", 27);
    else
        memcpy(block, header, sizeof(header) - 1);
    used = getenv("OTAD_FIXTURE_GRUBENV_BAD_HEADER") ? 27 : sizeof(header) - 1;
    if (strlen(body) > sizeof(block) - used)
        return -1;
    memcpy(block + used, body, strlen(body));
    fp = fopen(path, "wb");
    if (!fp)
        return -1;
    if (fwrite(block, 1, sizeof(block), fp) != sizeof(block) || fclose(fp) != 0)
        return -1;
    return 0;
}

static int fixture_mount(const char *source, const char *target,
                         const char *fstype, unsigned long flags,
                         const void *data)
{
    char boot[1024];
    char grub[1024];
    char grubenv_path[1024];
    char grubcfg_path[1024];
    const char *grubenv;
    const char *grubcfg;
    int blank_b = getenv("OTAD_FIXTURE_ROOT_B_BLANK") != NULL;

    if (!source || !target ||
        !(flags & MS_RDONLY) || !(flags & MS_NOSUID) ||
        !(flags & MS_NODEV) || !(flags & MS_NOEXEC))
        return -1;
    if (!strcmp(fstype, "ext4")) {
        char kernel[1024];
        FILE *fp;

        if (data || getenv("OTAD_FIXTURE_INACTIVE_MOUNT_FAIL"))
            return -1;
        if (snprintf(boot, sizeof(boot), "%s/boot", target) >=
                (int)sizeof(boot) ||
            snprintf(kernel, sizeof(kernel), "%s/vmlinuz", boot) >=
                (int)sizeof(kernel) || mkdir(boot, 0700) != 0)
            return -1;
        fixture_active_mounts++;
        if (getenv("OTAD_FIXTURE_KERNEL_MISSING"))
            return 0;
        if (getenv("OTAD_FIXTURE_KERNEL_SYMLINK"))
            return symlink("/boot/forged-vmlinuz", kernel);
        fp = fopen(kernel, "wb");
        if (!fp)
            return -1;
        if (!getenv("OTAD_FIXTURE_KERNEL_EMPTY") &&
            fwrite("kernel", 1, 6, fp) != 6) {
            fclose(fp);
            return -1;
        }
        return fclose(fp);
    }
    if (strcmp(fstype, "vfat") || !data ||
        strcmp((const char *)data, "uid=0,gid=0,fmask=0077,dmask=0077"))
        return -1;
    if (snprintf(boot, sizeof(boot), "%s/boot", target) >= (int)sizeof(boot) ||
        snprintf(grub, sizeof(grub), "%s/boot/grub", target) >= (int)sizeof(grub) ||
        snprintf(grubenv_path, sizeof(grubenv_path), "%s/grubenv", grub) >=
            (int)sizeof(grubenv_path) ||
        snprintf(grubcfg_path, sizeof(grubcfg_path), "%s/grub.cfg", grub) >=
            (int)sizeof(grubcfg_path) ||
        mkdir(boot, 0700) != 0 || mkdir(grub, 0700) != 0)
        return -1;
    if (getenv("OTAD_FIXTURE_GRUBENV_INVALID"))
        grubenv = "active_slot=A\npending_slot=\ntries_left=0\n";
    else if (getenv("OTAD_FIXTURE_GRUBENV_EMPTY_TRIES"))
        grubenv = "active_slot=A\npending_slot=\ntries_left=\n"
                  "last_good_slot=A\nslot_a_valid=1\nslot_b_valid=1\n";
    else if (getenv("OTAD_FIXTURE_GRUBENV_SIGNED_TRIES"))
        grubenv = "active_slot=A\npending_slot=\ntries_left=+0\n"
                  "last_good_slot=A\nslot_a_valid=1\nslot_b_valid=1\n";
    else if (getenv("OTAD_FIXTURE_PENDING_B"))
        grubenv = "active_slot=A\npending_slot=B\ntries_left=1\n"
                  "last_good_slot=A\nslot_a_valid=1\nslot_b_valid=1\n";
    else if (getenv("OTAD_FIXTURE_PENDING_ACTIVE"))
        grubenv = "active_slot=A\npending_slot=A\ntries_left=1\n"
                  "last_good_slot=A\nslot_a_valid=1\nslot_b_valid=1\n";
    else if (getenv("OTAD_FIXTURE_ACTIVE_B"))
        grubenv = "active_slot=B\npending_slot=\ntries_left=0\n"
                  "last_good_slot=B\nslot_a_valid=1\nslot_b_valid=1\n";
    else if (getenv("OTAD_FIXTURE_BLANK_B_VALID"))
        grubenv = "active_slot=A\npending_slot=\ntries_left=0\n"
                  "last_good_slot=A\nslot_a_valid=1\nslot_b_valid=1\n";
    else if (getenv("OTAD_FIXTURE_TRIES_WITHOUT_PENDING"))
        grubenv = "active_slot=A\npending_slot=\ntries_left=2\n"
                  "last_good_slot=A\nslot_a_valid=1\nslot_b_valid=1\n";
    else
        grubenv = blank_b ?
            "active_slot=A\npending_slot=\ntries_left=0\n"
            "last_good_slot=A\nslot_a_valid=1\nslot_b_valid=0\n" :
            "active_slot=A\npending_slot=\ntries_left=0\n"
            "last_good_slot=A\nslot_a_valid=1\nslot_b_valid=1\n";
    if (getenv("OTAD_FIXTURE_GRUBCFG_MISMATCH"))
        grubcfg =
            "menuentry 'A' {\n"
            " linux /boot/vmlinuz root=PARTUUID=root-b-uuid dreamingwrt.slot=A\n}\n"
            "menuentry 'B' {\n"
            " linux /boot/vmlinuz root=PARTUUID=root-b-uuid dreamingwrt.slot=B\n}\n";
    else if (getenv("OTAD_FIXTURE_GRUBCFG_COMMENT_SPOOF"))
        grubcfg =
            "# menuentry 'A' { linux /boot/vmlinuz root=PARTUUID=root-a-uuid dreamingwrt.slot=A }\n"
            "menuentry 'B' {\n"
            " linux /boot/vmlinuz root=PARTUUID=root-b-uuid dreamingwrt.slot=B\n}\n";
    else if (getenv("OTAD_FIXTURE_GRUBCFG_CROSS_ENTRY"))
        grubcfg =
            "menuentry 'A' {\n}\n"
            "linux /boot/vmlinuz root=PARTUUID=root-a-uuid dreamingwrt.slot=A\n"
            "menuentry 'B' {\n"
            " linux /boot/vmlinuz root=PARTUUID=root-b-uuid dreamingwrt.slot=B\n}\n";
    else
        grubcfg =
            "menuentry 'DreamingWrt slot A' --id dwrt_a {\n"
            " linux /boot/vmlinuz root=PARTUUID=root-a-uuid dreamingwrt.slot=A\n}\n"
            "menuentry 'DreamingWrt slot B' --id dwrt_b {\n"
            " linux /boot/vmlinuz root=PARTUUID=root-b-uuid dreamingwrt.slot=B\n}\n";
    if (fixture_write_grubenv(grubenv_path, grubenv) != 0 ||
        (!getenv("OTAD_FIXTURE_GRUBCFG_MISSING") &&
         fixture_write_file(grubcfg_path, grubcfg) != 0))
        return -1;
    fixture_active_mounts++;
    return 0;
}

static int fixture_umount(const char *target, int flags)
{
    char path[1024];
    int is_boot = strstr(target, "otad-boot-") != NULL;
    int fail = is_boot ? getenv("OTAD_FIXTURE_UMOUNT_FAIL") != NULL :
                         getenv("OTAD_FIXTURE_INACTIVE_UMOUNT_FAIL") != NULL;
    int detach_fail = fail && flags == MNT_DETACH &&
                      getenv("OTAD_FIXTURE_UMOUNT_DETACH_FAIL") != NULL;

    if (fail && flags != MNT_DETACH)
        return -1;
    snprintf(path, sizeof(path), "%s/boot/grub/grubenv", target);
    unlink(path);
    snprintf(path, sizeof(path), "%s/boot/grub/grub.cfg", target);
    unlink(path);
    snprintf(path, sizeof(path), "%s/boot/grub", target);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/boot/vmlinuz", target);
    unlink(path);
    snprintf(path, sizeof(path), "%s/boot", target);
    rmdir(path);
    if (!detach_fail && fixture_active_mounts > 0)
        fixture_active_mounts--;
    return detach_fail ? -1 : 0;
}

#define OTAD_TOPOLOGY_MOUNT fixture_mount
#define OTAD_TOPOLOGY_UMOUNT fixture_umount
#define OTAD_TOPOLOGY_MAJOR(value) ((unsigned int)((value) / 256))
#define OTAD_TOPOLOGY_MINOR(value) ((unsigned int)((value) % 256))

static int fixture_stat(const char *path, struct stat *st)
{
    const char *name;
    int disk = 0;
    int part = 0;

    if (lstat(path, st) != 0)
        return -1;
    name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (!strncmp(name, "sda", 3))
        disk = 8;
    else if (!strncmp(name, "sdb", 3))
        disk = 16;
    if (disk && name[3] >= '1' && name[3] <= '9' && !name[4]) {
        part = name[3] - '0';
        st->st_mode = (st->st_mode & 07777) | S_IFBLK;
        st->st_rdev = (dev_t)(disk * 256 + part);
    }
    return 0;
}

#define stat(path, st) fixture_stat((path), (st))

char *blkid_get_tag_value(blkid_cache cache, const char *tag, const char *path)
{
    const char *type = "";
    (void)cache;

    if (!strcmp(tag, "TYPE")) {
        if (getenv("OTAD_FIXTURE_ROOT_A_BLANK") && strstr(path, "sda2"))
            return NULL;
        if (getenv("OTAD_FIXTURE_ROOT_B_BLANK") && strstr(path, "sda3"))
            return NULL;
        if (strstr(path, "sda1") || strstr(path, "sdb1"))
            type = "vfat";
        else
            type = "ext4";
    }
    return type[0] ? strdup(type) : NULL;
}

const char *otad_json_str(struct json_object *o, const char *key, const char *def)
{
    struct json_object *value = NULL;

    if (!o || !json_object_object_get_ex(o, key, &value) ||
        !json_object_is_type(value, json_type_string))
        return def;
    return json_object_get_string(value);
}

int otad_json_bool(struct json_object *o, const char *key, int def)
{
    struct json_object *value = NULL;

    if (!o || !json_object_object_get_ex(o, key, &value))
        return def;
    return json_object_get_boolean(value) ? 1 : 0;
}

void otad_json_add_string(struct json_object *o, const char *key, const char *value)
{
    json_object_object_add(o, key, json_object_new_string(value ? value : ""));
}

#include "otad_topology.c"
#undef stat

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static int layout_contract(void)
{
    struct otad_ab_topology topology;
    struct json_object *firmware = json_object_new_object();
    struct json_object *layout = json_object_new_object();
    char error[128] = "";

    memset(&topology, 0, sizeof(topology));
    topology.root_a_size = topology.root_b_size = 2048ULL * 1024ULL * 1024ULL;
    topology.data_size = 4096ULL * 1024ULL * 1024ULL;
    json_object_object_add(layout, "schema", json_object_new_string(OTAD_AB_LAYOUT_SCHEMA));
    json_object_object_add(layout, "root_slots_equal_size", json_object_new_boolean(1));
    json_object_object_add(layout, "data_uses_remaining_space", json_object_new_boolean(1));
    json_object_object_add(layout, "min_slot_size_mib", json_object_new_int64(1024));
    json_object_object_add(layout, "min_data_size_mib", json_object_new_int64(2048));
    json_object_object_add(firmware, "ab_layout", layout);
    CHECK(otad_ab_topology_validate_release(&topology, firmware,
                                             error, sizeof(error)) == 0);
    json_object_object_add(layout, "schema", json_object_new_string("wrong"));
    CHECK(otad_ab_topology_validate_release(&topology, firmware,
                                             error, sizeof(error)) == -1);
    CHECK(!strcmp(error, "signed_ab_layout_incompatible"));
    json_object_object_add(layout, "schema", json_object_new_string(OTAD_AB_LAYOUT_SCHEMA));
    json_object_object_add(layout, "min_slot_size_mib", json_object_new_int64(4096));
    CHECK(otad_ab_topology_validate_release(&topology, firmware,
                                             error, sizeof(error)) == -1);
    CHECK(!strcmp(error, "signed_ab_layout_capacity_mismatch"));
    json_object_put(firmware);
    return 0;
}

int main(int argc, char **argv)
{
    struct otad_ab_topology topology;
    struct otad_ab_topology basic_topology;
    char error[128] = "";
    char basic_error[128] = "";
    int rc;

    CHECK(argc == 2);
    rc = otad_ab_topology_discover(&topology, error, sizeof(error));
    if (!strcmp(argv[1], "ok")) {
        int current_b = getenv("OTAD_FIXTURE_PENDING_B") != NULL ||
                        getenv("OTAD_FIXTURE_ACTIVE_B") != NULL;

        CHECK(rc == 0);
        CHECK(!strcmp(topology.current_slot, current_b ? "B" : "A"));
        CHECK(!strcmp(topology.inactive_slot, current_b ? "A" : "B"));
        CHECK(!strcmp(topology.parent_disk, "sda"));
        CHECK(strlen(topology.topology_digest) == 64);
        CHECK(!strcmp(topology.inactive_slot_state,
                      getenv("OTAD_FIXTURE_ROOT_B_BLANK") ?
                          "uninitialized_blank" : "initialized_ext4"));
        CHECK(topology.boot_state_verified == 1);
        CHECK(topology.slot_a_boot_entry_verified == 1);
        CHECK(topology.slot_b_boot_entry_verified == 1);
        CHECK(topology.inactive_slot_bootable_verified ==
              ((getenv("OTAD_FIXTURE_ROOT_B_BLANK") && !current_b) ||
               getenv("OTAD_FIXTURE_KERNEL_MISSING") ||
               getenv("OTAD_FIXTURE_KERNEL_EMPTY") ||
               getenv("OTAD_FIXTURE_KERNEL_SYMLINK") ||
               getenv("OTAD_FIXTURE_INACTIVE_MOUNT_FAIL") ? 0 : 1));
        CHECK(otad_ab_boot_state_readonly_verify(&topology, error,
                                                  sizeof(error)) == 0);
        CHECK(fixture_active_mounts == 0);
        CHECK(layout_contract() == 0);
    } else {
        CHECK(rc == -1);
        if (strcmp(error, argv[1]))
            fprintf(stderr, "expected error=%s actual=%s\n", argv[1], error);
        CHECK(!strcmp(error, argv[1]));
        if (!strncmp(argv[1], "bootloader_", 11) ||
            !strncmp(argv[1], "boot_partition_", 15)) {
            CHECK(otad_ab_topology_readonly_probe(
                      &basic_topology, basic_error,
                      sizeof(basic_error)) == 0);
            CHECK(!strcmp(basic_topology.current_slot, "A"));
            CHECK(!strcmp(basic_topology.inactive_slot, "B"));
            CHECK(basic_topology.boot_state_verified == 0);
            CHECK(basic_topology.topology_digest[0] == '\0');
        }
        if (!getenv("OTAD_FIXTURE_UMOUNT_DETACH_FAIL"))
            CHECK(fixture_active_mounts == 0);
    }
    return 0;
}
'''

PARTITIONS = {
    "sda1": ("DWRT_BOOT", "boot-uuid", "8", "1", "131072"),
    "sda2": ("DWRT_ROOT_A", "root-a-uuid", "8", "2", "4194304"),
    "sda3": ("DWRT_ROOT_B", "root-b-uuid", "8", "3", "4194304"),
    "sda4": ("DWRT_DATA", "data-uuid", "8", "4", "8388608"),
}


def write_partition(root: Path, name: str, values: tuple[str, ...], parent: str = "sda") -> None:
    label, partuuid, major, minor, sectors = values
    target = root / "sys/devices/pci0000:00/block" / parent / name
    target.mkdir(parents=True, exist_ok=True)
    (target / "partition").write_text("1\n", encoding="ascii")
    (target / "size").write_text(f"{sectors}\n", encoding="ascii")
    (target / "uevent").write_text(
        f"MAJOR={major}\nMINOR={minor}\nDEVNAME={name}\n"
        f"PARTNAME={label}\nPARTUUID={partuuid}\n",
        encoding="ascii",
    )
    (root / "dev" / name).touch()
    class_link = root / "sys/class/block" / name
    class_link.parent.mkdir(parents=True, exist_ok=True)
    class_link.symlink_to(target)
    uuid_link = root / "dev/disk/by-partuuid" / partuuid
    uuid_link.parent.mkdir(parents=True, exist_ok=True)
    uuid_link.symlink_to(root / "dev" / name)


def fixture(root: Path) -> None:
    for path in (root / "sys", root / "dev", root / "proc/self"):
        path.mkdir(parents=True, exist_ok=True)
    for name, values in PARTITIONS.items():
        write_partition(root, name, values)
    (root / "proc/cmdline").write_text(
        "root=PARTUUID=root-a-uuid dreamingwrt.slot=A quiet\n", encoding="ascii"
    )
    (root / "proc/self/mountinfo").write_text(
        "36 25 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n"
        "37 25 8:4 / /data rw,relatime - ext4 /dev/sda4 rw\n",
        encoding="ascii",
    )


def mutate(root: Path, case: str) -> str:
    if case == "cmdline_slot_mismatch":
        (root / "proc/cmdline").write_text(
            "root=PARTUUID=root-a-uuid dreamingwrt.slot=B\n", encoding="ascii")
        return "cmdline_slot_root_device_mismatch"
    if case == "cmdline_root_mismatch":
        (root / "proc/cmdline").write_text(
            "root=PARTUUID=root-b-uuid dreamingwrt.slot=A\n", encoding="ascii")
        return "cmdline_slot_root_device_mismatch"
    if case == "cmdline_slot_missing":
        (root / "proc/cmdline").write_text(
            "root=PARTUUID=root-a-uuid quiet\n", encoding="ascii")
        return "cmdline_slot_missing_or_ambiguous"
    if case == "cmdline_slot_duplicate":
        (root / "proc/cmdline").write_text(
            "root=PARTUUID=root-a-uuid dreamingwrt.slot=A dreamingwrt.slot=A\n",
            encoding="ascii")
        return "cmdline_slot_missing_or_ambiguous"
    if case == "cmdline_root_missing":
        (root / "proc/cmdline").write_text(
            "dreamingwrt.slot=A quiet\n", encoding="ascii")
        return "cmdline_root_partuuid_missing_or_ambiguous"
    if case == "cmdline_root_device":
        (root / "proc/cmdline").write_text(
            "root=/dev/sda2 dreamingwrt.slot=A\n", encoding="ascii")
        return "cmdline_root_partuuid_missing_or_ambiguous"
    if case == "cmdline_root_duplicate":
        (root / "proc/cmdline").write_text(
            "root=PARTUUID=root-a-uuid root=PARTUUID=root-a-uuid dreamingwrt.slot=A\n",
            encoding="ascii")
        return "cmdline_root_partuuid_missing_or_ambiguous"
    if case == "duplicate_label":
        values = ("DWRT_ROOT_A", "other-uuid", "8", "5", "4194304")
        write_partition(root, "sda5", values)
        return "ab_partlabel_missing_or_ambiguous"
    if case == "devno_rdev_mismatch":
        path = root / "sys/devices/pci0000:00/block/sda/sda3/uevent"
        path.write_text(path.read_text(encoding="ascii").replace(
            "MINOR=3", "MINOR=9"), encoding="ascii")
        return "ab_partlabel_missing_or_ambiguous"
    if case == "duplicate_partuuid":
        uevent = root / "sys/devices/pci0000:00/block/sda/sda3/uevent"
        uevent.write_text(uevent.read_text(encoding="ascii").replace(
            "PARTUUID=root-b-uuid", "PARTUUID=root-a-uuid"), encoding="ascii")
        return "ab_partuuid_missing_or_ambiguous"
    if case == "cross_disk":
        old = root / "sys/class/block/sda3"
        old.unlink()
        shutil.rmtree(root / "sys/devices/pci0000:00/block/sda/sda3")
        (root / "dev/sda3").unlink()
        (root / "dev/disk/by-partuuid/root-b-uuid").unlink()
        write_partition(root, "sdb1", ("DWRT_ROOT_B", "root-b-uuid", "16", "1", "4194304"), "sdb")
        return "ab_partitions_not_on_same_parent_disk"
    if case == "inactive_mounted":
        with (root / "proc/self/mountinfo").open("a", encoding="ascii") as handle:
            handle.write("38 25 8:3 / /mnt/inactive rw - ext4 /dev/sda3 rw\n")
        return "inactive_slot_is_mounted"
    if case == "data_mismatch":
        path = root / "proc/self/mountinfo"
        path.write_text(path.read_text(encoding="ascii").replace("8:4 / /data", "8:5 / /data"), encoding="ascii")
        return "data_mount_source_mismatch"
    if case == "duplicate_root_mount":
        with (root / "proc/self/mountinfo").open("a", encoding="ascii") as handle:
            handle.write("38 25 8:2 / / rw - ext4 /dev/sda2 rw\n")
        return "root_mount_topology_ambiguous"
    if case == "duplicate_data_mount":
        with (root / "proc/self/mountinfo").open("a", encoding="ascii") as handle:
            handle.write("38 25 8:4 / /data rw - ext4 /dev/sda4 rw\n")
        return "data_mount_missing_or_ambiguous"
    if case == "boot_mounted":
        with (root / "proc/self/mountinfo").open("a", encoding="ascii") as handle:
            handle.write("38 25 8:1 / /boot rw - vfat /dev/sda1 rw\n")
        return "boot_partition_already_mounted"
    if case == "current_slot_blkid_blank":
        return "current_slot_block_filesystem_mismatch"
    raise ValueError(case)


def select_root_b(root: Path) -> None:
    (root / "proc/cmdline").write_text(
        "root=PARTUUID=root-b-uuid dreamingwrt.slot=B quiet\n",
        encoding="ascii",
    )
    path = root / "proc/self/mountinfo"
    path.write_text(
        path.read_text(encoding="ascii").replace(
            "36 25 8:2 / /", "36 25 8:3 / /"
        ),
        encoding="ascii",
    )


def dependency_roots() -> tuple[Path, ...]:
    configured = os.environ.get("OTAD_TEST_DEP_ROOT", "")
    roots: list[Path] = []

    if configured:
        root = Path(configured)
        roots.append(root / "usr" if (root / "usr/include").is_dir() else root)
    roots.extend((
        Path("/opt/homebrew"),
        Path("/usr/local"),
        Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c/0.19"),
    ))
    return tuple(roots)


def find_dependencies() -> tuple[Path, Path, Path, Path]:
    roots = dependency_roots()
    for root in roots:
        json_header = root / "include/json-c/json.h"
        json_library = root / "lib/libjson-c.a"
        if not json_header.is_file() or not json_library.is_file():
            continue
        crypto_roots = (root, Path("/opt/homebrew/opt/openssl@3"), Path("/usr/local/opt/openssl@3"))
        for crypto_root in crypto_roots:
            if (crypto_root / "include/openssl/evp.h").is_file() and \
                    ((crypto_root / "lib/libcrypto.a").is_file() or
                     (crypto_root / "lib/libcrypto.so").is_file() or
                     (crypto_root / "lib/libcrypto.dylib").is_file()):
                return (root / "include", json_library,
                        crypto_root / "include", crypto_root / "lib")
    raise RuntimeError("json-c and OpenSSL development files not found")


def main() -> None:
    json_include, json_library, crypto_include, crypto_library_dir = find_dependencies()
    with tempfile.TemporaryDirectory(prefix="otad-topology-runtime-") as td:
        temp = Path(td)
        fixture_root = temp / "fixture"
        stub_root = temp / "stubs"
        for name, content in STUBS.items():
            path = stub_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="ascii")
        harness = temp / "harness.c"
        harness.write_text(HARNESS, encoding="ascii")
        binary = temp / "harness"
        command = [
            os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
            "-Werror=implicit-function-declaration", "-I", str(stub_root),
            "-I", str(json_include),
            "-I", str(crypto_include),
            "-I", str(ROOT / "src/otad"),
            f'-DOTAD_TOPOLOGY_SYS_BLOCK_DIR="{fixture_root / "sys/class/block"}"',
            f'-DOTAD_TOPOLOGY_DEV_DIR="{fixture_root / "dev"}"',
            f'-DOTAD_TOPOLOGY_PARTUUID_DIR="{fixture_root / "dev/disk/by-partuuid"}"',
            f'-DOTAD_TOPOLOGY_CMDLINE_PATH="{fixture_root / "proc/cmdline"}"',
            f'-DOTAD_TOPOLOGY_MOUNTINFO_PATH="{fixture_root / "proc/self/mountinfo"}"',
            str(harness), str(json_library), "-L", str(crypto_library_dir),
            "-lcrypto", "-o", str(binary),
        ]
        subprocess.run(command, check=True)

        run_env = os.environ.copy()
        current_library_path = run_env.get("LD_LIBRARY_PATH", "")
        run_env["LD_LIBRARY_PATH"] = str(crypto_library_dir) + (
            f":{current_library_path}" if current_library_path else ""
        )

        fixture(fixture_root)
        subprocess.run([str(binary), "ok"], check=True, env=run_env)
        blank_env = run_env.copy()
        blank_env["OTAD_FIXTURE_ROOT_B_BLANK"] = "1"
        subprocess.run([str(binary), "ok"], check=True, env=blank_env)
        for env_key in ("OTAD_FIXTURE_ACTIVE_B", "OTAD_FIXTURE_PENDING_B"):
            shutil.rmtree(fixture_root)
            fixture(fixture_root)
            select_root_b(fixture_root)
            boot_b_env = run_env.copy()
            boot_b_env[env_key] = "1"
            subprocess.run([str(binary), "ok"], check=True, env=boot_b_env)
        for case in (
            "cmdline_slot_mismatch", "cmdline_root_mismatch",
            "cmdline_slot_missing", "cmdline_slot_duplicate",
            "cmdline_root_missing", "cmdline_root_device",
            "cmdline_root_duplicate", "duplicate_label",
            "duplicate_partuuid", "devno_rdev_mismatch", "cross_disk",
            "inactive_mounted",
            "data_mismatch", "duplicate_root_mount", "duplicate_data_mount",
            "boot_mounted",
        ):
            shutil.rmtree(fixture_root)
            fixture(fixture_root)
            expected = mutate(fixture_root, case)
            subprocess.run([str(binary), expected], check=True, env=run_env)
        shutil.rmtree(fixture_root)
        fixture(fixture_root)
        active_blank_env = run_env.copy()
        active_blank_env["OTAD_FIXTURE_ROOT_A_BLANK"] = "1"
        subprocess.run([str(binary), "current_slot_block_filesystem_mismatch"],
                       check=True, env=active_blank_env)
        for env_key, expected in (
            ("OTAD_FIXTURE_GRUBENV_INVALID", "bootloader_grubenv_invalid"),
            ("OTAD_FIXTURE_GRUBENV_BAD_HEADER", "bootloader_grubenv_invalid"),
            ("OTAD_FIXTURE_GRUBENV_SHORT", "bootloader_grubenv_invalid"),
            ("OTAD_FIXTURE_GRUBENV_EMPTY_TRIES", "bootloader_grubenv_invalid"),
            ("OTAD_FIXTURE_GRUBENV_SIGNED_TRIES", "bootloader_grubenv_invalid"),
            ("OTAD_FIXTURE_GRUBCFG_MISMATCH", "bootloader_slot_entry_mismatch"),
            ("OTAD_FIXTURE_GRUBCFG_COMMENT_SPOOF", "bootloader_slot_entry_mismatch"),
            ("OTAD_FIXTURE_GRUBCFG_CROSS_ENTRY", "bootloader_slot_entry_mismatch"),
            ("OTAD_FIXTURE_GRUBCFG_MISSING", "bootloader_state_files_unavailable"),
            ("OTAD_FIXTURE_PENDING_ACTIVE", "bootloader_pending_active_slot_conflict"),
            ("OTAD_FIXTURE_TRIES_WITHOUT_PENDING", "bootloader_tries_without_pending_slot"),
        ):
            shutil.rmtree(fixture_root)
            fixture(fixture_root)
            case_env = run_env.copy()
            case_env[env_key] = "1"
            subprocess.run([str(binary), expected], check=True, env=case_env)
        for env_key in (
            "OTAD_FIXTURE_KERNEL_MISSING", "OTAD_FIXTURE_KERNEL_EMPTY",
            "OTAD_FIXTURE_KERNEL_SYMLINK", "OTAD_FIXTURE_INACTIVE_MOUNT_FAIL",
            "OTAD_FIXTURE_UMOUNT_FAIL", "OTAD_FIXTURE_INACTIVE_UMOUNT_FAIL",
        ):
            shutil.rmtree(fixture_root)
            fixture(fixture_root)
            case_env = run_env.copy()
            case_env[env_key] = "1"
            subprocess.run([str(binary), "ok"], check=True, env=case_env)
        for env_key, expected in (
            ("OTAD_FIXTURE_UMOUNT_FAIL", "bootloader_readonly_unmount_failed"),
            ("OTAD_FIXTURE_INACTIVE_UMOUNT_FAIL", "inactive_slot_readonly_unmount_failed"),
        ):
            shutil.rmtree(fixture_root)
            fixture(fixture_root)
            case_env = run_env.copy()
            case_env[env_key] = "1"
            case_env["OTAD_FIXTURE_UMOUNT_DETACH_FAIL"] = "1"
            subprocess.run([str(binary), expected], check=True, env=case_env)
        shutil.rmtree(fixture_root)
        fixture(fixture_root)
        blank_valid_env = run_env.copy()
        blank_valid_env["OTAD_FIXTURE_ROOT_B_BLANK"] = "1"
        blank_valid_env["OTAD_FIXTURE_BLANK_B_VALID"] = "1"
        subprocess.run([str(binary), "bootloader_blank_slot_marked_valid"],
                       check=True, env=blank_valid_env)
    print("ok: executable A/B topology fixtures cover dev_t binding, strict GRUB scopes, inactive kernel evidence, and cleanup")


if __name__ == "__main__":
    main()
