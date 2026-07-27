#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "jmx_system.c"

HARNESS = r'''
#define JMX_SYSTEM_MOUNT_CONTRACT_ONLY 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "jmx_system.h"

ssize_t jmx_system_mount_contract_write(int fd, const void *buf, size_t len) {
    return write(fd, buf, len);
}
int jmx_system_mount_contract_fsync(int fd) { return fsync(fd); }
void jmx_system_mount_contract_before_readback(const char *path) { (void)path; }

static void mkdir_p(const char *path) {
    char buf[4096], *p;
    assert(snprintf(buf, sizeof(buf), "%s", path) < (int)sizeof(buf));
    for (p = buf + 1; *p; p++) if (*p == '/') { *p = 0; mkdir(buf, 0755); *p = '/'; }
    assert(mkdir(buf, 0755) == 0 || errno == EEXIST);
}

static void write_text(const char *path, const char *text, int mode) {
    FILE *fp = fopen(path, "w");
    assert(fp); assert(fputs(text, fp) >= 0); assert(fclose(fp) == 0);
    assert(chmod(path, mode) == 0);
}

static void add_block(const char *root, const char *disk, const char *name,
                      const char *devno, int partition) {
    char target[4096], link_path[4096], file[4096], devnode[4096];
    if (partition)
        snprintf(target, sizeof(target), "%s/sys/devices/block/%s/%s", root, disk, name);
    else
        snprintf(target, sizeof(target), "%s/sys/devices/block/%s", root, name);
    mkdir_p(target);
    snprintf(file, sizeof(file), "%s/dev", target); write_text(file, devno, 0644);
    if (partition) { snprintf(file, sizeof(file), "%s/partition", target); write_text(file, "1\n", 0644); }
    snprintf(link_path, sizeof(link_path), "%s/sys/class/block/%s", root, name);
    assert(symlink(target, link_path) == 0);
    snprintf(devnode, sizeof(devnode), "%s/dev/%s", root, name); write_text(devnode, "", 0644);
}

static int probe(const struct jmx_system_mount_probe *p, size_t n, const char *name) {
    size_t i; for (i = 0; i < n; i++) if (!strcmp(p[i].name, name)) return (int)i;
    return -1;
}

static struct jmx_system_mount_spec spec(const char *source, const char *target) {
    struct jmx_system_mount_spec s; memset(&s, 0, sizeof(s));
    snprintf(s.source, sizeof(s.source), "%s", source);
    snprintf(s.target, sizeof(s.target), "%s", target);
    snprintf(s.fstype, sizeof(s.fstype), "ext4");
    snprintf(s.options, sizeof(s.options), "rw,noatime,nodev,nosuid,noexec");
    s.enabled = 1; return s;
}

int main(int argc, char **argv) {
    char path[4096], sysdir[4096], devroot[4096], uuiddir[4096], labeldir[4096];
    char mountinfo[4096], swaps[4096], blkid[4096], fstab[4096], mounts[4096];
    char mount_bin[4096], umount_bin[4096], mnt_root[4096], script[16384], original[128];
    struct jmx_system_mount_discovery_opts d;
    struct jmx_system_mount_probe p[32]; size_t n = 0;
    struct jmx_system_mount_txn_opts o; struct jmx_system_mount_txn_result tx;
    struct jmx_system_mount_batch_result br; struct jmx_system_mount_spec specs[2];
    FILE *fp; int a, b, c, whole, slow, huge;
    assert(argc == 2);
    snprintf(path, sizeof(path), "%s/sys/class/block", argv[1]); mkdir_p(path);
    snprintf(path, sizeof(path), "%s/sys/devices/block", argv[1]); mkdir_p(path);
    snprintf(devroot, sizeof(devroot), "%s/dev", argv[1]); mkdir_p(devroot);
    snprintf(uuiddir, sizeof(uuiddir), "%s/dev/disk/by-uuid", argv[1]); mkdir_p(uuiddir);
    snprintf(labeldir, sizeof(labeldir), "%s/dev/disk/by-label", argv[1]); mkdir_p(labeldir);
    add_block(argv[1], "sda", "sda", "8:0\n", 0);
    add_block(argv[1], "sda", "sda1", "8:1\n", 1);
    add_block(argv[1], "sdb", "sdb1", "8:17\n", 1);
    add_block(argv[1], "sdc", "sdc1", "8:33\n", 1);
    add_block(argv[1], "sdd", "sdd", "8:48\n", 0);
    add_block(argv[1], "sde", "sde", "8:64\n", 0);
    add_block(argv[1], "sdf", "sdf", "8:80\n", 0);
    snprintf(sysdir, sizeof(sysdir), "%s/sys/class/block", argv[1]);
    snprintf(mountinfo, sizeof(mountinfo), "%s/mountinfo", argv[1]);
    snprintf(path, sizeof(path),
             "31 22 0:42 / /overlay rw - overlay %s/sda1 rw\n", devroot);
    write_text(mountinfo, path, 0644);
    snprintf(swaps, sizeof(swaps), "%s/swaps", argv[1]); write_text(swaps, "Filename Type Size Used Priority\n", 0644);
    snprintf(blkid, sizeof(blkid), "%s/blkid", argv[1]);
    snprintf(script, sizeof(script),
        "#!/bin/sh\ncase \"$3\" in\n"
        "*/sda1) echo UUID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa; echo TYPE=ext4;;\n"
        "*/sdb1|*/sdc1) echo LABEL=DUP; echo TYPE=ext4;;\n"
        "*/sdd) echo UUID=dddddddd-dddd-dddd-dddd-dddddddddddd; echo TYPE=ext4;;\n"
        "*/sde) sleep 2; echo UUID=eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee; echo TYPE=ext4;;\n"
        "*/sdf) dd if=/dev/zero bs=3000 count=1 2>/dev/null | tr '\\000' x;;\n"
        "*) exit 2;; esac\n");
    write_text(blkid, script, 0755);
    memset(&d, 0, sizeof(d)); d.sys_class_block = sysdir; d.dev_root = devroot;
    d.by_uuid_dir = uuiddir; d.by_label_dir = labeldir; d.mountinfo_path = mountinfo;
    d.swaps_path = swaps; d.blkid_bin = blkid; d.blkid_timeout_ms = 500;
    d.trust_fixture_block_devices = 1;
    assert(jmx_system_mount_discover(&d, p, 32, &n, path, sizeof(path)) == 0);
    a = probe(p,n,"sda1"); b = probe(p,n,"sdb1"); c = probe(p,n,"sdc1");
    whole = probe(p,n,"sdd"); slow = probe(p,n,"sde"); huge = probe(p,n,"sdf");
    assert(a >= 0 && p[a].system_disk && !p[a].config_eligible);
    assert(b >= 0 && c >= 0 && !strcmp(p[b].excluded_reason,"duplicate_stable_source") &&
           !strcmp(p[c].excluded_reason,"duplicate_stable_source"));
    assert(whole >= 0 && p[whole].config_eligible && p[whole].mount_eligible);
    assert(slow >= 0 && !strcmp(p[slow].excluded_reason,"blkid_timeout"));
    assert(huge >= 0 && !strcmp(p[huge].excluded_reason,"blkid_output_oversize"));

    snprintf(fstab, sizeof(fstab), "%s/fstab", argv[1]); write_text(fstab, "# original\n", 0600);
    specs[0] = spec("UUID=11111111-1111-1111-1111-111111111111", "/mnt/one");
    specs[1] = spec("UUID=22222222-2222-2222-2222-222222222222", "/mnt/two");
    memset(&o, 0, sizeof(o)); o.fstab_path = fstab;
    assert(jmx_system_mount_save_batch(specs, 2, &o, &tx) == 0 && tx.changed);
    fp = fopen(fstab,"r"); assert(fp); assert(fread(script,1,sizeof(script)-1,fp)>0); fclose(fp);
    assert(strstr(script,"UUID=11111111") && strstr(script,"UUID=22222222"));
    write_text(fstab, "# original\n", 0600);

    snprintf(mounts, sizeof(mounts), "%s/mounts", argv[1]); write_text(mounts, "", 0644);
    snprintf(mnt_root, sizeof(mnt_root), "%s/mnt", argv[1]); mkdir_p(mnt_root);
    snprintf(mount_bin, sizeof(mount_bin), "%s/fake-mount", argv[1]);
    snprintf(script, sizeof(script),
        "#!/bin/sh\ntarget=\"$6\"\n[ \"$target\" = /mnt/two ] && exit 9\n"
        "echo \"$5 $target ext4 rw 0 0\" >> '%s'\n", mounts);
    write_text(mount_bin, script, 0755);
    snprintf(umount_bin, sizeof(umount_bin), "%s/fake-umount", argv[1]);
    snprintf(script, sizeof(script),
        "#!/bin/sh\ngrep -v \" $1 \" '%s' > '%s.new' || true\nmv '%s.new' '%s'\n",
        mounts, mounts, mounts, mounts);
    write_text(umount_bin, script, 0755);
    memset(&o, 0, sizeof(o)); o.fstab_path=fstab; o.mount_bin=mount_bin; o.umount_bin=umount_bin;
    o.mounts_path=mounts; o.mnt_root=mnt_root; o.execute_mount=1;
    assert(jmx_system_mount_apply_batch(specs,2,&o,&br) != 0);
    assert(br.failed_index == 1 && br.rollback_attempted && br.rollback_succeeded &&
           br.config_rollback_succeeded && br.mounts_rollback_succeeded);
    fp=fopen(fstab,"r"); assert(fp); assert(fgets(original,sizeof(original),fp)); fclose(fp);
    assert(!strcmp(original,"# original\n"));
    fp=fopen(mounts,"r"); assert(fp); assert(fgetc(fp)==EOF); fclose(fp);
    snprintf(path,sizeof(path),"%s/one",mnt_root); assert(access(path,F_OK)!=0);
    snprintf(path,sizeof(path),"%s/two",mnt_root); assert(access(path,F_OK)!=0);
    puts("system_mount_batch_discovery_contract: PASS");
    return 0;
}
'''


def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        harness = Path(td) / "harness.c"
        exe = Path(td) / "harness"
        harness.write_text(HARNESS, encoding="utf-8")
        compile_flags = ["-Wall", "-Wextra", "-Werror"]
        if sys.platform.startswith("linux"):
            # GCC 16 cannot infer the short tempfile paths used by this fixture.
            compile_flags.append("-Wno-format-truncation")
        subprocess.run([
            "cc", *compile_flags,
            "-DJMX_SYSTEM_MOUNT_CONTRACT_ONLY=1", "-DJMX_SYSTEM_MOUNT_TEST_HOOKS=1",
            "-I", str(ROOT), str(harness), str(SRC), "-o", str(exe),
        ], check=True)
        fixture = Path(td) / "fixture"
        fixture.mkdir()
        subprocess.run([str(exe), str(fixture)], check=True)


if __name__ == "__main__":
    main()
