#!/usr/bin/env python3
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

static void write_text(const char *path, const char *text) {
    FILE *fp = fopen(path, "w");
    assert(fp); assert(fputs(text, fp) >= 0); assert(fclose(fp) == 0);
}

int main(int argc, char **argv) {
    char mountinfo[4096], fstab[4096], target[4096], escaped[4096], text[16384], err[160] = {0};
    struct jmx_system_mount_runtime_entry runtime[16];
    struct jmx_system_mount_config_entry config[16];
    struct jmx_system_mount_read_opts opts;
    size_t runtime_count = 0, config_count = 0, i;
    int found_bind = 0, found_configured_runtime = 0;

    assert(argc == 2);
    snprintf(target, sizeof(target), "%s/mounted space", argv[1]);
    assert(mkdir(target, 0755) == 0);
    snprintf(escaped, sizeof(escaped), "%s/mounted\\040space", argv[1]);
    snprintf(mountinfo, sizeof(mountinfo), "%s/mountinfo", argv[1]);
    snprintf(text, sizeof(text),
        "17 1 8:1 / / rw,noatime - ext4 /dev/root rw\n"
        "18 17 0:23 / %s rw,nosuid,nodev - tmpfs tmpfs rw\n"
        "19 17 8:5 /persist/data /mnt/codex-read-contract rw,noatime - ext4 /dev/sda5 rw\n"
        "20 17 8:5 / /data rw,noatime - ext4 /dev/sda5 rw\n"
        "21 17 8:5 /persist/etc/config /etc/config rw,noatime - ext4 /dev/sda5 rw\n"
        "22 17 8:5 /persist/data/inner /mnt/codex-read-contract/inner rw,noatime - ext4 /dev/sda5 rw\n"
        "23 17 8:6 /persist/other /mnt/other-device rw,noatime - ext4 /dev/sda6 rw\n",
        escaped);
    write_text(mountinfo, text);
    snprintf(fstab, sizeof(fstab), "%s/fstab", argv[1]);
    snprintf(text, sizeof(text),
        "config 'global'\n\toption auto_mount '1'\n\n"
        "config 'mount' 'safe'\n"
        "\toption target '/mnt/codex-read-contract'\n"
        "\toption device '/dev/sda5'\n"
        "\toption fstype 'ext4'\n"
        "\toption options 'rw,noatime,nodev,nosuid,noexec'\n"
        "\toption enabled '0'\n"
        "\toption enabled_fsck '1'\n\n"
        "config 'mount' 'system-root'\n"
        "\toption target '/'\n"
        "\toption uuid '22222222-2222-2222-2222-222222222222'\n"
        "\toption enabled '0'\n");
    write_text(fstab, text);
    memset(&opts, 0, sizeof(opts));
    opts.mountinfo_path = mountinfo; opts.fstab_path = fstab;
    assert(jmx_system_mount_read(&opts, runtime, 16, &runtime_count,
                                 config, 16, &config_count, err, sizeof(err)) == 0);
    assert(runtime_count == 7 && config_count == 2);
    assert(!strcmp(runtime[0].fstype, "ext4") && !strcmp(runtime[0].target, "/"));
    assert(!strcmp(runtime[1].target, target) && !strcmp(runtime[1].fstype, "tmpfs"));
    assert(runtime[1].stat_ok && runtime[1].size_bytes > 0);
    for (i = 0; i < runtime_count; i++) {
        if (runtime[i].bind_mount) {
            found_bind = 1;
            assert(strchr(runtime[i].source, '[') != NULL);
        }
        if (runtime[i].configured) found_configured_runtime = 1;
    }
    assert(found_bind && found_configured_runtime);
    /*
     * 绑定挂载必须按 mountinfo 的 root 字段置位，且能追溯到宿主挂载点。
     * 判据是同设备上 root 为最长前缀的那条，所以嵌套绑定挂载的宿主是上一层绑定挂载，
     * 而不是整卷挂载 —— 这一条同时挡住"拿整卷挂载一律当宿主"的偷懒实现。
     */
    {
        const struct jmx_system_mount_runtime_entry *whole = NULL, *bind_data = NULL,
                                                   *bind_cfg = NULL, *nested = NULL,
                                                   *other_dev = NULL;

        for (i = 0; i < runtime_count; i++) {
            if (!strcmp(runtime[i].target, "/data")) whole = &runtime[i];
            else if (!strcmp(runtime[i].target, "/mnt/codex-read-contract")) bind_data = &runtime[i];
            else if (!strcmp(runtime[i].target, "/etc/config")) bind_cfg = &runtime[i];
            else if (!strcmp(runtime[i].target, "/mnt/codex-read-contract/inner")) nested = &runtime[i];
            else if (!strcmp(runtime[i].target, "/mnt/other-device")) other_dev = &runtime[i];
        }
        assert(whole && bind_data && bind_cfg && nested && other_dev);
        /* root 为 "/" 的整卷挂载不是绑定挂载，也没有宿主。 */
        assert(!whole->bind_mount && !whole->bind_host_target[0]);
        /* root 为 /persist/... 的都是绑定挂载。 */
        assert(bind_data->bind_mount && bind_cfg->bind_mount && nested->bind_mount);
        /* 同设备的整卷挂载是一层绑定挂载的宿主。 */
        assert(!strcmp(bind_data->bind_host_target, "/data"));
        assert(!strcmp(bind_cfg->bind_host_target, "/data"));
        /* 嵌套绑定挂载的宿主是最长前缀那条，不是 /data。 */
        assert(!strcmp(nested->bind_host_target, "/mnt/codex-read-contract"));
        /* 宿主判定不得跨设备：8:6 上没有整卷挂载，故留空。 */
        assert(other_dev->bind_mount && !other_dev->bind_host_target[0]);
        /* 绑定挂载与宿主共享同一份容量数字，这是 capacity_is_host_filesystem 的由来。 */
        assert(bind_cfg->size_bytes == 0 || bind_cfg->size_bytes == whole->size_bytes);
    }
    assert(!strcmp(config[0].section, "safe"));
    assert(!strcmp(config[0].source, "/dev/sda5"));
    assert(!strcmp(config[0].fstype, "ext4"));
    assert(!config[0].enabled && config[0].check_fs && config[0].mounted && config[0].editable);
    assert(!strcmp(config[1].section, "system-root"));
    assert(!strcmp(config[1].fstype, "auto"));
    assert(!config[1].mounted && !config[1].editable);
    puts("system_mount_read_contract: PASS");
    return 0;
}
'''


def main() -> None:
    source = SRC.read_text(encoding="utf-8")
    assert "df -P" not in source
    with tempfile.TemporaryDirectory() as td:
        harness = Path(td) / "harness.c"
        binary = Path(td) / "harness"
        fixture = Path(td) / "fixture"
        fixture.mkdir()
        harness.write_text(HARNESS, encoding="utf-8")
        flags = ["-Wall", "-Wextra", "-Werror"]
        if sys.platform.startswith("linux"):
            flags.append("-Wno-format-truncation")
        subprocess.run([
            "cc", *flags, "-DJMX_SYSTEM_MOUNT_CONTRACT_ONLY=1",
            "-DJMX_SYSTEM_MOUNT_TEST_HOOKS=1", "-I", str(ROOT),
            str(harness), str(SRC), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary), str(fixture)], check=True)


if __name__ == "__main__":
    main()
