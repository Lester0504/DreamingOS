#!/usr/bin/env python3
import os
import subprocess
import tempfile
from pathlib import Path

from otad_test_deps import find_host_dependencies


ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    ROOT / "src/otad/otad_common.c",
    ROOT / "src/otad/otad_db.c",
    ROOT / "src/otad/otad_firmware.c",
    ROOT / "src/otad/otad_hot.c",
    ROOT / "src/otad/otad_status.c",
    ROOT / "src/otad/otad_trust.c",
    ROOT / "src/otad/otad_topology.c",
]

STUBS = {
    "libubox/blobmsg.h": r'''
#pragma once
#include <stdbool.h>
#include <stddef.h>
struct blob_attr { int unused; };
struct blob_buf { void *head; };
struct blobmsg_policy { const char *name; int type; };
enum { BLOBMSG_TYPE_UNSPEC = 0 };
void blob_buf_init(struct blob_buf *, int);
void blob_buf_free(struct blob_buf *);
int blobmsg_add_json_from_string(struct blob_buf *, const char *);
''',
    "libubox/blobmsg_json.h": r'''
#pragma once
#include <stdbool.h>
struct blob_attr;
char *blobmsg_format_json(struct blob_attr *, bool);
''',
    "libubox/uloop.h": r'''
#pragma once
#include <sys/types.h>
struct uloop_timeout { void (*cb)(struct uloop_timeout *); };
struct uloop_process {
    pid_t pid;
    void (*cb)(struct uloop_process *, int);
};
int uloop_timeout_set(struct uloop_timeout *, int);
int uloop_process_add(struct uloop_process *);
''',
    "libubox/utils.h": r'''
#pragma once
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
''',
    "libubus.h": r'''
#pragma once
#include <stdint.h>
struct ubus_context;
struct ubus_request_data;
#define UBUS_STATUS_OK 0
struct ubus_context *ubus_connect(const char *path);
int ubus_lookup_id(struct ubus_context *, const char *, uint32_t *);
int ubus_invoke(struct ubus_context *, uint32_t, const char *, void *,
                void *, void *, int);
void ubus_free(struct ubus_context *);
''',
    "linux/fs.h": r'''
#pragma once
#include <sys/ioctl.h>
#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, unsigned long long)
#endif
''',
    "blkid/blkid.h": r'''
#pragma once
typedef void *blkid_cache;
char *blkid_get_tag_value(blkid_cache, const char *, const char *);
''',
    "sys/mount.h": r'''
#pragma once
#define MS_RDONLY 1UL
#define MS_NOSUID 2UL
#define MS_NODEV 4UL
#define MS_NOEXEC 8UL
#define MS_NOATIME 1024UL
#define MNT_DETACH 2
int mount(const char *, const char *, const char *, unsigned long, const void *);
int umount(const char *);
int umount2(const char *, int);
''',
    "unistd.h": r'''
#pragma once
#include_next <unistd.h>
int syncfs(int);
''',
}


def main() -> None:
    cc = os.environ.get("CC", "cc")
    deps = find_host_dependencies(
        ROOT, require_json_library=False, require_crypto_library=False
    )
    with tempfile.TemporaryDirectory() as td:
        stub_root = Path(td)
        for name, content in STUBS.items():
            path = stub_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="ascii")
        cmd = [
            cc,
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror=implicit-function-declaration",
            "-Werror=unused-parameter",
            "-Werror=unused-function",
            "-fsyntax-only",
            "-I",
            str(stub_root),
            "-I",
            str(deps.json_include),
            "-I",
            str(deps.openssl_include),
            "-I",
            str(ROOT / "src/otad"),
            *map(str, SOURCES),
        ]
        if os.uname().sysname == "Linux":
            cmd.insert(4, "-Werror=format-truncation")
        subprocess.run(cmd, check=True)
    print("ok: otad changed sources pass host syntax check")


if __name__ == "__main__":
    main()
