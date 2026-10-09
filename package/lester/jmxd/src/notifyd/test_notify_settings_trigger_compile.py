#!/usr/bin/env python3
"""Compile the changed notifyd translation units with minimal OpenWrt header stubs."""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

STUBS = {
    "libubox/blobmsg.h": r"""
#pragma once
struct blob_attr;
struct blob_buf { void *head; };
struct blobmsg_policy { const char *name; int type; };
#define BLOBMSG_TYPE_UNSPEC 0
void blob_buf_init(struct blob_buf *, int);
void blob_buf_free(struct blob_buf *);
int blobmsg_add_json_from_string(struct blob_buf *, const char *);
""",
    "libubox/blobmsg_json.h": r"""
#pragma once
#include <stdbool.h>
struct blob_attr;
char *blobmsg_format_json(struct blob_attr *, bool);
""",
    "libubox/uloop.h": r"""
#pragma once
struct uloop_timeout { void (*cb)(struct uloop_timeout *); };
""",
    "libubox/utils.h": r"""
#pragma once
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
""",
    "libubus.h": r"""
#pragma once
#include <libubox/blobmsg.h>
#include <libubox/utils.h>
struct ubus_context;
struct ubus_request_data;
struct ubus_object;
typedef int (*ubus_handler_t)(struct ubus_context *, struct ubus_object *,
                              struct ubus_request_data *, const char *,
                              struct blob_attr *);
struct ubus_method {
    const char *name;
    ubus_handler_t handler;
    const struct blobmsg_policy *policy;
    int n_policy;
};
struct ubus_object_type { const char *name; };
struct ubus_object {
    const char *name;
    struct ubus_object_type *type;
    const struct ubus_method *methods;
    int n_methods;
};
#define UBUS_METHOD(n, h, p) { .name = (n), .handler = (h), .policy = (p), .n_policy = ARRAY_SIZE(p) }
#define UBUS_OBJECT_TYPE(n, m) { .name = (n) }
#define UBUS_STATUS_OK 0
#define UBUS_STATUS_INVALID_ARGUMENT 2
#define UBUS_STATUS_NOT_FOUND 4
#define UBUS_STATUS_UNKNOWN_ERROR 5
struct ubus_context *ubus_connect(const char *);
void ubus_add_uloop(struct ubus_context *);
int ubus_add_object(struct ubus_context *, struct ubus_object *);
void ubus_remove_object(struct ubus_context *, struct ubus_object *);
void ubus_free(struct ubus_context *);
int ubus_send_reply(struct ubus_context *, struct ubus_request_data *, void *);
""",
}


def main() -> None:
    flags = subprocess.check_output(
        ["pkg-config", "--cflags", "json-c", "sqlite3"], text=True
    ).strip()
    env = os.environ.copy()
    env.pop("LD_LIBRARY_PATH", None)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for relative, content in STUBS.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        for relative in ("src/notifyd/notifyd_db.c", "src/notifyd/notifyd_ubus.c"):
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=gnu11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsyntax-only",
                    f"-I{root}",
                    f"-I{ROOT / 'src'}",
                    f"-I{ROOT / 'src/notifyd'}",
                    *shlex.split(flags),
                    str(ROOT / relative),
                ],
                check=True,
                env=env,
            )
    print("ok - notifyd settings/trigger translation units pass strict syntax compile")


if __name__ == "__main__":
    main()
