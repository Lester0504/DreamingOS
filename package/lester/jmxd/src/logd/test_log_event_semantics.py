#!/usr/bin/env python3
"""Trusted-source log classification fixtures for semantic log events."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
COLLECTORS = ROOT / "src/logd/logd_collectors.c"
EVENT_SEMANTICS = ROOT / "src/event_semantics.c"


def c_function(source: str, marker: str) -> str:
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    i = brace
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
        elif block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
        elif ch == "/" and nxt == "/":
            line_comment = True
            i += 1
        elif ch == "/" and nxt == "*":
            block_comment = True
            i += 1
        elif ch in ('"', "'"):
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1]
        i += 1
    raise AssertionError(f"unterminated C function: {marker}")


def test_trusted_log_classification_fixtures() -> None:
    source = COLLECTORS.read_text(encoding="utf-8")
    helper = c_function(source, "static void logd_auth_detail_token(")
    classify = c_function(source, "static void logd_line_classify(")
    business = c_function(source, "static int logd_business_line(")
    ftp = c_function(source, "static int logd_ftp_line(")
    compiler = shutil.which("cc") or shutil.which("clang")
    assert compiler, "a C compiler is required"
    cflags = subprocess.check_output(
        ["pkg-config", "--cflags", "json-c"], text=True
    ).split()
    libs = subprocess.check_output(
        ["pkg-config", "--libs", "json-c"], text=True
    ).split()
    harness = r'''
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <json-c/json.h>

static int logd_contains_ci(const char *s, const char *needle)
{
    size_t needle_len;
    if (!s || !needle || !needle[0]) return 0;
    needle_len = strlen(needle);
    for (; *s; s++)
        if (!strncasecmp(s, needle, needle_len)) return 1;
    return 0;
}

#include "event_semantics.h"
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
static const char *logd_json_str(struct json_object *o, const char *k, const char *fallback) {
    struct json_object *v = NULL;
    return json_object_object_get_ex(o,k,&v) && json_object_is_type(v,json_type_string) ? json_object_get_string(v) : fallback;
}
__HELPER__
__BUSINESS__
__FTP__
__CLASSIFY__

static const char *field(struct json_object *detail, const char *key)
{
    struct json_object *value = NULL;
    if (!json_object_object_get_ex(detail, key, &value) || !value)
        return "";
    return json_object_get_string(value);
}

static int check(const char *name, const char *line, int kernel,
                 const char *program, const char *facility,
                 const char *category_expected, const char *event_expected,
                 const char *user_expected, const char *ip_expected,
                 const char *result_expected)
{
    const char *category = NULL;
    const char *event = NULL;
    struct json_object *detail = json_object_new_object();
    int failed = 0;

    logd_line_classify(line, kernel, program, facility, &category, &event, detail);
    if (strcmp(category, category_expected) || strcmp(event, event_expected) ||
        strcmp(field(detail, "username"), user_expected) ||
        strcmp(field(detail, "source_ip"), ip_expected) ||
        strcmp(field(detail, "auth_result"), result_expected)) {
        fprintf(stderr, "%s: category=%s event=%s user=%s ip=%s result=%s\n",
                name, category, event, field(detail, "username"),
                field(detail, "source_ip"), field(detail, "auth_result"));
        failed = 1;
    }
    json_object_put(detail);
    return failed;
}

int main(void)
{
    int failed = 0;
    failed |= check("openssh-accepted",
        "Accepted publickey for root from 192.168.30.2 port 49708 ssh2",
        0, "sshd-session", "auth", "security", "security_auth_log",
        "root", "192.168.30.2", "success");
    failed |= check("openssh-invalid-user",
        "Failed password for invalid user alice from 1.2.3.4 port 2222 ssh2",
        0, "sshd", "auth", "security", "security_auth_log",
        "alice", "1.2.3.4", "failure");
    failed |= check("openssh-received-disconnect",
        "Received disconnect from 192.168.30.2 port 49708:11: disconnected by user",
        0, "sshd-session", "auth", "security", "security_auth_log",
        "", "192.168.30.2", "disconnected");
    failed |= check("openssh-user-disconnect",
        "Disconnected from user root 192.168.30.2 port 49708",
        0, "sshd-session", "auth", "security", "security_auth_log",
        "root", "192.168.30.2", "disconnected");
    failed |= check("dropbear-success",
        "Pubkey auth succeeded for 'root' from 10.0.0.8:55123",
        0, "dropbear", "auth", "security", "security_auth_log",
        "root", "10.0.0.8", "success");
    failed |= check("dropbear-disconnect",
        "Exit (root) from <10.0.0.8:55123>: Disconnect received",
        0, "dropbear", "auth", "security", "security_auth_log",
        "root", "10.0.0.8", "disconnected");
    failed |= check("ordinary-login-text",
        "application login screen rendered",
        0, "custom-daemon", "daemon", "system", "log_line", "", "", "");
    failed |= check("non-kernel-oom-text",
        "test fixture says out of memory but is not a kernel source",
        0, "custom-daemon", "daemon", "system", "log_line", "", "", "");
    failed |= check("kernel-oom",
        "Out of memory: Killed process 123",
        1, "kernel", "kern", "kernel", "out_of_memory", "", "", "");
    failed |= check("kernel-panic",
        "Kernel panic - not syncing: fatal exception",
        1, "kernel", "kern", "kernel", "kernel_panic", "", "", "");
    failed |= check("kernel-thermal",
        "critical temperature reached; thermal shutdown",
        1, "kernel", "kern", "kernel", "thermal_shutdown", "", "", "");
    failed |= check("webd-worker",
        "persistent worker restarted index=2 pid=5556",
        0, "dreamingwrt-webd", "daemon", "system", "service_worker_restarted",
        "", "", "");
    failed |= check("live-nfs-unreachable", "NAS 192.168.35.3 unreachable, will still try mount...", 0, "nfsmount", "user", "FILES", "NFS_TARGET_UNREACHABLE", "", "", "");
    failed |= check("live-nfs-retry", "mount attempt failed (code=1), retry in 60s", 0, "nfsmount", "user", "FILES", "NFS_MOUNT_RETRYING", "", "", "");
    failed |= check("nfs-text-wrong-producer", "mount attempt failed (code=1), retry in 60s", 0, "custom-daemon", "user", "system", "log_line", "", "", "");
    failed |= check("kernel-io", "I/O error, dev sda, sector 4096 op 0x0", 1, "kernel", "kern", "STORAGE", "STORAGE_IO_ERROR", "", "", "");
    failed |= check("kernel-read-only", "EXT4-fs (sda1): Remounting filesystem read-only", 1, "kernel", "kern", "STORAGE", "STORAGE_READ_ONLY", "", "", "");
    failed |= check("fake-kernel-io", "I/O error, dev sda, sector 4096", 0, "custom-daemon", "user", "system", "log_line", "", "", "");
    return failed ? 1 : 0;
}
'''.replace("__HELPER__", helper).replace("__BUSINESS__", business).replace("__FTP__", ftp).replace("__CLASSIFY__", classify)

    with tempfile.TemporaryDirectory(prefix="log-event-semantics-") as tmp:
        tmp_path = Path(tmp)
        source_path = tmp_path / "fixture.c"
        binary_path = tmp_path / "fixture"
        source_path.write_text(harness, encoding="utf-8")
        subprocess.run(
            [compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", *cflags,
             "-I", str(ROOT / "src"), str(source_path), str(EVENT_SEMANTICS), "-o", str(binary_path), *libs],
            check=True,
        )
        subprocess.run([str(binary_path)], check=True)

    classify_text = re.sub(r"/\*.*?\*/|//[^\n]*", "", classify, flags=re.S)
    assert '*category = "audit"' not in classify_text
    assert '*event = "auth_log"' not in classify_text


def test_auth_presentation_localizes_controlled_enums() -> None:
    compiler = shutil.which("cc") or shutil.which("clang")
    assert compiler, "a C compiler is required"
    cflags = subprocess.check_output(
        ["pkg-config", "--cflags", "json-c"], text=True
    ).split()
    libs = subprocess.check_output(
        ["pkg-config", "--libs", "json-c"], text=True
    ).split()
    harness = r'''
#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include "event_semantics.h"

static int check(const char *locale, const char *expected,
                 const char *forbidden)
{
    struct json_object *event = json_object_new_object();
    struct json_object *detail = json_object_new_object();
    struct json_object *presentation;
    struct json_object *description = NULL;
    const char *text;
    int failed = 0;

    json_object_object_add(event, "event",
                           json_object_new_string("SECURITY_AUTH_EVENT"));
    json_object_object_add(detail, "username", json_object_new_string("root"));
    json_object_object_add(detail, "source_ip",
                           json_object_new_string("192.168.30.2"));
    json_object_object_add(detail, "auth_method",
                           json_object_new_string("publickey"));
    json_object_object_add(detail, "auth_result",
                           json_object_new_string("success"));
    json_object_object_add(event, "detail_json", detail);
    presentation = dw_event_presentation_render(event, locale);
    if (!presentation ||
        !json_object_object_get_ex(presentation, "description", &description) ||
        !description) {
        fprintf(stderr, "%s: description missing\n", locale);
        failed = 1;
    } else {
        text = json_object_get_string(description);
        if (!strstr(text, expected) || strstr(text, forbidden) ||
            !strstr(text, "192.168.30.2")) {
            fprintf(stderr, "%s: unexpected description: %s\n", locale, text);
            failed = 1;
        }
    }
    if (presentation)
        json_object_put(presentation);
    json_object_put(event);
    return failed;
}

int main(void)
{
    int failed = 0;
    failed |= check("zh-CN", "通过公钥认证成功", "publickey");
    failed |= check("en", "authenticated successfully using public key", "publickey");
    return failed ? 1 : 0;
}
'''

    with tempfile.TemporaryDirectory(prefix="event-presentation-") as tmp:
        tmp_path = Path(tmp)
        harness_path = tmp_path / "presentation.c"
        binary_path = tmp_path / "presentation"
        harness_path.write_text(harness, encoding="utf-8")
        subprocess.run(
            [compiler, "-std=c99", "-Wall", "-Wextra", "-Werror", *cflags,
             "-I", str(ROOT / "src"), str(EVENT_SEMANTICS), str(harness_path),
             "-o", str(binary_path), *libs],
            check=True,
        )
        subprocess.run([str(binary_path)], check=True)


if __name__ == "__main__":
    test_trusted_log_classification_fixtures()
    test_auth_presentation_localizes_controlled_enums()
    print("ok - trusted-source log semantic fixtures passed")
