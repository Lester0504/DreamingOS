#!/usr/bin/env python3
"""Compile/runtime tests for fail-closed Gateway Shadow rendering helpers."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/jmx_gateway_shadow_runtime.c"
HEADER = ROOT / "src/jmx_gateway_shadow_runtime.h"

HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "jmx_gateway_shadow_runtime.h"

static char *read_file(const char *path)
{
    FILE *stream = fopen(path, "rb");
    long length;
    char *contents;
    assert(stream);
    assert(fseek(stream, 0, SEEK_END) == 0);
    length = ftell(stream);
    assert(length >= 0);
    rewind(stream);
    contents = calloc(1, (size_t)length + 1);
    assert(contents);
    assert(fread(contents, 1, (size_t)length, stream) == (size_t)length);
    fclose(stream);
    return contents;
}

int main(int argc, char **argv)
{
    struct jmx_gateway_shadow_runtime_config config = {
        .role = "primary",
        .lan_interface = "br-lan",
        .heartbeat_interface = "eth2",
        .heartbeat_local_ip = "169.254.51.1",
        .heartbeat_peer_ip = "169.254.51.2",
        .virtual_ipv4 = "192.168.30.1/24",
        .virtual_router_id = 51,
        .priority = 150,
        .advert_interval_seconds = 1,
        .preempt = 0,
        .connection_sync = 1
    };
    struct jmx_gateway_shadow_runtime_result result;
    struct stat status;
    char *keepalived, *conntrackd;
    char keepalived_path[4096], conntrackd_path[4096];

    assert(argc == 3);
    assert(jmx_gateway_shadow_runtime_validate(&config, &result) == 0);
    assert(jmx_gateway_shadow_runtime_render(&config, argv[1], &result) == 0);
    snprintf(keepalived_path, sizeof(keepalived_path), "%s/keepalived.conf", argv[1]);
    snprintf(conntrackd_path, sizeof(conntrackd_path), "%s/conntrackd.conf", argv[1]);
    assert(!strcmp(result.keepalived_path, keepalived_path));
    assert(!strcmp(result.conntrackd_path, conntrackd_path));
    assert(stat(keepalived_path, &status) == 0 && (status.st_mode & 0777) == 0600);
    assert(stat(conntrackd_path, &status) == 0 && (status.st_mode & 0777) == 0600);

    keepalived = read_file(keepalived_path);
    assert(strstr(keepalived, "state BACKUP"));
    assert(strstr(keepalived, "interface eth2"));
    assert(strstr(keepalived, "virtual_router_id 51"));
    assert(strstr(keepalived, "priority 150"));
    assert(strstr(keepalived, "nopreempt"));
    assert(strstr(keepalived, "unicast_src_ip 169.254.51.1"));
    assert(strstr(keepalived, "unicast_peer"));
    assert(strstr(keepalived, "169.254.51.2"));
    assert(strstr(keepalived, "192.168.30.1/24 dev br-lan"));
    free(keepalived);

    conntrackd = read_file(conntrackd_path);
    assert(strstr(conntrackd, "Mode FTFW"));
    assert(strstr(conntrackd, "UDP {"));
    assert(strstr(conntrackd, "IPv4_address 169.254.51.1"));
    assert(strstr(conntrackd, "IPv4_Destination_Address 169.254.51.2"));
    assert(strstr(conntrackd, "Interface eth2"));
    assert(strstr(conntrackd, "StartupResync On"));
    free(conntrackd);

    /* A second render exercises replacement and rollback staging paths. */
    config.priority = 140;
    assert(jmx_gateway_shadow_runtime_render(&config, argv[1], &result) == 0);
    keepalived = read_file(keepalived_path);
    assert(strstr(keepalived, "priority 140"));
    free(keepalived);

    /* Strict rejection: no output is accepted from injectable/unsafe input. */
    config.heartbeat_interface = "eth2\nscript";
    assert(jmx_gateway_shadow_runtime_validate(&config, &result) ==
           JMX_GS_RUNTIME_INVALID_INTERFACE);
    assert(strstr(result.message, "heartbeat_interface"));
    config.heartbeat_interface = "eth2";
    config.heartbeat_peer_ip = "10.0.0.2";
    assert(jmx_gateway_shadow_runtime_validate(&config, &result) ==
           JMX_GS_RUNTIME_INVALID_HEARTBEAT_ADDRESS);
    config.heartbeat_peer_ip = "169.254.51.2";
    config.preempt = 1;
    assert(jmx_gateway_shadow_runtime_validate(&config, &result) ==
           JMX_GS_RUNTIME_PREEMPT_UNSUPPORTED);
    config.preempt = 0;

    /* /usr/bin/true proves argv execution without starting any daemon. */
    assert(jmx_gateway_shadow_runtime_config_test(
               JMX_GS_DAEMON_KEEPALIVED, argv[2], keepalived_path, &result) == 0);
    assert(jmx_gateway_shadow_runtime_config_test(
               JMX_GS_DAEMON_CONNTRACKD, argv[2], conntrackd_path, &result) ==
           JMX_GS_RUNTIME_UNSUPPORTED);
    assert(strstr(result.message, "no safe non-starting config-test"));
    assert(jmx_gateway_shadow_runtime_daemon_control(
               JMX_GS_DAEMON_KEEPALIVED, JMX_GS_DAEMON_START, argv[2],
               keepalived_path, &result) == 0);
    assert(jmx_gateway_shadow_runtime_daemon_control(
               JMX_GS_DAEMON_CONNTRACKD, JMX_GS_DAEMON_START, argv[2],
               conntrackd_path, &result) == 0);
    assert(jmx_gateway_shadow_runtime_daemon_control(
               JMX_GS_DAEMON_CONNTRACKD, JMX_GS_DAEMON_STOP, argv[2],
               conntrackd_path, &result) == 0);
    assert(jmx_gateway_shadow_runtime_daemon_control(
               JMX_GS_DAEMON_CONNTRACKD, JMX_GS_DAEMON_RELOAD, argv[2],
               conntrackd_path, &result) == JMX_GS_RUNTIME_UNSUPPORTED);
    assert(jmx_gateway_shadow_runtime_daemon_control(
               JMX_GS_DAEMON_KEEPALIVED, 999, argv[2], keepalived_path, &result) ==
           JMX_GS_RUNTIME_INVALID_ARGUMENT);
    return 0;
}
'''


def test_runtime_render_and_exec_helpers() -> None:
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    true_binary = shutil.which("true")
    assert compiler and true_binary
    with tempfile.TemporaryDirectory(prefix="gateway-shadow-render-") as raw:
        directory = Path(raw)
        output = directory / "output with spaces"
        output.mkdir(mode=0o700)
        harness = directory / "fixture.c"
        executable = directory / "fixture"
        harness.write_text(HARNESS, encoding="utf-8")
        subprocess.run(
            [
                compiler,
                "-std=gnu11",
                "-D_GNU_SOURCE",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "src"),
                str(SOURCE),
                str(harness),
                "-o",
                str(executable),
            ],
            check=True,
        )
        subprocess.run([str(executable), str(output), true_binary], check=True)


def test_source_forbids_shell_execution_and_uses_durable_atomic_replace() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert "system(" not in source
    assert "popen(" not in source
    assert "fork()" in source
    assert "execv(" in source
    assert "waitpid(" in source
    assert "/etc/init.d/keepalived" not in source
    assert '"-f"' in source
    assert '"-p"' in source
    assert '"-r"' in source
    assert '"-C"' in source
    assert "openat(" in source
    assert "O_EXCL" in source
    assert "0600" in source
    assert "fsync(" in source
    assert "renameat(" in source


if __name__ == "__main__":
    test_runtime_render_and_exec_helpers()
    test_source_forbids_shell_execution_and_uses_durable_atomic_replace()
    print("ok: Gateway Shadow runtime rendering and process helpers")
