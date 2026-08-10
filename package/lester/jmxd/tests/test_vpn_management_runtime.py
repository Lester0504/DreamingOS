#!/usr/bin/env python3
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <json-c/json.h>
#include "webd_vpn_aggregate.h"

static struct json_object *child(struct json_object *obj, const char *key)
{
    struct json_object *value = NULL;
    assert(obj);
    assert(json_object_object_get_ex(obj, key, &value));
    return value;
}

static const char *string(struct json_object *obj, const char *key)
{
    return json_object_get_string(child(obj, key));
}

static int boolean(struct json_object *obj, const char *key)
{
    return json_object_get_boolean(child(obj, key));
}

static int is_null(struct json_object *obj, const char *key)
{
    struct json_object *value = (struct json_object *)0x1;
    return json_object_object_get_ex(obj, key, &value) && value == NULL;
}

static void write_text(const char *path, const char *text)
{
    FILE *stream = fopen(path, "w");
    assert(stream);
    assert(fputs(text, stream) >= 0);
    assert(fclose(stream) == 0);
}

static void create_interface(const char *root, const char *name,
                             const char *state, const char *rx, const char *tx)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", root, name);
    assert(mkdir(path, 0700) == 0);
    snprintf(path, sizeof(path), "%s/%s/statistics", root, name);
    assert(mkdir(path, 0700) == 0);
    snprintf(path, sizeof(path), "%s/%s/operstate", root, name);
    write_text(path, state);
    snprintf(path, sizeof(path), "%s/%s/statistics/rx_bytes", root, name);
    write_text(path, rx);
    snprintf(path, sizeof(path), "%s/%s/statistics/tx_bytes", root, name);
    write_text(path, tx);
}

static struct json_object *parse(const char *text)
{
    struct json_object *obj = json_tokener_parse(text);
    assert(obj);
    return obj;
}

int main(int argc, char **argv)
{
    struct json_object *config;
    struct json_object *legacy;
    struct json_object *data;
    struct json_object *servers;
    struct json_object *clients;
    struct json_object *server;
    struct json_object *client;
    struct json_object *server_runtime;
    struct json_object *client_runtime;
    struct json_object *cap;
    struct json_object *summary;
    struct json_object *view;
    struct json_object *certificate;

    assert(argc == 2);
    create_interface(argv[1], "wgclient0", "up\n", "1234\n", "5678\n");
    config = parse(
        "{\"global\":{\"enabled\":true},"
        "\"servers\":[{\"id\":\"server-a\",\"protocol\":\"OpenVPN\","
        "\"name\":\"Remote Access\",\"enabled\":true,\"listen\":\"tun404\","
        "\"routes\":[\"10.0.0.0/8\"],\"users_online\":0}],"
        "\"clients\":[{\"id\":\"client-a\",\"protocol\":\"WireGuard\","
        "\"name\":\"Office\",\"enabled\":true,\"iface\":\"wgclient0\","
        "\"remote\":\"vpn.example.test:51820\",\"latency\":0}],"
        "\"site_to_site\":[{\"id\":\"site-a\",\"type\":\"IPSec VPN\","
        "\"name\":\"Branch\",\"enabled\":true,\"peer\":\"203.0.113.8\","
        "\"transfer\":0}],"
        "\"accounts\":[{\"id\":\"acct-a\",\"username\":\"alice\","
        "\"status\":\"active\",\"online\":0}],"
        "\"certificates\":[{\"id\":\"cert-a\",\"name\":\"gateway\","
        "\"type\":\"Server\",\"status\":\"ok\"}],"
        "\"capabilities\":{\"wireguard\":true,\"openvpn\":true}}"
    );
    legacy = parse(
        "{\"protocols\":{\"WireGuard\":[{\"id\":\"wg-client-a\","
        "\"ifname\":\"wgclient0\",\"up_rate\":0,\"down_rate\":0}],"
        "\"OpenVPN\":[],\"IPSec VPN\":[]}}"
    );

    data = webd_vpn_aggregate_data_at(config, legacy, argv[1], 1784740000);
    assert(data);
    assert(!strcmp(string(data, "contract_version"), "vpn-management.v1"));
    assert(json_object_get_int64(child(data, "observed_at")) == 1784740000);
    servers = child(data, "servers");
    clients = child(data, "clients");
    assert(json_object_array_length(servers) == 1);
    assert(json_object_array_length(clients) == 1);
    server = json_object_array_get_idx(servers, 0);
    client = json_object_array_get_idx(clients, 0);
    server_runtime = child(server, "runtime");
    client_runtime = child(client, "runtime");

    assert(!boolean(server_runtime, "available"));
    assert(is_null(server_runtime, "connected"));
    assert(is_null(server_runtime, "rx_bytes"));
    assert(!strcmp(string(server_runtime, "reason"),
                   "runtime_interface_not_observed"));
    assert(boolean(client_runtime, "available"));
    assert(boolean(client_runtime, "interface_present"));
    assert(!strcmp(string(client_runtime, "interface_state"), "up"));
    assert(json_object_get_int64(child(client_runtime, "rx_bytes")) == 1234);
    assert(json_object_get_int64(child(client_runtime, "tx_bytes")) == 5678);
    assert(is_null(client_runtime, "connected"));
    assert(is_null(client_runtime, "latency_ms"));
    assert(is_null(client_runtime, "rx_rate"));

    assert(!json_object_object_get_ex(client_runtime, "latency", NULL));
    assert(!json_object_object_get_ex(server_runtime, "users_online", NULL));
    cap = child(data, "capabilities");
    assert(boolean(cap, "read"));
    assert(!boolean(cap, "runtime_status"));
    assert(!boolean(cap, "client_create"));
    assert(!boolean(cap, "transaction"));
    assert(!boolean(cap, "readback"));
    assert(!boolean(cap, "rollback"));
    summary = child(data, "summary");
    assert(is_null(summary, "active_tunnels"));
    assert(is_null(summary, "online_users"));
    assert(is_null(summary, "rx_rate"));
    certificate = json_object_array_get_idx(child(data, "certificates"), 0);
    assert(certificate);
    assert(!boolean(child(certificate, "runtime"), "available"));
    assert(is_null(child(certificate, "runtime"), "valid_now"));

    view = webd_vpn_resource_view(data, "clients");
    assert(view);
    assert(!strcmp(string(view, "resource"), "clients"));
    assert(json_object_array_length(child(view, "items")) == 1);
    assert(json_object_get_int64(child(view, "observed_at")) == 1784740000);

    json_object_put(view);
    json_object_put(data);
    json_object_put(legacy);
    json_object_put(config);
    puts("ok: VPN aggregation preserves config truth and null runtime semantics");
    return 0;
}
'''


def json_c_flags() -> list[str]:
    explicit = os.environ.get("WEBD_VPN_TEST_FLAGS", "").strip()
    if explicit:
        return shlex.split(explicit)
    # WEBD_VPN_TEST_FLAGS still wins. The old search tried Homebrew's static
    # archive first, which on 31.6 is an LTO archive the host linker rejects.
    return apd_test_deps.package_flags("json-c")


def main() -> None:
    flags = json_c_flags()
    with tempfile.TemporaryDirectory(prefix="vpn-management-runtime-") as raw:
        directory = Path(raw)
        sys_class_net = directory / "sys-class-net"
        sys_class_net.mkdir()
        source = directory / "runtime.c"
        executable = directory / "runtime"
        source.write_text(HARNESS, encoding="utf-8")
        subprocess.run([
            os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-I", str(ROOT / "src/webd"), str(source),
            str(ROOT / "src/webd/webd_vpn_aggregate.c"), *flags,
            "-o", str(executable),
        ], check=True)
        subprocess.run([str(executable), str(sys_class_net)], check=True)


if __name__ == "__main__":
    main()
