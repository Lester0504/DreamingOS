#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
MAIN = (SRC / "toolkit/toolkit_main.c").read_text(encoding="utf-8")
COMMON = (SRC / "toolkit/toolkit_common.c").read_text(encoding="utf-8")
DB = (SRC / "toolkit/toolkit_db.c").read_text(encoding="utf-8")
OPS = (SRC / "toolkit/toolkit_ops.c").read_text(encoding="utf-8")
WEBD = (SRC / "webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (SRC / "webd/jmx_app_perms.c").read_text(encoding="utf-8")
INIT = (SRC / "init/dreamingwrt_init.c").read_text(encoding="utf-8")
PKG = (ROOT / "Makefile").read_text(encoding="utf-8")


def test_toolkit_is_one_shot_and_not_supervised() -> None:
    assert '"execution_model", json_object_new_string("on_demand_one_shot")' in OPS
    assert '"resident", json_object_new_boolean(0)' in OPS
    assert 'define Package/dreamingwrt-toolkit/install' in PKG
    install = PKG[PKG.index('define Package/dreamingwrt-toolkit/install'):]
    install = install[:install.index('endef')]
    assert '$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-toolkit $(1)/usr/bin' in install
    assert '/etc/init.d' not in install
    assert 'name = "dreamingwrt-toolkit"' not in INIT


def test_webd_exec_bridge_is_structured_and_actor_owned() -> None:
    assert 'const char *binary = "/usr/bin/dreamingwrt-toolkit"' in WEBD
    assert 'execl(binary, binary, command, (char *)NULL)' in WEBD
    assert 'json_object_object_del(body, "actor")' in WEBD
    assert 'json_object_object_add(body, "actor"' in WEBD
    assert 'webd_toolkit_exec("router-check"' in WEBD
    assert 'webd_toolkit_exec("port-mirror-set"' in WEBD
    assert 'webd_toolkit_exec("ddns-set"' in WEBD
    assert 'webd_toolkit_exec("wake-on-lan"' in WEBD
    assert 'webd_toolkit_exec("throughput-start"' in WEBD
    assert '2 * 1024 * 1024' in WEBD
    assert '4 * 1024 * 1024' in MAIN


def test_port_mirror_only_owns_reserved_filters() -> None:
    assert '#define TOOLKIT_TC_PREF 49152' in (SRC / "toolkit/toolkit_internal.h").read_text(encoding="utf-8")
    assert '"pref", pref, "matchall", "action", "mirred"' in OPS
    assert '"filter", "del", "dev", (char *)source, (char *)hook, "pref", pref' in OPS
    assert '"qdisc", "replace", "dev", (char *)source, "clsact"' in OPS
    assert 'qdisc del' not in OPS


def test_ddns_secrets_are_encrypted_and_redacted() -> None:
    assert 'EVP_aes_256_gcm()' in DB
    assert '#define TOOLKIT_KEY_PATH "/etc/dreamingwrt/toolkit.key"' in DB
    assert 'chmod(TOOLKIT_KEY_PATH, 0600)' in DB
    assert '"credentials_set"' in DB
    assert '"credentials_redacted"' in DB
    assert 'json_object_object_add(o, "credentials"' not in DB
    assert 'CURLOPT_PROTOCOLS_STR, "https"' in OPS
    assert '"provider_not_implemented"' in OPS


def test_wol_and_throughput_use_real_kernel_tools() -> None:
    assert 'sendto(fd, packet, sizeof(packet)' in OPS
    assert 'sizeof(packet)' in OPS
    assert 'toolkit_lan_ifname_ok(ifname)' in OPS
    assert 'toolkit_bin("iperf3"' in OPS
    assert 'execv(iperf, argv)' in OPS
    assert 'toolkit_job_owned(meta, payload)' in OPS
    assert '!strcmp(comm, "iperf3")' in OPS
    assert 'kill(-pid, SIGTERM)' in OPS


def test_toolkit_routes_have_explicit_risk() -> None:
    for path in (
        "/api/v1/toolkit/router-check",
        "/api/v1/toolkit/port-mirror",
        "/api/v1/toolkit/ddns",
        "/api/v1/toolkit/wake-on-lan",
        "/api/v1/toolkit/throughput",
    ):
        assert path in PERMS


if __name__ == "__main__":
    test_toolkit_is_one_shot_and_not_supervised()
    test_webd_exec_bridge_is_structured_and_actor_owned()
    test_port_mirror_only_owns_reserved_filters()
    test_ddns_secrets_are_encrypted_and_redacted()
    test_wol_and_throughput_use_real_kernel_tools()
    test_toolkit_routes_have_explicit_risk()
    print("ok: one-shot toolkit, exec bridge, tc ownership, DDNS secrets, WOL, throughput, and RBAC")
