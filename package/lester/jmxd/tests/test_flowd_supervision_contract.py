#!/usr/bin/env python3
"""Architecture contract for flowd supervision and ubus ownership."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INIT = (ROOT / "src/init/dreamingwrt_init.c").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
FLOWD_UBUS = (ROOT / "src/flowd/flowd_ubus.c").read_text(encoding="utf-8")
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def test_central_supervisor_owns_flowd_lifecycle() -> None:
    assert (
        '{ .name = "dreamingwrt-flowd", .path = "/usr/bin/dreamingwrt-flowd", '
        ".enabled = 1" in INIT
    )
    for marker in (
        "static void reap_children(void)",
        "next_backoff_sec(&g_components[i], now)",
        "start_component(c, &dummy, 1)",
        "next_respawn_at",
    ):
        assert marker in INIT


def test_package_does_not_restore_split_init_scripts() -> None:
    install_start = MAKEFILE.index("define Package/dreamingwrt-flowd/install")
    install_end = MAKEFILE.index("endef", install_start)
    flowd_install = MAKEFILE[install_start:install_end]
    assert "$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-flowd $(1)/usr/bin" in flowd_install
    assert "/etc/init.d" not in flowd_install

    postinst_start = MAKEFILE.index("define Package/dreamingwrt-init/postinst")
    postinst_end = MAKEFILE.index("endef", postinst_start)
    postinst = MAKEFILE[postinst_start:postinst_end]
    assert "dreamingwrt-flowd" in postinst
    assert 'rm -f /etc/init.d/$$s' in postinst
    assert "dreamingwrt-init is the sole" in postinst


def test_flowd_is_the_only_ubus_object_owner() -> None:
    assert '.name = "dreamingwrt.flowd"' in FLOWD_UBUS
    assert '.name = "dreamingos.flowd"' in FLOWD_UBUS
    assert 'ubus_add_object(g_flowd_ubus, &flowd_object)' in FLOWD_UBUS
    assert 'ubus_add_object(g_flowd_ubus, &flowd_alias_object)' in FLOWD_UBUS

    assert 'app_ubus_invoke_object_timeout("dreamingwrt.flowd"' in WEBD
    assert '.name = "dreamingwrt.flowd"' not in WEBD
    assert '.name = "dreamingos.flowd"' not in WEBD
    assert 'ubus_add_object' not in WEBD


if __name__ == "__main__":
    test_central_supervisor_owns_flowd_lifecycle()
    test_package_does_not_restore_split_init_scripts()
    test_flowd_is_the_only_ubus_object_owner()
    print("ok: flowd uses centralized supervision and exclusively owns its ubus objects")
