from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_wan_apply_owns_firewall_zone_membership_and_rollback():
    source = (ROOT / "src" / "jmx_netconfig_db.c").read_text()
    start = source.index("int jmx_netconfig_apply_wan(const char *id)")
    end = source.index("static void nc_apply_lan_addresses", start)
    apply_wan = source[start:end]

    assert "nc_apply_wan_firewall_zone" in apply_wan
    assert 'nc_backup_config("firewall"' in apply_wan
    assert 'jmx_uci_commit(uctx, "firewall")' in apply_wan
    assert 'nc_restore_config("firewall"' in apply_wan
    assert "nc_reload_network_stack(0, 1" in apply_wan


def test_wan_zone_membership_supports_add_and_remove():
    source = (ROOT / "src" / "jmx_netconfig_db.c").read_text()
    start = source.index("static int nc_apply_wan_firewall_zone")
    end = source.index("int nc_uci_ensure_section", start)
    helper = source[start:end]

    assert 'strcmp(name->v.string, "wan")' in helper
    assert 'nc_uci_add_list_pkg(ctx, "firewall", section, "network", wan_id)' in helper
    assert 'nc_uci_del_list_pkg(ctx, "firewall", section, "network", wan_id)' in helper
