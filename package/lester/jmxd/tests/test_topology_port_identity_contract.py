from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "webd" / "jmx_app_api.c").read_text()


def test_port_links_prefer_physical_evidence_over_gateway_fallback():
    assert "has_port_evidence" in SOURCE
    assert "!matched && !has_port_evidence" in SOURCE
    for key in ("link_device", "link_port", "switch_port", "fdb_ifname"):
        assert key in SOURCE


def test_logical_isp_ids_are_not_emitted_as_macs():
    assert '"peer_id"' in SOURCE
    assert '"peer_mac"' in SOURCE
    assert '"topology_link_logical_peer"' in SOURCE
    assert "webd_normalize_mac_text(remote_mac" in SOURCE


def test_port_local_mac_comes_from_sysfs():
    assert "webd_add_port_mac_contract" in SOURCE
    assert '"/sys/class/net/%s/address"' in SOURCE
    assert '"sysfs:address"' in SOURCE


def test_network_ports_publish_real_sysfs_statistics():
    source = (ROOT / "src" / "jmx_netconfig_db.c").read_text()

    assert "nc_physical_port_add_statistics" in source
    assert '"/sys/class/net/%s/statistics/%s"' in source
    assert '"sysfs:netdev_statistics"' in source
    assert '"bytes_per_second"' in source
    assert '"counter_reset"' in source
    assert '"port_statistics_runtime"' in source
    assert '"port_local_mac"' in source
