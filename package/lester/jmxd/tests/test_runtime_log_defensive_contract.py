#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEBD = (ROOT / "src/webd/jmx_app_api.c").read_text()
NETCONFIG = (ROOT / "src/jmx_netconfig_db.c").read_text()


def main():
    combined = WEBD + NETCONFIG
    assert "/tmp/dw-port-network-reload.log" not in combined
    assert "/tmp/dw-adv-routing-apply.log" not in combined
    assert "/tmp/dw-adv-routing-run.log" not in combined
    assert 'O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC' in WEBD
    assert 'O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC' in NETCONFIG
    assert 'st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH))' in WEBD
    assert 'st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH))' in NETCONFIG
    assert 'const char *argv[] = { "/bin/sh", "/etc/dreamingwrt/advanced_routing_apply.sh", NULL }' in NETCONFIG
    assert 'nc_run_quiet("sh /etc/dreamingwrt/advanced_routing_apply.sh' not in NETCONFIG
    assert 'nft -f /etc/dreamingwrt/advanced_routing_pbr.nft\\n' in NETCONFIG
    print("ok: root runtime logs are unique, nofollow, and outside /tmp")


if __name__ == "__main__":
    main()
