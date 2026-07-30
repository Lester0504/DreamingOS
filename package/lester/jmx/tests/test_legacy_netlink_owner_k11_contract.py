#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KERNEL = (ROOT / "src/jmx_main.c").read_text()
USER = (ROOT.parent / "jmxd/src/jmx_netlink.c").read_text()
CLIENT = (ROOT / "src/jmx_client.c").read_text()


def main():
    assert "netlink_unicast(jmx_sock, nl_skb, 999" not in KERNEL
    assert "static u32 jmx_legacy_report_portid;" in KERNEL
    assert "u32 portid = READ_ONCE(jmx_legacy_report_portid);" in KERNEL
    assert "WRITE_ONCE(jmx_legacy_report_portid, portid);" in KERNEL
    assert "cmpxchg(&jmx_legacy_report_portid, portid, 0);" in KERNEL
    assert "ret == -ECONNREFUSED || ret == -ESRCH" in KERNEL
    assert "WRITE_ONCE(jmx_legacy_report_portid, 0);" in KERNEL

    assert "jmx_nl_msg_t init = { .action = JMX_NL_MSG_INIT };" in USER
    assert "jmx_nl_send_msg_to_kernel(fd, &init, sizeof(init))" in USER
    assert "close(fd);" in USER
    assert "nlh->nlmsg_len = NLMSG_LENGTH(payload_len);" in USER
    assert "frame_len = NLMSG_SPACE(payload_len);" in USER
    assert "nlh = calloc(1, frame_len);" in USER
    assert "len > MAX_NL_MSG_LEN - (int)sizeof(*hdr)" in USER
    assert "(size_t)sent != NLMSG_LENGTH(payload_len)" in USER
    assert "nlh->nlmsg_len = NLMSG_SPACE(MAX_NL_MSG_LEN)" not in USER

    assert "total_client++;" in CLIENT
    assert "if (total_client > 0)" in CLIENT
    assert "total_client--;" in CLIENT
    assert "total_client = 0;" in CLIENT
    print("ok: K-11 uses a registered legacy owner and balanced client gauge")


if __name__ == "__main__":
    main()
