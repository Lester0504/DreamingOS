#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text()


def function_body(name: str) -> str:
    marker = f"struct json_object *{name}("
    start = SOURCE.index(marker)
    brace = SOURCE.index("{", start)
    depth = 0
    for index in range(brace, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[brace + 1:index]
    raise AssertionError(f"unterminated function: {name}")


def main():
    apply = function_body("jmx_firewall_service_apply")
    assert 'fopen("/etc/config/dreamingwrt_firewall","w")' not in SOURCE
    assert "O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC" in SOURCE
    assert 'open("/etc/config", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)' in SOURCE
    assert "renameat(dirfd, tmp_name, dirfd, \"dreamingwrt_firewall\")" in SOURCE
    assert "fflush(fp) != 0" in SOURCE
    assert "fsync(fileno(fp)) != 0" in SOURCE
    assert "fclose(fp) != 0" in SOURCE
    assert "fsync(dirfd) == 0" in SOURCE
    assert 'unlinkat(dirfd, "dreamingwrt_firewall", 0)' in SOURCE
    assert "unlinkat(dirfd,tmp_name,0)" in SOURCE

    assert "static int nc_fw_uci_value" in SOURCE
    assert "'\\''" in SOURCE
    assert 'FW_VALUE("option comment",remark)' in SOURCE
    assert "option extra '--comment dreamingwrt:" not in SOURCE
    assert "nc_fw_port_expr_ok" in SOURCE
    assert "nc_fw_proto_ok" in SOURCE
    assert "nc_fw_addr_expr_ok" in SOURCE

    assert 'json_object_object_add(data,"runtime_applied",json_object_new_boolean(0))' in SOURCE
    assert 'json_object_object_add(data,"readback_verified",json_object_new_boolean(0))' in SOURCE
    assert 'json_object_object_add(data,"applied",json_object_new_boolean(0))' in SOURCE
    assert '"firewall4_transaction_executor_pending"' in SOURCE
    assert '"artifact_not_rendered_in_dry_run"' in SOURCE
    assert "json_object_new_boolean(!dry)" not in apply
    print("ok: U-09 firewall preview is atomic, encoded, and truthfully non-runtime")


if __name__ == "__main__":
    main()
