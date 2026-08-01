#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/main.c").read_text(encoding="utf-8")


def test_legacy_rule_manager_cleanup_uses_bounded_argv_exec() -> None:
    assert 'system("killall -9 rule_manager")' not in SOURCE
    assert '"/usr/bin/killall", "-9", "rule_manager", NULL' in SOURCE
    assert "jmx_exec_wait(argv[0], argv, 5000, &result)" in SOURCE
    assert "jmx_exec_result_free(&result)" in SOURCE
    connect = SOURCE.index("if (legacy_netlink && jmx_nl_fd.fd < 0)")
    call = SOURCE.index("jmx_stop_legacy_rule_manager();", connect)
    ready = SOURCE.index('LOG_INFO("netlink connect success', connect)
    assert connect < call < ready


def test_core_main_warning_cleanup_does_not_regress() -> None:
    assert "char signature_path[512];" in SOURCE
    assert "char cmd_buf[128]" not in SOURCE
    assert "void jmx_handle_sigusr1(int sig) {\n    (void)sig;" in SOURCE
    assert "void jmx_handle_sigusr2(int sig) {\n    (void)sig;" in SOURCE
    main = SOURCE[SOURCE.index("int main(int argc, char **argv)"):]
    assert "int ret = 0;" not in main


if __name__ == "__main__":
    test_legacy_rule_manager_cleanup_uses_bounded_argv_exec()
    test_core_main_warning_cleanup_does_not_regress()
    print("ok: U-15 legacy rule-manager cleanup uses bounded argv exec")
