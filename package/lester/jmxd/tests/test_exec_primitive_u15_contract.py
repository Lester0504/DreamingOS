#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXEC_SOURCE = ROOT / "src/jmx_exec.c"
EXEC_HEADER = ROOT / "src/jmx_exec.h"
WORK_MODE = (ROOT / "src/jmx_dreamingwrt_work_mode.c").read_text(encoding="utf-8")
CORE_HEADER = (ROOT / "src/jmx.h").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "src/Makefile").read_text(encoding="utf-8")
ACTIVE_C_SOURCES = list((ROOT / "src").rglob("*.c"))
ACTIVE_HEADERS = list((ROOT / "src").rglob("*.h"))


def test_legacy_shell_primitive_is_absent() -> None:
    for path in ACTIVE_C_SOURCES + ACTIVE_HEADERS:
        source = path.read_text(encoding="utf-8", errors="strict")
        assert "exec_with_result_line" not in source, path
    utils = (ROOT / "src/jmx_utils.c").read_text(encoding="utf-8")
    for token in ("popen(", "pclose("):
        assert token not in utils, token


def test_work_mode_has_no_shell_execution() -> None:
    for token in ("system(", "popen(", "pclose("):
        assert token not in WORK_MODE, token
    for token in (
        "jmx_exec_capture(",
        "jmx_exec_wait(",
        'wm_service_action("network", "reload")',
        'wm_service_action("dnsmasq", "reload")',
        'wm_service_action("firewall", "reload")',
        "inet_pton(AF_INET, host",
        'opendir("/proc")',
        "wm_token_ok(rollback_id, 63)",
    ):
        assert token in WORK_MODE, token
    assert "jmx_exec.o" in MAKEFILE


def test_work_mode_translation_unit_is_warning_clean() -> None:
    assert "static inline void af_log(" in CORE_HEADER
    assert "if ((int)level > current_log_level)" in CORE_HEADER
    preview = WORK_MODE[
        WORK_MODE.index("struct json_object *dw_work_mode_preview"):
        WORK_MODE.index("struct json_object *dw_work_mode_apply")
    ]
    assert "int disable_nat =" not in preview


def test_exec_primitive_runtime() -> None:
    fixture = r'''
#include "jmx_exec.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    struct jmx_exec_result r;
    char *printf_argv[] = { "/usr/bin/printf", "%s", "hello", NULL };
    char *sleep_argv[] = { "/bin/sleep", "2", NULL };
    char *leak_argv[] = { "/bin/sh", "-c", "sleep 2 & exit 0", NULL };
    char *relative_argv[] = { "printf", "bad", NULL };
    assert(jmx_exec_capture("/usr/bin/printf", printf_argv, 32, 1000, &r) == 0);
    assert(r.exit_code == 0 && !r.timed_out && !r.truncated);
    assert(r.output_len == 5 && strcmp(r.output, "hello") == 0);
    jmx_exec_result_free(&r);
    assert(jmx_exec_capture("printf", relative_argv, 32, 1000, &r) == -1);
    assert(jmx_exec_wait("/bin/sleep", sleep_argv, 50, &r) == 0);
    assert(r.timed_out && r.exit_code != 0);
    jmx_exec_result_free(&r);
    assert(jmx_exec_capture("/bin/sh", leak_argv, 32, 50, &r) == 0);
    assert(r.truncated && r.exit_code == 0);
    jmx_exec_result_free(&r);
    puts("ok: bounded argv exec primitive");
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / "fixture.c"
        binary = Path(td) / "fixture"
        source.write_text(fixture, encoding="utf-8")
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
             "-I", str(EXEC_HEADER.parent), str(source), str(EXEC_SOURCE),
             "-o", str(binary)], check=True
        )
        result = subprocess.run([str(binary)], text=True, capture_output=True,
                                check=True, timeout=5)
        assert "ok: bounded argv exec primitive" in result.stdout


if __name__ == "__main__":
    test_legacy_shell_primitive_is_absent()
    test_work_mode_has_no_shell_execution()
    test_work_mode_translation_unit_is_warning_clean()
    test_exec_primitive_runtime()
    print("ok: U-15 work-mode command family migrated to shared argv primitive")
