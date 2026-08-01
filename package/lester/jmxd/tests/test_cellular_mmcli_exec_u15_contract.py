#!/usr/bin/env python3
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_netconfig_db.c").read_text()
HEADER = ROOT / "src/jmx_mmcli_kv.h"


def between(text: str, start: str, end: str) -> str:
    begin = text.index(start)
    finish = text.index(end, begin)
    return text[begin:finish]


slot_set = between(SOURCE, "int jmx_cellular_slot_set", "int jmx_cellular_slot_delete")
probe = between(SOURCE, "static const char *nc_cellular_mmcli_path", "/* ── Wi-Fi config")
apply = between(SOURCE, "int jmx_cellular_service_apply", "/* ── Wi-Fi config")

assert "if (modem_path[0] && !jmx_mmcli_selector_ok(modem_path))" in slot_set
for forbidden in ("system(", "popen(", "pclose(", "| grep", "| awk", "| sed", "2>/dev/null"):
    assert forbidden not in probe, f"cellular probe still contains shell token: {forbidden}"
for required in (
    '"/usr/bin/mmcli"',
    '"/bin/mmcli"',
    '"-K"',
    'sim ? "-i" : "-m"',
    "jmx_exec_capture(path, argv",
    "result->timed_out",
    "result->truncated",
    "result->term_signal != 0",
    "result->exit_code != 0",
    "jmx_mmcli_parse_keyvalue",
    "CASE WHEN ?1 THEN ?2 ELSE signal END",
):
    assert required in probe, f"missing cellular fixed-argv/readback contract: {required}"

dry_pos = apply.index("if (dry_run)")
assert dry_pos < apply.index("nc_prepare(&st"), "dry-run still performs DB/probe work"
assert dry_pos < apply.index("nc_cellular_probe_slot"), "dry-run still executes mmcli"
assert dry_pos < apply.index('fopen("/etc/config/dreamingwrt_cellular"'), "dry-run still writes UCI"

fixture = r'''
#include <assert.h>
#include <string.h>
#include "jmx_mmcli_kv.h"

int main(void)
{
    struct jmx_mmcli_probe p = {0};
    char modem[] =
        "modem.generic.signal-quality.value : 73\n"
        "modem.3gpp.operator-name : China Mobile\n"
        "modem.generic.equipment-identifier : 867530900000001\n"
        "modem.generic.sim : /org/freedesktop/ModemManager1/SIM/2\n";
    char sim[] = "sim.properties.iccid : 89860012345678901234\n";
    char invalid[] =
        "modem.generic.signal-quality.value : 101\n"
        "modem.generic.equipment-identifier : 1234;touch/tmp/x\n"
        "modem.generic.sim : --bad-option\n";
    struct jmx_mmcli_probe bad = {0};

    assert(jmx_mmcli_parse_keyvalue(modem, &p, 0) == 4);
    assert(p.has_signal && p.signal == 73);
    assert(!strcmp(p.operator_name, "China Mobile"));
    assert(!strcmp(p.imei, "867530900000001"));
    assert(!strcmp(p.sim_path, "/org/freedesktop/ModemManager1/SIM/2"));
    assert(jmx_mmcli_parse_keyvalue(sim, &p, 1) == 1);
    assert(!strcmp(p.iccid, "89860012345678901234"));

    assert(jmx_mmcli_parse_keyvalue(invalid, &bad, 0) == 0);
    assert(!bad.has_signal && !bad.imei[0] && !bad.sim_path[0]);
    assert(jmx_mmcli_selector_ok("0"));
    assert(jmx_mmcli_selector_ok("/org/freedesktop/ModemManager1/Modem/0"));
    assert(jmx_mmcli_selector_ok("/org/freedesktop/ModemManager1/SIM/2"));
    assert(!jmx_mmcli_selector_ok("--help"));
    assert(!jmx_mmcli_selector_ok("0;reboot"));
    assert(!jmx_mmcli_selector_ok("/tmp/modem/0"));
    assert(!jmx_mmcli_selector_ok("/org/freedesktop/ModemManager1/Modem/a"));
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="jmx-mmcli-u15-") as td:
    td_path = Path(td)
    src = td_path / "fixture.c"
    exe = td_path / "fixture"
    src.write_text(fixture)
    cc = os.environ.get("CC", "cc")
    subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(HEADER.parent),
         str(src), "-o", str(exe)],
        check=True,
    )
    subprocess.run([str(exe)], check=True)

print("ok: U-15 cellular ModemManager probe uses fixed argv and machine output")
