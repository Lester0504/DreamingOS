#!/usr/bin/env python3
"""U-15 contract: identityd and aegisxd must not reach external tools via a shell.

Covers the two remaining data-carrying shell hops found in the defensive audit:

  * identityd bridge FDB lookup previously ran "brctl showmacs <bridge>".
    It now reads /sys/class/net/<bridge>/brforward directly.
  * aegisxd previously ran "ip neigh show <ip>" and "nft list table ..."
    through popen(), so an externally supplied address reached a root shell.

The test asserts the shell hops are gone, that the replacements keep an
explicit output/time budget, and that failure modes stay fail-closed.
"""
import pathlib
import re
import sys

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"
IDENTITY = SRC / "identityd" / "jmx_identity_collector.c"
AEGIS = SRC / "aegisxd" / "aegisxd_hits.c"
MAKEFILE = SRC / "Makefile"

failures = []


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def check(cond, message):
    if not cond:
        failures.append(message)


identity_src = IDENTITY.read_text()
identity_code = strip_comments(identity_src)
aegis_src = AEGIS.read_text()
aegis_code = strip_comments(aegis_src)
makefile = MAKEFILE.read_text()

# 1. No shell execution primitives remain in either translation unit.
for name, code in (("jmx_identity_collector.c", identity_code),
                   ("aegisxd_hits.c", aegis_code)):
    for primitive in ("system(", "popen(", "pclose("):
        check(primitive not in code,
              "%s still uses %s" % (name, primitive))

# 2. brctl is gone entirely; the kernel FDB file is the source of truth.
check("brctl" not in identity_code,
      "identityd still depends on brctl")
check("/sys/class/net/%s/brforward" in identity_code,
      "identityd does not read the bridge forwarding database directly")

# 3. The FDB reader must refuse unsafe bridge names and malformed MACs, and
#    must not follow symlinks out of /sys.
fdb = identity_code[identity_code.index("lookup_bridge_fdb_port(const char"):]
fdb = fdb[:fdb.index("\n}\n")]
check("jmx_bridge_name_ok(bridge)" in fdb,
      "bridge name is not validated before building a /sys path")
check("jmx_parse_mac_bytes(mac" in fdb,
      "MAC is not strictly parsed before comparison")
check("O_NOFOLLOW" in fdb,
      "bridge FDB open does not use O_NOFOLLOW")
check("JMX_FDB_ENTRY_SIZE" in fdb,
      "FDB record size is not enforced")
check("if (got < sizeof(entry))" in fdb,
      "truncated FDB record is not rejected")

name_ok = identity_code[identity_code.index("jmx_bridge_name_ok(const char"):]
name_ok = name_ok[:name_ok.index("\n}\n")]
check("IFNAMSIZ" in name_ok,
      "bridge name length is not bounded by IFNAMSIZ")
for token in ("'/'", '".."'):
    check(token in name_ok,
          "bridge name validation does not reject %s" % token)

# 4. aegisxd must run fixed argv with absolute paths and a bounded budget.
check('"/sbin/ip"' in aegis_code, "aegisxd does not use an absolute ip path")
check('"/usr/sbin/nft"' in aegis_code,
      "aegisxd does not use an absolute nft path")
check("jmx_exec_capture(" in aegis_code,
      "aegisxd does not use the shared bounded exec helper")
check("AEGISXD_EXEC_TIMEOUT_MS" in aegis_code,
      "aegisxd exec has no timeout budget")

neigh = aegis_code[aegis_code.index("aegisxd_hits_lookup_ip_neigh(const char"):]
neigh = neigh[:neigh.index("\n}\n")]
check("aegisxd_hits_source_ip_safe(ip)" in neigh,
      "ip neigh lookup lost its address validation")
check('"to"' in neigh,
      "ip neigh lookup does not pin the address as a 'to' selector")

# 5. Timeout, truncation and signals are always failures. A non-zero exit is a
#    failure for ip, but must stay distinguishable for nft so that "table not
#    present" does not masquerade as a broken command.
strict = aegis_code[aegis_code.index("aegisxd_exec_capture_text(const char"):]
strict = strict[:strict.index("\n}\n")]
for token in ("result.timed_out", "result.truncated", "result.term_signal",
              "result.exit_code != 0"):
    check(token in strict,
          "strict aegisxd capture ignores %s" % token)

lenient = aegis_code[aegis_code.index("aegisxd_exec_capture_text_allow_exit(const char"):]
lenient = lenient[:lenient.index("\n}\n")]
for token in ("result.timed_out", "result.truncated", "result.term_signal"):
    check(token in lenient,
          "lenient aegisxd capture ignores %s" % token)
check("result.exit_code != 0" not in lenient,
      "lenient aegisxd capture must tolerate a non-zero exit for nft")

poll = aegis_code[aegis_code.index("aegisxd_nft_poll_counters(void)"):]
poll = poll[:poll.index("\n}\n")]
check("aegisxd_exec_capture_text_allow_exit(" in poll,
      "nft counter poll does not use the exit-tolerant capture")
check('"table_or_counters_missing"' in poll,
      "nft counter poll lost the missing-table status")
check('"nft_command_failed"' in poll,
      "nft counter poll lost the command-failure status")

# 6. The shared exec object must actually be linked into aegisxd.
aegis_objs = [line for line in makefile.splitlines()
              if line.startswith("AEGISXD_OBJS")]
check(bool(aegis_objs), "AEGISXD_OBJS not found in Makefile")
if aegis_objs:
    check("jmx_exec.o" in aegis_objs[0],
          "aegisxd link set is missing jmx_exec.o")

if failures:
    for item in failures:
        print("FAIL: %s" % item)
    sys.exit(1)

print("ok: U-15 identityd FDB and aegisxd probes avoid shell execution")
