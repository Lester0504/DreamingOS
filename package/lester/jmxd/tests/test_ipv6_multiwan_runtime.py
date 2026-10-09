#!/usr/bin/env python3

import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "files" / "dreamingwrt-ipv6-multiwan.sh"


def write_executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


with tempfile.TemporaryDirectory(prefix="ipv6-mw-fixture-") as temporary:
    temp = Path(temporary)
    bin_dir = temp / "bin"
    bin_dir.mkdir()
    command_log = temp / "commands.log"
    nft_live = temp / "nft-live"
    state_file = temp / "state"
    lock_file = temp / "lock"
    nft_file = temp / "rules.nft"

    write_executable(
        bin_dir / "uci",
        "#!/bin/sh\n"
        "[ \"$1 $2 $3\" = '-q get network.globals.ula_prefix' ] && "
        "{ echo fd00:30:1::/48; exit 0; }\n"
        "exit 1\n",
    )
    write_executable(
        bin_dir / "ubus",
        """#!/usr/bin/env python3
import json, os, sys
wans = os.environ.get("MOCK_WANS", "wan,wan2,wan3,wan4").split(",")
args = sys.argv[1:]
if args[0] == "list":
    pattern = args[1]
    names = []
    for wan in wans:
        names.extend([wan, wan + "_6"])
    if pattern == "network.interface.wan*":
        print("\\n".join("network.interface." + name for name in names))
    elif pattern.startswith("network.interface.") and pattern[18:] in names:
        print(pattern)
    sys.exit(0)
if args[:2] == ["call", "network.interface.lan"]:
    print(json.dumps({"up": True, "l3_device": "br-lan"}))
    sys.exit(0)
if args[0] == "call" and args[1].startswith("network.interface."):
    name = args[1][18:]
    if name.endswith("_6"):
        wan = name[:-2]
        index = 1 if wan == "wan" else int(wan[3:])
        print(json.dumps({"up": True, "ipv6-prefix": [{"address": f"2001:db8:{index}::", "mask": 60}]}))
    else:
        index = 1 if name == "wan" else int(name[3:])
        print(json.dumps({"up": True, "l3_device": "pppoe-wan" + ("" if index == 1 else str(index))}))
    sys.exit(0)
sys.exit(1)
""",
    )
    write_executable(
        bin_dir / "jsonfilter",
        """#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
expr = args[args.index("-e") + 1]
data = json.load(sys.stdin)
if expr == "@.up": value = data.get("up")
elif expr == "@.l3_device": value = data.get("l3_device")
elif expr.endswith(".address"): value = data.get("ipv6-prefix", [{}])[0].get("address")
elif expr.endswith(".mask"): value = data.get("ipv6-prefix", [{}])[0].get("mask")
else: value = None
if isinstance(value, bool): print(str(value).lower())
elif value is not None: print(value)
""",
    )
    write_executable(
        bin_dir / "ip",
        """#!/bin/sh
echo "ip $*" >> "$MOCK_COMMAND_LOG"
case "$*" in
  "-6 route show default dev "*)
    dev=${6}
    echo "default via fe80::1 dev $dev"
    exit 0
    ;;
  "-6 rule del "*) exit 2 ;;
esac
exit 0
""",
    )
    write_executable(
        bin_dir / "nft",
        """#!/bin/sh
echo "nft $*" >> "$MOCK_COMMAND_LOG"
case "$*" in
  "list table ip6 "*) [ -f "$MOCK_NFT_LIVE" ] ;;
  "-c -f "*) exit 0 ;;
  "-f "*) cp "$2" "$MOCK_NFT_LIVE" ;;
  "delete table ip6 "*) rm -f "$MOCK_NFT_LIVE" ;;
esac
""",
    )
    write_executable(bin_dir / "logger", "#!/bin/sh\nexit 0\n")
    write_executable(
        bin_dir / "flock",
        """#!/bin/sh
if [ "$1" = "-w" ]; then
    shift 2
fi
exit 0
""",
    )

    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{bin_dir}:{environment['PATH']}",
            "MOCK_COMMAND_LOG": str(command_log),
            "MOCK_NFT_LIVE": str(nft_live),
            "DREAMINGWRT_IPV6_MW_STATE_FILE": str(state_file),
            "DREAMINGWRT_IPV6_MW_LOCK_FILE": str(lock_file),
            "DREAMINGWRT_IPV6_MW_NFT_FILE": str(nft_file),
        }
    )

    subprocess.run(["sh", str(SCRIPT), "apply"], env=environment, check=True)
    first_commands = command_log.read_text()
    first_state = state_file.read_text()
    first_nft = nft_live.read_text()

    assert first_state.count("\npath|") == 4
    assert "priority 1001" in first_commands and "priority 1004" in first_commands
    assert first_commands.count("from fd00:30:1::/48 fwmark") == 4
    assert "from fd00:30:1::/48 table 104 priority 2000" in first_commands
    assert first_nft.count("snat to") == 4
    assert first_nft.count("ip6 saddr fd00:30:1::/48") == 4
    assert "ip6 saddr fd00:30:1::/64" not in first_nft
    assert 'oifname "pppoe-wan3"' in first_nft
    assert "from all fwmark" not in first_commands

    command_log.write_text("")
    environment["MOCK_WANS"] = "wan,wan2"
    subprocess.run(["sh", str(SCRIPT), "apply"], env=environment, check=True)
    shrink_commands = command_log.read_text()
    shrink_state = state_file.read_text()
    shrink_nft = nft_live.read_text()

    assert shrink_state.count("\npath|") == 2
    assert "rule del priority 1003" in shrink_commands
    assert "rule del priority 1004" in shrink_commands
    assert "route flush table 103" in shrink_commands
    assert "route flush table 104" in shrink_commands
    assert "addr del 2001:db8:3::1/128 dev lo" in shrink_commands
    assert "addr del 2001:db8:4::1/128 dev lo" in shrink_commands
    assert "from fd00:30:1::/48 table 102 priority 2000" in shrink_commands
    assert shrink_nft.count("snat to") == 2

print("ok: IPv6 multi-WAN runtime apply and stale-path cleanup fixture")
