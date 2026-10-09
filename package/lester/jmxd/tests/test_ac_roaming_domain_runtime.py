#!/usr/bin/env python3
"""Phase 1/2 managed-AP roaming-domain persistence and observe-only contract."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/ac/ac_db.c"
# ac_db.c derives 802.11r R0KH/R1KH key material through the encrypted secret
# store, so the real ac_secrets.c is linked in rather than stubbed: the FT
# fan-out is exactly the path that shipped a hardcoded key while it had no
# coverage, and a stub would hide a repeat.  AC_SECRETS_TESTING relaxes the
# key-file owner check from root to the current euid so this runs unprivileged.
SECRETS = ROOT / "src/ac/ac_secrets.c"
FIXTURE = ROOT / "tests" / os.environ.get(
    "AC_ROAMING_FIXTURE", "ac_roaming_domain_runtime_fixture.c")
PREFIX = Path(os.environ.get("AC_SURVEY_TEST_PREFIX", "/opt/homebrew/opt/json-c"))
OPENSSL_PREFIX = Path(os.environ.get(
    "AC_SURVEY_TEST_OPENSSL_PREFIX", "/opt/homebrew/opt/openssl@3"))


APD_BACKEND = ROOT / "src/apd/apd_backend_openwrt.c"


def static_contract() -> None:
    """Guard the hostapd control-interface wire formats.

    Both Phase 3 commands once used an invented syntax that hostapd rejects,
    and the BTM one did so while still reporting success: hostapd only reads
    space-prefixed key=value tokens after the STA address, and
    ieee802_11_parse_candidate_list() returns 0 rather than an error when it
    finds no " neighbor=", so a request with no candidates was answered OK and
    recorded as a successful steer.  Neither failure is visible without real
    hardware, so pin the formats here.
    """
    apd = APD_BACKEND.read_text(encoding="utf-8")
    db = SOURCE.read_text(encoding="utf-8")

    for token in (
        '"SET_NEIGHBOR %s ssid=%s nr=%s"',
        '"BSS_TM_REQ %s neighbor=%s,%u,%d,%d,%d,0301ff pref=1"',
        '" valid_int=%d"',
        '"REQ_BEACON %s %02x%02x0000%02x%02x%02x"',
        '"measure_bssid"',
    ):
        assert token in apd, f"hostapd wire format lost: {token}"

    # The rejected spellings. hostapd parses none of these.
    for token in ('oc=%s', 'ch=%s', 'validity=%d'):
        assert token not in apd, f"invalid hostapd token reintroduced: {token}"

    # FT key material must stay derived. The literal below shipped as the
    # R0KH/R1KH key for every AP in every domain.
    assert "000102030405060708090a0b0c0d0e0f" not in db, (
        "hardcoded FT key reintroduced")
    assert "ac_roaming_ft_link_key" in db, "FT key derivation removed"
    # hostapd's add_r0kh()/add_r1kh() split on ' ' and reject the line without
    # one, so a comma-separated entry is dropped rather than partially applied.
    assert '"%s %s %s"' in db, "r0kh/r1kh must stay space separated"

    # Phase 4 has two confirmation tokens and they must stay different
    # strings.  One arms the deauth capability on a domain (a config change);
    # the other authorises a single frame at a single station.  If they were
    # ever collapsed into one literal, enabling the feature would silently
    # grant the right to fire it and the execute-time confirmation would be
    # decorative.  Neither the gate nor the wrapper is reachable from the
    # fixture -- both sit inside #ifndef AC_DB_TEST_STANDALONE -- so this is
    # pinned here alongside the hostapd wire formats.
    assert '"enable-forced-deauth"' in db, "domain-arm confirmation token lost"
    assert '"execute-forced-deauth"' in db, "execute confirmation token lost"
    assert '"force_disassoc_disabled"' in db, (
        "automatic forced-disassociation policy gate lost")
    assert 'snprintf(block_scope, sizeof(block_scope), "lower")' in db, (
        "higher-band steering no longer maps to the temporary lower-band block")


def main() -> None:
    static_contract()
    with tempfile.TemporaryDirectory(prefix="ac-roaming-domain-") as raw:
        temp = Path(raw)
        binary = temp / "fixture"
        command = [
            os.environ.get("CC", "cc"), "-std=c11",
            "-D_DARWIN_C_SOURCE" if sys.platform == "darwin" else "-D_GNU_SOURCE",
            "-DAC_DB_TEST_STANDALONE", "-DAC_DB_TELEMETRY_TEST_STANDALONE",
            "-DAC_SECRETS_TESTING",
            "-Wall", "-Wextra", "-Werror",
            f"-I{ROOT / 'src/ac'}",
            f"-I{PREFIX / 'include'}", f"-I{OPENSSL_PREFIX / 'include'}",
            str(FIXTURE), str(SOURCE), str(SECRETS), f"-L{PREFIX / 'lib'}",
            f"-Wl,-rpath,{PREFIX / 'lib'}", "-ljson-c",
            f"-L{OPENSSL_PREFIX / 'lib'}", "-lcrypto", "-lsqlite3", "-lm",
            "-o", str(binary),
        ]
        if os.environ.get("AC_ROAMING_ACTIONS_TEST") == "1":
            command.insert(1, "-DAC_DB_ROAMING_ACTIONS_TEST")
        built = subprocess.run(command, capture_output=True, text=True)
        if built.returncode:
            raise AssertionError(built.stderr)
        env = os.environ.copy()
        env["DREAMINGWRT_AC_SECRETS_KEY_PATH"] = str(temp / "ac-secrets.key")

        if FIXTURE.name == "ac_roaming_domain_runtime_fixture.c":
            migration = temp / "legacy.db"
            with sqlite3.connect(migration) as connection:
                connection.execute(
                    "CREATE TABLE ac_roaming_policies ("
                    "domain_id TEXT PRIMARY KEY, weak_rssi_dbm INTEGER NOT NULL, "
                    "band_steering_enabled INTEGER NOT NULL DEFAULT 0, "
                    "minimum_candidate_gain_db INTEGER NOT NULL, "
                    "candidate_min_rssi_dbm INTEGER NOT NULL, "
                    "decision_min_interval_sec INTEGER NOT NULL, "
                    "post_roam_cooldown_sec INTEGER NOT NULL, "
                    "max_btm_attempts_per_hour INTEGER NOT NULL, "
                    "deauth_after_btm_failures INTEGER NOT NULL, "
                    "deauth_cooldown_sec INTEGER NOT NULL, "
                    "domain_action_rate_limit INTEGER NOT NULL, "
                    "revision INTEGER NOT NULL, updated_at INTEGER NOT NULL, "
                    "updated_by TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO ac_roaming_policies VALUES "
                    "('legacy-domain',-75,1,10,-67,120,300,2,1,900,2,1,1,'fixture')"
                )
            migration.chmod(0o600)
            env["DREAMINGWRT_AC_DB_PATH"] = str(migration)
            migrated = subprocess.run([str(binary), "migration-only"], env=env,
                                      capture_output=True, text=True)
            assert migrated.returncode == 0, migrated.stderr
            assert migrated.stdout.strip() == "ok", migrated.stdout

        env["DREAMINGWRT_AC_DB_PATH"] = str(temp / "config.db")
        completed = subprocess.run([str(binary)], env=env,
                                   capture_output=True, text=True)
        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.strip() == "ok", completed.stdout
    print("ok: Phase 1/2 roaming-domain persistence and observe-only contract")


if __name__ == "__main__":
    main()
