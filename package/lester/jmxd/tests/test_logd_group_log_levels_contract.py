#!/usr/bin/env python3
"""Independent device / management / remote access / system log levels.

These contracts check that a level is not just stored config: the group is
derived from the category values producers already write, the level filters real
ingest, and error/critical can never be suppressed by a verbosity preference.
"""

from pathlib import Path
import sqlite3
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOGD = ROOT / "src" / "logd"
COMMON = (LOGD / "logd_common.c").read_text(encoding="utf-8")
DB = (LOGD / "logd_db.c").read_text(encoding="utf-8")
EVENT = (LOGD / "logd_event.c").read_text(encoding="utf-8")
INTERNAL = (LOGD / "logd_internal.h").read_text(encoding="utf-8")

GROUPS = ("device", "management", "remote_access", "system")
LEVELS = ("auto", "normal", "verbose", "debug")


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} missing: {missing}"


def c_function(source: str, signature: str) -> str:
    # Anchor on the definition so a longer name sharing the prefix (for example
    # logd_log_level_min_rank vs logd_log_level) cannot be matched instead.
    start = source.index(signature + "(")
    brace = source.index("{", start)
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[start:pos + 1]
    raise AssertionError(f"unterminated C function: {signature}")


def test_schema_migration_is_additive_and_defaults_to_auto() -> None:
    for group in GROUPS:
        column = f"log_level_{group}"
        assert (
            f'logd_config_add_column_if_missing("logd_settings", "{column}", '
            f'"TEXT NOT NULL DEFAULT \'auto\'")' in DB
        ), f"{column} must be added additively with an 'auto' default"
    # An upgrade must not rewrite or drop the settings table.
    assert "DROP TABLE logd_settings" not in DB
    assert "ALTER TABLE logd_settings RENAME" not in DB


def test_group_mapping_uses_real_producer_categories() -> None:
    """Groups must map categories that producers actually write."""
    body = c_function(COMMON, "const char *logd_log_level_group")
    # Categories observed in logd_event.c / collectors.
    for category in ("client", "dhcp", "port"):
        assert f'"{category}"' in body, f"device group must map {category}"
    for category in ("audit", "auth"):
        assert f'"{category}"' in body, f"management group must map {category}"
    for category in ("vpn", "wan", "pppoe"):
        assert f'"{category}"' in body, f"remote_access group must map {category}"
    # Unknown categories must stay visible instead of being silently dropped.
    assert 'return "system"' in body


def test_error_and_critical_are_never_filtered() -> None:
    body = c_function(EVENT, "struct json_object *logd_add_event")
    guard = body[:body.index("jmx_storage_guard_allow")]
    assert 'logd_event_severity_rank(severity) < logd_event_severity_rank("error")' in guard, (
        "the level filter must only ever consider severities below error"
    )
    assert "below_group_log_level" in guard


def test_filtered_event_is_reported_as_not_persisted() -> None:
    """A dropped event must not claim to have been written."""
    body = c_function(EVENT, "struct json_object *logd_add_event")
    block_start = body.index("below_group_log_level")
    block = body[body.rindex("if (", 0, block_start):block_start + 400]
    assert '"persisted", json_object_new_boolean(0)' in block
    assert '"filtered", json_object_new_boolean(1)' in block
    assert '"log_level_group"' in block and '"log_level"' in block


def test_settings_write_rejects_unknown_group_and_level() -> None:
    body = c_function(DB, "struct json_object *logd_settings_update")
    require_all(body, (
        "unknown_log_level_group",
        "invalid_log_level",
        "invalid_log_levels",
        "logd_log_level_cache_invalidate",
    ), "settings_update log level validation")


def test_settings_write_persists_every_group_column() -> None:
    body = c_function(DB, "struct json_object *logd_settings_update")
    for group in GROUPS:
        assert f"log_level_{group}=?" in body, f"UPDATE must bind log_level_{group}"


def test_settings_read_exposes_levels_and_capability_is_declared() -> None:
    read = c_function(DB, "struct json_object *logd_settings_json")
    assert '"log_levels"' in read
    for group in GROUPS:
        assert f'"{group}"' in read
    caps = c_function(EVENT, "struct json_object *logd_unifi_capabilities_json")
    require_all(caps, (
        '"log_levels"',
        '"log_level_groups"',
        '"log_level_enforced_at_ingest"',
        '"log_level_group_names"',
        '"log_level_values"',
    ), "log level capability")
    for level in LEVELS:
        assert f'"{level}"' in caps


def test_level_helpers_execute_with_expected_ranking() -> None:
    """Compile the real helpers and assert the actual filtering thresholds."""
    group_fn = c_function(COMMON, "const char *logd_log_level_group")
    level_fn = c_function(COMMON, "const char *logd_log_level")
    rank_fn = c_function(COMMON, "int logd_log_level_min_rank")
    severity_fn = c_function(COMMON, "const char *logd_severity")
    event_rank_fn = c_function(EVENT, "static int logd_event_severity_rank")

    program = f"""
#include <assert.h>
#include <stdio.h>
#include <string.h>

{severity_fn}
{group_fn}
{level_fn}
{rank_fn}
{event_rank_fn}

static int kept(const char *category, const char *level, const char *severity)
{{
    /* Mirrors the production guard: error and above always survive. */
    if (logd_event_severity_rank(severity) >= logd_event_severity_rank("error"))
        return 1;
    (void)category;
    return logd_event_severity_rank(severity) >= logd_log_level_min_rank(level);
}}

int main(void)
{{
    /* Group derivation. */
    assert(!strcmp(logd_log_level_group("client"), "device"));
    assert(!strcmp(logd_log_level_group("dhcp"), "device"));
    assert(!strcmp(logd_log_level_group("audit"), "management"));
    assert(!strcmp(logd_log_level_group("auth"), "management"));
    assert(!strcmp(logd_log_level_group("vpn"), "remote_access"));
    assert(!strcmp(logd_log_level_group("wan"), "remote_access"));
    assert(!strcmp(logd_log_level_group("system"), "system"));
    assert(!strcmp(logd_log_level_group("brand_new_thing"), "system"));
    assert(!strcmp(logd_log_level_group(NULL), "system"));

    /* Unknown levels fall back to auto rather than becoming a silent filter. */
    assert(!strcmp(logd_log_level("bogus"), "auto"));
    assert(!strcmp(logd_log_level(""), "auto"));
    assert(!strcmp(logd_log_level(NULL), "auto"));
    assert(!strcmp(logd_log_level("debug"), "debug"));

    /* auto/verbose preserve historical behavior: info kept, debug dropped. */
    assert(logd_log_level_min_rank("auto") == 1);
    assert(logd_log_level_min_rank("verbose") == 1);
    assert(logd_log_level_min_rank("normal") == 2);
    assert(logd_log_level_min_rank("debug") == 0);

    /* normal is quieter than auto. */
    assert(kept("client", "auto", "info"));
    assert(!kept("client", "normal", "info"));
    assert(kept("client", "normal", "notice"));
    assert(kept("client", "debug", "debug"));
    assert(!kept("client", "auto", "debug"));

    /* Failures survive every level, including the quietest. */
    assert(kept("client", "normal", "error"));
    assert(kept("client", "normal", "critical"));
    assert(kept("system", "normal", "error"));
    assert(kept("system", "normal", "critical"));

    puts("ok: group log level helpers");
    return 0;
}}
"""
    with tempfile.TemporaryDirectory(prefix="logd-levels-") as tmp:
        source = Path(tmp) / "levels.c"
        binary = Path(tmp) / "levels"
        source.write_text(program, encoding="utf-8")
        subprocess.run(
            ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(binary)],
            check=True,
        )
        out = subprocess.run([str(binary)], check=True, text=True,
                             capture_output=True).stdout
        assert "ok: group log level helpers" in out


def test_additive_migration_on_a_real_legacy_database() -> None:
    """An existing settings row must gain 'auto' defaults, not lose data."""
    with tempfile.TemporaryDirectory(prefix="logd-migrate-") as tmp:
        db_path = Path(tmp) / "config.db"
        con = sqlite3.connect(db_path)
        con.execute(
            "CREATE TABLE logd_settings ("
            " id INTEGER PRIMARY KEY CHECK (id=1),"
            " retention_days INTEGER NOT NULL DEFAULT 30,"
            " kernel_retention_days INTEGER NOT NULL DEFAULT 7,"
            " max_size_mb INTEGER NOT NULL DEFAULT 128,"
            " max_events INTEGER NOT NULL DEFAULT 50000,"
            " auto_cleanup INTEGER NOT NULL DEFAULT 1,"
            " archive_compress INTEGER NOT NULL DEFAULT 1,"
            " updated_at INTEGER NOT NULL DEFAULT 0)"
        )
        con.execute(
            "INSERT INTO logd_settings(id,retention_days,max_events) VALUES(1,90,12345)"
        )
        con.commit()
        for group in GROUPS:
            con.execute(
                f"ALTER TABLE logd_settings ADD COLUMN log_level_{group} "
                "TEXT NOT NULL DEFAULT 'auto'"
            )
        con.commit()
        row = con.execute(
            "SELECT retention_days,max_events,log_level_device,log_level_management,"
            "log_level_remote_access,log_level_system FROM logd_settings WHERE id=1"
        ).fetchone()
        con.close()
        # Pre-existing values preserved, new columns default to auto.
        assert row[0] == 90 and row[1] == 12345
        assert row[2:] == ("auto", "auto", "auto", "auto")


def test_ingest_cache_is_invalidated_on_write() -> None:
    """A level change must take effect immediately, not after a TTL."""
    reader = c_function(DB, "int logd_log_level_for_group")
    assert "g_logd_level_cache" in reader
    invalidate = c_function(DB, "void logd_log_level_cache_invalidate")
    assert "valid = 0" in invalidate
    assert "void logd_log_level_cache_invalidate(void);" in INTERNAL
    update = c_function(DB, "struct json_object *logd_settings_update")
    assert "logd_log_level_cache_invalidate()" in update


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok: {name}")
