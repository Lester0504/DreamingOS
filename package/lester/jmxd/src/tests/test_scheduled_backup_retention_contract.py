#!/usr/bin/env python3
"""Contract test for scheduled config backups and count-based retention.

The user's decision (2026-08-04) was: retention by COUNT, the count is set by the
USER, and when full the request is REFUSED rather than evicting an old backup.

The specific regression this guards against is storing backups in the upload
staging area, which caps entries at a 24h TTL and actively deletes expired ones.
Retention by count over a self-expiring store is a false feature: the limit is
almost never reached and backups vanish on their own.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "webd" / "jmx_app_api.c"
PERMS = ROOT / "webd" / "jmx_app_perms.c"
STORE_C = ROOT / "webd" / "webd_backup_store.c"
STORE_H = ROOT / "webd" / "webd_backup_store.h"
MAKEFILE = ROOT / "Makefile"


def main() -> None:
    api = API.read_text(encoding="utf-8")
    perms = PERMS.read_text(encoding="utf-8")
    store_c = STORE_C.read_text(encoding="utf-8")
    store_h = STORE_H.read_text(encoding="utf-8")
    makefile = MAKEFILE.read_text(encoding="utf-8")

    # ── the store must be a durable location, not upload staging ──
    assert 'WEBD_BACKUP_DEFAULT_ROOT "/data/persist/var/lib/dreamingwrt/backups"' in store_h
    # The store root must not point back into the staging tree. The header may
    # still describe the old location in prose; what matters is the path.
    assert "upload-staging" not in store_h[store_h.index("#define WEBD_BACKUP_DEFAULT_ROOT"):]
    assert "upload-staging" not in store_c
    # No TTL/expiry concept may leak into the backup store.
    for banned in ("expires_at", "TTL", "cleanup_expired"):
        assert banned not in store_c, banned
    assert '"durable_backup_store"' in api

    # ── retention is by count, user-configured, and refuses when full ──
    assert "WEBD_BACKUP_RETENTION_MIN" in store_h
    assert "WEBD_BACKUP_RETENTION_MAX" in store_h
    assert "webd_backup_retention_set" in store_c
    assert "webd_backup_retention_admit" in store_c
    assert "backup_retention_limit_reached" in store_c
    assert "backup_retention_limit_reached" in api
    assert '"retention_policy", json_object_new_string("count")' in api
    assert '"retention_full_behavior",\n                           json_object_new_string("reject_new")' in api \
        or 'json_object_new_string("reject_new")' in api

    # Refusing must not be implemented as eviction: nothing may delete the
    # oldest entry to make room.
    assert "evict" not in store_c.lower()

    # The limit must be evaluated before the snapshot is written, and again
    # under the store lock so concurrent creates cannot both pass.
    create_fn = api[api.index("webd_config_backup_create_for(const char *owner_id"):]
    create_fn = create_fn[:create_fn.index("\n}\n")]
    assert create_fn.index("webd_backup_retention_admit") < create_fn.index("mkstemp"), \
        "retention must be checked before any temp file is created"
    assert create_fn.index("webd_backup_retention_admit") < create_fn.index("webd_config_online_backup"), \
        "retention must be checked before the snapshot runs"
    assert create_fn.index("webd_config_online_backup") < create_fn.index("webd_backup_publish")
    publish = store_c[store_c.index("int webd_backup_publish"):]
    assert publish.index("lock_store") < publish.index("retention_admit_at")

    # ── contract fields the UI needs ──
    for field in ("retention_count", "backup_count", "retention_configured",
                  "retention_min", "retention_max"):
        assert field in api, field

    # ── list must distinguish manual from scheduled ──
    assert 'WEBD_BACKUP_SOURCE_MANUAL    "manual"' in store_h
    assert 'WEBD_BACKUP_SOURCE_SCHEDULED "scheduled"' in store_h
    assert '"source", json_object_new_string(m->source)' in api

    # ── a scheduled run that does not happen must stay visible ──
    assert "webd_backup_last_run_record" in store_c
    assert "last_scheduled_run" in api
    assert '"skipped"' in api, "retention refusal must be recorded, not silent"
    assert "webd_backup_schedule_due" in api
    assert "g_backup_schedule_timer" in api

    # ── capabilities converged ──
    assert 'json_object_object_add(data, "scheduled_backup_supported",\n' \
           '                               json_object_new_boolean(store_ok));' in api
    assert '"no_schedule_retention_or_snapshot_contract_implemented"' not in api

    # ── routed and permissioned ──
    assert "/api/v1/system/flash/backup-policy" in api
    assert '{ "/api/v1/system/flash/backup-policy",      "", JMX_RISK_HIGH },' in perms

    # ── linked into the build ──
    assert "webd/webd_backup_store.o" in makefile

    print("scheduled_backup_retention_contract: PASS")


if __name__ == "__main__":
    main()
