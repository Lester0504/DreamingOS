#!/usr/bin/env python3
"""Contract tests for group permission tiers and periodic password rotation.

Covers the two 2026-08-09 Front->Backend handoffs. Source-level assertions,
matching the style of the other webd contract tests in this directory: the
behaviour lives in one 70k-line file, and pinning the exact SQL and response
keys is what stops a later edit from silently reverting the contract the
frontend was built against.
"""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT.parent))
from jmxd.tests.webd_sources import webd_dispatch_text
WEBD = webd_dispatch_text()


# ── Group permission tiers ──

def test_group_tier_columns_are_migrated_not_rebuilt() -> None:
    """Existing installs must gain the columns without a table rebuild."""
    assert 'config_db_add_column_if_missing("web_user_groups", "permission_tier"' in WEBD
    assert 'config_db_add_column_if_missing("web_user_groups", "permissions_json"' in WEBD
    # Empty tier is the "never chose one" state; a NOT NULL default keeps it
    # distinguishable from a tier that grants nothing.
    assert "permission_tier TEXT NOT NULL DEFAULT ''" in WEBD
    assert "permissions_json TEXT NOT NULL DEFAULT '[]'" in WEBD


def test_group_tiers_reuse_the_existing_permission_vocabulary() -> None:
    """Tiers are presets over the user whitelist, not a second vocabulary."""
    tiers = WEBD.split("static const struct webd_group_tier *webd_group_tiers", 1)[1]
    tiers = tiers.split("static const struct webd_group_tier *webd_group_tier_find", 1)[0]
    for tier_id in ("readonly", "operator", "admin", "full", "custom"):
        assert f'"{tier_id}"' in tiers
    # Preset tiers list every lower grant explicitly, so an individual-grant
    # check cannot read "write.high only" as implying the ones below it.
    assert '"read", "write.low", "write.medium", "write.high"' in tiers
    # No invented permission names: every string must come from the whitelist
    # webd_directory_permissions_ok() enforces.
    allowed = {
        "read", "write.low", "write.medium", "write.high", "ai.low",
        "dreamingproxy.read", "dreamingproxy.operate", "dreamingproxy.configure",
        "dreamingproxy.apply", "dreamingproxy.secrets", "dreamingproxy.audit",
    }
    for line in tiers.splitlines():
        if "{ \"" not in line and '"read"' not in line:
            continue
        for token in line.split('"')[1::2]:
            if token in ("readonly", "operator", "admin", "full", "custom"):
                continue
            if token.startswith(("只读", "运维", "管理", "完全", "自定义", "仅可", "可查看", "可执行", "包含", "逐项")):
                continue
            assert token in allowed, f"tier permission outside whitelist: {token}"


def test_group_read_returns_tier_and_permissions() -> None:
    listing = WEBD.split("static struct json_object *webd_directory_groups_list", 1)[1]
    listing = listing.split("static int webd_directory_group_members_replace", 1)[0]
    assert "permission_tier,permissions_json" in listing
    assert 'webd_obj_add_str(group, "permission_tier"' in listing
    assert '"permissions"' in listing


def test_group_write_validates_tier_and_permissions() -> None:
    write = WEBD.split("static struct json_object *webd_directory_group_write", 1)[1]
    write = write.split("static struct json_object *webd_directory_group_delete", 1)[0]
    assert "webd_group_tier_ok(permission_tier)" in write
    # Group permissions are held to the same whitelist as a user's own grants.
    assert 'webd_directory_permissions_ok(body, "permissions")' in write
    assert '"invalid_group_permissions"' in write
    # A named preset defines its own set, so the tier label and the stored
    # permissions cannot drift apart.
    assert "webd_group_tier_permissions_text(tier" in write
    assert "permission_tier=COALESCE(?5,permission_tier)" in write
    assert "permissions_json=COALESCE(?6,permissions_json)" in write


def test_group_tier_is_enforced_not_merely_stored() -> None:
    """The tier must reach the request path, or it is a label enforcing nothing."""
    enforce = WEBD.split("static int webd_group_permission_allows", 1)[1]
    enforce = enforce.split("static void webd_group_tier_permissions_text", 1)[0]
    # Individual grants, not an ordered ceiling: a custom tier holding only
    # write.high must not imply write.low and write.medium.
    assert "webd_permission_array_has(permissions, generic_permission)" in enforce
    assert "native_permission" in enforce
    # Every tiered group must agree; membership is a set of limits.
    assert "return 0;" in enforce
    # Storage failure must not fail open.
    assert "return -1;" in enforce
    assert "step_rc == SQLITE_DONE ? 1 : -1" in enforce


def test_group_tier_denial_is_wired_into_the_dispatcher() -> None:
    assert "webd_group_permission_allows(device_id, risk," in WEBD
    assert '"group_permission_denied"' in WEBD
    assert '"group_permission_state_unavailable"' in WEBD
    # API keys and app devices have no group membership; they must not be
    # measured against a ceiling that does not exist for them.
    assert "if (!api_key_authenticated) {" in WEBD


def test_group_capabilities_are_published() -> None:
    caps = WEBD.split("static void webd_directory_add_capabilities", 1)[1]
    caps = caps.split("/* ── API-Key management", 1)[0]
    assert '"group_permission_tier", json_object_new_boolean(1)' in caps
    assert '"group_permission_tiers"' in caps
    for key in ('"id"', '"label"', '"hint"', '"permissions"'):
        assert key in caps


# ── Periodic password rotation ──

def test_rotation_columns_exist_and_do_not_reuse_updated_at() -> None:
    assert 'config_db_add_column_if_missing("web_users", "password_rotate_days"' in WEBD
    assert 'config_db_add_column_if_missing("web_users", "password_changed_at"' in WEBD
    assert 'config_db_add_column_if_missing("web_users", "password_must_change"' in WEBD
    assert "password_rotate_days INTEGER NOT NULL DEFAULT 0" in WEBD
    assert "password_changed_at INTEGER NOT NULL DEFAULT 0" in WEBD


def test_unknown_change_time_does_not_expire_the_password() -> None:
    """changed_at == 0 means unknown, not infinitely old.

    Treating unknown as expired would lock every pre-upgrade account out of the
    console at its first login after the column appeared.
    """
    check = WEBD.split("static int webd_password_change_required", 1)[1]
    check = check.split("static int webd_user_password_rotate", 1)[0]
    assert "rotate_days > 0 && changed_at > 0" in check
    # An unreadable policy must not silently disable itself.
    assert "return -1;" in check


def test_user_get_returns_the_three_fields_and_derived_expiry() -> None:
    user_json = WEBD.split("static struct json_object *webd_directory_user_json", 1)[1]
    user_json = user_json.split("static sqlite3_stmt *webd_directory_users_stmt", 1)[0]
    for key in ('"password_rotate_days"', '"password_changed_at"',
                '"password_must_change"', '"password_expires_at"'):
        assert key in user_json
    stmt = WEBD.split("static sqlite3_stmt *webd_directory_users_stmt", 1)[1]
    stmt = stmt.split("static void webd_directory_add_capabilities", 1)[0]
    assert "password_rotate_days,password_changed_at,password_must_change" in stmt


def test_patch_accepts_rotate_days_within_bounds() -> None:
    update = WEBD.split("static struct json_object *webd_directory_user_update", 1)[1]
    update = update.split("static struct json_object *webd_directory_user_delete", 1)[0]
    assert 'json_object_object_get_ex(body, "password_rotate_days"' in update
    assert '"invalid_password_rotate_days"' in update
    assert "> 3650" in update
    assert "password_rotate_days=COALESCE(?10,password_rotate_days)" in update


def test_every_password_write_stamps_the_clock() -> None:
    """A missed stamp re-prompts the user immediately after they changed it."""
    # Administrator reset through the user detail PATCH.
    assert "password_changed_at=CASE WHEN ?7 IS NOT NULL THEN ?8 ELSE password_changed_at END" in WEBD
    assert "password_must_change=CASE WHEN ?7 IS NOT NULL THEN 0" in WEBD
    # Creation paths seed the clock so the window starts counting.
    assert "last_login_at,display_name,email,assignments_json,password_changed_at" in WEBD
    assert "last_login_at,password_changed_at" in WEBD
    # The forced-change login write.
    assert "UPDATE web_users SET password_hash=?1,password_changed_at=?2," in WEBD
    # The system-settings admin transaction, forward and compensating halves.
    assert "password_changed_at=CASE WHEN ?5 THEN ?3 ELSE password_changed_at END" in WEBD
    assert "password_changed_at=?5,password_must_change=?6" in WEBD
    assert "old_password_changed_at" in WEBD


def test_login_signals_rotation_without_overloading_401_semantics() -> None:
    login = WEBD.split("static struct json_object *jmx_web_login_ex", 1)[1]
    login = login.split("static int gen_pair_code", 1)[0]
    # Explicit signal the frontend already matches on, both shapes.
    assert '"password_change_required"' in login
    assert '"password_expires_at"' in login
    # Distinct codes so a plain typo is never presented as "time to rotate".
    assert '"password_confirm_mismatch"' in login
    assert '"password_reuse_denied"' in login
    assert '"password_policy_state_unavailable"' in login
    # The session response tells the client the rotation actually happened.
    assert '"password_rotated"' in login


def test_rotation_write_happens_after_the_2fa_gate() -> None:
    """A stolen password alone must not be able to replace the credential."""
    login = WEBD.split("static struct json_object *jmx_web_login_ex", 1)[1]
    login = login.split("static int gen_pair_code", 1)[0]
    twofa_gate = login.index("webd_totp_verify_secret")
    rotate_call = login.index("webd_user_password_rotate(username, password, new_password)")
    assert rotate_call > twofa_gate
    # The expiry signal itself is emitted before the 2FA prompt, so the browser
    # learns it must rotate on the first correct password.
    assert login.index('"password_change_required"') < twofa_gate


def test_rotation_verifies_the_old_password_at_the_write() -> None:
    rotate = WEBD.split("static int webd_user_password_rotate", 1)[1]
    rotate = rotate.split("static int webd_user_get_role", 1)[0]
    assert "webd_password_verify(old_password, stored)" in rotate
    assert "strlen(new_password) < 8" in rotate
    assert "strcmp(old_password, new_password)" in rotate
    assert "OPENSSL_cleanse(stored" in rotate
    assert "OPENSSL_cleanse(hash" in rotate


def test_rotation_capabilities_are_published() -> None:
    caps = WEBD.split("static void webd_directory_add_capabilities", 1)[1]
    caps = caps.split("/* ── API-Key management", 1)[0]
    assert '"password_rotation", json_object_new_boolean(1)' in caps
    assert '"password_rotate_choices"' in caps
    assert '"value"' in caps and '"label"' in caps


# ── Per-user API-Key creation deny ──

def test_api_key_creation_deny_column_is_migrated_with_false_default() -> None:
    assert 'config_db_add_column_if_missing("web_users", "api_key_create_denied"' in WEBD
    assert "api_key_create_denied INTEGER NOT NULL DEFAULT 0" in WEBD


def test_user_reads_always_return_api_key_creation_deny() -> None:
    user_json = WEBD.split("static struct json_object *webd_directory_user_json", 1)[1]
    user_json = user_json.split("static sqlite3_stmt *webd_directory_users_stmt", 1)[0]
    assert '"api_key_create_denied"' in user_json
    stmt = WEBD.split("static sqlite3_stmt *webd_directory_users_stmt", 1)[1]
    stmt = stmt.split("static void webd_directory_add_capabilities", 1)[0]
    assert "api_key_create_denied" in stmt


def test_api_key_creation_deny_capability_is_published() -> None:
    caps = WEBD.split("static void webd_directory_add_capabilities", 1)[1]
    caps = caps.split("/* ── API-Key management", 1)[0]
    assert '"api_key_deny_per_user", json_object_new_boolean(1)' in caps


def test_patch_requires_a_boolean_and_persists_api_key_creation_deny() -> None:
    update = WEBD.split("static struct json_object *webd_directory_user_update", 1)[1]
    update = update.split("static struct json_object *webd_directory_user_delete", 1)[0]
    assert 'json_object_object_get_ex(body, "api_key_create_denied"' in update
    assert "json_type_boolean" in update
    assert '"invalid_api_key_create_denied"' in update
    assert "api_key_create_denied=COALESCE(?12,api_key_create_denied)" in update
    assert "sqlite3_bind_int(st, 12, api_key_create_denied)" in update


def test_owner_cannot_be_denied_api_key_creation() -> None:
    update = WEBD.split("static struct json_object *webd_directory_user_update", 1)[1]
    update = update.split("static struct json_object *webd_directory_user_delete", 1)[0]
    assert "api_key_create_denied == 1" in update
    assert '"api_key_create_deny_owner_forbidden"' in update
    assert "!strcmp(role ? role : old_role, \"owner\")" in update


def test_api_key_create_is_denied_for_the_current_web_user_only() -> None:
    create = WEBD.split("static struct json_object *webd_api_keys_create_response", 1)[1]
    create = create.split("/* Key ids are generated hex", 1)[0]
    assert "webd_identity_is_user(created_by)" in create
    assert "webd_identity_username(created_by)" in create
    assert '"api_key_create_denied_for_user"' in create
    assert '"api_key_create_policy_unavailable"' in create
    assert "if (api_key_create_denied)" in create
    assert "webd_api_key_revoke" not in create
    assert "webd_api_key_delete" not in create
