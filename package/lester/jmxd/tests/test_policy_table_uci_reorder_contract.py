from pathlib import Path
import re
import os
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
WEB = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def section(name, kind):
    return {"name": name, "kind": kind}


def reorder_same_scope(items, target_kinds, requested_names):
    """Model the C executor's complete-package desired-order algorithm."""
    slots = [i for i, item in enumerate(items) if item["kind"] in target_kinds]
    targets = {item["name"]: item for item in items if item["kind"] in target_kinds}
    assert len(slots) == len(requested_names)
    desired = list(items)
    for slot, name in zip(slots, requested_names):
        desired[slot] = targets[name]
    return desired


def test_foreign_firewall_sections_keep_absolute_slots():
    original = [
        section("defaults", "defaults"),
        section("lan", "zone"),
        section("r1", "rule"),
        section("custom", "include"),
        section("r2", "rule"),
        section("wan", "zone"),
        section("r3", "rule"),
    ]
    result = reorder_same_scope(original, {"rule"}, ["r3", "r1", "r2"])
    assert [x["name"] for x in result] == [
        "defaults", "lan", "r3", "custom", "r1", "wan", "r2"
    ]
    for index in (0, 1, 3, 5):
        assert result[index] is original[index]


def test_route4_route6_share_one_ordered_scope():
    original = [
        section("lan", "interface"),
        section("v4-a", "route"),
        section("wan", "interface"),
        section("v6-a", "route6"),
        section("v4-b", "route"),
    ]
    result = reorder_same_scope(
        original, {"route", "route6"}, ["v4-b", "v6-a", "v4-a"]
    )
    assert [x["name"] for x in result] == [
        "lan", "v4-b", "wan", "v6-a", "v4-a"
    ]


def test_executor_uses_real_uci_reorder_and_guarded_transaction():
    for token in (
        "uci_reorder_section(ctx, desired[i], i)",
        "uci_save(ctx, pkg)",
        "uci_commit(ctx, &pkg, false)",
        "webd_policy_copy_file(sc->config_path",
        "policy_reorder_runtime_reload_failed",
        "config_restored_from_backup",
        "reorder_incomplete_scope",
        "reorder_scope_conflict",
        "LOCK_EX | LOCK_NB",
        "policy_write_busy",
        '"refresh_required"',
        '"row_ids_may_change"',
    ):
        assert token in WEB


def test_capability_matches_supported_scopes():
    for policy_type in (
        "pbr", "firewall", "port_forwarding", "nat", "static_route", "dns", "qos"
    ):
        assert f'json_object_new_string("{policy_type}")' in WEB
    assert '"reorder_full_scope_required"' in WEB
    assert '"reorder_uci_foreign_sections_preserved"' in WEB
    assert '"reorder_mixed_sources_supported"' in WEB


def test_dispatch_is_not_pbr_only_anymore():
    dispatch = re.search(
        r'if \(!strcmp\(operation, "reorder"\)\)\s*return ([^;]+);', WEB
    )
    assert dispatch
    assert "webd_policy_reorder_response" in dispatch.group(1)
    assert "webd_policy_pbr_reorder_response" not in dispatch.group(1)


def test_real_libuci_preserves_foreign_slots_when_available():
    """Exercise libuci itself without touching /etc/config.

    This runs on OpenWrt/build hosts that provide uci.h and libuci. Local macOS
    development hosts legitimately skip it; the 31.6 target-toolchain run is
    the authoritative execution.
    """
    cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
    cflags = os.environ.get("POLICY_REORDER_UCI_CFLAGS", "")
    ldflags = os.environ.get("POLICY_REORDER_UCI_LDFLAGS", "")
    if not cc or not cflags or not ldflags:
        return
    source = r'''
#include <stdio.h>
#include <string.h>
#include <uci.h>

static int is_rule(struct uci_section *s) {
    return s && s->type && !strcmp(s->type, "rule");
}

int main(int argc, char **argv) {
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;
    struct uci_section *all[32], *rules[3], *desired[32];
    int slots[3], n = 0, rn = 0, i, pos;

    if (argc != 2) return 2;
    ctx = uci_alloc_context();
    if (!ctx) return 3;
    uci_set_confdir(ctx, argv[1]);
    if (uci_load(ctx, "firewall", &pkg) != UCI_OK || !pkg) return 4;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (n >= 32) return 5;
        all[n] = desired[n] = s;
        if (is_rule(s)) {
            if (rn >= 3) return 6;
            slots[rn] = n;
            rules[rn++] = s;
        }
        n++;
    }
    if (n != 7 || rn != 3) return 7;
    desired[slots[0]] = rules[2];
    desired[slots[1]] = rules[0];
    desired[slots[2]] = rules[1];
    for (i = 0; i < n; i++) {
        int cur = 0;
        uci_foreach_element(&pkg->sections, e) {
            if (uci_to_section(e) == desired[i]) break;
            cur++;
        }
        if (cur != i && uci_reorder_section(ctx, desired[i], i) != UCI_OK)
            return 8;
    }
    if (uci_save(ctx, pkg) != UCI_OK || uci_commit(ctx, &pkg, false) != UCI_OK)
        return 9;
    pos = 0;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        printf("%d:%s:%s\n", pos++, s->type, s->e.name ? s->e.name : "");
    }
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return 0;
}
'''
    fixture = """\
config defaults 'defaults'\n\toption input 'REJECT'\n\n
config zone 'lan'\n\toption name 'lan'\n\n
config rule 'r1'\n\toption name 'r1'\n\n
config include 'custom'\n\toption path '/tmp/custom'\n\n
config rule 'r2'\n\toption name 'r2'\n\n
config zone 'wan'\n\toption name 'wan'\n\n
config rule 'r3'\n\toption name 'r3'\n
"""
    with tempfile.TemporaryDirectory(prefix="policy-uci-reorder-") as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "fixture.c").write_text(source, encoding="utf-8")
        (tmp_path / "firewall").write_text(fixture, encoding="utf-8")
        subprocess.run(
            [cc, *cflags.split(), str(tmp_path / "fixture.c"),
             *ldflags.split(), "-luci", "-o", str(tmp_path / "fixture")],
            check=True,
        )
        run = subprocess.run(
            [str(tmp_path / "fixture"), str(tmp_path)],
            check=True, text=True, capture_output=True,
            env={**os.environ, "LD_LIBRARY_PATH": os.environ.get("POLICY_REORDER_UCI_LIBDIR", "")},
        )
        assert run.stdout.splitlines() == [
            "0:defaults:defaults", "1:zone:lan", "2:rule:r3",
            "3:include:custom", "4:rule:r1", "5:zone:wan", "6:rule:r2",
        ]
