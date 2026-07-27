#!/usr/bin/env python3
"""Validate the packaged fingerprint catalog as the sole runtime authority."""

from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATABASE = ROOT / "files/fingerprint.db"
APPLICATION_ID = 1146570320
SCHEMA_VERSION = 1
EXPECTED_DEVICES = 33986


CURATED_ENGINE = 9000
CURATED_XIAOMI = {
    9000001: "Xiaomi Router AX3000T",
    9000002: "Xiaomi Router AX3600",
    9000003: "Xiaomi Router AX6000",
    9000004: "Xiaomi Router AX9000",
    9000005: "Xiaomi Router BE3600",
    9000006: "Xiaomi Router BE7000",
    9000007: "Xiaomi Router BE10000",
    9000008: "Xiaomi Router BE10000 Pro",
}
CURATED_SIZES = "51,101,129,257"


def test_catalog_contract() -> None:
    if not DATABASE.is_file():
        raise unittest.SkipTest("private fingerprint database is not part of the public tree")
    db = sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)
    try:
        assert db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("PRAGMA foreign_key_check").fetchone() is None
        meta = dict(db.execute("SELECT key,value FROM fingerprint_meta"))
        assert int(meta["device_count"]) == EXPECTED_DEVICES
        assert meta["source"] == "unifi-public-fingerprint"
        assert db.execute("SELECT COUNT(*) FROM fingerprint_device").fetchone()[0] == EXPECTED_DEVICES
        assert db.execute("SELECT COUNT(*) FROM fingerprint_score_weight").fetchone()[0] == 7
        assert db.execute(
            "SELECT COUNT(*) FROM fingerprint_match_signal WHERE signal_type='oui_vendors'"
        ).fetchone()[0] == 6401
        assert db.execute(
            "SELECT COUNT(*) FROM fingerprint_match_signal WHERE signal_type!='oui_vendors'"
        ).fetchone()[0] == 0
        raw = db.execute(
            "SELECT source_raw_json FROM fingerprint_device "
            "WHERE source_object_id!='' OR source_class_id!='' LIMIT 1"
        ).fetchone()[0]
        assert isinstance(json.loads(raw), dict)
        assert db.execute(
            "SELECT COUNT(*) FROM fingerprint_device "
            "WHERE source_name='' OR source_raw_json=''"
        ).fetchone()[0] == 0
    finally:
        db.close()


def test_curated_xiaomi_router_gallery_entries() -> None:
    if not DATABASE.is_file():
        raise unittest.SkipTest("private fingerprint database is not part of the public tree")
    db = sqlite3.connect(f"file:{DATABASE}?mode=ro", uri=True)
    try:
        rows = db.execute(
            "SELECT device_id,device_name,vendor_name,device_type,family,web_image,best_image,sizes,source_raw_json "
            "FROM fingerprint_device WHERE engine=? ORDER BY device_id",
            (CURATED_ENGINE,),
        ).fetchall()
        assert [row[0] for row in rows] == list(CURATED_XIAOMI)
        by_id = {row[0]: row for row in rows}
        for device_id, expected_name in CURATED_XIAOMI.items():
            row = by_id[device_id]
            assert row[1] == expected_name
            assert row[2] == "Xiaomi Inc."
            assert row[3] == "router"
            assert row[4] == "Router"
            assert row[7] == CURATED_SIZES
            assert row[5].endswith("/257x257.png")
            assert row[6].endswith("/257x257.png")
            raw = json.loads(row[8])
            assert raw["source"] == "dreamingwrt-curated-dev-pic"
            assert raw["device_id"] == device_id
            assert raw["engine"] == CURATED_ENGINE
        assert by_id[9000002][5] == by_id[9000003][5]
        assert by_id[9000002][6] == by_id[9000003][6]
        assert json.loads(by_id[9000002][8])["image_owner_device_id"] == 9000002
        assert json.loads(by_id[9000003][8])["image_owner_device_id"] == 9000002
    finally:
        db.close()


def test_curated_xiaomi_router_gallery_images_exist() -> None:
    if not DATABASE.is_file():
        raise unittest.SkipTest("private fingerprint image library is not part of the public tree")
    owner_ids = [9000001, 9000002, 9000004, 9000005, 9000006, 9000007, 9000008]
    for owner_id in owner_ids:
        directory = ROOT / "files/fingerprint/images" / f"engine-{CURATED_ENGINE}" / str(owner_id)
        assert directory.is_dir(), directory
        for size in (51, 101, 129, 257):
            image = directory / f"{size}x{size}.png"
            assert image.is_file(), image
            header = image.read_bytes()[:24]
            assert header.startswith(b"\x89PNG\r\n\x1a\n"), image
            width = int.from_bytes(header[16:20], "big")
            height = int.from_bytes(header[20:24], "big")
            assert max(width, height) == size
    assert not (ROOT / "files/fingerprint/images" / f"engine-{CURATED_ENGINE}" / "9000003").exists()

if __name__ == "__main__":
    import unittest

    try:
        test_catalog_contract()
        test_curated_xiaomi_router_gallery_entries()
        test_curated_xiaomi_router_gallery_images_exist()
        print("ok: fingerprint.db authority, curated Xiaomi gallery, and lossless source evidence")
    except unittest.SkipTest as skipped:
        # Private datasets are not part of the public tree; skipping is the
        # expected outcome there and must not fail the release contract run.
        print(f"skip: {skipped}")
