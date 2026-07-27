#!/usr/bin/env python3
"""Validate the region-blocking flag asset and firmware install contract."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"
FLAG_DIR = ROOT / "files" / "logo" / "flags"
EXPECTED_COUNT = 258
ALLOWED_SUFFIXES = {".svg"}
FLAG_NAME = re.compile(r"^[a-z]{2}(?:-[a-z]{2,3})?\.svg$")


def flag_assets() -> list[Path]:
    if not FLAG_DIR.is_dir():
        raise unittest.SkipTest("private logo and flag library is not part of the public tree")
    return sorted(path for path in FLAG_DIR.iterdir() if path.is_file())


def test_flag_asset_inventory() -> None:
    assets = flag_assets()
    assert len(assets) == EXPECTED_COUNT
    assert all(path.stat().st_size > 0 for path in assets)
    assert {path.suffix.lower() for path in assets} <= ALLOWED_SUFFIXES
    assert all(FLAG_NAME.fullmatch(path.name) for path in assets)


def test_required_country_codes_exist() -> None:
    if not FLAG_DIR.is_dir():
        raise unittest.SkipTest("private logo and flag library is not part of the public tree")
    for filename in ("cn.svg", "us.svg", "gb.svg", "jp.svg", "de.svg"):
        assert (FLAG_DIR / filename).is_file(), filename


def test_flags_do_not_collide_with_flat_logo_assets() -> None:
    if not FLAG_DIR.is_dir():
        raise unittest.SkipTest("private logo and flag library is not part of the public tree")
    logo_dir = ROOT / "files" / "logo"
    flat_assets = {path.name: path for path in logo_dir.iterdir() if path.is_file()}
    collisions = set(flat_assets) & {path.name for path in flag_assets()}

    # bt.svg is BitTorrent in the app namespace and Bhutan in the flag namespace.
    assert collisions == {"bt.svg"}
    assert flat_assets["bt.svg"].read_bytes() != (FLAG_DIR / "bt.svg").read_bytes()


def test_firmware_install_path_is_stable_and_separate() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    destination = "$(1)/www/dreamingwrt/static/images/flags"
    assert destination in makefile
    assert "config DREAMINGWRT_LOGOS" in makefile
    assert "default n" in makefile[makefile.index("config DREAMINGWRT_LOGOS"):]
    assert "$(CP) ./files/logo/flags/*.svg " + destination + "/" in makefile
    assert "$(CP) ./files/logo/*" not in makefile


if __name__ == "__main__":
    import unittest

    try:
        test_flag_asset_inventory()
        test_required_country_codes_exist()
        test_flags_do_not_collide_with_flat_logo_assets()
        test_firmware_install_path_is_stable_and_separate()
        print("ok: flag assets contract")
    except unittest.SkipTest as skipped:
        # Private datasets are not part of the public tree; skipping is the
        # expected outcome there and must not fail the release contract run.
        print(f"skip: {skipped}")
