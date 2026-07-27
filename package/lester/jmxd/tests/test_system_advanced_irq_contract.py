#!/usr/bin/env python3
"""Static regression checks for the IRQ affinity runtime contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "jmx_netconfig_db.c").read_text(encoding="utf-8")


def require(fragment: str) -> None:
    assert fragment in SOURCE, f"missing IRQ contract fragment: {fragment}"


def main() -> None:
    require("nc_irq_affinity_path_writable")
    require("st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)")
    assert "access(path, W_OK)" not in SOURCE
    require('"writable_irq_count"')
    require('"write_supported"')
    require('"kernel_managed_affinity_or_read_only"')
    require('"irq_affinity_read_only"')
    require("nc_irq_affinity_any_writable()")
    print("system_advanced_irq_contract: PASS")


if __name__ == "__main__":
    main()
