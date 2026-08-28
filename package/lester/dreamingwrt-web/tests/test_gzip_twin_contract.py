#!/usr/bin/env python3
"""Every shipped static source with a gzip twin must match it byte-for-byte."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from verify_gzip_twins import check, source_paths  # noqa: E402


failures = [problem for path in source_paths([]) if (problem := check(path))]
assert not failures, "stale or invalid gzip twins:\n  " + "\n  ".join(failures)
print(f"gzip twin contract: ok ({len(source_paths([]))} pairs)")
