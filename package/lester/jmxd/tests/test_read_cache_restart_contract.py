#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "dw_read_cache.c").read_text()


def function_body(name: str) -> str:
    start = SOURCE.index(f"void {name}(void)")
    end = SOURCE.index("\n}", start) + 2
    return SOURCE[start:end]


def test_read_cache_timer_restarts_after_stop() -> None:
    init = function_body("dw_read_cache_init")
    stop = function_body("dw_read_cache_stop")

    assert "if (!g_cache.initialised)" in init
    assert "g_cache.running = 1;" in init
    assert "uloop_timeout_set(&g_cache.refresh_tm, 100);" in init
    assert init.index("g_cache.running = 1;") < init.index("uloop_timeout_set")
    assert "if (g_cache.initialised)\n        return;" not in init

    assert "g_cache.running = 0;" in stop
    assert "uloop_timeout_cancel(&g_cache.refresh_tm);" in stop


if __name__ == "__main__":
    test_read_cache_timer_restarts_after_stop()
    print("read cache restart contract: ok")
