#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    source = (ROOT / "src/routed/routed_main.c").read_text(encoding="utf-8")
    assert '#define ROUTED_INITIAL_DELAY_MS 1000' in source
    assert '#define ROUTED_RETRY_DELAY_MS 3000' in source
    assert 'route_invoke_reload()' in source
    assert 'route_proc_has_wan()' in source
    assert '"route_reload"' in source
    assert 'blobmsg_get_u32(tb[0]) == 2000' in source
    assert source.index('route_invoke_reload()') < source.index('route_invoke_tick()', source.index('static void route_tick_cb'))
    assert 'route_runtime_loaded ? ROUTED_INTERVAL_MS : ROUTED_RETRY_DELAY_MS' in source
    print("ok: routed replays route_reload before health ticks and self-heals an empty kernel table")


if __name__ == "__main__":
    main()
