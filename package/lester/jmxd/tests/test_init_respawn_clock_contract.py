from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INIT = ROOT / "src" / "init" / "dreamingwrt_init.c"


def test_respawn_deadline_is_bounded_after_wall_clock_rollback():
    source = INIT.read_text()

    assert "DWRT_MAX_RESPAWN_BACKOFF_SEC 60" in source
    assert "component_respawn_in_sec" in source
    assert "remaining <= DWRT_MAX_RESPAWN_BACKOFF_SEC" in source
    assert "c->next_respawn_at = now + delay" in source
    assert source.count("component_respawn_in_sec(c, now)") >= 4
