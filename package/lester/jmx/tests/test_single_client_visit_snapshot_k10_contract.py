#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "jmx_client_fs.c").read_text(encoding="utf-8")


def function_body(name: str) -> str:
    match = re.search(
        rf"static\s+[^;{{]*?\b{re.escape(name)}\s*\([^;{{]*\)\s*\{{",
        SOURCE,
    )
    assert match, f"function not found: {name}"
    start = match.end()
    depth = 1
    for offset, char in enumerate(SOURCE[start:], start=start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start:offset]
    raise AssertionError(f"unterminated function: {name}")


def test_snapshot_is_bounded_and_lock_only_copies_pod() -> None:
    body = function_body("single_client_visit_take_snapshot")
    lock = body.index("spin_lock_bh(&st->client->visit_info_lock);")
    unlock = body.index("spin_unlock_bh(&st->client->visit_info_lock);")
    critical = body[lock:unlock]

    assert "st->snapshot_count >= MAX_RECORD_APP_NUM" in critical
    assert "st->snapshot_truncated = true;" in critical
    assert "snapshot = &st->snapshots[st->snapshot_count++];" in critical
    for field in (
        "app_id",
        "total_num",
        "drop_num",
        "conn_count",
        "is_http",
        "latest_time",
        "latest_action",
    ):
        assert f"snapshot->{field} = info->{field};" in critical
    assert "seq_" not in critical
    assert "kmalloc" not in critical
    assert "kcalloc" not in critical
    assert "kfree" not in critical


def test_seq_iteration_and_formatting_are_lock_free_snapshot_reads() -> None:
    for name in (
        "single_client_visit_seq_start",
        "single_client_visit_seq_next",
        "single_client_visit_seq_stop",
        "single_client_visit_seq_show",
    ):
        body = function_body(name)
        assert "spin_lock" not in body
        assert "spin_unlock" not in body
        assert "visit_info_hash" not in body

    start = function_body("single_client_visit_seq_start")
    next_body = function_body("single_client_visit_seq_next")
    show = function_body("single_client_visit_seq_show")
    assert "index = *pos - 1;" in start
    assert "index < st->snapshot_count" in start
    assert "(*pos)++;" in next_body
    assert "index < st->snapshot_count" in next_body
    assert "struct single_client_visit_snapshot *snapshot = v;" in show
    assert "%-8u %-8u %-8u %-8u %-8u %-12lu %-12u %-10u\\n" in show


def test_open_oom_and_seq_open_failures_release_all_ownership() -> None:
    opened = function_body("single_client_visit_open")
    acquire = opened.index("af_client_get_if_live(client)")
    alloc_iter = opened.index("kzalloc(sizeof(*iter), GFP_KERNEL)")
    alloc_snapshot = opened.index("kcalloc(MAX_RECORD_APP_NUM")
    take_snapshot = opened.index("single_client_visit_take_snapshot(iter)")
    seq_open = opened.index("seq_open(file, &single_client_visit_seq_ops)")
    assert acquire < alloc_iter < alloc_snapshot < take_snapshot < seq_open

    snapshot_oom = opened[alloc_snapshot:take_snapshot]
    assert snapshot_oom.index("kfree(iter);") < snapshot_oom.index(
        "af_client_put(client);"
    )
    seq_failure = opened[seq_open:]
    assert seq_failure.index("kfree(iter->snapshots);") < seq_failure.index(
        "kfree(iter);"
    ) < seq_failure.index("af_client_put(client);")


def test_release_frees_snapshot_and_drops_client_reference() -> None:
    release = function_body("single_client_visit_release")
    free_snapshot = release.index("kfree(snapshots);")
    release_private = release.index("seq_release_private(inode, file)")
    put_client = release.index("af_client_put(client);")
    assert free_snapshot < release_private < put_client


def test_snapshot_position_model_handles_empty_partial_and_truncated_reads() -> None:
    maximum = 64

    def visible(rows):
        snapshot = rows[:maximum]
        output = ["HEADER"]
        output.extend(snapshot)
        return output

    assert visible([]) == ["HEADER"]
    assert visible(["one", "two"]) == ["HEADER", "one", "two"]
    rows = [f"row-{index}" for index in range(80)]
    output = visible(rows)
    assert len(output) == maximum + 1
    assert output[-1] == "row-63"
    assert len(output) == len(set(output))


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("ok: K-10 single-client visit snapshot contract passed")
