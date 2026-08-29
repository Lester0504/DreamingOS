#!/usr/bin/env python3
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from jmxd.tests.webd_sources import webd_dispatch_text


SOURCE = webd_dispatch_text()


def main():
    assert "APP_API_REQUEST_DEADLINE_MS" in SOURCE
    assert "clock_gettime(CLOCK_MONOTONIC" in SOURCE
    assert "app_api_deadline_remaining_ms" in SOURCE
    dispatch = SOURCE[SOURCE.index("static void client_fd_cb") :]
    assert '!strcmp(path, "/api/v1/events/stream")' in dispatch
    assert "pid_t pid = fork();" in dispatch
    assert "app_api_parent_fast_route(method, path) ||" not in dispatch
    assert "app_api_child_safe_route(method, path))" not in dispatch
    assert "content_length_count > 1" in SOURCE
    assert "transfer_encoding_count != 0" in SOURCE
    assert "*line == ' ' || *line == '\\t'" in SOURCE
    assert "line[-1] != '\\r'" in SOURCE
    print("ok: webd absolute deadline and strict framing contract")


if __name__ == "__main__":
    main()
