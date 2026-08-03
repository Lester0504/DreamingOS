#!/usr/bin/env python3
"""Runtime test for the shared event-socket single-instance guard.

This regression is one I caused on a live router: starting a second webd on a
different port, bound only to loopback, stole the running instance's event
socket and deleted the path on exit. SSE delivery went silently dead while the
HTTP API kept answering normally, so nothing looked broken.

Two real processes race for the same path here. The losing one must not acquire
the socket and, critically, must not remove the winner's path when it exits.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "src/webd/jmx_app_api.c"
FIXTURE = ROOT / "tests/event_socket_guard_fixture.c"

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def build(workdir: Path) -> Path:
    shutil.copy(FIXTURE, workdir / "fixture.c")
    binary = workdir / "fixture"
    result = subprocess.run(
        [os.environ.get("CC", "cc"), "-O1", "-Wall", "-Wextra",
         "-Wno-unused-parameter", "-o", str(binary), str(workdir / "fixture.c")],
        text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(f"fixture build failed:\n{result.stdout}\n{result.stderr}")
    noise = [line for line in result.stderr.splitlines() if "warning:" in line]
    check(not noise, f"guard fixture emits warnings: {noise}")
    return binary


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        binary = build(workdir)
        sock = workdir / "events.sock"

        # First instance takes the socket and keeps holding it.
        holder = subprocess.Popen([str(binary), str(sock), "hold"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True)
        first = json.loads(holder.stdout.readline())
        check(first["acquired"] is True, "the first instance must acquire the socket")
        check(first["owned"] is True, "the first instance must be marked as owner")
        check(first["socket_present"] is True, "the socket path must exist after bind")

        # Second instance, exactly the situation that broke the live router.
        rival = subprocess.run([str(binary), str(sock), "try"],
                               text=True, capture_output=True, check=True)
        second = json.loads(rival.stdout)
        check(second["acquired"] is False,
              "a second instance must not acquire the shared event socket")
        check(second["owned"] is False,
              "a second instance must never be marked as owner")
        # The whole point: the loser's exit must leave the winner's path intact.
        check(second["socket_present_after_exit"] is True,
              "a second instance deleted the running instance's socket path")
        check(sock.exists(),
              "the socket path is gone after a losing instance exited")

        # The owner still releases its own path on a clean shutdown.
        holder.stdin.write("\n")
        holder.stdin.flush()
        released = json.loads(holder.stdout.readline())
        holder.wait(timeout=10)
        check(released["socket_present"] is False,
              "the owning instance must remove its socket path on shutdown")

        # After the owner is gone the lock is free again, so a restart works.
        restart = subprocess.run([str(binary), str(sock), "try"],
                                 text=True, capture_output=True, check=True)
        third = json.loads(restart.stdout)
        check(third["acquired"] is True,
              "a restart must be able to take the socket once the owner exits")

        # Production source must actually carry the guard, not just the fixture.
        source = API.read_text()
        check("APP_API_EVENT_SOCKET_LOCK" in source,
              "jmx_app_api.c must define a lock path for the event socket")
        check("flock(lock_fd, LOCK_EX | LOCK_NB)" in source,
              "app_event_socket_init() must take a non-blocking exclusive lock")
        check("if (g_event_socket_owned)\n            unlink(APP_API_EVENT_SOCKET)" in source,
              "the unlink in jmx_app_api_done() must be gated on ownership")
        # The child must not inherit ownership or pin the lock.
        check(source.count("g_event_socket_owned = 0;") >= 3,
              "request and AI-worker children must both clear event-socket ownership")

    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("PASS: a second webd cannot steal or delete the shared event socket")
    return 0


if __name__ == "__main__":
    sys.exit(main())
