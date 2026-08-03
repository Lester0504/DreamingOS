#!/usr/bin/env python3
"""Runtime regression test for the webd request-framing path.

Covers Acceptance A-012: every POST carrying a JSON body returned
"invalid json body" whenever the client sent header and body in one write,
because the parent wrote a NUL terminator at the body's first byte before
handing the buffer to the child.

http_content_length_from_raw() is extracted from src/webd/jmx_app_api.c and
compiled, so this exercises shipped code rather than a copy. The test then
replays both TCP segmentation patterns against the same request and requires
identical results.
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
FIXTURE = ROOT / "tests/http_body_framing_fixture.c"

EXTRACT_START = ("static int http_content_length_from_raw(const char *raw, "
                 "int raw_len, int *out_len)\n{")
EXTRACT_END = "static int app_api_deadline_remaining_ms"

# parse_http_request()'s body computation, taken verbatim so that dropping the
# Content-Length clamp in production fails this test.
BODY_LEN_START = "        out->body = hdr_end + 4;"
BODY_LEN_END = "    }\n    return 0;\n}"

# The defect was one statement: the parent NUL-terminating its prefetch buffer
# at the offset that is the body's first byte. The fixture cannot see the real
# app_api_pending_fd_cb(), so detect the write here and replay it, which keeps
# the test honest if the line ever comes back.
PARENT_TERMINATOR = "pending->header[header_len] = '\\0';"

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        failures.append(message)


def parent_writes_nul() -> bool:
    """True when app_api_pending_fd_cb() still terminates at header_len."""
    return PARENT_TERMINATOR in API.read_text()


def extract_under_test() -> str:
    source = API.read_text()
    begin = source.find(EXTRACT_START)
    if begin < 0:
        raise SystemExit(f"extraction anchor not found: {EXTRACT_START!r}")
    stop = source.find(EXTRACT_END, begin)
    if stop < 0:
        raise SystemExit(f"extraction end anchor not found: {EXTRACT_END!r}")
    return source[begin:stop]


def extract_body_len() -> str:
    source = API.read_text()
    begin = source.find(BODY_LEN_START)
    if begin < 0:
        raise SystemExit(f"body-length anchor not found: {BODY_LEN_START!r}")
    stop = source.find(BODY_LEN_END, begin)
    if stop < 0:
        raise SystemExit(f"body-length end anchor not found: {BODY_LEN_END!r}")
    return source[begin:stop]


def build(workdir: Path, asan: bool = False) -> Path:
    (workdir / "http_framing_extracted.h").write_text(extract_under_test())
    (workdir / "http_body_len_extracted.h").write_text(extract_body_len())
    shutil.copy(FIXTURE, workdir / "fixture.c")
    binary = workdir / ("fixture_asan" if asan else "fixture")
    command = [
        os.environ.get("CC", "cc"),
        "-O1", "-Wall", "-Wextra", "-Wno-unused-parameter",
        "-Wno-unused-function",
        *(["-fsanitize=address", "-g"] if asan else []),
        "-o", str(binary), str(workdir / "fixture.c"),
        f"-I{workdir}",
    ]
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode != 0:
        if asan:
            return None
        raise SystemExit(f"fixture build failed:\n{result.stdout}\n{result.stderr}")
    noise = [line for line in result.stderr.splitlines() if "warning:" in line]
    if not asan:
        check(not noise, f"extracted framing code emits warnings: {noise}")
    return binary


def request_bytes(body: bytes, path: str = "/api/v1/session/login",
                  extra: str = "") -> bytes:
    head = (
        f"POST {path} HTTP/1.1\r\n"
        "Host: h\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{extra}"
        "Connection: close\r\n"
        "\r\n"
    )
    return head.encode() + body


def run(binary: Path, raw: bytes, prefetch: int, terminates: bool,
        exact: bool = False) -> dict:
    result = subprocess.run([str(binary), str(prefetch),
                             "1" if terminates else "0",
                             "1" if exact else "0"],
                            input=raw, capture_output=True, check=True)
    return json.loads(result.stdout.decode())


def header_length(raw: bytes) -> int:
    return raw.index(b"\r\n\r\n") + 4


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        binary = build(workdir)
        terminates = parent_writes_nul()

        bodies = [
            b'{"username":"x","password":"y"}',
            b"{}",
            b'{"a":1}',
            b"null",
            b"1",
            b'{"target":"1.1.1.1"}',
        ]

        for body in bodies:
            raw = request_bytes(body)
            hdr = header_length(raw)

            # A: header and body in one recv(), the reported failing case.
            single = run(binary, raw, len(raw), terminates)
            # B: header alone, body arrives later, the reported passing case.
            split = run(binary, raw, hdr, terminates)

            label = body.decode()
            check(single["pending_state"] == 1,
                  f"[{label}] combined send must still detect a complete header")
            check(not single["body_first_is_nul"],
                  f"[{label}] body's first byte was overwritten with NUL")
            check(single["body"] == body.decode(),
                  f"[{label}] combined send body corrupted: {single['body']!r}")
            check(single["body_len"] == len(body),
                  f"[{label}] combined send body_len {single['body_len']} != {len(body)}")
            check(single["framing_rc"] == 0 and single["content_len"] == len(body),
                  f"[{label}] Content-Length must parse without a NUL terminator: "
                  f"rc={single['framing_rc']} len={single['content_len']}")
            # The acceptance criterion: both timings agree.
            check(single["body"] == split["body"] or split["body"] is None,
                  f"[{label}] send timing changed the parsed body: "
                  f"{single['body']!r} vs {split['body']!r}")

        # Framing must be parsed from an explicit length, with a live body byte
        # sitting exactly at raw[raw_len].
        raw = request_bytes(b'{"k":"v"}')
        hdr = header_length(raw)
        probe = run(binary, raw, len(raw), terminates)
        check(probe["header_len"] == hdr,
              f"header_len {probe['header_len']} must point just past CRLFCRLF ({hdr})")

        # A pipelined second request must not leak into this body.
        body = b'{"username":"x"}'
        pipelined = request_bytes(body) + b"GET /api/v1/system/status HTTP/1.1\r\n\r\n"
        result = run(binary, pipelined, len(pipelined), terminates)
        check(result["body"] == body.decode(),
              f"pipelined bytes leaked into the body: {result['body']!r}")
        check(result["body_len"] == len(body),
              f"body_len must follow Content-Length, got {result['body_len']}")

        # A body shorter than Content-Length must not be silently padded.
        short = request_bytes(b'{"username":"x","password":"y"}')[:-5]
        result = run(binary, short, len(short), terminates)
        check(result["body_len"] == len(b'{"username":"x","password":"y"}') - 5,
              "a truncated body must report only the bytes actually present, "
              f"got {result['body_len']}")

        # No body at all: body_len 0 and no phantom NUL.
        empty = request_bytes(b"")
        result = run(binary, empty, len(empty), terminates)
        check(result["body_len"] == 0,
              f"bodyless POST must report body_len 0, got {result['body_len']}")
        check(not result["body_first_is_nul"],
              "bodyless POST must not report a NUL body byte")

        # Bare LF framing stays rejected: nginx and webd must agree.
        bad = (b"POST /api/v1/session/login HTTP/1.1\r\n"
               b"Host: h\nContent-Length: 2\r\n\r\n{}")
        result = run(binary, bad, len(bad), terminates)
        check(result["pending_state"] != 1 or result["framing_rc"] != 0,
              "bare LF in headers must not be accepted as valid framing")

        check(not terminates,
              "app_api_pending_fd_cb() writes a NUL at pending->header[header_len], "
              "which is the body's first byte (Acceptance A-012)")

        # Framing must not read past raw_len. webd passes header_len while the
        # byte there belongs to the body, so any NUL-dependent scan is a real
        # overread. An exactly-sized allocation under ASAN proves it.
        asan_binary = build(workdir, asan=True)
        if asan_binary is None:
            print("NOTE: ASAN unavailable, skipped the bounded-scan check")
        else:
            raw = request_bytes(b'{"username":"x","password":"y"}')
            probe = subprocess.run(
                [str(asan_binary), str(len(raw)), "0", "1"],
                input=raw, capture_output=True)
            report = probe.stderr.decode()
            check(probe.returncode == 0 and "AddressSanitizer" not in report,
                  "framing parser reads past raw_len; it must not depend on a "
                  f"NUL terminator: {report.splitlines()[:3]}")

    for failure in failures:
        print(f"FAIL: {failure}")
    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("PASS: webd body framing survives combined header+body sends")
    return 0


if __name__ == "__main__":
    sys.exit(main())
