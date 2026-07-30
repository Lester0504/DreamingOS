#!/usr/bin/env python3
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/webd/jmx_app_api.c").read_text(encoding="utf-8")


def function(name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", SOURCE, re.DOTALL)
    assert match, name
    start = SOURCE.index("{", match.start())
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(SOURCE)):
        char = SOURCE[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[match.start():index + 1]
    raise AssertionError(name)


def test_accept_loop_never_peeks_or_runs_a_request() -> None:
    accept = function("client_fd_cb")
    assert "app_api_set_nonblock(cfd)" in accept
    assert "app_api_pending_add(cfd)" in accept
    for forbidden in ("poll(", "recv(", "MSG_PEEK", "handle_client(cfd)",
                      "app_api_wait_first_byte(cfd)"):
        assert forbidden not in accept, forbidden


def test_pending_state_machine_has_budgets_deadline_and_cleanup() -> None:
    callback = function("app_api_pending_fd_cb")
    dispatch = function("app_api_dispatch_ready")
    sweep = function("app_api_pending_sweep_timer_cb")
    add = function("app_api_pending_add")
    done = function("jmx_app_api_done")

    assert "MSG_DONTWAIT" in callback
    assert "MSG_PEEK" not in callback
    assert "pending->header + pending->header_len" in callback
    assert "g_handoff_prefix" in SOURCE
    reader = function("read_http_request_complete")
    assert "size_t initial_len" in reader
    assert "if (total >= need)" in reader
    assert "APP_API_MAX_HEADER" in callback
    assert "http_content_length_from_raw" in callback
    assert "SSE request body is not allowed" in callback
    for marker in ("APP_API_MAX_CLIENTS", "APP_API_MAX_HEADER_LINES",
                   "APP_API_MAX_HEADER_LINE", "APP_API_PENDING_SWEEP_MS"):
        assert marker in SOURCE
    assert "CLOCK_MONOTONIC" in add
    assert "APP_API_FIRST_BYTE_TIMEOUT_MS" in add
    assert "request header deadline exceeded" in sweep
    assert "app_api_pending_close(&g_pending_clients[i])" in done
    assert "g_sse_count >= MAX_SSE_CLIENTS" in dispatch
    assert "count >= limit" in dispatch
    assert "handle_client(fd);" not in dispatch[dispatch.index("if (pid > 0)"):]


def test_production_parser_with_slow_and_ready_sockets() -> None:
    enum_block = SOURCE[SOURCE.index("enum app_api_pending_result"):
                        SOURCE.index("static void app_api_pending_close", SOURCE.index("enum app_api_pending_result"))]
    parser = "static int " + function("app_api_parse_route_line")
    header = "static int " + function("app_api_pending_header")
    fixture = f"""
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#define APP_API_READ_BUF 16384
#define APP_API_MAX_HEADER APP_API_READ_BUF
#define APP_API_MAX_HEADER_LINES 128
#define APP_API_MAX_HEADER_LINE 8192
{enum_block}
{parser}
{header}

static int probe(int fd, char *method, size_t method_len, char *path, size_t path_len) {{
    char buf[APP_API_MAX_HEADER + 1];
    size_t header_len = 0;
    ssize_t n = recv(fd, buf, APP_API_MAX_HEADER, MSG_PEEK | MSG_DONTWAIT);
    int state;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return APP_API_PENDING_WAIT;
    assert(n > 0);
    state = app_api_pending_header(buf, (size_t)n, &header_len);
    if (state == APP_API_PENDING_READY)
        assert(app_api_parse_route_line(buf, header_len, method, method_len,
                                        path, path_len) == 0);
    return state;
}}

int main(void) {{
    int slow[2], fast[2];
    char method[8] = "", path[512] = "";
    static const char slow_request[] = "GET /api/v1/he";
    static const char fast_request[] =
        "GET /api/v1/health HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n";
    char long_line[APP_API_MAX_HEADER_LINE + 4];
    char too_many[2048];
    size_t off = 0;
    int i;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, slow) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fast) == 0);
    assert(write(slow[0], slow_request, sizeof(slow_request) - 1) ==
           (ssize_t)(sizeof(slow_request) - 1));
    assert(write(fast[0], fast_request, sizeof(fast_request) - 1) ==
           (ssize_t)(sizeof(fast_request) - 1));
    assert(probe(slow[1], method, sizeof(method), path, sizeof(path)) == APP_API_PENDING_WAIT);
    assert(probe(fast[1], method, sizeof(method), path, sizeof(path)) == APP_API_PENDING_READY);
    assert(strcmp(method, "GET") == 0);
    assert(strcmp(path, "/api/v1/health") == 0);
    memset(long_line, 'a', sizeof(long_line));
    assert(app_api_pending_header(long_line, sizeof(long_line), NULL) == APP_API_PENDING_TOO_LARGE);
    assert(app_api_pending_header("GET / HTTP/1.1\\n\\n", 16, NULL) == APP_API_PENDING_BAD);
    memcpy(too_many + off, "GET / HTTP/1.1\\r\\n", 16); off += 16;
    for (i = 0; i < APP_API_MAX_HEADER_LINES; i++) {{
        memcpy(too_many + off, "X: y\\r\\n", 6); off += 6;
    }}
    memcpy(too_many + off, "\\r\\n", 2); off += 2;
    assert(app_api_pending_header(too_many, off, NULL) == APP_API_PENDING_TOO_LARGE);
    close(slow[0]); close(slow[1]); close(fast[0]); close(fast[1]);
    puts("ok: U-04 pending handshake state machine runtime fixture");
    return 0;
}}
"""
    with tempfile.TemporaryDirectory() as td:
        source = Path(td) / "fixture.c"
        binary = Path(td) / "fixture"
        source.write_text(fixture, encoding="utf-8")
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
             str(source), "-o", str(binary)], check=True
        )
        result = subprocess.run([str(binary)], check=True, text=True,
                                capture_output=True)
        assert "ok: U-04" in result.stdout


if __name__ == "__main__":
    test_accept_loop_never_peeks_or_runs_a_request()
    test_pending_state_machine_has_budgets_deadline_and_cleanup()
    test_production_parser_with_slow_and_ready_sockets()
    print("ok: U-04 asynchronous pending-handshake contract")
