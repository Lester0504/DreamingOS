#!/usr/bin/env python3
import os
import socket
import subprocess
import tempfile
import threading
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "webd" / "webd_init_control.c"
HDR_DIR = ROOT / "webd"

HARNESS = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "webd_init_control.h"

int main(int argc, char **argv) {
    char *response = NULL;
    size_t response_len = 0;
    char err[128] = "";
    int rc;

    assert(argc == 3);
    rc = webd_init_config_restore_request_at(argv[1], argv[2], &response,
                                             &response_len, err, sizeof(err));
    if (!strcmp(argv[2], "apply") || !strcmp(argv[2], "status;reboot")) {
        assert(rc != 0);
        assert(!response);
        assert(!strcmp(err, "invalid_init_control_request"));
        return 0;
    }
    assert(rc == 0);
    assert(response);
    assert(response_len == strlen(response));
    assert(strstr(response, "\"ok\":true"));
    free(response);
    return 0;
}
'''


def serve_once(path: Path, observed: list[bytes]) -> threading.Thread:
    ready = threading.Event()

    def server() -> None:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.bind(str(path))
            sock.listen(1)
            ready.set()
            conn, _ = sock.accept()
            with conn:
                chunks = []
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                observed.append(b"".join(chunks))
                conn.sendall(b'{"ok":true,"phase":"armed"}\n')

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    assert ready.wait(timeout=2)
    return thread


def main() -> None:
    source = SRC.read_text(encoding="utf-8")
    for forbidden in ("system(", "popen(", "execl(", "/bin/sh"):
        assert forbidden not in source
    assert "action_allowed" in source
    assert "SO_RCVTIMEO" in source
    assert "WEBD_INIT_RESPONSE_MAX" in source

    with tempfile.TemporaryDirectory(dir="/tmp") as td:
        root = Path(td)
        harness = root / "harness.c"
        executable = root / "harness"
        harness.write_text(HARNESS, encoding="ascii")
        subprocess.run(
            [
                os.environ.get("CC", "cc"), "-Wall", "-Wextra", "-Werror",
                "-I", str(HDR_DIR), str(harness), str(SRC), "-o", str(executable),
            ],
            check=True,
        )

        socket_path = root / "init.sock"
        for action in ("status", "arm", "confirm", "rollback"):
            socket_path.unlink(missing_ok=True)
            observed: list[bytes] = []
            thread = serve_once(socket_path, observed)
            subprocess.run([str(executable), str(socket_path), action], check=True)
            thread.join(timeout=2)
            assert not thread.is_alive()
            assert observed == [f"config-restore {action} --json\n".encode("ascii")]

        subprocess.run([str(executable), str(socket_path), "apply"], check=True)
        subprocess.run([str(executable), str(socket_path), "status;reboot"], check=True)

    print("webd_init_control_contract: PASS")


if __name__ == "__main__":
    main()
