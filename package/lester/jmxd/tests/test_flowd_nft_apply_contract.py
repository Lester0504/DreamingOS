#!/usr/bin/env python3
"""Executable contracts for the bounded flowd nft revision transaction."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import textwrap

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apd_test_deps  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
FLOWD = ROOT / "src" / "flowd"
HEADER = (FLOWD / "flowd_nft_apply.h").read_text(encoding="utf-8")
DB = (FLOWD / "flowd_db.c").read_text(encoding="utf-8")
UBUS = (FLOWD / "flowd_ubus.c").read_text(encoding="utf-8")
RUNTIME = (FLOWD / "flowd_runtime_contract.h").read_text(encoding="utf-8")
WEBD = (ROOT / "src" / "webd" / "jmx_app_api.c").read_text(encoding="utf-8")


def test_no_shell_and_strict_transaction_contract() -> None:
    for forbidden in ("system(", "popen(", "sh -c", "/bin/sh"):
        assert forbidden not in HEADER
    for required in (
        "execv(binary, argv)",
        'check_argv[1] = "-c"',
        'check_argv[2] = "-f"',
        "flowd_nft_readback",
        "flowd_nft_json_sentinel",
        "nft_revision_readback_mismatch",
        "nft_rollback_verification_failed",
        "FLOWD_NFT_RUN_TIMEOUT",
        "FLOWD_NFT_RUN_OUTPUT_LIMIT",
        "FLOWD_NFT_RUN_WAIT_FAILED",
        "flowd_nft_kill_and_reap(pid)",
        "flowd_nft_write_all",
        "LOCK_EX | LOCK_NB",
        '"nft_apply_busy"',
        "O_NOFOLLOW",
        "FLOWD_NFT_REVISION_PREFIX",
    ):
        assert required in HEADER, required


def test_handler_job_and_capability_boundaries() -> None:
    for required in (
        "struct json_object *flowd_nft_revision_apply",
        'flowd_json_bool(body, "dry_run", 1)',
        '"nft_revision_apply"',
        'state = "applying"',
        'state = "applied"',
        'state = "rolled_back"',
        '"sentinel_only"',
        '"contains_policy_rules"',
        '"sentinel_applied"',
        '"runtime_applied"',
        "flowd_apply_job_save",
        "flowd_nft_apply_revision(FLOWD_NFT_BINARY",
    ):
        assert required in DB, required
    assert 'json_object_object_add(resp, "applied", json_object_new_boolean(0))' in DB
    assert 'flowd_apply_job_save(job_id, "compile", requested_by, dry_run' in DB
    assert 'UBUS_METHOD("nft_revision_apply", flowd_handle_nft_revision_apply' in UBUS
    assert 'UBUS_METHOD("nft_revision_status", flowd_handle_nft_revision_status' in UBUS
    for required in (
        "struct json_object *flowd_nft_revision_status(void)",
        'flowd_nft_readback(FLOWD_NFT_BINARY, settings.runtime_dir,',
        '"ownership_verified"',
        '"observed_at"',
        '"nft-json-readback"',
    ):
        assert required in DB, required
    assert '"/api/v1/flowd/nft-revision"' in WEBD
    assert '"nft_revision_status"' in WEBD
    assert '"nft_revision_apply"' in WEBD
    for capability in (
        '"nft_revision_transaction"',
        '"nft_revision_readback"',
        '"nft_revision_sentinel_only"',
    ):
        assert capability in RUNTIME
    assert '"flow_engine_apply",\n                           json_object_new_boolean(0)' in RUNTIME


def _fake_nft() -> str:
    return textwrap.dedent(r'''
        #!/usr/bin/env python3
        import json
        import os
        from pathlib import Path
        import re
        import sys

        state_path = Path(os.environ["FLOWD_FAKE_NFT_STATE"])
        mode = os.environ.get("FLOWD_FAKE_NFT_MODE", "ok")

        def load():
            if not state_path.exists():
                return {"present": False, "revision": ""}
            return json.loads(state_path.read_text(encoding="utf-8"))

        def save(state):
            state_path.write_text(json.dumps(state), encoding="utf-8")

        args = sys.argv[1:]
        if mode == "runner_sleep":
            import time
            time.sleep(30)
            raise SystemExit(0)
        if mode == "runner_flood":
            sys.stdout.write("x" * (300 * 1024))
            sys.stdout.flush()
            raise SystemExit(0)
        state = load()
        if args == ["-j", "list", "tables"]:
            items = [{"metainfo": {"json_schema_version": 1}}]
            if state["present"]:
                items.append({"table": {"family": "inet", "name": "dreamingwrt_flowd"}})
            print(json.dumps({"nftables": items}))
            raise SystemExit(0)
        if args == ["-j", "list", "table", "inet", "dreamingwrt_flowd"]:
            if not state["present"]:
                raise SystemExit(1)
            print(json.dumps({"nftables": [
                {"metainfo": {"json_schema_version": 1}},
                {"table": {"family": "inet", "name": "dreamingwrt_flowd",
                           "comment": "flowd-revision:" + state["revision"]}},
            ]}))
            raise SystemExit(0)
        check = args[:2] == ["-c", "-f"]
        apply = args[:1] == ["-f"]
        if not (check or apply) or len(args) != (3 if check else 2):
            raise SystemExit(2)
        batch = Path(args[-1]).read_text(encoding="utf-8")
        if mode == "check_fail" and check and "-apply.nft" in args[-1]:
            raise SystemExit(3)
        if check:
            if ("delete table inet dreamingwrt_flowd" in batch and
                    not state["present"]):
                raise SystemExit(5)
            raise SystemExit(0)
        is_rollback = "-rollback.nft" in args[-1]
        if mode == "apply_fail" and not is_rollback:
            raise SystemExit(4)
        match = re.search(r'flowd-revision:([A-Za-z0-9_.-]+)', batch)
        if match:
            revision = match.group(1)
            if mode == "mismatch" and not is_rollback:
                revision = "wrong-revision"
            save({"present": True, "revision": revision})
        elif "delete table inet dreamingwrt_flowd" in batch:
            save({"present": False, "revision": ""})
        raise SystemExit(0)
    ''').lstrip()


def test_apply_readback_and_rollback_behavior() -> None:
    harness = textwrap.dedent(r'''
        #include <assert.h>
#include <errno.h>
#include <fcntl.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include "flowd_nft_apply.h"

        static void write_state(const char *path, int present, const char *revision) {
            FILE *fp = fopen(path, "w");
            assert(fp);
            fprintf(fp, "{\"present\":%s,\"revision\":\"%s\"}",
                    present ? "true" : "false", revision ? revision : "");
            assert(fclose(fp) == 0);
        }

        static void verify_readback(const char *binary, const char *dir,
                                    int present, const char *revision) {
            struct flowd_nft_readback rb;
            assert(flowd_nft_readback(binary, dir, "verify", &rb) == 0);
            assert(rb.present == present);
            if (present) {
                assert(rb.sentinel_only == 1);
                assert(strcmp(rb.revision, revision) == 0);
            }
        }

        int main(int argc, char **argv) {
            struct flowd_nft_apply_result result;
            const char *binary = argv[1];
            const char *dir = argv[2];
            const char *state = argv[3];
            assert(argc == 4);

            setenv("FLOWD_FAKE_NFT_MODE", "ok", 1);
            write_state(state, 0, "");
            { int rc = flowd_nft_apply_revision(binary, dir, "rev-success", &result);
              if (rc != 0) fprintf(stderr, "success rc=%d error=%s validated=%d applied=%d readback=%d rollback=%d/%d\n",
                                   rc, result.error, result.validated, result.applied,
                                   result.readback_ok, result.rolled_back, result.rollback_ok);
              assert(rc == 0); }
            assert(result.validated && result.applied && result.readback_ok);
            assert(!result.rolled_back);
            verify_readback(binary, dir, 1, "rev-success");

            setenv("FLOWD_FAKE_NFT_MODE", "mismatch", 1);
            write_state(state, 1, "rev-old");
            assert(flowd_nft_apply_revision(binary, dir, "rev-new", &result) != 0);
            assert(result.applied && !result.readback_ok);
            assert(result.rolled_back && result.rollback_ok);
            assert(strcmp(result.error, "nft_revision_readback_mismatch") == 0);
            verify_readback(binary, dir, 1, "rev-old");

            setenv("FLOWD_FAKE_NFT_MODE", "apply_fail", 1);
            write_state(state, 0, "");
            assert(flowd_nft_apply_revision(binary, dir, "rev-fail", &result) != 0);
            assert(result.validated && !result.applied);
            assert(result.rolled_back && result.rollback_ok);
            assert(strcmp(result.error, "nft_apply_failed") == 0);
            verify_readback(binary, dir, 0, "");

            setenv("FLOWD_FAKE_NFT_MODE", "check_fail", 1);
            write_state(state, 1, "rev-stable");
            assert(flowd_nft_apply_revision(binary, dir, "rev-check", &result) != 0);
            assert(!result.validated && !result.applied && !result.rolled_back);
            verify_readback(binary, dir, 1, "rev-stable");

            {
                char lock_path[PATH_MAX];
                int lock_fd;
                snprintf(lock_path, sizeof(lock_path), "%s/nft-apply.lock", dir);
                lock_fd = open(lock_path, O_RDWR | O_CREAT, 0600);
                assert(lock_fd >= 0);
                assert(flock(lock_fd, LOCK_EX | LOCK_NB) == 0);
                setenv("FLOWD_FAKE_NFT_MODE", "ok", 1);
                write_state(state, 1, "rev-busy-stable");
                assert(flowd_nft_apply_revision(binary, dir, "rev-busy", &result) != 0);
                assert(strcmp(result.error, "nft_apply_busy") == 0);
                verify_readback(binary, dir, 1, "rev-busy-stable");
                assert(flock(lock_fd, LOCK_UN) == 0);
                close(lock_fd);
            }
            return 0;
        }
    ''')
    # Keyed on real resolvability: pkg-config has no json-c entry on 31.6, so
    # the old probe printed "skip" there and the contract went unexercised.
    if not apd_test_deps.have_package("json-c"):
        print("skip: executable nft contract fixture requires host json-c development metadata")
        return
    json_c_flags = apd_test_deps.package_flags("json-c")
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        fake = tmp / "fake-nft"
        source = tmp / "nft_apply_test.c"
        binary = tmp / "nft_apply_test"
        runtime = tmp / "runtime"
        state = tmp / "state.json"
        runtime.mkdir()
        fake.write_text(_fake_nft(), encoding="utf-8")
        fake.chmod(0o755)
        source.write_text(harness, encoding="utf-8")
        flags = json_c_flags
        subprocess.run([
            "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            "-I", str(FLOWD), str(source), *flags, "-o", str(binary),
        ], check=True)
        env = os.environ.copy()
        env["FLOWD_FAKE_NFT_STATE"] = str(state)
        subprocess.run(
            [str(binary), str(fake), str(runtime), str(state)],
            check=True, env=env,
        )


def test_runner_timeout_output_limit_and_wait_failure() -> None:
    harness = textwrap.dedent(r'''
        #include <assert.h>
        #include <errno.h>
        #include <signal.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <sys/stat.h>
        #include <sys/types.h>
        #include <sys/wait.h>
        #include <unistd.h>

        static int inject_wait_failure;
        static pid_t test_waitpid(pid_t pid, int *status, int options) {
            if (inject_wait_failure && (options & WNOHANG)) {
                inject_wait_failure = 0;
                errno = ECHILD;
                return -1;
            }
            return waitpid(pid, status, options);
        }
        #define FLOWD_NFT_WAITPID test_waitpid
        #include "flowd_nft_apply.h"

        static void assert_no_children(void) {
            int status = 0;
            errno = 0;
            assert(waitpid(-1, &status, WNOHANG) == -1);
            assert(errno == ECHILD);
        }

        int main(int argc, char **argv) {
            char output[PATH_MAX];
            char *run_argv[] = { argv[1], "runner", NULL };
            struct stat st;
            int rc;
            assert(argc == 3);
            snprintf(output, sizeof(output), "%s/runner.log", argv[2]);

            setenv("FLOWD_FAKE_NFT_MODE", "runner_sleep", 1);
            rc = flowd_nft_run_timeout(argv[1], run_argv, output, 80);
            assert(rc == FLOWD_NFT_RUN_TIMEOUT);
            assert_no_children();

            setenv("FLOWD_FAKE_NFT_MODE", "runner_flood", 1);
            rc = flowd_nft_run_timeout(argv[1], run_argv, output, 1000);
            assert(rc == FLOWD_NFT_RUN_OUTPUT_LIMIT);
            assert(stat(output, &st) == 0);
            assert((uint64_t)st.st_size <= FLOWD_NFT_OUTPUT_MAX);
            assert_no_children();

            setenv("FLOWD_FAKE_NFT_MODE", "runner_sleep", 1);
            inject_wait_failure = 1;
            rc = flowd_nft_run_timeout(argv[1], run_argv, output, 1000);
            assert(rc == FLOWD_NFT_RUN_WAIT_FAILED);
            assert_no_children();
            return 0;
        }
    ''')
    # Same reasoning as above: resolve json-c rather than trusting pkg-config.
    if not apd_test_deps.have_package("json-c"):
        print("skip: executable nft runner fixture requires host json-c development metadata")
        return
    json_c_flags = apd_test_deps.package_flags("json-c")
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        fake = tmp / "fake-nft"
        source = tmp / "nft_runner_test.c"
        binary = tmp / "nft_runner_test"
        fake.write_text(_fake_nft(), encoding="utf-8")
        fake.chmod(0o755)
        source.write_text(harness, encoding="utf-8")
        flags = json_c_flags
        subprocess.run([
            "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            "-I", str(FLOWD), str(source), *flags, "-o", str(binary),
        ], check=True)
        env = os.environ.copy()
        env["FLOWD_FAKE_NFT_STATE"] = str(tmp / "state.json")
        subprocess.run([str(binary), str(fake), str(tmp)], check=True, env=env)


if __name__ == "__main__":
    test_no_shell_and_strict_transaction_contract()
    test_handler_job_and_capability_boundaries()
    test_apply_readback_and_rollback_behavior()
    test_runner_timeout_output_limit_and_wait_failure()
    print("ok: flowd nft revision apply requires verified readback and rollback")
