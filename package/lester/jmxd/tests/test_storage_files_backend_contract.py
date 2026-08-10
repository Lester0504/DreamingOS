#!/usr/bin/env python3
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FILES = (SRC / "storage/storage_files.c").read_text(encoding="utf-8")
HEADER = (SRC / "storage/storage_files.h").read_text(encoding="utf-8")
MAKE = (SRC / "Makefile").read_text(encoding="utf-8")
UBUS = (SRC / "jmx_dreamingwrt_api.c").read_text(encoding="utf-8")
WEB = (SRC / "webd/jmx_app_api.c").read_text(encoding="utf-8")
PERMS = (SRC / "webd/jmx_app_perms.c").read_text(encoding="utf-8")


def require_all(text: str, needles: tuple[str, ...], scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    assert not missing, f"{scope} missing {missing}"


def test_phase_two_text_read_is_wired_end_to_end() -> None:
    require_all(HEADER, ("jmx_storage_files_list", "jmx_storage_files_content"),
                "public header")
    require_all(MAKE, ("storage/storage_files.o",), "core object list")
    require_all(UBUS, ('"storage_files"', "dw_handle_storage_files",
                       "jmx_storage_files_list"), "ubus")
    require_all(UBUS, ('"storage_file_content"',
                       "dw_handle_storage_file_content",
                       "jmx_storage_files_content"), "content ubus")
    require_all(WEB, ('"/api/v1/storage/files"', '"storage_files"',
                      '"root_id"', '"path"', '"search"'), "REST")
    require_all(PERMS, ('"/api/v1/storage/files"', '"GET"', "JMX_RISK_LOW"),
                "permission registry")
    require_all(WEB, ('"/api/v1/storage/files/content"',
                      '"storage_file_content"', '"root_id"', '"path"'),
                "content REST")
    # Presence-only check: the risk level itself is pinned by compiling the
    # table in test_content_route_compiled_permission_boundary(), because a
    # substring search cannot tell which row a level belongs to.
    require_all(PERMS, ('"/api/v1/storage/files/content"', '"GET"',
                        "JMX_RISK_MEDIUM"), "content permission registry")
    require_all(FILES, ('"storage-files.v1"', '"mountinfo+openat-nofollow"',
                        '"entries"', '"roots"', '"capabilities"',
                        '"entries_truncated"', '"list"',
                        '"no_eligible_storage_roots"'), "response contract")
    for capability in ("download", "preview", "write", "mkdir", "create",
                       "rename", "permissions", "upload", "download_url",
                       "copy", "move", "compress", "extract", "delete",
                       "install_package"):
        assert f'"{capability}"' in FILES
    # mkdir/create/write/rename are exactly what POST /storage/files/mutate
    # accepts, so they now follow root writability instead of being pinned off.
    # Everything below has no backend endpoint and must stay hardcoded false;
    # reporting it true would enable UI controls that cannot work.
    unsupported = FILES.split("static const char *const unsupported[] = {")[1]
    unsupported = unsupported.split("};")[0]
    for capability in ("upload", "delete", "copy", "move", "compress",
                       "extract", "permissions", "download_url",
                       "install_package", "download"):
        assert f'"{capability}"' in unsupported, (
            f"{capability} has no backend endpoint and must stay false"
        )
    for capability in ("mkdir", "create", "rename", "write"):
        assert f'"{capability}"' not in unsupported, (
            f"{capability} is wired through storage_files_mutate and must not "
            "be pinned false"
        )
    assert 'json_object_object_add(caps, "mkdir", json_object_new_boolean(writable))' in FILES
    # A read-only root must still refuse, and say so honestly.
    assert '"storage_root_read_only"' in FILES
    assert "storage_file_write_jobs_pending" not in FILES, (
        "the write route is wired; this reason would misattribute a refusal"
    )
    assert "json_object_new_boolean(0)" in FILES


def test_small_utf8_text_read_is_bounded_and_fail_closed() -> None:
    require_all(FILES, (
        "STORAGE_FILES_MAX_TEXT_BYTES (256U * 1024U)",
        "STORAGE_FILES_MAX_PROBE_BYTES (4U * 1024U * 1024U)",
        "storage_files_open_regular", "storage_files_read_text_fd",
        "storage_files_utf8_text", "storage_files_stat_unchanged",
        "O_NOFOLLOW | O_NONBLOCK", "RESOLVE_BENEATH",
        "RESOLVE_NO_SYMLINKS", "RESOLVE_NO_XDEV",
        '"text_too_large"', '"not_utf8_text"', '"file_read_failed"',
        '"text/plain; charset=utf-8"', '"encoding"', '"newline"',
        '"etag"', '"read_only"', '"truncated"',
        '"max_text_read_bytes"', '"max_text_probe_bytes_per_listing"',
    ), "bounded text read")
    for forbidden in ("fopen(display", "fopen(path", "system(", "popen("):
        assert forbidden not in FILES


def test_basic_write_handler_is_transactional_and_gated_when_exposed() -> None:
    """Writes are transactional, and the route exposing them stays gated.

    This test used to assert the opposite of its second half: that the handler
    existed but reached no ubus method and no REST route. The route was opened
    deliberately on 2026-08-08 so the file manager could create and edit files,
    which inverts that half. The transactional half is unchanged and still the
    point: a partial write must roll back rather than land.

    What replaces "not advertised" is "not reachable without confirm and a
    permission row" - the invariant is that the entry point exists and is
    guarded, never that it is absent. A future reader finding the route wired up
    is looking at intended behaviour, not a mistake.
    """
    require_all(HEADER, ("jmx_storage_files_mutate",), "write handler ABI")
    require_all(FILES, (
        "jmx_storage_files_mutate", '"confirmation_required"',
        "storage_files_open_directory", "storage_files_safe_name",
        "storage_files_join_path", "expected_etag_required",
        '"revision_conflict"', "STORAGE_FILES_TRANSACTION_PREFIX",
        "RENAME_NOREPLACE", "RENAME_EXCHANGE", "fsync(parent_fd)",
        '"readback_verified"', '"rolled_back"',
    ), "transactional basic writes")
    # confirm must be a real JSON boolean: storage_files_json_bool() rejects the
    # string "true", so a client cannot talk its way past the gate with a body
    # that merely looks affirmative.
    require_all(FILES, ("storage_files_json_bool(payload, \"confirm\")",
                        "json_object_is_type(value, json_type_boolean)"),
                "confirm must be a JSON boolean")
    require_all(UBUS, ('"storage_files_mutate"',
                       "dw_handle_storage_files_mutate",
                       "jmx_storage_files_mutate"), "write ubus method")
    require_all(WEB, ('"/api/v1/storage/files/mutate"', '"storage_files_mutate"',
                      '"POST"'), "write REST route")
    require_all(PERMS, ('"/api/v1/storage/files/mutate"',), "write permission row")
    # The whole body is forwarded rather than rebuilt field by field, so a
    # missing confirm cannot be defaulted to false-but-present and a missing
    # root_id cannot silently become roots[0].
    assert "app_ubus_invoke_timeout(\"storage_files_mutate\", body_json" in WEB, (
        "the mutate body must be forwarded verbatim; rebuilding params here has "
        "historically weakened confirm and root_id"
    )
    # Filesystem writes must be attributable.
    mutate_route = WEB[WEB.index('"/api/v1/storage/files/mutate"'):]
    mutate_route = mutate_route[:mutate_route.index('"/api/v1/storage/file-services"')]
    assert "jmx_app_audit_log" in mutate_route and '"medium"' in mutate_route, (
        "storage writes must emit a medium-risk audit record"
    )


def test_mutate_route_compiled_permission_boundary() -> None:
    """The write route is MEDIUM, so viewer is refused before the handler runs.

    Registering the row explicitly matters even though an unregistered write
    would also default to MEDIUM: only a listed row is covered by the table-order
    audit, and only a listed row survives a future change to that default. The
    row must also sit ahead of the shorter "/api/v1/storage/files" inventory row,
    which would otherwise match first at the '/' boundary and answer LOW - the
    exact shadowing defect already fixed once on /content.
    """
    _compile_and_run_perms_harness(r'''
#include <stdio.h>
#include "jmx_app_perms.h"

int main(void)
{
    if (jmx_perm_route_risk("POST", "/api/v1/storage/files/mutate") != JMX_RISK_MEDIUM) {
        fputs("storage write route must be medium risk\n", stderr);
        return 1;
    }
    /* Opening the write row must not have dragged the inventory listing up, nor
     * loosened the byte-reading rows it sits beside. */
    if (jmx_perm_route_risk("GET", "/api/v1/storage/files") != JMX_RISK_LOW) {
        fputs("inventory listing must stay low risk\n", stderr);
        return 1;
    }
    if (jmx_perm_route_risk("GET", "/api/v1/storage/files/content") != JMX_RISK_MEDIUM ||
        jmx_perm_route_risk("GET", "/api/v1/storage/files/raw") != JMX_RISK_MEDIUM) {
        fputs("byte-reading rows must stay medium risk\n", stderr);
        return 1;
    }
    return 0;
}
''')


def test_raw_byte_stream_route_is_registered_before_the_capability_opens() -> None:
    """The download/preview byte stream must exist as a real route.

    downloadEntry() in storage-files.js points at a byte-stream URL, and the only
    thing keeping it from hitting a 404 was the download capability being pinned
    false. That is a coincidence, not a guard: the moment the capability flips,
    the request lands. This pins the route, its permission row and the guards it
    must reuse, so the route cannot be dropped while the frontend still calls it.
    """
    require_all(HEADER, ("storage_files_open_stream",
                         "struct storage_files_stream"), "stream ABI")
    require_all(FILES, ("storage_files_open_stream",
                        "storage_files_content_denied(display, base, reason)",
                        "storage_files_open_regular(root, relative, &st)"),
                "stream reuses the content guards")
    require_all(WEB, ('"/api/v1/storage/files/raw"',
                      "webd_storage_files_raw_response",
                      "storage_files_open_stream",
                      "Accept-Ranges: bytes"), "raw REST route")
    webd_objs = [line for line in MAKE.splitlines()
                 if line.startswith("WEBD_OBJS")]
    assert webd_objs and "storage/storage_files.o" in webd_objs[0], (
        "webd must link storage/storage_files.o or the raw route cannot reuse "
        "the path/mount/deny-list guards")
    # The text-only limits must NOT apply to the byte stream, otherwise it is
    # just /content again and no image, video or archive ever loads.
    stream = FILES[FILES.index("int storage_files_open_stream"):]
    stream = stream[:stream.index("static const char *storage_files_json_string")]
    for text_only in ("storage_files_read_text_fd", "storage_files_utf8_text",
                      "STORAGE_FILES_MAX_TEXT_BYTES"):
        assert text_only not in stream, (
            f"{text_only} in the byte-stream open would refuse binary files, "
            "which is the whole reason this entry point exists")


def _compile_and_run_perms_harness(harness: str) -> None:
    """Compile jmx_app_perms.c against a harness and run it.

    json-c is stubbed with an empty header: this translation unit references no
    json-c symbol, so the real dependency is not needed to pin route risks.
    """
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    assert compiler, "a C compiler is required for the permission contract"
    with tempfile.TemporaryDirectory(prefix="perms-contract-") as raw:
        temporary = Path(raw)
        include = temporary / "include/json-c"
        include.mkdir(parents=True)
        (include / "json.h").write_text("", encoding="utf-8")
        source = temporary / "contract.c"
        binary = temporary / "contract"
        source.write_text(harness, encoding="utf-8")
        subprocess.run([
            compiler, "-std=c99", "-Wall", "-Wextra", "-Werror",
            "-I", str(temporary / "include"),
            "-I", str(SRC / "webd"),
            str(SRC / "webd/jmx_app_perms.c"), str(source),
            "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


def test_aegis_content_policy_validators_stay_low_compiled() -> None:
    """Dry-run validators must remain LOW while their siblings stay MEDIUM.

    This lives beside the storage-files boundary test because both are the same
    defect: a child row shadowed by its parent prefix. It is compiled rather than
    parsed so it pins the real jmx_perm_route_risk() semantics, independent of
    the Python mirror used by the whole-table audit below.
    """
    _compile_and_run_perms_harness(r'''
#include <stdio.h>
#include "jmx_app_perms.h"

int main(void)
{
    if (jmx_perm_route_risk("POST", "/api/v1/aegis/content-policy/validate") != JMX_RISK_LOW ||
        jmx_perm_route_risk("POST", "/api/v1/aegis/content-policy/pcdn/validate") != JMX_RISK_LOW) {
        fputs("aegis validate routes must stay low risk\n", stderr);
        return 1;
    }
    /* The mutations they sit above must not have been loosened by the move. */
    if (jmx_perm_route_risk("POST", "/api/v1/aegis/content-policy") != JMX_RISK_MEDIUM ||
        jmx_perm_route_risk("PUT", "/api/v1/aegis/content-policy/pcdn") != JMX_RISK_MEDIUM ||
        jmx_perm_route_risk("POST", "/api/v1/aegis/content-policy/pcdn/sync") != JMX_RISK_MEDIUM) {
        fputs("aegis content-policy writes must stay medium risk\n", stderr);
        return 1;
    }
    return 0;
}
''')


def test_content_route_compiled_permission_boundary() -> None:
    """Reading file bytes is MEDIUM; listing an inventory stays LOW.

    The escalation is expressed purely by table order: route lookup returns the
    first match and a shorter prefix matches a longer path at a '/' boundary, so
    "/api/v1/storage/files" sitting ahead of ".../content" silently answered LOW
    for content reads. Both assertions below must hold together - pinning only
    the content row would let a re-ordering pass by flipping the inventory row.
    """
    _compile_and_run_perms_harness(r'''
#include <stdio.h>
#include "jmx_app_perms.h"

int main(void)
{
    if (jmx_perm_route_risk("GET", "/api/v1/storage/files/content") != JMX_RISK_MEDIUM ||
        jmx_perm_route_risk("PUT", "/api/v1/storage/files/content") != JMX_RISK_MEDIUM) {
        fputs("storage content route risk mismatch\n", stderr);
        return 1;
    }
    /*
     * HEAD stays at the readonly default: the table row covers GET only, and
     * jmx_app_api.c dispatches this path for GET alone, so a HEAD never reaches
     * the byte-serving handler. Raising it here would widen the boundary beyond
     * the route that actually returns file contents.
     */
    if (jmx_perm_route_risk("HEAD", "/api/v1/storage/files/content") != JMX_RISK_LOW) {
        fputs("storage content HEAD expectation changed\n", stderr);
        return 1;
    }
    if (jmx_perm_route_risk("GET", "/api/v1/storage/files") != JMX_RISK_LOW ||
        jmx_perm_route_risk("HEAD", "/api/v1/storage/files") != JMX_RISK_LOW) {
        fputs("storage inventory route must stay low risk\n", stderr);
        return 1;
    }
    return 0;
}
''')


def test_raw_route_compiled_permission_boundary() -> None:
    """Raw bytes stay MEDIUM, and HEAD carries the same risk as GET.

    /content can leave HEAD at the readonly default because its handler answers
    GET only, so a HEAD never reaches the byte-serving code. The raw handler
    answers HEAD too, in order to report Content-Length and Accept-Ranges to a
    media player before it starts fetching, so HEAD really does reach the
    byte-serving path here and must not fall back to LOW.
    """
    _compile_and_run_perms_harness(r'''
#include <stdio.h>
#include "jmx_app_perms.h"

int main(void)
{
    if (jmx_perm_route_risk("GET", "/api/v1/storage/files/raw") != JMX_RISK_MEDIUM ||
        jmx_perm_route_risk("HEAD", "/api/v1/storage/files/raw") != JMX_RISK_MEDIUM) {
        fputs("raw byte stream must be medium risk for GET and HEAD\n", stderr);
        return 1;
    }
    /* The row sits above the inventory row; confirm that move did not drag the
     * inventory listing up with it. */
    if (jmx_perm_route_risk("GET", "/api/v1/storage/files") != JMX_RISK_LOW) {
        fputs("inventory listing must stay low risk\n", stderr);
        return 1;
    }
    return 0;
}
''')

def test_roots_admit_real_mounts_and_exclude_pseudo_filesystems() -> None:
    """Root admission is per-path, not a whole-device exclusion.

    The previous policy admitted only /mnt and /media and then dropped every
    mount sharing a device with /, /data, /etc/dreamingwrt or /boot.  On a unit
    whose data lives on the system disk those two rules intersect to the empty
    set, so the file manager had no roots at all and every path returned
    storage_root_not_found.  Browsing the real filesystem is the intended
    product behaviour; writes are constrained by the deny-lists instead.
    """
    require_all(FILES, (
        'STORAGE_FILES_MOUNTINFO "/proc/self/mountinfo"',
        '"proc", "sysfs", "devtmpfs"', '"tmpfs", "overlay"',
        '"bpf", "nfsd", "mqueue"',
        "(unsigned int)major(st.st_dev) != maj",
        "(unsigned int)minor(st.st_dev) != min",
        'storage_files_option_present(fields[5], "ro")',
        'open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)',
        "SYS_openat2", "RESOLVE_BENEATH", "RESOLVE_NO_SYMLINKS",
        "RESOLVE_NO_XDEV",
        "storage_files_root_excluded(path)",
        "storage_files_root_write_protected(root.path)",
    ), "root discovery")
    # Credential and live-state mounts must not be offered as roots at all.
    require_all(FILES, (
        '"/etc/shadow", "/etc/dropbear", "/etc/ssh", "/etc/ssl/private"',
        '"/etc/dreamingwrt", "/data/dreamingwrt"',
    ), "root exclusion list")
    # Roots carrying the running system or service configuration are presented
    # read-only, so the UI does not offer edits the write guard will refuse.
    require_all(FILES, (
        '"/", "/boot", "/etc", "/etc/config", "/etc/crontabs"',
        '"/etc/nginx", "/etc/samba", "/etc/rc.local"',
    ), "read-only root list")
    # The blanket policy must not come back: no /mnt+/media gate, and no
    # device-wide exclusion that would take the whole filesystem with it.
    assert 'storage_files_path_prefix(path, "/mnt") ||' not in FILES
    assert "storage_files_protected_device" not in FILES
    assert "st.st_dev == dev" not in FILES
    assert 'strstr(fields[5], "ro")' not in FILES

def test_path_walk_never_follows_links_or_crosses_mounts() -> None:
    require_all(FILES, (
        'openat(fd, part,', 'O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW',
        "st.st_dev != root->dev", 'strcmp(part, "..")',
        "STORAGE_FILES_MAX_PATH_DEPTH", "AT_SYMLINK_NOFOLLOW",
        '"mount_boundary_rejected"', '"invalid_relative_path"',
        "root_stat.st_dev != root->dev",
    ), "descriptor-relative path walk")
    for forbidden in ("realpath(", "chdir(", "system(", "popen(", "glob("):
        assert forbidden not in FILES


def test_directory_work_is_bounded_and_special_files_are_not_readable() -> None:
    require_all(FILES, (
        "STORAGE_FILES_MAX_ENTRIES 1000", "STORAGE_FILES_MAX_SEARCH 128",
        "emitted >= STORAGE_FILES_MAX_ENTRIES", '"symlink"', '"other"',
        "storage_files_capabilities(S_ISDIR(st.st_mode) &&",
    ), "bounded listing")
    assert "fopen(item_path" not in FILES
    assert "readlink(" not in FILES


def _parse_route_table() -> list[tuple[int, str, str, str]]:
    """Extract (line, prefix, methods, risk) for every row of g_route_risks[]."""
    lines = PERMS.splitlines()
    start = next(i for i, line in enumerate(lines) if "g_route_risks[] = {" in line)
    end = next(i for i, line in enumerate(lines[start:], start)
               if line.startswith("};"))
    row = re.compile(
        r'^\s*\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*(JMX_RISK_\w+)\s*\}')
    parsed = []
    for index in range(start, end):
        found = row.match(lines[index])
        if found:
            parsed.append((index + 1, found.group(1), found.group(2),
                           found.group(3)))
    return parsed


def _first_match(rows, path: str, method: str):
    """Mirror jmx_perm_route_risk(): first row whose prefix and method match."""
    for entry in rows:
        _, prefix, methods, _ = entry
        if not path.startswith(prefix):
            continue
        if not prefix.endswith("/"):
            rest = path[len(prefix):]
            if rest and not rest.startswith("/"):
                continue
        if method in [m.strip().upper() for m in methods.split(",") if m.strip()]:
            return entry
    return None


def test_no_table_row_is_shadowed_into_a_weaker_risk() -> None:
    """A shorter prefix must never swallow a longer row and lower its risk.

    route_prefix_matches() added a segment-boundary check after
    "/api/v1/auth/security" swallowed ".../failures". That guard fixes *sibling*
    paths but by design does not fix a *true subpath*: for
    "/api/v1/storage/files/content" the character after the shorter prefix is
    '/', which is exactly what the boundary check admits. So the escalation of a
    child route still depends on it being written above its parent, and nothing
    in the compiler or the rest of this file enforces that.

    This walks the whole table so the next such row fails here instead of
    silently downgrading a route in production.
    """
    rank = {"JMX_RISK_LOW": 0, "JMX_RISK_MEDIUM": 1, "JMX_RISK_HIGH": 2,
            "JMX_RISK_BLOCKED": 3}
    rows = _parse_route_table()
    assert len(rows) > 400, f"route table looks unparsed ({len(rows)} rows)"

    downgraded = []
    raised = []
    for entry in rows:
        line, path, methods, risk = entry
        for method in [m.strip().upper() for m in methods.split(",") if m.strip()]:
            winner = _first_match(rows, path, method)
            if winner is None or winner is entry:
                continue
            if rank[winner[3]] < rank[risk]:
                downgraded.append(
                    f":{line} {method} {path} declares {risk} but :{winner[0]} "
                    f'"{winner[1]}" [{winner[2]}] matches first and answers '
                    f"{winner[3]} - move the longer row above it")
            elif rank[winner[3]] > rank[risk]:
                raised.append(
                    f":{line} {method} {path} declares {risk} but :{winner[0]} "
                    f'"{winner[1]}" [{winner[2]}] matches first and answers '
                    f"{winner[3]}")
    assert not downgraded, "shadowed route rows:\n" + "\n".join(downgraded)
    # The opposite direction is fail-safe rather than a security hole, but it
    # still means the table says one thing and the runtime does another, which
    # is how the aegis content-policy validators ended up unusable by a
    # read-only role while their row read LOW.
    assert not raised, "rows silently tightened by an earlier row:\n" + "\n".join(raised)


def test_storage_files_subpath_escalation_survives_the_parent_row() -> None:
    """Regression for the real defect shape: a true subpath, not a sibling."""
    rows = _parse_route_table()
    content = _first_match(rows, "/api/v1/storage/files/content", "GET")
    assert content is not None, "content route vanished from the risk table"
    assert content[1] == "/api/v1/storage/files/content", (
        f'"{content[1]}" now matches GET /storage/files/content first; the '
        "MEDIUM escalation is shadowed again")
    assert content[3] == "JMX_RISK_MEDIUM"

    inventory = _first_match(rows, "/api/v1/storage/files", "GET")
    assert inventory is not None and inventory[3] == "JMX_RISK_LOW", (
        "listing an inventory must stay LOW; only byte reads escalate")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for test in tests:
        test()
    print(f"ok: {len(tests)} storage-files Phase 1/2A contracts")
