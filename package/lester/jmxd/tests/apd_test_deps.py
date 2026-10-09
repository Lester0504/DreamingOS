"""Locate C dependencies (json-c / openssl / sqlite3 / libmaxminddb) for the
jmxd test fixtures.

These fixtures compile C harnesses with the host compiler, so they need a
prefix that actually carries the headers and a linkable library. The original
code only consulted APD_TEST_PREFIX and otherwise jumped straight to a macOS
Homebrew path, so on the authoritative tree (31.6) every one of them tried to
link /opt/homebrew/.../libjson-c.a and died with "plugin needed to handle lto
object" -- a failure that reads like an APD defect but is purely a dependency
lookup problem.

Search well-known locations instead of hard-coding one machine's layout. An
explicit APD_TEST_PREFIX / APD_TEST_OPENSSL_PREFIX still wins, so existing
invocations keep working unchanged.

The module keeps its historical name because the APD fixtures import it by
that name, but it now serves every fixture: `package_flags()` is the entry
point for callers that used to shell out to `pkg-config` directly and die on
31.6, where json-c and libmaxminddb ship no `.pc` file at all.

Two switches exist for verifying the search itself rather than one machine's
luck; they are test-harness only and default to off:

    DWRT_TEST_DEPS_NO_PKG_CONFIG=1   skip pkg-config, force the prefix search
    DWRT_TEST_DEPS_NO_HOMEBREW=1     drop Homebrew candidates, proving the
                                     staging_dir is found on its own and not
                                     through a /opt/homebrew compatibility
                                     symlink
"""
import glob
import os
import platform
import shlex
import shutil
import subprocess
from pathlib import Path


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip() not in ("", "0", "false", "no")


def _staging_candidates() -> list:
    """OpenWrt staging_dir, four levels up from tests/ (package/lester/jmxd)."""
    staging = Path(__file__).resolve().parents[4] / "staging_dir"
    if not staging.is_dir():
        return []
    candidates = list(staging.glob("target-*/usr"))
    # These fixtures are linked by the host compiler. Prefer the target sysroot
    # matching that host so an x86_64 compiler never consumes an ARM sysroot's
    # headers or libraries merely because of lexical directory ordering.
    machine = platform.machine().lower()
    preferred = ("x86_64" if machine in {"x86_64", "amd64"}
                 else "aarch64" if machine in {"aarch64", "arm64"}
                 else machine)
    return sorted(
        candidates,
        key=lambda path: (0 if preferred in path.parent.name.lower() else 1,
                          path.parent.name),
    )


def _homebrew_candidates(package: str) -> list:
    """Homebrew names the package, not the library: openssl@3 ships libssl."""
    if _truthy("DWRT_TEST_DEPS_NO_HOMEBREW"):
        return []
    candidates = [Path("/opt/homebrew/opt") / package,
                  Path("/usr/local/opt") / package]
    candidates.extend(Path(value) for value in glob.glob(
        "/opt/homebrew/var/homebrew/tmp/.cellar/%s/*" % package))
    return candidates


def resolve_prefix(library: str, header: str, env_var: str = "",
                   package: str = "") -> tuple:
    """Return (prefix, shared) for <library>.

    "shared" reports whether the prefix offers a .so, because the callers link
    differently in that case: a staging_dir .a is an LTO archive produced by
    the cross toolchain and the host linker cannot consume it, while the .so
    carries no bytecode and links cleanly.
    """
    configured = os.environ.get(env_var, "") if env_var else ""
    if configured:
        prefix = Path(configured)
        assert (prefix / "include" / header).is_file(), \
            "%s=%s has no include/%s" % (env_var, configured, header)
        return prefix, (prefix / "lib" / ("lib%s.so" % library)).is_file()

    searched = (_staging_candidates()
                + _homebrew_candidates(package or library)
                + [Path("/usr"), Path("/usr/local")])
    # Two passes, shared first. A static-only prefix is a last resort because
    # the archives that turn up here are LTO archives (staging_dir, and the
    # Homebrew cellar copy on 31.6, which reports "bytecode stream ...
    # generated with LTO version 16.0 instead of the expected 15.1"). Ordering
    # by kind rather than by directory means a machine that keeps a usable .so
    # somewhere further down the list still gets it.
    for want_shared in (True, False):
        for candidate in searched:
            if not (candidate / "include" / header).is_file():
                continue
            shared = (candidate / "lib" / ("lib%s.so" % library)).is_file()
            if want_shared:
                if shared:
                    return candidate, shared
                continue
            for suffix in (".dylib", ".a"):
                if (candidate / "lib" / ("lib%s%s" % (library, suffix))).is_file():
                    return candidate, shared
    raise AssertionError(
        "%s headers plus a linkable library are required; set %s explicitly"
        % (library, env_var or "APD_TEST_PREFIX"))


def resolve_json_prefix() -> tuple:
    return resolve_prefix("json-c", "json-c/json.h", "APD_TEST_PREFIX")


def resolve_openssl_prefix() -> tuple:
    return resolve_prefix("ssl", "openssl/ssl.h", "APD_TEST_OPENSSL_PREFIX",
                          package="openssl@3")


# pkg-config package name -> how to find it without pkg-config.
#   libs    link names, in link order; the first one doubles as the marker
#           file used to decide whether a candidate prefix is usable
#   header  a header that must exist under <prefix>/include
#   env     historical per-package override, honoured before any search
#   brew    Homebrew formula name, which differs from the library name
_PACKAGES = {
    "json-c": {"libs": ["json-c"], "header": "json-c/json.h",
               "env": "APD_TEST_PREFIX", "brew": "json-c"},
    "sqlite3": {"libs": ["sqlite3"], "header": "sqlite3.h",
                "env": "APD_TEST_SQLITE3_PREFIX", "brew": "sqlite"},
    "openssl": {"libs": ["ssl", "crypto"], "header": "openssl/ssl.h",
                "env": "APD_TEST_OPENSSL_PREFIX", "brew": "openssl@3"},
    "libmaxminddb": {"libs": ["maxminddb"], "header": "maxminddb.h",
                     "env": "APD_TEST_MAXMINDDB_PREFIX",
                     "brew": "libmaxminddb"},
    "libcurl": {"libs": ["curl"], "header": "curl/curl.h",
                "env": "APD_TEST_CURL_PREFIX", "brew": "curl"},
}


def _link_flags(prefix: Path, libs: list) -> list:
    """Flags that actually link <libs> out of <prefix>.

    A .so needs an rpath because the staging_dir is not on the loader path; a
    .dylib carries its install_name and does not; a bare archive is linked by
    path, which is what the macOS-only fixtures have always done.
    """
    library_dir = prefix / "lib"
    marker = libs[0]
    if (library_dir / ("lib%s.so" % marker)).is_file():
        return (["-L%s" % library_dir]
                + ["-l%s" % name for name in libs]
                + ["-Wl,-rpath,%s" % library_dir])
    if (library_dir / ("lib%s.dylib" % marker)).is_file():
        return ["-L%s" % library_dir] + ["-l%s" % name for name in libs]
    archives = [library_dir / ("lib%s.a" % name) for name in libs]
    if all(archive.is_file() for archive in archives):
        return [str(archive) for archive in archives]
    # Mixed layout (e.g. libssl.a present, libcrypto.a absent): fall back to
    # -L/-l and let the linker pick whatever it can find.
    return ["-L%s" % library_dir] + ["-l%s" % name for name in libs]


def _pkg_config_flags(packages: list) -> list:
    """`pkg-config --cflags --libs`, or None when it cannot answer.

    Asked for the whole set at once, exactly as the callers used to, so a host
    with a complete .pc layout keeps producing byte-identical flags. A single
    missing package fails the set, which is why the caller falls back per
    package instead of giving up.
    """
    if _truthy("DWRT_TEST_DEPS_NO_PKG_CONFIG"):
        return None
    pkg_config = os.environ.get("PKG_CONFIG") or shutil.which("pkg-config")
    if not pkg_config:
        return None
    try:
        probe = subprocess.run([pkg_config, "--cflags", "--libs", *packages],
                               capture_output=True, text=True, check=False)
    except OSError:
        # A PKG_CONFIG pointing at a missing binary must degrade to the prefix
        # search, not abort the fixture.
        return None
    if probe.returncode != 0:
        return None
    flags = shlex.split(probe.stdout)
    return flags or None


def _resolved_flags(package: str) -> list:
    spec = _PACKAGES.get(package)
    assert spec, (
        "unknown dependency %r; add it to apd_test_deps._PACKAGES rather than "
        "calling pkg-config directly" % package)
    single = _pkg_config_flags([package])
    if single is not None:
        return single
    prefix, _ = resolve_prefix(spec["libs"][0], spec["header"], spec["env"],
                               package=spec["brew"])
    return ["-I%s" % (prefix / "include")] + _link_flags(prefix, spec["libs"])


def package_flags(*packages: str) -> list:
    """Compile+link flags for pkg-config-style package names.

    Drop-in replacement for
    `subprocess.run(["pkg-config", "--cflags", "--libs", *packages])`. On a
    host with proper .pc files the output is pkg-config's own; on 31.6, where
    json-c and libmaxminddb ship no .pc file at all, the prefix search takes
    over so the fixture compiles instead of raising CalledProcessError.
    """
    assert packages, "package_flags() needs at least one package"
    combined = _pkg_config_flags(list(packages))
    if combined is not None:
        return combined
    flags: list = []
    for package in packages:
        for flag in _resolved_flags(package):
            if flag not in flags or flag.startswith(("-l", "-Wl,")):
                flags.append(flag)
    return flags


def split_package_flags(*packages: str) -> tuple:
    """(cflags, libs) for callers that keep the two apart on the command line."""
    flags = package_flags(*packages)
    cflags = [flag for flag in flags
              if flag.startswith(("-I", "-D", "-isystem"))]
    return cflags, [flag for flag in flags if flag not in cflags]


def have_package(*packages: str) -> bool:
    """Whether every package can be resolved; for skip guards."""
    try:
        package_flags(*packages)
    except (AssertionError, OSError):
        return False
    return True
