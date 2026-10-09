#!/usr/bin/env python3
"""Locate host-native dependencies for OTAD compile-and-run tests."""

from dataclasses import dataclass
import os
import platform
from pathlib import Path


@dataclass(frozen=True)
class HostDependencies:
    json_include: Path
    json_library: Path | None
    openssl_include: Path
    openssl_library_dir: Path | None


def _candidate_roots(project_root: Path) -> list[Path]:
    roots: list[Path] = []
    configured = os.environ.get("OTAD_TEST_DEP_ROOT", "").strip()
    if configured:
        root = Path(configured)
        roots.append(root / "usr" if (root / "usr/include").is_dir() else root)

    for parent in (project_root, *project_root.parents):
        host = parent / "staging_dir/host"
        if host.is_dir():
            roots.append(host)
            break

    if platform.system() == "Darwin":
        roots.extend((Path("/opt/homebrew"), Path("/usr/local"), Path("/usr")))
    else:
        roots.extend((Path("/usr/local"), Path("/usr")))

    unique: list[Path] = []
    for root in roots:
        if root not in unique:
            unique.append(root)
    return unique


def _find_library(root: Path, name: str) -> Path | None:
    for suffix in (".so", ".dylib", ".a"):
        candidate = root / "lib" / f"lib{name}{suffix}"
        if candidate.is_file():
            return candidate
    return None


def find_host_dependencies(
    project_root: Path,
    *,
    require_json_library: bool = True,
    require_crypto_library: bool = True,
) -> HostDependencies:
    roots = _candidate_roots(project_root)
    json_include_override = os.environ.get("JSON_C_INCLUDE", "").strip()
    json_roots = roots
    if json_include_override:
        include = Path(json_include_override)
        if not (include / "json-c/json.h").is_file():
            raise RuntimeError(
                f"JSON_C_INCLUDE does not contain json-c/json.h: {include}"
            )
        json_roots = [include.parent, *roots]

    json_include = None
    json_library = None
    for root in json_roots:
        include = Path(json_include_override) if json_include_override else root / "include"
        if not (include / "json-c/json.h").is_file():
            continue
        library = _find_library(root, "json-c")
        if require_json_library and library is None:
            continue
        json_include = include
        json_library = library
        break
    if json_include is None:
        raise RuntimeError("host-native json-c development files not found")

    openssl_include = None
    openssl_library_dir = None
    openssl_roots = list(roots)
    if platform.system() == "Darwin":
        openssl_roots[:0] = [
            Path("/opt/homebrew/opt/openssl@3"),
            Path("/usr/local/opt/openssl@3"),
        ]
    for root in openssl_roots:
        include = root / "include"
        if not (include / "openssl/evp.h").is_file():
            continue
        library = _find_library(root, "crypto")
        if require_crypto_library and library is None:
            continue
        openssl_include = include
        openssl_library_dir = root / "lib" if library is not None else None
        break
    if openssl_include is None:
        raise RuntimeError("host-native OpenSSL development files not found")

    return HostDependencies(
        json_include=json_include,
        json_library=json_library,
        openssl_include=openssl_include,
        openssl_library_dir=openssl_library_dir,
    )
