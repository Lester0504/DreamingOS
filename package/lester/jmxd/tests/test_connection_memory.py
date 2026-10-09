from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def test_adaptive_capacity_preserves_rows_and_delta():
    import sys
    if sys.platform != "linux":
        import pytest
        pytest.skip("production read model uses Linux getrandom")
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "openssl", "json-c", "sqlite3"], text=True).split()
    with tempfile.TemporaryDirectory(prefix="connection-memory-") as directory:
        output = Path(directory) / "test"
        subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O2", "-I" + str(ROOT / "src"),
                        str(ROOT / "tests/test_connection_memory.c"),
                        str(ROOT / "src/system/memory_profile.c"),
                        *flags, "-lpthread", "-o", str(output)], check=True)
        subprocess.run([str(output), str(Path(directory) / "conntrack")], check=True)


if __name__ == "__main__":
    test_adaptive_capacity_preserves_rows_and_delta()
