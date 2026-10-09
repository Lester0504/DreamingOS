from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def test_cache_lifecycle():
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "json-c", "sqlite3"], text=True).split()
    with tempfile.TemporaryDirectory(prefix="webd-memory-") as directory:
        output = Path(directory) / "cache-test"
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(ROOT / "tests/test_webd_memory_lifecycle.c"),
                        *flags, "-lpthread", "-o", str(output)], check=True)
        subprocess.run([str(output)], check=True)


if __name__ == "__main__":
    test_cache_lifecycle()
