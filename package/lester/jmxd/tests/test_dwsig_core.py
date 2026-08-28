from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def test_dwsig_core_roundtrip_and_rejection() -> None:
    with tempfile.TemporaryDirectory(prefix="dw-dwsig-build-") as directory:
        binary = Path(directory) / "test-dwsig-core"
        subprocess.run(
            [
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-I", str(ROOT / "src" / "corpus"),
                str(ROOT / "src" / "corpus" / "dwsig.c"),
                str(ROOT / "tests" / "test_dwsig_core.c"),
                "-o", str(binary), "-lcrypto", "-lsqlite3",
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)
