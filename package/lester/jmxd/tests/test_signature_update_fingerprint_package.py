#!/usr/bin/env python3
import json
import sqlite3
import subprocess
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGER = ROOT / "tools" / "package-signature-update.sh"


def create_signature_db(path: Path) -> None:
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE app(app_id INTEGER PRIMARY KEY, enabled INTEGER);
        CREATE TABLE dpi_rule(rule_id INTEGER PRIMARY KEY, app_id INTEGER, enabled INTEGER,
          match_type TEXT, pattern_format TEXT, pattern_text TEXT, pattern_hex TEXT);
        CREATE TABLE domain_group(id INTEGER);
        CREATE TABLE domain_entry(id INTEGER);
        CREATE TABLE device_vendor(id INTEGER);
        CREATE TABLE device_type(id INTEGER);
        CREATE TABLE device_fingerprint_rule(id INTEGER, enabled INTEGER);
        CREATE TABLE carrier_prefix(id INTEGER, enabled INTEGER);
        CREATE TABLE geoip_country(id INTEGER, enabled INTEGER);
        CREATE TABLE geoip_country_prefix(id INTEGER, enabled INTEGER);
        CREATE TABLE reputation_ip_entry(id INTEGER, enabled INTEGER);
        CREATE TABLE reputation_domain_entry(id INTEGER, enabled INTEGER);
        CREATE TABLE reputation_url_entry(id INTEGER, enabled INTEGER);
        CREATE TABLE content_category(id INTEGER, enabled INTEGER);
        CREATE TABLE content_domain_entry(id INTEGER, enabled INTEGER);
        CREATE TABLE app_icon(app_id INTEGER, icon_key TEXT);
        CREATE TABLE icon_asset(icon_key TEXT, icon_file TEXT);
        INSERT INTO app VALUES(1, 1);
        INSERT INTO icon_asset VALUES('test', 'test.png');
        """
    )
    db.commit()
    db.close()


def create_fingerprint_db(path: Path, *, application_id: int = 1146570320,
                          expected: int = 2, actual: int = 2) -> None:
    db = sqlite3.connect(path)
    db.execute(f"PRAGMA application_id={application_id}")
    db.execute("PRAGMA user_version=1")
    db.executescript(
        """
        CREATE TABLE fingerprint_meta(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE fingerprint_device(device_id INTEGER PRIMARY KEY);
        """
    )
    db.execute("INSERT INTO fingerprint_meta VALUES('device_count', ?)", (str(expected),))
    db.executemany("INSERT INTO fingerprint_device VALUES(?)", [(i + 1,) for i in range(actual)])
    db.commit()
    db.close()


def package(tmp: Path, fingerprint: Path, name: str = "update.bin") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(PACKAGER), "--db", str(tmp / "signature.db"),
            "--logo", str(tmp / "logo"), "--out", str(tmp / name),
            "--format", "v2", "--fingerprint", str(fingerprint),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def prepare(tmp: Path) -> None:
    create_signature_db(tmp / "signature.db")
    (tmp / "logo").mkdir()
    (tmp / "logo" / "test.png").write_bytes(b"png")


def test_file_and_directory_inputs_are_canonical() -> None:
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        prepare(tmp)
        fp_dir = tmp / "catalog"
        fp_dir.mkdir()
        create_fingerprint_db(fp_dir / "fingerprint.db")

        for input_path, output in ((fp_dir / "fingerprint.db", "file.bin"),
                                   (fp_dir, "dir.bin")):
            result = package(tmp, input_path, output)
            assert result.returncode == 0, result.stderr
            with tarfile.open(tmp / output) as archive:
                names = archive.getnames()
                assert "fingerprint/fingerprint.db" in names
                assert not any(name.startswith("fingerprint/") and
                               name != "fingerprint/fingerprint.db" for name in names)
                manifest = json.load(archive.extractfile("manifest.json"))
            datasets = [d for d in manifest["datasets"] if d["name"] == "fingerprint"]
            assert len(datasets) == 1
            assert datasets[0]["path"] == "fingerprint/fingerprint.db"


def test_invalid_fingerprint_identity_and_count_are_rejected() -> None:
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        prepare(tmp)
        bad_id = tmp / "bad-id.db"
        bad_count = tmp / "bad-count.db"
        create_fingerprint_db(bad_id, application_id=1)
        create_fingerprint_db(bad_count, expected=3, actual=2)

        # The fixed filename contract is checked before database content.
        result = package(tmp, bad_id)
        assert result.returncode != 0
        assert "must be named fingerprint.db" in result.stderr

        identity_dir = tmp / "identity"
        count_dir = tmp / "count"
        identity_dir.mkdir()
        count_dir.mkdir()
        bad_id.rename(identity_dir / "fingerprint.db")
        bad_count.rename(count_dir / "fingerprint.db")
        result = package(tmp, identity_dir, "bad-id.bin")
        assert result.returncode != 0
        assert "application_id mismatch" in result.stderr
        result = package(tmp, count_dir, "bad-count.bin")
        assert result.returncode != 0
        assert "device_count mismatch" in result.stderr


if __name__ == "__main__":
    test_file_and_directory_inputs_are_canonical()
    test_invalid_fingerprint_identity_and_count_are_rejected()
    print("ok: signature v2 fingerprint package identity and canonical layout")
