#!/usr/bin/env python3
import csv
import re
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "files" / "geoip" / "iso3166-1.csv"
FLAGS = ROOT / "files" / "logo" / "flags"
SIGNATURE_DB = ROOT / "files" / "signatures" / "dreamingwrt_signatures.db"

OFFICIAL_CODES = set(
    """AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW""".split()
)
EXTRA_FLAG_CODES = {"ES-CA", "ES-GA", "EU", "GB-ENG", "GB-NIR", "GB-SCT", "GB-WLS", "UN", "XK"}
CONTINENTS = {
    "Africa",
    "Antarctica",
    "Asia",
    "Europe",
    "North America",
    "Oceania",
    "South America",
}


def load_catalog() -> list[dict[str, str]]:
    with CATALOG.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        assert reader.fieldnames == ["code", "name_en", "name_zh", "continent", "sort_order"]
        return list(reader)


def test_catalog_is_complete_official_iso3166_1() -> None:
    rows = load_catalog()
    codes = [row["code"] for row in rows]

    assert len(rows) == 249
    assert len(set(codes)) == 249
    assert set(codes) == OFFICIAL_CODES
    assert codes == sorted(codes)
    assert all(re.fullmatch(r"[A-Z]{2}", code) for code in codes)
    assert [int(row["sort_order"]) for row in rows] == list(range(1, 250))
    assert all(row["name_en"].strip() and row["name_zh"].strip() for row in rows)
    assert all(row["continent"] in CONTINENTS for row in rows)


def test_catalog_flags_exist_and_extensions_are_not_countries() -> None:
    catalog_codes = {row["code"] for row in load_catalog()}
    flag_codes = {path.stem.upper() for path in FLAGS.glob("*.svg")}

    assert all((FLAGS / f"{code.lower()}.svg").is_file() for code in catalog_codes)
    assert EXTRA_FLAG_CODES.isdisjoint(catalog_codes)
    assert all((FLAGS / f"{code.lower()}.svg").is_file() for code in EXTRA_FLAG_CODES)
    assert flag_codes - catalog_codes == EXTRA_FLAG_CODES


def test_signature_database_catalog_matches_csv() -> None:
    rows = load_catalog()
    expected = {
        row["code"]: (row["name_en"], row["name_zh"], row["continent"])
        for row in rows
    }

    uri = f"file:{SIGNATURE_DB}?mode=ro"
    with sqlite3.connect(uri, uri=True) as db:
        schema = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='geoip_country'"
        ).fetchone()
        assert schema is not None
        actual_rows = db.execute(
            "SELECT iso_code,name_en,name_zh,continent,flag_asset,source,enabled "
            "FROM geoip_country ORDER BY iso_code"
        ).fetchall()

    assert len(actual_rows) == 249
    assert {row[0] for row in actual_rows} == OFFICIAL_CODES
    for code, name_en, name_zh, continent, flag_asset, source, enabled in actual_rows:
        assert (name_en, name_zh, continent) == expected[code]
        assert flag_asset == ""
        assert source == "dreamingwrt_geoip"
        assert enabled == 1


if __name__ == "__main__":
    test_catalog_is_complete_official_iso3166_1()
    test_catalog_flags_exist_and_extensions_are_not_countries()
    test_signature_database_catalog_matches_csv()
    print("ok: Geo-block country catalog is the complete official ISO 3166-1 set")
