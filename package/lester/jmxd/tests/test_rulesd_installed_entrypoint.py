from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULESD = ROOT / "files" / "rule_manager.lua"


def test_packaged_rulesd_name_enters_main_loop():
    source = RULESD.read_text()

    assert 'arg[0]:match("dreamingwrt%-rulesd")' in source
    assert "main_loop()" in source
