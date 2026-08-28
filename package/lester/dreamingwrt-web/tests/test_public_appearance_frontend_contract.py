from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESIGN = (ROOT / "design.md").read_text()
SETUP = (ROOT / "files/www/dreamingwrt/static/js/setup-welcome.js").read_text()
LOGIN = (ROOT / "files/www/dreamingwrt/login/index.html").read_text()


def test_login_and_setup_share_public_appearance_contract() -> None:
    retired_theme_endpoint = "/api/v1/login/" + "theme"
    for source in (DESIGN, SETUP, LOGIN):
        assert retired_theme_endpoint not in source
    assert "readJson('/api/v1/public/appearance')" in SETUP
    assert "getJson('/api/v1/public/appearance')" in LOGIN
    assert "GET /api/v1/public/appearance" in DESIGN


def test_anonymous_pages_use_standard_material_without_legacy_aliases() -> None:
    for source in (SETUP, LOGIN):
        apply_start = source.index("function applyLiquidGlass(data)")
        apply_end = source.index("function " if source is SETUP else "async function initTheme()", apply_start + 30)
        material_parser = source[apply_start:apply_end]
        assert "material_glass" in material_parser
        assert "login_glass_" not in material_parser
        assert "liquid_glass" not in material_parser
        assert "menu_liquid_glass" not in material_parser


def test_setup_failure_path_is_single_shot_and_usable() -> None:
    init_start = SETUP.index("async function initTheme()")
    init_end = SETUP.index("async function loadSession()", init_start)
    init_theme = SETUP[init_start:init_end]
    assert init_theme.count("/api/v1/public/appearance") == 1
    assert "catch (_) {}" in init_theme
    assert "setInterval" in init_theme
    assert "readJson('/api/v1/public/appearance')" in init_theme
