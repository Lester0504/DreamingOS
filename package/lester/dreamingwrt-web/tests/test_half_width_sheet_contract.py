#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KIT_JS = (ROOT / "files/www/dreamingwrt/static/ui-kit/dwrt-ui-kit.js").read_text(encoding="utf-8")
KIT_CSS = (ROOT / "files/www/dreamingwrt/static/ui-kit/dwrt-ui-kit.css").read_text(encoding="utf-8")


def require(source: str, fragment: str, message: str) -> None:
    assert fragment in source, message


require(KIT_JS, "function ensureSheetMaterial(sheet)", "half-width Sheet material must be owned by the UI Kit")
require(KIT_JS, "width >= window.innerWidth * 0.9", "near-fullscreen sheets must remain outside the half-width migration")
require(KIT_JS, "if (width <= 0) return", "hidden sheets must wait for measurable geometry before classification")
require(KIT_JS, "sheet.dataset.dwrtSheetVariant = 'fullscreen'", "fullscreen Sheet must receive an explicit opt-out marker")
require(KIT_JS, "sheet.dataset.dwrtSheetVariant = sheet.dataset.dwrtSheetVariant || 'copilot'", "ordinary side Sheets must use the shared copilot variant")
require(KIT_JS, "if (sheet.dataset.dwrtSheetVariant === 'copilot' || explicitModalCopilot)", "an observed class change must not reclassify an explicitly migrated Sheet or Modal")
require(KIT_JS, "if (appliedLegacyClasses.length) sheet.classList.remove(...appliedLegacyClasses)", "private glass aliases must be removed without creating no-op class mutations")
require(KIT_JS, "data-dwrt-sheet-wallpaper-image", "the Sheet needs a lightweight wallpaper mirror")
require(KIT_JS, "document.getElementById('appWallpaper')", "the Sheet must reuse the existing app wallpaper source")
require(KIT_JS, "image.style.left = `${-rect.left}px`", "mirrored wallpaper must align to the overlay's real viewport x coordinate")
require(KIT_JS, "image.style.top = `${-rect.top}px`", "mirrored wallpaper must align to the overlay's real viewport y coordinate")
require(KIT_JS, "syncMountedGlassWallpapers();", "viewport changes must realign Sheet and Modal wallpaper mirrors")
require(KIT_JS, "dialog.addEventListener('transitionend', state.transitionend)", "centered Modal must realign its mirror after the entrance transform")
require(KIT_CSS, '.dwrt-kit-sheet[data-dwrt-sheet-variant="copilot"]', "copilot Sheet needs a shared Kit selector")
require(KIT_CSS, '.dwrt-kit-modal[data-dwrt-modal-variant="copilot"]', "centered Modal needs the same explicit copilot material")
require(KIT_CSS, ".dwrt-kit-sheet-wallpaper", "wallpaper geometry must be shared")
require(KIT_CSS, ".dwrt-kit-sheet-material", "the material layer must be shared")
require(KIT_CSS, "backdrop-filter: blur(var(--dwrt-glass-base-blur, 3.2px))", "Sheet material must use the established liquid-glass parameter")
require(KIT_CSS, "background: rgba(2, 7, 15, 0.16);", "the overlay must match the lightweight AI scrim")
assert "new OffscreenCanvas" not in KIT_JS, "opening a Sheet must not create another graphics renderer"
assert "canvas" not in KIT_JS[KIT_JS.index("function ensureSheetMaterial"):KIT_JS.index("function mountSheet")], "Sheet material setup must remain DOM/CSS-only"

print("half-width Sheet contract: ok")
