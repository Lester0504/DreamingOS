#!/usr/bin/env python3
"""圆角归入 token 体系 + 停止自画 kit 材质（Acceptance-to-Front 单）。

覆盖该单第一节（client-details 圆角）、第二节（client-details 材质逃逸）、
第三节（container-service 复制 overview 卡 DOM）与第七节（抽屉宽度魔法值）。

断言前先剥注释：本次注释里含「圆角」「材质」「token」等字样，宽松子串匹配会被
注释喂饱。
"""
import gzip
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / 'files' / 'www' / 'dreamingwrt'
CD_CSS = WWW / 'static' / 'css' / 'client-details.css'
CD_JS = WWW / 'static' / 'js' / 'client-details.js'
AI_CSS = WWW / 'static' / 'css' / 'ai-assistant.css'
CS_JS = WWW / 'plugins' / 'native' / 'container-service.js'
DESIGN = ROOT / 'DESIGN.md'

# 允许保留字面量的半径：药丸形（DESIGN.md 明确列出），以及由元素尺寸反推的
# 极小半径（滑块轨道 15px 高、游标 5px 宽，套 8px 会糊成一团）。
# 1px / 2px 是勾号与分隔条一类的装饰细节，6px 用在 18px 见方的复选框和
# 行内 `code` 上——这些尺寸下 8px 已经接近半个元素，不属于漂移。
ALLOWED_LITERALS = {'999', '99', '9999', '1', '2', '3', '4', '5', '6'}

# 第一节点名的漂移档位。收敛后这些值不得再出现在已处理的文件里。
DRIFT_STEPS = ('7', '9', '10', '11', '13', '14', '15', '16', '20', '22', '26', '30')

# 已完成收敛的文件。每收一个就加进来，让契约随进度一起长。
CONVERGED_CSS = (
    'client-details.css',
    'user-authentication.css',
    'system-settings.css',
)

# 拟物插画的例外：模拟真实设备外框的圆角不套 UI token，
# 42px 外框配 24px 屏幕是机身比例，换成 --app-radius-card 两者会一样圆。
PHYSICAL_EXCEPTIONS = {
    'user-authentication.css': {'42', '26', '24', '15'},
}


def strip_comments(text):
    return re.sub(r'/\*.*?\*/', '', text, flags=re.S)


def test_client_details_radii_use_tokens():
    """client-details.css 不再出现四档之外的硬编码圆角。"""
    css = strip_comments(CD_CSS.read_text(encoding='utf-8'))
    literals = re.findall(r'border-radius:\s*(\d+)px', css)
    stray = sorted({v for v in literals if v not in ALLOWED_LITERALS}, key=int)
    assert not stray, f'仍有非 token 圆角字面量：{stray}px'

    # 这些是审计里点名的漂移档位，必须一个都不剩
    for value in ('7', '9', '10', '13', '14', '15', '16', '20', '22'):
        assert f'border-radius: {value}px' not in css, f'{value}px 圆角仍然存在'


def test_radius_tokens_still_defined_as_four_steps():
    """四档 token 本身没被改动 —— 收敛的前提是档位稳定。"""
    design = DESIGN.read_text(encoding='utf-8')
    for token in ('--app-radius-card', '--app-radius-panel',
                  '--app-radius-control', '--app-radius-compact'):
        assert token in design, f'DESIGN.md 缺少 {token}'


def test_converged_files_have_no_drifted_radii():
    """已收敛的文件里不得再出现四档之外的圆角。

    这条随进度增长：每收一个文件就加进 CONVERGED_CSS，
    既锁住已完成的成果，也避免把还没处理的文件当成回归报出来。
    """
    for name in CONVERGED_CSS:
        css = strip_comments((WWW / 'static' / 'css' / name).read_text(encoding='utf-8'))
        allowed = ALLOWED_LITERALS | PHYSICAL_EXCEPTIONS.get(name, set())
        literals = re.findall(r'border-radius:\s*(\d+)px', css)
        stray = sorted({v for v in literals if v not in allowed}, key=int)
        assert not stray, f'{name} 仍有非 token 圆角：{stray}px'

        for value in DRIFT_STEPS:
            if value in PHYSICAL_EXCEPTIONS.get(name, set()):
                continue
            assert f'border-radius: {value}px' not in css, f'{name} 里 {value}px 圆角仍然存在'


def test_pill_shapes_are_written_as_pills_not_half_height():
    """药丸形要写 999px，不要写「刚好等于半高」的字面量。

    iOS 开关轨道高 28px、圆角写 15px，内存条高 10px、圆角写 6px —— 两者的意图都是
    「完全圆头」，但写成半高值时读者无从判断，改了高度也不会跟着变。写 999px 之后
    意图自明，且高度再变都还是药丸。
    """
    kit_css = strip_comments((WWW / 'static' / 'ui-kit' / 'dwrt-ui-kit.css').read_text(encoding='utf-8'))
    system_css = strip_comments((WWW / 'static' / 'css' / 'system-settings.css').read_text(encoding='utf-8'))
    for css, selector in ((kit_css, '.dwrt-kit-switch input[type="checkbox"]::before'), (system_css, '.system-mem-preview')):
        block = re.search(re.escape(selector) + r'\s*\{([^}]*)\}', css)
        assert block, f'找不到 {selector}'
        radius = re.search(r'border-radius:\s*([^;]+)', block.group(1))
        assert radius, f'{selector} 没有 border-radius'
        assert '999' in radius.group(1), (
            f'{selector} 的药丸形要写 999px，当前是 {radius.group(1).strip()}'
        )


def test_client_detail_cards_take_material_from_kit():
    """卡片材质来自 .dwrt-kit-glass-surface，页面 CSS 只留几何。"""
    css = strip_comments(CD_CSS.read_text(encoding='utf-8'))

    for selector in ('.client-detail-card', '.client-connection-filter-card'):
        # 必须锚在行首且是独立选择器：这两个类名都还出现在别的组合选择器里
        # （`.client-detail-overview > .client-detail-card:last-child` 等），
        # 宽松匹配只会校验到第一个撞上的块，改坏另一个不会被发现。
        blocks = re.findall(r'^' + re.escape(selector) + r'\s*\{([^}]*)\}', css, flags=re.M)
        assert blocks, f'找不到 {selector} 规则块'
        for body in blocks:
            assert 'background:' not in body, f'{selector} 仍在自画背景'
            assert 'inset 0 0 0 1px' not in body, f'{selector} 仍在自画 inset 边框'
            assert 'var(--app-radius-' in body, f'{selector} 圆角未走 token'

    js = CD_JS.read_text(encoding='utf-8')
    # 每个带 client-detail-card 的卡片都要挂 kit 材质（-head 子元素除外）
    cards = re.findall(r'class="([^"]*\bclient-detail-card(?!-)[^"]*)"', js)
    assert cards, '找不到 client-detail-card 用法'
    missing = [c for c in cards if 'dwrt-kit-glass-surface' not in c]
    assert not missing, f'{len(missing)} 处卡片未挂 kit 材质：{missing[:2]}'

    filters = re.findall(r'class="([^"]*\bclient-connection-filter-card(?!-)[^"]*)"', js)
    assert filters, '找不到 client-connection-filter-card 用法'
    assert all('dwrt-kit-glass-surface' in c for c in filters), '筛选卡未挂 kit 材质'


def test_container_service_uses_kit_overview_renderer():
    """container-service 不再手写 overview 卡 DOM。"""
    js = strip_comments(CS_JS.read_text(encoding='utf-8'))
    assert 'overviewCardsMarkup' in js, '未调用 kit 的 overviewCardsMarkup'

    for fragment in ('dwrt-kit-overview-content', 'dwrt-kit-overview-label',
                     'dwrt-kit-overview-icon', '<article class="dwrt-kit-overview-card'):
        assert fragment not in js, f'仍在手写 overview 卡内部结构：{fragment}'
    assert '<section class="dwrt-kit-overview-grid' not in js, '仍在手写 overview 容器'


def test_ai_drawer_width_references_the_kit_step():
    """AI 抽屉宽度引用 kit 标准档，不复写字面量。"""
    css = strip_comments(AI_CSS.read_text(encoding='utf-8'))
    decl = re.search(r'--ai-drawer-width:\s*([^;]+);', css)
    assert decl, '找不到 --ai-drawer-width 声明'
    assert 'var(--dwrt-kit-sheet-width-standard' in decl.group(1), \
        'AI 抽屉宽度仍是逐页魔法值，未引用 kit 标准档'


def test_gzip_twins_match_sources():
    for path in (CD_CSS, CD_JS, AI_CSS, CS_JS, WWW / 'static' / 'js' / 'menu-shell.js'):
        twin = path.with_suffix(path.suffix + '.gz')
        assert twin.exists(), f'缺少 gzip 孪生：{twin.name}'
        assert gzip.decompress(twin.read_bytes()) == path.read_bytes(), \
            f'{twin.name} 与源文件不一致'


def main():
    for name, value in sorted(globals().items()):
        if name.startswith('test_') and callable(value):
            value()
    print('kit material and radius contract: ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
