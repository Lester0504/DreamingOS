#!/usr/bin/env python3
"""编辑 LAN / WAN / 端口抽屉的四条修复的源码契约。

对应用户 2026-08-05 的四条要求：抽屉过宽、逻辑接口应为下拉、手风琴点不动、
点一下就整体重载。断言针对代码本身而不是注释 —— 本次的解释性注释里含
“抽屉”“重载”等字样，用宽松子串匹配会被注释喂饱而漏掉真实回归。
"""
import gzip
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / 'files' / 'www' / 'dreamingwrt'
NIC_JS = WWW / 'plugins' / 'native' / 'network-interface-config.js'
GC_JS = WWW / 'plugins' / 'native' / 'global-config.js'
NIC_CSS = WWW / 'static' / 'css' / 'network-interface-config.css'
GC_CSS = WWW / 'static' / 'css' / 'global-config.css'
KIT_CSS = WWW / 'static' / 'ui-kit' / 'dwrt-ui-kit.css'


def strip_comments(text):
    """去掉 /* */ 注释，避免注释里的字样满足断言。"""
    return re.sub(r'/\*.*?\*/', '', text, flags=re.S)


def test_drawer_width_is_standard_matching_ai_drawer():
    """抽屉宽度收敛到标准档，且标准档本身仍是 460px（AI 抽屉基准）。"""
    kit = KIT_CSS.read_text(encoding='utf-8')
    assert '--dwrt-kit-sheet-width-standard: min(460px,' in kit, '标准档不再是 460px，与 AI 抽屉脱钩'

    nic = NIC_CSS.read_text(encoding='utf-8')
    block = re.search(r'\.network-interface-drawer\s*\{(.*?)\}', nic, flags=re.S)
    assert block, '找不到 .network-interface-drawer 规则块'
    body = strip_comments(block.group(1))
    assert '--dwrt-kit-sheet-width: var(--dwrt-kit-sheet-width-standard)' in body, \
        '编辑 LAN/WAN 抽屉宽度未使用标准档'
    assert 'sheet-width-wide' not in body, '编辑 LAN/WAN 抽屉又回到了 -wide（820px）'

    gc = strip_comments(GC_CSS.read_text(encoding='utf-8'))
    port = re.search(r'\.global-port-drawer\s*\{([^}]*)\}', gc)
    assert port, '找不到 .global-port-drawer 规则'
    assert 'sheet-width-standard' in port.group(1), '全局端口抽屉宽度未收敛到标准档'


def test_narrow_drawer_forms_are_width_adaptive_not_viewport_gated():
    """460px 抽屉内的表单栅格必须按可用宽度自适应。

    媒体查询量的是视口，抽屉却固定 460px，桌面端永远命中不到 max-width 断点，
    所以写死两列会一直挤着。
    """
    nic = strip_comments(NIC_CSS.read_text(encoding='utf-8'))
    # 必须锚在行首的独立选择器上：文件里还有 `... > .network-interface-form-grid + *`
    # 这类组合选择器，宽松匹配会先撞上它们。
    grid = re.search(r'^\.network-interface-form-grid\s*\{(.*?)\}', nic, flags=re.S | re.M)
    assert grid, '找不到 .network-interface-form-grid'
    assert 'auto-fit' in grid.group(1), '表单栅格不是自适应列数'
    assert 'repeat(2, minmax(0, 1fr))' not in grid.group(1), '表单栅格又写死成两列'

    gc = strip_comments(GC_CSS.read_text(encoding='utf-8'))
    detail = re.search(r'\.global-detail-grid\s*\{([^}]*)\}', gc)
    assert detail, '找不到 .global-detail-grid'
    assert 'auto-fit' in detail.group(1), '端口明细栅格不是自适应列数'


def test_ifname_is_a_select_not_a_free_text_input():
    """逻辑接口是下拉，候选取自真实事实而非硬编码。"""
    src = strip_comments(NIC_JS.read_text(encoding='utf-8'))
    assert 'function ifnameOptions(' in src, '缺少逻辑接口候选函数'

    used = re.findall(r"formField\('逻辑接口',\s*(\w+)\(", src)
    assert len(used) == 2, f'逻辑接口应出现在 LAN 与 WAN 两处，实际 {len(used)}'
    assert set(used) == {'selectField'}, f'逻辑接口仍在用 {set(used)} 而不是 selectField'

    opts = re.search(r'function ifnameOptions\(draft\)\s*\{(.*?)\n  \}', src, flags=re.S)
    assert opts, '无法提取 ifnameOptions 主体'
    body = opts.group(1)
    assert 'state.rows' in body, '候选未包含现有接口'
    assert 'state.ports' in body, '候选未包含物理口'
    assert '占用' in body, '未标注已被其他接口占用的名字'


def test_background_data_must_not_rebuild_an_open_drawer():
    """applyData() 在抽屉打开时不得整页重绘。

    这是“点一下里面的东西整个抽屉重新加载”的根因：宿主每 20s 喂一次 setData()，
    而 render() 是 root.innerHTML 整页重建。
    """
    src = strip_comments(NIC_JS.read_text(encoding='utf-8'))
    fn = re.search(r'function applyData\(config, ports\)\s*\{(.*?)\n  \}', src, flags=re.S)
    assert fn, '无法提取 applyData'
    body = fn.group(1)
    assert re.search(r'if\s*\(state\.drawer\)', body), 'applyData 未检查抽屉是否打开'

    branch = re.search(r'if\s*\(state\.drawer\)\s*\{(.*?)\}\s*else\s*\{(.*?)\}', body, flags=re.S)
    assert branch, 'applyData 的抽屉分支结构不可识别'
    assert 'render()' not in branch.group(1), '抽屉打开时仍然调用了 render()'
    assert 'render()' in branch.group(2), '抽屉关闭时反而不再重绘'


def test_events_bound_on_document_because_the_sheet_is_portalled():
    """事件绑在 document 上并按实例归属过滤。

    kit 的 mountAll() 把 .dwrt-kit-sheet 搬进 body 下的 portal，绑在 root 上的
    委派监听收不到抽屉内的事件 —— 这正是手风琴点了没反应的原因。
    """
    src = strip_comments(NIC_JS.read_text(encoding='utf-8'))
    for event in ('click', 'input', 'change'):
        assert f"root.addEventListener('{event}'" not in src, \
            f'{event} 又绑回 root，抽屉进 portal 后会失效'
        assert f"document.addEventListener('{event}'" in src, f'{event} 未绑在 document 上'
        assert f"document.removeEventListener('{event}'" in src, f'{event} 卸载时未解绑'

    assert 'function ownsEvent(' in src, '缺少事件归属过滤，LAN/WAN 两个实例会互相串台'
    assert 'data-interface-owner' in src, '抽屉未标记所属实例'


def test_accordion_and_drawer_lookups_survive_the_portal():
    """手风琴与抽屉内查询不以 root 为作用域。"""
    src = strip_comments(NIC_JS.read_text(encoding='utf-8'))
    assert 'function drawerNode(' in src, '缺少 portal 感知的抽屉查找'

    toggle = re.search(r'const editorToggle = event\.target\.closest.*?\n      return;', src, flags=re.S)
    assert toggle, '无法提取手风琴分支'
    body = toggle.group(0)
    assert 'root.querySelectorAll' not in body, '手风琴仍从 root 查询分组，抽屉进 portal 后找不到'
    assert 'drawerNode()' in body, '手风琴未以抽屉为作用域'
    assert 'const drawer = drawerNode();' in src, 'patchDrawerContents 未使用 portal 感知查找'


def test_gzip_twins_match_sources():
    for path in (NIC_JS, GC_JS, NIC_CSS, GC_CSS):
        twin = path.with_suffix(path.suffix + '.gz')
        assert twin.exists(), f'缺少 gzip 孪生：{twin.name}'
        assert gzip.decompress(twin.read_bytes()) == path.read_bytes(), \
            f'{twin.name} 与源文件不一致'


def main():
    for name, value in sorted(globals().items()):
        if name.startswith('test_') and callable(value):
            value()
    print('interface drawer portal contract: ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
