#!/usr/bin/env python3
"""用户 2026-08-05 第二轮四条要求的源码契约。
1) IPv6 上游 WAN 必须是下拉（多选），不是逗号分隔文本框。
2) LAN 表 VLAN 空值显示「默认」，不是「--」。
3) WAN 模式属于后端契约缺口，前端不得伪造 capability。
4) 路由表页面 tab 必须用 kit 页面档，且页面壳层不得重复写 gutter。
断言一律针对去注释后的代码。本次注释里恰好含「下拉」「默认」「gutter」
等字样，宽松子串匹配会被注释喂饱而漏掉真实回归。
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / 'files' / 'www' / 'dreamingwrt'
NIC_JS = WWW / 'plugins' / 'native' / 'network-interface-config.js'
GC_JS = WWW / 'plugins' / 'native' / 'global-config.js'
NIC_CSS = WWW / 'static' / 'css' / 'network-interface-config.css'
RT_JS = WWW / 'plugins' / 'native' / 'routing-table.js'
RT_CSS = WWW / 'static' / 'css' / 'routing-table.css'
PO_JS = WWW / 'plugins' / 'native' / 'policy-objects.js'
KIT_CSS = WWW / 'static' / 'ui-kit' / 'dwrt-ui-kit.css'


def strip_block_comments(text):
    return re.sub(r'/\*.*?\*/', '', text, flags=re.S)


def strip_all_comments(text):
    text = strip_block_comments(text)
    return re.sub(r'^\s*//.*$', '', text, flags=re.M)


def test_ipv6_upstream_wan_is_a_multi_select_not_free_text():
    src = strip_all_comments(NIC_JS.read_text(encoding='utf-8'))
    assert "multiSelectField('ipv6.parent_wans'" in src, '上游 WAN 不再使用多选下拉'
    assert "inputField('ipv6.parent_text'" not in src, '上游 WAN 又回到了逗号分隔的自由文本输入框'
    block = re.search(r'function multiSelectField\([^)]*\)\s*\{(.*?)\n  \}', src, flags=re.S)
    assert block, '找不到 multiSelectField 定义'
    body = block.group(1)
    assert '<select' in body and 'multiple' in body, 'multiSelectField 没有产出 <select multiple>'
    assert 'data-interface-multi' in body, '多选控件缺少 data-interface-multi 标记'


def test_multi_select_reads_selected_options_not_value():
    src = strip_all_comments(NIC_JS.read_text(encoding='utf-8'))
    patch = re.search(r'function patchDraft\(field, input\)\s*\{(.*?)\n  \}', src, flags=re.S)
    assert patch, '找不到 patchDraft 定义'
    body = patch.group(1)
    assert 'selectedOptions' in body, 'patchDraft 未读取 selectedOptions，多选会被截断成一个值'
    assert re.search(r'input\.multiple|data-interface-multi', body), 'patchDraft 没有识别多选控件的分支'


def test_wan_candidates_are_fed_by_host_at_mount_and_on_setdata():
    nic = strip_all_comments(NIC_JS.read_text(encoding='utf-8'))
    assert 'wanNames: asArray(context.wanNames)' in nic, 'network-interface-config 未接收宿主传入的 wanNames'
    assert 'function upstreamWanOptions' in nic, '缺少 WAN 候选推导函数'
    setdata = re.search(r'setData\(config, ports, wanNames\)\s*\{(.*?)\n    \}', nic, flags=re.S)
    assert setdata, 'setData 未接收 wanNames 形参'
    assert 'state.wanNames' in setdata.group(1), 'setData 未更新 state.wanNames'
    gc = strip_all_comments(GC_JS.read_text(encoding='utf-8'))
    assert 'wanNames: state.wans.map(' in gc, '宿主 mount 时未传 wanNames'
    assert re.search(r'setData\?\.\([^)]*interfacePayloads\.ports,\s*\n?\s*state\.wans\.map', gc), \
        '宿主 setData 时未传 wanNames，晚到的 WAN 列表永远进不来'


def test_multi_select_has_its_own_height_rule():
    css = strip_block_comments(NIC_CSS.read_text(encoding='utf-8'))
    block = re.search(r'\.network-interface-field select\[multiple\]\s*\{(.*?)\}', css, flags=re.S)
    assert block, '多选 select 没有独立的样式规则'
    assert 'height: auto' in block.group(1), '多选 select 仍套用单行的固定高度'


def test_lan_vlan_empty_shows_default_label():
    src = strip_all_comments(NIC_JS.read_text(encoding='utf-8'))
    assert "row.vlan_id || '默认'" in src, 'LAN 表 VLAN 空值未显示「默认」'
    assert "row.vlan_id || '--'" not in src, 'LAN 表 VLAN 空值又回到了「--」'


def test_wan_mode_capability_is_not_fabricated():
    src = strip_all_comments(GC_JS.read_text(encoding='utf-8'))
    line = re.search(r'const policyWritable = (.*?);', src)
    assert line, '找不到 WAN 模式的能力门控'
    expr = line.group(1)
    assert 'strictCap(' in expr, 'WAN 模式门控不再走 strictCap，可能被伪造成恒真'
    assert not re.search(r'\btrue\b', expr), 'WAN 模式门控被硬编码为 true'
    assert 'global-contract-note' in src, '缺少能力缺失时的解释性占位'


def test_routing_table_tabs_use_kit_page_tier():
    src = strip_all_comments(RT_JS.read_text(encoding='utf-8'))
    nav = re.search(r'function tabsMarkup\(\)\s*\{(.*?)\n  \}', src, flags=re.S)
    assert nav, '找不到 routing-table 的 tabsMarkup'
    body = nav.group(1)
    assert 'dwrt-kit-page-tabs' in body, '路由表 tab 未使用 kit 页面档，会掉回 48px 紧凑档'
    assert 'role="tab"' in body, '路由表 tab 缺少 role="tab"'
    assert 'data-value=' in body, '路由表 tab 缺少 data-value，kit 药丸滑块无法定位'
    po = strip_all_comments(PO_JS.read_text(encoding='utf-8'))
    assert 'dwrt-kit-page-tabs' in po, '基线页面 policy-objects 也没有页面档，基线判断失效'
    kit = KIT_CSS.read_text(encoding='utf-8')
    assert '--dwrt-page-tab-height: 62px' in kit, 'kit 页面档高度已变，需重新确认基线'


def test_routing_table_does_not_redeclare_page_gutter():
    css = strip_block_comments(RT_CSS.read_text(encoding='utf-8'))
    block = re.search(r'\.routing-table-shell\s*\{(.*?)\}', css, flags=re.S)
    assert block, '找不到 .routing-table-shell 规则块'
    assert 'app-page-gutter' not in block.group(1), \
        '.routing-table-shell 又自己写了 gutter，tab 会被推离其它页面的 18/296'
    for hit in re.finditer(r'\.routing-table-shell\s*\{([^}]*)\}', css):
        assert 'app-page-gutter' not in hit.group(1), '某个断点里的 .routing-table-shell 补回了 gutter'
    for hit in re.finditer(r'\.routing-page-tabs[^{]*\{([^}]*)\}', css):
        body = hit.group(1)
        for prop in ('width:', 'overflow-x:', 'min-width:'):
            assert prop not in body, f'页面又自己写了 tab 几何（{prop}），会脱离 kit 页面档'


def main():
    tests = [value for key, value in sorted(globals().items()) if key.startswith('test_')]
    failed = 0
    for test in tests:
        try:
            test()
            print(f'PASS  {test.__name__}')
        except AssertionError as exc:
            failed += 1
            print(f'FAIL  {test.__name__}: {exc}')
    print(f'\n{len(tests) - failed}/{len(tests)} passed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
