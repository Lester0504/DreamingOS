#!/usr/bin/env python3
"""页面插件必须经会话闸门发请求，不得裸 fetch。

背景（Acceptance-to-Front-ui-batch-20260802.md 第 6 条）：通知推送页进入时报
「部分数据读取失败：unauthorized · unauthorized · ...」六连，切到仪表盘再回来就好了。
根因是插件自己写了一份 requestJson，裸 fetch 直接从 localStorage 取 access token，
完全绕开 DWRT_SESSION：token 过期时既不刷新也不重试，六个并发请求全部拿 401；
切走时走闸门的页面刷新了 token，所以再切回来就正常。

这条测试锁住两件事：闸门暴露了共享传输入口，且没有任何插件再直接调用裸 fetch。
"""
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WWW = ROOT / "files/www/dreamingwrt"
GATE = (WWW / "static/js/dwrt-session-gate.js").read_text(encoding="utf-8")
PLUGINS = sorted((WWW / "plugins/native").glob("*.js"))

# 闸门必须暴露共享入口，且内部走 DWRT_SESSION.fetch（它已处理 refresh 与单次重试）
assert "window.DWRT_REQUEST" in GATE
assert "function sessionFetch(" in GATE
assert "function sessionRequestJson(" in GATE
assert "gate.fetch(requestUrl, init)" in GATE
assert "gate ? gate.fetch(url, init) : fetch(url, init)" in GATE

# 裸 fetch( 调用：排除成员调用（api.fetch / window.fetch / gate.fetch）
BARE_FETCH = re.compile(r"(?<![\w.])fetch\(")
ADAPTER_FALLBACK = "window.DWRT_REQUEST ? window.DWRT_REQUEST.fetch(url, init) : fetch(url, init)"

offenders = []
missing_adapter = []
for plugin in PLUGINS:
    source = plugin.read_text(encoding="utf-8")
    # 适配器自身的兜底分支是唯一允许的裸 fetch
    stripped = source.replace(ADAPTER_FALLBACK, "")
    hits = BARE_FETCH.findall(stripped)
    if hits:
        offenders.append((plugin.name, len(hits)))
    # 有网络请求的插件必须持有适配器
    if "sessionFetch(" in source and "function sessionFetch(" not in source:
        missing_adapter.append(plugin.name)

assert not offenders, f"这些插件仍在裸 fetch，会绕过 token 刷新：{offenders}"
assert not missing_adapter, f"这些插件调用了 sessionFetch 但没有定义适配器：{missing_adapter}"

# 适配器必须定义在 mount 作用域内，否则拿不到闭包也无法被插件复用
for plugin in PLUGINS:
    source = plugin.read_text(encoding="utf-8")
    if "function sessionFetch(" not in source:
        continue
    adapter_at = source.index("function sessionFetch(")
    mount = re.search(r"export function mount\(", source)
    assert mount, plugin.name
    assert mount.start() < adapter_at, f"{plugin.name}: 适配器落在了 mount 作用域之外"

patched = [p.name for p in PLUGINS if "function sessionFetch(" in p.read_text(encoding="utf-8")]
assert len(patched) >= 30, f"预期至少 30 个插件接入闸门，实际 {len(patched)}"

print(f"ok: {len(patched)} plugins route through the session gate, no bare fetch left")
