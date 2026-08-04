"""抽屉被搬进 portal 之后，重复 mount 不得把它当孤儿销毁。

用户 2026-08-04：「新建限速的抽屉不稳定，点击后可以打开，但马上会消失，
认证与管控涉及到抽屉的几乎全部由这个问题」。

真因在共享 kit，不在页面模块：`mountSheet()` 会把抽屉搬到 body 级的
`dwrtKitSheetPortal`，而 `reclaimStaleSheets(context)` 原本的孤儿判据是

    if (!home || !home.isConnected || home === host || host?.contains(home)) disposeSheet(node);

`home` 是抽屉搬迁前的原父节点，仍在 route host 里。于是抽屉一被搬走，
**此后任何一次 `mountAll(root)` 都满足 `host.contains(home)`**，抽屉立刻被销毁。
实测：打开抽屉后手工调一次 `mountAll(root)`，`.dwrt-kit-sheet` 从 1 变 0。
页面模块每次刷新都会 mount，所以表现就是抽屉一闪即消。

修法是区分两种情况：宿主内容被重绘（真孤儿，该回收）与单纯的重复 mount
（抽屉仍有效）。搬迁时记下宿主里的一个存活探针，它还在原位就说明宿主没被重绘。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KIT = (ROOT / "files/www/dreamingwrt/static/ui-kit/dwrt-ui-kit.js").read_text(encoding="utf-8")

reclaim = KIT[KIT.index("function reclaimStaleSheets("):KIT.index("function watchSheetPortal(")]

# 旧判据必须消失：只要 host 包含 home 就销毁，会误杀刚打开的抽屉。
assert not re.search(
    r"if \(!home \|\| !home\.isConnected \|\| home === host \|\| host\?\.contains\(home\)\) disposeSheet",
    reclaim,
), "这条判据分不清「宿主被重绘」和「抽屉刚搬走」，会让抽屉一闪即消"

# 宿主脱离文档仍然要回收，否则 portal 会泄漏。
assert "!home.isConnected" in reclaim and "disposeSheet(node)" in reclaim, (
    "宿主已脱离文档的抽屉必须回收，不能因为怕误杀就不清理"
)

# 存活探针：搬迁时记下，回收时校验。
assert "hostAnchor" in reclaim, "回收判据要靠存活探针区分重绘与重复 mount"
elevate = KIT[KIT.index("function elevateSheet("):KIT.index("function restoreSheetHome(")]
assert re.search(r"\bhostAnchor:\s*\(", elevate), (
    "搬迁时必须把探针写进 state.portalHome，只在回收侧读它是读不到东西的"
)
assert "child !== sheet && child !== overlay" in elevate, (
    "探针要取宿主里除抽屉与遮罩之外的子节点，否则它会跟着抽屉一起被搬走"
)

# 探针还在原位就不许销毁。
assert re.search(r"anchor\.isConnected && anchor\.parentElement === home", reclaim), (
    "探针仍在原位说明宿主没被重绘，抽屉必须留下"
)

print("ok: portaled sheets survive a repeat mount, and true orphans are still reclaimed")
