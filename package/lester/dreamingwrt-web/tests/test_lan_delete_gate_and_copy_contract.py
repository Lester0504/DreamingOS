#!/usr/bin/env python3
"""LAN 删除：判据写死 + 文案把「前端没接线」说成「后端没实现」。

用户看到的原话是「当前 Web API 尚未提供 LAN 删除路由，此操作不会伪造成成功。」——
这句话不成立。`DELETE /api/v1/network/lans/<id>` 一直存在：webd 里 `lan_delete`
字面量命中 1 次，core 里 5 次，且 core 还带 `lan_ports_attached` / `lan_delete_failed`
这类拒绝原因，说明它会真的执行并有裁定逻辑。

前端有两处写死，叠在一起让 LAN 完全没法删：

1. `const unavailable = !isWan` —— 只要是 LAN 就判「路由不存在」，按钮恒灰并配错误解释。
2. `deleteWan()` 第一行 `if (!isWan || ...) return` —— 就算点到了也静默返回，
   LAN 根本没有提交通路。ENDPOINT 本身早就按 kind 切到 /lans 了。

后果比单纯不可用更糟：用户据此认为无解，只能手改 /etc/config/network。

纯源码契约，不需要设备。
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JS_PATH = ROOT / "files/www/dreamingwrt/plugins/native/network-interface-config.js"
JS = JS_PATH.read_text()


def strip_comments(text: str) -> str:
    """注释里必须能提到旧文案（那是历史说明），所以断言一律对去注释后的源码做。"""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"^\s*//.*$", "", text, flags=re.M)


CODE = strip_comments(JS)


def test_false_backend_missing_copy_is_gone() -> None:
    assert "尚未提供 LAN 删除路由" not in CODE, (
        "又把「后端没有这条路由」写回去了；lan_delete 在 webd 与 core 里都存在"
    )
    assert "不会伪造成成功" not in CODE, "错误解释的残句还在"


def test_delete_gate_not_hardcoded_to_wan() -> None:
    assert "const unavailable = !isWan" not in CODE, "又按 isWan 写死可用性了"
    fn = re.search(r"function deleteConfirmationMarkup\(.*?\n  \}", CODE, re.S)
    assert fn, "找不到 deleteConfirmationMarkup"
    body = fn.group(0)
    assert not re.search(r"canDelete\s*=\s*isWan\s*&&", body), (
        "canDelete 又加回了 isWan 限制，非默认 LAN 的删除按钮会恒灰"
    )


def test_default_lan_still_protected() -> None:
    """管理网络不该从此页删掉，这一支的保护是对的，不能连带放开。"""
    fn = re.search(r"function deleteConfirmationMarkup\(.*?\n  \}", CODE, re.S)
    assert fn, "找不到 deleteConfirmationMarkup"
    body = fn.group(0)
    assert "protectedLan" in body, "默认 lan 的保护丢了"
    assert re.search(r"protectedLan\s*=\s*!isWan\s*&&\s*row\.id\s*===\s*'lan'", body), (
        "默认 lan 的判据被改动了"
    )
    assert "默认 LAN 是当前管理网络" in body, "默认 lan 被拒的理由文案丢了"


def test_last_wan_still_protected() -> None:
    fn = re.search(r"function deleteConfirmationMarkup\(.*?\n  \}", CODE, re.S)
    assert fn and "lastWan" in fn.group(0), "至少保留一条 WAN 的约束丢了"


def test_submit_path_accepts_lan() -> None:
    """按钮可点还不够：原先 deleteWan() 第一行就把 LAN 挡在门外。"""
    assert "deleteWan" not in CODE, "仍有 WAN 专用的删除函数名，LAN 走不进来"
    fn = re.search(r"async function deleteRow\(.*?\n  \}", CODE, re.S)
    assert fn, "找不到 deleteRow"
    body = fn.group(0)
    assert not re.search(r"if\s*\(\s*!isWan\s*\|\|", body), (
        "删除入口又用 !isWan 短路，LAN 点了也没反应"
    )
    assert "state.selectedId === 'lan'" in body, "提交路径里默认 lan 的保护丢了"
    assert re.search(r"isWan\s*&&\s*state\.rows\.length\s*<=\s*1", body), (
        "提交路径里「至少留一条 WAN」的保护丢了"
    )
    assert "method: 'DELETE'" in body, "没有真的发 DELETE"


def test_delete_uses_kind_aware_endpoint() -> None:
    assert re.search(
        r"const ENDPOINT = `/api/v1/network/\$\{isWan \? 'wans' : 'lans'\}`", CODE
    ), "ENDPOINT 不再按 kind 切换，LAN 会打到 WAN 的路由上"


def test_confirm_accept_calls_delete() -> None:
    assert "deleteRow()" in CODE, "确认按钮没有接到删除动作"


def test_backend_reject_reason_is_translated() -> None:
    """被拒时要显示真实原因，而不是 lan_ports_attached 这种裸字面量。"""
    assert "DELETE_ERROR_TEXT" in CODE, "缺少删除错误码的翻译表"
    assert "lan_ports_attached" in CODE, "没有覆盖 core 实际会回的 lan_ports_attached"
    table = re.search(r"DELETE_ERROR_TEXT = \{.*?\n  \};", CODE, re.S)
    assert table, "找不到翻译表"
    assert "物理端口" in table.group(0), "lan_ports_attached 没有翻成可操作的说明"
    assert "deleteErrorText" in CODE, "翻译表没有被使用"


"""jmx_netconfig_lan_delete_result() 的 switch 全集（jmx_netconfig_db.c:15825-15835），
外加 default 兜底的 lan_delete_failed。这套字面量同时也是 lans[] 上
delete_blocked_reason 的取值（nc_lan_delete_block_reason()，同文件 :4468）。"""
BACKEND_DELETE_CODES = (
    "not_found",
    "protected_management_lan",
    "last_enabled_lan",
    "lan_ports_attached",
    "child_lans_attached",
    "ipam_network_attached",
    "management_reachability_risk",
    "snapshot_failed",
    "lan_delete_failed",
)

"""后端从来不返回这两个码——真实取值是 not_found 与 protected_management_lan。
30.1 上的 dreamingwrt-core 里这两个字面量连子串都匹配不到（对照组：not_found 命中
25 次、snapshot_failed 7 次）。写回来就是永不命中的死键。"""
PHANTOM_DELETE_CODES = ("lan_not_found", "lan_is_default")


def _delete_error_table() -> str:
    table = re.search(r"DELETE_ERROR_TEXT = \{.*?\n  \};", CODE, re.S)
    assert table, "找不到翻译表"
    return table.group(0)


def test_no_phantom_delete_codes() -> None:
    """死键回归防线：这两个键存在会让人以为默认 lan / 找不到的情况已经有文案了。"""
    table = _delete_error_table()
    for code in PHANTOM_DELETE_CODES:
        assert code not in table, (
            f"{code} 又被写回翻译表；后端从不返回它，"
            "真实的码是 not_found / protected_management_lan"
        )


def test_delete_table_covers_every_backend_code() -> None:
    """后端 switch 里每个码都要有中文文案，否则该场景会把裸字面量透给用户。"""
    table = _delete_error_table()
    keys = set(re.findall(r"^\s{4}([a-z_]+):", table, re.M))
    missing = [code for code in BACKEND_DELETE_CODES if code not in keys]
    assert not missing, f"这些后端会返回的码没有文案：{', '.join(missing)}"


def test_delete_table_has_no_unknown_keys() -> None:
    """反向约束：表里不该有后端不存在的码，那种键只会掩盖真实缺口。"""
    table = _delete_error_table()
    keys = set(re.findall(r"^\s{4}([a-z_]+):", table, re.M))
    extra = sorted(keys - set(BACKEND_DELETE_CODES))
    assert not extra, f"翻译表里有后端不返回的码：{', '.join(extra)}"


def test_generic_not_found_is_matched_on_word_boundary() -> None:
    """not_found 是通用词。message 兜底若用裸 includes()，wan_not_found 也会被
    翻成 LAN 的文案。"""
    fn = re.search(r"function deleteErrorText\(.*?\n  \}", CODE, re.S)
    assert fn, "找不到 deleteErrorText"
    body = fn.group(0)
    assert "message.includes(key)" not in body, (
        "message 兜底又退回裸 includes()，通用码 not_found 会误命中 wan_not_found"
    )
    assert re.search(r"\\\\b\$\{key\}\\\\b", body), "message 兜底没有按词边界匹配"


def test_error_code_is_carried_on_error_object() -> None:
    """翻译表要能拿到码。requestJson 原先只填 message/details，不填 code，
    那样翻译表永远命中不了，等于死代码。"""
    fn = re.search(r"async function requestJson\(.*?\n  \}", CODE, re.S)
    assert fn, "找不到 requestJson"
    assert "error.code" in fn.group(0), "错误对象上没有带 code，翻译表拿不到错误码"


def test_failed_delete_closes_confirmation_so_notice_can_render() -> None:
    """删除被拒的原因必须真的显示出来。页面级提示的渲染条件是 `!state.drawer`，而删除
    确认卡不是 sheet（patchDrawerContents 找不到 .network-interface-drawer 会退回
    render），所以失败时若不收掉 drawer，提示两处都落不下来 —— 浏览器实测确认过：
    DELETE 发出、后端回 lan_ports_attached，而页面上既无裸码也无中文解释。"""
    fn = re.search(r"async function deleteRow\(.*?\n  \}", CODE, re.S)
    assert fn, "找不到 deleteRow"
    body = fn.group(0)
    catch = body[body.index("catch"):]
    assert "state.drawer = ''" in catch, (
        "删除失败时没有收掉确认卡，被拒原因无处渲染"
    )
    assert "render()" in catch, "失败分支没有重绘"


def test_validation_message_prefers_translated_text() -> None:
    fn = re.search(r"function validationMessage\(.*?\n  \}", CODE, re.S)
    assert fn, "找不到 validationMessage"
    assert "deleteErrorText" in fn.group(0), "被拒原因没有走翻译"


def main() -> int:
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {name}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
