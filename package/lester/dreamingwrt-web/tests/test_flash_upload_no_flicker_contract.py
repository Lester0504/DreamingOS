"""固件上传与校验期间不得整页重绘。

用户 2026-08-04：「备份/升级页面上传固件过程中整个页面闪烁」。

真因是两处按拍调用整页 `render()`：

1. `uploadStagedFile()` 每传完一个 2MiB 分片就 `render()` 一次。
2. 校验状态轮询 3s 一拍，每拍也 `render()` 一次。

`render()` 会重写整个 `system-settings-layout` 的 innerHTML，再 `ui.mountAll()`
重挂所有 kit 组件、`scheduleGlassCardsRender()` 重跑玻璃采样。实测一个 12MB 镜像
（5 个分片 + 4 拍轮询）整页重建 **12 次**；改成局部更新后是 **3 次**，
且三次间隔都在 800ms 以上，都是真实的阶段切换。

进度唯一的可见落点是暂存按钮的文字，校验状态唯一的落点是「本次升级校验」那张卡，
所以这两处各自局部更新即可。
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "files/www/dreamingwrt/plugins/native/system-settings.js").read_text(encoding="utf-8")


def block(start: str, end: str) -> str:
    return JS[JS.index(start):JS.index(end)]


def test_chunk_loop_does_not_rebuild_the_page() -> None:
    loop = block("async function uploadStagedFile(", "function flashOperationFromResponse(")
    assert "updateFlashProgressLabel()" in loop, (
        "分片进度只能局部更新按钮文字"
    )
    assert not re.search(r"^\s*render\(\);", loop, re.M), (
        "分片循环里不得整页 render()：一个几十 MB 的镜像会连续重建几十次，就是用户看到的闪烁"
    )


def test_progress_label_helper_only_touches_text() -> None:
    helper = block("function updateFlashProgressLabel(", "function systemFlashStageButtonLabel(")
    assert "data-system-action=\"flash-upload-verify\"" in helper, "要按稳定钩子定位按钮"
    assert "textContent" in helper, "只写文字"
    for forbidden in ("innerHTML", "mountAll", "scheduleGlassCardsRender"):
        assert forbidden not in helper, f"局部更新不得触发 {forbidden}"


def test_verify_polling_patches_only_the_operation_card() -> None:
    poll = block("function startFlashOperationPolling(", "async function applyFirmwareOperation(")
    assert "patchFlashOperationCard()" in poll, "非终态只换校验卡"
    assert "isFlashOperationTerminal" in poll, "终态才走完整 render()"
    # 终态那一次整页重绘是有意保留的：按钮解禁与能力提示要一并收敛。
    assert "if (terminal) render();" in poll


def test_operation_card_patch_is_scoped_and_focus_safe() -> None:
    patch = block("function patchFlashOperationCard(", "function systemSignatureUpdateCard(")
    assert ".system-flash-firmware-operation" in patch, "要用稳定容器定位"
    assert "document.activeElement" in patch, (
        "焦点在卡内（例如「应用固件」按钮）时不能替换，否则打断用户操作"
    )
    assert "replaceWith" in patch and "mountAll?.(next)" in patch, (
        "替换后只对新节点重挂 kit，不做全局挂载"
    )


def test_upload_to_verify_transition_is_not_a_second_rebuild() -> None:
    fn = block("async function uploadAndVerifyFirmware(", "function flashRequestErrorText(")
    transition = fn[fn.index("state.flashWorking = 'firmware-verify';"):]
    transition = transition[: transition.index("try {")]
    assert "updateFlashProgressLabel()" in transition, (
        "转入校验只改按钮文字：verify 返回快时它和 finally 里那次 render() 只隔 7ms，"
        "肉眼是一次明显抖动"
    )
    assert "render()" not in transition


for name, value in sorted(globals().items()):
    if name.startswith("test_") and callable(value):
        value()

print("ok: firmware upload and verify update in place instead of rebuilding the page")
