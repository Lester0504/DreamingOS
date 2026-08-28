from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
JS = (
    ROOT / "files/www/dreamingwrt/static/js/insights-flows.js"
).read_text(encoding="utf-8")


def audit_poll_is_stable(source: str) -> bool:
    return all(
        marker in source
        for marker in (
            "renderAuditPoll();",
            "function render(target)",
            "preserve(state.root, render);",
            "restoreUiScrollState(scrollState);",
            "bindDom(preservedInput, target);",
        )
    )


assert audit_poll_is_stable(JS), (
    "URL 审计轮询必须通过 Kit morph 到现有路由，保留滚动容器、焦点和选区身份"
)
assert "state.audit.loading = false;\n        render();" not in JS, (
    "审计轮询不得退回整树 render()"
)

# 反向验证：把轮询入口退回原来的整树 render() 后，本测试判据必须转红。
REGRESSION = JS.replace("renderAuditPoll();", "render();", 1)
assert not audit_poll_is_stable(REGRESSION), "反向验证失效：整树重绘未被探针识别"

print("ok: insights audit polling preserves route DOM identity; reverse render regression fails")
