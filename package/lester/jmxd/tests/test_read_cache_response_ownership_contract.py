#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/jmx_dreamingwrt_api.c").read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    marker = f"static int {name}("
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0

    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:index + 1]
    raise AssertionError(f"unterminated function: {name}")


def test_cache_miss_payload_ownership_moves_to_response() -> None:
    body = function_body(SOURCE, "dw_handle_read_cached")
    ownership = body.index(
        "out = jmx_gen_api_response_data(API_CODE_SUCCESS, data);"
    )
    reply = body.index("dw_send_json(ctx, req, out);", ownership)

    assert "json_object_put(data);" not in body[ownership:reply]
    assert "json_object_put(out);" in body[reply:]


if __name__ == "__main__":
    test_cache_miss_payload_ownership_moves_to_response()
    print("ok: read-cache miss response keeps transferred JSON ownership")
