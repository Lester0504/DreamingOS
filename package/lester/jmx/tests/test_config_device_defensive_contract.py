#!/usr/bin/env python3
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "jmx_config.c").read_text()


def function_body(name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", SOURCE, re.DOTALL)
    assert match, f"function {name} not found"

    start = match.end() - 1
    depth = 0
    for index in range(start, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start + 1 : index]
    raise AssertionError(f"unterminated function {name}")


def test_write_reserves_nul_byte() -> None:
    body = function_body("jmx_cdev_write")
    assert "count > sizeof(file->buf) - file->size - 1" in body
    assert "file->size + count > sizeof(file->buf)" not in body
    assert "file->buf[file->size] = '\\0';" in body


def test_api_is_strictly_a_string() -> None:
    body = function_body("jmx_config_handle")
    root_validation = body.index("config_obj->type != cJSON_Object")
    validation = body.index("api_obj->type != cJSON_String")
    dereference = body.index("api_obj->valuestring", validation)
    dispatch = body.index("strcmp(req_item->api, api_obj->valuestring)")
    assert root_validation < validation < dereference < dispatch
    assert "!api_obj->valuestring" in body


def test_capability_is_checked_at_open_and_commit() -> None:
    open_body = function_body("jmx_cdev_open")
    release_body = function_body("jmx_cdev_release")
    assert "capable(CAP_NET_ADMIN)" in open_body
    assert "capable(CAP_NET_ADMIN)" in release_body
    assert release_body.index("capable(CAP_NET_ADMIN)") < release_body.index(
        "jmx_config_handle(file->buf, file->size)"
    )


def test_mutex_is_scoped_to_commit() -> None:
    open_body = function_body("jmx_cdev_open")
    write_body = function_body("jmx_cdev_write")
    release_body = function_body("jmx_cdev_release")

    assert "mutex_lock" not in open_body
    assert "mutex_unlock" not in open_body
    assert "mutex_lock" not in write_body
    assert "mutex_unlock" not in write_body

    lock = release_body.index("mutex_lock(&jmx_cdev_mutex);")
    commit = release_body.index("jmx_config_handle(file->buf, file->size);")
    unlock = release_body.index("mutex_unlock(&jmx_cdev_mutex);")
    assert lock < commit < unlock
    assert release_body.count("mutex_lock(&jmx_cdev_mutex);") == 1
    assert release_body.count("mutex_unlock(&jmx_cdev_mutex);") == 1


if __name__ == "__main__":
    test_write_reserves_nul_byte()
    test_api_is_strictly_a_string()
    test_capability_is_checked_at_open_and_commit()
    test_mutex_is_scoped_to_commit()
    print("ok: /dev/jmx defensive contract passed")
