#!/usr/bin/env python3
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "k_json.c").read_text()
HEADER = (ROOT / "src" / "k_json.h").read_text()


def test_parser_has_all_hard_budgets() -> None:
    for name in (
        "CJSON_PARSE_MAX_DEPTH",
        "CJSON_PARSE_MAX_NODES",
        "CJSON_PARSE_MAX_STRING",
        "CJSON_PARSE_MAX_TOTAL_ALLOC",
    ):
        assert re.search(rf"#define\s+{name}\s+", HEADER)
        assert name in SOURCE
    assert "struct cjson_parse_ctx" in SOURCE
    assert "ctx->depth >= CJSON_PARSE_MAX_DEPTH" in SOURCE
    assert "ctx->nodes >= CJSON_PARSE_MAX_NODES" in SOURCE
    assert "total > CJSON_PARSE_MAX_TOTAL_ALLOC" in SOURCE


def test_oom_and_format_string_contracts() -> None:
    assert "resized = cJSON_realloc" in SOURCE
    assert "buffer->data = resized" in SOURCE
    assert "sprintf(" not in SOURCE
    assert "snprintf(" not in SOURCE
    assert "printbuf_append" in SOURCE
    assert "if (!item)" in SOURCE
    assert "cJSON_Delete(array);" in SOURCE


def test_parser_runtime_limits_and_round_trip() -> None:
    fixture = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/slab.h>
#include "k_json.h"

long test_alloc_count;
long test_fail_at;
long test_live_allocs;

static int check(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        return 0;
    }
    return 1;
}

int main(void)
{
    cJSON *root;
    char *printed;
    char *deep;
    char *wide;
    char *long_string;
    char *allocation_heavy;
    size_t i;

    test_alloc_count = 0;
    test_fail_at = 0;
    test_live_allocs = 0;

    root = cJSON_Parse("{\"percent%key\":\"100% safe\",\"a\":[1,-2147483648,2147483647]}");
    if (!check(root != NULL, "valid document rejected")) return 1;
    printed = cJSON_Print(root);
    if (!check(printed != NULL, "print failed")) return 1;
    if (!check(strstr(printed, "percent%key") && strstr(printed, "100% safe"),
               "percent data corrupted")) return 1;
    kfree(printed);
    cJSON_Delete(root);
    if (!check(test_live_allocs == 0, "round-trip allocation leak")) return 1;

    deep = calloc(CJSON_PARSE_MAX_DEPTH + 3, 2);
    for (i = 0; i < CJSON_PARSE_MAX_DEPTH + 1; i++) deep[i] = '[';
    deep[CJSON_PARSE_MAX_DEPTH + 1] = '0';
    for (i = 0; i < CJSON_PARSE_MAX_DEPTH + 1; i++)
        deep[CJSON_PARSE_MAX_DEPTH + 2 + i] = ']';
    if (!check(cJSON_Parse(deep) == NULL, "depth budget not enforced")) return 1;
    free(deep);
    if (!check(test_live_allocs == 0, "depth failure allocation leak")) return 1;

    wide = malloc((CJSON_PARSE_MAX_NODES + 2) * 2 + 2);
    wide[0] = '[';
    for (i = 0; i < CJSON_PARSE_MAX_NODES + 1; i++) {
        wide[1 + i * 2] = '0';
        wide[2 + i * 2] = ',';
    }
    wide[2 + CJSON_PARSE_MAX_NODES * 2] = ']';
    wide[3 + CJSON_PARSE_MAX_NODES * 2] = '\0';
    if (!check(cJSON_Parse(wide) == NULL, "node budget not enforced")) return 1;
    free(wide);
    if (!check(test_live_allocs == 0, "node failure allocation leak")) return 1;

    long_string = malloc(CJSON_PARSE_MAX_STRING + 4);
    long_string[0] = '"';
    memset(long_string + 1, 'x', CJSON_PARSE_MAX_STRING + 1);
    long_string[CJSON_PARSE_MAX_STRING + 2] = '"';
    long_string[CJSON_PARSE_MAX_STRING + 3] = '\0';
    if (!check(cJSON_Parse(long_string) == NULL, "string budget not enforced")) return 1;
    free(long_string);
    if (!check(test_live_allocs == 0, "string failure allocation leak")) return 1;

    allocation_heavy = malloc(9 * 60000 + 32);
    allocation_heavy[0] = '[';
    deep = allocation_heavy + 1;
    for (i = 0; i < 9; i++) {
        *deep++ = '"';
        memset(deep, 'a', 60000);
        deep += 60000;
        *deep++ = '"';
        *deep++ = i == 8 ? ']' : ',';
    }
    *deep = '\0';
    if (!check(cJSON_Parse(allocation_heavy) == NULL,
               "total allocation budget not enforced")) return 1;
    free(allocation_heavy);
    if (!check(test_live_allocs == 0, "allocation budget failure leak")) return 1;

    if (!check(cJSON_Parse("{\"x\":1} trailing") == NULL, "trailing data accepted")) return 1;
    if (!check(cJSON_Parse("{\"x\":\"\\u12xz\"}") == NULL, "bad unicode accepted")) return 1;
    if (!check(cJSON_Parse("{\"x\":\"\\ud800\"}") == NULL,
               "isolated high surrogate accepted")) return 1;
    if (!check(cJSON_Parse("{\"x\":\"\\udc00\"}") == NULL,
               "isolated low surrogate accepted")) return 1;
    root = cJSON_Parse("{\"x\":\"\\ud83d\\ude00\"}");
    if (!check(root != NULL, "valid surrogate pair rejected")) return 1;
    printed = cJSON_Print(root);
    if (!check(printed && strstr(printed, "\xf0\x9f\x98\x80"),
               "surrogate pair was not encoded as UTF-8")) return 1;
    kfree(printed);
    cJSON_Delete(root);
    if (!check(cJSON_Parse("{\"x\":\"" "\xc0\x80" "\"}") == NULL,
               "overlong UTF-8 accepted")) return 1;
    if (!check(cJSON_Parse("{\"x\":\"" "\xf4\x90\x80\x80" "\"}") == NULL,
               "out-of-range UTF-8 accepted")) return 1;
    if (!check(cJSON_Parse("2147483648") == NULL, "integer overflow accepted")) return 1;
    if (!check(test_live_allocs == 0, "malformed input allocation leak")) return 1;

    for (i = 1; i <= 16; i++) {
        test_alloc_count = 0;
        test_fail_at = (long)i;
        root = cJSON_Parse("{\"one\":[1,2,3],\"two\":\"value\"}");
        cJSON_Delete(root);
        if (!check(test_live_allocs == 0, "parse OOM allocation leak")) return 1;
    }
    test_fail_at = 0;
    root = cJSON_Parse("{\"percent%key\":\"100% safe\",\"a\":[1,2,3]}");
    if (!check(root != NULL, "OOM fixture parse setup failed")) return 1;
    for (i = 1; i <= 12; i++) {
        test_alloc_count = 0;
        test_fail_at = (long)i;
        printed = cJSON_Print(root);
        kfree(printed);
        if (!check(test_live_allocs > 0, "parse tree unexpectedly lost")) return 1;
    }
    cJSON_Delete(root);
    if (!check(test_live_allocs == 0, "print OOM allocation leak")) return 1;

    for (i = 1; i <= 8; i++) {
        int values[] = { 1, 2, 3, 4 };
        test_alloc_count = 0;
        test_fail_at = (long)i;
        root = cJSON_CreateIntArray(values, 4);
        cJSON_Delete(root);
        if (!check(test_live_allocs == 0, "constructor OOM allocation leak")) return 1;
    }
    for (i = 1; i <= 10; i++) {
        const char *values[] = { "one", "two", "three" };
        test_alloc_count = 0;
        test_fail_at = (long)i;
        root = cJSON_CreateStringArray(values, 3);
        cJSON_Delete(root);
        if (!check(test_live_allocs == 0, "string constructor OOM allocation leak")) return 1;
    }
    test_fail_at = 0;
    root = cJSON_CreateObject();
    printed = (char *)cJSON_CreateString("owned item");
    if (!check(root && printed, "object ownership fixture setup failed")) return 1;
    test_alloc_count = 0;
    test_fail_at = 1;
    cJSON_AddItemToObject(root, "key", (cJSON *)printed);
    if (!check(root->child == NULL, "key OOM attached an invalid item")) return 1;
    cJSON_Delete(root);
    if (!check(test_live_allocs == 0, "object key OOM allocation leak")) return 1;
    test_fail_at = 0;
    root = cJSON_CreateString("owned array item");
    if (!check(root != NULL, "array ownership fixture setup failed")) return 1;
    cJSON_AddItemToArray(NULL, root);
    if (!check(test_live_allocs == 0, "null array allocation leak")) return 1;
    test_fail_at = 0;
    puts("ok: k_json defensive runtime fixture passed");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="k-json-defensive-") as tmp:
        tmp_path = Path(tmp)
        compat = tmp_path / "compat" / "linux"
        compat.mkdir(parents=True)
        (compat / "module.h").write_text("#pragma once\n")
        (compat / "types.h").write_text(
            "#pragma once\n#include <stdbool.h>\n#include <stddef.h>\n"
        )
        (compat / "string.h").write_text("#pragma once\n#include <string.h>\n#include <strings.h>\n")
        (compat / "slab.h").write_text(
            "#pragma once\n#include <stdlib.h>\n"
            "#define GFP_KERNEL 0\n"
            "extern long test_alloc_count;\nextern long test_fail_at;\nextern long test_live_allocs;\n"
            "static inline int test_should_fail(void) {\n"
            "  test_alloc_count++; return test_fail_at > 0 && test_alloc_count == test_fail_at;\n}\n"
            "static inline void *kmalloc(size_t n, int f) { void *p; (void)f;\n"
            "  if (test_should_fail()) { return NULL; }\n"
            "  p = malloc(n);\n"
            "  if (p) { test_live_allocs++; }\n"
            "  return p;\n}\n"
            "static inline void *krealloc(void *p, size_t n, int f) { void *q; (void)f;\n"
            "  if (test_should_fail()) { return NULL; }\n"
            "  q = realloc(p,n);\n"
            "  if (q && !p) { test_live_allocs++; }\n"
            "  return q;\n}\n"
            "static inline void kfree(void *p) {\n"
            "  if (p) { test_live_allocs--; }\n"
            "  free(p);\n}\n"
        )
        fixture_path = tmp_path / "fixture.c"
        fixture_path.write_text(fixture)
        binary = tmp_path / "fixture"
        subprocess.run(
            [
                "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-Wformat=2", "-Werror=format-security",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(tmp_path / "compat"), "-I", str(ROOT / "src"),
                str(fixture_path), str(ROOT / "src" / "k_json.c"),
                "-o", str(binary),
            ],
            check=True,
            cwd=ROOT,
        )
        completed = subprocess.run([str(binary)], text=True, capture_output=True)
        if completed.returncode:
            raise AssertionError(
                f"fixture failed ({completed.returncode})\n"
                f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
            )
        assert completed.stdout.strip() == "ok: k_json defensive runtime fixture passed"


if __name__ == "__main__":
    test_parser_has_all_hard_budgets()
    test_oom_and_format_string_contracts()
    test_parser_runtime_limits_and_round_trip()
    print("ok: k_json defensive contract passed")
