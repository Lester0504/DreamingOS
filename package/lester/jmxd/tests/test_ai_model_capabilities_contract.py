import json
import os
import pathlib
import shlex
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
AI_RUNTIME_SOURCE = ROOT / "src" / "webd" / "ai_runtime.c"
NETCONFIG_SOURCE = ROOT / "src" / "jmx_netconfig_db.c"


def extract_c_function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening_brace = source.index("{", start + len(signature))
    depth = 0
    for index in range(opening_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise ValueError(f"unterminated C function: {signature}")


def production_functions() -> str:
    runtime_source = AI_RUNTIME_SOURCE.read_text(encoding="utf-8")
    netconfig_source = NETCONFIG_SOURCE.read_text(encoding="utf-8")
    signatures = (
        "static struct json_object *ai_model_explicit_value(",
        "static int ai_model_modalities_has(",
        "static void ai_model_add_nullable_bool(",
        "static struct json_object *ai_model_detail(",
    )
    functions = [extract_c_function(runtime_source, signature) for signature in signatures]
    functions.append(
        extract_c_function(
            netconfig_source, "struct json_object *jmx_ai_models_get(void)"
        )
    )
    return "\n\n".join(functions)


HARNESS_PREFIX = r'''
#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define API_CODE_SUCCESS 0

static int64_t nc_now_s(void)
{
    return INT64_C(1700000000);
}

static struct json_object *jmx_gen_api_response_data(int code,
                                                     struct json_object *data)
{
    struct json_object *response = json_object_new_object();
    json_object_object_add(response, "code", json_object_new_int(code));
    json_object_object_add(response, "data", data);
    return response;
}
'''


HARNESS_SUFFIX = r'''
static int print_json(struct json_object *object)
{
    const char *serialized;

    if (!object)
        return 1;
    serialized = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
    if (!serialized)
        return 1;
    puts(serialized);
    return 0;
}

int main(int argc, char **argv)
{
    struct json_object *result = NULL;
    int rc;

    if (argc == 2 && !strcmp(argv[1], "static")) {
        result = jmx_ai_models_get();
    } else if (argc == 4 && !strcmp(argv[1], "normalize")) {
        struct json_object *item = json_tokener_parse(argv[2]);
        if (!item || !json_object_is_type(item, json_type_object)) {
            if (item)
                json_object_put(item);
            fprintf(stderr, "provider item must be a JSON object\n");
            return 2;
        }
        result = ai_model_detail(item, argv[3]);
        json_object_put(item);
    } else {
        fprintf(stderr, "usage: %s static | normalize ITEM ID\n", argv[0]);
        return 2;
    }

    rc = print_json(result);
    if (result)
        json_object_put(result);
    return rc;
}
'''


def json_c_flags() -> tuple[list[str], dict[str, str]]:
    env = os.environ.copy()
    candidates: list[pathlib.Path] = []
    configured_prefix = env.get("JSON_C_PREFIX")
    if configured_prefix:
        candidates.append(pathlib.Path(configured_prefix))

    try:
        candidates.append(
            pathlib.Path(
                subprocess.check_output(
                    ["brew", "--prefix", "json-c"], text=True, stderr=subprocess.DEVNULL
                ).strip()
            )
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    candidates.extend(
        pathlib.Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c").glob("*")
    )
    for ancestor in (ROOT, *ROOT.parents):
        candidates.append(ancestor / "staging_dir" / "host")

    for prefix in candidates:
        header = prefix / "include" / "json-c" / "json.h"
        libraries = (
            prefix / "lib" / "libjson-c.a",
            prefix / "lib" / "libjson-c.dylib",
            prefix / "lib" / "libjson-c.so",
        )
        library = next((candidate for candidate in libraries if candidate.is_file()), None)
        if header.is_file() and library:
            return [f"-I{prefix / 'include'}", str(library)], env

    try:
        output = subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "json-c"], text=True, env=env
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        raise RuntimeError("json-c development files are required") from error
    return shlex.split(output), env


class AiModelCapabilitiesContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        flags, cls.env = json_c_flags()
        cls.tempdir = tempfile.TemporaryDirectory(prefix="ai-model-capabilities-")
        temp_path = pathlib.Path(cls.tempdir.name)
        source_path = temp_path / "contract.c"
        cls.executable = temp_path / "contract"
        source_path.write_text(
            HARNESS_PREFIX + "\n" + production_functions() + "\n" + HARNESS_SUFFIX,
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c11",
                "-Wall",
                "-Wextra",
                str(source_path),
                *flags,
                "-lm",
                "-o",
                str(cls.executable),
            ],
            text=True,
            capture_output=True,
            env=cls.env,
        )
        if result.returncode != 0:
            raise AssertionError(f"harness compilation failed:\n{result.stderr}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tempdir.cleanup()

    def run_harness(self, *arguments: str) -> dict:
        result = subprocess.run(
            [str(self.executable), *arguments],
            text=True,
            capture_output=True,
            env=self.env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def normalize(self, item: dict, model_id: str = "controlled-model") -> dict:
        return self.run_harness(
            "normalize", json.dumps(item, separators=(",", ":")), model_id
        )

    def test_provider_explicit_support_is_preserved(self) -> None:
        detail = self.normalize(
            {
                "vision": True,
                "capabilities": {
                    "file_input": 1,
                    "tool_calling": True,
                    "streaming": 1,
                    "context_length": 131072,
                },
            },
            "provider-supported",
        )

        self.assertEqual(detail["id"], "provider-supported")
        self.assertIs(detail["vision"], True)
        self.assertIs(detail["file_input"], True)
        self.assertIs(detail["tool_calling"], True)
        self.assertIs(detail["streaming"], True)
        self.assertEqual(detail["context_window"], 131072)
        self.assertEqual(detail["capability_source"], "provider_metadata")

    def test_provider_explicit_non_support_is_not_overridden(self) -> None:
        detail = self.normalize(
            {
                "capabilities": {
                    "vision": False,
                    "file_input": 0,
                    "tool_calling": False,
                    "streaming": 0,
                    "context_window": 0,
                },
                "input_modalities": ["image", "file"],
            }
        )

        self.assertIs(detail["vision"], False)
        self.assertIs(detail["file_input"], False)
        self.assertIs(detail["tool_calling"], False)
        self.assertIs(detail["streaming"], False)
        self.assertEqual(detail["context_window"], 0)
        self.assertEqual(detail["capability_source"], "provider_metadata")

    def test_provider_unspecified_capabilities_remain_null(self) -> None:
        detail = self.normalize({"id": "provider-opaque"}, "provider-opaque")

        for key in (
            "vision",
            "file_input",
            "tool_calling",
            "streaming",
            "context_window",
        ):
            self.assertIsNone(detail[key], f"{key} was guessed instead of remaining null")
        self.assertEqual(detail["capability_source"], "provider_unspecified")

    def test_modalities_and_context_aliases_are_normalized(self) -> None:
        detail = self.normalize(
            {
                "input_modalities": ["text", "IMAGE"],
                "modalities": ["FiLe"],
                "max_context_length": 65536,
            }
        )

        self.assertIs(detail["vision"], True)
        self.assertIs(detail["file_input"], True)
        self.assertIsNone(detail["tool_calling"])
        self.assertIsNone(detail["streaming"])
        self.assertEqual(detail["context_window"], 65536)
        self.assertEqual(detail["capability_source"], "provider_metadata")

        nested_alias = self.normalize(
            {"capabilities": {"context_length": 32768}}, "nested-context"
        )
        self.assertEqual(nested_alias["context_window"], 32768)

    def test_static_catalog_has_stable_field_types(self) -> None:
        response = self.run_harness("static")

        self.assertEqual(response["code"], 0)
        data = response["data"]
        self.assertIs(data["model_capabilities_normalized"], True)
        self.assertIs(type(data["ts"]), int)
        self.assertTrue(data["models"])
        self.assertEqual(len(data["models"]), len(data["model_details"]))

        for model_id, detail in zip(data["models"], data["model_details"]):
            self.assertIs(type(model_id), str)
            self.assertIs(type(detail), dict)
            self.assertIs(type(detail["id"]), str)
            self.assertEqual(detail["id"], model_id)
            for key in (
                "vision",
                "file_input",
                "tool_calling",
                "streaming",
                "context_window",
            ):
                self.assertIsNone(detail[key])
            self.assertIs(type(detail["capability_source"]), str)
            self.assertEqual(
                detail["capability_source"], "static_catalog_unspecified"
            )


if __name__ == "__main__":
    unittest.main()
