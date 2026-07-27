import os
import pathlib
import shlex
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
DB_SOURCE = ROOT / "src" / "jmx_netconfig_db.c"


def extract_ai_config_get() -> str:
    source = DB_SOURCE.read_text(encoding="utf-8")
    start = source.index("struct json_object *jmx_ai_config_get(void)")
    end = source.index("\nstatic int nc_ai_temperature", start)
    return source[start:end].rstrip()


HARNESS_PREFIX = r'''
#include <json-c/json.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define API_CODE_SUCCESS 0

static sqlite3 *g_netconfig_db;

static void fail(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(1);
}

static int nc_exec(const char *sql)
{
    char *error = NULL;
    int rc = sqlite3_exec(g_netconfig_db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite error: %s\n", error ? error : "unknown");
        sqlite3_free(error);
        return -1;
    }
    return 0;
}

static int nc_prepare(sqlite3_stmt **statement, const char *sql)
{
    return sqlite3_prepare_v2(g_netconfig_db, sql, -1, statement, NULL) == SQLITE_OK
        ? 0 : -1;
}

static int jmx_netconfig_db_init(void)
{
    return g_netconfig_db ? 0 : -1;
}

static void nc_ai_db_init(void)
{
    if (nc_exec(
            "CREATE TABLE IF NOT EXISTS ai_config ("
            "id INTEGER PRIMARY KEY CHECK (id = 1),"
            "provider TEXT NOT NULL DEFAULT 'openai',"
            "api_base TEXT NOT NULL DEFAULT '',"
            "api_key TEXT NOT NULL DEFAULT '',"
            "model TEXT NOT NULL DEFAULT 'gpt-4o',"
            "temperature REAL NOT NULL DEFAULT 0.7,"
            "max_tokens INTEGER NOT NULL DEFAULT 4096,"
            "system_prompt TEXT NOT NULL DEFAULT '',"
            "tool_policy TEXT NOT NULL DEFAULT 'confirm_medium',"
            "enabled INTEGER NOT NULL DEFAULT 0,"
            "reasoning_effort TEXT NOT NULL DEFAULT 'auto',"
            "reasoning_api_shape TEXT NOT NULL DEFAULT 'chat_completions',"
            "auth_mode TEXT NOT NULL DEFAULT 'api_key',"
            "updated_at INTEGER NOT NULL DEFAULT 0)"))
        fail("failed to create ai_config");
}

static void nc_add_text(struct json_object *object, const char *key,
                        sqlite3_stmt *statement, int column)
{
    const char *value = (const char *)sqlite3_column_text(statement, column);
    json_object_object_add(object, key, json_object_new_string(value ? value : ""));
}

static const char *nc_json_str_def(struct json_object *object, const char *key,
                                   const char *fallback)
{
    struct json_object *value = NULL;
    const char *string;
    if (!object || !json_object_object_get_ex(object, key, &value) || !value)
        return fallback;
    string = json_object_get_string(value);
    return string ? string : fallback;
}

static int nc_json_bool_def(struct json_object *object, const char *key, int fallback)
{
    struct json_object *value = NULL;
    if (!object || !json_object_object_get_ex(object, key, &value) || !value)
        return fallback;
    return json_object_get_boolean(value);
}

static int64_t nc_now_s(void)
{
    return (int64_t)time(NULL);
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
static struct json_object *field(struct json_object *object, const char *key,
                                 enum json_type type)
{
    struct json_object *value = NULL;
    if (!json_object_object_get_ex(object, key, &value)) {
        fprintf(stderr, "missing field: %s\n", key);
        exit(1);
    }
    if (!json_object_is_type(value, type)) {
        fprintf(stderr, "wrong type for %s: %s\n", key,
                json_type_to_name(json_object_get_type(value)));
        exit(1);
    }
    return value;
}

static void expect_string(struct json_object *object, const char *key,
                          const char *expected)
{
    const char *actual = json_object_get_string(field(object, key, json_type_string));
    if (strcmp(actual, expected)) {
        fprintf(stderr, "%s: expected '%s', got '%s'\n", key, expected, actual);
        exit(1);
    }
}

static void expect_bool(struct json_object *object, const char *key, int expected)
{
    int actual = json_object_get_boolean(field(object, key, json_type_boolean));
    if (actual != expected) {
        fprintf(stderr, "%s: expected %d, got %d\n", key, expected, actual);
        exit(1);
    }
}

static struct json_object *response_data(struct json_object *response)
{
    return field(response, "data", json_type_object);
}

static void test_empty_table(void)
{
    sqlite3_stmt *statement = NULL;
    struct json_object *response = jmx_ai_config_get();
    struct json_object *data = response_data(response);
    struct json_object *caps;

    if (sqlite3_prepare_v2(g_netconfig_db, "SELECT COUNT(*) FROM ai_config", -1,
                           &statement, NULL) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_ROW ||
        sqlite3_column_int(statement, 0) != 0)
        fail("ai_config is not an empty real SQLite table");
    sqlite3_finalize(statement);

    expect_string(data, "provider", "openai");
    expect_string(data, "api_base", "");
    expect_string(data, "api_key", "");
    expect_bool(data, "api_key_set", 0);
    expect_string(data, "model", "gpt-4o");
    if (json_object_get_double(field(data, "temperature", json_type_double)) != 0.7)
        fail("temperature default mismatch");
    if (json_object_get_int(field(data, "max_tokens", json_type_int)) != 4096)
        fail("max_tokens default mismatch");
    expect_string(data, "system_prompt", "");
    expect_string(data, "tool_policy", "confirm_medium");
    expect_bool(data, "enabled", 0);
    expect_string(data, "reasoning_effort", "auto");
    expect_string(data, "reasoning_api_shape", "chat_completions");
    expect_string(data, "auth_mode", "api_key");
    caps = field(data, "capabilities", json_type_object);
    expect_bool(caps, "reasoning_effort_supported", 1);
    expect_string(caps, "reasoning_api_shape", "chat_completions");
    field(caps, "reasoning_effort_values", json_type_array);
    field(data, "ts", json_type_int);
    json_object_put(response);
}

static void test_existing_row_is_preserved_and_secret_is_masked(void)
{
    const char *secret = "sk-secret-1234567890";
    struct json_object *response;
    struct json_object *data;
    const char *serialized;

    if (nc_exec(
            "INSERT INTO ai_config (id,provider,api_base,api_key,model,temperature,"
            "max_tokens,system_prompt,tool_policy,enabled,reasoning_effort,"
            "reasoning_api_shape,auth_mode,updated_at) VALUES (1,'deepseek',"
            "'https://example.invalid/v1','sk-secret-1234567890','deepseek-reasoner',"
            "1.25,8192,'system','confirm_all',1,'high','responses','oauth',123)"))
        fail("failed to insert existing config row");

    response = jmx_ai_config_get();
    data = response_data(response);
    expect_string(data, "provider", "deepseek");
    expect_string(data, "api_base", "https://example.invalid/v1");
    expect_string(data, "api_key", "***7890");
    expect_bool(data, "api_key_set", 1);
    expect_string(data, "model", "deepseek-reasoner");
    if (json_object_get_double(field(data, "temperature", json_type_double)) != 1.25)
        fail("existing temperature changed");
    if (json_object_get_int(field(data, "max_tokens", json_type_int)) != 8192)
        fail("existing max_tokens changed");
    expect_string(data, "system_prompt", "system");
    expect_string(data, "tool_policy", "confirm_all");
    expect_bool(data, "enabled", 1);
    expect_string(data, "reasoning_effort", "high");
    expect_string(data, "reasoning_api_shape", "responses");
    expect_string(data, "auth_mode", "oauth");
    serialized = json_object_to_json_string_ext(response, JSON_C_TO_STRING_PLAIN);
    if (strstr(serialized, secret))
        fail("plaintext API key leaked in response");
    json_object_put(response);
}

int main(void)
{
    if (sqlite3_open(":memory:", &g_netconfig_db) != SQLITE_OK)
        fail("failed to open in-memory SQLite database");
    test_empty_table();
    test_existing_row_is_preserved_and_secret_is_masked();
    sqlite3_close(g_netconfig_db);
    return 0;
}
'''


def json_c_flags() -> tuple[list[str], dict[str, str]]:
    env = os.environ.copy()
    candidates = []
    try:
        prefix = pathlib.Path(
            subprocess.check_output(["brew", "--prefix", "json-c"], text=True).strip()
        )
        candidates.append(prefix)
    except (FileNotFoundError, subprocess.CalledProcessError):
        pass
    candidates.extend(
        pathlib.Path("/opt/homebrew/var/homebrew/tmp/.cellar/json-c").glob("*")
    )
    for prefix in candidates:
        header = prefix / "include" / "json-c" / "json.h"
        library = prefix / "lib" / "libjson-c.a"
        if header.is_file() and library.is_file():
            return [f"-I{prefix / 'include'}", str(library)], env

    try:
        output = subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "json-c"], text=True, env=env
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        raise RuntimeError("json-c development files are required") from error
    return shlex.split(output), env


class AiConfigDefaultContract(unittest.TestCase):
    def test_real_empty_sqlite_table_and_existing_row_contract(self) -> None:
        flags, env = json_c_flags()
        harness = HARNESS_PREFIX + "\n" + extract_ai_config_get() + "\n" + HARNESS_SUFFIX
        with tempfile.TemporaryDirectory(prefix="ai-config-contract-") as tmp:
            tmp_path = pathlib.Path(tmp)
            source = tmp_path / "ai_config_contract.c"
            executable = tmp_path / "ai_config_contract"
            source.write_text(harness, encoding="utf-8")
            compile_result = subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(source),
                    "-lsqlite3",
                    *flags,
                    "-o",
                    str(executable),
                ],
                text=True,
                capture_output=True,
                env=env,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(executable)], text=True, capture_output=True, env=env
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)


if __name__ == "__main__":
    unittest.main()
