// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime contract for the W2a config executor core.  The fixture binary
 * doubles as the fake uci/wifi command (argv dispatch, mode via
 * APD_CONFIG_FIXTURE_MODE, argv log via APD_CONFIG_FIXTURE_LOG, live
 * option state in <config_dir>/values) so the executor's real command
 * execution path is exercised end to end without any system mutation. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <openssl/sha.h>

#include "../src/apd/apd_config_executor.h"

static void fake_log(int argc, char **argv)
{
    const char *path = getenv("APD_CONFIG_FIXTURE_LOG");
    FILE *f;
    int i;

    if (!path)
        return;
    f = fopen(path, "a");
    if (!f)
        return;
    for (i = 1; i < argc; i++)
        fprintf(f, "%s%s", i > 1 ? " " : "", argv[i]);
    fputc('\n', f);
    fclose(f);
}

static const char *fake_mode(void)
{
    const char *mode = getenv("APD_CONFIG_FIXTURE_MODE");

    return mode ? mode : "success";
}

static int values_path(const char *dir, char *out, size_t size)
{
    return snprintf(out, size, "%s/values", dir) < (int)size ? 0 : -1;
}

static int fake_uci_get(const char *dir, const char *key)
{
    char path[512];
    char line[512];
    size_t key_len = strlen(key);
    FILE *f;

    if (values_path(dir, path, sizeof(path)) != 0)
        return 2;
    f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, key, key_len) && line[key_len] == '=') {
                fputs(line + key_len + 1, stdout);
                fclose(f);
                return 0;
            }
        }
        fclose(f);
    }
    fputs("uci: Entry not found\n", stderr);
    return 1;
}

static int fake_uci_write(const char *dir, const char *key,
                          const char *value)
{
    char path[512];
    char temp[520];
    char line[512];
    size_t key_len = strlen(key);
    FILE *in;
    FILE *out;

    if (values_path(dir, path, sizeof(path)) != 0)
        return 2;
    snprintf(temp, sizeof(temp), "%s.tmp", path);
    out = fopen(temp, "w");
    if (!out)
        return 2;
    in = fopen(path, "r");
    if (in) {
        while (fgets(line, sizeof(line), in))
            if (strncmp(line, key, key_len) != 0 || line[key_len] != '=')
                fputs(line, out);
        fclose(in);
    }
    if (value)
        fprintf(out, "%s=%s\n", key, value);
    fclose(out);
    return rename(temp, path) == 0 ? 0 : 2;
}

static int fake_uci(int argc, char **argv)
{
    const char *dir;
    const char *verb;

    fake_log(argc, argv);
    if (argc < 4 || strcmp(argv[1], "-c") != 0)
        return 2;
    dir = argv[2];
    verb = argv[3];
    if (!strcmp(verb, "get") && argc == 5)
        return fake_uci_get(dir, argv[4]);
    if (!strcmp(verb, "set") && argc == 5) {
        char *assignment = strdup(argv[4]);
        char *equals = assignment ? strchr(assignment, '=') : NULL;
        int rc;

        if (!equals) {
            free(assignment);
            return 2;
        }
        if (strstr(fake_mode(), "set-fail") &&
            strstr(assignment, "poison")) {
            fputs("uci: Invalid argument\n", stderr);
            free(assignment);
            return 1;
        }
        *equals = '\0';
        rc = fake_uci_write(dir, assignment, equals + 1);
        free(assignment);
        return rc;
    }
    if (!strcmp(verb, "delete") && argc == 5)
        return fake_uci_write(dir, argv[4], NULL);
    if (!strcmp(verb, "commit") && argc == 5) {
        if (strstr(fake_mode(), "commit-fail")) {
            fputs("uci: I/O error\n", stderr);
            return 1;
        }
        return 0;
    }
    return 2;
}

static int fake_wifi(int argc, char **argv)
{
    fake_log(argc, argv);
    if (strstr(fake_mode(), "reload-fail")) {
        fputs("wifi: reload failed\n", stderr);
        return 1;
    }
    return 0;
}

/* ---- test driver ---- */

static struct json_object *field(struct json_object *object,
                                 const char *name)
{
    struct json_object *value = NULL;

    return object && json_object_object_get_ex(object, name, &value) ?
           value : NULL;
}

static const char *text(struct json_object *object, const char *name)
{
    struct json_object *value = field(object, name);

    return value ? json_object_get_string(value) : "";
}

static int boolean(struct json_object *object, const char *name)
{
    return json_object_get_boolean(field(object, name));
}

static char *digest_of(const char *canonical)
{
    static const char hex[] = "0123456789abcdef";
    static char out[7 + SHA256_DIGEST_LENGTH * 2 + 1];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t i;

    SHA256((const unsigned char *)canonical, strlen(canonical), digest);
    memcpy(out, "sha256:", 7);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out[7 + i * 2] = hex[digest[i] >> 4];
        out[7 + i * 2 + 1] = hex[digest[i] & 15];
    }
    out[7 + SHA256_DIGEST_LENGTH * 2] = '\0';
    return out;
}

static struct json_object *candidate_new(const char *section,
                                         const char *option,
                                         const char *value,
                                         const char *canonical)
{
    struct json_object *candidate = json_object_new_object();
    struct json_object *sections = json_object_new_array();
    struct json_object *entry = json_object_new_object();
    struct json_object *options = json_object_new_object();

    json_object_object_add(candidate, "format",
        json_object_new_string(APD_CONFIG_CANDIDATE_FORMAT));
    json_object_object_add(candidate, "candidate_digest",
        json_object_new_string(digest_of(canonical)));
    json_object_object_add(entry, "section",
                           json_object_new_string(section));
    json_object_object_add(options, option,
                           json_object_new_string(value));
    json_object_object_add(entry, "options", options);
    json_object_array_add(sections, entry);
    json_object_object_add(candidate, "sections", sections);
    return candidate;
}

static int write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");

    if (!f)
        return -1;
    fputs(content, f);
    return fclose(f) == 0 ? 0 : -1;
}

static char *read_file(const char *path)
{
    static char buffer[4096];
    FILE *f = fopen(path, "r");
    size_t got;

    if (!f)
        return NULL;
    got = fread(buffer, 1, sizeof(buffer) - 1, f);
    buffer[got] = '\0';
    fclose(f);
    return buffer;
}

static int log_contains(const char *log_path, const char *needle)
{
    char *content = read_file(log_path);

    return content && strstr(content, needle) != NULL;
}

int main(int argc, char **argv)
{
    struct apd_config_paths paths;
    struct json_object *candidate;
    struct json_object *result = NULL;
    struct json_object *previous;
    char config_dir[256];
    char staging_dir[256];
    char log_path[320];
    char values[320];
    char staged[320];
    const char *root;
    int rc = 1;

    if (argc >= 2 && !strcmp(argv[1], "-c"))
        return fake_uci(argc, argv);
    if (argc >= 2 && !strcmp(argv[1], "reload"))
        return fake_wifi(argc, argv);
    if (argc != 3 || strcmp(argv[1], "run") != 0) {
        fprintf(stderr, "usage: fixture run <tempdir>\n");
        return 2;
    }
    root = argv[2];
    snprintf(config_dir, sizeof(config_dir), "%s/config", root);
    snprintf(staging_dir, sizeof(staging_dir), "%s/staging", root);
    snprintf(log_path, sizeof(log_path), "%s/command.log", root);
    snprintf(values, sizeof(values), "%s/values", config_dir);
    snprintf(staged, sizeof(staged), "%s/wireless", staging_dir);
    setenv("APD_CONFIG_FIXTURE_LOG", log_path, 1);
    setenv("APD_CONFIG_FIXTURE_MODE", "success", 1);
    paths.uci = argv[0];
    paths.wifi = argv[0];
    paths.config_dir = config_dir;
    paths.staging_dir = staging_dir;
    if (write_file(values, "wireless.radio1.channel=11\n") != 0 ||
        write_file(staged, "") != 0)
        return 2;
    {
        char wireless[320];

        snprintf(wireless, sizeof(wireless), "%s/wireless", config_dir);
        if (write_file(wireless, "config wifi-device 'radio1'\n") != 0)
            return 2;
    }

    /* validate: good candidate passes, tampered digest fails. */
    candidate = candidate_new("radio1", "channel", "6",
                              "radio1\nchannel=6\n");
    if (apd_config_candidate_validate(candidate, &result) != 0 ||
        !boolean(result, "ok")) {
        fprintf(stderr, "validate ok case: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    json_object_object_add(candidate, "candidate_digest",
        json_object_new_string("sha256:" "00000000000000000000000000000000"
                               "00000000000000000000000000000000"));
    if (apd_config_candidate_validate(candidate, &result) == 0 ||
        strcmp(text(result, "reason"), "candidate_digest_mismatch")) {
        fprintf(stderr, "digest mismatch case: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    json_object_put(candidate);

    /* validate: non-allowlisted option and non-ASCII value reject. */
    candidate = candidate_new("radio1", "channel", "6",
                              "radio1\nchannel=6\n");
    {
        struct json_object *sections = field(candidate, "sections");
        struct json_object *entry = json_object_array_get_idx(sections, 0);
        struct json_object *options = field(entry, "options");

        json_object_object_add(options, "country",
                               json_object_new_string("CN"));
    }
    if (apd_config_candidate_validate(candidate, &result) == 0 ||
        strcmp(text(result, "reason"), "candidate_option_not_allowed"))
        goto done;
    json_object_put(result);
    json_object_put(candidate);
    candidate = candidate_new("radio1", "ssid", "2\xe6\xa5\xbc",
                              "radio1\nssid=2\xe6\xa5\xbc\n");
    if (apd_config_candidate_validate(candidate, &result) == 0 ||
        strcmp(text(result, "reason"), "candidate_value_invalid"))
        goto done;
    json_object_put(result);
    json_object_put(candidate);

    /* stage: copies the live config and drives uci set/commit against
     * the staging directory only. */
    candidate = candidate_new("radio1", "channel", "6",
                              "radio1\nchannel=6\n");
    if (apd_config_stage(&paths, candidate, &result) != 0 ||
        !boolean(result, "ok") || !boolean(result, "staged")) {
        fprintf(stderr, "stage: %s\n", json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    if (!log_contains(log_path, "-c") ||
        !log_contains(log_path, "set wireless.radio1.channel=6") ||
        !log_contains(log_path, "commit wireless") ||
        !read_file(staged) || !strstr(read_file(staged), "wifi-device")) {
        fprintf(stderr, "stage command trail incomplete\n");
        goto done;
    }

    /* apply: captures previous values, sets, commits, reloads; readback
     * then confirms the new value through the same uci path. */
    if (apd_config_apply(&paths, candidate, &result) != 0 ||
        !boolean(result, "ok") || !boolean(result, "applied")) {
        fprintf(stderr, "apply: %s\n", json_object_to_json_string(result));
        goto done;
    }
    previous = json_object_get(field(result, "previous"));
    json_object_put(result);
    if (!previous || json_object_array_length(previous) != 1 ||
        strcmp(text(field(json_object_array_get_idx(previous, 0),
                          "options"), "channel"), "11")) {
        fprintf(stderr, "previous capture wrong: %s\n",
                json_object_to_json_string(previous));
        goto done;
    }
    if (!log_contains(log_path, "reload radio1")) {
        fprintf(stderr, "apply skipped wifi reload\n");
        goto done;
    }
    if (apd_config_readback(&paths, candidate, &result) != 0 ||
        !boolean(result, "match")) {
        fprintf(stderr, "readback after apply: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);

    /* rollback: restores the captured value (and reloads). */
    if (apd_config_rollback(&paths, previous, &result) != 0 ||
        !boolean(result, "ok") || !boolean(result, "rolled_back")) {
        fprintf(stderr, "rollback: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    json_object_put(previous);
    if (apd_config_readback(&paths, candidate, &result) != 0 ||
        boolean(result, "match") ||
        json_object_array_length(field(result, "mismatches")) != 1 ||
        strcmp(text(json_object_array_get_idx(field(result, "mismatches"),
                                              0), "actual"), "11")) {
        fprintf(stderr, "readback after rollback: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    json_object_put(candidate);

    /* apply failure mid-set rolls back the already-written options. */
    setenv("APD_CONFIG_FIXTURE_MODE", "set-fail", 1);
    candidate = candidate_new("radio1", "ssid", "poison-net",
                              "radio1\nssid=poison-net\n");
    if (apd_config_apply(&paths, candidate, &result) == 0 ||
        strcmp(text(result, "reason"), "uci_set_failed") ||
        !boolean(result, "rolled_back") ||
        !field(result, "evidence")) {
        fprintf(stderr, "apply set failure: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    json_object_put(candidate);
    setenv("APD_CONFIG_FIXTURE_MODE", "success", 1);
    if (!read_file(values) || strstr(read_file(values), "poison")) {
        fprintf(stderr, "poison value survived rollback\n");
        goto done;
    }

    /* reload failure also reports rolled_back. */
    setenv("APD_CONFIG_FIXTURE_MODE", "reload-fail", 1);
    candidate = candidate_new("radio1", "channel", "1",
                              "radio1\nchannel=1\n");
    if (apd_config_apply(&paths, candidate, &result) == 0 ||
        strcmp(text(result, "reason"), "wifi_reload_failed") ||
        !boolean(result, "rolled_back")) {
        fprintf(stderr, "apply reload failure: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    json_object_put(candidate);
    setenv("APD_CONFIG_FIXTURE_MODE", "success", 1);
    if (strstr(read_file(values), "channel=1\n")) {
        fprintf(stderr, "reload failure left new value behind\n");
        goto done;
    }

    printf("ok\n");
    rc = 0;
    result = NULL;
done:
    if (result)
        json_object_put(result);
    return rc;
}
