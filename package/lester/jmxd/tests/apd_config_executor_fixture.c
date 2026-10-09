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
#include <unistd.h>

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
    char fallback[512];
    char marker[512];
    char line[512];
    size_t key_len = strlen(key);
    FILE *f;

    if (values_path(dir, path, sizeof(path)) != 0)
        return 2;
    snprintf(marker, sizeof(marker), "%s/readback-active", dir);
    if (access(marker, F_OK) == 0 && strstr(fake_mode(), "readback-fail")) {
        fputs("uci: readback failed\n", stderr);
        return 2;
    }
    f = fopen(path, "r");
    if (!f && strstr(dir, "/staging")) {
        snprintf(fallback, sizeof(fallback), "%s/../config/values", dir);
        f = fopen(fallback, "r");
    }
    if (f) {
        int found = 0;
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, key, key_len) && line[key_len] == '=') {
                if (access(marker, F_OK) == 0 &&
                    strstr(fake_mode(), "readback-mismatch"))
                    fputs("99\n", stdout);
                else
                    fputs(line + key_len + 1, stdout);
                found = 1;
            }
        }
        fclose(f);
        if (found)
            return 0;
    }
    if (strstr(dir, "/staging")) {
        snprintf(fallback, sizeof(fallback), "%s/../config/values", dir);
        f = fopen(fallback, "r");
        if (f) {
            int found = 0;

            while (fgets(line, sizeof(line), f)) {
                if (!strncmp(line, key, key_len) && line[key_len] == '=') {
                    fputs(line + key_len + 1, stdout);
                    found = 1;
                }
            }
            fclose(f);
            if (found)
                return 0;
        }
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
    int section_delete = !value && strchr(key, '.') == strrchr(key, '.');
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
        while (fgets(line, sizeof(line), in)) {
            int exact = !strncmp(line, key, key_len) && line[key_len] == '=';
            int child = section_delete && !strncmp(line, key, key_len) &&
                        line[key_len] == '.';

            if (!exact && !child)
                fputs(line, out);
        }
        fclose(in);
    }
    if (value)
        fprintf(out, "%s=%s\n", key, value);
    fclose(out);
    return rename(temp, path) == 0 ? 0 : 2;
}

static int fake_uci_add_list(const char *dir, const char *key,
                             const char *value)
{
    char path[512];
    FILE *f;

    if (values_path(dir, path, sizeof(path)) != 0)
        return 2;
    f = fopen(path, "a");
    if (!f)
        return 2;
    fprintf(f, "%s=%s\n", key, value);
    fclose(f);
    return 0;
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
        if (strstr(dir, "/config") && strstr(fake_mode(), "rollback-fail") &&
            !strcmp(equals + 1, "11")) {
            fputs("uci: rollback failed\n", stderr);
            free(assignment);
            return 1;
        }
        rc = fake_uci_write(dir, assignment, equals + 1);
        free(assignment);
        return rc;
    }
    if (!strcmp(verb, "add_list") && argc == 5) {
        char *assignment = strdup(argv[4]);
        char *equals = assignment ? strchr(assignment, '=') : NULL;
        int rc;

        if (!equals) {
            free(assignment);
            return 2;
        }
        *equals = '\0';
        rc = fake_uci_add_list(dir, assignment, equals + 1);
        free(assignment);
        return rc;
    }
    if (!strcmp(verb, "delete") && argc == 5)
        return fake_uci_write(dir, argv[4], NULL);
    if (!strcmp(verb, "commit") && argc == 5) {
        char marker[512];

        if (strstr(fake_mode(), "commit-fail")) {
            fputs("uci: I/O error\n", stderr);
            return 1;
        }
        if (strstr(dir, "/config")) {
            FILE *marker_file;

            snprintf(marker, sizeof(marker), "%s/readback-active", dir);
            marker_file = fopen(marker, "w");
            if (marker_file)
                fclose(marker_file);
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

static struct json_object *candidate_new_with_list(
    const char *section,
    const char *option, const char *value,
    const char *list_option, const char **list_values,
    size_t list_count,
    const char *canonical)
{
    struct json_object *candidate = json_object_new_object();
    struct json_object *sections = json_object_new_array();
    struct json_object *entry = json_object_new_object();
    struct json_object *options = json_object_new_object();
    struct json_object *list_options = json_object_new_object();
    struct json_object *list_array = json_object_new_array();
    size_t i;

    json_object_object_add(candidate, "format",
        json_object_new_string(APD_CONFIG_CANDIDATE_FORMAT));
    json_object_object_add(candidate, "candidate_digest",
        json_object_new_string(digest_of(canonical)));
    json_object_object_add(entry, "section",
                           json_object_new_string(section));
    json_object_object_add(options, option,
                           json_object_new_string(value));
    for (i = 0; i < list_count; i++)
        json_object_array_add(list_array,
            json_object_new_string(list_values[i]));
    json_object_object_add(list_options, list_option, list_array);
    json_object_object_add(entry, "options", options);
    json_object_object_add(entry, "list_options", list_options);
    json_object_array_add(sections, entry);
    json_object_object_add(candidate, "sections", sections);
    return candidate;
}

static struct json_object *candidate_create_with_list(
    const char *section, const char *section_type,
    const char *option, const char *value,
    const char *list_option, const char **list_values,
    size_t list_count, const char *canonical)
{
    struct json_object *candidate = json_object_new_object();
    struct json_object *sections = json_object_new_array();
    struct json_object *entry = json_object_new_object();
    struct json_object *options = json_object_new_object();
    struct json_object *list_options = json_object_new_object();
    struct json_object *list_array = json_object_new_array();
    size_t i;

    json_object_object_add(candidate, "format",
        json_object_new_string(APD_CONFIG_CANDIDATE_FORMAT));
    json_object_object_add(candidate, "candidate_digest",
        json_object_new_string(digest_of(canonical)));
    json_object_object_add(entry, "section",
                           json_object_new_string(section));
    json_object_object_add(entry, "operation",
                           json_object_new_string("create"));
    json_object_object_add(entry, "section_type",
                           json_object_new_string(section_type));
    json_object_object_add(options, option,
                           json_object_new_string(value));
    for (i = 0; i < list_count; i++)
        json_object_array_add(list_array,
            json_object_new_string(list_values[i]));
    json_object_object_add(list_options, list_option, list_array);
    json_object_object_add(entry, "options", options);
    json_object_object_add(entry, "list_options", list_options);
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
    /* Stream the log instead of reusing read_file's fixed 4096-byte static
     * buffer.  The command log outgrows that after a few driver phases, and a
     * truncated read reports a command that really did run as "not called" --
     * a fixture artefact that looks exactly like a product defect. */
    char window[8192];
    size_t needle_len = strlen(needle);
    size_t keep = needle_len ? needle_len - 1 : 0;
    size_t filled = 0;
    int found = 0;
    FILE *f;

    if (!needle_len || keep >= sizeof(window) - 1)
        return 0;
    f = fopen(log_path, "r");
    if (!f)
        return 0;
    for (;;) {
        size_t got = fread(window + filled, 1,
                           sizeof(window) - 1 - filled, f);

        if (!got)
            break;
        filled += got;
        window[filled] = '\0';
        if (strstr(window, needle)) {
            found = 1;
            break;
        }
        /* Carry the last needle_len-1 bytes so a match spanning two reads is
         * still seen. */
        if (filled > keep) {
            memmove(window, window + filled - keep, keep);
            filled = keep;
        }
    }
    fclose(f);
    return found;
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
    char active_marker[320];
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
    snprintf(active_marker, sizeof(active_marker), "%s/readback-active", config_dir);
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
    if (!field(result, "readback") ||
        !boolean(field(result, "readback"), "match") ||
        !text(field(result, "readback"), "candidate_digest")[0] ||
        !text(field(result, "readback"), "readback_digest")[0]) {
        fprintf(stderr, "apply readback evidence incomplete: %s\n",
                json_object_to_json_string(result));
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

    /* Candidate-aware mismatch and readback command failure both roll back. */
    unlink(active_marker);
    setenv("APD_CONFIG_FIXTURE_MODE", "readback-mismatch", 1);
    candidate = candidate_new("radio1", "channel", "6",
                              "radio1\nchannel=6\n");
    if (apd_config_apply(&paths, candidate, &result) == 0 ||
        strcmp(text(result, "reason"), "readback_mismatch") ||
        !boolean(result, "rolled_back") || boolean(result, "applied")) {
        fprintf(stderr, "readback mismatch: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    json_object_put(candidate);
    unlink(active_marker);
    setenv("APD_CONFIG_FIXTURE_MODE", "readback-fail", 1);
    candidate = candidate_new("radio1", "channel", "6",
                              "radio1\nchannel=6\n");
    if (apd_config_apply(&paths, candidate, &result) == 0 ||
        strcmp(text(result, "reason"), "readback_failed") ||
        !boolean(result, "rolled_back")) {
        fprintf(stderr, "readback failure: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    json_object_put(candidate);
    setenv("APD_CONFIG_FIXTURE_MODE", "readback-mismatch rollback-fail", 1);
    unlink(active_marker);
    candidate = candidate_new("radio1", "channel", "6",
                              "radio1\nchannel=6\n");
    if (apd_config_apply(&paths, candidate, &result) == 0 ||
        strcmp(text(result, "reason"), "rollback_failed") ||
        boolean(result, "rolled_back") || boolean(result, "applied")) {
        fprintf(stderr, "rollback failure: %s\n",
                json_object_to_json_string(result));
        goto done;
    }
    json_object_put(result);
    json_object_put(candidate);
    setenv("APD_CONFIG_FIXTURE_MODE", "success", 1);

    /* list_options: validate accepts r0kh/r1kh list options. */
    {
        const char *r0kh_values[] = {
            "aa:bb:cc:dd:ee:ff,r0kh-id,000102030405060708090a0b0c0d0e0f"
        };
        /* canonical: "radio1\nchannel=6\nr0kh=aa:bb:...\n" */
        const char *canonical =
            "radio1\nchannel=6\n"
            "r0kh=aa:bb:cc:dd:ee:ff,r0kh-id,000102030405060708090a0b0c0d0e0f\n";

        candidate = candidate_new_with_list(
            "radio1", "channel", "6",
            "r0kh", r0kh_values, 1, canonical);
        if (apd_config_candidate_validate(candidate, &result) != 0 ||
            !boolean(result, "ok")) {
            fprintf(stderr, "list_options validate: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        /* Non-allowlisted list option rejected. */
        {
            struct json_object *sections = field(candidate, "sections");
            struct json_object *entry = json_object_array_get_idx(sections, 0);
            struct json_object *lo = field(entry, "list_options");
            struct json_object *bad = json_object_new_array();

            json_object_array_add(bad, json_object_new_string("val"));
            json_object_object_add(lo, "bad_list", bad);
        }
        if (apd_config_candidate_validate(candidate, &result) == 0 ||
            strcmp(text(result, "reason"),
                   "candidate_list_option_not_allowed")) {
            fprintf(stderr, "list_options reject bad: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        json_object_put(candidate);
    }

    /* list_options: apply with r0kh list writes via add_list. */
    {
        const char *r0kh_values[] = {
            "aa:bb:cc:dd:ee:ff,r0kh-id,000102030405060708090a0b0c0d0e0f",
            "11:22:33:44:55:66,r0kh-id2,0f0e0d0c0b0a09080706050403020100"
        };
        const char *canonical =
            "radio1\nchannel=6\n"
            "r0kh=aa:bb:cc:dd:ee:ff,r0kh-id,000102030405060708090a0b0c0d0e0f\n"
            "r0kh=11:22:33:44:55:66,r0kh-id2,0f0e0d0c0b0a09080706050403020100\n";

        candidate = candidate_new_with_list(
            "radio1", "channel", "6",
            "r0kh", r0kh_values, 2, canonical);
        if (apd_config_apply(&paths, candidate, &result) != 0 ||
            !boolean(result, "ok") || !boolean(result, "applied")) {
            fprintf(stderr, "list_options apply: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        /* Verify add_list was called. */
        if (!log_contains(log_path, "add_list wireless.radio1.r0kh=")) {
            fprintf(stderr, "list_options apply: add_list not called\n");
            goto done;
        }
        json_object_put(candidate);
    }

    /* MLO reuses the existing SSID and key while device becomes a list. */
    {
        const char *devices[] = { "radio0", "radio1", "radio2" };
        const char *canonical =
            "wifi_existing\nmlo=1\n"
            "device=radio0\ndevice=radio1\ndevice=radio2\n";

        candidate = candidate_new_with_list(
            "wifi_existing", "mlo", "1", "device", devices, 3, canonical);
        fake_uci_write(paths.config_dir, "wireless.wifi_existing.device", "radio0");
        fake_uci_write(paths.config_dir, "wireless.wifi_existing.key", "keep-existing-key");
        if (apd_config_stage(&paths, candidate, &result) != 0 ||
            !boolean(result, "ok")) {
            fprintf(stderr, "MLO stage: %s\n", json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        if (apd_config_apply(&paths, candidate, &result) != 0 ||
            !boolean(result, "applied")) {
            fprintf(stderr, "MLO apply: %s\n", json_object_to_json_string(result));
            goto done;
        }
        previous = json_object_get(field(result, "previous"));
        json_object_put(result);
        if (apd_config_readback(&paths, candidate, &result) != 0 ||
            !boolean(result, "match")) {
            fprintf(stderr, "MLO readback: %s\n", json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        if (apd_config_rollback(&paths, previous, &result) != 0 ||
            !boolean(result, "ok")) {
            fprintf(stderr, "MLO rollback: %s\n", json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        json_object_put(candidate);
        json_object_put(previous);
    }

    /* dreamingwrt_mlo_members carries a structured JSON document, not a UCI
     * scalar: it holds double quotes and runs past the 64-byte scalar limit,
     * so the value validator, the digest capacity and the `uci set` argument
     * buffer all have to admit it.  A truncated value would stage a half
     * document and then fail readback against its own candidate. */
    {
        const char *members =
            "{\"version\":1,\"members\":["
            "{\"section\":\"wifi0\",\"device\":[\"radio0\"],\"disabled\":\"0\"},"
            "{\"section\":\"wifi1\",\"device\":[\"radio1\"],\"disabled\":\"0\"},"
            "{\"section\":\"wifi2\",\"device\":[\"radio2\"],\"disabled\":\"0\"}]}";
        char canonical[512];

        snprintf(canonical, sizeof(canonical),
                 "wifi_existing\ndreamingwrt_mlo_members=%s\n", members);
        candidate = candidate_new("wifi_existing", "dreamingwrt_mlo_members",
                                  members, canonical);
        if (apd_config_stage(&paths, candidate, &result) != 0 ||
            !boolean(result, "ok")) {
            fprintf(stderr, "MLO members stage: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        if (apd_config_apply(&paths, candidate, &result) != 0 ||
            !boolean(result, "applied")) {
            fprintf(stderr, "MLO members apply: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        if (apd_config_readback(&paths, candidate, &result) != 0 ||
            !boolean(result, "match")) {
            fprintf(stderr, "MLO members readback: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        json_object_put(candidate);
    }

    /* A newly-created MLO wifi-iface inherits the WPA key from its first
     * member, while the candidate and rollback journal remain secret-free.
     * The device scalar is cleared before add_list writes the three radios;
     * rollback removes the complete created section rather than leaving a
     * half-configured VAP behind. */
    {
        const char *devices[] = { "radio0", "radio1", "radio2" };
        const char *members =
            "{\"version\":1,\"members\":["
            "{\"section\":\"wifi0\",\"device\":[\"radio0\"],\"disabled\":\"0\"},"
            "{\"section\":\"wifi1\",\"device\":[\"radio1\"],\"disabled\":\"0\"}]}";
        const char *canonical =
            "wifi_mlo\n!create\n"
            "mlo=1\n"
            "encryption=sae+ccmp\n"
            "network=lan\n"
            "ssid=Mesh-MLO\n"
            "dreamingwrt_mlo_members={\"version\":1,\"members\":["
            "{\"section\":\"wifi0\",\"device\":[\"radio0\"],\"disabled\":\"0\"},"
            "{\"section\":\"wifi1\",\"device\":[\"radio1\"],\"disabled\":\"0\"}]}\n"
            "device=radio0\ndevice=radio1\ndevice=radio2\n";
        const char *values_after;

        fake_uci_write(paths.config_dir, "wireless.wifi0", "wifi-iface");
        fake_uci_write(paths.config_dir, "wireless.wifi0.key", "source-key");
        candidate = candidate_create_with_list(
            "wifi_mlo", "wifi-iface", "mlo", "1", "device", devices, 3,
            canonical);
        {
            struct json_object *section = json_object_array_get_idx(
                field(candidate, "sections"), 0);
            struct json_object *options = field(section, "options");
            json_object_object_add(options, "encryption",
                json_object_new_string("sae+ccmp"));
            json_object_object_add(options, "network",
                json_object_new_string("lan"));
            json_object_object_add(options, "ssid",
                json_object_new_string("Mesh-MLO"));
            json_object_object_add(options, "dreamingwrt_mlo_members",
                json_object_new_string(members));
            json_object_object_add(candidate, "candidate_digest",
                json_object_new_string(digest_of(canonical)));
        }
        if (apd_config_candidate_validate(candidate, &result) != 0 ||
            !boolean(result, "ok")) {
            fprintf(stderr, "MLO create validate: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        if (apd_config_stage(&paths, candidate, &result) != 0 ||
            !boolean(result, "ok")) {
            fprintf(stderr, "MLO create stage: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        if (apd_config_apply(&paths, candidate, &result) != 0 ||
            !boolean(result, "applied")) {
            fprintf(stderr, "MLO create apply: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        previous = json_object_get(field(result, "previous"));
        json_object_put(result);
        values_after = read_file(values);
        if (!values_after || !strstr(values_after,
                "wireless.wifi_mlo.key=source-key") ||
            !strstr(values_after, "wireless.wifi_mlo.device=radio0") ||
            !strstr(values_after, "wireless.wifi_mlo.device=radio1") ||
            !strstr(values_after, "wireless.wifi_mlo.device=radio2")) {
            fprintf(stderr, "MLO create did not inherit key/list: %s\n",
                    values_after ? values_after : "<missing>");
            goto done;
        }
        if (apd_config_rollback(&paths, previous, &result) != 0 ||
            !boolean(result, "ok")) {
            fprintf(stderr, "MLO create rollback: %s\n",
                    json_object_to_json_string(result));
            goto done;
        }
        json_object_put(result);
        values_after = read_file(values);
        if (values_after && strstr(values_after, "wireless.wifi_mlo")) {
            fprintf(stderr, "MLO created section survived rollback: %s\n",
                    values_after);
            goto done;
        }
        json_object_put(candidate);
        json_object_put(previous);
    }

    printf("ok\n");
    rc = 0;
    result = NULL;
done:
    if (result)
        json_object_put(result);
    return rc;
}
