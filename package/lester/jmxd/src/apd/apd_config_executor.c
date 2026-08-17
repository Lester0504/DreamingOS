// SPDX-License-Identifier: GPL-2.0-or-later
/* Phase W2a config executor core.  See apd_config_executor.h for the
 * reachability contract: nothing in production invokes these functions
 * until the W2b config_job wire lands behind the capability gates.
 *
 * Candidate contract (built by the AC from validated desired config):
 *   {
 *     "format": "uci-wireless-candidate.v1",
 *     "candidate_digest": "sha256:<64 hex>",
 *     "sections": [
 *       { "section": "radio1",
 *         "options": { "channel": "6", "htmode": "EHT40" } }
 *     ]
 *   }
 * The digest covers the canonical serialization (section name, then each
 * option as name=value in the given order, one per line).  Values are
 * printable ASCII only: the candidate travels over the ap-control wire,
 * whose strict parser rejects raw non-ASCII bytes (2026-07-26 finding).
 */
#include "apd_config_executor.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "apd_readonly_command.h"

static const char *const apd_config_option_allowlist[] = {
    "channel", "htmode", "txpower", "disabled", "ssid",
};

static struct json_object *apd_config_result_new(const char *operation)
{
    struct json_object *result = json_object_new_object();

    json_object_object_add(result, "operation",
                           json_object_new_string(operation));
    return result;
}

static int apd_config_fail(struct json_object **out, const char *operation,
                           const char *reason,
                           const struct apd_command_result *command)
{
    struct json_object *result = apd_config_result_new(operation);

    json_object_object_add(result, "ok", json_object_new_boolean(0));
    json_object_object_add(result, "reason",
                           json_object_new_string(reason));
    if (command) {
        struct json_object *evidence = json_object_new_object();
        const char *stderr_text = command->stderr_text ?
                                  command->stderr_text : "";
        char excerpt[161];

        snprintf(excerpt, sizeof(excerpt), "%s", stderr_text);
        json_object_object_add(evidence, "exit_status",
                               json_object_new_int(command->exit_status));
        json_object_object_add(evidence, "timed_out",
                               json_object_new_boolean(command->timed_out));
        json_object_object_add(evidence, "stderr_excerpt",
                               json_object_new_string(excerpt));
        json_object_object_add(result, "evidence", evidence);
    }
    *out = result;
    return -1;
}

static int apd_config_ok(struct json_object **out,
                         struct json_object *result)
{
    json_object_object_add(result, "ok", json_object_new_boolean(1));
    *out = result;
    return 0;
}

static int apd_config_name_valid(const char *value)
{
    size_t i;
    size_t length = value ? strlen(value) : 0;

    if (length == 0 || length > APD_CONFIG_NAME_MAX)
        return 0;
    for (i = 0; i < length; i++) {
        char c = value[i];

        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
            return 0;
    }
    return 1;
}

static int apd_config_value_valid(const char *value)
{
    size_t i;
    size_t length = value ? strlen(value) : 0;

    if (length == 0 || length > APD_CONFIG_VALUE_MAX)
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];

        if (c < 0x20 || c > 0x7e || c == '\'' || c == '"' || c == '\\')
            return 0;
    }
    return 1;
}

static int apd_config_option_allowed(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(apd_config_option_allowlist) /
                    sizeof(apd_config_option_allowlist[0]); i++)
        if (!strcmp(name, apd_config_option_allowlist[i]))
            return 1;
    return 0;
}

static int apd_config_digest_hex(struct json_object *sections,
                                 char out[SHA256_DIGEST_LENGTH * 2 + 8])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char *canonical;
    size_t capacity = 256;
    size_t used = 0;
    size_t i;
    size_t j;

    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *options = NULL;

        capacity += APD_CONFIG_NAME_MAX + 2;
        json_object_object_get_ex(section, "options", &options);
        json_object_object_foreach(options, option, value) {
            (void)value;
            capacity += strlen(option) + APD_CONFIG_VALUE_MAX + 3;
        }
    }
    canonical = malloc(capacity);
    if (!canonical)
        return -1;
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        used += (size_t)snprintf(canonical + used, capacity - used, "%s\n",
                                 json_object_get_string(name));
        json_object_object_foreach(options, option, value) {
            used += (size_t)snprintf(canonical + used, capacity - used,
                                     "%s=%s\n", option,
                                     json_object_get_string(value));
        }
    }
    if (used >= capacity ||
        !SHA256((const unsigned char *)canonical, used, digest)) {
        free(canonical);
        return -1;
    }
    free(canonical);
    memcpy(out, "sha256:", 7);
    for (j = 0; j < SHA256_DIGEST_LENGTH; j++) {
        out[7 + j * 2] = hex[digest[j] >> 4];
        out[7 + j * 2 + 1] = hex[digest[j] & 15];
    }
    out[7 + SHA256_DIGEST_LENGTH * 2] = '\0';
    return 0;
}

static int apd_config_readback_digest(struct json_object *sections,
                                      char out[SHA256_DIGEST_LENGTH * 2 + 8])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t i;

    if (!sections || !context || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        return -1;
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;

        if (!json_object_object_get_ex(section, "section", &name) ||
            !json_object_object_get_ex(section, "options", &options))
            return -1;
        EVP_DigestUpdate(context, json_object_get_string(name),
                         strlen(json_object_get_string(name)));
        EVP_DigestUpdate(context, "\n", 1);
        json_object_object_foreach(options, option, value) {
            const char *actual = value &&
                !json_object_is_type(value, json_type_null) ?
                json_object_get_string(value) : "<missing>";
            EVP_DigestUpdate(context, option, strlen(option));
            EVP_DigestUpdate(context, "=", 1);
            EVP_DigestUpdate(context, actual, strlen(actual));
            EVP_DigestUpdate(context, "\n", 1);
        }
    }
    if (EVP_DigestFinal_ex(context, digest, &digest_length) != 1 ||
        digest_length != SHA256_DIGEST_LENGTH) {
        EVP_MD_CTX_free(context);
        return -1;
    }
    EVP_MD_CTX_free(context);
    memcpy(out, "sha256:", 7);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out[7 + i * 2] = hex[digest[i] >> 4];
        out[7 + i * 2 + 1] = hex[digest[i] & 15];
    }
    out[7 + SHA256_DIGEST_LENGTH * 2] = '\0';
    return 0;
}

/* Structural validation shared by every operation that takes a candidate.
 * Returns NULL on success or the rejection reason. */
static const char *apd_config_candidate_check(struct json_object *candidate,
                                              struct json_object **sections_out)
{
    struct json_object *format = NULL;
    struct json_object *digest = NULL;
    struct json_object *sections = NULL;
    char computed[SHA256_DIGEST_LENGTH * 2 + 8];
    size_t i;

    *sections_out = NULL;
    if (!candidate || !json_object_is_type(candidate, json_type_object))
        return "candidate_not_object";
    {
        json_object_object_foreach(candidate, name, child) {
            (void)child;
            if (strcmp(name, "format") && strcmp(name, "candidate_digest") &&
                strcmp(name, "sections"))
                return "candidate_unknown_field";
        }
    }
    if (!json_object_object_get_ex(candidate, "format", &format) ||
        !format || !json_object_is_type(format, json_type_string) ||
        strcmp(json_object_get_string(format),
               APD_CONFIG_CANDIDATE_FORMAT))
        return "candidate_format_invalid";
    if (!json_object_object_get_ex(candidate, "sections", &sections) ||
        !sections || !json_object_is_type(sections, json_type_array) ||
        json_object_array_length(sections) == 0 ||
        json_object_array_length(sections) > APD_CONFIG_SECTIONS_MAX)
        return "candidate_sections_invalid";
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;
        size_t option_count = 0;

        if (!section || !json_object_is_type(section, json_type_object))
            return "candidate_section_invalid";
        {
            json_object_object_foreach(section, key, child) {
                (void)child;
                if (strcmp(key, "section") && strcmp(key, "options"))
                    return "candidate_section_unknown_field";
            }
        }
        if (!json_object_object_get_ex(section, "section", &name) || !name ||
            !json_object_is_type(name, json_type_string) ||
            !apd_config_name_valid(json_object_get_string(name)))
            return "candidate_section_name_invalid";
        if (!json_object_object_get_ex(section, "options", &options) ||
            !options || !json_object_is_type(options, json_type_object))
            return "candidate_options_invalid";
        json_object_object_foreach(options, option, value) {
            option_count++;
            if (!apd_config_option_allowed(option))
                return "candidate_option_not_allowed";
            if (!value || !json_object_is_type(value, json_type_string) ||
                !apd_config_value_valid(json_object_get_string(value)))
                return "candidate_value_invalid";
        }
        if (option_count == 0 || option_count > APD_CONFIG_OPTIONS_MAX)
            return "candidate_options_bounds";
    }
    if (!json_object_object_get_ex(candidate, "candidate_digest", &digest) ||
        !digest || !json_object_is_type(digest, json_type_string) ||
        apd_config_digest_hex(sections, computed) != 0 ||
        strcmp(json_object_get_string(digest), computed))
        return "candidate_digest_mismatch";
    *sections_out = sections;
    return NULL;
}

int apd_config_candidate_validate(struct json_object *candidate,
                                  struct json_object **out)
{
    struct json_object *sections = NULL;
    const char *reason;
    struct json_object *result;

    if (!out)
        return -1;
    reason = apd_config_candidate_check(candidate, &sections);
    if (reason)
        return apd_config_fail(out, "validate", reason, NULL);
    result = apd_config_result_new("validate");
    json_object_object_add(result, "complete", json_object_new_boolean(1));
    json_object_object_add(result, "sections", json_object_new_int(
        (int)json_object_array_length(sections)));
    return apd_config_ok(out, result);
}

static int apd_config_run(const struct apd_config_paths *paths,
                          char *const argv[],
                          struct apd_command_result *command)
{
    (void)paths;
    return apd_readonly_command_bounded(argv[0], argv,
                                        APD_CONFIG_COMMAND_TIMEOUT_MS,
                                        APD_CONFIG_COMMAND_OUTPUT_LIMIT,
                                        command) == 0 &&
           command->exit_status == 0 ? 0 : -1;
}

static void apd_config_key(char *buffer, size_t size, const char *section,
                           const char *option)
{
    snprintf(buffer, size, "wireless.%s.%s", section, option);
}

static void apd_config_assignment(char *buffer, size_t size,
                                  const char *section, const char *option,
                                  const char *value)
{
    snprintf(buffer, size, "wireless.%s.%s=%s", section, option, value);
}

static int apd_config_copy_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb");
    FILE *dst;
    char buffer[4096];
    size_t got;
    int failed = 0;

    if (!in)
        return -1;
    dst = fopen(to, "wb");
    if (!dst) {
        fclose(in);
        return -1;
    }
    while ((got = fread(buffer, 1, sizeof(buffer), in)) > 0)
        if (fwrite(buffer, 1, got, dst) != got)
            failed = 1;
    failed |= ferror(in);
    fclose(in);
    if (fclose(dst) != 0)
        failed = 1;
    return failed ? -1 : 0;
}

int apd_config_stage(const struct apd_config_paths *paths,
                     struct json_object *candidate,
                     struct json_object **out)
{
    struct json_object *sections = NULL;
    const char *reason;
    struct json_object *result;
    char source[512];
    char staged[512];
    size_t i;

    if (!out)
        return -1;
    if (!paths || !paths->uci || !paths->config_dir || !paths->staging_dir)
        return apd_config_fail(out, "stage", "paths_invalid", NULL);
    reason = apd_config_candidate_check(candidate, &sections);
    if (reason)
        return apd_config_fail(out, "stage", reason, NULL);
    snprintf(source, sizeof(source), "%s/wireless", paths->config_dir);
    snprintf(staged, sizeof(staged), "%s/wireless", paths->staging_dir);
    if (mkdir(paths->staging_dir, 0700) != 0 && errno != EEXIST)
        return apd_config_fail(out, "stage", "staging_dir_unavailable",
                               NULL);
    if (apd_config_copy_file(source, staged) != 0)
        return apd_config_fail(out, "stage", "wireless_config_unreadable",
                               NULL);
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        json_object_object_foreach(options, option, value) {
            char assignment[256];
            struct apd_command_result command = { 0 };
            char *const argv[] = {
                (char *)paths->uci, "-c", (char *)paths->staging_dir,
                "set", assignment, NULL
            };
            int failed;

            apd_config_assignment(assignment, sizeof(assignment),
                                  json_object_get_string(name), option,
                                  json_object_get_string(value));
            failed = apd_config_run(paths, argv, &command);
            if (failed) {
                int rc = apd_config_fail(out, "stage", "uci_set_failed",
                                         &command);

                apd_command_result_free(&command);
                return rc;
            }
            apd_command_result_free(&command);
        }
    }
    {
        struct apd_command_result command = { 0 };
        char *const argv[] = {
            (char *)paths->uci, "-c", (char *)paths->staging_dir,
            "commit", "wireless", NULL
        };

        if (apd_config_run(paths, argv, &command) != 0) {
            int rc = apd_config_fail(out, "stage", "uci_commit_failed",
                                     &command);

            apd_command_result_free(&command);
            return rc;
        }
        apd_command_result_free(&command);
    }
    result = apd_config_result_new("stage");
    json_object_object_add(result, "staged", json_object_new_boolean(1));
    json_object_object_add(result, "sections", json_object_new_int(
        (int)json_object_array_length(sections)));
    return apd_config_ok(out, result);
}

/* Read one option from the live config; returns 0 with *value_out set to
 * a string (caller frees) or NULL when the option is absent, -1 on
 * command failure. */
static int apd_config_get(const struct apd_config_paths *paths,
                          const char *section, const char *option,
                          char **value_out)
{
    char key[256];
    struct apd_command_result command = { 0 };
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)paths->config_dir,
        "get", key, NULL
    };
    int rc;

    *value_out = NULL;
    apd_config_key(key, sizeof(key), section, option);
    rc = apd_readonly_command_bounded(argv[0], argv,
                                      APD_CONFIG_COMMAND_TIMEOUT_MS,
                                      APD_CONFIG_COMMAND_OUTPUT_LIMIT,
                                      &command);
    /* uci get uses exit 1 for a legitimate missing option. Any other
     * runner/command failure must remain a readback failure. */
    if ((rc != 0 && command.exit_status != 1) ||
        command.exit_status > 1 || command.timed_out) {
        apd_command_result_free(&command);
        return -1;
    }
    if (command.exit_status == 0 && command.text) {
        size_t length = strlen(command.text);

        while (length > 0 && (command.text[length - 1] == '\n' ||
                              command.text[length - 1] == '\r'))
            command.text[--length] = '\0';
        *value_out = strdup(command.text);
    }
    apd_command_result_free(&command);
    return 0;
}

int apd_config_readback(const struct apd_config_paths *paths,
                        struct json_object *candidate,
                        struct json_object **out)
{
    struct json_object *sections = NULL;
    const char *reason;
    struct json_object *result;
    struct json_object *mismatches = json_object_new_array();
    struct json_object *actual_sections = json_object_new_array();
    char readback_digest[SHA256_DIGEST_LENGTH * 2 + 8];
    const char *candidate_digest = NULL;
    size_t i;

    if (!out) {
        json_object_put(mismatches);
        return -1;
    }
    if (!paths || !paths->uci || !paths->config_dir) {
        json_object_put(mismatches);
        json_object_put(actual_sections);
        return apd_config_fail(out, "readback", "paths_invalid", NULL);
    }
    reason = apd_config_candidate_check(candidate, &sections);
    if (reason) {
        json_object_put(mismatches);
        json_object_put(actual_sections);
        return apd_config_fail(out, "readback", reason, NULL);
    }
    json_object_object_get_ex(candidate, "candidate_digest", &result);
    candidate_digest = result ? json_object_get_string(result) : "";
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        {
            struct json_object *actual_section = json_object_new_object();
            struct json_object *actual_options = json_object_new_object();

            json_object_object_add(actual_section, "section",
                json_object_new_string(json_object_get_string(name)));
            json_object_object_add(actual_section, "options", actual_options);
            json_object_array_add(actual_sections, actual_section);
        }
        json_object_object_foreach(options, option, value) {
            char *actual = NULL;
            struct json_object *actual_section =
                json_object_array_get_idx(actual_sections,
                    json_object_array_length(actual_sections) - 1);
            struct json_object *actual_options = NULL;

            json_object_object_get_ex(actual_section, "options", &actual_options);

            if (apd_config_get(paths, json_object_get_string(name), option,
                               &actual) != 0) {
                json_object_put(mismatches);
                json_object_put(actual_sections);
                return apd_config_fail(out, "readback", "uci_get_failed",
                                       NULL);
            }
            if (actual)
                json_object_object_add(actual_options, option,
                    json_object_new_string(actual));
            else
                json_object_object_add(actual_options, option,
                    json_object_new_null());
            if (!actual ||
                strcmp(actual, json_object_get_string(value)) != 0) {
                struct json_object *entry = json_object_new_object();

                json_object_object_add(entry, "section",
                    json_object_new_string(json_object_get_string(name)));
                json_object_object_add(entry, "option",
                    json_object_new_string(option));
                json_object_object_add(entry, "expected",
                    json_object_new_string(json_object_get_string(value)));
                json_object_object_add(entry, "actual", actual ?
                    json_object_new_string(actual) : NULL);
                json_object_array_add(mismatches, entry);
            }
            free(actual);
        }
    }
    result = apd_config_result_new("readback");
    if (apd_config_readback_digest(actual_sections, readback_digest) != 0)
        readback_digest[0] = '\0';
    json_object_put(actual_sections);
    json_object_object_add(result, "candidate_digest",
                           json_object_new_string(candidate_digest));
    json_object_object_add(result, "readback_digest",
                           json_object_new_string(readback_digest));
    json_object_object_add(result, "match", json_object_new_boolean(
        json_object_array_length(mismatches) == 0));
    json_object_object_add(result, "mismatches", mismatches);
    return apd_config_ok(out, result);
}

static int apd_config_set_live(const struct apd_config_paths *paths,
                               const char *section, const char *option,
                               const char *value,
                               struct apd_command_result *command)
{
    char assignment[256];
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)paths->config_dir,
        "set", assignment, NULL
    };

    apd_config_assignment(assignment, sizeof(assignment), section, option,
                          value);
    return apd_config_run(paths, argv, command);
}

static int apd_config_delete_live(const struct apd_config_paths *paths,
                                  const char *section, const char *option,
                                  struct apd_command_result *command)
{
    char key[256];
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)paths->config_dir,
        "delete", key, NULL
    };

    apd_config_key(key, sizeof(key), section, option);
    return apd_config_run(paths, argv, command);
}

static int apd_config_commit_live(const struct apd_config_paths *paths,
                                  struct apd_command_result *command)
{
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)paths->config_dir,
        "commit", "wireless", NULL
    };

    return apd_config_run(paths, argv, command);
}

static int apd_config_reload(const struct apd_config_paths *paths,
                             const char *section,
                             struct apd_command_result *command)
{
    char *const argv[] = {
        (char *)paths->wifi, "reload", (char *)section, NULL
    };

    return apd_config_run(paths, argv, command);
}

/* Restore previously captured option values (value null = delete).  Used
 * by apply() failure paths and by rollback(); best effort, reports the
 * first failure but keeps restoring the remaining options. */
static int apd_config_restore(const struct apd_config_paths *paths,
                              struct json_object *previous_sections)
{
    size_t i;
    int failed = 0;

    for (i = 0; i < json_object_array_length(previous_sections); i++) {
        struct json_object *section =
            json_object_array_get_idx(previous_sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        json_object_object_foreach(options, option, value) {
            struct apd_command_result command = { 0 };
            int rc;

            if (value && !json_object_is_type(value, json_type_null))
                rc = apd_config_set_live(paths,
                    json_object_get_string(name), option,
                    json_object_get_string(value), &command);
            else
                rc = apd_config_delete_live(paths,
                    json_object_get_string(name), option, &command);
            failed |= rc != 0;
            apd_command_result_free(&command);
        }
    }
    {
        struct apd_command_result command = { 0 };

        failed |= apd_config_commit_live(paths, &command) != 0;
        apd_command_result_free(&command);
    }
    return failed ? -1 : 0;
}

int apd_config_rollback(const struct apd_config_paths *paths,
                        struct json_object *previous,
                        struct json_object **out);

int apd_config_capture_previous(const struct apd_config_paths *paths,
                                struct json_object *candidate,
                                struct json_object **out)
{
    struct json_object *sections = NULL;
    const char *reason;
    struct json_object *result;
    struct json_object *previous = json_object_new_array();
    size_t i;

    if (!out) {
        json_object_put(previous);
        return -1;
    }
    if (!paths || !paths->uci || !paths->config_dir) {
        json_object_put(previous);
        return apd_config_fail(out, "capture", "paths_invalid", NULL);
    }
    reason = apd_config_candidate_check(candidate, &sections);
    if (reason) {
        json_object_put(previous);
        return apd_config_fail(out, "capture", reason, NULL);
    }
    /* Capture the previous values first: they are the rollback
     * reference the caller must journal before anything mutates. */
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;
        struct json_object *captured = json_object_new_object();
        struct json_object *captured_options = json_object_new_object();

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        json_object_object_add(captured, "section",
            json_object_new_string(json_object_get_string(name)));
        json_object_object_foreach(options, option, value) {
            char *current = NULL;

            (void)value;
            if (apd_config_get(paths, json_object_get_string(name), option,
                               &current) != 0) {
                json_object_put(captured_options);
                json_object_put(captured);
                json_object_put(previous);
                return apd_config_fail(out, "capture",
                                       "previous_capture_failed", NULL);
            }
            json_object_object_add(captured_options, option, current ?
                json_object_new_string(current) : json_object_new_null());
            free(current);
        }
        json_object_object_add(captured, "options", captured_options);
        json_object_array_add(previous, captured);
    }
    result = apd_config_result_new("capture");
    json_object_object_add(result, "previous", previous);
    return apd_config_ok(out, result);
}

int apd_config_apply_prepared(const struct apd_config_paths *paths,
                              struct json_object *candidate,
                              struct json_object *previous,
                              struct json_object **out)
{
    struct json_object *sections = NULL;
    const char *reason;
    struct json_object *result;
    size_t i;

    if (!out)
        return -1;
    if (!paths || !paths->uci || !paths->wifi || !paths->config_dir ||
        !previous || !json_object_is_type(previous, json_type_array))
        return apd_config_fail(out, "apply",
                               "paths_or_previous_invalid", NULL);
    reason = apd_config_candidate_check(candidate, &sections);
    if (reason)
        return apd_config_fail(out, "apply", reason, NULL);
    if (json_object_array_length(previous) !=
        json_object_array_length(sections))
        return apd_config_fail(out, "apply", "previous_shape_invalid",
                               NULL);

    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct json_object *options = NULL;

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        json_object_object_foreach(options, option, value) {
            struct apd_command_result command = { 0 };

            if (apd_config_set_live(paths, json_object_get_string(name),
                                    option, json_object_get_string(value),
                                    &command) != 0) {
                int rc;
                int rollback_rc = apd_config_restore(paths, previous);

                rc = apd_config_fail(out, "apply",
                                     rollback_rc == 0 ? "uci_set_failed" :
                                     "rollback_failed",
                                     &command);
                json_object_object_add(*out, "rolled_back",
                                       json_object_new_boolean(rollback_rc == 0));
                apd_command_result_free(&command);
                return rc;
            }
            apd_command_result_free(&command);
        }
    }
    {
        struct apd_command_result command = { 0 };

        if (apd_config_commit_live(paths, &command) != 0) {
            int rc;
            int rollback_rc = apd_config_restore(paths, previous);

            rc = apd_config_fail(out, "apply",
                                 rollback_rc == 0 ? "uci_commit_failed" :
                                 "rollback_failed",
                                 &command);
            json_object_object_add(*out, "rolled_back",
                                   json_object_new_boolean(rollback_rc == 0));
            apd_command_result_free(&command);
            return rc;
        }
        apd_command_result_free(&command);
    }
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name = NULL;
        struct apd_command_result command = { 0 };

        json_object_object_get_ex(section, "section", &name);
        if (apd_config_reload(paths, json_object_get_string(name),
                              &command) != 0) {
            int rc;
            int rollback_rc = apd_config_restore(paths, previous);

            rc = apd_config_fail(out, "apply",
                                 rollback_rc == 0 ? "wifi_reload_failed" :
                                 "rollback_failed",
                                 &command);
            json_object_object_add(*out, "rolled_back",
                                   json_object_new_boolean(rollback_rc == 0));
            apd_command_result_free(&command);
            return rc;
        }
        apd_command_result_free(&command);
    }
    {
        struct json_object *readback = NULL;
        struct json_object *match = NULL;
        int readback_rc = apd_config_readback(paths, candidate, &readback);
        int matched = readback_rc == 0 && readback &&
            json_object_object_get_ex(readback, "match", &match) &&
            json_object_get_boolean(match);

        if (!matched) {
            struct json_object *rollback = NULL;
            int rollback_rc = apd_config_rollback(paths, previous, &rollback);
            struct json_object *rolled_back = rollback ?
                json_object_object_get(rollback, "rolled_back") : NULL;
            int rollback_ok = rollback_rc == 0 && rolled_back &&
                json_object_get_boolean(rolled_back);

            if (!rollback_ok) {
                int rc = apd_config_fail(out, "apply", "rollback_failed", NULL);
                json_object_object_add(*out, "rolled_back",
                                       json_object_new_boolean(0));
                json_object_object_add(*out, "readback", readback ?
                                       readback : json_object_new_null());
                if (readback)
                    json_object_get(readback);
                json_object_put(rollback);
                json_object_put(readback);
                return rc;
            }
            apd_config_fail(out, "apply",
                readback_rc == 0 ? "readback_mismatch" : "readback_failed", NULL);
            json_object_object_add(*out, "rolled_back",
                                   json_object_new_boolean(1));
            json_object_object_add(*out, "readback", readback ?
                                   readback : json_object_new_null());
            if (readback)
                json_object_get(readback);
            json_object_put(rollback);
            json_object_put(readback);
            return -1;
        }
        result = apd_config_result_new("apply");
        json_object_object_add(result, "applied", json_object_new_boolean(1));
        json_object_object_add(result, "readback", readback);
        return apd_config_ok(out, result);
    }
}

int apd_config_apply(const struct apd_config_paths *paths,
                     struct json_object *candidate,
                     struct json_object **out)
{
    struct json_object *capture = NULL;
    struct json_object *previous = NULL;
    struct json_object *apply = NULL;
    int rc;

    if (!out)
        return -1;
    if (apd_config_capture_previous(paths, candidate, &capture) != 0) {
        *out = capture;
        return -1;
    }
    if (!json_object_object_get_ex(capture, "previous", &previous)) {
        json_object_put(capture);
        return apd_config_fail(out, "apply", "previous_capture_failed",
                               NULL);
    }
    json_object_get(previous);
    json_object_put(capture);
    rc = apd_config_apply_prepared(paths, candidate, previous, &apply);
    if (rc == 0)
        json_object_object_add(apply, "previous", json_object_get(previous));
    json_object_put(previous);
    *out = apply;
    return rc;
}

int apd_config_rollback(const struct apd_config_paths *paths,
                        struct json_object *previous,
                        struct json_object **out)
{
    struct json_object *result;
    size_t i;

    if (!out)
        return -1;
    if (!paths || !paths->uci || !paths->wifi || !paths->config_dir)
        return apd_config_fail(out, "rollback", "paths_invalid", NULL);
    if (!previous || !json_object_is_type(previous, json_type_array) ||
        json_object_array_length(previous) == 0 ||
        json_object_array_length(previous) > APD_CONFIG_SECTIONS_MAX)
        return apd_config_fail(out, "rollback", "previous_invalid", NULL);
    if (apd_config_restore(paths, previous) != 0)
        return apd_config_fail(out, "rollback", "restore_failed", NULL);
    for (i = 0; i < json_object_array_length(previous); i++) {
        struct json_object *section =
            json_object_array_get_idx(previous, i);
        struct json_object *name = NULL;
        struct apd_command_result command = { 0 };

        json_object_object_get_ex(section, "section", &name);
        if (!name)
            continue;
        if (apd_config_reload(paths, json_object_get_string(name),
                              &command) != 0) {
            int rc = apd_config_fail(out, "rollback", "wifi_reload_failed",
                                     &command);

            apd_command_result_free(&command);
            return rc;
        }
        apd_command_result_free(&command);
    }
    result = apd_config_result_new("rollback");
    json_object_object_add(result, "rolled_back",
                           json_object_new_boolean(1));
    return apd_config_ok(out, result);
}

int apd_config_executor_available(const struct apd_config_paths *paths)
{
    char parent[4096];
    char *slash;

    if (!paths || !paths->uci || !paths->wifi || !paths->config_dir ||
        !paths->staging_dir)
        return 0;
    if (snprintf(parent, sizeof(parent), "%s", paths->staging_dir) >=
        (int)sizeof(parent))
        return 0;
    slash = strrchr(parent, '/');
    if (!slash)
        return 0;
    *slash = '\0';
    return access(paths->uci, X_OK) == 0 && access(paths->wifi, X_OK) == 0 &&
           access(paths->config_dir, R_OK | W_OK) == 0 &&
           access(parent[0] ? parent : "/", R_OK | W_OK | X_OK) == 0;
}

int apd_config_executor_available_default(void)
{
    struct apd_config_paths paths = {
        "/sbin/uci", "/sbin/wifi", "/etc/config",
        "/tmp/dreamingwrt-apd-config-candidate"
    };

    return apd_config_executor_available(&paths);
}
