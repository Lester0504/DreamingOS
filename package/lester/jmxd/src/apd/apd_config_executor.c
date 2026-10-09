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
 *         "options": { "channel": "6", "htmode": "EHT40" },
 *         "list_options": { "r0kh": ["mac,id,key", ...] } }
 *     ]
 *   }
 * The digest covers the canonical serialization (section name, then each
 * option as name=value in the given order, one per line).  Values are
 * printable ASCII only: the candidate travels over the ap-control wire,
 * whose strict parser rejects raw non-ASCII bytes (2026-07-26 finding).
 */
#include "apd_config_executor.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "../ap_mlo_members.h"
#include "apd_readonly_command.h"

static const char *const apd_config_option_allowlist[] = {
    "channel", "htmode", "txpower", "disabled", "ssid",
    /* wifi-iface (SSID) options.  Needed for SSID create/update/delete;
     * without these the transaction scope covered radio-level parameters
     * only, which is what capability `ssid_create` reported as
     * transaction_scope_not_supported.
     *
     * `key` (the WPA passphrase) is deliberately NOT here.  Rollback works by
     * journaling each option's previous value, so admitting `key` would write
     * the current passphrase in clear into the APD job journal -- exactly what
     * the phase2 secret-safe contract forbids.  Fixing that is not a matter of
     * redaction either: a redacted previous value cannot be restored, so the
     * rollback would quietly delete the passphrase instead of putting it back.
     * The passphrase needs a compensating transaction driven from the AC
     * secret store rather than a local restore, which is the work
     * `password_rotation` still reports as phase2_secret_safe_apply_pending.
     * apd_config_option_secret() below keeps the rejection explicit. */
    "device", "mode", "network", "encryption", "mlo",
    "dreamingwrt_mlo_members",
    "hidden", "isolate", "ifname", "ieee80211w", "wpa_group_rekey",
    "macfilter", "maxassoc",
    /* Roaming-domain 11r/k/v options (Phase 1). */
    "ieee80211r", "ieee80211k", "ieee80211v",
    "bss_transition", "rrm_neighbor_report", "rrm_beacon_report",
    "mobility_domain", "ft_over_ds", "ft_protocol",
    "nas_identifier",
    /* r0kh and r1kh are list options, handled via list_options. */
};

static const char *const apd_config_list_option_allowlist[] = {
    "r0kh", "r1kh", "device",
};

static int apd_config_get(const struct apd_config_paths *paths,
                          const char *section, const char *option,
                          char **value_out);
static int apd_config_set_live(const struct apd_config_paths *paths,
                               const char *section, const char *option,
                               const char *value,
                               struct apd_command_result *command);
static int apd_config_section_create_live(const struct apd_config_paths *paths,
                                          const char *section,
                                          const char *type,
                                          struct apd_command_result *command);
static int apd_config_section_drop_live(const struct apd_config_paths *paths,
                                        const char *section,
                                        struct apd_command_result *command);
static int apd_config_restore(const struct apd_config_paths *paths,
                              struct json_object *previous);
static int apd_config_mlo_key_sync(const struct apd_config_paths *paths,
                                   const char *config_dir,
                                   const char *section,
                                   int allow_missing_destination,
                                   struct apd_command_result *command);

/* Options whose value is secret material.  Their values must not appear in
 * results, evidence or logs; only the fact that they were set may. */
static int apd_config_option_secret(const char *name)
{
    return name && (!strcmp(name, "key") || !strcmp(name, "wpa_passphrase") ||
                    !strcmp(name, "auth_secret"));
}

static int apd_config_list_option_allowed(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(apd_config_list_option_allowlist) /
                    sizeof(apd_config_list_option_allowlist[0]); i++)
        if (!strcmp(name, apd_config_list_option_allowlist[i]))
            return 1;
    return 0;
}

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

static int apd_config_mlo_encryption_is_open(const char *value)
{
    return !value || !strcasecmp(value, "none") ||
           !strcasecmp(value, "open") || !strcasecmp(value, "owe");
}

/* Per-option value check.  Every option is a UCI scalar under the rule above
 * except `dreamingwrt_mlo_members`, whose value is the JSON record of the
 * pre-merge MLO membership: double quotes, and well past 64 bytes.  The AC
 * applies the identical check from the same header
 * (ac_config_candidate_option_value_valid), because a value one side accepts
 * and the other refuses becomes a journalled transaction that can only fail. */
static int apd_config_option_value_valid(const char *option,
                                         const char *value)
{
    if (dreamingwrt_mlo_members_option(option))
        return dreamingwrt_mlo_members_value_valid(value);
    return apd_config_value_valid(value);
}

/* Longest value any option may carry, used to size the `uci set` argument
 * buffers.  A scalar option needs 64 bytes; the MLO membership record needs
 * 4096, and truncating it would write half a JSON document into the config and
 * then fail readback against the candidate that produced it. */
#define APD_CONFIG_VALUE_MAX_ANY \
    (APD_CONFIG_VALUE_MAX > DREAMINGWRT_MLO_MEMBERS_VALUE_MAX ? \
     APD_CONFIG_VALUE_MAX : DREAMINGWRT_MLO_MEMBERS_VALUE_MAX)
/* "wireless." + section + "." + option + "=" + value + NUL, with room to
 * spare. */
#define APD_CONFIG_ASSIGNMENT_MAX (128U + APD_CONFIG_VALUE_MAX_ANY)

static int apd_config_option_allowed(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(apd_config_option_allowlist) /
                    sizeof(apd_config_option_allowlist[0]); i++)
        if (!strcmp(name, apd_config_option_allowlist[i]))
            return 1;
    return 0;
}

/* A UCI section *type* is not a section name.  The real types in
 * /etc/config/wireless are `wifi-iface` and `wifi-device`, both of which
 * apd_config_name_valid rejects, because a section *name* may not contain '-'.
 * So types get their own check -- and it is an allow-list rather than a
 * character class: the only type a candidate has any business creating is
 * `wifi-iface`, a VAP.  A `wifi-device` is a radio, enumerated from the
 * hardware that is present, and inventing one would describe a radio that does
 * not exist.  Widen this only together with a caller that needs it.
 *
 * Rollback does not come through here: apd_config_restore recreates a deleted
 * section with the type it captured from live config, which is ground truth and
 * must not be second-guessed while things are already going wrong. */
static int apd_config_section_type_allowed(const char *value)
{
    return value && !strcmp(value, "wifi-iface");
}

/* A section with no explicit operation is a plain option update, which is
 * what every candidate written before SSID CRUD existed means. */
static const char *apd_config_section_operation(struct json_object *section)
{
    struct json_object *operation = NULL;

    if (section && json_object_object_get_ex(section, "operation", &operation) &&
        operation && json_object_is_type(operation, json_type_string))
        return json_object_get_string(operation);
    return "set";
}

static int apd_config_digest_hex_internal(struct json_object *sections,
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

        /* +32 covers the "!<operation>\n" line emitted below. */
        capacity += APD_CONFIG_NAME_MAX + 2 + 32;
        json_object_object_get_ex(section, "options", &options);
        json_object_object_foreach(options, option, value) {
            const char *text = json_object_get_string(value);

            /* Reserve the value's real length, not the scalar maximum: the MLO
             * membership record is 4096 bytes wide, so a fixed 64-byte
             * allowance under-sizes the buffer, `used` reaches `capacity`, and
             * the digest silently comes out of a truncated canonical form --
             * which then never matches the AC's. */
            capacity += strlen(option) + (text ? strlen(text) : 0) + 3;
        }
        {
            struct json_object *lo = NULL;

            json_object_object_get_ex(section, "list_options", &lo);
            if (lo) {
                json_object_object_foreach(lo, lo_name, lo_values) {
                    size_t k;
    
                    for (k = 0; k < json_object_array_length(lo_values); k++) {
                        struct json_object *entry =
                            json_object_array_get_idx(lo_values, k);
                        const char *text = json_object_get_string(entry);

                        capacity += strlen(lo_name) +
                                    (text ? strlen(text) : 0) + 3;
                    }
                }
            }
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
        /* Bind the operation into the digest, or a candidate could be flipped
         * from create to delete without changing its digest and the signature
         * would still verify.  Emitted only when it is not the default "set"
         * so every candidate written before SSID CRUD keeps its digest. */
        {
            const char *op = apd_config_section_operation(section);

            if (strcmp(op, "set"))
                used += (size_t)snprintf(canonical + used, capacity - used,
                                         "!%s\n", op);
        }
        json_object_object_foreach(options, option, value) {
            used += (size_t)snprintf(canonical + used, capacity - used,
                                     "%s=%s\n", option,
                                     json_object_get_string(value));
        }
        {
            struct json_object *lo = NULL;

            json_object_object_get_ex(section, "list_options", &lo);
            if (lo) {
                json_object_object_foreach(lo, lo_name, lo_values) {
                    size_t k;
    
                    for (k = 0; k < json_object_array_length(lo_values); k++) {
                        struct json_object *entry =
                            json_object_array_get_idx(lo_values, k);
    
                        used += (size_t)snprintf(canonical + used, capacity - used,
                                                 "%s=%s\n", lo_name,
                                                 json_object_get_string(entry));
                    }
                }
            }
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

/* Public wrapper: recompute the canonical digest for a section array.
 *
 * The AP backend splits a candidate into UCI sections and hostapd-action
 * sections and applies only the former.  That subset needs its own digest --
 * carrying the whole candidate's digest onto a subset makes every mixed
 * candidate fail candidate_check with candidate_digest_mismatch.  The caller
 * must verify the full candidate's digest first; this only restates the
 * digest for a subset that has already been authenticated as part of it. */
int apd_config_candidate_digest(struct json_object *sections,
                                char *out, size_t out_len)
{
    char computed[SHA256_DIGEST_LENGTH * 2 + 8];

    if (!sections || !out || out_len < sizeof(computed))
        return -1;
    if (apd_config_digest_hex_internal(sections, computed) != 0)
        return -1;
    memcpy(out, computed, sizeof(computed));
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
        /* Mirror apd_config_digest_hex_internal exactly: the two digests sit
         * next to each other in ac_transaction_targets and are compared. */
        {
            const char *op = apd_config_section_operation(section);

            if (strcmp(op, "set")) {
                EVP_DigestUpdate(context, "!", 1);
                EVP_DigestUpdate(context, op, strlen(op));
                EVP_DigestUpdate(context, "\n", 1);
            }
        }
        json_object_object_foreach(options, option, value) {
            const char *actual = value &&
                !json_object_is_type(value, json_type_null) ?
                json_object_get_string(value) : "<missing>";
            EVP_DigestUpdate(context, option, strlen(option));
            EVP_DigestUpdate(context, "=", 1);
            EVP_DigestUpdate(context, actual, strlen(actual));
            EVP_DigestUpdate(context, "\n", 1);
        }
        {
            struct json_object *lo = NULL;

            json_object_object_get_ex(section, "list_options", &lo);
            if (lo) {
                json_object_object_foreach(lo, lo_name, lo_values) {
                    size_t k;
    
                    for (k = 0; k < json_object_array_length(lo_values); k++) {
                        struct json_object *entry =
                            json_object_array_get_idx(lo_values, k);
                        const char *actual = entry &&
                            !json_object_is_type(entry, json_type_null) ?
                            json_object_get_string(entry) : "<missing>";
    
                        EVP_DigestUpdate(context, lo_name, strlen(lo_name));
                        EVP_DigestUpdate(context, "=", 1);
                        EVP_DigestUpdate(context, actual, strlen(actual));
                        EVP_DigestUpdate(context, "\n", 1);
                    }
                }
            }
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
                if (strcmp(key, "section") && strcmp(key, "options") &&
                    strcmp(key, "list_options") && strcmp(key, "operation") &&
                    strcmp(key, "section_type"))
                    return "candidate_section_unknown_field";
            }
        }
        if (!json_object_object_get_ex(section, "section", &name) || !name ||
            !json_object_is_type(name, json_type_string) ||
            !apd_config_name_valid(json_object_get_string(name)))
            return "candidate_section_name_invalid";
        {
            struct json_object *operation = NULL;
            struct json_object *section_type = NULL;
            const char *op;

            if (json_object_object_get_ex(section, "operation", &operation)) {
                if (!operation ||
                    !json_object_is_type(operation, json_type_string))
                    return "candidate_operation_invalid";
                op = json_object_get_string(operation);
                if (strcmp(op, "set") && strcmp(op, "create") &&
                    strcmp(op, "delete"))
                    return "candidate_operation_invalid";
                /* A create needs a type to create the section as; a set or a
                 * delete must not carry one, so the field cannot be used to
                 * retype an existing section behind the operation's back. */
                if (!strcmp(op, "create")) {
                    if (!json_object_object_get_ex(section, "section_type",
                                                   &section_type) ||
                        !section_type ||
                        !json_object_is_type(section_type, json_type_string) ||
                        !apd_config_section_type_allowed(
                            json_object_get_string(section_type)))
                        return "candidate_section_type_invalid";
                } else if (json_object_object_get_ex(section, "section_type",
                                                     &section_type)) {
                    return "candidate_section_type_unexpected";
                }
            } else if (json_object_object_get_ex(section, "section_type",
                                                 &section_type)) {
                return "candidate_section_type_unexpected";
            }
        }
        if (!json_object_object_get_ex(section, "options", &options) ||
            !options || !json_object_is_type(options, json_type_object))
            return "candidate_options_invalid";
        json_object_object_foreach(options, option, value) {
            option_count++;
            /* Checked before the allow-list so the caller is told the real
             * reason rather than a generic "not allowed". */
            if (apd_config_option_secret(option))
                return "candidate_option_secret_not_supported";
            if (!apd_config_option_allowed(option))
                return "candidate_option_not_allowed";
            if (!value || !json_object_is_type(value, json_type_string) ||
                !apd_config_option_value_valid(
                    option, json_object_get_string(value)))
                return "candidate_value_invalid";
        }
        /* Validate list_options if present. */
        {
            struct json_object *list_options = NULL;

            if (json_object_object_get_ex(section, "list_options",
                                          &list_options)) {
                size_t list_option_count = 0;

                if (!json_object_is_type(list_options, json_type_object))
                    return "candidate_list_options_invalid";
                if (list_options) {
                    json_object_object_foreach(list_options, option, values) {
                        size_t j;
    
                        list_option_count++;
                        if (!apd_config_list_option_allowed(option))
                            return "candidate_list_option_not_allowed";
                        if (!values ||
                            !json_object_is_type(values, json_type_array) ||
                            json_object_array_length(values) == 0 ||
                            json_object_array_length(values) >
                                APD_CONFIG_LIST_OPTIONS_MAX)
                            return "candidate_list_option_values_invalid";
                        for (j = 0; j < json_object_array_length(values); j++) {
                            struct json_object *entry =
                                json_object_array_get_idx(values, j);
    
                            if (!entry ||
                                !json_object_is_type(entry, json_type_string) ||
                                !apd_config_value_valid(
                                    json_object_get_string(entry)))
                                return "candidate_list_option_value_invalid";
                        }
                    }
                }
                option_count += list_option_count;
            }
        }
        /* A delete removes the whole section, so it legitimately carries no
         * options; every other operation must name at least one. */
        if ((option_count == 0 &&
             strcmp(apd_config_section_operation(section), "delete")) ||
            option_count > APD_CONFIG_OPTIONS_MAX)
            return "candidate_options_bounds";
    }
    if (!json_object_object_get_ex(candidate, "candidate_digest", &digest) ||
        !digest || !json_object_is_type(digest, json_type_string) ||
        apd_config_digest_hex_internal(sections, computed) != 0 ||
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

int apd_config_hostapd_actions_validate(struct json_object *candidate,
                                        struct json_object **out)
{
    static const char *const types[] = {
        "set_neighbor", "del_neighbor", "btm_request", "beacon_request",
        "deauth_request", "reassoc_block"
    };
    static const char *const allowed[] = {
        "hostapd_action_type", "station_mac",
        "neighbor_bssid", "neighbor_ssid", "neighbor_opclass",
        "neighbor_channel", "neighbor_phy", "neighbor_ft",
        "source_bssid", "source_ssid",
        "target_bssid", "target_opclass", "target_channel", "target_phy",
        "target_ft", "btm_validity",
        "target_bssid_2", "target_opclass_2", "target_channel_2",
        "target_phy_2", "target_ft_2", "btm_disassoc_imminent",
        "btm_disassoc_timer",
        "measure_opclass", "measure_channel", "measure_duration_tu",
        "measure_ssid", "measure_bssid", "deauth_reason", "block_scope",
        "block_duration_sec", "target_frequency_mhz",
        "block_not_after"
    };
    struct json_object *sections, *format, *digest;
    struct json_object *result;
    char computed[APD_CONFIG_DIGEST_MAX];
    const char *reason = "hostapd_action_candidate_invalid";
    size_t i;

    if (!out)
        return -1;
    if (!candidate || !json_object_is_type(candidate, json_type_object))
        goto fail;
    sections = json_object_object_get(candidate, "sections");
    format = json_object_object_get(candidate, "format");
    digest = json_object_object_get(candidate, "candidate_digest");
    if (!format || !json_object_is_type(format, json_type_string) ||
        strcmp(json_object_get_string(format), APD_CONFIG_CANDIDATE_FORMAT) ||
        !sections || !json_object_is_type(sections, json_type_array) ||
        !json_object_array_length(sections) ||
        json_object_array_length(sections) > APD_CONFIG_SECTIONS_MAX)
        goto fail;
    json_object_object_foreach(candidate, key, value) {
        (void)value;
        if (strcmp(key, "format") && strcmp(key, "sections") &&
            strcmp(key, "candidate_digest"))
            goto fail;
    }
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *name, *options, *type;
        const char *text;
        size_t j, length, option_limit = APD_CONFIG_OPTIONS_MAX;

        if (!section || !json_object_is_type(section, json_type_object))
            goto fail;
        name = json_object_object_get(section, "section");
        options = json_object_object_get(section, "options");
        if (!name || !json_object_is_type(name, json_type_string) ||
            !options || !json_object_is_type(options, json_type_object))
            goto fail;
        type = json_object_object_get(options, "hostapd_action_type");
        if (!type || !json_object_is_type(type, json_type_string)) {
            reason = "hostapd_actions_mixed_with_uci";
            goto fail;
        }
        json_object_object_foreach(section, key, value) {
            (void)value;
            if (strcmp(key, "section") && strcmp(key, "options"))
                goto fail;
        }
        text = json_object_get_string(name);
        length = strlen(text);
        if (!length || length > APD_CONFIG_NAME_MAX)
            goto fail;
        for (j = 0; j < length; j++)
            if (!isalnum((unsigned char)text[j]) &&
                text[j] != '_' && text[j] != '-' &&
                text[j] != '.' && text[j] != ':')
                goto fail;
        for (j = 0; j < sizeof(types) / sizeof(types[0]); j++)
            if (!strcmp(json_object_get_string(type), types[j]))
                break;
        if (j == sizeof(types) / sizeof(types[0])) {
            reason = "hostapd_action_type_invalid";
            goto fail;
        }
        /* BTM candidate 2 and imminent controls fit under the shared bound. */
        if (!strcmp(json_object_get_string(type), "reassoc_block"))
            option_limit = 10;
        if ((size_t)json_object_object_length(options) > option_limit)
            goto fail;
        json_object_object_foreach(options, option_key, option_value) {
            for (j = 0; j < sizeof(allowed) / sizeof(allowed[0]); j++)
                if (!strcmp(option_key, allowed[j]))
                    break;
            if (j == sizeof(allowed) / sizeof(allowed[0]) ||
                !option_value ||
                !json_object_is_type(option_value, json_type_string)) {
                reason = "hostapd_action_option_invalid";
                goto fail;
            }
            text = json_object_get_string(option_value);
            length = strlen(text);
            if (!length || length > APD_CONFIG_VALUE_MAX)
                goto fail;
            for (j = 0; j < length; j++)
                if ((unsigned char)text[j] < 32 || text[j] == 127)
                    goto fail;
        }
        if (!strcmp(json_object_get_string(type), "reassoc_block")) {
            static const char *const required[] = {
                "station_mac", "source_bssid", "source_ssid", "target_bssid",
                "block_scope", "block_duration_sec", "block_not_after"
            };
            const char *scope;
            char *end;
            long duration;

            /* One lease is atomic; do not mix it with other runtime writes. */
            if (json_object_array_length(sections) != 1)
                goto fail;
            for (j = 0; j < sizeof(required) / sizeof(required[0]); j++)
                if (!json_object_object_get(options, required[j]))
                    goto fail;
            scope = json_object_get_string(
                json_object_object_get(options, "block_scope"));
            if (strcmp(scope, "bss") && strcmp(scope, "ap") &&
                strcmp(scope, "band") && strcmp(scope, "lower"))
                goto fail;
            if (!strcmp(scope, "lower")) {
                long target_frequency;

                text = json_object_get_string(json_object_object_get(
                    options, "target_frequency_mhz"));
                if (!text)
                    goto fail;
                target_frequency = strtol(text, &end, 10);
                if (*end || target_frequency < 2400 ||
                    target_frequency > 7125)
                    goto fail;
            }
            text = json_object_get_string(
                json_object_object_get(options, "block_duration_sec"));
            duration = strtol(text, &end, 10);
            if (*end || duration < 1 || duration > 30)
                goto fail;
            text = json_object_get_string(
                json_object_object_get(options, "block_not_after"));
            if (strtoll(text, &end, 10) <= 0 || *end)
                goto fail;
        }
    }
    if (!digest || !json_object_is_type(digest, json_type_string) ||
        apd_config_candidate_digest(sections, computed, sizeof(computed)) != 0 ||
        strcmp(json_object_get_string(digest), computed)) {
        reason = "candidate_digest_mismatch";
        goto fail;
    }
    result = apd_config_result_new("validate");
    json_object_object_add(result, "runtime_actions", json_object_new_boolean(1));
    return apd_config_ok(out, result);
fail:
    return apd_config_fail(out, "validate", reason, NULL);
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

static int apd_config_add_list(const struct apd_config_paths *paths,
                               const char *config_dir,
                               const char *section, const char *option,
                               const char *value)
{
    char assignment[APD_CONFIG_ASSIGNMENT_MAX];
    struct apd_command_result command = { 0 };
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)config_dir,
        "add_list", assignment, NULL
    };
    int rc;

    apd_config_assignment(assignment, sizeof(assignment), section, option,
                          value);
    rc = apd_config_run(paths, argv, &command);
    apd_command_result_free(&command);
    return rc;
}

/* Clear an option in <config_dir> before a list is written.
 *
 * `uci add_list` appends: replaying a candidate, or promoting an option that
 * already holds a scalar (device=radio0 becoming a three-radio MLO list),
 * would otherwise leave the old value in front of the new list and fail
 * readback with a duplicated first element.  A missing option makes `uci
 * delete` exit non-zero, which is the desired end state here, so the status
 * is deliberately ignored. */
static void apd_config_clear_option(const struct apd_config_paths *paths,
                                    const char *config_dir,
                                    const char *section, const char *option)
{
    char key[256];
    struct apd_command_result command = { 0 };
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)config_dir,
        "delete", key, NULL
    };

    apd_config_key(key, sizeof(key), section, option);
    (void)apd_config_run(paths, argv, &command);
    apd_command_result_free(&command);
}

/* Read a section's UCI type.  `uci get wireless.<name>` prints the type for a
 * section, so this doubles as the existence probe: *type_out NULL means the
 * section is absent, which is a normal answer, not a failure.  Only a genuine
 * command failure returns -1 -- conflating the two would make a broken uci
 * look like "section not there" and let a create silently clobber. */
static int apd_config_section_type(const struct apd_config_paths *paths,
                                   const char *section, char **type_out)
{
    char key[256];
    struct apd_command_result command = { 0 };
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)paths->config_dir,
        "get", key, NULL
    };
    int rc;

    *type_out = NULL;
    snprintf(key, sizeof(key), "wireless.%s", section);
    rc = apd_readonly_command_bounded(argv[0], argv,
                                      APD_CONFIG_COMMAND_TIMEOUT_MS,
                                      APD_CONFIG_COMMAND_OUTPUT_LIMIT,
                                      &command);
    /* Same convention as apd_config_get: exit 1 is a legitimate "absent". */
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
        if (length)
            *type_out = strdup(command.text);
    }
    apd_command_result_free(&command);
    return 0;
}

/* Create or confirm a named section: `uci set wireless.<name>=<type>`.
 * UCI makes this idempotent when the section already exists with that type,
 * so a replayed transaction cannot produce a duplicate section. */
static int apd_config_section_create_live(const struct apd_config_paths *paths,
                                          const char *section,
                                          const char *type,
                                          struct apd_command_result *command)
{
    char assignment[256];
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)paths->config_dir,
        "set", assignment, NULL
    };

    snprintf(assignment, sizeof(assignment), "wireless.%s=%s", section, type);
    return apd_config_run(paths, argv, command);
}

/* Remove an entire named section: `uci delete wireless.<name>`. */
static int apd_config_section_drop_live(const struct apd_config_paths *paths,
                                        const char *section,
                                        struct apd_command_result *command)
{
    char key[256];
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)paths->config_dir,
        "delete", key, NULL
    };

    snprintf(key, sizeof(key), "wireless.%s", section);
    return apd_config_run(paths, argv, command);
}

/* Snapshot every option of a section via `uci show wireless.<name>` so a
 * section we are about to delete can be put back exactly as it was.
 * Capturing only the options the candidate happens to name would silently
 * drop the rest of the section the moment a rollback fired -- for a wifi-iface
 * that means losing the encryption mode or the network binding while the SSID
 * itself comes back, which is worse than not rolling back at all.
 *
 * `uci show` renders a list as `key='a' 'b'`, so a value containing the
 * quote-space-quote separator is split back into a list. */
static int apd_config_section_export(const struct apd_config_paths *paths,
                                     const char *section,
                                     struct json_object **options_out,
                                     struct json_object **list_options_out)
{
    char key[256];
    struct apd_command_result command = { 0 };
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)paths->config_dir,
        "show", key, NULL
    };
    struct json_object *options = json_object_new_object();
    struct json_object *list_options = json_object_new_object();
    char *cursor;
    int rc;

    *options_out = NULL;
    *list_options_out = NULL;
    snprintf(key, sizeof(key), "wireless.%s", section);
    rc = apd_readonly_command_bounded(argv[0], argv,
                                      APD_CONFIG_COMMAND_TIMEOUT_MS,
                                      APD_CONFIG_COMMAND_OUTPUT_LIMIT,
                                      &command);
    if ((rc != 0 && command.exit_status != 1) ||
        command.exit_status > 1 || command.timed_out) {
        json_object_put(options);
        json_object_put(list_options);
        apd_command_result_free(&command);
        return -1;
    }
    cursor = command.text;
    while (cursor && *cursor) {
        char *line = cursor;
        char *newline = strchr(cursor, '\n');
        char *equals;
        char *option;
        char *value;
        size_t value_len;

        if (newline) {
            *newline = '\0';
            cursor = newline + 1;
        } else {
            cursor = NULL;
        }
        equals = strchr(line, '=');
        if (!equals)
            continue;
        *equals = '\0';
        value = equals + 1;
        /* Skip the type line `wireless.<name>=wifi-iface`: it has no dot
         * after the section name and is recorded separately. */
        option = strrchr(line, '.');
        if (!option || option == strchr(line, '.'))
            continue;
        option++;
        if (!apd_config_name_valid(option))
            continue;
        value_len = strlen(value);
        if (value_len >= 2 && value[0] == '\'' && value[value_len - 1] == '\'') {
            value[value_len - 1] = '\0';
            value++;
            value_len -= 2;
        }
        if (strstr(value, "' '")) {
            struct json_object *values = json_object_new_array();
            char *item = value;

            while (item) {
                char *sep = strstr(item, "' '");

                if (sep)
                    *sep = '\0';
                json_object_array_add(values, json_object_new_string(item));
                item = sep ? sep + 3 : NULL;
            }
            json_object_object_add(list_options, option, values);
        } else {
            json_object_object_add(options, option,
                                   json_object_new_string(value));
        }
    }
    apd_command_result_free(&command);
    *options_out = options;
    *list_options_out = list_options;
    return 0;
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
        struct json_object *section_type = NULL;
        const char *operation = apd_config_section_operation(section);
        struct apd_config_paths staged_paths = *paths;

        staged_paths.config_dir = paths->staging_dir;

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        if (!strcmp(operation, "create")) {
            struct apd_command_result command = { 0 };

            json_object_object_get_ex(section, "section_type", &section_type);
            if (apd_config_section_create_live(&staged_paths,
                    json_object_get_string(name),
                    json_object_get_string(section_type), &command) != 0) {
                int rc = apd_config_fail(out, "stage", "uci_add_failed",
                                         &command);

                apd_command_result_free(&command);
                return rc;
            }
            apd_command_result_free(&command);
        } else if (!strcmp(operation, "delete")) {
            struct apd_command_result command = { 0 };

            (void)apd_config_section_drop_live(&staged_paths,
                json_object_get_string(name), &command);
            apd_command_result_free(&command);
            continue;
        }
        json_object_object_foreach(options, option, value) {
            char assignment[APD_CONFIG_ASSIGNMENT_MAX];
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
        {
            struct apd_command_result command = { 0 };
            int key_rc = apd_config_mlo_key_sync(&staged_paths,
                paths->staging_dir, json_object_get_string(name), 1,
                &command);

            if (key_rc != 0) {
                const char *reason = key_rc == -2 ?
                    "mlo_source_key_unavailable" :
                    key_rc == -3 ? "mlo_credentials_mismatch" :
                    key_rc == -4 ? "mlo_key_set_failed" :
                    "mlo_key_probe_failed";
                int rc = apd_config_fail(out, "stage", reason,
                                         command.exit_status >= 0 ?
                                         &command : NULL);

                apd_command_result_free(&command);
                return rc;
            }
            apd_command_result_free(&command);
        }
        /* Handle list options (r0kh, r1kh) via uci add_list. */
        {
            struct json_object *list_options = NULL;

            json_object_object_get_ex(section, "list_options",
                                      &list_options);
            if (list_options) {
                json_object_object_foreach(list_options, option, values) {
                    size_t k;
    
                    apd_config_clear_option(paths, paths->staging_dir,
                                            json_object_get_string(name),
                                            option);
                    for (k = 0; k < json_object_array_length(values); k++) {
                        struct json_object *entry =
                            json_object_array_get_idx(values, k);
    
                        if (apd_config_add_list(paths, paths->staging_dir,
                                                json_object_get_string(name),
                                                option,
                                                json_object_get_string(entry)) != 0) {
                            return apd_config_fail(out, "stage",
                                                   "uci_add_list_failed", NULL);
                        }
                    }
                }
            }
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

/* Copy the source wifi-iface key into a newly-created MLO wifi-iface without
 * putting the secret in the candidate, digest, journal or readback.  A
 * pre-existing destination must already have a matching key: changing it
 * would make rollback impossible because candidate journals are intentionally
 * secret-free. */
static int apd_config_mlo_key_sync(const struct apd_config_paths *paths,
                                   const char *config_dir,
                                   const char *section,
                                   int allow_missing_destination,
                                   struct apd_command_result *command)
{
    struct apd_config_paths target;
    char *mlo = NULL;
    char *members = NULL;
    char *encryption = NULL;
    char *source_key = NULL;
    char *destination_key = NULL;
    struct json_object *root = NULL;
    struct json_object *member_list = NULL;
    struct json_object *member = NULL;
    struct json_object *source_name = NULL;
    const char *source_section;
    int rc = -1;

    if (!paths || !config_dir || !section)
        return -1;
    target = *paths;
    target.config_dir = config_dir;
    if (apd_config_get(&target, section, "mlo", &mlo) != 0 ||
        !mlo || strcmp(mlo, "1")) {
        rc = 0;
        goto done;
    }
    if (apd_config_get(&target, section, "encryption", &encryption) != 0)
        goto done;
    if (apd_config_mlo_encryption_is_open(encryption)) {
        rc = 0;
        goto done;
    }
    if (apd_config_get(&target, section, DREAMINGWRT_MLO_MEMBERS_OPTION,
                       &members) != 0 ||
        !members || !dreamingwrt_mlo_members_value_valid(members))
        goto done;
    root = json_tokener_parse(members);
    if (!root || !json_object_object_get_ex(root, "members", &member_list) ||
        json_object_array_length(member_list) == 0)
        goto done;
    member = json_object_array_get_idx(member_list, 0);
    if (!member || !json_object_object_get_ex(member, "section", &source_name))
        goto done;
    source_section = json_object_get_string(source_name);
    if (apd_config_get(&target, source_section, "key", &source_key) != 0)
        goto done;
    if (!source_key || !source_key[0]) {
        rc = -2;
        goto done;
    }
    if (apd_config_get(&target, section, "key", &destination_key) != 0)
        goto done;
    if (destination_key && destination_key[0]) {
        rc = strcmp(destination_key, source_key) == 0 ? 0 : -3;
        goto done;
    }
    if (!allow_missing_destination) {
        rc = -5;
        goto done;
    }
    rc = apd_config_set_live(&target, section, "key", source_key, command) == 0
        ? 0 : -4;
done:
    free(mlo);
    free(members);
    free(encryption);
    free(source_key);
    free(destination_key);
    if (root)
        json_object_put(root);
    return rc;
}

/* Read a list option from the live config; returns 0 with *values_out
 * set to a JSON array of strings (caller frees) or NULL when the option
 * is absent, -1 on command failure. */
static int apd_config_get_list(const struct apd_config_paths *paths,
                               const char *section, const char *option,
                               struct json_object **values_out)
{
    char key[256];
    struct apd_command_result command = { 0 };
    char *const argv[] = {
        (char *)paths->uci, "-c", (char *)paths->config_dir,
        "get", key, NULL
    };
    int rc;

    *values_out = NULL;
    apd_config_key(key, sizeof(key), section, option);
    rc = apd_readonly_command_bounded(argv[0], argv,
                                      APD_CONFIG_COMMAND_TIMEOUT_MS,
                                      APD_CONFIG_COMMAND_OUTPUT_LIMIT,
                                      &command);
    if ((rc != 0 && command.exit_status != 1) ||
        command.exit_status > 1 || command.timed_out) {
        apd_command_result_free(&command);
        return -1;
    }
    if (command.exit_status == 0 && command.text) {
        char *text = strdup(command.text);
        char *saveptr = NULL;
        char *token;
        struct json_object *values = json_object_new_array();

        if (!text) {
            json_object_put(values);
            apd_command_result_free(&command);
            return -1;
        }
        /* Strip trailing newline. */
        {
            size_t length = strlen(text);

            while (length > 0 && (text[length - 1] == '\n' ||
                                  text[length - 1] == '\r'))
                text[--length] = '\0';
        }
        /* `uci get` prints list values separated by spaces on real OpenWrt.
         * The fixture historically emitted one value per line, so accept
         * both forms. Candidate list values are validated as whitespace-free
         * UCI atoms before reaching this reader. */
        for (token = strtok_r(text, " \t\r\n", &saveptr); token;
             token = strtok_r(NULL, " \t\r\n", &saveptr)) {
            /* Skip leading whitespace. */
            while (*token == ' ' || *token == '\t')
                token++;
            if (*token)
                json_object_array_add(values,
                    json_object_new_string(token));
        }
        free(text);
        if (json_object_array_length(values) == 0) {
            json_object_put(values);
            values = NULL;
        }
        *values_out = values;
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
        const char *operation = apd_config_section_operation(section);

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        {
            struct json_object *actual_section = json_object_new_object();
            struct json_object *actual_options = json_object_new_object();
            struct json_object *actual_list_options = json_object_new_object();

            json_object_object_add(actual_section, "section",
                json_object_new_string(json_object_get_string(name)));
            /* Carry the operation onto the observed section so the readback
             * digest canonicalises the same way the candidate digest does. */
            if (strcmp(operation, "set"))
                json_object_object_add(actual_section, "operation",
                    json_object_new_string(operation));
            json_object_object_add(actual_section, "options", actual_options);
            json_object_object_add(actual_section, "list_options",
                                   actual_list_options);
            json_object_array_add(actual_sections, actual_section);
        }
        /* Verify the section-level outcome.  A delete carries no options, so
         * without this the option loop below compares nothing, trivially
         * "matches", and a delete that silently did nothing reports success. */
        if (strcmp(operation, "set")) {
            char *live_type = NULL;
            int want_present = !strcmp(operation, "create");

            if (apd_config_section_type(paths, json_object_get_string(name),
                                        &live_type) != 0) {
                json_object_put(mismatches);
                json_object_put(actual_sections);
                return apd_config_fail(out, "readback", "uci_get_failed",
                                       NULL);
            }
            {
                struct json_object *actual_section =
                    json_object_array_get_idx(actual_sections,
                        json_object_array_length(actual_sections) - 1);

                json_object_object_add(actual_section, "section_present",
                    json_object_new_boolean(live_type != NULL));
            }
            if (want_present != (live_type != NULL)) {
                struct json_object *entry = json_object_new_object();

                json_object_object_add(entry, "section",
                    json_object_new_string(json_object_get_string(name)));
                json_object_object_add(entry, "option",
                    json_object_new_string("<section>"));
                json_object_object_add(entry, "expected",
                    json_object_new_string(want_present ? "present" :
                                           "absent"));
                json_object_object_add(entry, "actual",
                    json_object_new_string(live_type ? "present" : "absent"));
                json_object_array_add(mismatches, entry);
            }
            free(live_type);
            if (!want_present) {
                /* Nothing further to read back on a section that should be
                 * gone; reading its options would only re-report absence. */
                continue;
            }
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
        /* Read back list options. */
        {
            struct json_object *list_options = NULL;
            struct json_object *actual_section =
                json_object_array_get_idx(actual_sections,
                    json_object_array_length(actual_sections) - 1);
            struct json_object *actual_list_options = NULL;

            json_object_object_get_ex(section, "list_options", &list_options);
            json_object_object_get_ex(actual_section, "list_options",
                                      &actual_list_options);
            if (list_options) {
                json_object_object_foreach(list_options, lo_name, expected_values) {
                    struct json_object *actual_values = NULL;
    
                    if (apd_config_get_list(paths, json_object_get_string(name),
                                            lo_name, &actual_values) != 0) {
                        json_object_put(mismatches);
                        json_object_put(actual_sections);
                        return apd_config_fail(out, "readback",
                                               "uci_get_list_failed", NULL);
                    }
                    if (actual_values)
                        json_object_object_add(actual_list_options, lo_name,
                            json_object_get(actual_values));
                    else
                        json_object_object_add(actual_list_options, lo_name,
                            json_object_new_array());
                    /* Compare expected vs actual list values. */
                    {
                        size_t expected_count =
                            json_object_array_length(expected_values);
                        size_t actual_count = actual_values ?
                            json_object_array_length(actual_values) : 0;
                        size_t j, k;
                        int all_match = (expected_count == actual_count);
    
                        if (all_match) {
                            for (j = 0; j < expected_count; j++) {
                                struct json_object *expected_entry =
                                    json_object_array_get_idx(expected_values, j);
                                int found = 0;
    
                                for (k = 0; k < actual_count; k++) {
                                    struct json_object *actual_entry =
                                        json_object_array_get_idx(
                                            actual_values, k);
    
                                    if (!strcmp(json_object_get_string(
                                                expected_entry),
                                                json_object_get_string(
                                                    actual_entry))) {
                                        found = 1;
                                        break;
                                    }
                                }
                                if (!found) {
                                    all_match = 0;
                                    break;
                                }
                            }
                        }
                        if (!all_match) {
                            struct json_object *entry = json_object_new_object();
    
                            json_object_object_add(entry, "section",
                                json_object_new_string(
                                    json_object_get_string(name)));
                            json_object_object_add(entry, "option",
                                json_object_new_string(lo_name));
                            json_object_object_add(entry, "expected",
                                json_object_get(expected_values));
                            json_object_object_add(entry, "actual",
                                actual_values ?
                                json_object_get(actual_values) :
                                json_object_new_array());
                            json_object_array_add(mismatches, entry);
                        }
                    }
                    if (actual_values)
                        json_object_put(actual_values);
                }
            }
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
    char assignment[APD_CONFIG_ASSIGNMENT_MAX];
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
        struct json_object *existed = NULL;
        struct json_object *captured_op = NULL;
        const char *operation = "set";

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        if (json_object_object_get_ex(section, "operation", &captured_op) &&
            captured_op && json_object_is_type(captured_op, json_type_string))
            operation = json_object_get_string(captured_op);
        json_object_object_get_ex(section, "existed", &existed);
        /* Undo section-level changes before option-level ones.  The two are
         * not symmetric: putting option values back cannot remove a section
         * that was created, and cannot bring back one that was deleted.
         *
         * Driven entirely from what was captured -- never from a fresh probe
         * of live state.  Rollback runs precisely when things are already
         * going wrong, and an earlier version of this asked `uci` what exists
         * right now; under fault injection that read fails and took the whole
         * rollback down with it.  Rollback must not be more fragile than the
         * thing it is rescuing. */
        if (existed && !json_object_get_boolean(existed) &&
            !strcmp(operation, "create")) {
            /* We created it; take it back out.  A delete that finds nothing
             * is not an error here: absent is the state we are restoring. */
            struct apd_command_result command = { 0 };

            apd_config_section_drop_live(paths, json_object_get_string(name),
                                         &command);
            apd_command_result_free(&command);
            continue;
        }
        if (existed && json_object_get_boolean(existed) &&
            !strcmp(operation, "delete")) {
            /* We deleted it; recreate it before restoring its options,
             * otherwise every `uci set` below writes into nothing.  This one
             * must succeed -- failing to bring the section back is a real
             * rollback failure, unlike failing to remove something absent. */
            struct json_object *section_type = NULL;
            struct apd_command_result command = { 0 };

            json_object_object_get_ex(section, "section_type", &section_type);
            if (!section_type) {
                failed = 1;
            } else {
                failed |= apd_config_section_create_live(paths,
                    json_object_get_string(name),
                    json_object_get_string(section_type), &command) != 0;
            }
            apd_command_result_free(&command);
        }
        json_object_object_foreach(options, option, value) {
            struct apd_command_result command = { 0 };
            int rc = 0;

            if (value && !json_object_is_type(value, json_type_null)) {
                rc = apd_config_set_live(paths,
                    json_object_get_string(name), option,
                    json_object_get_string(value), &command);
                failed |= rc != 0;
            } else {
                /* The option was absent when we captured it, so restoring
                 * means making it absent again -- and `uci delete` exits
                 * non-zero when there is nothing to remove, which is exactly
                 * the state we want.  Its exit code cannot separate "already
                 * gone" from "could not do it" (uci answers 1 for both), so
                 * ask what is there before acting:
                 *   absent      -> nothing to do
                 *   present     -> delete, and a failure there is a real one
                 *   cannot tell -> delete best-effort, like the list path
                 *                  below.  A rollback must not be recorded as
                 *                  failed merely because a probe was. */
                char *current = NULL;
                int probed = apd_config_get(paths,
                    json_object_get_string(name), option, &current);

                if (probed != 0 || current) {
                    rc = apd_config_delete_live(paths,
                        json_object_get_string(name), option, &command);
                    if (probed == 0)
                        failed |= rc != 0;
                }
                free(current);
            }
            apd_command_result_free(&command);
        }
        /* Handle list options (r0kh, r1kh) via uci add_list. */
        {
            struct json_object *list_options = NULL;

            json_object_object_get_ex(section, "list_options",
                                      &list_options);
            /* First delete all existing list values, then re-add the
             * previous ones. uci delete removes the entire list. */
            {
                if (list_options) {
                    json_object_object_foreach(list_options, del_opt, del_val) {
                        struct apd_command_result del_command = { 0 };
    
                        (void)del_val;
                        apd_config_delete_live(paths,
                            json_object_get_string(name), del_opt, &del_command);
                        apd_command_result_free(&del_command);
                    }
                }
            }
            {
                if (list_options) {
                    json_object_object_foreach(list_options, add_opt, add_vals) {
                        size_t k;
    
                        for (k = 0; k < json_object_array_length(add_vals); k++) {
                            struct json_object *entry =
                                json_object_array_get_idx(add_vals, k);
    
                            if (apd_config_add_list(paths, paths->config_dir,
                                                    json_object_get_string(name),
                                                    add_opt,
                                                    json_object_get_string(entry)) != 0) {
                                failed = 1;
                            }
                        }
                    }
                }
            }
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
        const char *operation = apd_config_section_operation(section);
        char *existing_type = NULL;

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        json_object_object_add(captured, "section",
            json_object_new_string(json_object_get_string(name)));
        json_object_object_add(captured, "list_options",
                               json_object_new_object());
        /* Record whether the section existed and, if so, as what type.  This
         * is what makes create and delete reversible at all: restoring option
         * values cannot undo a section that was brought into being, and it
         * cannot resurrect one that was removed. */
        if (apd_config_section_type(paths, json_object_get_string(name),
                                    &existing_type) != 0) {
            json_object_put(captured_options);
            json_object_put(captured);
            json_object_put(previous);
            return apd_config_fail(out, "capture",
                                   "previous_capture_failed", NULL);
        }
        json_object_object_add(captured, "existed",
                               json_object_new_boolean(existing_type != NULL));
        /* Journal the operation alongside the state it applied to: restore
         * reads it back rather than re-probing live config. */
        json_object_object_add(captured, "operation",
                               json_object_new_string(operation));
        if (existing_type)
            json_object_object_add(captured, "section_type",
                                   json_object_new_string(existing_type));
        /* A delete takes the whole section with it, so capture the whole
         * section -- not merely the options the candidate names.  Restoring a
         * partial wifi-iface would bring the SSID back without its encryption
         * or network binding, which is a worse outcome than no rollback. */
        if (!strcmp(operation, "delete") && existing_type) {
            struct json_object *full_options = NULL;
            struct json_object *full_list_options = NULL;

            if (apd_config_section_export(paths, json_object_get_string(name),
                                          &full_options,
                                          &full_list_options) != 0) {
                free(existing_type);
                json_object_put(captured_options);
                json_object_put(captured);
                json_object_put(previous);
                return apd_config_fail(out, "capture",
                                       "previous_capture_failed", NULL);
            }
            json_object_put(captured_options);
            json_object_object_add(captured, "options", full_options);
            json_object_object_add(captured, "list_options",
                                   full_list_options);
            json_object_array_add(previous, captured);
            free(existing_type);
            continue;
        }
        free(existing_type);
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
        /* Capture list options. */
        {
            struct json_object *list_options = NULL;
            struct json_object *captured_list_options = NULL;

            json_object_object_get_ex(section, "list_options",
                                      &list_options);
            json_object_object_get_ex(captured, "list_options",
                                      &captured_list_options);
            if (list_options) {
                json_object_object_foreach(list_options, option, value) {
                    struct json_object *current_values = NULL;
    
                    (void)value;
                    if (apd_config_get_list(paths, json_object_get_string(name),
                                            option, &current_values) != 0) {
                        json_object_put(captured);
                        json_object_put(previous);
                        return apd_config_fail(out, "capture",
                                               "previous_list_capture_failed",
                                               NULL);
                    }
                    json_object_object_add(captured_list_options, option,
                        current_values ? current_values :
                        json_object_new_array());
                }
            }
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
        const char *operation = apd_config_section_operation(section);

        json_object_object_get_ex(section, "section", &name);
        json_object_object_get_ex(section, "options", &options);
        if (!strcmp(operation, "create")) {
            struct json_object *section_type = NULL;
            struct apd_command_result command = { 0 };

            json_object_object_get_ex(section, "section_type", &section_type);
            if (apd_config_section_create_live(paths,
                    json_object_get_string(name),
                    json_object_get_string(section_type), &command) != 0) {
                int rc;
                int rollback_rc = apd_config_restore(paths, previous);

                rc = apd_config_fail(out, "apply",
                                     rollback_rc == 0 ? "uci_add_failed" :
                                     "rollback_failed", &command);
                json_object_object_add(*out, "rolled_back",
                                       json_object_new_boolean(rollback_rc == 0));
                apd_command_result_free(&command);
                return rc;
            }
            apd_command_result_free(&command);
        } else if (!strcmp(operation, "delete")) {
            struct apd_command_result command = { 0 };
            char *existing_type = NULL;

            /* Idempotent: a section that is already gone is the desired end
             * state, and `uci delete` on a missing section is an error. */
            if (apd_config_section_type(paths, json_object_get_string(name),
                                        &existing_type) != 0) {
                int rollback_rc = apd_config_restore(paths, previous);

                (void)rollback_rc;
                return apd_config_fail(out, "apply", "uci_get_failed", NULL);
            }
            if (existing_type) {
                free(existing_type);
                if (apd_config_section_drop_live(paths,
                        json_object_get_string(name), &command) != 0) {
                    int rc;
                    int rollback_rc = apd_config_restore(paths, previous);

                    rc = apd_config_fail(out, "apply",
                                         rollback_rc == 0 ?
                                         "uci_section_delete_failed" :
                                         "rollback_failed", &command);
                    json_object_object_add(*out, "rolled_back",
                        json_object_new_boolean(rollback_rc == 0));
                    apd_command_result_free(&command);
                    return rc;
                }
            }
            apd_command_result_free(&command);
            /* Nothing to set on a section that no longer exists. */
            continue;
        }
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
        {
            struct apd_command_result command = { 0 };
            int key_rc = apd_config_mlo_key_sync(paths, paths->config_dir,
                json_object_get_string(name), 1, &command);

            if (key_rc != 0) {
                int rollback_rc = apd_config_restore(paths, previous);
                const char *reason = key_rc == -2 ?
                    "mlo_source_key_unavailable" :
                    key_rc == -3 ? "mlo_credentials_mismatch" :
                    key_rc == -4 ? "mlo_key_set_failed" :
                    "mlo_key_probe_failed";
                int rc = apd_config_fail(out, "apply",
                    rollback_rc == 0 ? reason : "rollback_failed",
                    command.exit_status >= 0 ? &command : NULL);

                json_object_object_add(*out, "rolled_back",
                    json_object_new_boolean(rollback_rc == 0));
                apd_command_result_free(&command);
                return rc;
            }
            apd_command_result_free(&command);
        }
        /* Apply list options to live config. */
        {
            struct json_object *list_options = NULL;

            json_object_object_get_ex(section, "list_options",
                                      &list_options);
            if (list_options) {
                json_object_object_foreach(list_options, option, values) {
                    size_t k;

                    apd_config_clear_option(paths, paths->config_dir,
                                            json_object_get_string(name),
                                            option);
                    for (k = 0; k < json_object_array_length(values); k++) {
                        struct json_object *entry =
                            json_object_array_get_idx(values, k);

                        if (apd_config_add_list(paths, paths->config_dir,
                                                json_object_get_string(name),
                                                option,
                                                json_object_get_string(entry)) != 0) {
                            int rollback_rc = apd_config_restore(paths, previous);

                            (void)rollback_rc;
                            return apd_config_fail(out, "apply",
                                                   "uci_add_list_failed", NULL);
                        }
                    }
                }
            }
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

int apd_config_rollback_readback(const struct apd_config_paths *paths,
                                 struct json_object *previous,
                                 struct json_object **out)
{
    struct json_object *result;
    struct json_object *mismatches = json_object_new_array();
    size_t i;

    if (!out) {
        json_object_put(mismatches);
        return -1;
    }
    if (!paths || !paths->uci || !paths->config_dir || !previous ||
        !json_object_is_type(previous, json_type_array) ||
        json_object_array_length(previous) == 0 ||
        json_object_array_length(previous) > APD_CONFIG_SECTIONS_MAX) {
        json_object_put(mismatches);
        return apd_config_fail(out, "rollback_readback", "previous_invalid",
                               NULL);
    }
    for (i = 0; i < json_object_array_length(previous); i++) {
        struct json_object *section = json_object_array_get_idx(previous, i);
        struct json_object *name = NULL;
        struct json_object *existed = NULL;
        struct json_object *section_type = NULL;
        struct json_object *options = NULL;
        struct json_object *list_options = NULL;
        char *live_type = NULL;
        int expected_present;

        if (!section || !json_object_is_type(section, json_type_object) ||
            !json_object_object_get_ex(section, "section", &name) ||
            !name || !json_object_is_type(name, json_type_string) ||
            !json_object_object_get_ex(section, "existed", &existed) ||
            !existed || !json_object_is_type(existed, json_type_boolean) ||
            !json_object_object_get_ex(section, "options", &options) ||
            !options || !json_object_is_type(options, json_type_object)) {
            json_object_put(mismatches);
            return apd_config_fail(out, "rollback_readback",
                                   "previous_shape_invalid", NULL);
        }
        json_object_object_get_ex(section, "section_type", &section_type);
        json_object_object_get_ex(section, "list_options", &list_options);
        expected_present = json_object_get_boolean(existed);
        if (apd_config_section_type(paths, json_object_get_string(name),
                                    &live_type) != 0) {
            json_object_put(mismatches);
            return apd_config_fail(out, "rollback_readback",
                                   "uci_get_failed", NULL);
        }
        if (expected_present != (live_type != NULL) ||
            (expected_present && section_type &&
             strcmp(json_object_get_string(section_type), live_type))) {
            struct json_object *entry = json_object_new_object();

            json_object_object_add(entry, "section",
                json_object_new_string(json_object_get_string(name)));
            json_object_object_add(entry, "option",
                json_object_new_string("<section>"));
            json_object_object_add(entry, "expected",
                json_object_new_string(expected_present ?
                    (section_type ? json_object_get_string(section_type) :
                     "present") : "absent"));
            json_object_object_add(entry, "actual", live_type ?
                json_object_new_string(live_type) : NULL);
            json_object_array_add(mismatches, entry);
        }
        free(live_type);
        if (!expected_present)
            continue;
        json_object_object_foreach(options, option, expected) {
            char *actual = NULL;
            int expected_absent = !expected ||
                json_object_is_type(expected, json_type_null);

            if (apd_config_get(paths, json_object_get_string(name), option,
                               &actual) != 0) {
                json_object_put(mismatches);
                return apd_config_fail(out, "rollback_readback",
                                       "uci_get_failed", NULL);
            }
            if ((expected_absent && actual) ||
                (!expected_absent && (!actual || strcmp(actual,
                    json_object_get_string(expected))))) {
                struct json_object *entry = json_object_new_object();

                json_object_object_add(entry, "section",
                    json_object_new_string(json_object_get_string(name)));
                json_object_object_add(entry, "option",
                    json_object_new_string(option));
                json_object_object_add(entry, "expected", expected_absent ?
                    NULL : json_object_new_string(
                        json_object_get_string(expected)));
                json_object_object_add(entry, "actual", actual ?
                    json_object_new_string(actual) : NULL);
                json_object_array_add(mismatches, entry);
            }
            free(actual);
        }
        if (list_options && json_object_is_type(list_options,
                                                json_type_object)) {
            json_object_object_foreach(list_options, option, expected_values) {
                struct json_object *actual_values = NULL;
                size_t expected_count = json_object_array_length(
                    expected_values);
                size_t actual_count;
                size_t j, k;
                int all_match;

                if (apd_config_get_list(paths, json_object_get_string(name),
                                        option, &actual_values) != 0) {
                    json_object_put(mismatches);
                    return apd_config_fail(out, "rollback_readback",
                                           "uci_get_list_failed", NULL);
                }
                actual_count = actual_values ?
                    json_object_array_length(actual_values) : 0;
                all_match = expected_count == actual_count;
                for (j = 0; all_match && j < expected_count; j++) {
                    struct json_object *expected_entry =
                        json_object_array_get_idx(expected_values, j);
                    int found = 0;

                    for (k = 0; k < actual_count; k++) {
                        struct json_object *actual_entry =
                            json_object_array_get_idx(actual_values, k);

                        if (!strcmp(json_object_get_string(expected_entry),
                                    json_object_get_string(actual_entry))) {
                            found = 1;
                            break;
                        }
                    }
                    all_match = found;
                }
                if (!all_match) {
                    struct json_object *entry = json_object_new_object();

                    json_object_object_add(entry, "section",
                        json_object_new_string(json_object_get_string(name)));
                    json_object_object_add(entry, "option",
                        json_object_new_string(option));
                    json_object_object_add(entry, "expected",
                        json_object_get(expected_values));
                    json_object_object_add(entry, "actual", actual_values ?
                        json_object_get(actual_values) :
                        json_object_new_array());
                    json_object_array_add(mismatches, entry);
                }
                json_object_put(actual_values);
            }
        }
    }
    result = apd_config_result_new("rollback_readback");
    json_object_object_add(result, "match", json_object_new_boolean(
        json_object_array_length(mismatches) == 0));
    json_object_object_add(result, "mismatches", mismatches);
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
