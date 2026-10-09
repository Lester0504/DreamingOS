// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_CONFIG_EXECUTOR_H
#define DREAMINGWRT_APD_CONFIG_EXECUTOR_H

/* The config job executor core.  These functions implement the
 * stage / apply / readback / rollback primitives over an injectable uci
 * binary, config directory and staging directory so the whole state
 * machine is testable without touching a live system.
 *
 * apply() and rollback() mutate the supplied config_dir; every caller must
 * hold the capability gate and a journaled rollback reference first. */

#include <stddef.h>

#include <json-c/json.h>

#define APD_CONFIG_CANDIDATE_FORMAT "uci-wireless-candidate.v1"
#define APD_CONFIG_SECTIONS_MAX 16U
#define APD_CONFIG_OPTIONS_MAX 16U
#define APD_CONFIG_LIST_OPTIONS_MAX 32U
#define APD_CONFIG_NAME_MAX 32U
#define APD_CONFIG_VALUE_MAX 64U
/* "sha256:" + 64 hex + NUL, rounded up. */
#define APD_CONFIG_DIGEST_MAX 80U
#ifndef APD_CONFIG_COMMAND_TIMEOUT_MS
#define APD_CONFIG_COMMAND_TIMEOUT_MS 5000
#endif
#define APD_CONFIG_COMMAND_OUTPUT_LIMIT (64U * 1024U)

struct apd_config_paths {
    const char *uci;         /* uci binary path */
    const char *wifi;        /* wifi reload script path */
    const char *config_dir;  /* live UCI config directory */
    const char *staging_dir; /* private staging directory (stage only) */
};

/* Every function returns 0 with *out = {ok:true, operation, ...} on
 * success, -1 with *out = {ok:false, operation, reason, evidence?} on
 * failure.  *out is always set and owned by the caller. */
int apd_config_candidate_validate(struct json_object *candidate,
                                  struct json_object **out);
/* Runtime actions use the config-job journal, never the UCI executor. Mixed
 * candidates are rejected by this validator so actions cannot cause a reload. */
int apd_config_hostapd_actions_validate(struct json_object *candidate,
                                        struct json_object **out);
static inline int apd_config_candidate_has_actions(struct json_object *candidate)
{
    struct json_object *sections;
    size_t i;

    if (!candidate || !json_object_is_type(candidate, json_type_object))
        return 0;
    sections = json_object_object_get(candidate, "sections");
    if (!sections || !json_object_is_type(sections, json_type_array))
        return 0;
    for (i = 0; i < json_object_array_length(sections); i++) {
        struct json_object *section = json_object_array_get_idx(sections, i);
        struct json_object *options;

        if (!section || !json_object_is_type(section, json_type_object))
            continue;
        options = json_object_object_get(section, "options");
        if (options && json_object_is_type(options, json_type_object) &&
            json_object_object_get(options, "hostapd_action_type"))
            return 1;
    }
    return 0;
}
/* Recompute the canonical candidate digest over a section array.  `out` must
 * be at least APD_CONFIG_DIGEST_MAX bytes.  Needed by callers that split a
 * candidate into subsets: a subset's digest has to be restated, because the
 * parent candidate's digest no longer describes it. */
int apd_config_candidate_digest(struct json_object *sections,
                                char *out, size_t out_len);
int apd_config_stage(const struct apd_config_paths *paths,
                     struct json_object *candidate,
                     struct json_object **out);
int apd_config_readback(const struct apd_config_paths *paths,
                        struct json_object *candidate,
                        struct json_object **out);
/* Capture is read-only. The caller must durably journal the returned
 * previous array before apply_prepared() may mutate live UCI. */
int apd_config_capture_previous(const struct apd_config_paths *paths,
                                struct json_object *candidate,
                                struct json_object **out);
int apd_config_apply_prepared(const struct apd_config_paths *paths,
                              struct json_object *candidate,
                              struct json_object *previous,
                              struct json_object **out);
int apd_config_apply(const struct apd_config_paths *paths,
                     struct json_object *candidate,
                     struct json_object **out);
int apd_config_rollback(const struct apd_config_paths *paths,
                        struct json_object *previous,
                        struct json_object **out);
int apd_config_rollback_readback(const struct apd_config_paths *paths,
                                 struct json_object *previous,
                                 struct json_object **out);

/* Runtime availability is shared by the capability surface and transport. */
int apd_config_executor_available(const struct apd_config_paths *paths);
int apd_config_executor_available_default(void);

#endif
