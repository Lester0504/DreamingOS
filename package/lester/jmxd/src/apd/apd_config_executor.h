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

#include <json-c/json.h>

#define APD_CONFIG_CANDIDATE_FORMAT "uci-wireless-candidate.v1"
#define APD_CONFIG_SECTIONS_MAX 16U
#define APD_CONFIG_OPTIONS_MAX 8U
#define APD_CONFIG_NAME_MAX 32U
#define APD_CONFIG_VALUE_MAX 64U
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

/* Runtime availability is shared by the capability surface and transport. */
int apd_config_executor_available(const struct apd_config_paths *paths);
int apd_config_executor_available_default(void);

#endif
