// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_SETUP_INTERNAL_H
#define WEBD_API_SETUP_INTERNAL_H

#include <stddef.h>  /* size_t */

/*
 * Setup/wifi response helpers shared across TUs. The four app_setup_* builders
 * below are defined in api_setup.c (moved out of jmx_app_api.c in phase 7X);
 * app_wifi_capability_disabled_response stays in jmx_app_api.c. handle_client
 * in the main TU and the setup BFF adapters in api_setup.c both call them, so
 * each needs the prototypes. The generic jmx_app_audit_log_ex is NOT declared here — it
 * lives in the public jmx_app_api.h beside jmx_app_audit_log (40 file-wide uses).
 *
 * webd_identity_is_user / webd_identity_username are non-static identity helpers
 * defined in main and used across domains (also borrowed by api_notifyd_internal.h);
 * the setup/finish handler needs them to format the finish actor. webd_ai_oauth_start
 * (setup/oauth/start) comes from ai_oauth.h, which api_setup.c includes directly.
 */
struct json_object;

struct json_object *app_setup_finish_response(struct json_object *body,
                                              const char *actor, int *status);
struct json_object *app_setup_oauth_response(void);
struct json_object *app_setup_security_response(void);
struct json_object *app_setup_status_slice_response(const char *slice);
struct json_object *app_wifi_capability_disabled_response(const char *op,
                                                          const char *reason);

int webd_identity_is_user(const char *identity);
const char *webd_identity_username(const char *identity);


/*
 * Phase 7R: setup-session + 2FA-challenge primitives. Definitions moved to
 * api_setup_session.c; the setup/security handlers in the main TU (which
 * includes this header) still call them, so they need visible prototypes.
 */
int webd_setup_session_clear(void);
int webd_setup_session_active(void);
int webd_setup_session_claim(const char *client_ip, char *token, size_t token_len,
                             int *already_active);
int webd_setup_session_verify(const char *token, const char *client_ip, int touch);
int webd_setup_session_actor(const char *token, const char *client_ip,
                             char *out, size_t out_len);
int webd_setup_owner_username(char *out, size_t out_len);
int webd_setup_twofa_challenge_store(const char *token, const char *client_ip,
                                     const char *username, const char *secret);
int webd_setup_twofa_challenge_verify(const char *token, const char *client_ip,
                                      const char *username, const char *secret);
int webd_setup_twofa_challenge_clear(const char *token, const char *client_ip);
void webd_setup_session_cookie(char *out, size_t out_len, const char *token, int clear);

/* Borrowed by api_setup_session.c: definition stays in the main TU (also called
 * by the 2FA enable/prepare paths there); de-static'd for the moved callers. */
int webd_totp_secret_ok(const char *secret);

/* Phase 7X: borrowed by the finish builder in api_setup.c. The definition stays
 * in the main TU (handle_client and the 2FA setup builders call it there). */
struct json_object *app_setup_session_error_response(const char *error,
                                                     const char *message);

#endif /* WEBD_API_SETUP_INTERNAL_H */
