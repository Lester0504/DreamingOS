// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_SYSTEM_INFO_INTERNAL_H
#define WEBD_API_SYSTEM_INFO_INTERNAL_H

/* Phase 7O cross-TU surface for the system basic-info builders moved to
 * api_system_info.c. The two EXPORT builders are called from handle_client()
 * in the main TU; the two 2FA helpers remain defined in the main TU but are
 * now also called from the moved region. */

struct json_object;

/* Defined in api_system_info.c; called from handle_client() in jmx_app_api.c. */
struct json_object *webd_system_basic_response(int *status);
void webd_system_basic_attach_auth_state(struct json_object *resp,
                                         const char *identity);

/* Defined in jmx_app_api.c (main); called from api_system_info.c. */
int webd_twofa_qr_available(void);
struct json_object *webd_twofa_public_status(const char *username);

#endif /* WEBD_API_SYSTEM_INFO_INTERNAL_H */
