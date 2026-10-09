// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_AUTHENTICATION_INTERNAL_H
#define WEBD_API_AUTHENTICATION_INTERNAL_H

/*
 * Borrowed from jmx_app_api.c. app_authentication_write is de-static'd there (its
 * definition stays in main, shared with the seven inline id-detail STAY branches
 * that still call it); the authentication BFF write adapters in api_authentication.c
 * reuse that single implementation. The authentication TU is a separate compilation
 * unit and needs the prototype.
 */
struct json_object;

struct json_object *app_authentication_write(const char *method,
                                             struct json_object *payload,
                                             const char *resource_id,
                                             int inject_id,
                                             const char *device_id,
                                             int *http_status);

#endif /* WEBD_API_AUTHENTICATION_INTERNAL_H */
