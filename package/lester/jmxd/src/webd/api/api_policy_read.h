// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
/* Policy Engine read-only projections and route registration. */
#ifndef WEBD_API_POLICY_READ_H
#define WEBD_API_POLICY_READ_H

#include "api_router.h"

struct json_object;
struct http_req;

extern const struct jmx_api_route policy_read_api_routes[];

struct json_object *webd_policy_catalog_response(const struct http_req *req,
                                                 int *http_status);
struct json_object *webd_policy_table_response(const struct http_req *req,
                                               int *http_status);
struct json_object *webd_policy_detail_response(const struct http_req *req,
                                                const char *id,
                                                int *http_status);

#endif /* WEBD_API_POLICY_READ_H */
