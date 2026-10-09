// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_POLICY_CORE_INTERNAL_H
#define WEBD_API_POLICY_CORE_INTERNAL_H
/* Phase 7G: shared firewall-policy primitives (webd_policy_* label/UCI/raw
 * builders + row/action assemblers) moved out of jmx_app_api.c
 * (behavior-preserving). These are external-linkage helpers already
 * consumed by the api_policy_{read,write,objects,firewall,services} TUs via
 * their own headers; only the definitions relocate here. Routes are
 * unchanged and still dispatched from handle_client() in the main TU. */
struct json_object;
struct http_req;
struct uci_context;
struct uci_section;
struct uci_option;
struct uci_package;

#endif
