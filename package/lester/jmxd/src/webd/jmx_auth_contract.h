// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_WEBD_AUTH_CONTRACT_H
#define DREAMINGWRT_WEBD_AUTH_CONTRACT_H

struct json_object;

struct json_object *auth_contract_session_read(
    struct json_object *session, const char *role_name);
struct json_object *auth_contract_session_error(const char *code,
                                                const char *message);

#endif
