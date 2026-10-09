// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_WEBD_WIFI_CONTRACT_H
#define DREAMINGWRT_WEBD_WIFI_CONTRACT_H

struct json_object;

struct json_object *wifi_contract_read(struct json_object *wifi_data,
                                       const char *role_name);

#endif
