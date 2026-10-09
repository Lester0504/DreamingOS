// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_APD_IW_TOPOLOGY_H
#define DREAMINGWRT_APD_IW_TOPOLOGY_H

#include <stdint.h>

struct json_object;

int apd_iw_topology_parse(const char *text, struct json_object *radios,
                          struct json_object *ssids, int64_t observed_at);

#endif
