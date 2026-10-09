// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_FLOWD_WAN_RUNTIME_H
#define DREAMINGWRT_FLOWD_WAN_RUNTIME_H

#include <stddef.h>

int flowd_wan_resolve_ifname(const char *wan, char *out, size_t out_len);
int flowd_wan_resolve_l3_ifname(const char *wan, char *out, size_t out_len);

#endif
