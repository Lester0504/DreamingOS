// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGOS_NVR_H
#define DREAMINGOS_NVR_H
#include <json-c/json.h>
int nvr_init(const char *config);
void nvr_close(void);
void nvr_tick(void);
struct json_object *nvr_request(const char *,const char *,struct json_object *,int *);
#endif
