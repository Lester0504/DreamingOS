// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __JMX_EVENTS_H__
#define __JMX_EVENTS_H__

#include <json-c/json.h>

void jmx_events_emit(const char *topic, const char *type, struct json_object *data);

#endif
