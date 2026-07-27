// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __JMX_SIGNATURE_UPDATE_H__
#define __JMX_SIGNATURE_UPDATE_H__

#include <json-c/json.h>

struct json_object *jmx_signature_update_validate(struct json_object *cfg);
struct json_object *jmx_signature_update_apply(struct json_object *cfg);
struct json_object *jmx_signature_update_status(struct json_object *cfg);

#endif
