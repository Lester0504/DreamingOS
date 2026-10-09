// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGOS_CLOUD_BROWSER_H
#define DREAMINGOS_CLOUD_BROWSER_H

#include "cloud_web_client.h"
#include <json-c/json.h>

#ifndef CLOUD_BROWSER_CONFIG_DIR
#define CLOUD_BROWSER_CONFIG_DIR "/etc/config"
#endif
#ifndef CLOUD_BROWSER_CERT
#define CLOUD_BROWSER_CERT "/etc/dreamingwrt/tls/console.crt"
#endif

int cloud_browser_load(struct cwc_config *config, int *enabled, int full);
void cloud_browser_transport_start(void);
void cloud_browser_transport_stop(void);
void cloud_browser_configured(int enabled);
void cloud_browser_control_start(void);
void cloud_browser_control_stop(void);
struct json_object *cloud_browser_control(const char *action, const char *actor,
                                          struct json_object *request);
struct json_object *cloud_browser_preflight(const struct cwc_config *config);
struct json_object *cloud_browser_services(const char *action, struct json_object *request);

#endif
