// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_EVENT_SEMANTICS_H
#define DREAMINGWRT_EVENT_SEMANTICS_H

#include <stddef.h>
#include <json-c/json.h>

struct dw_event_definition {
    const char *id;
    const char *category;
    const char *label_en;
    const char *label_zh;
    const char *producer;
    const char *recovery_event;
    const char *recovers_event;
    const char *unavailable_reason;
    const char *default_severity;
    const char *message_key;
    unsigned int message_version;
    int available;
};

extern const struct dw_event_definition dw_event_definitions[];
extern const size_t dw_event_definitions_count;

struct dw_event_domain_definition {
    const char *id;
    const char *label_zh;
    const char *label_en;
};
extern const struct dw_event_domain_definition dw_event_domains[];
extern const size_t dw_event_domains_count;
const struct dw_event_domain_definition *dw_event_domain_find(const char *id);
const char *dw_event_audit_action_label(const char *action);
const char *dw_event_audit_domain(const char *action);
const char *dw_event_domain(const char *category, const char *id,
                            struct json_object *detail);
int dw_event_is_business(const char *id);
const char *dw_event_effective_severity(const char *id, struct json_object *detail,
                                        const char *stored);

const struct dw_event_definition *dw_event_definition_find(const char *id);
const char *dw_event_locale_normalize(const char *locale);
struct json_object *dw_event_message_args(struct json_object *event);
struct json_object *dw_event_presentation_render(struct json_object *event,
                                                 const char *locale);
int dw_event_payload_present(struct json_object *event, const char *locale);

#endif
