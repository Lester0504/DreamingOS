// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AP_MLO_MEMBERS_H
#define DREAMINGWRT_AP_MLO_MEMBERS_H

/* Validation for the one UCI option whose value is a structured document.
 *
 * `dreamingwrt_mlo_members` records what an MLO group looked like before it was
 * merged, so turning MLO off can put each wifi-iface back on its own radio
 * instead of leaving the members disabled forever.  That record is JSON:
 *
 *   {"version":1,"members":[{"section":"wifi0","device":["radio0"],
 *                            "disabled":"0"}]}
 *
 * It therefore contains double quotes and runs well past the 64-byte scalar
 * limit that both candidate validators apply to every other option, which is
 * why adding the name to the allow-lists was not enough on its own: the value
 * check refused it afterwards with candidate_value_invalid.
 *
 * The check lives in a shared header for the same reason ap_radio_id.h does.
 * The AC validates a candidate before journalling it and the AP validates it
 * again before applying, so any divergence between the two produces a
 * transaction the controller accepts and the AP is certain to refuse -- after
 * the journal entry exists.  One implementation, included by both, cannot
 * drift.
 *
 * The accept set is deliberately no wider than what the page emits: printable
 * ASCII, no single quote and no backslash, an exact key set, and section and
 * device names under the same rule as a UCI section name.  Secrets never
 * appear here -- only names, radio bindings and enable state.
 */

#include <string.h>

#include <json-c/json.h>

#define DREAMINGWRT_MLO_MEMBERS_OPTION "dreamingwrt_mlo_members"
#define DREAMINGWRT_MLO_MEMBERS_VALUE_MAX 4096U
#define DREAMINGWRT_MLO_MEMBERS_MAX 16U
#define DREAMINGWRT_MLO_MEMBERS_DEVICE_MAX 32U
#define DREAMINGWRT_MLO_MEMBERS_NAME_MAX 32U

static inline int dreamingwrt_mlo_members_option(const char *name)
{
    return name && !strcmp(name, DREAMINGWRT_MLO_MEMBERS_OPTION);
}

/* Same character class as a UCI section name: lowercase, digits, underscore. */
static inline int dreamingwrt_mlo_members_name_valid(const char *value)
{
    size_t i;
    size_t length = value ? strlen(value) : 0;

    if (length == 0 || length > DREAMINGWRT_MLO_MEMBERS_NAME_MAX)
        return 0;
    for (i = 0; i < length; i++)
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= '0' && value[i] <= '9') || value[i] == '_'))
            return 0;
    return 1;
}

static inline int dreamingwrt_mlo_members_object_keys_ok(
    struct json_object *object, const char *const *allowed, size_t allowed_len)
{
    size_t i;

    json_object_object_foreach(object, key, ignored) {
        int found = 0;

        (void)ignored;
        for (i = 0; i < allowed_len; i++)
            if (!strcmp(key, allowed[i])) {
                found = 1;
                break;
            }
        if (!found)
            return 0;
    }
    return 1;
}

static inline int dreamingwrt_mlo_members_string(struct json_object *object,
                                                 const char *key,
                                                 const char **out)
{
    struct json_object *value = NULL;

    if (!json_object_object_get_ex(object, key, &value) || !value ||
        !json_object_is_type(value, json_type_string))
        return 0;
    *out = json_object_get_string(value);
    return 1;
}

static inline int dreamingwrt_mlo_members_device_valid(
    struct json_object *member)
{
    struct json_object *devices = NULL;
    size_t count;
    size_t i;
    size_t j;

    if (!json_object_object_get_ex(member, "device", &devices) || !devices ||
        !json_object_is_type(devices, json_type_array))
        return 0;
    count = json_object_array_length(devices);
    if (count == 0 || count > DREAMINGWRT_MLO_MEMBERS_DEVICE_MAX)
        return 0;
    for (i = 0; i < count; i++) {
        struct json_object *entry = json_object_array_get_idx(devices, i);
        const char *name;

        if (!entry || !json_object_is_type(entry, json_type_string))
            return 0;
        name = json_object_get_string(entry);
        if (!dreamingwrt_mlo_members_name_valid(name))
            return 0;
        /* A radio listed twice would make `uci add_list` write it twice and
         * then fail readback against its own candidate. */
        for (j = 0; j < i; j++) {
            struct json_object *other = json_object_array_get_idx(devices, j);

            if (other && json_object_is_type(other, json_type_string) &&
                !strcmp(json_object_get_string(other), name))
                return 0;
        }
    }
    return 1;
}

static inline int dreamingwrt_mlo_members_value_valid(const char *value)
{
    static const char *const root_keys[] = { "version", "members" };
    static const char *const member_keys[] = { "section", "device",
                                               "disabled" };
    struct json_object *root = NULL;
    struct json_object *version = NULL;
    struct json_object *members = NULL;
    size_t length = value ? strlen(value) : 0;
    size_t count;
    size_t i;
    size_t j;
    int ok = 0;

    if (length == 0 || length > DREAMINGWRT_MLO_MEMBERS_VALUE_MAX)
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];

        if (c < 0x20 || c > 0x7e || c == '\'' || c == '\\')
            return 0;
    }
    root = json_tokener_parse(value);
    if (!root || !json_object_is_type(root, json_type_object))
        goto done;
    if (!dreamingwrt_mlo_members_object_keys_ok(root, root_keys, 2))
        goto done;
    if (!json_object_object_get_ex(root, "version", &version) || !version ||
        !json_object_is_type(version, json_type_int) ||
        json_object_get_int64(version) != 1)
        goto done;
    if (!json_object_object_get_ex(root, "members", &members) || !members ||
        !json_object_is_type(members, json_type_array))
        goto done;
    count = json_object_array_length(members);
    if (count > DREAMINGWRT_MLO_MEMBERS_MAX)
        goto done;
    for (i = 0; i < count; i++) {
        struct json_object *member = json_object_array_get_idx(members, i);
        const char *section;
        const char *disabled;

        if (!member || !json_object_is_type(member, json_type_object) ||
            !dreamingwrt_mlo_members_object_keys_ok(member, member_keys, 3) ||
            !dreamingwrt_mlo_members_string(member, "section", &section) ||
            !dreamingwrt_mlo_members_name_valid(section) ||
            !dreamingwrt_mlo_members_string(member, "disabled", &disabled) ||
            (strcmp(disabled, "0") && strcmp(disabled, "1")) ||
            !dreamingwrt_mlo_members_device_valid(member))
            goto done;
        /* Two records for one section would make the restore order decide
         * which binding wins. */
        for (j = 0; j < i; j++) {
            struct json_object *other = json_object_array_get_idx(members, j);
            const char *other_section;

            if (other && json_object_is_type(other, json_type_object) &&
                dreamingwrt_mlo_members_string(other, "section",
                                               &other_section) &&
                !strcmp(other_section, section))
                goto done;
        }
    }
    ok = 1;
done:
    if (root)
        json_object_put(root);
    return ok;
}

#endif
