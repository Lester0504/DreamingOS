#ifndef JMX_MMCLI_KV_H
#define JMX_MMCLI_KV_H

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct jmx_mmcli_probe {
    int has_signal;
    int signal;
    char operator_name[128];
    char imei[64];
    char sim_path[256];
    char iccid[64];
};

static inline int jmx_mmcli_value_missing(const char *value)
{
    return !value || !value[0] || !strcmp(value, "--") ||
           !strcmp(value, "unknown") || !strcmp(value, "none");
}

static inline int jmx_mmcli_copy_value(char *dst, size_t dst_len,
                                       const char *value)
{
    size_t len;

    if (!dst || dst_len == 0 || jmx_mmcli_value_missing(value))
        return -1;
    len = strlen(value);
    if (len == 0 || len >= dst_len)
        return -1;
    memcpy(dst, value, len + 1);
    return 0;
}

static inline int jmx_mmcli_decimal_id_ok(const char *value, size_t min_len,
                                          size_t max_len)
{
    const unsigned char *p;
    size_t len;

    if (jmx_mmcli_value_missing(value))
        return 0;
    len = strlen(value);
    if (len < min_len || len > max_len)
        return 0;
    for (p = (const unsigned char *)value; *p; p++) {
        if (!isdigit(*p))
            return 0;
    }
    return 1;
}

static inline int jmx_mmcli_selector_ok(const char *value)
{
    const unsigned char *p;
    static const char modem_prefix[] =
        "/org/freedesktop/ModemManager1/Modem/";
    static const char sim_prefix[] =
        "/org/freedesktop/ModemManager1/SIM/";
    size_t len;

    if (jmx_mmcli_value_missing(value) || value[0] == '-')
        return 0;
    len = strlen(value);
    if (len == 0 || len >= sizeof(((struct jmx_mmcli_probe *)0)->sim_path))
        return 0;
    if (value[0] != '/') {
        for (p = (const unsigned char *)value; *p; p++) {
            if (!isdigit(*p))
                return 0;
        }
        return 1;
    }
    if (!strncmp(value, modem_prefix, sizeof(modem_prefix) - 1))
        p = (const unsigned char *)value + sizeof(modem_prefix) - 1;
    else if (!strncmp(value, sim_prefix, sizeof(sim_prefix) - 1))
        p = (const unsigned char *)value + sizeof(sim_prefix) - 1;
    else
        return 0;
    if (!*p)
        return 0;
    for (; *p; p++) {
        if (!isdigit(*p))
            return 0;
    }
    return 1;
}

static inline int jmx_mmcli_text_ok(const char *value)
{
    const unsigned char *p;

    if (jmx_mmcli_value_missing(value))
        return 0;
    for (p = (const unsigned char *)value; *p; p++) {
        if (*p < 0x20 || *p == 0x7f)
            return 0;
    }
    return 1;
}

static inline char *jmx_mmcli_trim(char *value)
{
    char *end;

    while (*value && isspace((unsigned char)*value))
        value++;
    end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return value;
}

static inline int jmx_mmcli_parse_line(char *line, struct jmx_mmcli_probe *probe,
                                       int sim_output)
{
    char *separator;
    char *key;
    char *value;
    char *end = NULL;
    long signal;

    if (!line || !probe)
        return 0;
    separator = strchr(line, ':');
    if (!separator)
        return 0;
    *separator = '\0';
    key = jmx_mmcli_trim(line);
    value = jmx_mmcli_trim(separator + 1);
    if (!key[0] || jmx_mmcli_value_missing(value))
        return 0;

    if (sim_output) {
        if (!strcmp(key, "sim.properties.iccid") &&
            jmx_mmcli_decimal_id_ok(value, 10, 32) &&
            jmx_mmcli_copy_value(probe->iccid, sizeof(probe->iccid), value) == 0)
            return 1;
        return 0;
    }

    if (!strcmp(key, "modem.generic.signal-quality.value")) {
        errno = 0;
        signal = strtol(value, &end, 10);
        if (!errno && end && !*end && signal >= 0 && signal <= 100) {
            probe->signal = (int)signal;
            probe->has_signal = 1;
            return 1;
        }
        return 0;
    }
    if (!strcmp(key, "modem.3gpp.operator-name")) {
        if (jmx_mmcli_text_ok(value) &&
            jmx_mmcli_copy_value(probe->operator_name,
                                 sizeof(probe->operator_name), value) == 0)
            return 1;
        return 0;
    }
    if (!strcmp(key, "modem.generic.equipment-identifier") ||
        !strcmp(key, "modem.3gpp.imei")) {
        if (jmx_mmcli_decimal_id_ok(value, 8, 32) &&
            jmx_mmcli_copy_value(probe->imei, sizeof(probe->imei), value) == 0)
            return 1;
        return 0;
    }
    if (!strcmp(key, "modem.generic.sim")) {
        if (jmx_mmcli_selector_ok(value) &&
            jmx_mmcli_copy_value(probe->sim_path, sizeof(probe->sim_path), value) == 0)
            return 1;
        return 0;
    }
    return 0;
}

static inline int jmx_mmcli_parse_keyvalue(char *output,
                                           struct jmx_mmcli_probe *probe,
                                           int sim_output)
{
    char *cursor;
    int fields = 0;

    if (!output || !probe)
        return -1;
    cursor = output;
    while (*cursor) {
        char *line = cursor;
        char *newline = strchr(cursor, '\n');

        if (newline) {
            *newline = '\0';
            cursor = newline + 1;
        } else {
            cursor += strlen(cursor);
        }
        if (*line && line[strlen(line) - 1] == '\r')
            line[strlen(line) - 1] = '\0';
        fields += jmx_mmcli_parse_line(line, probe, sim_output);
    }
    return fields;
}

#endif
