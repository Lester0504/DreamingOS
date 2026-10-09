// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dwrt_features.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

enum section {
    SECTION_NONE = 0,
    SECTION_ENABLED,
    SECTION_DISABLED,
    SECTION_FUNCTIONS,
};

static void warnf(dwrt_features_warn_fn warn, void *ctx, struct dwrt_features *f,
                  int line, const char *fmt, ...)
{
    char msg[256];
    va_list ap;

    f->warnings++;
    if (!warn)
        return;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    warn(ctx, line, msg);
}

static char *trim(char *s)
{
    char *e;

    while (*s && isspace((unsigned char)*s))
        s++;
    e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1]))
        *--e = '\0';
    return s;
}

/* '#' starts a comment at the beginning of a line or after whitespace. */
static void strip_comment(char *s)
{
    char *p;

    for (p = s; *p; p++) {
        if (*p == '#' && (p == s || isspace((unsigned char)p[-1]))) {
            *p = '\0';
            return;
        }
    }
}

static int name_ok(const char *s)
{
    size_t n = 0;

    if (!s || !*s)
        return 0;
    for (; *s; s++, n++) {
        if (!(isalnum((unsigned char)*s) || *s == '-' || *s == '_' || *s == '.'))
            return 0;
    }
    return n < DWRT_FEATURES_NAME_MAX;
}

static int mode_ok(const char *s)
{
    size_t n = 0;

    if (!s || !*s)
        return 0;
    for (; *s; s++, n++) {
        if (!(islower((unsigned char)*s) || isdigit((unsigned char)*s) ||
              *s == '-' || *s == '_'))
            return 0;
    }
    return n < DWRT_FEATURES_MODE_MAX;
}

int dwrt_features_function_code_ok(const char *code)
{
    size_t n = 0;

    if (!code || !*code)
        return 0;
    for (; *code; code++, n++) {
        if (!(isupper((unsigned char)*code) || isdigit((unsigned char)*code) ||
              *code == '_'))
            return 0;
    }
    return n <= 64;
}

int dwrt_features_known_arg(const char *key)
{
    return key && (!strcmp(key, "work_dir") || !strcmp(key, "work_mode"));
}

static int path_chars_ok(const char *p)
{
    for (; *p; p++) {
        if (!(isalnum((unsigned char)*p) || *p == '/' || *p == '-' ||
              *p == '_' || *p == '.'))
            return 0;
    }
    return 1;
}

static int has_dotdot_segment(const char *p)
{
    const char *s = p;

    while ((s = strstr(s, "..")) != NULL) {
        int left = (s == p) || s[-1] == '/';
        int right = s[2] == '\0' || s[2] == '/';

        if (left && right)
            return 1;
        s += 2;
    }
    return 0;
}

int dwrt_features_work_dir_ok(const char *path)
{
    size_t n;

    if (!path || path[0] != '/')
        return 0;
    n = strlen(path);
    if (n < 2 || n >= DWRT_FEATURES_ARG_MAX - 16)
        return 0;
    if (!path_chars_ok(path) || has_dotdot_segment(path) || strstr(path, "//"))
        return 0;
    /* /mnt/<name>[/...]: an external mount, never /mnt itself. */
    if (!strncmp(path, "/mnt/", 5) && path[5] && path[5] != '/')
        return 1;
    if (!strcmp(path, "/data/persist") || !strncmp(path, "/data/persist/", 14))
        return 1;
#ifdef DWRT_FEATURES_TEST_WORKDIR_PREFIX
    /* Host tests only; never defined by the package build. */
    if (!strncmp(path, DWRT_FEATURES_TEST_WORKDIR_PREFIX, strlen(DWRT_FEATURES_TEST_WORKDIR_PREFIX)))
        return 1;
#endif
    return 0;
}

int dwrt_features_work_dir_usable(const char *path, char *resolved, size_t resolved_len)
{
    char real[PATH_MAX];
    struct stat st, system;

    if (!dwrt_features_work_dir_ok(path))
        return 0;
    if (!realpath(path, real))
        return 0;
    if (!dwrt_features_work_dir_ok(real))
        return 0;
    if (stat(real, &st) != 0 || !S_ISDIR(st.st_mode))
        return 0;
    if (access(real, R_OK | W_OK | X_OK) != 0)
        return 0;
#ifndef DWRT_FEATURES_TEST_WORKDIR_PREFIX
    /* An empty /mnt/name on overlay is not a mounted data volume. */
    if (stat("/", &system) != 0 || st.st_dev == system.st_dev)
        return 0;
    if (stat("/overlay", &system) == 0 && st.st_dev == system.st_dev)
        return 0;
#else
    (void)system;
#endif
    if (resolved && resolved_len) {
        if (strlen(real) >= resolved_len)
            return 0;
        snprintf(resolved, resolved_len, "%s", real);
    }
    return 1;
}

static int arg_value_ok(const char *key, const char *value)
{
    if (!value || !*value)
        return 0;
    if (!strcmp(key, "work_dir"))
        return dwrt_features_work_dir_ok(value);
    if (!strcmp(key, "work_mode"))
        return mode_ok(value);
    return 0;
}

static struct dwrt_features_entry *entry_slot(struct dwrt_features *f, const char *name)
{
    size_t i;

    for (i = 0; i < f->n_entries; i++) {
        if (!strcmp(f->entries[i].name, name))
            return &f->entries[i];
    }
    if (f->n_entries >= DWRT_FEATURES_MAX_ENTRIES)
        return NULL;
    return &f->entries[f->n_entries++];
}

static void add_function(struct dwrt_features *f, const char *code, int line,
                         dwrt_features_warn_fn warn, void *ctx)
{
    size_t i;

    if (!dwrt_features_function_code_ok(code)) {
        warnf(warn, ctx, f, line, "invalid Disabled_function code '%.64s' skipped", code);
        return;
    }
    for (i = 0; i < f->n_functions; i++) {
        if (!strcmp(f->functions[i], code))
            return;
    }
    if (f->n_functions >= DWRT_FEATURES_MAX_FUNCTIONS) {
        warnf(warn, ctx, f, line, "too many Disabled_function codes; '%s' skipped", code);
        return;
    }
    snprintf(f->functions[f->n_functions++], DWRT_FEATURES_FUNC_MAX, "%s", code);
    f->present = 1;
}

static void add_functions_text(struct dwrt_features *f, char *text, int line,
                               dwrt_features_warn_fn warn, void *ctx)
{
    char *save = NULL;
    char *tok;

    for (tok = strtok_r(text, " \t,", &save); tok; tok = strtok_r(NULL, " \t,", &save))
        add_function(f, tok, line, warn, ctx);
}

static void add_component(struct dwrt_features *f, int state, char *text, int line,
                          dwrt_features_warn_fn warn, void *ctx)
{
    struct dwrt_features_entry *e;
    char *save = NULL;
    char *tok;
    char *name;

    name = strtok_r(text, " \t", &save);
    if (!name_ok(name)) {
        warnf(warn, ctx, f, line, "invalid component name '%.64s' skipped", name ? name : "");
        return;
    }
    e = entry_slot(f, name);
    if (!e) {
        warnf(warn, ctx, f, line, "too many component entries; '%s' skipped", name);
        return;
    }
    if (e->name[0] && e->state != state)
        warnf(warn, ctx, f, line, "%s listed in both Enabled and Disabled; line %d wins",
              name, line);
    memset(e, 0, sizeof(*e));
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->state = state;
    e->line = line;
    f->present = 1;

    while ((tok = strtok_r(NULL, " \t", &save)) != NULL) {
        char key[32];
        const char *eq;
        size_t klen;

        if (state != DWRT_FEATURE_ENABLED) {
            warnf(warn, ctx, f, line, "argument '%.64s' on Disabled entry %s ignored", tok, name);
            continue;
        }
        if (strncmp(tok, "--", 2) != 0 || !(eq = strchr(tok, '=')) || eq == tok + 2) {
            warnf(warn, ctx, f, line, "malformed argument '%.64s' for %s skipped (want --key=value)",
                  tok, name);
            continue;
        }
        klen = (size_t)(eq - (tok + 2));
        if (klen >= sizeof(key)) {
            warnf(warn, ctx, f, line, "argument key too long for %s skipped", name);
            continue;
        }
        memcpy(key, tok + 2, klen);
        key[klen] = '\0';
        if (!dwrt_features_known_arg(key)) {
            warnf(warn, ctx, f, line, "unknown argument --%s for %s skipped", key, name);
            continue;
        }
        if (!arg_value_ok(key, eq + 1)) {
            warnf(warn, ctx, f, line, "rejected value for --%s on %s", key, name);
            continue;
        }
        if (dwrt_features_entry_arg(e, key)) {
            warnf(warn, ctx, f, line, "duplicate --%s for %s skipped", key, name);
            continue;
        }
        if (e->argc >= DWRT_FEATURES_MAX_ARGS || strlen(tok) >= DWRT_FEATURES_ARG_MAX) {
            warnf(warn, ctx, f, line, "argument '%.64s' for %s skipped (limit)", tok, name);
            continue;
        }
        snprintf(e->args[e->argc++], DWRT_FEATURES_ARG_MAX, "%s", tok);
    }
}

static int key_is(const char *key, const char *want)
{
    return strcasecmp(key, want) == 0;
}

int dwrt_features_storage_priority_ok(const char *priority)
{
    static const char *const names[] = { "nvme", "disk", "usb", "sd", "emmc", "system" };
    unsigned seen = 0;
    const char *p = priority;
    if (!p || !*p || strlen(p) >= 128)
        return 0;
    while (*p) {
        const char *end = strchr(p, ',');
        size_t n = end ? (size_t)(end - p) : strlen(p), i;
        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
            if (strlen(names[i]) == n && !strncmp(p, names[i], n))
                break;
        if (i == sizeof(names) / sizeof(names[0]) || (seen & (1U << i)) ||
            (i == 5 && end))
            return 0;
        seen |= 1U << i;
        if (!end)
            return i == 5;
        p = end + 1;
    }
    return 0;
}

/*
 * "Key:" / "Key: value" / "Key :" -- the text before the first ':' is a single
 * identifier. Component lines never contain ':' before their first argument.
 */
static char *header_colon(char *line)
{
    char *colon = strchr(line, ':');
    char *p;

    if (!colon || colon == line)
        return NULL;
    for (p = line; p < colon; p++) {
        if (isspace((unsigned char)*p)) {
            char *q = p;

            while (q < colon && isspace((unsigned char)*q))
                q++;
            return q == colon ? colon : NULL;
        }
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '-'))
            return NULL;
    }
    return colon;
}

int dwrt_features_parse(const char *buf, size_t len, struct dwrt_features *out,
                        dwrt_features_warn_fn warn, void *ctx)
{
    enum section section = SECTION_NONE;
    const char *p = buf;
    const char *end = buf + len;
    int line_no = 0;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (!buf)
        return 0;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t n = nl ? (size_t)(nl - p) : (size_t)(end - p);
        char raw[1024];
        char *line;
        char *colon;

        line_no++;
        if (n >= sizeof(raw)) {
            warnf(warn, ctx, out, line_no, "line too long; skipped");
            p = nl ? nl + 1 : end;
            continue;
        }
        memcpy(raw, p, n);
        raw[n] = '\0';
        p = nl ? nl + 1 : end;
        if (memchr(raw, '\0', n)) {
            warnf(warn, ctx, out, line_no, "NUL byte in line; skipped");
            continue;
        }
        strip_comment(raw);
        line = trim(raw);
        if (!*line)
            continue;

        colon = header_colon(line);
        if (colon) {
            char *key = line;
            char *value;

            *colon = '\0';
            key = trim(key);
            value = trim(colon + 1);
            if (key_is(key, "Preset_version") || key_is(key, "Data_storage") ||
                key_is(key, "Storage_priority") || key_is(key, "Storage_automount")) {
                int valid = 0;
                section = SECTION_NONE;
                if (key_is(key, "Preset_version") && !strcmp(value, "1")) {
                    out->preset_version = 1;
                    valid = 1;
                } else if (key_is(key, "Data_storage") &&
                           (!strcmp(value, "legacy") || !strcmp(value, "auto"))) {
                    snprintf(out->data_storage, sizeof(out->data_storage), "%s", value);
                    valid = 1;
                } else if (key_is(key, "Storage_priority") &&
                           dwrt_features_storage_priority_ok(value)) {
                    snprintf(out->storage_priority, sizeof(out->storage_priority), "%s", value);
                    valid = 1;
                } else if (key_is(key, "Storage_automount") &&
                           (!strcmp(value, "0") || !strcmp(value, "1"))) {
                    out->has_automount = 1;
                    out->storage_automount = value[0] == '1';
                    valid = 1;
                }
                if (valid)
                    out->present = 1;
                else
                    warnf(warn, ctx, out, line_no, "invalid %s ignored", key);
                continue;
            }
            if (key_is(key, "Work_mode")) {
                section = SECTION_NONE;
                if (!mode_ok(value)) {
                    warnf(warn, ctx, out, line_no, "invalid Work_mode '%.32s' ignored", value);
                    continue;
                }
                snprintf(out->work_mode, sizeof(out->work_mode), "%s", value);
                out->present = 1;
                continue;
            }
            if (key_is(key, "Enabled")) {
                section = SECTION_ENABLED;
            } else if (key_is(key, "Disabled")) {
                section = SECTION_DISABLED;
            } else if (key_is(key, "Disabled_function") || key_is(key, "Disabled_functions")) {
                section = SECTION_FUNCTIONS;
                out->has_function_section = 1;
            } else {
                section = SECTION_NONE;
                warnf(warn, ctx, out, line_no, "unknown key '%.32s' skipped", key);
                continue;
            }
            if (*value) {
                if (section == SECTION_FUNCTIONS)
                    add_functions_text(out, value, line_no, warn, ctx);
                else
                    add_component(out, section == SECTION_ENABLED ? DWRT_FEATURE_ENABLED
                                                                  : DWRT_FEATURE_DISABLED,
                                  value, line_no, warn, ctx);
            }
            continue;
        }

        switch (section) {
        case SECTION_ENABLED:
            add_component(out, DWRT_FEATURE_ENABLED, line, line_no, warn, ctx);
            break;
        case SECTION_DISABLED:
            add_component(out, DWRT_FEATURE_DISABLED, line, line_no, warn, ctx);
            break;
        case SECTION_FUNCTIONS:
            add_functions_text(out, line, line_no, warn, ctx);
            break;
        default:
            warnf(warn, ctx, out, line_no, "line outside any section skipped");
            break;
        }
    }
    return 0;
}

int dwrt_features_load(const char *path, struct dwrt_features *out,
                       dwrt_features_warn_fn warn, void *ctx)
{
    FILE *fp;
    char *buf;
    size_t n;
    int rc;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (!path)
        path = DWRT_FEATURES_PATH;
    fp = fopen(path, "re");
    if (!fp)
        return errno == ENOENT ? 0 : -1;
    buf = malloc(DWRT_FEATURES_MAX_BYTES + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    n = fread(buf, 1, DWRT_FEATURES_MAX_BYTES + 1, fp);
    if (ferror(fp) || n > DWRT_FEATURES_MAX_BYTES) {
        fclose(fp);
        free(buf);
        if (warn)
            warn(ctx, 0, n > DWRT_FEATURES_MAX_BYTES ? "file exceeds 64 KiB; ignored"
                                                     : "read error; ignored");
        return -1;
    }
    fclose(fp);
    rc = dwrt_features_parse(buf, n, out, warn, ctx);
    free(buf);
    return rc;
}

const struct dwrt_features_entry *dwrt_features_find(const struct dwrt_features *f,
                                                     const char *name)
{
    size_t i;

    if (!f || !name)
        return NULL;
    for (i = 0; i < f->n_entries; i++) {
        if (!strcmp(f->entries[i].name, name))
            return &f->entries[i];
    }
    return NULL;
}

const char *dwrt_features_entry_arg(const struct dwrt_features_entry *e, const char *key)
{
    size_t klen;
    int i;

    if (!e || !key)
        return NULL;
    klen = strlen(key);
    for (i = 0; i < e->argc; i++) {
        const char *a = e->args[i];

        if (!strncmp(a, "--", 2) && !strncmp(a + 2, key, klen) && a[2 + klen] == '=')
            return a + 3 + klen;
    }
    return NULL;
}

const char *dwrt_args_get(int argc, char **argv, const char *key)
{
    size_t klen;
    int i;

    if (!argv || !key)
        return NULL;
    while (*key == '-')
        key++;
    klen = strlen(key);
    if (!klen)
        return NULL;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (a && !strncmp(a, "--", 2) && !strncmp(a + 2, key, klen) && a[2 + klen] == '=')
            return a + 3 + klen;
    }
    return NULL;
}
