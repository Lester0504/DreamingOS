// SPDX-License-Identifier: GPL-2.0-or-later
#include "storage/storage_migration.h"

#include <json-c/json.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>

/* Capture the real producer transport without touching host syslog. */
void syslog(int priority, const char *format, ...)
{
    va_list ap;
    (void)priority;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static int g_reopen_rc;
static int g_reopen_fail_once;
static int g_freeze_rc;
static int g_freeze_calls;
static int g_unfreeze_calls;

static int join_path(char *out, size_t out_len, const char *base,
                     const char *suffix)
{
    size_t base_len;
    size_t suffix_len;

    if (!out || !out_len || !base || !suffix)
        return -1;
    base_len = strlen(base);
    suffix_len = strlen(suffix);
    if (base_len >= out_len || suffix_len > out_len - base_len - 1)
        return -1;
    memcpy(out, base, base_len);
    memcpy(out + base_len, suffix, suffix_len);
    out[base_len + suffix_len] = '\0';
    return 0;
}

static int freeze_consumer(const char *use, void *arg)
{
    (void)arg;
    if (!use)
        return -1;
    g_freeze_calls++;
    return g_freeze_rc;
}

static int unfreeze_consumer(const char *use, void *arg)
{
    (void)arg;
    if (!use)
        return -1;
    g_unfreeze_calls++;
    return 0;
}

static int reopen_consumer(const char *use, const char *old_path,
                           const char *new_path, void *arg)
{
    (void)arg;
    if (!use || !old_path || !new_path)
        return -1;
    if (g_reopen_fail_once) {
        g_reopen_fail_once = 0;
        return -1;
    }
    return g_reopen_rc;
}

static struct json_object *request(const char *use, const char *provider,
                                   const char *old_path, const char *new_path,
                                   int confirm, int dry_run)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "use", json_object_new_string(use));
    json_object_object_add(o, "provider_id", json_object_new_string(provider));
    json_object_object_add(o, "old_path", json_object_new_string(old_path));
    json_object_object_add(o, "new_path", json_object_new_string(new_path));
    json_object_object_add(o, "snapshot_id", json_object_new_string("fixture-1"));
    json_object_object_add(o, "confirm", json_object_new_boolean(confirm));
    json_object_object_add(o, "dry_run", json_object_new_boolean(dry_run));
    return o;
}

int main(int argc, char **argv)
{
    struct json_object *r;

    if (argc != 3)
        return 2;
    jmx_storage_migration_set_consumer_reopen_hook(reopen_consumer, NULL);

    r = jmx_storage_migration_apply(request("audit", "uuid:fixture",
                                            argv[1], argv[2], 0, 1));
    puts(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN));
    json_object_put(r);

    r = jmx_storage_migration_apply(request("audit", "uuid:fixture",
                                            argv[1], argv[2], 0, 0));
    puts(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN));
    json_object_put(r);

    g_reopen_rc = 0;
    r = jmx_storage_migration_apply(request("audit", "uuid:fixture",
                                            argv[1], argv[2], 1, 0));
    puts(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN));
    json_object_put(r);

    jmx_storage_migration_set_consumer_freeze_hooks(freeze_consumer,
                                                    unfreeze_consumer, NULL);
    r = jmx_storage_migration_apply(request("audit", "uuid:fixture",
                                            argv[1], argv[2], 1, 0));
    puts(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN));
    json_object_put(r);

    {
        char failed_old[4096], failed_new[4096];
        FILE *fp;

        if (join_path(failed_old, sizeof(failed_old), argv[1], "-failure") != 0 ||
            join_path(failed_new, sizeof(failed_new), argv[2], "-failure") != 0)
            return 6;
        fp = fopen(failed_old, "wb");
        if (!fp)
            return 3;
        fputs("rollback-fixture", fp);
        fclose(fp);
        g_reopen_rc = 0;
        g_reopen_fail_once = 1;
        r = jmx_storage_migration_apply(request("audit", "uuid:fixture",
                                                failed_old, failed_new, 1, 0));
        puts(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN));
        json_object_put(r);
    }

    {
        char dir_old[4096], dir_new[4096], quoted_file[4096];
        FILE *fp;

        if (join_path(dir_old, sizeof(dir_old), argv[1], "-directory") != 0 ||
            join_path(dir_new, sizeof(dir_new), argv[2], "-directory") != 0 ||
            join_path(quoted_file, sizeof(quoted_file), dir_old,
                      "/quote\"name.txt") != 0)
            return 6;
        if (mkdir(dir_old, 0750) != 0)
            return 4;
        fp = fopen(quoted_file, "wb");
        if (!fp)
            return 5;
        fputs("directory-fixture", fp);
        fclose(fp);
        g_reopen_rc = 0;
        r = jmx_storage_migration_apply(request("snapshots", "uuid:fixture",
                                                dir_old, dir_new, 1, 0));
        puts(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN));
        json_object_put(r);
    }
    return 0;
}
