// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "jmx_dataset_path.h"
#include "storage/storage_binding.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DATASET_CACHE_SLOTS 32

struct dataset_slot {
    const char *use;
    const char *leaf;
    const char *value;
    unsigned generation;
};

static pthread_mutex_t g_dataset_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dataset_slot g_dataset_slots[DATASET_CACHE_SLOTS];
static unsigned g_dataset_generation = 1;
static int g_dataset_have_stamp;
static struct stat g_dataset_stamp;

/* Caller holds the lock. Bumps the generation when assignments.json changed. */
static void dataset_refresh_stamp(void)
{
    struct stat st;
    int have = stat(JMX_STORAGE_ASSIGNMENTS_PATH, &st) == 0;

    if (have == g_dataset_have_stamp &&
        (!have || (st.st_ino == g_dataset_stamp.st_ino &&
                   st.st_size == g_dataset_stamp.st_size &&
                   st.st_mtime == g_dataset_stamp.st_mtime &&
#ifdef __APPLE__
                   st.st_mtimespec.tv_nsec == g_dataset_stamp.st_mtimespec.tv_nsec)))
#else
                   st.st_mtim.tv_nsec == g_dataset_stamp.st_mtim.tv_nsec)))
#endif
        return;
    g_dataset_have_stamp = have;
    if (have)
        g_dataset_stamp = st;
    g_dataset_generation++;
}

static void dataset_compute(const char *use, const char *leaf, char *out, size_t out_len)
{
    char active[4096] = "";
    const char *base;

    if (jmx_storage_binding_read(use, NULL, 0, active, sizeof(active),
                                 NULL, 0, NULL, 0) != 0)
        snprintf(active, sizeof(active), "/dev/null/dreamingwrt-storage-unavailable");
    base = active[0] == '/' ? active : jmx_storage_binding_default_path(use);
    if (leaf)
        snprintf(out, out_len, "%s/%s", base, leaf);
    else
        snprintf(out, out_len, "%s", base);
}

static const char *dataset_lookup(const char *use, const char *leaf)
{
    struct dataset_slot *slot = NULL;
    const char *result;
    char path[4096];
    size_t i;

    pthread_mutex_lock(&g_dataset_lock);
    dataset_refresh_stamp();
    for (i = 0; i < DATASET_CACHE_SLOTS; i++) {
        struct dataset_slot *s = &g_dataset_slots[i];

        if (s->use && !strcmp(s->use, use) &&
            ((!s->leaf && !leaf) || (s->leaf && leaf && !strcmp(s->leaf, leaf)))) {
            slot = s;
            break;
        }
        if (!s->use && !slot) {
            slot = s;
            slot->use = use;
            slot->leaf = leaf;
            break;
        }
    }
    if (!slot) {
        /*
         * More distinct (use, leaf) pairs than slots -- a programming error,
         * the set is fixed at compile time. Stay correct, not immutable: the
         * thread-local copy is valid until this thread's next overflow call.
         */
        static __thread char overflow[4096];

        pthread_mutex_unlock(&g_dataset_lock);
        dataset_compute(use, leaf, overflow, sizeof(overflow));
        return overflow;
    }
    if (!slot->value || slot->generation != g_dataset_generation) {
        dataset_compute(use, leaf, path, sizeof(path));
        if (!slot->value || strcmp(slot->value, path) != 0) {
            char *fresh = strdup(path);

            if (fresh)
                slot->value = fresh; /* previous string intentionally retained */
        }
        slot->generation = g_dataset_generation;
    }
    result = slot->value ? slot->value : "/dev/null/dreamingwrt-storage-unavailable";
    /* Readiness can change without assignments.json changing (disk removal).
     * Do not let SQLITE_OPEN_CREATE make a replacement empty authority. */
    const char *fallback = jmx_storage_binding_default_path(use);
    char expected[4096];
    char external_root[4096];
    const char *ready_path = result;
    if (leaf && strlen(result) > strlen(leaf) + 1) {
        size_t n = strlen(result) - strlen(leaf) - 1;
        memcpy(external_root, result, n);
        external_root[n] = '\0';
        ready_path = external_root;
    }
    snprintf(expected, sizeof(expected), "%s%s%s", fallback, leaf ? "/" : "", leaf ? leaf : "");
    if (strcmp(result, expected) &&
        !jmx_storage_binding_path_ready(ready_path,
            leaf || !strcmp(use, "audit") || !strcmp(use, "aegis_work") ||
            !strcmp(use, "snapshots")))
        result = "/dev/null/dreamingwrt-storage-unavailable";
    pthread_mutex_unlock(&g_dataset_lock);
    return result;
}

const char *jmx_dataset_path(const char *use)
{
    if (!use)
        return "";
    return dataset_lookup(use, NULL);
}

const char *jmx_dataset_child(const char *use, const char *leaf)
{
    if (!use || !leaf)
        return "";
    return dataset_lookup(use, leaf);
}
