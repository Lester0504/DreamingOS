/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DW_MEMORY_DIAGNOSTICS_H
#define DW_MEMORY_DIAGNOSTICS_H

/* On-demand accounting only. Allocation sizes and RSS overlap; never sum them. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <json-c/json.h>
#include <sqlite3.h>
#ifdef __GLIBC__
#include <malloc.h>
#endif

static inline void dw_mem_u64(struct json_object *o, const char *key, uint64_t n)
{
    json_object_object_add(o, key, json_object_new_int64((int64_t)n));
}

static inline struct json_object *dw_mem_unknown(const char *reason)
{
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "available", json_object_new_boolean(0));
    json_object_object_add(o, "reason", json_object_new_string(reason));
    return o;
}

/* Counts content, without serializing (and thereby allocating a print buffer).
 * String bytes/nodes exclude json-c tables, capacity slack and allocator metadata. */
static inline void dw_mem_json_content(struct json_object *o,
                                       uint64_t *nodes, uint64_t *strings)
{
    if (!o) return;
    ++*nodes;
    switch (json_object_get_type(o)) {
    case json_type_string:
        *strings += (uint64_t)json_object_get_string_len(o) + 1;
        break;
    case json_type_array:
        for (size_t i = 0; i < json_object_array_length(o); ++i)
            dw_mem_json_content(json_object_array_get_idx(o, i), nodes, strings);
        break;
    case json_type_object: {
        json_object_object_foreach(o, key, value) {
            *strings += strlen(key) + 1;
            dw_mem_json_content(value, nodes, strings);
        }
        break;
    }
    default: break;
    }
}

static inline struct json_object *dw_mem_sqlite(sqlite3 *db)
{
    static const struct { const char *name; int op; } fields[] = {
        { "cache_bytes", SQLITE_DBSTATUS_CACHE_USED },
        { "schema_bytes", SQLITE_DBSTATUS_SCHEMA_USED },
        { "statement_bytes", SQLITE_DBSTATUS_STMT_USED },
    };
    struct json_object *o;
    if (!db) return dw_mem_unknown("connection_not_open");
    o = json_object_new_object();
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        int current = 0, high = 0;
        int rc = sqlite3_db_status(db, fields[i].op, &current, &high, 0);
        json_object_object_add(o, fields[i].name,
            rc == SQLITE_OK ? json_object_new_int64(current) : NULL);
    }
    json_object_object_add(o, "temp_bytes", NULL);
    json_object_object_add(o, "temp_reason", json_object_new_string(
        "sqlite_has_no_per_connection_temp_byte_counter; cache_includes_pagers"));
    return o;
}

static inline struct json_object *dw_mem_process(void)
{
    struct json_object *o = json_object_new_object();
    struct json_object *allocator;
    struct json_object *proc = json_object_new_object();
    FILE *fp;
    char line[256], key[64];
    unsigned long long kib;
    static const char *keys[] = {
        "VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM", "VmLck", "VmSwap"
    };
    dw_mem_u64(o, "pid", (uint64_t)getpid());
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 33)
    struct mallinfo2 mi = mallinfo2();
    allocator = json_object_new_object();
    json_object_object_add(allocator, "provider", json_object_new_string("glibc.mallinfo2"));
    dw_mem_u64(allocator, "arena_bytes", mi.arena);
    dw_mem_u64(allocator, "allocated_arena_bytes", mi.uordblks);
    dw_mem_u64(allocator, "free_arena_bytes", mi.fordblks);
    dw_mem_u64(allocator, "allocated_mmap_bytes", mi.hblkhd);
    dw_mem_u64(allocator, "top_releasable_bytes", mi.keepcost);
    json_object_object_add(allocator, "note", json_object_new_string(
        "allocator_accounting_not_residency; tcache_may_count_as_allocated; free_is_not_all_releasable"));
#else
    allocator = dw_mem_unknown("glibc_without_mallinfo2");
#endif
#else
    allocator = dw_mem_unknown("allocator_has_no_live_free_counter; use_module_counters_and_proc");
#endif
    json_object_object_add(o, "allocator", allocator);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
        json_object_object_add(proc, keys[i], NULL);
    fp = fopen("/proc/self/status", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "%63[^:]: %llu kB", key, &kib) != 2) continue;
            for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
                if (!strcmp(key, keys[i])) dw_mem_u64(proc, key, kib * 1024);
        }
        fclose(fp);
    } else {
        json_object_object_add(proc, "reason", json_object_new_string("proc_status_unavailable"));
    }
    json_object_object_add(proc, "Pss", NULL);
    fp = fopen("/proc/self/smaps_rollup", "r");
    if (!fp) fp = fopen("/proc/self/smaps", "r");
    if (fp) {
        uint64_t pss = 0;
        int found = 0;
        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "Pss: %llu kB", &kib) == 1) {
                pss += kib * 1024;
                found = 1;
            }
        }
        fclose(fp);
        if (found) dw_mem_u64(proc, "Pss", pss);
        else json_object_object_add(proc, "pss_reason", json_object_new_string("pss_counter_unavailable"));
    } else {
        json_object_object_add(proc, "pss_reason", json_object_new_string("smaps_unavailable"));
    }
    json_object_object_add(o, "proc_bytes", proc);
    json_object_object_add(o, "unattributed_anon_bytes", NULL);
    json_object_object_add(o, "accounting_note", json_object_new_string(
        "module_allocations_and_allocator_totals_overlap; allocation_bytes_cannot_be_subtracted_from_RssAnon"));
    return o;
}
#endif
