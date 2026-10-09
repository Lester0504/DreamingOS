/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "dw_read_model.h"
#include "system/memory_profile.h"
#include <stdatomic.h>

#include <errno.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#define DW_RM_DEFAULT_PERIOD_MS 1000U
#define DW_RM_DEFAULT_RING_SLOTS 64U
#define DW_RM_DEFAULT_RING_BYTES (32U * 1024U * 1024U)
#define DW_RM_MAX_RING_SLOTS 256U
#define DW_RM_DURATION_SAMPLES 64U
#define DW_RM_MAX_RESOURCES 16U

struct dw_rm_delta_entry {
    uint64_t revision;
    int64_t observed_at;
    void *payload;
    size_t bytes;
};

struct dw_rm_resource {
    char name[64];
    char contract[96];
    char snapshot_id[40];
    unsigned int period_ms;
    unsigned int stale_after_ms;
    size_t ring_slots;
    size_t ring_bytes_max;
    size_t ring_slot_limit;
    size_t standard_ring_bytes;
    unsigned int standard_period_ms;
    int memory_profile;
    int64_t memory_revision;
    atomic_int_fast64_t last_reader_ms;
    void *context;
    struct dw_rm_ops ops;

    pthread_rwlock_t lock;
    pthread_mutex_t worker_lock;
    pthread_cond_t worker_cond;
    pthread_t worker;
    int worker_started;
    int stop_requested;

    void *generation;
    uint64_t revision;
    int64_t observed_at;
    int64_t collect_ms;
    uint64_t scanned_rows;
    int complete;

    struct dw_rm_delta_entry *ring;
    size_t ring_start;
    size_t ring_count;
    size_t ring_bytes;
    size_t ring_bytes_peak;
    uint64_t scanned_rows_peak;
    uint64_t resume_floor_revision;
    enum dw_rm_resume_result resume_floor_reason;

    uint64_t collect_runs;
    uint64_t collect_failures;
    uint64_t publish_count;
    uint64_t delta_build_failures;
    int64_t collect_ms_max;
    int64_t duration_samples[DW_RM_DURATION_SAMPLES];
    size_t duration_count;
    size_t duration_next;
};

static pthread_mutex_t g_dw_rm_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct dw_rm_resource *g_dw_rm_resources[DW_RM_MAX_RESOURCES];
static size_t g_dw_rm_resource_count;

static int64_t dw_rm_mono_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void dw_rm_make_snapshot_id(const char *name, char out[40])
{
    FILE *fp = fopen("/proc/sys/kernel/random/boot_id", "r");
    char boot_id[80] = "";
    char seed[192];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char random_bytes[32];
    size_t i;

    if (fp) {
        if (!fgets(boot_id, sizeof(boot_id), fp))
            boot_id[0] = '\0';
        fclose(fp);
    }
    if (!boot_id[0]) {
        char random_hex[sizeof(random_bytes) * 2 + 1];

        if (getrandom(random_bytes, sizeof(random_bytes), 0) !=
            (ssize_t)sizeof(random_bytes)) {
            uint64_t fallback = (uint64_t)time(NULL) ^ (uint64_t)getpid();

            memset(random_bytes, 0, sizeof(random_bytes));
            memcpy(random_bytes, &fallback, sizeof(fallback));
        }
        for (i = 0; i < sizeof(random_bytes); i++)
            snprintf(random_hex + i * 2, sizeof(random_hex) - i * 2,
                     "%02x", random_bytes[i]);
        snprintf(boot_id, sizeof(boot_id), "%s", random_hex);
    }
    snprintf(seed, sizeof(seed), "%s|%s", boot_id, name ? name : "resource");
    SHA256((const unsigned char *)seed, strlen(seed), digest);
    memcpy(out, "boot:", 5);
    for (i = 0; i < 16; i++)
        snprintf(out + 5 + i * 2, 40 - 5 - i * 2, "%02x", digest[i]);
}

static void dw_rm_free_delta(struct dw_rm_resource *resource,
                             struct dw_rm_delta_entry *entry)
{
    if (!resource || !entry)
        return;
    if (entry->payload && resource->ops.free_delta)
        resource->ops.free_delta(resource->context, entry->payload);
    memset(entry, 0, sizeof(*entry));
}

static void dw_rm_evict_oldest(struct dw_rm_resource *resource)
{
    struct dw_rm_delta_entry *entry;

    if (!resource || !resource->ring_count)
        return;
    entry = &resource->ring[resource->ring_start];
    if (resource->ring_bytes >= entry->bytes)
        resource->ring_bytes -= entry->bytes;
    else
        resource->ring_bytes = 0;
    dw_rm_free_delta(resource, entry);
    resource->ring_start = (resource->ring_start + 1) % resource->ring_slots;
    resource->ring_count--;
}

static void dw_rm_clear_ring(struct dw_rm_resource *resource)
{
    while (resource && resource->ring_count)
        dw_rm_evict_oldest(resource);
}

static void dw_rm_record_duration(struct dw_rm_resource *resource,
                                  int64_t collect_ms)
{
    resource->duration_samples[resource->duration_next] = collect_ms;
    resource->duration_next = (resource->duration_next + 1) %
                              DW_RM_DURATION_SAMPLES;
    if (resource->duration_count < DW_RM_DURATION_SAMPLES)
        resource->duration_count++;
    if (collect_ms > resource->collect_ms_max)
        resource->collect_ms_max = collect_ms;
}

static void dw_rm_publish(struct dw_rm_resource *resource,
                          struct dw_rm_collect_result *result,
                          int64_t collect_ms)
{
    void *previous;
    void *delta = NULL;
    size_t delta_bytes = 0;
    int diff_ok = 0;
    uint64_t next_revision;

    /* Comparison may be much slower than pointer publication. Keep the old
     * immutable generation readable while the single producer builds its
     * delta, then take the write lock only for ownership transfer and ring
     * bookkeeping. */
    pthread_rwlock_rdlock(&resource->lock);
    previous = resource->generation;
    next_revision = resource->revision + 1;
    if (previous && resource->ops.diff &&
        resource->ops.diff(resource->context, previous, result->generation,
                           &delta, &delta_bytes) == 0)
        diff_ok = 1;
    pthread_rwlock_unlock(&resource->lock);

    pthread_rwlock_wrlock(&resource->lock);

    resource->generation = result->generation;
    result->generation = NULL;
    resource->revision = next_revision;
    resource->observed_at = result->observed_at > 0 ?
                            result->observed_at : (int64_t)time(NULL);
    resource->collect_ms = collect_ms;
    resource->scanned_rows = result->scanned_rows;
    if (result->scanned_rows > resource->scanned_rows_peak)
        resource->scanned_rows_peak = result->scanned_rows;
    resource->complete = result->complete;
    resource->collect_runs++;
    resource->publish_count++;
    dw_rm_record_duration(resource, collect_ms);

    if (!previous) {
        resource->resume_floor_revision = next_revision;
        resource->resume_floor_reason = DW_RM_RESUME_SOURCE_REBUILT;
    } else if (!diff_ok) {
        resource->delta_build_failures++;
        dw_rm_clear_ring(resource);
        resource->resume_floor_revision = next_revision;
        resource->resume_floor_reason = DW_RM_RESUME_SOURCE_REBUILT;
    } else if (delta_bytes > resource->ring_bytes_max) {
        if (delta && resource->ops.free_delta)
            resource->ops.free_delta(resource->context, delta);
        delta = NULL;
        dw_rm_clear_ring(resource);
        resource->resume_floor_revision = next_revision;
        resource->resume_floor_reason = DW_RM_RESUME_REVISION_TOO_OLD;
    } else {
        struct dw_rm_delta_entry *entry;
        size_t slot;

        while (resource->ring_count >= resource->ring_slot_limit ||
               (resource->ring_count && resource->ring_bytes + delta_bytes >
                resource->ring_bytes_max))
            dw_rm_evict_oldest(resource);
        slot = (resource->ring_start + resource->ring_count) %
               resource->ring_slots;
        entry = &resource->ring[slot];
        entry->revision = next_revision;
        entry->observed_at = resource->observed_at;
        entry->payload = delta;
        entry->bytes = delta_bytes;
        resource->ring_count++;
        resource->ring_bytes += delta_bytes;
        if (resource->ring_bytes > resource->ring_bytes_peak)
            resource->ring_bytes_peak = resource->ring_bytes;
    }
    pthread_rwlock_unlock(&resource->lock);

    if (previous && resource->ops.free_generation)
        resource->ops.free_generation(resource->context, previous);
}

static void dw_rm_record_collect_failure(struct dw_rm_resource *resource,
                                         int64_t collect_ms)
{
    pthread_rwlock_wrlock(&resource->lock);
    resource->collect_runs++;
    resource->collect_failures++;
    resource->collect_ms = collect_ms;
    dw_rm_record_duration(resource, collect_ms);
    pthread_rwlock_unlock(&resource->lock);
}

static void dw_rm_memory_policy(struct dw_rm_resource *r)
{
    if (!r->memory_profile) return;
    struct dw_memory_profile p;
    dw_mp_load(&p);
    int64_t last = atomic_load(&r->last_reader_ms);
    pthread_rwlock_wrlock(&r->lock);
    r->period_ms = p.compact ? ((last && dw_rm_mono_ms() - last < 10000) ? 2000U : 5000U) : r->standard_period_ms;
    r->stale_after_ms = r->period_ms * 3U;
    r->ring_slot_limit = p.compact && r->ring_slots > 16 ? 16 : r->ring_slots;
    r->ring_bytes_max = p.compact && r->standard_ring_bytes > 4 * DW_MP_MIB ? 4 * DW_MP_MIB : r->standard_ring_bytes;
    r->memory_revision = p.revision;
    while (r->ring_count > r->ring_slot_limit || r->ring_bytes > r->ring_bytes_max)
        dw_rm_evict_oldest(r);
    pthread_rwlock_unlock(&r->lock);
}

static void *dw_rm_worker(void *argument)
{
    struct dw_rm_resource *resource = argument;

    for (;;) {
        struct dw_rm_collect_result result;
        struct timespec deadline;
        int64_t started = dw_rm_mono_ms();
        int rc;

        dw_rm_memory_policy(resource);
        memset(&result, 0, sizeof(result));
        rc = resource->ops.collect(resource->context, &result);
        if (rc == 0 && result.generation)
            dw_rm_publish(resource, &result, dw_rm_mono_ms() - started);
        else {
            if (result.generation && resource->ops.free_generation)
                resource->ops.free_generation(resource->context,
                                              result.generation);
            dw_rm_record_collect_failure(resource, dw_rm_mono_ms() - started);
        }

        pthread_mutex_lock(&resource->worker_lock);
        if (resource->stop_requested) {
            pthread_mutex_unlock(&resource->worker_lock);
            break;
        }
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_nsec += (resource->period_ms % 1000U) * 1000000L;
        deadline.tv_sec += resource->period_ms / 1000U +
                           deadline.tv_nsec / 1000000000L;
        deadline.tv_nsec %= 1000000000L;
        (void)pthread_cond_timedwait(&resource->worker_cond,
                                     &resource->worker_lock, &deadline);
        if (resource->stop_requested) {
            pthread_mutex_unlock(&resource->worker_lock);
            break;
        }
        pthread_mutex_unlock(&resource->worker_lock);
    }
    return NULL;
}

static int dw_rm_registry_add(struct dw_rm_resource *resource)
{
    int rc = -1;

    pthread_mutex_lock(&g_dw_rm_registry_lock);
    if (g_dw_rm_resource_count < DW_RM_MAX_RESOURCES) {
        g_dw_rm_resources[g_dw_rm_resource_count++] = resource;
        rc = 0;
    }
    pthread_mutex_unlock(&g_dw_rm_registry_lock);
    return rc;
}

static void dw_rm_registry_remove(struct dw_rm_resource *resource)
{
    size_t i;

    pthread_mutex_lock(&g_dw_rm_registry_lock);
    for (i = 0; i < g_dw_rm_resource_count; i++) {
        if (g_dw_rm_resources[i] != resource)
            continue;
        memmove(&g_dw_rm_resources[i], &g_dw_rm_resources[i + 1],
                (g_dw_rm_resource_count - i - 1) *
                sizeof(g_dw_rm_resources[0]));
        g_dw_rm_resource_count--;
        break;
    }
    pthread_mutex_unlock(&g_dw_rm_registry_lock);
}

int dw_rm_create(const struct dw_rm_config *config,
                 struct dw_rm_resource **resource_out)
{
    struct dw_rm_resource *resource;

    if (resource_out)
        *resource_out = NULL;
    if (!config || !resource_out || !config->name || !config->name[0] ||
        !config->contract || !config->contract[0] || !config->ops.collect ||
        !config->ops.free_generation || !config->ops.diff ||
        !config->ops.free_delta)
        return -1;
    resource = calloc(1, sizeof(*resource));
    if (!resource)
        return -1;
    snprintf(resource->name, sizeof(resource->name), "%s", config->name);
    snprintf(resource->contract, sizeof(resource->contract), "%s",
             config->contract);
    resource->period_ms = config->period_ms ? config->period_ms :
                          DW_RM_DEFAULT_PERIOD_MS;
    resource->stale_after_ms = config->stale_after_ms ?
                               config->stale_after_ms :
                               resource->period_ms * 3U;
    resource->ring_slots = config->ring_slots ? config->ring_slots :
                           DW_RM_DEFAULT_RING_SLOTS;
    if (resource->ring_slots > DW_RM_MAX_RING_SLOTS)
        resource->ring_slots = DW_RM_MAX_RING_SLOTS;
    resource->ring_bytes_max = config->ring_bytes_max ?
                               config->ring_bytes_max :
                               DW_RM_DEFAULT_RING_BYTES;
    resource->context = config->context;
    resource->ops = config->ops;
    resource->ring_slot_limit = resource->ring_slots;
    resource->standard_ring_bytes = resource->ring_bytes_max;
    resource->standard_period_ms = resource->period_ms;
    resource->memory_profile = config->memory_profile;
    atomic_init(&resource->last_reader_ms, 0);
    resource->ring = calloc(resource->ring_slots, sizeof(*resource->ring));
    if (!resource->ring) {
        free(resource);
        return -1;
    }
    pthread_rwlock_init(&resource->lock, NULL);
    pthread_mutex_init(&resource->worker_lock, NULL);
    pthread_cond_init(&resource->worker_cond, NULL);
    dw_rm_make_snapshot_id(resource->name, resource->snapshot_id);
    if (dw_rm_registry_add(resource) != 0) {
        pthread_cond_destroy(&resource->worker_cond);
        pthread_mutex_destroy(&resource->worker_lock);
        pthread_rwlock_destroy(&resource->lock);
        free(resource->ring);
        free(resource);
        return -1;
    }
    *resource_out = resource;
    return 0;
}

int dw_rm_start(struct dw_rm_resource *resource)
{
    int rc;

    if (!resource)
        return -1;
    pthread_mutex_lock(&resource->worker_lock);
    if (resource->worker_started) {
        pthread_mutex_unlock(&resource->worker_lock);
        return 0;
    }
    resource->stop_requested = 0;
    rc = pthread_create(&resource->worker, NULL, dw_rm_worker, resource);
    if (rc == 0)
        resource->worker_started = 1;
    pthread_mutex_unlock(&resource->worker_lock);
    return rc == 0 ? 0 : -1;
}

void dw_rm_stop(struct dw_rm_resource *resource)
{
    if (!resource)
        return;
    pthread_mutex_lock(&resource->worker_lock);
    if (!resource->worker_started) {
        pthread_mutex_unlock(&resource->worker_lock);
        return;
    }
    resource->stop_requested = 1;
    pthread_cond_broadcast(&resource->worker_cond);
    pthread_mutex_unlock(&resource->worker_lock);
    pthread_join(resource->worker, NULL);
    pthread_mutex_lock(&resource->worker_lock);
    resource->worker_started = 0;
    pthread_mutex_unlock(&resource->worker_lock);
}

void dw_rm_destroy(struct dw_rm_resource *resource)
{
    void *generation;

    if (!resource)
        return;
    dw_rm_stop(resource);
    dw_rm_registry_remove(resource);
    pthread_rwlock_wrlock(&resource->lock);
    generation = resource->generation;
    resource->generation = NULL;
    dw_rm_clear_ring(resource);
    pthread_rwlock_unlock(&resource->lock);
    if (generation)
        resource->ops.free_generation(resource->context, generation);
    pthread_cond_destroy(&resource->worker_cond);
    pthread_mutex_destroy(&resource->worker_lock);
    pthread_rwlock_destroy(&resource->lock);
    free(resource->ring);
    free(resource);
}

static void dw_rm_fill_view_locked(struct dw_rm_resource *resource,
                                   struct dw_rm_view *view)
{
    int64_t age_ms;

    memset(view, 0, sizeof(*view));
    view->resource = resource;
    view->generation = resource->generation;
    view->name = resource->name;
    view->contract = resource->contract;
    view->snapshot_id = resource->snapshot_id;
    view->revision = resource->revision;
    view->observed_at = resource->observed_at;
    view->collect_ms = resource->collect_ms;
    view->scanned_rows = resource->scanned_rows;
    view->complete = resource->complete;
    age_ms = resource->observed_at > 0 ?
             ((int64_t)time(NULL) - resource->observed_at) * 1000 : INT64_MAX;
    view->stale = age_ms > (int64_t)resource->stale_after_ms;
    view->locked = 1;
}

int dw_rm_view_begin(struct dw_rm_resource *resource, struct dw_rm_view *view)
{
    if (!resource || !view)
        return -1;
    atomic_store(&resource->last_reader_ms, dw_rm_mono_ms());
    pthread_rwlock_rdlock(&resource->lock);
    dw_rm_fill_view_locked(resource, view);
    return resource->generation ? 0 : -EAGAIN;
}

enum dw_rm_resume_result dw_rm_resume_begin(struct dw_rm_resource *resource,
                                            const char *snapshot_id,
                                            uint64_t since_revision,
                                            struct dw_rm_view *view)
{
    uint64_t oldest_base;
    size_t i;

    if (!resource || !view)
        return DW_RM_RESUME_BUILDING;
    atomic_store(&resource->last_reader_ms, dw_rm_mono_ms());
    pthread_rwlock_rdlock(&resource->lock);
    dw_rm_fill_view_locked(resource, view);
    view->base_revision = since_revision;
    if (!resource->generation)
        return DW_RM_RESUME_BUILDING;
    if (!snapshot_id || strcmp(snapshot_id, resource->snapshot_id))
        return DW_RM_RESUME_SNAPSHOT_CHANGED;
    if (since_revision > resource->revision)
        return DW_RM_RESUME_REVISION_AHEAD;
    if (since_revision < resource->resume_floor_revision)
        return resource->resume_floor_reason;
    oldest_base = resource->ring_count ?
        resource->ring[resource->ring_start].revision - 1 : resource->revision;
    if (since_revision < oldest_base)
        return DW_RM_RESUME_REVISION_TOO_OLD;
    for (i = 0; i < resource->ring_count; i++) {
        struct dw_rm_delta_entry *entry = &resource->ring[
            (resource->ring_start + i) % resource->ring_slots];

        if (entry->revision <= since_revision)
            continue;
        view->delta_offset = i;
        view->delta_count = resource->ring_count - i;
        return DW_RM_RESUME_OK;
    }
    view->delta_offset = resource->ring_count;
    view->delta_count = 0;
    return DW_RM_RESUME_OK;
}

const void *dw_rm_view_delta_at(const struct dw_rm_view *view, size_t index,
                                uint64_t *revision, int64_t *observed_at,
                                size_t *bytes)
{
    struct dw_rm_resource *resource;
    struct dw_rm_delta_entry *entry;
    size_t logical;

    if (!view || !view->locked || index >= view->delta_count)
        return NULL;
    resource = view->resource;
    logical = view->delta_offset + index;
    entry = &resource->ring[(resource->ring_start + logical) %
                            resource->ring_slots];
    if (revision)
        *revision = entry->revision;
    if (observed_at)
        *observed_at = entry->observed_at;
    if (bytes)
        *bytes = entry->bytes;
    return entry->payload;
}

void dw_rm_view_end(struct dw_rm_view *view)
{
    if (!view || !view->locked || !view->resource)
        return;
    pthread_rwlock_unlock(&view->resource->lock);
    memset(view, 0, sizeof(*view));
}

const char *dw_rm_resume_reason(enum dw_rm_resume_result result)
{
    switch (result) {
    case DW_RM_RESUME_SNAPSHOT_CHANGED:
        return "snapshot_changed";
    case DW_RM_RESUME_REVISION_TOO_OLD:
        return "revision_too_old";
    case DW_RM_RESUME_REVISION_AHEAD:
        return "revision_ahead";
    case DW_RM_RESUME_SOURCE_REBUILT:
        return "source_rebuilt";
    case DW_RM_RESUME_BUILDING:
        return "source_rebuilt";
    case DW_RM_RESUME_OK:
    default:
        return "";
    }
}

struct json_object *dw_rm_resync_json(struct dw_rm_resource *resource,
                                      enum dw_rm_resume_result result)
{
    struct json_object *root = json_object_new_object();

    if (!root)
        return NULL;
    pthread_rwlock_rdlock(&resource->lock);
    json_object_object_add(root, "contract",
                           json_object_new_string(resource->contract));
    json_object_object_add(root, "type",
                           json_object_new_string("resync_required"));
    json_object_object_add(root, "reason",
                           json_object_new_string(dw_rm_resume_reason(result)));
    json_object_object_add(root, "snapshot_id",
                           json_object_new_string(resource->snapshot_id));
    json_object_object_add(root, "revision",
                           json_object_new_int64((int64_t)resource->revision));
    pthread_rwlock_unlock(&resource->lock);
    return root;
}

static int dw_rm_i64_compare(const void *left, const void *right)
{
    const int64_t a = *(const int64_t *)left;
    const int64_t b = *(const int64_t *)right;

    return a < b ? -1 : a > b;
}

static void dw_rm_percentiles_locked(struct dw_rm_resource *resource,
                                     int64_t *p50, int64_t *p95)
{
    int64_t values[DW_RM_DURATION_SAMPLES];
    size_t count = resource->duration_count;

    *p50 = 0;
    *p95 = 0;
    if (!count)
        return;
    memcpy(values, resource->duration_samples, count * sizeof(values[0]));
    qsort(values, count, sizeof(values[0]), dw_rm_i64_compare);
    *p50 = values[(count - 1) / 2];
    *p95 = values[((count - 1) * 95) / 100];
}

struct json_object *dw_rm_status_json(struct dw_rm_resource *resource)
{
    struct json_object *root;
    int64_t p50, p95;
    int64_t age_ms;

    if (!resource)
        return NULL;
    root = json_object_new_object();
    pthread_rwlock_rdlock(&resource->lock);
    dw_rm_percentiles_locked(resource, &p50, &p95);
    age_ms = resource->observed_at > 0 ?
             ((int64_t)time(NULL) - resource->observed_at) * 1000 : -1;
    json_object_object_add(root, "name", json_object_new_string(resource->name));
    json_object_object_add(root, "contract",
                           json_object_new_string(resource->contract));
    json_object_object_add(root, "snapshot_id",
                           json_object_new_string(resource->snapshot_id));
    json_object_object_add(root, "revision",
                           json_object_new_int64((int64_t)resource->revision));
    json_object_object_add(root, "observed_at",
                           json_object_new_int64(resource->observed_at));
    json_object_object_add(root, "snapshot_age_ms",
                           json_object_new_int64(age_ms));
    json_object_object_add(root, "complete",
                           json_object_new_boolean(resource->complete));
    json_object_object_add(root, "memory_profile_revision", json_object_new_int64(resource->memory_revision));
    json_object_object_add(root, "period_ms",
                           json_object_new_int(resource->period_ms));
    json_object_object_add(root, "stale_after_ms",
                           json_object_new_int(resource->stale_after_ms));
    json_object_object_add(root, "collect_runs",
                           json_object_new_int64((int64_t)resource->collect_runs));
    json_object_object_add(root, "collect_failures",
                           json_object_new_int64((int64_t)resource->collect_failures));
    json_object_object_add(root, "publish_count",
                           json_object_new_int64((int64_t)resource->publish_count));
    json_object_object_add(root, "collect_ms_last",
                           json_object_new_int64(resource->collect_ms));
    json_object_object_add(root, "collect_ms_p50", json_object_new_int64(p50));
    json_object_object_add(root, "collect_ms_p95", json_object_new_int64(p95));
    json_object_object_add(root, "collect_ms_max",
                           json_object_new_int64(resource->collect_ms_max));
    json_object_object_add(root, "scanned_rows",
                           json_object_new_int64((int64_t)resource->scanned_rows));
    json_object_object_add(root, "scanned_rows_peak",
                           json_object_new_int64((int64_t)resource->scanned_rows_peak));
    json_object_object_add(root, "delta_build_failures", json_object_new_int64(
        (int64_t)resource->delta_build_failures));
    json_object_object_add(root, "ring_count",
                           json_object_new_int64((int64_t)resource->ring_count));
    json_object_object_add(root, "ring_bytes",
                           json_object_new_int64((int64_t)resource->ring_bytes));
    json_object_object_add(root, "ring_bytes_peak",
                           json_object_new_int64((int64_t)resource->ring_bytes_peak));
    json_object_object_add(root, "ring_slots",
                           json_object_new_int64((int64_t)resource->ring_slot_limit));
    json_object_object_add(root, "ring_bytes_max", json_object_new_int64(
        (int64_t)resource->ring_bytes_max));
    pthread_rwlock_unlock(&resource->lock);
    return root;
}

struct json_object *dw_rm_registry_status_json(void)
{
    struct json_object *root = json_object_new_object();
    struct json_object *resources = json_object_new_array();
    size_t i;

    pthread_mutex_lock(&g_dw_rm_registry_lock);
    for (i = 0; i < g_dw_rm_resource_count; i++)
        json_object_array_add(resources,
                              dw_rm_status_json(g_dw_rm_resources[i]));
    pthread_mutex_unlock(&g_dw_rm_registry_lock);
    json_object_object_add(root, "resources", resources);
    json_object_object_add(root, "resource_count",
                           json_object_new_int64((int64_t)g_dw_rm_resource_count));
    return root;
}
