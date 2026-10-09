/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "dw_read_model.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct fixture {
    int value;
};

struct fixture_delta {
    int previous;
    int current;
};

static int collect(void *context, struct dw_rm_collect_result *result)
{
    struct fixture *source = context;
    struct fixture *generation = malloc(sizeof(*generation));

    if (!generation)
        return -1;
    generation->value = source->value++;
    result->generation = generation;
    result->observed_at = 1000 + generation->value;
    result->complete = 1;
    result->scanned_rows = (uint64_t)generation->value;
    return 0;
}

static void free_generation(void *context, void *generation)
{
    (void)context;
    free(generation);
}

static int diff(void *context, const void *previous, const void *current,
                void **delta_out, size_t *delta_bytes)
{
    const struct fixture *before = previous;
    const struct fixture *after = current;
    struct fixture_delta *delta = malloc(sizeof(*delta));

    (void)context;
    if (!delta)
        return -1;
    delta->previous = before->value;
    delta->current = after->value;
    *delta_out = delta;
    *delta_bytes = sizeof(*delta);
    return 0;
}

static void free_delta(void *context, void *delta)
{
    (void)context;
    free(delta);
}

int main(void)
{
    struct fixture source = { .value = 1 };
    struct dw_rm_config config = {
        .name = "fixture",
        .contract = "fixture.v1",
        .period_ms = 20,
        .stale_after_ms = 5000,
        .ring_slots = 8,
        .ring_bytes_max = 4096,
        .context = &source,
        .ops = {
            .collect = collect,
            .free_generation = free_generation,
            .diff = diff,
            .free_delta = free_delta,
        },
    };
    struct dw_rm_resource *resource = NULL;
    struct dw_rm_view first = {0};
    struct dw_rm_view replay = {0};
    struct dw_rm_view mismatch = {0};
    char snapshot_id[40];
    uint64_t revision;
    enum dw_rm_resume_result result;

    assert(dw_rm_create(&config, &resource) == 0);
    assert(dw_rm_start(resource) == 0);
    usleep(140000);
    assert(dw_rm_view_begin(resource, &first) == 0);
    assert(first.generation != NULL);
    assert(first.revision >= 2);
    snprintf(snapshot_id, sizeof(snapshot_id), "%s", first.snapshot_id);
    revision = first.revision > 2 ? first.revision - 2 : first.revision - 1;
    dw_rm_view_end(&first);

    result = dw_rm_resume_begin(resource, snapshot_id, revision, &replay);
    assert(result == DW_RM_RESUME_OK);
    assert(replay.delta_count >= 1);
    assert(dw_rm_view_delta_at(&replay, 0, NULL, NULL, NULL) != NULL);
    dw_rm_view_end(&replay);

    result = dw_rm_resume_begin(resource, "boot:not-the-same", revision,
                                &mismatch);
    assert(result == DW_RM_RESUME_SNAPSHOT_CHANGED);
    dw_rm_view_end(&mismatch);

    dw_rm_destroy(resource);
    puts("dw_read_model tests: ok");
    return 0;
}
