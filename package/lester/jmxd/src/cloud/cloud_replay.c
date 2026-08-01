// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Replay guard.
 *
 * The Ed25519 signature proves a frame came from a registered App, but says
 * nothing about whether it is fresh: a relay operator who captured a frame
 * could resend it. Two independent checks close that:
 *
 *   1. issued_at must be inside CLOUD_ISSUED_AT_SKEW_S of now (in cloud_tunnel),
 *   2. a request_id already served is refused, which is this file.
 *
 * Together they bound a captured frame's usefulness to the skew window, and
 * within that window the id cache rejects it outright.
 *
 * Fixed-size ring: memory use is bounded by construction, and the worst case of
 * an eviction under flood is a request id becoming replayable again, which the
 * issued_at window still constrains. Growing without bound would be the more
 * dangerous failure.
 */
#include "cloud_internal.h"

struct cloud_replay_entry {
    char request_id[CLOUD_REQUEST_ID_MAX + 1];
    int64_t seen_at;
};

static struct cloud_replay_entry g_entries[CLOUD_REPLAY_CACHE_SIZE];
static size_t g_next;

/*
 * Returns 1 when this request id was already served (caller must refuse), 0
 * when it is fresh and has been recorded.
 */
int cloud_replay_seen(const char *request_id, int64_t now)
{
    size_t i, oldest = 0;
    int64_t oldest_seen = 0;

    if (!request_id || !request_id[0])
        return 1;

    for (i = 0; i < CLOUD_REPLAY_CACHE_SIZE; i++) {
        if (!g_entries[i].request_id[0])
            continue;
        /* Entries older than the acceptance window cannot cause a replay that
         * the issued_at check would not already reject, so they are reusable. */
        if (now - g_entries[i].seen_at > CLOUD_ISSUED_AT_SKEW_S * 2) {
            g_entries[i].request_id[0] = '\0';
            continue;
        }
        if (!strcmp(g_entries[i].request_id, request_id))
            return 1;
        if (!oldest_seen || g_entries[i].seen_at < oldest_seen) {
            oldest_seen = g_entries[i].seen_at;
            oldest = i;
        }
    }

    /* Prefer a free slot; fall back to evicting the oldest live entry. */
    for (i = 0; i < CLOUD_REPLAY_CACHE_SIZE; i++) {
        size_t slot = (g_next + i) % CLOUD_REPLAY_CACHE_SIZE;

        if (!g_entries[slot].request_id[0]) {
            snprintf(g_entries[slot].request_id,
                     sizeof(g_entries[slot].request_id), "%s", request_id);
            g_entries[slot].seen_at = now;
            g_next = (slot + 1) % CLOUD_REPLAY_CACHE_SIZE;
            return 0;
        }
    }

    snprintf(g_entries[oldest].request_id,
             sizeof(g_entries[oldest].request_id), "%s", request_id);
    g_entries[oldest].seen_at = now;
    g_next = (oldest + 1) % CLOUD_REPLAY_CACHE_SIZE;
    return 0;
}

void cloud_replay_reset(void)
{
    memset(g_entries, 0, sizeof(g_entries));
    g_next = 0;
}
