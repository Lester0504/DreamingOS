// SPDX-License-Identifier: GPL-2.0-or-later
//
// cloud-web-v1 tunnel-session enforcement (CLOUD side). Authoritative runtime for
// the "OPEN service_id registry + STREAM_LIMIT enforcement point" and the
// flow-control / lifecycle / revoke-close machine (PM-to-Backend §3.2, §7). Pure
// state fed pre-decoded frame events; depends only on wire.h. See session.h.
#include "session.h"

#include <string.h>

/* service_id grammar — MUST stay identical to webframe.c cw_web_is_service_id
 * (that file is the schema authority in docs/cloud-web-v1-wire.md §19). Mirrored
 * here so this module stays json-c-free and fuzzable in isolation. */
static int valid_service_id(const char *id)
{
    if (!id)
        return 0;
    size_t n = strlen(id);
    if (n < 1 || n > CW_SESS_SERVICE_ID_MAX)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = id[i];
        int alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!(alnum || c == '-'))
            return 0;
        if ((i == 0 || i == n - 1) && !alnum) /* no leading/trailing '-' */
            return 0;
    }
    return 1;
}

static struct cw_stream *find_slot(struct cw_session *s, uint32_t id)
{
    if (id == 0)
        return NULL;
    for (int i = 0; i < (int)CW_WIRE_MAX_STREAMS; i++)
        if (s->streams[i].in_use && s->streams[i].id == id)
            return &s->streams[i];
    return NULL;
}

static struct cw_stream *alloc_slot(struct cw_session *s)
{
    for (int i = 0; i < (int)CW_WIRE_MAX_STREAMS; i++)
        if (!s->streams[i].in_use)
            return &s->streams[i];
    return NULL;
}

static void close_stream(struct cw_session *s, struct cw_stream *st)
{
    if (!st->in_use)
        return;
    memset(st, 0, sizeof(*st));
    if (s->n_active > 0)
        s->n_active--;
}

void cw_session_init(struct cw_session *s, uint32_t generation,
                     uint32_t max_streams, uint32_t stream_window,
                     uint32_t conn_window)
{
    if (!s)
        return;
    memset(s, 0, sizeof(*s));
    s->generation = generation < 1 ? 1 : generation;
    if (max_streams < 1)
        max_streams = 1;
    if (max_streams > CW_WIRE_MAX_STREAMS)
        max_streams = CW_WIRE_MAX_STREAMS;
    s->max_streams = max_streams;
    if (stream_window < 1)
        stream_window = 1;
    if (stream_window > CW_WIRE_WINDOW_MAX)
        stream_window = CW_WIRE_WINDOW_MAX;
    if (conn_window < stream_window)
        conn_window = stream_window;
    if (conn_window > CW_WIRE_WINDOW_MAX)
        conn_window = CW_WIRE_WINDOW_MAX;
    s->init_stream_window = stream_window;
    s->conn_win[CW_DIR_UP] = conn_window;
    s->conn_win[CW_DIR_DOWN] = conn_window;
}

int cw_session_set_services(struct cw_session *s, const char *const *ids, int n)
{
    if (!s)
        return -1;
    s->n_services = 0;
    memset(s->services, 0, sizeof(s->services));
    if (n < 0 || n > CW_SESS_MAX_SERVICES)
        return -1;
    if (n > 0 && !ids)
        return -1;
    /* validate everything first so a bad manifest commits nothing (fail-closed) */
    for (int i = 0; i < n; i++) {
        if (!valid_service_id(ids[i]))
            return -1;
        for (int j = 0; j < i; j++)
            if (strcmp(ids[i], ids[j]) == 0) /* duplicate */
                return -1;
    }
    for (int i = 0; i < n; i++)
        memcpy(s->services[i], ids[i], strlen(ids[i]) + 1);
    s->n_services = n;
    return 0;
}

int cw_session_has_service(const struct cw_session *s, const char *service_id)
{
    if (!s || !service_id)
        return 0;
    for (int i = 0; i < s->n_services; i++)
        if (strcmp(s->services[i], service_id) == 0)
            return 1;
    return 0;
}
int cw_session_open(struct cw_session *s, uint32_t stream_id, const char *service_id)
{
    if (!s || !service_id)
        return -1;
    if (s->superseded)
        return CW_ERR_GENERATION;
    if (s->revoked)
        return CW_ERR_REVOKED;
    if (stream_id == 0)                       /* data streams need nonzero id */
        return CW_ERR_PROTOCOL;
    if (find_slot(s, stream_id))              /* stream_id reuse within session */
        return CW_ERR_PROTOCOL;
    if (!cw_session_has_service(s, service_id))
        return CW_ERR_SERVICE;
    if (s->n_active >= (int)s->max_streams)
        return CW_ERR_STREAM_LIMIT;
    struct cw_stream *st = alloc_slot(s);
    if (!st)                                  /* defensive: table full */
        return CW_ERR_STREAM_LIMIT;
    memset(st, 0, sizeof(*st));
    st->id = stream_id;
    st->in_use = 1;
    st->win[CW_DIR_UP] = s->init_stream_window;
    st->win[CW_DIR_DOWN] = s->init_stream_window;
    s->n_active++;
    return 0;
}

int cw_session_on_resp(struct cw_session *s, uint32_t stream_id)
{
    if (!s)
        return -1;
    struct cw_stream *st = find_slot(s, stream_id);
    if (!st)
        return CW_ERR_PROTOCOL;
    if (st->resp_seen)                        /* RESP is once per stream */
        return CW_ERR_PROTOCOL;
    if (st->fin[CW_DIR_DOWN])                 /* response already ended */
        return CW_ERR_PROTOCOL;
    st->resp_seen = 1;
    return 0;
}
int cw_session_on_data(struct cw_session *s, uint32_t stream_id, int dir,
                       uint32_t n, int fin)
{
    if (!s)
        return -1;
    if (dir != CW_DIR_UP && dir != CW_DIR_DOWN)
        return -1;
    struct cw_stream *st = find_slot(s, stream_id);
    if (!st)
        return CW_ERR_PROTOCOL;
    if (st->fin[dir])                          /* DATA after this dir's FIN */
        return CW_ERR_PROTOCOL;
    if (dir == CW_DIR_DOWN && !st->resp_seen)  /* response body before RESP head */
        return CW_ERR_PROTOCOL;
    if (n > CW_WIRE_FRAME_MAX)
        return CW_ERR_FRAME_TOO_BIG;
    /* charge both the stream and the connection window for this direction;
     * check both before spending either so a reject leaves state unchanged */
    if (n > st->win[dir] || n > s->conn_win[dir])
        return CW_ERR_FLOW_CONTROL;
    st->win[dir] -= n;
    s->conn_win[dir] -= n;
    if (fin) {
        st->fin[dir] = 1;
        if (st->fin[CW_DIR_UP] && st->fin[CW_DIR_DOWN])
            close_stream(s, st);
    }
    return 0;
}

int cw_session_on_fin(struct cw_session *s, uint32_t stream_id, int dir)
{
    if (!s)
        return -1;
    if (dir != CW_DIR_UP && dir != CW_DIR_DOWN)
        return -1;
    struct cw_stream *st = find_slot(s, stream_id);
    if (!st)
        return CW_ERR_PROTOCOL;
    if (st->fin[dir])
        return CW_ERR_PROTOCOL;
    if (dir == CW_DIR_DOWN && !st->resp_seen)
        return CW_ERR_PROTOCOL;
    st->fin[dir] = 1;
    if (st->fin[CW_DIR_UP] && st->fin[CW_DIR_DOWN])
        close_stream(s, st);
    return 0;
}
int cw_session_on_reset(struct cw_session *s, uint32_t stream_id)
{
    if (!s)
        return -1;
    struct cw_stream *st = find_slot(s, stream_id);
    if (!st)                                   /* idempotent: already gone */
        return 0;
    close_stream(s, st);
    return 0;
}

int cw_session_on_window(struct cw_session *s, uint32_t stream_id, int dir,
                         uint32_t credit)
{
    if (!s)
        return -1;
    if (dir != CW_DIR_UP && dir != CW_DIR_DOWN)
        return -1;
    if (stream_id == 0) {                      /* connection-level credit */
        if (cw_wire_window_add(&s->conn_win[dir], credit) != 0)
            return CW_ERR_FLOW_CONTROL;
        return 0;
    }
    struct cw_stream *st = find_slot(s, stream_id);
    if (!st)
        return CW_ERR_PROTOCOL;
    if (cw_wire_window_add(&st->win[dir], credit) != 0)
        return CW_ERR_FLOW_CONTROL;
    return 0;
}

int cw_session_supersede(struct cw_session *s, uint32_t new_generation)
{
    if (!s)
        return -1;
    if (new_generation <= s->generation)       /* must strictly increase */
        return CW_ERR_PROTOCOL;
    s->generation = new_generation;
    s->superseded = 1;
    memset(s->streams, 0, sizeof(s->streams)); /* close every active stream */
    s->n_active = 0;
    return 0;
}

int cw_session_revoke(struct cw_session *s)
{
    if (!s)
        return -1;
    int closed = s->n_active;
    s->revoked = 1;
    memset(s->streams, 0, sizeof(s->streams)); /* close every active stream */
    s->n_active = 0;
    return closed;
}

int cw_session_active_streams(const struct cw_session *s)
{
    return s ? s->n_active : 0;
}

const struct cw_stream *cw_session_find(const struct cw_session *s, uint32_t stream_id)
{
    if (!s || stream_id == 0)
        return NULL;
    for (int i = 0; i < (int)CW_WIRE_MAX_STREAMS; i++)
        if (s->streams[i].in_use && s->streams[i].id == stream_id)
            return &s->streams[i];
    return NULL;
}
