/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Live conntrack fwmark counting for route_status.
 *
 * The previous implementation walked /proc/net/nf_conntrack every few
 * seconds on the uloop thread, which cost ~120ms per scan once the table had
 * thousands of entries.  This runtime moves that work to a dedicated thread:
 * it subscribes to ctnetlink NEW/UPDATE/DESTROY events and keeps only the
 * conntrack id -> fwmark mapping needed to answer "how many flows are steered
 * to each rule/WAN".  A full dump seeds the table at startup, on event loss
 * (ENOBUFS/MSG_TRUNC), and periodically as a cheap drift correction.
 *
 * If the kernel does not expose CTA_ID, or the table overflows, the reader
 * falls back to the old procfs path; nothing here can block the uloop thread.
 */
#include "jmx_route_mark_runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnfnetlink/linux_nfnetlink_compat.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>

#define JMX_ROUTE_MARK_SLOTS 16384
#define JMX_ROUTE_MARK_RCVBUF_BYTES (4 * 1024 * 1024)
#define JMX_ROUTE_MARK_POLL_MS 1000
#define JMX_ROUTE_MARK_RESYNC_SEC 300
#define JMX_ROUTE_MARK_RETRY_SEC 2
#define JMX_ROUTE_MARK_DUMP_DEADLINE_SEC 3
#define JMX_ROUTE_MARK_GROUPS (NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY)

enum route_mark_slot_state {
    ROUTE_MARK_SLOT_EMPTY = 0,
    ROUTE_MARK_SLOT_USED = 1,
    ROUTE_MARK_SLOT_TOMB = 2,
};

struct route_mark_slot {
    uint32_t id;
    uint32_t mark;
    uint8_t state;
};

struct jmx_route_mark_state {
    pthread_mutex_t lock;
    pthread_t thread;
    int thread_started;
    int stop;
    int active;
    int supported;
    int dumping;
    int resync_needed;
    int overflow;
    int missing_id;
    int missing_destroy;
    int last_errno;
    uint32_t total;
    uint64_t events_upsert;
    uint64_t events_destroy;
    uint64_t events_error;
    uint64_t enobufs;
    uint64_t dumps;
    uint64_t dump_entries;
    time_t last_full_sync;
    time_t dump_deadline;
    time_t updated_at;
    struct route_mark_slot slots[JMX_ROUTE_MARK_SLOTS];
};

static struct jmx_route_mark_state g_route_mark = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .supported = 1,
};

static void route_mark_set_time(void)
{
    g_route_mark.updated_at = time(NULL);
}

static uint32_t route_mark_hash(uint32_t id)
{
    /* multiplicative hash so consecutive IDs spread across the table. */
    uint32_t h = id * 2654435761u;

    return h & (JMX_ROUTE_MARK_SLOTS - 1);
}

static int route_mark_slot_find(struct jmx_route_mark_state *st, uint32_t id,
                                uint32_t *idx_out)
{
    uint32_t idx = route_mark_hash(id);
    uint32_t i;

    for (i = 0; i < JMX_ROUTE_MARK_SLOTS; i++, idx = (idx + 1) & (JMX_ROUTE_MARK_SLOTS - 1)) {
        if (st->slots[idx].state == ROUTE_MARK_SLOT_USED &&
            st->slots[idx].id == id) {
            if (idx_out)
                *idx_out = idx;
            return 1;
        }
        if (st->slots[idx].state == ROUTE_MARK_SLOT_EMPTY)
            break;
    }
    return 0;
}

static void route_mark_slot_upsert(struct jmx_route_mark_state *st,
                                   uint32_t id, uint32_t mark)
{
    uint32_t idx = route_mark_hash(id);
    uint32_t i;
    uint32_t first_tomb = JMX_ROUTE_MARK_SLOTS;

    for (i = 0; i < JMX_ROUTE_MARK_SLOTS; i++, idx = (idx + 1) & (JMX_ROUTE_MARK_SLOTS - 1)) {
        struct route_mark_slot *s = &st->slots[idx];

        if (s->state == ROUTE_MARK_SLOT_USED) {
            if (s->id == id) {
                s->mark = mark;
                return;
            }
            continue;
        }
        if (s->state == ROUTE_MARK_SLOT_TOMB) {
            if (first_tomb == JMX_ROUTE_MARK_SLOTS)
                first_tomb = idx;
            continue;
        }
        if (first_tomb != JMX_ROUTE_MARK_SLOTS)
            idx = first_tomb;
        st->slots[idx].id = id;
        st->slots[idx].mark = mark;
        st->slots[idx].state = ROUTE_MARK_SLOT_USED;
        st->total++;
        return;
    }
    st->overflow = 1;
}

static int route_mark_slot_remove(struct jmx_route_mark_state *st, uint32_t id)
{
    uint32_t idx;

    if (!route_mark_slot_find(st, id, &idx))
        return 0;
    st->slots[idx].state = ROUTE_MARK_SLOT_TOMB;
    st->slots[idx].id = 0;
    st->slots[idx].mark = 0;
    if (st->total > 0)
        st->total--;
    return 1;
}

static void route_mark_clear(struct jmx_route_mark_state *st)
{
    memset(st->slots, 0, sizeof(st->slots));
    st->total = 0;
    st->overflow = 0;
    st->missing_destroy = 0;
}

static void route_mark_apply(const struct nf_conntrack *ct, int destroyed,
                             struct jmx_route_mark_state *st)
{
    uint32_t id = 0;
    uint32_t mark = 0;

    if (!nfct_attr_is_set(ct, ATTR_ID)) {
        pthread_mutex_lock(&st->lock);
        st->missing_id++;
        pthread_mutex_unlock(&st->lock);
        return;
    }
    id = nfct_get_attr_u32(ct, ATTR_ID);
    if (nfct_attr_is_set(ct, ATTR_MARK))
        mark = nfct_get_attr_u32(ct, ATTR_MARK);

    pthread_mutex_lock(&st->lock);
    if (destroyed) {
        st->events_destroy++;
        if (!route_mark_slot_remove(st, id))
            st->missing_destroy++;
    } else {
        st->events_upsert++;
        route_mark_slot_upsert(st, id, mark);
    }
    route_mark_set_time();
    pthread_mutex_unlock(&st->lock);
}

static int route_mark_process_buffer(struct jmx_route_mark_state *st,
                                     const unsigned char *buffer,
                                     ssize_t received,
                                     unsigned int *pending_dumps)
{
    struct nlmsghdr *nlh;
    int remaining = (int)received;

    for (nlh = (struct nlmsghdr *)buffer; NLMSG_OK(nlh, remaining);
         nlh = NLMSG_NEXT(nlh, remaining)) {
        struct nf_conntrack *ct;
        int msg_type;
        int destroyed;

        if (nlh->nlmsg_type == NLMSG_DONE) {
            if (*pending_dumps > 0) {
                (*pending_dumps)--;
                if (*pending_dumps == 0) {
                    pthread_mutex_lock(&st->lock);
                    st->dumping = 0;
                    st->dumps++;
                    st->last_full_sync = time(NULL);
                    route_mark_set_time();
                    pthread_mutex_unlock(&st->lock);
                }
            }
            continue;
        }
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            pthread_mutex_lock(&st->lock);
            st->events_error++;
            st->last_errno = errno ? errno : EPROTO;
            route_mark_set_time();
            pthread_mutex_unlock(&st->lock);
            return -1;
        }
        if (NFNL_SUBSYS_ID(nlh->nlmsg_type) != NFNL_SUBSYS_CTNETLINK)
            continue;
        msg_type = NFNL_MSG_TYPE(nlh->nlmsg_type);
        /* ctnetlink sends UPDATE as CT_NEW as well; both are upserts here. */
        if (msg_type != IPCTNL_MSG_CT_NEW && msg_type != IPCTNL_MSG_CT_DELETE)
            continue;
        destroyed = msg_type == IPCTNL_MSG_CT_DELETE;
        ct = nfct_new();
        if (!ct || nfct_nlmsg_parse(nlh, ct) != 0) {
            if (ct)
                nfct_destroy(ct);
            pthread_mutex_lock(&st->lock);
            st->events_error++;
            st->last_errno = errno ? errno : EPROTO;
            route_mark_set_time();
            pthread_mutex_unlock(&st->lock);
            return -1;
        }
        route_mark_apply(ct, destroyed, st);
        nfct_destroy(ct);
        pthread_mutex_lock(&st->lock);
        if (st->dumping)
            st->dump_entries++;
        pthread_mutex_unlock(&st->lock);
    }
    return remaining == 0 ? 0 : -1;
}

static int route_mark_request_dumps(struct nfct_handle *h,
                                    unsigned int *pending_dumps)
{
    int family;

    *pending_dumps = 0;
    family = AF_INET;
    if (nfct_query(h, NFCT_Q_DUMP, &family) == 0)
        (*pending_dumps)++;
    family = AF_INET6;
    if (nfct_query(h, NFCT_Q_DUMP, &family) == 0)
        (*pending_dumps)++;
    return *pending_dumps > 0 ? 0 : -1;
}

static void route_mark_thread_set_error(const char *reason, int err)
{
    pthread_mutex_lock(&g_route_mark.lock);
    g_route_mark.active = 0;
    g_route_mark.last_errno = err;
    g_route_mark.updated_at = time(NULL);
    pthread_mutex_unlock(&g_route_mark.lock);
    (void)reason;
}

static void *route_mark_thread_main(void *arg)
{
    (void)arg;

    while (1) {
        struct nfct_handle *h = NULL;
        unsigned int pending_dumps = 0;
        time_t next_resync;
        int fd;
        int rc;

        pthread_mutex_lock(&g_route_mark.lock);
        if (g_route_mark.stop) {
            pthread_mutex_unlock(&g_route_mark.lock);
            break;
        }
        pthread_mutex_unlock(&g_route_mark.lock);

        h = nfct_open(CONNTRACK, JMX_ROUTE_MARK_GROUPS);
        if (!h) {
            route_mark_thread_set_error("nfct_open_failed", errno ? errno : ENODEV);
            sleep(JMX_ROUTE_MARK_RETRY_SEC);
            continue;
        }
        fd = nfct_fd(h);
        if (fd >= 0) {
            int requested = JMX_ROUTE_MARK_RCVBUF_BYTES;
            (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                             &requested, sizeof(requested));
            (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
        }

        pthread_mutex_lock(&g_route_mark.lock);
        route_mark_clear(&g_route_mark);
        g_route_mark.active = 1;
        g_route_mark.supported = 1;
        g_route_mark.resync_needed = 0;
        g_route_mark.missing_id = 0;
        g_route_mark.updated_at = time(NULL);
        pthread_mutex_unlock(&g_route_mark.lock);

        rc = route_mark_request_dumps(h, &pending_dumps);
        if (rc != 0) {
            pthread_mutex_lock(&g_route_mark.lock);
            g_route_mark.supported = 0;
            g_route_mark.active = 0;
            pthread_mutex_unlock(&g_route_mark.lock);
            nfct_close(h);
            return NULL;
        }
        pthread_mutex_lock(&g_route_mark.lock);
        g_route_mark.dumping = rc == 0 && pending_dumps > 0;
        g_route_mark.dump_deadline = g_route_mark.dumping ?
            time(NULL) + JMX_ROUTE_MARK_DUMP_DEADLINE_SEC : 0;
        pthread_mutex_unlock(&g_route_mark.lock);
        next_resync = time(NULL) + JMX_ROUTE_MARK_RESYNC_SEC;

        while (1) {
            struct pollfd pfd;
            unsigned char buffer[64 * 1024];
            struct msghdr msg;
            struct iovec iov;
            ssize_t received;
            int timeout_ms = JMX_ROUTE_MARK_POLL_MS;
            time_t now = time(NULL);

            pthread_mutex_lock(&g_route_mark.lock);
            if (g_route_mark.dumping && g_route_mark.dump_deadline &&
                now >= g_route_mark.dump_deadline) {
                pending_dumps = 0;
                g_route_mark.dumping = 0;
                g_route_mark.dumps++;
                g_route_mark.last_full_sync = now;
                g_route_mark.dump_deadline = 0;
                route_mark_set_time();
            }
            pthread_mutex_unlock(&g_route_mark.lock);

            pthread_mutex_lock(&g_route_mark.lock);
            if (g_route_mark.stop || g_route_mark.resync_needed ||
                g_route_mark.overflow) {
                pthread_mutex_unlock(&g_route_mark.lock);
                break;
            }
            pthread_mutex_unlock(&g_route_mark.lock);

            if (now >= next_resync) {
                pthread_mutex_lock(&g_route_mark.lock);
                g_route_mark.resync_needed = 1;
                pthread_mutex_unlock(&g_route_mark.lock);
                break;
            }
            if (next_resync - now < timeout_ms / 1000)
                timeout_ms = (int)(next_resync - now) * 1000;

            pfd.fd = fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            rc = poll(&pfd, 1, timeout_ms);
            if (rc < 0) {
                if (errno == EINTR)
                    continue;
                pthread_mutex_lock(&g_route_mark.lock);
                g_route_mark.last_errno = errno;
                g_route_mark.events_error++;
                g_route_mark.updated_at = time(NULL);
                pthread_mutex_unlock(&g_route_mark.lock);
                break;
            }
            if (rc == 0)
                continue;

            memset(&msg, 0, sizeof(msg));
            memset(&iov, 0, sizeof(iov));
            iov.iov_base = buffer;
            iov.iov_len = sizeof(buffer);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            received = recvmsg(fd, &msg, MSG_DONTWAIT);
            if (received < 0 && errno == EINTR)
                continue;
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    continue;
                if (errno == ENOBUFS) {
                    pthread_mutex_lock(&g_route_mark.lock);
                    g_route_mark.enobufs++;
                    g_route_mark.resync_needed = 1;
                    pthread_mutex_unlock(&g_route_mark.lock);
                }
                pthread_mutex_lock(&g_route_mark.lock);
                g_route_mark.last_errno = errno;
                g_route_mark.events_error++;
                g_route_mark.updated_at = time(NULL);
                pthread_mutex_unlock(&g_route_mark.lock);
                break;
            }
            if (!received)
                continue;
            if (msg.msg_flags & MSG_TRUNC) {
                pthread_mutex_lock(&g_route_mark.lock);
                g_route_mark.enobufs++;
                g_route_mark.resync_needed = 1;
                g_route_mark.events_error++;
                g_route_mark.updated_at = time(NULL);
                pthread_mutex_unlock(&g_route_mark.lock);
                continue;
            }
            if (route_mark_process_buffer(&g_route_mark, buffer, received,
                                          &pending_dumps) != 0) {
                pthread_mutex_lock(&g_route_mark.lock);
                g_route_mark.resync_needed = 1;
                pthread_mutex_unlock(&g_route_mark.lock);
                break;
            }
            pthread_mutex_lock(&g_route_mark.lock);
            if (!g_route_mark.dumping && g_route_mark.missing_id > 0) {
                g_route_mark.supported = 0;
                g_route_mark.active = 0;
                pthread_mutex_unlock(&g_route_mark.lock);
                if (h) {
                    nfct_close(h);
                    h = NULL;
                }
                return NULL;
            }
            pthread_mutex_unlock(&g_route_mark.lock);
        }

        if (h) {
            nfct_close(h);
            h = NULL;
        }
        pthread_mutex_lock(&g_route_mark.lock);
        g_route_mark.active = 0;
        if (g_route_mark.overflow) {
            g_route_mark.supported = 0;
            pthread_mutex_unlock(&g_route_mark.lock);
            return NULL;
        }
        pthread_mutex_unlock(&g_route_mark.lock);
        pthread_mutex_lock(&g_route_mark.lock);
        {
            int stop = g_route_mark.stop;
            pthread_mutex_unlock(&g_route_mark.lock);
            if (stop)
                break;
        }
        sleep(JMX_ROUTE_MARK_RETRY_SEC);
    }

    pthread_mutex_lock(&g_route_mark.lock);
    g_route_mark.active = 0;
    g_route_mark.updated_at = time(NULL);
    pthread_mutex_unlock(&g_route_mark.lock);
    return NULL;
}

int jmx_route_mark_runtime_start(void)
{
    int rc;

    pthread_mutex_lock(&g_route_mark.lock);
    if (g_route_mark.thread_started) {
        pthread_mutex_unlock(&g_route_mark.lock);
        return 0;
    }
    g_route_mark.stop = 0;
    pthread_mutex_unlock(&g_route_mark.lock);

    rc = pthread_create(&g_route_mark.thread, NULL, route_mark_thread_main, NULL);
    if (rc != 0) {
        pthread_mutex_lock(&g_route_mark.lock);
        g_route_mark.last_errno = rc;
        g_route_mark.supported = 0;
        pthread_mutex_unlock(&g_route_mark.lock);
        return -1;
    }
    pthread_detach(g_route_mark.thread);
    pthread_mutex_lock(&g_route_mark.lock);
    g_route_mark.thread_started = 1;
    pthread_mutex_unlock(&g_route_mark.lock);
    return 0;
}

void jmx_route_mark_runtime_stop(void)
{
    int waited = 0;

    pthread_mutex_lock(&g_route_mark.lock);
    g_route_mark.stop = 1;
    pthread_mutex_unlock(&g_route_mark.lock);

    /* Detached thread; give it a short window to notice the flag, then let the
     * process exit clean up.  The poll timeout bounds the wait. */
    while (waited < 3000) {
        int exited;

        pthread_mutex_lock(&g_route_mark.lock);
        exited = !g_route_mark.thread_started || !g_route_mark.active;
        pthread_mutex_unlock(&g_route_mark.lock);
        if (exited)
            break;
        usleep(50000);
        waited += 50;
    }
}

int jmx_route_mark_runtime_sample(const int *rule_prios,
                                  const int *rule_carriers,
                                  int rule_n,
                                  const int *wan_ids,
                                  int wan_n,
                                  struct jmx_route_mark_counts *out)
{
    struct jmx_route_mark_state *st = &g_route_mark;
    uint32_t i;

    if (!out || rule_n < 0 || wan_n < 0)
        return -1;
    if (rule_n > JMX_ROUTE_MARK_MAX_RULE_PRIOS)
        rule_n = JMX_ROUTE_MARK_MAX_RULE_PRIOS;

    pthread_mutex_lock(&st->lock);
    if (!st->thread_started || !st->active || !st->supported ||
        st->dumping || st->resync_needed || st->overflow) {
        pthread_mutex_unlock(&st->lock);
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->prio_n = rule_n;
    for (i = 0; i < (uint32_t)rule_n; i++) {
        out->prio[i] = rule_prios[i];
        out->per_prio[i] = 0;
    }
    for (i = 0; i < JMX_ROUTE_MARK_SLOTS; i++) {
        const struct route_mark_slot *s = &st->slots[i];
        uint32_t mark;
        int prio;
        int wan;
        int carrier = -1;
        int wan_known = 0;
        uint32_t j;

        if (s->state != ROUTE_MARK_SLOT_USED)
            continue;
        out->total++;
        mark = s->mark;
        if (mark == 0) {
            out->unsteered++;
            continue;
        }
        prio = (int)((mark >> 16) & 0xffff);
        wan = (int)(mark & 0xffff);
        for (j = 0; j < (uint32_t)rule_n; j++) {
            if (rule_prios[j] == prio) {
                out->per_prio[j]++;
                carrier = rule_carriers[j];
                break;
            }
        }
        for (j = 0; j < (uint32_t)wan_n; j++) {
            if (wan_ids[j] == wan) {
                wan_known = 1;
                break;
            }
        }
        if (carrier < 0 || !wan_known)
            out->unknown++;
        else if (carrier > 0)
            out->explicit_steer++;
        else
            out->load_balance++;
    }
    pthread_mutex_unlock(&st->lock);
    return 0;
}

int jmx_route_mark_runtime_status(struct jmx_route_mark_runtime_status *out)
{
    struct jmx_route_mark_runtime_status s;

    if (!out)
        return -1;
    memset(&s, 0, sizeof(s));
    pthread_mutex_lock(&g_route_mark.lock);
    s.thread_started = g_route_mark.thread_started;
    s.active = g_route_mark.active;
    s.supported = g_route_mark.supported;
    s.dumping = g_route_mark.dumping;
    s.resync_needed = g_route_mark.resync_needed;
    s.overflow = g_route_mark.overflow;
    s.missing_id = g_route_mark.missing_id;
    s.last_errno = g_route_mark.last_errno;
    s.events_upsert = g_route_mark.events_upsert;
    s.events_destroy = g_route_mark.events_destroy;
    s.events_error = g_route_mark.events_error;
    s.enobufs = g_route_mark.enobufs;
    s.dumps = g_route_mark.dumps;
    s.dump_entries = g_route_mark.dump_entries;
    s.last_full_sync = g_route_mark.last_full_sync;
    s.dump_deadline = g_route_mark.dump_deadline;
    s.updated_at = g_route_mark.updated_at;
    pthread_mutex_unlock(&g_route_mark.lock);
    *out = s;
    return 0;
}
