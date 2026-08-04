// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Worker pool for read-only ubus queries. See dw_async_query.h for the contract
 * and for why this exists.
 *
 * Shape of the thing:
 *
 *   main thread                     worker thread
 *   -----------                     -------------
 *   submit()                        pop job
 *     ubus_defer_request            run fn(in)      <- the slow part
 *     push job, signal cond         push to done queue
 *     return 0                      write(1 byte) to wake the loop
 *   uloop fd readable
 *     pop done queue
 *     reply(ctx, req, result)       <- shared blob buffer, main thread only
 *     ubus_complete_deferred_request
 *
 * The eventfd-style wakeup is what keeps uloop and ubus single-threaded. libubox
 * and libubus are not thread safe, so a worker never touches either; it only
 * writes one byte to a pipe that the loop already watches.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <libubox/uloop.h>

#include "dw_async_query.h"
#include "jmx.h"

#define DW_ASYNC_MAX_WORKERS 8
/*
 * Queue bound. A deferred ubus request holds kernel-side state, so an unbounded
 * queue would let a burst of slow queries accumulate without limit. When full,
 * submit() refuses and the caller runs the query inline: slower for that one
 * request, but never a leak and never a silent drop.
 */
#define DW_ASYNC_MAX_PENDING 64

struct dw_async_job {
    struct dw_async_job *next;
    struct ubus_context *ctx;
    struct ubus_request_data req;   /* copy owned by us after defer */
    struct json_object *in;
    struct json_object *out;
    dw_async_query_fn fn;
    dw_async_reply_fn reply;
    unsigned int gen;               /* ubus connection generation at submit */
};

static struct {
    pthread_t threads[DW_ASYNC_MAX_WORKERS];
    unsigned int thread_count;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct dw_async_job *queue_head;
    struct dw_async_job *queue_tail;
    struct dw_async_job *done_head;
    struct dw_async_job *done_tail;
    int pending;
    int running;
    int wake_fd[2];                 /* [0] read side watched by uloop */
    struct uloop_fd ufd;
    int initialised;
} g_async;

/*
 * Bumped whenever the ubus connection is lost. A job deferred on the old
 * connection must not be completed on the new one: ubus_reconnect() closes the
 * old socket, so the descriptor number can be reused by something unrelated,
 * and replying would then write a ubus frame into a foreign fd. The caller of
 * the old request is already lost either way, so the reply is dropped and the
 * job simply freed.
 *
 * Not under the mutex: it is written only from the main thread and read only
 * from the main thread (submit and drain both run there).
 */
static unsigned int g_async_conn_gen;

void dw_async_query_connection_lost(void)
{
    g_async_conn_gen++;
}

/*
 * Deliberately outside g_async: init() memsets that struct, so a cleanup hook
 * registered before the pool starts would be silently discarded and every
 * worker would leak its sqlite handle.
 */
static void (*g_async_thread_cleanup)(void);

/*
 * Set for the lifetime of a worker thread. Read by dw_async_query_on_worker()
 * so shared-singleton accessors can route to per-thread resources instead.
 */
static __thread int g_async_is_worker;

int dw_async_query_on_worker(void)
{
    return g_async_is_worker;
}

void dw_async_query_set_thread_cleanup(void (*fn)(void))
{
    g_async_thread_cleanup = fn;
}

static void dw_async_queue_push(struct dw_async_job **head,
                                struct dw_async_job **tail,
                                struct dw_async_job *job)
{
    job->next = NULL;
    if (*tail)
        (*tail)->next = job;
    else
        *head = job;
    *tail = job;
}

static struct dw_async_job *dw_async_queue_pop(struct dw_async_job **head,
                                               struct dw_async_job **tail)
{
    struct dw_async_job *job = *head;

    if (!job)
        return NULL;
    *head = job->next;
    if (!*head)
        *tail = NULL;
    job->next = NULL;
    return job;
}

static void dw_async_job_free(struct dw_async_job *job)
{
    if (!job)
        return;
    if (job->in)
        json_object_put(job->in);
    if (job->out)
        json_object_put(job->out);
    free(job);
}

/*
 * Drain finished jobs. Runs on the main thread only, so touching ubus and the
 * shared blob buffer here is safe.
 */
static void dw_async_drain_done(void)
{
    for (;;) {
        struct dw_async_job *job;

        pthread_mutex_lock(&g_async.lock);
        job = dw_async_queue_pop(&g_async.done_head, &g_async.done_tail);
        pthread_mutex_unlock(&g_async.lock);
        if (!job)
            break;
        if (job->gen != g_async_conn_gen) {
            /* Connection died under this job; see g_async_conn_gen. */
            dw_async_job_free(job);
            continue;
        }
        /*
         * Always complete the deferred request, even when the worker produced
         * nothing: an uncompleted deferral leaves the caller waiting for its
         * full timeout, which is exactly the hang this work set out to remove.
         */
        if (job->reply)
            job->reply(job->ctx, &job->req, job->out);
        ubus_complete_deferred_request(job->ctx, &job->req, 0);
        dw_async_job_free(job);
    }
}

static void dw_async_wake_cb(struct uloop_fd *ufd, unsigned int events)
{
    char buf[64];
    ssize_t n;

    (void)ufd;
    (void)events;
    /* Coalesced wakeups are fine; the queue is the source of truth. */
    do {
        n = read(g_async.wake_fd[0], buf, sizeof(buf));
    } while (n > 0);
    dw_async_drain_done();
}

static void *dw_async_worker(void *arg)
{
    (void)arg;
    g_async_is_worker = 1;
    for (;;) {
        struct dw_async_job *job;

        pthread_mutex_lock(&g_async.lock);
        while (g_async.running && !g_async.queue_head)
            pthread_cond_wait(&g_async.cond, &g_async.lock);
        if (!g_async.running && !g_async.queue_head) {
            pthread_mutex_unlock(&g_async.lock);
            break;
        }
        job = dw_async_queue_pop(&g_async.queue_head, &g_async.queue_tail);
        pthread_mutex_unlock(&g_async.lock);
        if (!job)
            continue;

        /* The slow part, with no locks held so workers do not serialise. */
        if (job->fn)
            job->out = job->fn(job->in);

        pthread_mutex_lock(&g_async.lock);
        dw_async_queue_push(&g_async.done_head, &g_async.done_tail, job);
        if (g_async.pending > 0)
            g_async.pending--;
        pthread_mutex_unlock(&g_async.lock);

        /*
         * One byte is enough; the callback drains the whole done queue. Errors
         * are ignored deliberately: a full pipe means a wakeup is already
         * queued, which is all this write is for.
         */
        if (write(g_async.wake_fd[1], "x", 1) < 0)
            (void)0;
    }
    /*
     * Close per-thread resources here rather than at pool shutdown: a sqlite
     * handle must be closed by whichever thread is done with it, and after the
     * loop above no further job can be assigned to this thread.
     */
    if (g_async_thread_cleanup)
        g_async_thread_cleanup();
    return NULL;
}

int dw_async_query_init(unsigned int workers)
{
    unsigned int i;

    if (g_async.initialised)
        return 0;
    memset(&g_async, 0, sizeof(g_async));
    if (workers == 0)
        workers = 2;
    if (workers > DW_ASYNC_MAX_WORKERS)
        workers = DW_ASYNC_MAX_WORKERS;

    if (pipe(g_async.wake_fd) != 0) {
        LOG_WARN("async query: pipe failed: %s\n", strerror(errno));
        return -1;
    }
    /*
     * Both ends non-blocking. The read side must not stall the loop; the write
     * side must not stall a worker if the loop is briefly behind.
     */
    for (i = 0; i < 2; i++) {
        int fl = fcntl(g_async.wake_fd[i], F_GETFL, 0);

        if (fl >= 0)
            fcntl(g_async.wake_fd[i], F_SETFL, fl | O_NONBLOCK);
        fcntl(g_async.wake_fd[i], F_SETFD, FD_CLOEXEC);
    }

    pthread_mutex_init(&g_async.lock, NULL);
    pthread_cond_init(&g_async.cond, NULL);
    g_async.running = 1;

    g_async.ufd.fd = g_async.wake_fd[0];
    g_async.ufd.cb = dw_async_wake_cb;
    if (uloop_fd_add(&g_async.ufd, ULOOP_READ) != 0) {
        LOG_WARN("async query: uloop_fd_add failed\n");
        g_async.running = 0;
        close(g_async.wake_fd[0]);
        close(g_async.wake_fd[1]);
        return -1;
    }

    for (i = 0; i < workers; i++) {
        if (pthread_create(&g_async.threads[i], NULL,
                           dw_async_worker, NULL) != 0) {
            LOG_WARN("async query: pthread_create %u failed\n", i);
            break;
        }
        g_async.thread_count++;
    }
    if (g_async.thread_count == 0) {
        uloop_fd_delete(&g_async.ufd);
        g_async.running = 0;
        close(g_async.wake_fd[0]);
        close(g_async.wake_fd[1]);
        return -1;
    }
    g_async.initialised = 1;
    LOG_INFO("async query: %u worker(s) ready\n", g_async.thread_count);
    return 0;
}

void dw_async_query_stop(void)
{
    unsigned int i;

    if (!g_async.initialised)
        return;
    pthread_mutex_lock(&g_async.lock);
    g_async.running = 0;
    pthread_cond_broadcast(&g_async.cond);
    pthread_mutex_unlock(&g_async.lock);
    for (i = 0; i < g_async.thread_count; i++)
        pthread_join(g_async.threads[i], NULL);
    /* Anything already finished still owes its caller a reply. */
    dw_async_drain_done();
    uloop_fd_delete(&g_async.ufd);
    close(g_async.wake_fd[0]);
    close(g_async.wake_fd[1]);
    g_async.initialised = 0;
    g_async.thread_count = 0;
}

int dw_async_query_available(void)
{
    return g_async.initialised && g_async.running;
}

int dw_async_query_pending(void)
{
    int n;

    if (!g_async.initialised)
        return 0;
    pthread_mutex_lock(&g_async.lock);
    n = g_async.pending;
    pthread_mutex_unlock(&g_async.lock);
    return n;
}

int dw_async_query_submit(struct ubus_context *ctx,
                          struct ubus_request_data *req,
                          struct json_object *in,
                          dw_async_query_fn fn,
                          dw_async_reply_fn reply)
{
    struct dw_async_job *job;

    if (!dw_async_query_available() || !ctx || !req || !fn)
        return -1;

    pthread_mutex_lock(&g_async.lock);
    if (g_async.pending >= DW_ASYNC_MAX_PENDING) {
        pthread_mutex_unlock(&g_async.lock);
        return -1;
    }
    pthread_mutex_unlock(&g_async.lock);

    job = calloc(1, sizeof(*job));
    if (!job)
        return -1;
    job->ctx = ctx;
    job->fn = fn;
    job->reply = reply;
    job->gen = g_async_conn_gen;
    /* Ownership transfer, not a shared reference: see the header. */
    job->in = in ? in : json_object_new_object();

    /*
     * Defer before queueing. Once ubus_defer_request() has copied the request,
     * libubus will not answer it on return, and our copy is the only thing that
     * can complete it.
     */
    ubus_defer_request(ctx, req, &job->req);

    pthread_mutex_lock(&g_async.lock);
    dw_async_queue_push(&g_async.queue_head, &g_async.queue_tail, job);
    g_async.pending++;
    pthread_cond_signal(&g_async.cond);
    pthread_mutex_unlock(&g_async.lock);
    return 0;
}
