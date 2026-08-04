// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Off-loop execution for read-only ubus query handlers.
 *
 * jmxd answers every ubus method inside its single uloop iteration, so a slow
 * read blocks the whole daemon: while audit_flow_host_rollup spends ~850ms in
 * sqlite, no other ubus request is served. Measured consequence on 30.1 was
 * that webd's eight insights fetches could not overlap at all, and a webd-side
 * parallel batch made things worse rather than better because the queueing was
 * here, not there.
 *
 * This module runs such a handler on a worker thread and completes the deferred
 * ubus request back on the main thread. It is deliberately narrow:
 *
 *   - Only for handlers that READ. A handler that mutates shared state, touches
 *     the global blob buffer, or calls ubus itself must stay on the loop.
 *   - The worker gets no ubus access at all. It receives parsed JSON input,
 *     returns a JSON result, and never sees ubus_context.
 *   - Completion, including blobmsg encoding via the shared dw_b buffer, always
 *     happens on the main thread.
 */
#ifndef DW_ASYNC_QUERY_H
#define DW_ASYNC_QUERY_H

#include <json-c/json.h>
#include <libubus.h>

/*
 * Worker body. Runs on a thread with no locks held; must not touch ubus, the
 * shared blob buffer, or any mutable global. The framework retains ownership of
 * `in`; the returned object is passed to the reply function and then released.
 */
typedef struct json_object *(*dw_async_query_fn)(struct json_object *in);

/*
 * Reply sender, invoked on the main thread with the worker's result. Exists so
 * this module needs no knowledge of dw_send_json() or the response envelope,
 * which live in jmx_dreamingwrt_api.c.
 */
typedef void (*dw_async_reply_fn)(struct ubus_context *ctx,
                                  struct ubus_request_data *req,
                                  struct json_object *result);

/*
 * Initialise the pool. Safe to call more than once; later calls are no-ops.
 * Returns 0 on success. On failure callers must fall back to synchronous
 * execution rather than failing the request.
 */
int dw_async_query_init(unsigned int workers);

/* Stop accepting work and join the workers. Used on shutdown. */
void dw_async_query_stop(void);

/*
 * Hand a read-only query to the pool.
 *
 * Ownership of `in` transfers to the pool on success and stays with the caller
 * on failure. This is deliberate rather than a shared reference: json-c 0.18
 * refcounts are plain int increments with no atomics, so a main-thread
 * json_object_put() racing a worker still holding the object is a torn counter
 * and eventually a double free. Handing the object over outright means exactly
 * one thread ever owns it.
 *
 * Returns 0 when the request has been deferred and will be completed later, or
 * -1 when it could not be queued, in which case the caller still owns `in`,
 * must answer synchronously, and the ubus request is left untouched.
 */
int dw_async_query_submit(struct ubus_context *ctx,
                          struct ubus_request_data *req,
                          struct json_object *in,
                          dw_async_query_fn fn,
                          dw_async_reply_fn reply);

/* Depth of the pending queue, for status reporting. */
int dw_async_query_pending(void);

/* Whether the pool is running; false means every query runs inline. */
int dw_async_query_available(void);

/*
 * True only on a pool worker. Callers use this to pick per-thread resources:
 * the audit sqlite handle in particular is a process-wide singleton shared by
 * ~28 call sites, and a worker must open its own read-only connection instead
 * of borrowing it.
 */
int dw_async_query_on_worker(void);

/*
 * Register a teardown callback run on each worker just before it exits, so
 * per-thread resources (sqlite handles) close on the thread that opened them.
 */
void dw_async_query_set_thread_cleanup(void (*fn)(void));

/*
 * Tell the pool the ubus connection was lost. In-flight jobs are then dropped
 * on completion instead of replying onto a reconnected (and possibly recycled)
 * socket. Call from the main thread, in the connection_lost path.
 */
void dw_async_query_connection_lost(void);

#endif /* DW_ASYNC_QUERY_H */
