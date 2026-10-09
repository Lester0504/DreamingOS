// SPDX-License-Identifier: GPL-2.0-or-later
/* DreamingWrt centralized AP controller. */
#include <malloc.h>
#include "ac_internal.h"
#include "ac_discovery.h"
#include "ac_secret_rotation.h"
#include "../dw_async_query.h"

/*
 * dw_async_query.c 用 jmx.h 那套日志宏，宏体引用一个由每个守护进程各自定义的
 * 等级变量（main.c / healthd / identityd 各有一份）。AC 现在也用那个池，所以
 * 补一份；1 == LOG_LEVEL_WARN，与其余守护进程取值一致。
 */
int current_log_level = 1;

static void ac_handle_signal(int signo)
{
    (void)signo;
    uloop_end();
}

/*
 * Periodic survey collection.
 *
 * The tick itself is cheap and fixed at 30s; whether anything is dispatched is
 * decided by ac_survey_schedule (disabled by default, interval 60..3600s). The
 * timer runs regardless so that enabling the schedule takes effect without a
 * restart, and so a disabled schedule costs one DB read per half minute.
 *
 * Only survey jobs are created here. Neighbour scans do leave the working
 * channel, so scheduling them would interrupt associated clients; they stay a
 * manual action.
 */
static struct uloop_timeout ac_survey_schedule_timer;
static struct uloop_timeout ac_roaming_schedule_timer;

#define AC_SURVEY_SCHEDULE_TICK_MS 30000

static void ac_survey_schedule_tick_cb(struct uloop_timeout *t)
{
    int dispatched = 0;

    if (ac_db_survey_schedule_tick(ac_now_s(), &dispatched) == 0 && dispatched > 0)
        fprintf(stderr, "[%s] survey schedule dispatched jobs=%d\n",
                AC_SERVICE_NAME, dispatched);
    /*
     * 低频（30s）把已 free 的堆顶页还给内核，配合 main 里的 M_ARENA_MAX/
     * M_TRIM_THRESHOLD。只回收 glibc 已经 free 的页，不触碰在用数据，故对功能零影响；
     * 放在这个既有 tick 上，避免新增定时器，也不会每秒调用。
     */
    malloc_trim(0);
    uloop_timeout_set(t, AC_SURVEY_SCHEDULE_TICK_MS);
}

static void ac_roaming_schedule_tick_cb(struct uloop_timeout *t)
{
    int dispatched = 0;

    ac_db_roaming_schedule_tick(ac_now_s(), &dispatched);
    uloop_timeout_set(t, 15000);
}

int main(int argc, char **argv)
{
    struct ac_secrets *secrets = NULL;
    const char *secrets_key_path;
    (void)argc;
    (void)argv;

    /*
     * 性能优化（PM-to-Backend-perf-ac-mem-core-cpu）：把 glibc 分配器封在单一
     * arena。AC 的传输层固定起 8 个 worker 线程（AC_TRANSPORT_WORKERS_MAX），
     * glibc 默认会给每个争用主 arena 锁的线程新开一个 64MB 的 secondary arena，
     * 于是 RssAnon 平台化在 ~9×64MB（实测 535MB）却几乎不还给内核 —— 这是碎片
     * 倍数，不是泄漏。M_ARENA_MAX=1 只改「多少 arena 摊给多线程」，不动线程数、
     * 不动业务逻辑、不动任何数据结构；对 2-4 AP 的低并发，多出来的锁争用可忽略。
     * 必须在任何线程/分配发生之前调用（此处即 main 入口，早于 ac_db_init）。
     */
    mallopt(M_ARENA_MAX, 1);
    /*
     * 让释放的堆页真的还给 OS。glibc 默认几乎不 trim，一次突发（TLS 握手 / PKI /
     * 大 snapshot 解析）把 arena 撑起来后就永不回落。调低 trim 阈值后，配合 30s
     * survey tick 里的 malloc_trim(0)，把已 free 的顶部页交还内核。只动已释放内存。
     */
    mallopt(M_TRIM_THRESHOLD, 128 * 1024);

    signal(SIGINT, ac_handle_signal);
    signal(SIGTERM, ac_handle_signal);
    g_ac_started_at = ac_now_s();

    if (ac_db_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=db_init\n",
                AC_SERVICE_NAME);
        return 1;
    }
    secrets_key_path = getenv("DREAMINGWRT_AC_SECRETS_KEY_PATH");
    if (!secrets_key_path || !secrets_key_path[0])
        secrets_key_path = AC_SECRETS_KEY_PATH;
    if (ac_secrets_open_or_create(g_ac_db, secrets_key_path, &secrets) !=
            AC_SECRETS_OK) {
        fprintf(stderr, "[%s] startup failed stage=secrets_init\n",
                AC_SERVICE_NAME);
        goto fail_db;
    }
    ac_db_set_secrets(secrets);
    if (ac_protocol_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=protocol_init\n",
                AC_SERVICE_NAME);
        goto fail_db;
    }
    if (ac_secret_rotation_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=secret_rotation_init\n",
                AC_SERVICE_NAME);
        goto fail_protocol;
    }
    if (uloop_init() != 0) {
        fprintf(stderr, "[%s] startup failed stage=uloop_init\n",
                AC_SERVICE_NAME);
        goto fail_secret_rotation;
    }
    /*
     * 两个 worker 就够：只有 txpower_mode 这一条路径会长等，而 AC 侧同时最多
     * 8 笔 pending（AC_TXPOWER_PENDING_MAX）。池子起不来不算致命 —— 那时
     * dw_async_query_submit() 会拒收，txpower 当场答一个可重试的错误，
     * 而不是把 uloop 堵死半分钟。
     */
    if (dw_async_query_init(2) != 0)
        fprintf(stderr, "[%s] async query pool unavailable; "
                "txpower_mode will answer async_query_pool_unavailable\n",
                AC_SERVICE_NAME);
    if (ac_ubus_start() != 0) {
        fprintf(stderr, "[%s] startup failed stage=ubus_start\n",
                AC_SERVICE_NAME);
        goto fail_uloop;
    }
    if (ac_transport_start() != 0) {
        fprintf(stderr, "[%s] startup failed stage=transport_start reason=%s\n",
                AC_SERVICE_NAME, ac_transport_reason());
        goto fail_ubus;
    }

    /*
     * Discovery is best-effort: if the beacon port cannot be bound the
     * controller still runs and simply reports the capability as
     * unavailable with a reason. Failing startup over an optional
     * convenience feature would be the wrong trade.
     */
    if (ac_discovery_start() != 0)
        fprintf(stderr, "[%s] discovery unavailable reason=%s\n",
                AC_SERVICE_NAME, ac_discovery_reason());

    ac_survey_schedule_timer.cb = ac_survey_schedule_tick_cb;
    uloop_timeout_set(&ac_survey_schedule_timer, AC_SURVEY_SCHEDULE_TICK_MS);
    ac_roaming_schedule_timer.cb = ac_roaming_schedule_tick_cb;
    uloop_timeout_set(&ac_roaming_schedule_timer, 15000);

    fprintf(stderr,
            "[%s] started contract=%s schema=%d transport=%s port=%d\n",
            AC_SERVICE_NAME, AC_CONTRACT_VERSION, AC_SCHEMA_VERSION,
            ac_transport_listening() ? "listening" : "unavailable",
            ac_transport_port());
    uloop_run();

    uloop_timeout_cancel(&ac_survey_schedule_timer);
    uloop_timeout_cancel(&ac_roaming_schedule_timer);
    ac_discovery_stop();
    ac_transport_stop();
    ac_ubus_stop();
    dw_async_query_stop();
    uloop_done();
    ac_protocol_close();
    ac_secret_rotation_close();
    ac_db_set_secrets(NULL);
    ac_secrets_close(secrets);
    ac_db_close();
    return 0;

fail_ubus:
    ac_ubus_stop();
fail_uloop:
    dw_async_query_stop();
    uloop_done();
fail_protocol:
    ac_protocol_close();
    goto fail_db;
fail_secret_rotation:
    ac_secret_rotation_close();
    goto fail_protocol;
fail_db:
    ac_db_set_secrets(NULL);
    ac_secrets_close(secrets);
    ac_db_close();
    return 1;
}
