// SPDX-License-Identifier: GPL-2.0-or-later
#include "flowd_internal.h"
#include "jmx_dataset_path.h"
#include "wan_sla_runtime.h"
#include "wan_sla_tx.h"
#include "wan_sla_eval.h"
#include "flowd_wan_runtime.h"
#include "wan_sla_history.h"
#include "wan_sla_config.h"
#include "../healthd/wan_probe.h"

#include <stddef.h>
#include <net/if.h>
#include <sys/socket.h>

#define SLA_SLOTS 32
#define SLA_WORKERS 4
#define SLA_HISTORY_PATH jmx_dataset_path("wan_sla")
#define SLA_HISTORY_BYTES (64LL * 1024 * 1024)
#define SLA_RUNTIME_APPLY_ENABLED 0

struct sla_slot {
    char id[FLOWD_MAX_ID], wan[FLOWD_MAX_ID];
    int64_t revision, next_due_at, seen, test_at;
    int enabled, test_pending, running;
    struct json_object *rule, *runtime, *test_plan, *test_result;
    int restored;
    struct wan_sla_evaluator *evaluator;
};

struct sla_batch {
    unsigned count;
    struct wan_probe_result targets[WAN_SLA_MAX_TARGETS];
};

struct sla_worker {
    struct uloop_process process;
    struct sla_slot *slot;
    int fd, is_test;
    int64_t revision, deadline;
    struct json_object *rule;
};

static struct sla_slot slots[SLA_SLOTS];
static struct sla_worker workers[SLA_WORKERS];
static struct uloop_timeout timer;
static int started, config_ready, history_degraded;
static unsigned schedule_cursor;
static int64_t last_reload, last_history_prune, decision_sequence;
static sqlite3 *history_db;

/* The sampler may run in observe mode before production evaluation/apply are
 * advertised.  The public capability bits remain false until the shadow and
 * non-primary-WAN acceptance gates are completed. */
#define SLA_SHADOW_SAMPLER_IMPLEMENTED 1

static struct json_object *value(struct json_object *o,const char *key)
{
    struct json_object *v=NULL;
    if(o)json_object_object_get_ex(o,key,&v);
    return v;
}

static struct json_object *reply_error(const char *code,int status)
{
    struct json_object *out=flowd_error(code,code);
    json_object_object_add(out,"http_status",json_object_new_int(status));
    return out;
}

static struct sla_slot *slot_for(const char *id,int create)
{
    unsigned i;
    struct sla_slot *empty=NULL;
    for(i=0;i<SLA_SLOTS;i++) {
        if(slots[i].id[0] && !strcmp(slots[i].id,id))return &slots[i];
        if(!slots[i].id[0] && !empty)empty=&slots[i];
    }
    if(!create || !empty)return NULL;
    snprintf(empty->id,sizeof(empty->id),"%s",id);
    return empty;
}

static void slot_clear(struct sla_slot *s)
{
    if(s->rule)json_object_put(s->rule);
    if(s->runtime)json_object_put(s->runtime);
    if(s->test_plan)json_object_put(s->test_plan);
    if(s->test_result)json_object_put(s->test_result);
    free(s->evaluator);
    memset(s,0,sizeof(*s));
}

static int history_open(void)
{
    if(history_db)return 0;
    if(wan_sla_history_open(SLA_HISTORY_PATH,&history_db)!=0)return -1;
    return 0;
}

static const char *transition_event(struct json_object *runtime)
{
    const char *state=flowd_json_str(runtime,"state","unknown");
    const char *stable=flowd_json_str(runtime,"stable_state","unknown");
    if(!strcmp(state,"recovering"))return "wan.sla.recovering";
    if(!strcmp(stable,"healthy"))return "wan.sla.recovered";
    if(!strcmp(stable,"degraded"))return "wan.sla.degraded";
    if(!strcmp(stable,"critical"))return "wan.sla.critical";
    if(!strcmp(stable,"down"))return "wan.sla.down";
    return NULL;
}

static void event_add(struct json_object *events,struct json_object *runtime,
                      const char *name)
{
    struct json_object *event;
    if(!name || !name[0])return;
    event=json_tokener_parse(json_object_to_json_string_ext(runtime,JSON_C_TO_STRING_PLAIN));
    if(!event)return;
    json_object_object_add(event,"event",json_object_new_string(name));
    json_object_array_add(events,event);
}

static void history_store(struct sla_slot *s,struct json_object *samples,
                           struct json_object *runtime,const char *decision)
{
    struct json_object *events=json_object_new_array();
    struct json_object *action=value(runtime,"route_action");
    const char *suppressed=flowd_json_str(action,"suppressed_reason","");
    const char *error=flowd_json_str(action,"error","");
    int transition=flowd_json_bool(runtime,"transition",0);
    (void)s;(void)decision;
    if(transition)
        event_add(events,runtime,transition_event(runtime));
    if(transition && suppressed[0])event_add(events,runtime,"wan.sla.action_suppressed");
    if(transition && error[0])event_add(events,runtime,"wan.sla.route_action_failed");
    if(!strcmp(flowd_json_str(runtime,"decision_suppressed_reason",""),"evidence_stale"))
        event_add(events,runtime,"wan.sla.evidence_stale");
    if(history_open() || wan_sla_history_record(history_db,runtime,samples,events))
        history_degraded=1;
    else history_degraded=0;
    json_object_put(events);
}

static int action_candidate(struct sla_slot *slot,struct json_object *runtime,
                            int64_t now,int *level)
{
    const char *suppressed;
    if(!slot || !slot->enabled || !runtime ||
       !flowd_json_bool(runtime,"sample_fresh",0) || now>
       json_object_get_int64(value(runtime,"expires_at")) || !value(runtime,"requested_level"))return 0;
    suppressed=flowd_json_str(runtime,"decision_suppressed_reason","");
    if(suppressed[0])return 0;
    *level=flowd_json_int(runtime,"requested_level",-1);
    return *level>=0 && *level<=3;
}

static int aggregate_worst(struct sla_slot *current,struct json_object *runtime,
                           struct json_object **contributors,const char **winner)
{
    int64_t now=flowd_now_s();
    int current_level=-1,worst=-1;
    const char *chosen=NULL;
    unsigned i;
    struct json_object *items=json_object_new_array();

    for(i=0;i<SLA_SLOTS;i++) {
        struct sla_slot *slot=&slots[i];
        struct json_object *candidate=slot==current?runtime:slot->runtime;
        struct json_object *item;
        int level;
        if(!slot->id[0] || strcmp(slot->wan,current->wan) ||
           !action_candidate(slot,candidate,now,&level))continue;
        item=json_object_new_object();
        json_object_object_add(item,"sla_id",json_object_new_string(slot->id));
        json_object_object_add(item,"sla_revision",json_object_new_int64(slot->revision));
        json_object_object_add(item,"requested_level",json_object_new_int(level));
        json_object_object_add(item,"stable_state",json_object_get(value(candidate,"stable_state")));
        json_object_object_add(item,"decision_id",json_object_get(value(candidate,"decision_id")));
        json_object_array_add(items,item);
        if(level>worst || (level==worst && (!chosen || strcmp(slot->id,chosen)<0))) {
            worst=level;chosen=slot->id;
        }
        if(slot==current)current_level=level;
    }
    *contributors=items;
    *winner=chosen;
    return current_level>=0 && chosen && !strcmp(chosen,current->id);
}

static struct json_object *route_action(struct sla_slot *s,struct json_object *runtime,
                                        const char *decision)
{
    struct json_object *action=json_object_new_object(),*request,*response,*data=NULL,*contributors;
    const char *mode=flowd_json_str(s->rule,"action_mode","observe");
    const char *suppressed=flowd_json_str(runtime,"decision_suppressed_reason","");
    const char *winner=NULL;
    int is_winner=aggregate_worst(s,runtime,&contributors,&winner);
    char digest[17];

    json_object_object_add(action,"decision_id",json_object_new_string(decision));
    json_object_object_add(action,"requested_level",json_object_get(value(runtime,"requested_level")));
    json_object_object_add(action,"applied_level",NULL);
    json_object_object_add(action,"readback_ok",json_object_new_boolean(0));
    json_object_object_add(action,"aggregation",json_object_new_string("worst"));
    json_object_object_add(action,"contributing_slas",contributors);
    if(winner)json_object_object_add(action,"winning_sla_id",json_object_new_string(winner));
    if(!strcmp(mode,"observe")) {
        json_object_object_add(action,"suppressed_reason",json_object_new_string("observe_mode"));
        return action;
    }
    if(!SLA_RUNTIME_APPLY_ENABLED) {
        json_object_object_add(action,"suppressed_reason",json_object_new_string("acceptance_gate_closed"));
        return action;
    }
    if(!is_winner) {
        json_object_object_add(action,"suppressed_reason",json_object_new_string(
            winner?"aggregated_by_worst_sla":"evaluation_unavailable"));
        return action;
    }
    if(!flowd_json_bool(runtime,"sample_fresh",0) || suppressed[0] ||
       !value(runtime,"requested_level")) {
        json_object_object_add(action,"suppressed_reason",json_object_new_string(
            suppressed[0]?suppressed:"evaluation_unavailable"));
        return action;
    }
    request=json_object_new_object();
    snprintf(digest,sizeof(digest),"%s",flowd_json_str(runtime,"config_digest",""));
    if(!digest[0])wan_sla_config_digest(s->rule,digest);
    json_object_object_add(request,"sla_id",json_object_new_string(s->id));
    json_object_object_add(request,"sla_revision",json_object_new_int64(s->revision));
    json_object_object_add(request,"wan_id",json_object_new_string(s->wan));
    json_object_object_add(request,"evaluated_at",json_object_get(value(runtime,"evaluated_at")));
    json_object_object_add(request,"expires_at",json_object_get(value(runtime,"expires_at")));
    json_object_object_add(request,"state",json_object_get(value(runtime,"state")));
    json_object_object_add(request,"stable_state",json_object_get(value(runtime,"stable_state")));
    json_object_object_add(request,"requested_level",json_object_get(value(runtime,"requested_level")));
    json_object_object_add(request,"reasons",json_object_get(value(runtime,"breached_dimensions")));
    json_object_object_add(request,"evidence_window",json_object_get(value(runtime,"window")));
    json_object_object_add(request,"decision_id",json_object_new_string(decision));
    json_object_object_add(request,"config_digest",json_object_new_string(digest));
    json_object_object_add(request,"transition",json_object_get(value(runtime,"transition")));
    json_object_object_add(request,"contributing_slas",json_object_get(contributors));
    response=flowd_core_call("route_sla_apply",request,5000);
    json_object_put(request);
    if(response && json_object_object_get_ex(response,"data",&data) && data &&
       json_object_is_type(data,json_type_object)) {
        json_object_put(action);
        action=json_tokener_parse(json_object_to_json_string_ext(data,JSON_C_TO_STRING_PLAIN));
    } else {
        json_object_object_add(action,"error",json_object_new_string(
            response?flowd_json_str(response,"error","route_action_failed"):"route_action_failed"));
    }
    if(response)json_object_put(response);
    return action;
}

static struct json_object *sample_json(struct sla_slot *s,const char *decision,
                                       struct json_object *rule,unsigned i,
                                       const struct wan_probe_result *r)
{
    struct json_object *out=json_object_new_object();
    /* decision_id is at most 159 bytes; retain the complete sample suffix. */
    char id[160 + sizeof(":4294967295") - 1];
    snprintf(id,sizeof(id),"%s:%u",decision,i);
    json_object_object_add(out,"sample_id",json_object_new_string(id));
    json_object_object_add(out,"decision_id",json_object_new_string(decision));
    json_object_object_add(out,"sla_id",json_object_new_string(s->id));
    json_object_object_add(out,"sla_revision",json_object_new_int64(s->revision));
    json_object_object_add(out,"wan_id",json_object_new_string(s->wan));
    json_object_object_add(out,"target",json_object_get(json_object_array_get_idx(value(rule,"targets"),i)));
    json_object_object_add(out,"method",json_object_new_string(flowd_json_str(rule,"method","")));
#define BOOL_FIELD(k) json_object_object_add(out,#k,json_object_new_boolean(r->k))
    BOOL_FIELD(ok);BOOL_FIELD(valid);
#undef BOOL_FIELD
#define NUM_FIELD(k) json_object_object_add(out,#k,r->k>=0?json_object_new_double(r->k):NULL)
    NUM_FIELD(latency_ms);NUM_FIELD(dns_ms);NUM_FIELD(tcp_ms);NUM_FIELD(tls_ms);
#undef NUM_FIELD
    json_object_object_add(out,"started_at",json_object_new_int64(r->started_at));
    json_object_object_add(out,"finished_at",json_object_new_int64(r->finished_at));
    json_object_object_add(out,"http_status",r->http_status?json_object_new_int(r->http_status):NULL);
    json_object_object_add(out,"source_ifname",json_object_new_string(r->source_ifname));
    json_object_object_add(out,"source_address",json_object_new_string(r->source_address));
    json_object_object_add(out,"source_address_family",json_object_new_int(r->address_family));
    json_object_object_add(out,"error_class",json_object_new_string(r->error_class));
    json_object_object_add(out,"error_detail_redacted",json_object_new_string(r->error_class));
    return out;
}

static void worker_done(struct uloop_process *p,int status)
{
    struct sla_worker *w=(struct sla_worker *)((char *)p - offsetof(struct sla_worker,process));
    struct sla_slot *s=w->slot;
    struct sla_batch batch;
    struct wan_sla_profile profile;
    struct json_object *samples=json_object_new_array(),*runtime,*action;
    struct wan_sla_round round={.at=flowd_now_s(),.forwarding_loss_pct=-1};
    char decision[160],config_digest[17];
    unsigned i,valid=0,ok=0;
    ssize_t n=recv(w->fd,&batch,sizeof(batch),MSG_DONTWAIT);
    int success=WIFEXITED(status) && WEXITSTATUS(status)==0;
    snprintf(decision,sizeof(decision),"%s:%lld:%lld:%lld",s->id,(long long)w->revision,
        (long long)round.at,(long long)++decision_sequence);
    if(!success || n!=(ssize_t)sizeof(batch) || batch.count<1 || batch.count>WAN_SLA_MAX_TARGETS) {
        memset(&batch,0,sizeof(batch));
        batch.count=(unsigned)json_object_array_length(value(w->rule,"targets"));
        for(i=0;i<batch.count;i++)snprintf(batch.targets[i].error_class,sizeof(batch.targets[i].error_class),"probe_worker_failed");
    }
    for(i=0;i<batch.count;i++) {
        valid+=batch.targets[i].valid!=0;ok+=batch.targets[i].ok!=0;
        round.latency_ms[i]=batch.targets[i].latency_ms;
        if(batch.targets[i].ok)round.ok_mask|=1U<<i;
        json_object_array_add(samples,sample_json(s,decision,w->rule,i,&batch.targets[i]));
    }
    round.count=batch.count;
    if(w->is_test) {
        if(s->test_result)json_object_put(s->test_result);
        s->test_result=json_object_new_object();
        json_object_object_add(s->test_result,"complete",json_object_new_boolean(1));
        json_object_object_add(s->test_result,"targets",json_object_get(samples));
        json_object_object_add(s->test_result,"ready",json_object_new_boolean(
            valid==batch.count && !wan_sla_profile_read(w->rule,&profile) && ok>=(unsigned)profile.reliability));
        s->test_at=round.at;
    } else if(config_ready && s->enabled && s->revision==w->revision &&
               !wan_sla_profile_read(w->rule,&profile)) {
        if(!s->evaluator) {
            s->evaluator=calloc(1,sizeof(*s->evaluator));
            if(s->evaluator)wan_sla_evaluator_reset(s->evaluator,s->revision);
        }
        if(s->evaluator && valid==batch.count)wan_sla_evaluator_add(s->evaluator,s->revision,&round);
        runtime=wan_sla_evaluate(s->evaluator,&profile,round.at);
        if(valid!=batch.count)json_object_object_add(runtime,"decision_suppressed_reason",json_object_new_string("probe_invalid"));
        json_object_object_add(runtime,"available",json_object_new_boolean(s->evaluator!=NULL));
        json_object_object_add(runtime,"sla_id",json_object_new_string(s->id));
        json_object_object_add(runtime,"sla_revision",json_object_new_int64(s->revision));
        json_object_object_add(runtime,"wan_id",json_object_new_string(s->wan));
        json_object_object_add(runtime,"decision_id",json_object_new_string(decision));
        json_object_object_add(runtime,"evaluated_at",json_object_new_int64(round.at));
        json_object_object_add(runtime,"expires_at",json_object_new_int64(round.at+profile.interval_s*3));
        wan_sla_config_digest(w->rule,config_digest);
        json_object_object_add(runtime,"config_digest",json_object_new_string(config_digest));
        json_object_object_add(runtime,"samples",json_object_get(samples));
        json_object_object_add(runtime,"thresholds",json_object_get(w->rule));
        action=route_action(s,runtime,decision);
        json_object_object_add(runtime,"route_action",action);
        if(s->runtime)json_object_put(s->runtime);
        s->runtime=runtime;
        s->next_due_at=round.at+(s->evaluator && s->evaluator->recovering?profile.recovery_interval_s:
            s->evaluator && s->evaluator->failure_streak?profile.failure_interval_s:profile.interval_s);
        history_store(s,samples,runtime,decision);
    }
    json_object_put(samples);json_object_put(w->rule);close(w->fd);
    s->running=0;
    memset(w,0,sizeof(*w));w->fd=-1;
}

static void child_probe(struct sla_worker *w,int fd)
{
    struct sla_batch batch={0};
    struct json_object *targets=value(w->rule,"targets");
    struct json_object *expected=value(w->rule,"expected_status");
    char ifname[IFNAMSIZ]="";
    int expected_status[16];
    unsigned expected_count=0;
    unsigned i;
    int resolved=flowd_wan_resolve_l3_ifname(flowd_json_str(w->rule,"wan",""),ifname,sizeof(ifname));
    if(expected && json_object_is_type(expected,json_type_array)) {
        expected_count=(unsigned)json_object_array_length(expected);
        if(expected_count>16)expected_count=16;
        for(i=0;i<expected_count;i++)
            expected_status[i]=json_object_get_int(json_object_array_get_idx(expected,i));
    }
    batch.count=(unsigned)json_object_array_length(targets);
    for(i=0;i<batch.count;i++) {
        struct wan_probe_request request={.ifname=ifname,
            .method=flowd_json_str(w->rule,"method",""),
            .target=json_object_get_string(json_object_array_get_idx(targets,i)),
            .dns_servers=flowd_json_str(w->rule,"dns_servers",""),
            .body_marker=flowd_json_str(w->rule,"body_marker",""),
            .expected_status=expected_count?expected_status:NULL,
            .expected_status_count=expected_count,
            .timeout_ms=flowd_json_int(w->rule,"timeout_ms",1000)};
        if(resolved)snprintf(batch.targets[i].error_class,sizeof(batch.targets[i].error_class),"wan_device_unavailable");
        else wan_probe_run(&request,&batch.targets[i]);
    }
    _exit(send(fd,&batch,sizeof(batch),MSG_NOSIGNAL)==(ssize_t)sizeof(batch)?0:1);
}

static int worker_start(struct sla_slot *s,int is_test)
{
    struct sla_worker *w=NULL;
    unsigned i;
    int pair[2];
    pid_t pid;
    for(i=0;i<SLA_WORKERS;i++) {
        if(workers[i].slot && !strcmp(workers[i].slot->wan,s->wan))return -1;
        if(!workers[i].slot && !w)w=&workers[i];
    }
    if(!w || socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0,pair))return -1;
    w->slot=s;w->is_test=is_test;w->revision=s->revision;
    w->rule=json_object_get(is_test?s->test_plan:s->rule);
    pid=fork();
    if(pid<0){json_object_put(w->rule);memset(w,0,sizeof(*w));close(pair[0]);close(pair[1]);return -1;}
    if(!pid) {
        close(pair[0]);
        signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);
        child_probe(w,pair[1]);
    }
    close(pair[1]);w->fd=pair[0];w->process.pid=pid;w->process.cb=worker_done;
    w->deadline=flowd_now_s()+5+(int64_t)json_object_array_length(value(w->rule,"targets"))*
        ((flowd_json_int(w->rule,"timeout_ms",1000)+999)/1000);
    if(uloop_process_add(&w->process)) {
        kill(pid,SIGKILL);while(waitpid(pid,NULL,0)<0 && errno==EINTR);
        close(pair[0]);json_object_put(w->rule);memset(w,0,sizeof(*w));return -1;
    }
    s->running=1;if(is_test)s->test_pending=0;
    return 0;
}

static void reload_config(int64_t now)
{
    struct json_object *listing=flowd_wan_sla_list(NULL),*items=value(listing,"items");
    unsigned i;
    config_ready=flowd_json_bool(listing,"ok",0) && flowd_wan_sla_shadow_ready();
    if(!config_ready){json_object_put(listing);return;}
    for(i=0;i<json_object_array_length(items);i++) {
        struct json_object *item=json_object_array_get_idx(items,i);
        const char *id=flowd_json_str(item,"id","");
        struct sla_slot *s=slot_for(id,flowd_json_bool(item,"enabled",0));
        int64_t revision=json_object_get_int64(value(item,"revision"));
        if(!s)continue;
        s->seen=now;
        if(s->revision!=revision) {
            if(s->runtime){json_object_put(s->runtime);s->runtime=NULL;}
            if(s->evaluator)wan_sla_evaluator_reset(s->evaluator,revision);
            s->revision=revision;
            s->restored=0;
        }
        s->enabled=flowd_json_bool(item,"enabled",0);
        snprintf(s->wan,sizeof(s->wan),"%s",flowd_json_str(item,"wan",""));
        if(s->enabled && !s->runtime && !s->restored && history_db) {
            struct json_object *restored=wan_sla_history_restore(history_db,s->id);
            if(restored) {
                json_object_object_add(restored,"available",json_object_new_boolean(0));
                json_object_object_add(restored,"sample_fresh",json_object_new_boolean(0));
                json_object_object_add(restored,"decision_suppressed_reason",
                    json_object_new_string("revalidating_after_restart"));
                s->runtime=restored;
            }
            s->restored=1;
        }
        json_object_object_del(item,"runtime");
        if(s->rule)json_object_put(s->rule);
        s->rule=json_object_get(item);
    }
    for(i=0;i<SLA_SLOTS;i++) {
        struct sla_slot *s=&slots[i];
        if(!s->id[0] || s->seen==now)continue;
        s->enabled=0;
        if(!s->running && !s->test_pending && now-s->test_at>120)slot_clear(s);
    }
    json_object_put(listing);
}

static void tick(struct uloop_timeout *t)
{
    int64_t now=flowd_now_s();
    unsigned i;
    (void)t;
    if(!started)return;
    if(!last_reload || now-last_reload>=5){reload_config(now);last_reload=now;}
    if(history_db && (!last_history_prune || now-last_history_prune>=300)) {
        last_history_prune=now;
        if(wan_sla_history_prune(history_db,now,SLA_HISTORY_BYTES,100000,100000,10000))
            history_degraded=1;
    }
    for(i=0;i<SLA_WORKERS;i++)
        if(workers[i].slot && now>workers[i].deadline)kill(workers[i].process.pid,SIGKILL);
    for(i=0;i<SLA_SLOTS;i++) {
        struct sla_slot *s=&slots[(schedule_cursor+i)%SLA_SLOTS];
        if(!s->id[0] || s->running)continue;
        if(s->test_pending)worker_start(s,1);
        else if(config_ready && s->enabled && s->next_due_at<=now)worker_start(s,0);
    }
    schedule_cursor=(schedule_cursor+1)%SLA_SLOTS;
    uloop_timeout_set(&timer,250);
}

int flowd_wan_sla_runtime_start(void)
{
    if(started)return 0;
    memset(&timer,0,sizeof(timer));timer.cb=tick;
    if(history_open()!=0)history_degraded=1;
    started=1;uloop_timeout_set(&timer,1000);return 0;
}

void flowd_wan_sla_runtime_stop(void)
{
    unsigned i;
    started=0;uloop_timeout_cancel(&timer);
    for(i=0;i<SLA_WORKERS;i++)if(workers[i].slot) {
        uloop_process_delete(&workers[i].process);kill(workers[i].process.pid,SIGKILL);
        while(waitpid(workers[i].process.pid,NULL,0)<0 && errno==EINTR);
        close(workers[i].fd);json_object_put(workers[i].rule);memset(&workers[i],0,sizeof(workers[i]));
    }
    for(i=0;i<SLA_SLOTS;i++)slot_clear(&slots[i]);
    if(history_db){sqlite3_close(history_db);history_db=NULL;}
}

int flowd_wan_sla_shadow_ready(void) { return started && SLA_SHADOW_SAMPLER_IMPLEMENTED; }

void flowd_wan_sla_config_changed(void)
{
    last_reload=0;
    if(started)uloop_timeout_set(&timer,1);
}

struct json_object *flowd_wan_sla_runtime_item(const char *id)
{
    struct sla_slot *s=slot_for(id,0);
    struct json_object *out=s && s->runtime?
        json_tokener_parse(json_object_to_json_string_ext(s->runtime,JSON_C_TO_STRING_PLAIN)):json_object_new_object();
    int64_t now=flowd_now_s();
    if(!s || !s->runtime) {
        json_object_object_add(out,"available",json_object_new_boolean(0));
        json_object_object_add(out,"state",json_object_new_string("unknown"));
        json_object_object_add(out,"reason",json_object_new_string(s && s->enabled?"revalidating":"disabled"));
    } else if(!s->enabled || !config_ready || now>json_object_get_int64(value(out,"expires_at"))) {
        json_object_object_add(out,"sample_fresh",json_object_new_boolean(0));
        json_object_object_add(out,"decision_suppressed_reason",json_object_new_string(!s->enabled?"disabled":!config_ready?"config_unavailable":"evidence_stale"));
    }
    json_object_object_add(out,"next_sample_at",json_object_new_int64(s?s->next_due_at:0));
    json_object_object_add(out,"history_degraded",json_object_new_boolean(history_degraded));
    if(s && s->test_result)json_object_object_add(out,"test",json_object_get(s->test_result));
    json_object_object_add(out,"test_pending",json_object_new_boolean(s && (s->test_pending || s->running)));
    return out;
}

struct json_object *flowd_wan_sla_runtime_json(struct json_object *body)
{
    struct json_object *out=json_object_new_object(),*items=json_object_new_array();
    const char *id=flowd_json_str(body,"id","");
    unsigned i;
    for(i=0;i<SLA_SLOTS;i++)if(slots[i].id[0] && (!id[0] || !strcmp(id,slots[i].id))) {
        struct json_object *item=flowd_wan_sla_runtime_item(slots[i].id);
        json_object_object_add(item,"sla_id",json_object_new_string(slots[i].id));
        json_object_object_add(item,"wan_id",json_object_new_string(slots[i].wan));
        json_object_array_add(items,item);
    }
    json_object_object_add(out,"ok",json_object_new_boolean(1));
    json_object_object_add(out,"items",items);
    json_object_object_add(out,"action_mode",json_object_new_string("observe"));
    json_object_object_add(out,"global_concurrency_limit",json_object_new_int(SLA_WORKERS));
    json_object_object_add(out,"per_wan_concurrency_limit",json_object_new_int(1));
    return out;
}

struct json_object *flowd_wan_sla_test(struct json_object *body)
{
    struct json_object *request,*preview,*plan,*out;
    struct sla_slot *s;
    const char *id;
    if(!flowd_wan_sla_shadow_ready())return reply_error("shadow_validation_pending",503);
    if(!body || !json_object_is_type(body,json_type_object))return reply_error("invalid_request",400);
    request=json_tokener_parse(json_object_to_json_string_ext(body,JSON_C_TO_STRING_PLAIN));
    json_object_object_add(request,"enabled",json_object_new_boolean(0));
    json_object_object_add(request,"operation",json_object_new_string("upsert"));
    preview=flowd_wan_sla_preview(request);json_object_put(request);
    if(!flowd_json_bool(preview,"ok",0))return preview;
    plan=value(preview,"plan");id=flowd_json_str(plan,"id","");
    s=slot_for(id,1);
    if(!s || s->running || s->test_pending){json_object_put(preview);return reply_error("sampler_busy",429);}
    snprintf(s->wan,sizeof(s->wan),"%s",flowd_json_str(plan,"wan",""));
    s->revision=json_object_get_int64(value(plan,"expected_revision"));
    if(s->test_plan)json_object_put(s->test_plan);
    if(s->test_result){json_object_put(s->test_result);s->test_result=NULL;}
    s->test_plan=json_object_get(plan);s->test_pending=1;
    out=json_object_new_object();
    json_object_object_add(out,"ok",json_object_new_boolean(1));
    json_object_object_add(out,"http_status",json_object_new_int(202));
    json_object_object_add(out,"resource_id",json_object_new_string(s->id));
    json_object_object_add(out,"pending",json_object_new_boolean(1));
    json_object_object_add(out,"runtime_applied",json_object_new_boolean(0));
    json_object_put(preview);uloop_timeout_set(&timer,1);return out;
}

int flowd_wan_sla_dry_probe_matches(struct json_object *plan)
{
    struct sla_slot *s=slot_for(flowd_json_str(plan,"id",""),0);
    struct json_object *copy;
    int match;
    if(!started || !s || !s->test_plan || !s->test_result ||
        !flowd_json_bool(s->test_result,"ready",0) || flowd_now_s()<s->test_at || flowd_now_s()-s->test_at>120)return 0;
    copy=json_tokener_parse(json_object_to_json_string_ext(plan,JSON_C_TO_STRING_PLAIN));
    json_object_object_add(copy,"enabled",json_object_new_boolean(0));
    match=json_object_equal(copy,s->test_plan);json_object_put(copy);return match;
}

struct json_object *flowd_wan_sla_history(struct json_object *body)
{
    struct json_object *out=wan_sla_history_query(SLA_HISTORY_PATH,body);
    if(!flowd_json_bool(out,"ok",0)) {
        int status=flowd_json_int(out,"http_status",503);
        char error[64];
        snprintf(error,sizeof(error),"%s",flowd_json_str(out,"error","history_unavailable"));
        json_object_put(out);
        return reply_error(error,status);
    }
    return out;
}
