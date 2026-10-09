/* SPDX-License-Identifier: GPL-2.0-or-later
 * Session transitions share the analyzer's one SQLite transaction. The provider
 * has its own durable idempotency receipts; retries across the two stores use
 * the same request id and never create a second rule/trial.
 */
static struct json_object *provider_request(const struct ada_environment *e,const char *op,
                                           struct json_object *s,struct json_object *b,int *status) {
    if(!e->provider)return error(status,409,"exact_device_domain_provider_unavailable","原生 DNS 设备执行点尚未就绪");
    struct json_object *req=b?copy(b):obj();
    if(s){text(req,"session_id",str(s,"session_id"));text(req,"operator_id",str(s,"operator_id"));text(req,"device_id",str(s,"device_id"));text(req,"device_ip",str(s,"device_ip"));}
    struct json_object *r=e->provider(e->provider_context,op,req);json_object_put(req);
    if(!r)return error(status,503,"provider_unavailable","无法连接设备规则服务，请保留草稿并重试");
    if(!num(r,"ok")){const char *code=str(child(r,"error"),"code");*status=!strcmp(code,"resource_owner_required")?403:!strncmp(code,"invalid_",8)?400:!strcmp(code,"storage_unavailable")||!strcmp(code,"provider_apply_failed")?503:409;}
    return r;
}
static int provider_ready(const struct ada_environment *e) {
    if(!e->provider)return 0;int st=200;struct json_object *r=provider_request(e,"capabilities",NULL,NULL,&st);int ready=st<400&&num(r,"ready");json_object_put(r);return ready;
}
static void trial_event(struct json_object *s,const struct ada_environment *e,const char *event,struct json_object *value) {
    struct json_object *h=child(s,"trial_history");if(!h){h=arr();json_object_object_add(s,"trial_history",h);}if(json_object_array_length(h)>=96)json_object_array_del_idx(h,0,1);
    struct json_object *v=obj();number(v,"at",e->now);text(v,"event",event);json_object_object_add(v,"detail",copy(value));json_object_array_add(h,v);
}
static int report_conclusions(sqlite3 *db,struct json_object *s,const struct ada_environment *e) {
    if(!*str(s,"report_id"))return 0;struct json_object *r=load(db,"analyzer_reports",str(s,"report_id"));if(!r)return 0;
    const char *keys[]={"trial_history","conclusions","bisect",NULL};for(int i=0;keys[i];i++)if(child(s,keys[i]))json_object_object_add(r,keys[i],copy(child(s,keys[i])));
    number(r,"conclusions_updated_at",e->now);number(r,"report_revision",num(r,"report_revision")+1);
    sqlite3_stmt *st=NULL;int rc=-1;if(strlen(json(r))<=MAX_DOCUMENT&&sqlite3_prepare_v2(db,"UPDATE analyzer_reports SET document=?2 WHERE id=?1",-1,&st,NULL)==SQLITE_OK){sqlite3_bind_text(st,1,str(s,"report_id"),-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,2,json(r),-1,SQLITE_TRANSIENT);rc=sqlite3_step(st)==SQLITE_DONE?0:-1;}sqlite3_finalize(st);json_object_put(r);return rc;
}
static int trial_live(struct json_object *s) {const char *state=str(child(s,"trial"),"apply_state");return !strcmp(state,"applied")||!strcmp(state,"reverting");}
static struct json_object *withdraw(const struct ada_environment *e,struct json_object *s,struct json_object *b,int *status) {
    struct json_object *r=provider_request(e,"revoke",s,b,status);if(*status<400){struct json_object *t=child(s,"trial");if(t){text(t,"apply_state","reverted");number(t,"reverted_at",e->now);trial_event(s,e,"reverted",t);}}return r;
}
static struct json_object *apply_trial(const struct ada_environment *e,struct json_object *s,struct json_object *b,int *status) {
    struct json_object *req=copy(b);char id[48];
    mutation_id(id,sizeof(id),"trial_",str(s,"operator_id"),str(b,"request_id"));
    text(req,"trial_id",id);
    struct json_object *r=provider_request(e,"replace",s,req,status);json_object_put(req);
    if(*status<400){number(r,"revision",num(child(s,"trial"),"revision")+1);json_object_object_add(s,"trial",copy(r));trial_event(s,e,"applied",r);}
    return r;
}
static struct json_object *split_round(struct json_object *candidates) {
    struct json_object *x=obj(),*applied=arr(),*holdout=arr();size_t n=json_object_array_length(candidates),half=(n+1)/2;
    for(size_t i=0;i<n;i++)json_object_array_add(i<half?applied:holdout,copy(json_object_array_get_idx(candidates,i)));
    json_object_object_add(x,"candidates",copy(candidates));json_object_object_add(x,"applied",applied);json_object_object_add(x,"holdout",holdout);boolean(x,"final_retest",n==1);text(x,"state","awaiting_feedback");return x;
}
static int round_id(struct json_object *x){char id[48];if(make_id(id,sizeof(id),"round_"))return -1;text(x,"round_id",id);return 0;}
static struct json_object *trial_change(sqlite3 *db,const struct ada_environment *e,struct json_object *s,
                                       const char *method,const char *suffix,struct json_object *b,int *status) {
    struct json_object *r=NULL;
    if(!strncmp(suffix,"conclusions/",12)&&strcmp(method,"POST"))return error(status,405,"method_not_allowed","保存与预览使用 POST");
    if(num(s,"ended")&&(strstr(suffix,"trial")||!strncmp(suffix,"bisect",6)))return error(status,409,"session_ended","会话已结束，请创建新会话");
    if(!strcmp(suffix,"conclusions/preview"))return provider_request(e,"preview",s,b,status);
    if(!strcmp(suffix,"conclusions/commit")) {
        r=provider_request(e,"commit",s,b,status);
        if(*status<400){struct json_object *c=child(s,"conclusions");if(!c){c=arr();json_object_object_add(s,"conclusions",c);}if(json_object_array_length(c)>=16){json_object_array_del_idx(c,0,1);boolean(s,"conclusions_truncated",1);}json_object_array_add(c,copy(r));trial_event(s,e,"permanent_saved",r);}
    }else if(!strcmp(suffix,"trial")&&!strcmp(method,"DELETE")){
        r=withdraw(e,s,b,status);if(*status<400&&child(s,"bisect"))text(child(s,"bisect"),"state","ended");
    }else if(!strcmp(suffix,"trial")&&(!strcmp(method,"POST")||!strcmp(method,"PUT"))){
        r=apply_trial(e,s,b,status);if(*status<400&&child(s,"bisect"))text(child(s,"bisect"),"state","replaced_manually");
    }else if(!strcmp(suffix,"trial/feedback")&&!strcmp(method,"POST")){
        struct json_object *t=child(s,"trial");const char *feedback=str(b,"feedback");
        if(!trial_live(s)||strcmp(str(t,"id"),str(b,"trial_id"))||num(t,"expires_at")<=e->now)return error(status,409,"trial_expired","试验未生效或已到期，请重新应用");
        if(strcmp(feedback,"effective")&&strcmp(feedback,"ineffective")&&strcmp(feedback,"uncertain"))return error(status,400,"invalid_feedback","请选择有效、无效或不确定");
        text(t,"feedback",feedback);number(t,"feedback_at",e->now);trial_event(s,e,"manual_feedback",t);r=ok(obj());
    }else if(!strncmp(suffix,"bisect",6)&&!strcmp(method,"POST")){
        struct json_object *old=child(s,"bisect"),*x=NULL,*req=copy(b),*history=NULL;
        if(!strcmp(suffix,"bisect")){
            if(!num(b,"baseline_confirmed")){json_object_put(req);return error(status,400,"baseline_required","请先确认问题可重复出现，再开始分轮排查");}
            struct json_object *pv=provider_request(e,"preview",s,b,status);
            if(*status>=400){json_object_put(req);return pv;}
            x=split_round(child(pv,"rules"));json_object_put(pv);
            json_object_object_add(x,"original",copy(child(b,"rules")));json_object_object_add(x,"cleared",arr());json_object_object_add(x,"history",arr());number(x,"round",1);
        }else{
            struct json_object *t=child(s,"trial");
            int final_undo=!strcmp(suffix,"bisect/undo")&&old&&(!strcmp(str(old,"state"),"verified_candidate")||!strcmp(str(old,"state"),"unlocated"));
            if(!old||(!final_undo&&(strcmp(str(old,"state"),"awaiting_feedback")||!trial_live(s)||num(t,"expires_at")<=e->now))||strcmp(str(t,"id"),str(b,"trial_id"))||strcmp(str(old,"round_id"),str(b,"round_id"))){json_object_put(req);return error(status,409,"round_conflict","轮次已变化、已结束或租约失效，请回读当前试验");}
            history=copy(child(old,"history"));if(!history)history=arr();
            if(!strcmp(suffix,"bisect/undo")){
                size_t n=json_object_array_length(history);if(!n){json_object_put(req);json_object_put(history);return error(status,409,"no_previous_round","已经是第一轮");}
                x=copy(json_object_array_get_idx(history,n-1));json_object_array_del_idx(history,n-1,1);json_object_object_add(x,"history",history);
            }else if(!strcmp(suffix,"bisect/feedback")){
                const char *feedback=str(b,"feedback");if(strcmp(feedback,"effective")&&strcmp(feedback,"ineffective")&&strcmp(feedback,"uncertain")){json_object_put(req);json_object_put(history);return error(status,400,"invalid_feedback","反馈必须明确");}
                if(json_object_array_length(history)>=24){json_object_put(req);json_object_put(history);return error(status,409,"round_limit","已达轮次上限，请结束后重新确认基线");}
                struct json_object *snapshot=copy(old);json_object_object_del(snapshot,"history");text(snapshot,"feedback",feedback);number(snapshot,"feedback_at",e->now);json_object_array_add(history,snapshot);trial_event(s,e,"round_feedback",snapshot);
                if(!strcmp(feedback,"uncertain")){x=copy(old);json_object_object_add(x,"history",history);}
                else if(num(old,"final_retest")){
                    x=copy(old);json_object_object_add(x,"history",history);text(x,"state",!strcmp(feedback,"effective")?"verified_candidate":"unlocated");
                    if(!strcmp(feedback,"effective"))json_object_object_add(x,"culprits",copy(child(old,"applied")));
                    text(x,"interpretation",!strcmp(feedback,"effective")?"single_rule_retest_effective_not_proof_of_only_cause":"candidate_not_reproducible_or_multiple_causes");
                }else{
                    struct json_object *remaining=child(old,!strcmp(feedback,"effective")?"applied":"holdout");x=split_round(remaining);json_object_object_add(x,"original",copy(child(old,"original")));json_object_object_add(x,"history",history);struct json_object *cleared=copy(child(old,"cleared"));if(!cleared)cleared=arr();struct json_object *excluded=child(old,!strcmp(feedback,"effective")?"holdout":"applied");for(size_t i=0;i<json_object_array_length(excluded);i++)json_object_array_add(cleared,copy(json_object_array_get_idx(excluded,i)));json_object_object_add(x,"cleared",cleared);if(!json_object_array_length(remaining))text(x,"state","unlocated");
                }
                number(x,"round",num(old,"round")+1);
            }else{json_object_put(req);json_object_put(history);return error(status,404,"not_found","分轮操作不存在");}
        }
        if(round_id(x)){json_object_put(req);json_object_put(x);return error(status,503,"entropy_unavailable","无法生成轮次标识");}
        if(!strcmp(str(x,"state"),"awaiting_feedback")){
            json_object_object_add(req,"rules",copy(child(x,"applied")));r=apply_trial(e,s,req,status);
            if(*status<400){text(x,"trial_id",str(r,"id"));number(x,"expires_at",num(r,"expires_at"));}
        }else r=withdraw(e,s,req,status);
        if(*status<400)json_object_object_add(s,"bisect",x);else json_object_put(x);json_object_put(req);
    }else return error(status,405,"method_not_allowed","不支持此操作");
    if(*status<400){number(s,"revision",num(s,"revision")+1);if(save_session(db,s)||report_conclusions(db,s,e)){json_object_put(r);return error(status,503,"session_persist_failed","设备规则操作已返回，分析记录保存失败；请使用同一请求标识重试并回读试验状态");}if(strcmp(suffix,"conclusions/commit")){json_object_put(r);r=public_session(s,1,str(s,"operator_id"),1);}else number(r,"session_revision",num(s,"revision"));}
    return r;
}
