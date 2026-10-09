/* SPDX-License-Identifier: GPL-2.0-or-later */
static struct json_object *ai_local_chat(int fd,struct json_object *body,const char *actor,int *http_status)
{
    struct ai_config cfg={0};struct ai_stream_state stream={.fd=fd,.execution_backend="local"};
    struct json_object *status_req=json_object_new_object(),*status_reply,*local,*md,*messages=NULL,*reply=NULL,*error=NULL;
    int code=503,sock=-1,slot=-1,terminal=0,cancel_sent=0,stream_started=0;size_t bytes=0;char validation[256]={0};
    al_str(status_req,"op","status");status_reply=ai_local_call(status_req,&code);json_object_put(status_req);local=json_object_object_get(status_reply,"data");md=local?json_object_object_get(local,"model"):NULL;
    if(!local||!al_i(local,"ready")){error=ai_error("local_not_ready",local?al_s(local,"reason"):"local_manager_unavailable",409,0,NULL,NULL);code=409;goto done;}
    const char *selected=ai_json_string(body,"local_model_id",al_s(md,"loaded_id"));
    if(!selected[0]||strcmp(selected,al_s(md,"loaded_id"))){error=ai_error("local_model_changed","The loaded local model changed",409,0,NULL,NULL);code=409;goto done;}
    snprintf(cfg.provider,sizeof(cfg.provider),"rkllm");snprintf(cfg.model,sizeof(cfg.model),"%s",selected);cfg.enabled=1;cfg.max_tokens=512;snprintf(cfg.tool_policy,sizeof(cfg.tool_policy),"disabled");
    snprintf(stream.conversation_id,sizeof(stream.conversation_id),"%s",ai_json_string(body,"conversation_id",""));if(!ai_value_ok(stream.conversation_id,sizeof(stream.conversation_id)-1))snprintf(stream.conversation_id,sizeof(stream.conversation_id),"ai-%lld-%ld",(long long)ai_now_ms(),(long)getpid());
    snprintf(stream.response_id,sizeof(stream.response_id),"resp-local-%lld-%ld",(long long)ai_now_ms(),(long)getpid());
    if(ai_rate_limited(actor,"ai.chat")||(slot=ai_acquire_slot())<0){error=ai_error("ai_busy","AI concurrency limit reached",429,0,NULL,NULL);code=429;goto done;}
    if(ai_prepare_messages(&cfg,body,actor,&messages,&bytes,validation,sizeof(validation))){error=ai_error("invalid_request",validation,400,0,NULL,NULL);code=400;goto done;}
    if(bytes>128*1024){error=ai_error("context_too_large","Local context exceeds 128 KiB",413,0,NULL,NULL);code=413;goto done;}
    error=ai_history_begin(&cfg,body,stream.conversation_id,actor,&code);if(error)goto done;
    if(ai_response_register(&stream,actor)){error=ai_error("stream_state_unavailable","Cannot register response",503,0,NULL,NULL);code=503;goto done;}
    sock=al_connect();if(sock<0){error=ai_error("local_manager_unavailable","Local manager unavailable",503,0,NULL,NULL);goto done;}
    struct json_object *q=json_object_new_object();al_str(q,"op","generate");al_str(q,"tool_policy","disabled");al_str(q,"actor",actor);al_str(q,"response_id",stream.response_id);al_str(q,"model_id",cfg.model);al_num(q,"max_tokens",al_i(body,"max_tokens"));json_object_object_add(q,"messages",json_object_get(messages));int sent=al_send(sock,q);json_object_put(q);
    if(sent){error=ai_error("inference_unavailable","Cannot submit local generation",503,0,NULL,NULL);goto done;}
    reply=json_object_new_object();al_str(reply,"execution_backend","local");al_str(reply,"provider","rkllm");al_str(reply,"model",cfg.model);al_str(reply,"response_id",stream.response_id);al_str(reply,"conversation_id",stream.conversation_id);json_object_object_add(reply,"usage",NULL);json_object_object_add(reply,"history_revision",json_object_get(json_object_object_get(body,"revision")));
    time_t deadline=time(NULL)+620;
    while(!terminal&&time(NULL)<deadline){
        if(ai_stream_progress(&stream,0,0,0,0)&&!cancel_sent){struct json_object *cancel=json_object_new_object();al_str(cancel,"op","cancel");al_str(cancel,"actor",actor);al_str(cancel,"response_id",stream.response_id);int cs=0;struct json_object *ack=ai_local_call(cancel,&cs);json_object_put(ack);json_object_put(cancel);cancel_sent=1;}
        struct pollfd p={sock,POLLIN,0};int rc=poll(&p,1,250);if(rc<0&&errno==EINTR)continue;if(rc<0)break;if(!rc)continue;
        struct json_object *ev=al_recv(sock,5000);if(!ev)break;const char *event=al_s(ev,"event");
        if (!strcmp(event,"tool_call") || !strcmp(event,"tool_calls") ||
            !strcmp(event,"requires_action") || !strcmp(event,"function_call") ||
            json_object_object_get(ev,"tool_calls") || json_object_object_get(ev,"function_call")) {
            error=ai_error("tools_disabled","Local text generation cannot call device tools",422,0,NULL,NULL);
            code=422;terminal=1;
            struct json_object *cancel=json_object_new_object();al_str(cancel,"op","cancel");al_str(cancel,"actor",actor);al_str(cancel,"response_id",stream.response_id);int cs=0;struct json_object *ack=ai_local_call(cancel,&cs);json_object_put(ack);json_object_put(cancel);
        }
        else if(!strcmp(event,"started")){if(fd>=0){if(http_send_sse_header(fd)){stream.disconnected=1;}else{stream_started=1;ai_stream_emit(&stream,"response.started",reply);}}}
        else if(!strcmp(event,"delta")){const char *delta=al_s(ev,"delta");size_t n=strlen(delta);if(stream.reply_len+n>AI_MAX_RESPONSE_BYTES){json_object_put(ev);break;}char *b=realloc(stream.reply,stream.reply_len+n+1);if(!b){json_object_put(ev);break;}stream.reply=b;memcpy(b+stream.reply_len,delta,n+1);stream.reply_len+=n;if(stream_started)ai_stream_emit(&stream,"response.delta",ev);}
        else if(!strcmp(event,"completed")||!strcmp(event,"failed")){terminal=1;if(!strcmp(event,"failed")&&!stream.cancelled){code=503;error=ai_error("inference_failed",al_s(ev,"reason"),503,0,NULL,NULL);}}
        else if(json_object_object_get(ev,"error")){error=json_object_get(ev);code=al_i(ev,"status")?(int)al_i(ev,"status"):503;terminal=1;}
        json_object_put(ev);
    }
    if(!terminal&&!error){code=503;error=ai_error("inference_interrupted","Local inference ended without a terminal event",503,0,NULL,NULL);}
    al_str(reply,"reply",stream.reply?stream.reply:"");al_str(reply,"status",stream.cancelled&&terminal?"cancelled":error?"interrupted":"completed");al_bool(reply,"cancelled",stream.cancelled&&terminal);
    int saved=ai_history_save_chat(&cfg,actor,stream.conversation_id,ai_json_string(body,"title",AI_CONVERSATION_TITLE_FALLBACK),body,NULL,reply);al_bool(reply,"history_saved",saved==0);if(saved==-2)al_str(reply,"history_error","conversation_conflict");
    if(stream_started){if(error){json_object_object_add(reply,"error",json_object_get(json_object_object_get(error,"error")));ai_stream_emit(&stream,"response.failed",reply);}else ai_stream_emit(&stream,stream.cancelled?"response.cancelled":"response.completed",reply);}
    if(!error)code=200;
 done:
    if(sock>=0)close(sock);if(slot>=0)close(slot);ai_response_unregister(&stream);if(messages)json_object_put(messages);if(status_reply)json_object_put(status_reply);free(stream.reply);
    if(http_status)*http_status=code;
    if(fd>=0){if(error&&!stream_started)ai_stream_send_error(fd,json_object_get(error),code);if(reply)json_object_put(reply);if(error)json_object_put(error);return NULL;}
    if(error){if(reply){json_object_object_add(error,"data",reply);}return error;}return ai_success(reply,"webd.ai.local");
}
