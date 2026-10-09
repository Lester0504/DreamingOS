/* SPDX-License-Identifier: GPL-2.0-or-later
 * DreamingWrt RKLLM adapter. Build against Rockchip's matching SDK header.
 * SDK code/library are not copied from RoceOS and are not bundled here.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <dlfcn.h>
#include <rkllm.h>
#include "local_ipc.h"
static LLMHandle handle;
static int (*abort_run)(LLMHandle);
static int finished,failed;
static sigset_t signals;
static void *abort_thread(void *arg) { (void)arg;for(;;){int sig;if(!sigwait(&signals,&sig)&&handle)abort_run(handle);}return NULL; }
static int result(RKLLMResult *r,void *u,LLMCallState state) {
    (void)u;struct json_object *j=json_object_new_object();
    if(state==RKLLM_RUN_NORMAL&&r&&r->text){al_str(j,"event","delta");al_str(j,"delta",r->text);if(al_send(3,j))failed=1;}
    if(state==RKLLM_RUN_FINISH)finished=1;if(state==RKLLM_RUN_ERROR)failed=1;
    json_object_put(j);return 0;
}
#define LOAD(name) __typeof__(&name) p_##name=reinterpret_cast<__typeof__(&name)>(dlsym(lib,#name));if(!p_##name)return 3
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--version")){puts("rkllm-1.3.1");return 0;}
    if(argc!=5)return 2;
    pid_t parent=getppid();prctl(PR_SET_PDEATHSIG,SIGKILL);if(parent<=1||getppid()!=parent)return 2;
    sigemptyset(&signals);sigaddset(&signals,SIGUSR1);pthread_sigmask(SIG_BLOCK,&signals,NULL);signal(SIGPIPE,SIG_IGN);
    void *lib=dlopen("/usr/lib/librkllmrt.so",RTLD_NOW|RTLD_LOCAL);if(!lib)return 3;
    LOAD(rkllm_createDefaultParam);LOAD(rkllm_init);LOAD(rkllm_destroy);LOAD(rkllm_run);LOAD(rkllm_abort);LOAD(rkllm_clear_kv_cache);LOAD(rkllm_set_chat_template);
    abort_run=p_rkllm_abort;
    RKLLMParam p=p_rkllm_createDefaultParam();p.model_path=argv[1];p.max_context_len=atoi(argv[2]);p.max_new_tokens=atoi(argv[3]);p.is_async=false;p.extend_param.n_batch=1;
    RKLLMCallback cb={};cb.result_callback=result;
    if(p_rkllm_init(&handle,&p,&cb))return 4;
    /* The model catalog owns the chat template. Input is already rendered with
     * that template; do not let the engine wrap a second user/assistant turn. */
    if(p_rkllm_set_chat_template(handle,"","",""))return 4;
    pthread_t t;if(pthread_create(&t,NULL,abort_thread,NULL))return 4;
    struct json_object *ready=json_object_new_object();al_str(ready,"event","loaded");al_str(ready,"model_id",argv[4]);al_send(3,ready);json_object_put(ready);
    for(;;){struct json_object *j=al_recv(3,-1);if(!j)break;
        if(p_rkllm_clear_kv_cache(handle,0,NULL,NULL)){json_object_put(j);break;}
        RKLLMInput in={};in.role="user";in.input_type=RKLLM_INPUT_PROMPT;in.prompt_input=al_s(j,"prompt");in.enable_thinking=false;
        RKLLMInferParam ip={};ip.mode=RKLLM_INFER_GENERATE;ip.keep_history=0;ip.max_new_tokens=(int)al_i(j,"max_tokens");
        if(ip.max_new_tokens<1||ip.max_new_tokens>p.max_new_tokens)ip.max_new_tokens=p.max_new_tokens;
        finished=failed=0;int rc=p_rkllm_run(handle,&in,&ip,NULL);
        struct json_object *end=json_object_new_object();al_str(end,"event",rc||failed||!finished?"failed":"completed");al_str(end,"reason",rc||failed||!finished?"inference_failed":"");json_object_object_add(end,"usage",NULL);al_send(3,end);json_object_put(end);json_object_put(j);
    }
    /* No handle is visible to the signal thread after it has been joined. */
    pthread_cancel(t);pthread_join(t,NULL);p_rkllm_destroy(handle);dlclose(lib);return 0;
}
