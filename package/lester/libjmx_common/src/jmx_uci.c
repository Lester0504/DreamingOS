// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uci.h>
#include "jmx_uci.h"

static int jmx_uci_copy_key(char *dst, size_t dst_len, const char *key)
{
    int ret;

    if (!dst || !dst_len || !key)
        return -1;

    ret = snprintf(dst, dst_len, "%s", key);
    if (ret < 0 || ret >= (int)dst_len) {
        printf("uci key too long\n");
        return -1;
    }

    return 0;
}

static int jmx_uci_format_key_value(char *dst, size_t dst_len, const char *key, const char *value)
{
    int ret;

    if (!dst || !dst_len || !key || !value)
        return -1;

    ret = snprintf(dst, dst_len, "%s=%s", key, value);
    if (ret < 0 || ret >= (int)dst_len) {
        printf("uci key/value too long\n");
        return -1;
    }

    return 0;
}

static int jmx_uci_format_key_int(char *dst, size_t dst_len, const char *key, int value)
{
    int ret;

    if (!dst || !dst_len || !key)
        return -1;

    ret = snprintf(dst, dst_len, "%s=%d", key, value);
    if (ret < 0 || ret >= (int)dst_len) {
        printf("uci key/value too long\n");
        return -1;
    }

    return 0;
}


int jmx_uci_get_int_value(struct uci_context *ctx, const char *key)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = -1;
    char param_tmp[128] = {0};
    if (!ctx)
        return ret;
    if (jmx_uci_copy_key(param_tmp, sizeof(param_tmp), key) != 0)
        return ret;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        return ret;
    }
    
    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        ctx->err = UCI_ERR_NOTFOUND;
        goto done;
    }
    
    e = ptr.last;
    switch(e->type) {
        case UCI_TYPE_SECTION:
            ret = -1;
			goto done;
        case UCI_TYPE_OPTION:
            ret = atoi(ptr.o->v.string);
			goto done;
        default:
            break;
    }
done:
	
	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int jmx_uci_get_value(struct uci_context *ctx, const char *key, char *output, int out_len)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char param_tmp[128] = {0};
    if (!ctx || !output || out_len <= 0)
        return 1;
    if (jmx_uci_copy_key(param_tmp, sizeof(param_tmp), key) != 0)
        return 1;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    
    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        ctx->err = UCI_ERR_NOTFOUND;
        ret = 1;
        goto done;
    }
    
    e = ptr.last;
    switch(e->type) {
        case UCI_TYPE_SECTION:
            ret = snprintf(output, out_len, "%s", ptr.s->type);
            if (ret < 0 || ret >= out_len)
                ret = 1;
            else
                ret = 0;
            break;
        case UCI_TYPE_OPTION:
			ret = snprintf(output, out_len, "%s", ptr.o->v.string);
			if (ret < 0 || ret >= out_len)
				ret = 1;
			else
				ret = 0;
			break;
        default:
			ret = 1;
            break;
    }
done:    
	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int jmx_uci_delete(struct uci_context *ctx, const char *key)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char param_tmp[128] = {0};    
    if (!ctx)
        return 1;
    if (jmx_uci_copy_key(param_tmp, sizeof(param_tmp), key) != 0)
        return 1;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_delete(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}



int jmx_uci_add_list(struct uci_context *ctx, const char *key, const char *value)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char param_tmp[MAX_PARAM_LIST_LEN] = {0};    
    if (!ctx)
        return 1;
    if (jmx_uci_format_key_value(param_tmp, sizeof(param_tmp), key, value) != 0)
        return -1;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_add_list(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int jmx_uci_get_list_value(struct uci_context *ctx, const char *key, char *output, int out_len, const char *delimt)
{
    struct uci_element *e;
    struct uci_ptr ptr;
    int ret = -1;
    char param_tmp[128] = {0};
    if (!ctx || !output || out_len <= 0)
        return ret;
    if (jmx_uci_copy_key(param_tmp, sizeof(param_tmp), key) != 0)
        return ret;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        return ret;
    }
    
    if (!(ptr.flags & UCI_LOOKUP_COMPLETE)) {
        ctx->err = UCI_ERR_NOTFOUND;
        goto done;
    }
    int sep = 0;
    e = ptr.last;
	int len = 0;
    switch(e->type) {
        case UCI_TYPE_SECTION:
            ret = -1;
			goto done;
        case UCI_TYPE_OPTION:
			if (UCI_TYPE_LIST == ptr.o->type){
				memset(output, 0x0, out_len);
				uci_foreach_element(&ptr.o->v.list, e) {
                    int written;
					len = strlen(output);
					if (sep){
                        written = snprintf(output + len, out_len - len, "%s", delimt ? delimt : "");
                        if (written < 0 || written >= out_len - len) {
                            ret = -1;
                            goto done;
                        }
					}
					len = strlen(output);
                    written = snprintf(output + len, out_len - len, "%s", e->name);
                    if (written < 0 || written >= out_len - len) {
                        ret = -1;
                        goto done;
                    }
					sep = 1;
				}
				ret = 0;
			}
			goto done;
        default:
            break;
    }
done:	
	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int jmx_uci_add_int_list(struct uci_context *ctx, const char *key, int value)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char param_tmp[128] = {0};    
    if (!ctx)
        return 1;
    if (jmx_uci_format_key_int(param_tmp, sizeof(param_tmp), key, value) != 0)
        return 1;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_add_list(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}

int jmx_uci_del_list(struct uci_context *ctx, const char *key, const char *value)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char param_tmp[128] = {0};    
    if (!ctx)
        return 1;
    if (jmx_uci_format_key_value(param_tmp, sizeof(param_tmp), key, value) != 0)
        return 1;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_del_list(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}


int jmx_uci_set_value(struct uci_context *ctx, const char *key, const char *value)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char param_tmp[2048] = {0};    
    if (!ctx)
        return 1;
    if (jmx_uci_format_key_value(param_tmp, sizeof(param_tmp), key, value) != 0)
        return 1;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    
    ret = uci_set(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

	if (ptr.p)
		uci_unload(ctx, ptr.p);
    return ret;
}

int jmx_uci_set_int_value(struct uci_context *ctx, const char *key, int value)
{
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char param_tmp[128] = {0};    
    if (!ctx)
        return 1;
    if (jmx_uci_format_key_int(param_tmp, sizeof(param_tmp), key, value) != 0)
        return 1;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        ret = 1;
        return ret;
    }
    ret = uci_set(ctx, &ptr);
    if (ret == UCI_OK)
       ret = uci_save(ctx, ptr.p);

    if (ptr.p)
        uci_unload(ctx, ptr.p);
    return ret;
}

int jmx_uci_del_array_value(struct uci_context *ctx, const char *key_fmt, int index){
    int ret;
    char key[128] = {0};
    ret = key_fmt ? snprintf(key, sizeof(key), key_fmt, index) : -1;
    if (ret < 0 || ret >= (int)sizeof(key))
        return 1;
    return jmx_uci_delete(ctx, key);
}

int jmx_uci_set_array_value(struct uci_context *ctx, const char *key_fmt, int index, const char *value){
    int ret;
    char key[128] = {0};
    ret = key_fmt ? snprintf(key, sizeof(key), key_fmt, index) : -1;
    if (ret < 0 || ret >= (int)sizeof(key))
        return 1;
    return jmx_uci_set_value(ctx, key, value);
}

int jmx_uci_commit(struct uci_context *ctx, const char * package) {
    struct uci_ptr ptr;
    int ret = UCI_OK;
    char param_tmp[128] = {0};
    if (!ctx || !package){
        return -1;
    }
    if (jmx_uci_copy_key(param_tmp, sizeof(param_tmp), package) != 0)
        return -1;
    if (uci_lookup_ptr(ctx, &ptr, param_tmp, true) != UCI_OK) {
        return -1;
    }   

    if (uci_commit(ctx, &ptr.p, false) != UCI_OK) {
    	ret = -1;
        goto done;
    }
done:
	if (ptr.p)
		uci_unload(ctx, ptr.p);

    return ret;
}

int jmx_uci_get_list_num(struct uci_context * ctx, const char *package, const char *section){
    int count = 0;
    struct uci_element *e; 
    struct uci_package *pkg = NULL;

    if (!ctx || !package || !section)
        return -1;

    if (UCI_OK != uci_load(ctx, package, &pkg)){
        return -1; 
    }   
    uci_foreach_element(&pkg->sections, e){ 
        struct uci_section *s = uci_to_section(e);
        if (strcmp(s->type, section)){
            continue;
        }
        count++;
    }   
    uci_unload(ctx, pkg);
    return count;
}
int jmx_uci_get_array_value(struct uci_context *ctx, const char *key_fmt, int index, char *output, int out_len)
{
    int ret;
    char key[128] = {0};
    ret = key_fmt ? snprintf(key, sizeof(key), key_fmt, index) : -1;
    if (ret < 0 || ret >= (int)sizeof(key))
        return 1;
    return jmx_uci_get_value(ctx, key, output, out_len);
}

int jmx_uci_add_section(struct uci_context * ctx, const char *package_name, const char *section)
{
    struct uci_section *s = NULL;
    struct uci_package *p = NULL;
    int ret;
    if (!ctx || !package_name || !section)
        return -1;
    ret = uci_load(ctx, package_name , &p);
    if (ret != UCI_OK)
        goto done;

    ret = uci_add_section(ctx, p, section, &s);
    if (ret != UCI_OK)
        goto done;
    ret = uci_save(ctx, p); 
done:
    if (s) 
        fprintf(stdout, "%s\n", s->e.name);
    return ret;
}
