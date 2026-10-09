/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include "../src/dw_read_model.c"
static int fail_mapping, fail_remapping, mapping_countdown;
static void *test_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    if (fail_mapping || (mapping_countdown > 0 && --mapping_countdown == 0))
        { errno=ENOMEM; return MAP_FAILED; }
    return mmap(addr,length,prot,flags,fd,offset);
}
static void *test_mremap(void *addr, size_t old_size, size_t new_size, int flags)
{
    if (fail_remapping) { errno=ENOMEM; return MAP_FAILED; }
    return mremap(addr,old_size,new_size,flags);
}
static const char *fixture_path;
static FILE *fixture_fopen(const char *path, const char *mode)
{
    if (!strcmp(path,"/proc/net/nf_conntrack")) return fopen(fixture_path,mode);
    if (!strncmp(path,"/proc/",6)) return NULL;
    return fopen(path,mode);
}
#define fopen fixture_fopen
#define mmap test_mmap
#define mremap test_mremap
#include "../src/client_connections_snapshot.c"
#undef fopen
#undef mmap
#undef mremap
char *get_app_name_by_id(int id) { (void)id; return ""; }
static struct dw_cc_generation *collect(size_t count)
{
    FILE *fp=fopen(fixture_path,"w");assert(fp);
    for(size_t i=0;i<count;++i)
        fprintf(fp,"ipv4 2 tcp 6 60 ESTABLISHED src=192.168.1.2 dst=8.8.8.8 sport=%zu dport=443 packets=2 bytes=120 src=8.8.8.8 dst=192.168.1.2 sport=443 dport=%zu packets=2 bytes=120 mark=0 use=1\n",i+1024,i+1024);
    fclose(fp);
    struct dw_rm_collect_result result={0};
    assert(dw_cc_collect(NULL,&result)==0);
    struct dw_cc_generation *g=result.generation;
    assert(g && g->row_count==count && g->row_capacity>=count && result.complete);
    return g;
}

static void publish(struct dw_cc_generation *g)
{
    struct dw_rm_collect_result result={.generation=g,.complete=1,.scanned_rows=g->row_count};
    dw_rm_publish(g_dw_cc_resource,&result,0);
}

static void expect_delta(const struct dw_cc_client_filter *filter, uint64_t revision,
                         size_t upserts, size_t removed)
{
    int rc=0;
    struct json_object *j=dw_cc_delta_json(filter,g_dw_cc_resource->snapshot_id,revision,&rc);
    assert(j && rc==0);
    assert(json_object_array_length(json_object_object_get(j,"upserts"))==upserts);
    assert(json_object_array_length(json_object_object_get(j,"removed"))==removed);
    json_object_put(j);
}

static void test_membership_and_ring(void)
{
    struct dw_rm_config config={.name="client_connections",.contract="client-connections.v2",
        .ring_slots=64,.ring_bytes_max=128U*1024*1024,
        .ops={.collect=dw_cc_collect,.free_generation=dw_cc_generation_free,
              .diff=dw_cc_diff,.free_delta=dw_cc_delta_free}};
    assert(dw_rm_create(&config,&g_dw_cc_resource)==0);
    struct dw_cc_generation *a=collect(5);
    strcpy(a->rows[0].dpi_mac,"AA:BB:CC:DD:EE:01");
    strcpy(a->rows[1].original_src,"2001:db8::1");
    strcpy(a->rows[2].original_dst,"2001:db8::2");
    strcpy(a->rows[3].reply_src,"2001:db8::3");
    strcpy(a->rows[4].reply_dst,"2001:db8::4");
    publish(a);
    struct dw_cc_generation *b=collect(5);
    strcpy(b->rows[0].dpi_mac,"AA:BB:CC:DD:EE:02");
    publish(b);
    struct dw_cc_client_filter filter;
    dw_cc_filter_init(&filter,"aa:bb:cc:dd:ee:01");expect_delta(&filter,1,0,1);
    dw_cc_filter_init(&filter,"aa:bb:cc:dd:ee:02");expect_delta(&filter,1,1,0);
    for(int i=1;i<=4;i++) {
        char address[64];snprintf(address,sizeof(address),"2001:0db8:0:0:0:0:0:%d",i);
        dw_cc_filter_init(&filter,NULL);
        assert(dw_cc_filter_add_address(&filter,address)==0);
        expect_delta(&filter,1,0,1);
    }
    publish(collect(0));
    dw_cc_filter_init(&filter,"aa:bb:cc:dd:ee:02");expect_delta(&filter,2,0,1);
    struct dw_cc_generation *c=collect(5);strcpy(c->rows[0].dpi_mac,"AA:BB:CC:DD:EE:02");
    publish(c);expect_delta(&filter,1,1,0); /* removed, then re-added */
    for(int i=0;i<68;i++)publish(collect(5));
    assert(g_dw_cc_resource->ring_count==64);
    struct dw_rm_view view;
    assert(dw_rm_resume_begin(g_dw_cc_resource,g_dw_cc_resource->snapshot_id,1,&view)==DW_RM_RESUME_REVISION_TOO_OLD);
    dw_rm_view_end(&view);
    assert(dw_rm_resume_begin(g_dw_cc_resource,"different",1,&view)==DW_RM_RESUME_SNAPSHOT_CHANGED);
    dw_rm_view_end(&view);
    dw_cc_snapshot_stop();
}

static void test_row_buffer_reuse_and_shrink(void)
{
    struct dw_rm_config config={.name="client_connections",.contract="client-connections.v2",
        .ring_slots=64,.ring_bytes_max=128U*1024*1024,
        .ops={.collect=dw_cc_collect,.free_generation=dw_cc_generation_free,
              .diff=dw_cc_diff,.free_delta=dw_cc_delta_free}};
    assert(dw_rm_create(&config,&g_dw_cc_resource)==0);
    publish(collect(5000));publish(collect(5000));
    struct dw_cc_row *spare=g_dw_cc_spare_rows; assert(spare);
    struct dw_cc_generation *g=collect(5000);
    assert(g->rows==spare && !g_dw_cc_spare_rows);publish(g);
    publish(collect(100));publish(collect(100));
    assert(!g_dw_cc_spare_rows && !g_dw_cc_spare_row_bytes);
    assert(((struct dw_cc_generation*)g_dw_cc_resource->generation)->row_capacity==128);
    dw_cc_snapshot_stop();assert(!g_dw_cc_mapped_bytes);
}

static void test_sparse_previous_memberships(void)
{
    struct dw_cc_generation *a=collect(1200), *b=collect(1200);
    struct dw_cc_delta *delta=NULL;
    size_t bytes=0;
    for(size_t i=0;i<b->row_count;i++) b->rows[i].original_bytes++;
    assert(dw_cc_diff(NULL,a,b,(void **)&delta,&bytes)==0);
    assert(delta->upsert_count==1200 && !delta->previous_membership_count);
    assert(!delta->previous_memberships);
    for(size_t i=0;i<delta->upsert_count;i++)
        assert(delta->upserts[i].has_previous && !delta->upserts[i].previous);
    dw_cc_delta_free(NULL,delta); delta=NULL;
    for(size_t i=0;i<b->row_count;i++) strcpy(b->rows[i].dpi_mac,"AA:BB:CC:DD:EE:01");
    uint64_t live_before=g_dw_cc_mapped_bytes;
    mapping_countdown=2; /* upserts succeeds; previous-membership mmap fails */
    assert(dw_cc_diff(NULL,a,b,(void **)&delta,&bytes)==-1 && !delta);
    assert(g_dw_cc_mapped_bytes==live_before);
    mapping_countdown=0;
    assert(dw_cc_diff(NULL,a,b,(void **)&delta,&bytes)==0);
    assert(delta->previous_membership_count==1200);
    for(size_t i=0;i<delta->upsert_count;i++) {
        assert(delta->upserts[i].previous && !delta->upserts[i].previous->dpi_mac[0]);
        assert(!strcmp(delta->upserts[i].current.dpi_mac,"AA:BB:CC:DD:EE:01"));
    }
    dw_cc_delta_free(NULL,delta);
    dw_cc_generation_free(NULL,a); dw_cc_generation_free(NULL,b);
}

static void test_mapping_failure_cleanup(void)
{
    struct dw_rm_collect_result result={0};
    struct dw_cc_generation *g=collect(5000);dw_cc_generation_free(NULL,g);
    fail_mapping=1;
    assert(dw_cc_collect(NULL,&result)==-1 && !result.generation);
    fail_mapping=0;
    g=collect(1);dw_cc_generation_free(NULL,g); /* reset starting capacity */
    g=collect(5000);dw_cc_generation_free(NULL,g);
    g=collect(1);dw_cc_generation_free(NULL,g);
    /* The file now has 1 row; write a large fixture without a successful collect. */
    FILE *fp=fopen(fixture_path,"w");assert(fp);
    for(int i=0;i<5000;i++)fprintf(fp,"ipv4 2 tcp 6 60 ESTABLISHED src=192.168.1.2 dst=8.8.8.8 sport=%d dport=443 packets=2 bytes=120 src=8.8.8.8 dst=192.168.1.2 sport=443 dport=%d packets=2 bytes=120 mark=0 use=1\n",i+1024,i+1024);
    fclose(fp);
    fail_remapping=1;
    assert(dw_cc_collect(NULL,&result)==-1 && !result.generation);
    fail_remapping=0;
    assert(g_dw_cc_mapped_bytes==0);
}
int main(int argc,char **argv)
{
    assert(argc==2);fixture_path=argv[1];
    struct dw_cc_generation *small=collect(1), *large=collect(5000), *back=collect(3), *settled=collect(3);
    assert(small->row_capacity==128 && large->row_capacity>=5000 && settled->row_capacity==128);
    void *delta=NULL;size_t bytes=0;
    assert(dw_cc_diff(NULL,large,back,&delta,&bytes)==0);
    assert(((struct dw_cc_delta *)delta)->removed_count==4997);
    assert(((struct dw_cc_delta *)delta)->upsert_count==0);
    dw_cc_delta_free(NULL,delta);
    printf("snapshot rows=5000 preserved; removals=4997; small allocated_rows=128; row_size=%zu PASS\n",sizeof(struct dw_cc_row));
    dw_cc_generation_free(NULL,small);dw_cc_generation_free(NULL,large);dw_cc_generation_free(NULL,back);dw_cc_generation_free(NULL,settled);
    test_membership_and_ring();
    test_sparse_previous_memberships();
    test_row_buffer_reuse_and_shrink();
    test_mapping_failure_cleanup();
    assert(g_dw_cc_mapped_bytes==0);
    printf("MAC/all four IPv6 memberships, delete/re-add, ring resync, mmap/mremap failure cleanup PASS\n");
    unlink(fixture_path);
}
