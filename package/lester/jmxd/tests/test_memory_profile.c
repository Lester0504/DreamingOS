/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../src/system/memory_profile.c"

static struct dw_memory_profile fixture;
static void fixture_load(struct dw_memory_profile *p) { *p = fixture; }
#define dw_mp_load fixture_load
#include "../src/dw_read_model.c"
#undef dw_mp_load

static void test_selection(void)
{
    struct dw_memory_profile p;
    assert(dw_mp_select("invalid", "", 0, &p) == -1);
    assert(dw_mp_select("auto", "", 384 * DW_MP_MIB, &p) == 0 && p.compact && p.supported);
    assert(dw_mp_select("auto", "", 2048 * DW_MP_MIB, &p) == 0 && !p.compact && p.supported);
    assert(dw_mp_select("auto", "", 1024 * DW_MP_MIB, &p) == 0 && !p.supported);
    assert(dw_mp_select("auto", "AX1800Pro", 600 * DW_MP_MIB, &p) == 0 && p.compact);
    assert(dw_mp_select("standard", "AX1800Pro", 384 * DW_MP_MIB, &p) == 0 && !p.compact);
}
static void test_admission(const char *directory)
{
    int lease = -1, second = -1; const char *reason;
    assert(dw_mp_reserve(directory, 160 * DW_MP_MIB, 1, 64 * DW_MP_MIB, 0, &lease, &reason) == -1);
    assert(!strcmp(reason, "resource_peak_unknown"));
    assert(dw_mp_reserve(directory, 160 * DW_MP_MIB, 1, 64 * DW_MP_MIB, 1, &lease, &reason) == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        close(lease); /* child must not keep parent's lease alive */
        int rc = dw_mp_reserve(directory, 160 * DW_MP_MIB, 1, 64 * DW_MP_MIB, 1, &second, &reason);
        _exit(rc == -1 && !strcmp(reason, "insufficient_memory") ? 0 : 1);
    }
    int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    dw_mp_release(&lease);
    assert(dw_mp_reserve(directory, 160 * DW_MP_MIB, 1, 64 * DW_MP_MIB, 1, &second, &reason) == 0);
    dw_mp_release(&second);
    assert(dw_mp_reserve(directory, 64 * DW_MP_MIB, 1, 1, 1, &lease, &reason) == -1);
    assert(dw_mp_reserve(directory, 0, 0, 0, 1, &lease, &reason) == -1);
}
static int collect(void *ctx, struct dw_rm_collect_result *r) { (void)ctx; (void)r; return 0; }
static void release_gen(void *ctx, void *g) { (void)ctx; free(g); }
static int diff(void *ctx, const void *a, const void *b, void **out, size_t *bytes)
{ (void)ctx; (void)a; (void)b; *out = NULL; *bytes = 0; return 0; }
static void test_policy_keeps_current_table(void)
{
    struct dw_rm_config c = { .name="test", .contract="test.v1", .period_ms=750, .ring_slots=64,
        .ring_bytes_max=128 * DW_MP_MIB, .memory_profile=1,
        .ops={ .collect=collect, .free_generation=release_gen, .diff=diff, .free_delta=release_gen } };
    struct dw_rm_resource *r = NULL;
    assert(dw_rm_create(&c, &r) == 0);
    r->generation = malloc(16000); r->revision = 80; void *full = r->generation;
    for (int i=0; i<64; i++) {
        r->ring[i].revision = 17+i; r->ring[i].bytes = 64*1024;
    }
    r->ring_count=64; r->ring_bytes=4*DW_MP_MIB;
    dw_mp_select("compact", "", 512*DW_MP_MIB, &fixture); fixture.revision=2;
    dw_rm_memory_policy(r);
    assert(r->ring_count==16 && r->ring_bytes_max==4*DW_MP_MIB && r->period_ms==5000);
    assert(r->generation==full && r->revision==80);
    struct dw_rm_view view;
    assert(dw_rm_resume_begin(r,r->snapshot_id,20,&view)==DW_RM_RESUME_REVISION_TOO_OLD); dw_rm_view_end(&view);
    dw_rm_memory_policy(r); assert(r->period_ms==2000);
    dw_mp_select("standard", "", 512*DW_MP_MIB, &fixture);
    dw_rm_memory_policy(r); assert(r->period_ms==750 && r->ring_slot_limit==64 && r->generation==full);
    dw_rm_destroy(r);
}
int main(int argc,char **argv)
{
    assert(argc==2); test_selection(); test_admission(argv[1]); test_policy_keeps_current_table();
    puts("memory profile selection, atomic admission, crash lease recovery, ring transition: PASS");
    return 0;
}
