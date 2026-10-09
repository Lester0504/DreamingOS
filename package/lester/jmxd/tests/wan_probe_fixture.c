// SPDX-License-Identifier: GPL-2.0-or-later
#include "healthd/wan_probe.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc,char **argv)
{
    struct wan_probe_request request={.ifname="lo",.timeout_ms=1500};
    struct wan_probe_result result;
    int expected_status=503;
    int rc;
    setvbuf(stdout,NULL,_IONBF,0);
    assert(argc==4);
    request.method=argv[1];request.target=argv[2];
    if(!strcmp(argv[3],"body"))request.body_marker="expected-marker";
    if(!strcmp(argv[3],"body-mismatch"))request.body_marker="missing-marker";
    if(!strcmp(argv[3],"expect-503")) {
        request.expected_status=&expected_status;
        request.expected_status_count=1;
    }
    if(!strcmp(argv[3],"device"))request.ifname="nonexistent";
    if(!strcmp(argv[3],"success") || !strcmp(argv[3],"body") ||
       !strcmp(argv[3],"expect-503"))assert(!wan_probe_validate(&request));
    rc=wan_probe_run(&request,&result);
    printf("ok=%d valid=%d class=%s source=%s family=%d status=%d\n",result.ok,
        result.valid,result.error_class,result.source_ifname,result.address_family,result.http_status);
    if(!strcmp(argv[3],"success") || !strcmp(argv[3],"body") ||
       !strcmp(argv[3],"expect-503")) {
        assert(!rc && result.ok && result.valid && result.address_family==4);
        assert(!strcmp(result.source_ifname,"lo"));
    } else {
        assert(rc && !result.ok);
        if(!strcmp(argv[3],"device"))assert(!result.valid);
        else if(!strcmp(argv[3],"invalid"))assert(!result.valid);
        else assert(result.valid);
    }
    return 0;
}
