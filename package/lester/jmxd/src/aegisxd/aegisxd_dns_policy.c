/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "aegisxd_internal.h"
#include "../dns_policy/ad_dns_control.h"
#include <fcntl.h>
#include <pwd.h>
#define AD_DNS_DIR "/var/run/dreamingwrt/ad-dns"
static struct uloop_timeout ad_dns_timer;
static int initialized;
static struct ad_dns_environment environment(void) {
    return (struct ad_dns_environment){g_aegisxd_config_db,AD_DNS_DIR,"/tmp/dhcp.leases",aegisxd_now_s(),53,aegisxd_content_dns_conflicts};
}
static void tick(struct uloop_timeout *timer) {
    struct ad_dns_environment e=environment();
    if(initialized)ad_dns_reconcile(&e,0);
    uloop_timeout_set(timer,5000);
}
void aegisxd_ad_dns_start(void) {
    struct ad_dns_environment e=environment();
    if(aegisxd_mkdir_p(AD_DNS_DIR,0755))return;
    int fd=open(AD_DNS_DIR "/queries.log",O_CREAT|O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW,0640);
    if(fd<0)return;
    struct passwd *pw=getpwnam("dnsmasq");
    if(fchown(fd,pw?pw->pw_uid:453,0)||fchmod(fd,0640)){close(fd);return;}close(fd);
    initialized=ad_dns_init(&e)==0;
    if(initialized)ad_dns_reconcile(&e,1);
    ad_dns_timer.cb=tick;uloop_timeout_set(&ad_dns_timer,5000);
}
void aegisxd_ad_dns_stop(void) {
    uloop_timeout_cancel(&ad_dns_timer);struct ad_dns_environment e=environment();if(initialized)ad_dns_reconcile(&e,1);
}
struct json_object *aegisxd_ad_dns_json(struct json_object *body) {
    if(!initialized)return aegisxd_error("native_dns_provider_not_ready","原生 DNS 设备规则服务未就绪");
    struct ad_dns_environment e=environment();
    return ad_dns_handle(&e,aegisxd_json_str(body,"operation","capabilities"),body);
}

struct json_object *aegisxd_ad_dns_canonical(struct json_object *body,int deleting) {
    if(!initialized)return aegisxd_error("native_dns_provider_not_ready","原生 DNS 设备规则服务未就绪");
    struct ad_dns_environment e=environment();return ad_dns_canonical(&e,body,deleting);
}
