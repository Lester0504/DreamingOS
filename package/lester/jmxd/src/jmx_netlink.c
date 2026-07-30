
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <json-c/json.h>
#include "jmx_user.h"
#include "jmx_netlink.h"
#include "jmx.h"
#define MAX_NL_RCV_BUF_SIZE 4096

#define REPORT_INTERVAL_SECS 60


extern traffic_stat_t g_global_hourly_traffic[HOURS_PER_DAY];
extern u_int32_t g_global_traffic_date;

void jmx_netlink_handler(struct uloop_fd *u, unsigned int ev)
{
    int ret;
    int i;
    char buf[MAX_NL_RCV_BUF_SIZE];
    struct sockaddr_nl nladdr;
    struct iovec iov = {buf, sizeof(buf)};
    struct nlmsghdr *h;
    const char *mac = NULL;
    char *kdata;
    char json_buf[MAX_NL_RCV_BUF_SIZE];

    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    do
    {
        ret = recvmsg(u->fd, &msg, 0);
    } while ((-1 == ret) && (EINTR == errno));

    if (ret < 0)
    {
        printf("recv msg error\n");
        return;
    }
    else if (0 == ret)
    {
        return;
    }

    if (ret < (int)(sizeof(struct nlmsghdr) + sizeof(struct jmx_nl_msg_hdr)))
    {
        printf("netlink msg too short\n");
        return;
    }

    h = (struct nlmsghdr *)buf;
    if (!NLMSG_OK(h, (unsigned int)ret) ||
        h->nlmsg_len < NLMSG_LENGTH(sizeof(struct jmx_nl_msg_hdr)))
    {
        printf("netlink header error\n");
        return;
    }

    char *kmsg = (char *)NLMSG_DATA(h);
    struct jmx_nl_msg_hdr *af_hdr = (struct jmx_nl_msg_hdr *)kmsg;
    if (af_hdr->magic != 0xa0b0c0d0)
    {
        printf("magic error %x\n", af_hdr->magic);
        return;
    }

    if (af_hdr->len <= 0 || af_hdr->len >= MAX_JMX_NETLINK_MSG_LEN ||
        af_hdr->len >= (int)sizeof(json_buf) ||
        h->nlmsg_len < NLMSG_LENGTH(sizeof(struct jmx_nl_msg_hdr) + af_hdr->len))
    {
        printf("data len error\n");
        return;
    }

    kdata = kmsg + sizeof(struct jmx_nl_msg_hdr);
    memcpy(json_buf, kdata, af_hdr->len);
    json_buf[af_hdr->len] = '\0';
    struct json_object *root = json_tokener_parse(json_buf);
    if (!root)
    {
        LOG_ERROR("parse json failed:%s", json_buf);
        return;
    }

    struct json_object *mac_obj = json_object_object_get(root, "mac");

    if (!mac_obj)
    {
        printf("parse mac obj failed\n");
        json_object_put(root);
        return;
    }

    mac = json_object_get_string(mac_obj);

    client_node_t *node = find_client_node(mac);

    if (!node)
    {
        node = add_client_node(mac);
        if (!node)
        {
            printf("add dev node failed\n");
            json_object_put(root);
            return;
        }
    }

    struct json_object *ip_obj = json_object_object_get(root, "ip");
    if (ip_obj)
        strncpy(node->ip, json_object_get_string(ip_obj), sizeof(node->ip));
    
    struct json_object *ipv6_obj = json_object_object_get(root, "ipv6");
    if (ipv6_obj) {
        const char *ipv6_str = json_object_get_string(ipv6_obj);
        if (ipv6_str && strlen(ipv6_str) > 0) {
            strncpy(node->ipv6, ipv6_str, sizeof(node->ipv6) - 1);
            node->ipv6[sizeof(node->ipv6) - 1] = '\0';
            LOG_DEBUG("jmx_netlink: received ipv6=%s for %s\n", node->ipv6, mac);
        } else {
            node->ipv6[0] = '\0';
        }
    } else {
        node->ipv6[0] = '\0';
    }
    
    struct json_object *active_obj = json_object_object_get(root, "active");
    int prev_active = node->active;
    if (active_obj) {
        node->active = json_object_get_int(active_obj);
        LOG_DEBUG("jmx_netlink: received active=%d for %s\n", node->active, mac);
    }
    
    
    struct json_object *up_flow_obj = json_object_object_get(root, "up_flow");
    struct json_object *down_flow_obj = json_object_object_get(root, "down_flow");
    unsigned long long total_up_bytes = 0;
    unsigned long long total_down_bytes = 0;
    
    if (up_flow_obj) {
        
        total_up_bytes = (unsigned long long)json_object_get_int64(up_flow_obj) * 1024;
    }
    if (down_flow_obj) {
        
        total_down_bytes = (unsigned long long)json_object_get_int64(down_flow_obj) * 1024;
    }
    
    LOG_DEBUG("jmx_netlink: received flow data for %s: up_flow=%llu KB (%llu bytes), down_flow=%llu KB (%llu bytes)\n",
             mac, total_up_bytes / 1024, total_up_bytes, total_down_bytes / 1024, total_down_bytes);
    
    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);
    time_t cur_time_t = cur_time.tv_sec;
    u_int32_t today_start = get_today_start_timestamp();
    if ((u_int32_t)cur_time.tv_sec >= today_start && ((u_int32_t)cur_time.tv_sec - today_start) < 120) {
        json_object_put(root);
        return;
    }
    struct tm *tm_info = localtime(&cur_time_t);
    int hour = -1;
    if (tm_info) {
        hour = tm_info->tm_hour;
    }
    
    daily_hourly_stat_t *today_stat = NULL;
    if (hour >= 0 && hour < HOURS_PER_DAY) {
        today_stat = get_today_stat(node);
        
        if (node->online == 1) {
            if (today_stat) {
                today_stat->hourly_online_time[hour] += REPORT_INTERVAL_SECS;
                LOG_DEBUG("jmx_netlink: updated hourly_online_time[%d] for %s: +%d seconds\n",
                         hour, mac, REPORT_INTERVAL_SECS);
            }
        }
        
        if (node->active == 1) {
            if (today_stat) {
                today_stat->hourly_active_time[hour] += REPORT_INTERVAL_SECS;
                LOG_DEBUG("jmx_netlink: updated hourly_active_time[%d] for %s: +%d seconds\n",
                         hour, mac, REPORT_INTERVAL_SECS);
            }
        }
    }
    
    
    if (hour >= 0 && hour < HOURS_PER_DAY && (total_up_bytes > 0 || total_down_bytes > 0)) {
        if (today_stat) {
            
            today_stat->hourly_traffic[hour].up_bytes += total_up_bytes;
            today_stat->hourly_traffic[hour].down_bytes += total_down_bytes;
            LOG_DEBUG("jmx_netlink: updated hourly_traffic[%d] for %s: up_bytes=%llu, down_bytes=%llu\n",
                     hour, mac, today_stat->hourly_traffic[hour].up_bytes, today_stat->hourly_traffic[hour].down_bytes);
        }
        
        
        u_int32_t today = get_today_start_timestamp();
        if (g_global_traffic_date != today) {
            memset(g_global_hourly_traffic, 0, sizeof(g_global_hourly_traffic));
            g_global_traffic_date = today;
        }
        g_global_hourly_traffic[hour].up_bytes += total_up_bytes;
        g_global_hourly_traffic[hour].down_bytes += total_down_bytes;
    }
    
    struct json_object *visit_array = json_object_object_get(root, "visit_info");
    if (!visit_array)
    {
        
        json_object_put(root);
        return;
    }

    for (i = 0; i < json_object_array_length(visit_array); i++)
    {
        struct json_object *visit_obj = json_object_array_get_idx(visit_array, i);
        struct json_object *appid_obj = json_object_object_get(visit_obj, "appid");
        struct json_object *action_obj = json_object_object_get(visit_obj, "latest_action");
        
        int appid = json_object_get_int(appid_obj);
        int action = json_object_get_int(action_obj);
        int type;
        int id;

        type = appid / 1000;
        id = appid % 1000;
        if (id <= 0 || type <= 0)
            continue;
        
        
        visit_stat_t *stat_node = NULL;
        int found_stat = 0;
        list_for_each_entry(stat_node, &node->stat_list, list) {
            if (stat_node->appid == appid) {
                stat_node->total_time += REPORT_INTERVAL_SECS;
                found_stat = 1;
                break;
            }
        }
        
        
        if (!found_stat) {
            stat_node = (visit_stat_t *)calloc(1, sizeof(visit_stat_t));
            if (stat_node) {
                stat_node->appid = appid;
                stat_node->total_time = REPORT_INTERVAL_SECS;
                INIT_LIST_HEAD(&stat_node->list);
                list_add(&stat_node->list, &node->stat_list);
            }
        }
        
        
        update_global_app_type_stats(appid, REPORT_INTERVAL_SECS);



        visit_info_t *p = NULL;
        int found = 0;
        int cur_time_sec = cur_time.tv_sec;
        
        list_for_each_entry(p, &node->online_visit, visit) {
            if (p->appid == appid && p->action == action) {
                p->latest_time = cur_time_sec;
                found = 1;
                break;
            }
        }
        

        if (!found) {
            p = (visit_info_t *)calloc(1, sizeof(visit_info_t));
            if (!p)
                continue;
            p->appid = appid;
            p->first_time = cur_time_sec;
            p->latest_time = cur_time_sec;
            p->action = action;
            INIT_LIST_HEAD(&p->visit);

            add_visit_info_node(&node->online_visit, p);
			
        }
    }
    json_object_put(root);
}

#define MAX_NL_MSG_LEN 1024
int jmx_nl_send_msg_to_kernel(int fd, void *msg, int len)
{
    struct sockaddr_nl daddr;
    struct nlmsghdr *nlh = NULL;
    struct jmx_nl_msg_hdr *hdr;
    size_t payload_len;
    size_t frame_len;
    ssize_t sent;

    if (fd < 0 || !msg || len <= 0 ||
        len > MAX_NL_MSG_LEN - (int)sizeof(*hdr)) {
        errno = EINVAL;
        return -1;
    }
    payload_len = sizeof(*hdr) + (size_t)len;
    frame_len = NLMSG_SPACE(payload_len);
    nlh = calloc(1, frame_len);
    if (!nlh) {
        errno = ENOMEM;
        return -1;
    }
    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel
    daddr.nl_groups = 0;
    nlh->nlmsg_len = NLMSG_LENGTH(payload_len);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = DEFAULT_JMX_NL_PID;
    hdr = (struct jmx_nl_msg_hdr *)NLMSG_DATA(nlh);
    hdr->magic = 0xa0b0c0d0;
    hdr->len = len;
    memcpy(hdr + 1, msg, (size_t)len);

    sent = sendto(fd, nlh, nlh->nlmsg_len, 0,
                  (struct sockaddr *)&daddr, sizeof(daddr));
    free(nlh);
    if (sent < 0)
        return -1;
    if ((size_t)sent != NLMSG_LENGTH(payload_len)) {
        errno = EIO;
        return -1;
    }

    return 0;
}

int jmx_netlink_init(void)
{
    int fd;
    struct sockaddr_nl nls;
    jmx_nl_msg_t init = { .action = JMX_NL_MSG_INIT };
    fd = socket(AF_NETLINK, SOCK_RAW, JMX_NETLINK_ID);
    if (fd < 0)
    {
        LOG_DEBUG("Connect netlink %d failed %s\n", JMX_NETLINK_ID, strerror(errno));
        return -1;
    }
    memset(&nls, 0, sizeof(struct sockaddr_nl));
    nls.nl_pid = DEFAULT_JMX_NL_PID;
    nls.nl_groups = 0;
    nls.nl_family = AF_NETLINK;

    if (bind(fd, (void *)&nls, sizeof(struct sockaddr_nl)))
    {
        LOG_DEBUG("Bind failed %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    if (jmx_nl_send_msg_to_kernel(fd, &init, sizeof(init)) != 0) {
        LOG_DEBUG("Register legacy netlink owner failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

int jmx_v2_netlink_init(void)
{
    int fd;
    struct sockaddr_nl nls;
    fd = socket(AF_NETLINK, SOCK_RAW, JMX_NETLINK_ID);
    if (fd < 0)
    {
        LOG_DEBUG("v2: Connect netlink %d failed %s\n", JMX_NETLINK_ID, strerror(errno));
        return -1;
    }
    memset(&nls, 0, sizeof(struct sockaddr_nl));
    nls.nl_pid = getpid();
    nls.nl_groups = 0;
    nls.nl_family = AF_NETLINK;

    if (bind(fd, (void *)&nls, sizeof(struct sockaddr_nl)))
    {
        LOG_DEBUG("v2: Bind failed %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}
