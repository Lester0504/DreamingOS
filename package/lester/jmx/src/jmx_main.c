
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <uapi/linux/ipv6.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/ktime.h>
#include <linux/lockdep.h>
#include <linux/overflow.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include "jmx_v2_rules.h"
#include "jmx_v3_nl_handler.h"
#include "jmx_v3_rules.h"
extern int jmx_v2_nl_handle(const char *data, int len, uint32_t portid,
			    uint32_t nlmsg_seq,
			    jmx_v3_nl_reply_fn reply);
#include "jmx.h"
#include "jmx_utils.h"
#include "jmx_log.h"
#include "jmx_client.h"
#include "jmx_client_fs.h"
#include "k_json.h"
#include "jmx_conntrack.h"
#include "jmx_config.h"
#include "jmx_mac_filter.h"
#include "jmx_app_filter.h"
#include <linux/version.h>
#include <linux/timer.h>

static inline char *jmx_compat_strncpy(char *dst, const char *src, size_t count)
{
	if (!count)
		return dst;
	strscpy(dst, src ? src : "", count);
	return dst;
}

#ifndef strncpy
#define strncpy jmx_compat_strncpy
#endif

#ifndef HAVE_JMX_TIMER_SHUTDOWN_SYNC
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
#define HAVE_JMX_TIMER_SHUTDOWN_SYNC 1
#endif
#endif

static inline void jmx_del_timer_sync_compat(struct timer_list *t)
{
#if defined(HAVE_JMX_TIMER_SHUTDOWN_SYNC)
        timer_shutdown_sync(t);
#else
        del_timer_sync(t);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
#define jmx_timer_delete_sync(t) timer_delete_sync(t)
#define jmx_timer_shutdown_sync(t) timer_shutdown_sync(t)
#else
#define jmx_timer_delete_sync(t) del_timer_sync(t)
#define jmx_timer_shutdown_sync(t) del_timer_sync(t)
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("www.lesterwrt.com");
MODULE_DESCRIPTION("jmx module");
MODULE_VERSION(AF_VERSION);
struct list_head af_feature_head = LIST_HEAD_INIT(af_feature_head);

DEFINE_RWLOCK(af_feature_lock);




#define ACTIVE_APP_TIMEOUT_SEC 300  /* 5 minutes */

/* /proc/dreamingwrt/jmx/ root directory */
struct proc_dir_entry *jmx_proc_root = NULL;

static LIST_HEAD(active_app_list);
static DEFINE_SPINLOCK(active_app_list_lock);

static int jmx_copy_visible_token(char *dst, size_t dst_len,
				  const char *src, int src_len);
static int jmx_visible_token_is_valid(const char *src);

#define JMX_MATCH_STATUS_IGNORE       0x1
#define JMX_MATCH_STATUS_CLIENT_HELLO 0x2
#define JMX_MATCH_STATUS_RELIABLE     0x4
#ifndef NF_JMX_MATCH_STATUS_NO_OFFLOAD
#define NF_JMX_MATCH_STATUS_NO_OFFLOAD 0x80000000U
#endif
#define JMX_MATCH_STATUS_NO_OFFLOAD   NF_JMX_MATCH_STATUS_NO_OFFLOAD

/* Update active app list from v2 regex result (called from jmx_v2_nl_handler) */

#include <net/neighbour.h>
#include <net/route.h>

static void jmx_arp_lookup_mac(u_int32_t ip, unsigned char *mac)
{
    struct neighbour *neigh;
    struct rtable *rt;
    struct flowi4 fl4;

    eth_zero_addr(mac);
    if (ip == 0)
        return;

    memset(&fl4, 0, sizeof(fl4));
    fl4.daddr = ip;
    fl4.flowi4_oif = 0;

    rt = ip_route_output_key(&init_net, &fl4);
    if (IS_ERR(rt))
        return;

    neigh = dst_neigh_lookup(&rt->dst, &ip);
    if (neigh) {
        read_lock_bh(&neigh->lock);
        if (neigh->nud_state & NUD_VALID)
            memcpy(mac, neigh->ha, ETH_ALEN);
        read_unlock_bh(&neigh->lock);
        neigh_release(neigh);
    }
    ip_rt_put(rt);
}

void jmx_v2_update_active_app_ex(uint32_t appid, uint32_t src_ip, uint32_t dst_ip,
				  uint16_t src_port, uint16_t dst_port, uint8_t proto,
				  uint8_t app_proto, const char *host, uint8_t host_len)
{
	active_app_node_t *node = NULL, *tmp_node = NULL;
	int found = 0;

	if (appid == 0)
		return;

	spin_lock_bh(&active_app_list_lock);
	list_for_each_entry_safe(node, tmp_node, &active_app_list, list) {
		if (node->app_id == appid) {
			node->src_ip = src_ip;
			node->dst_ip = dst_ip;
			node->src_port = src_port;
			node->dst_port = dst_port;
			node->l4_protocol = (proto == 6) ? IPPROTO_TCP : IPPROTO_UDP;
			node->proto_type = app_proto;
			jmx_copy_visible_token(node->host, sizeof(node->host),
					       host, host_len);
			jmx_arp_lookup_mac(src_ip, node->mac);
			node->update_time = ktime_get_real_seconds();
			found = 1;
			break;
		}
	}
	if (!found) {
		node = kzalloc(sizeof(*node), GFP_ATOMIC);
		if (node) {
			node->app_id = appid;
			node->src_ip = src_ip;
			node->dst_ip = dst_ip;
			node->src_port = src_port;
			node->dst_port = dst_port;
			node->l4_protocol = (proto == 6) ? IPPROTO_TCP : IPPROTO_UDP;
			node->proto_type = app_proto;
			jmx_copy_visible_token(node->host, sizeof(node->host),
					       host, host_len);
			jmx_arp_lookup_mac(src_ip, node->mac);
			node->update_time = ktime_get_real_seconds();
			list_add(&node->list, &active_app_list);
		}
	}
	spin_unlock_bh(&active_app_list_lock);
}

void jmx_v2_update_active_app(uint32_t appid, uint32_t src_ip, uint32_t dst_ip,
			       uint16_t src_port, uint16_t dst_port, uint8_t proto)
{
	jmx_v2_update_active_app_ex(appid, src_ip, dst_ip, src_port, dst_port,
				 proto, 0, NULL, 0);
}

void jmx_v2_update_active_app6_ex(uint32_t appid,
				  const uint8_t *src_ip6, const uint8_t *dst_ip6,
				  uint16_t src_port, uint16_t dst_port, uint8_t proto,
				  uint8_t app_proto, const char *host, uint8_t host_len)
{
	active_app_node_t *node = NULL, *tmp_node = NULL;
	int found = 0;

	if (appid == 0)
		return;

	spin_lock_bh(&active_app_list_lock);
	list_for_each_entry_safe(node, tmp_node, &active_app_list, list) {
		if (node->app_id == appid) {
			node->src_ip = 0;
			node->dst_ip = 0;
			if (src_ip6) memcpy(&node->src_ip6, src_ip6, 16);
			if (dst_ip6) memcpy(&node->dst_ip6, dst_ip6, 16);
			node->src_port = src_port;
			node->dst_port = dst_port;
			node->l4_protocol = (proto == 6) ? IPPROTO_TCP : IPPROTO_UDP;
			node->proto_type = app_proto;
			jmx_copy_visible_token(node->host, sizeof(node->host),
					       host, host_len);
			node->update_time = ktime_get_real_seconds();
			found = 1;
			break;
		}
	}
	if (!found) {
		node = kzalloc(sizeof(*node), GFP_ATOMIC);
		if (node) {
			node->app_id = appid;
			node->src_ip = 0;
			node->dst_ip = 0;
			if (src_ip6) memcpy(&node->src_ip6, src_ip6, 16);
			if (dst_ip6) memcpy(&node->dst_ip6, dst_ip6, 16);
			node->src_port = src_port;
			node->dst_port = dst_port;
			node->l4_protocol = (proto == 6) ? IPPROTO_TCP : IPPROTO_UDP;
			node->proto_type = app_proto;
			jmx_copy_visible_token(node->host, sizeof(node->host),
					       host, host_len);
			node->update_time = ktime_get_real_seconds();
			list_add(&node->list, &active_app_list);
		}
	}
	spin_unlock_bh(&active_app_list_lock);
}



static LIST_HEAD(active_host_list);
static DEFINE_SPINLOCK(active_host_list_lock);

u_int32_t jmx_log_level = 3;  

#define feature_list_read_lock() read_lock_bh(&af_feature_lock);
#define feature_list_read_unlock() read_unlock_bh(&af_feature_lock);
#define feature_list_write_lock() write_lock_bh(&af_feature_lock);
#define feature_list_write_unlock() write_unlock_bh(&af_feature_lock);


#define SET_APPID(ct, appid) ((ct)->jmx_data.app_id = (appid))
#define GET_APPID(ct) ((ct)->jmx_data.app_id)
#define MAX_OAF_NETLINK_MSG_LEN 1024
#define MAX_AF_SUPPORT_DATA_LEN 3000

#define JMX_DEFAULT_FEATURE_LINE_LIMIT 8192
#define JMX_DEFAULT_FEATURE_NODE_LIMIT 32768

static unsigned int g_feature_line_count;
static unsigned int g_feature_node_count;
static unsigned int g_feature_line_limit = JMX_DEFAULT_FEATURE_LINE_LIMIT;
static unsigned int g_feature_node_limit = JMX_DEFAULT_FEATURE_NODE_LIMIT;

module_param_named(feature_line_limit, g_feature_line_limit, uint, 0644);
MODULE_PARM_DESC(feature_line_limit, "Maximum number of feature lines accepted from jmxd");
module_param_named(feature_node_limit, g_feature_node_limit, uint, 0644);
MODULE_PARM_DESC(feature_node_limit, "Maximum number of parsed feature nodes accepted from jmxd");

static int jmx_copy_visible_token(char *dst, size_t dst_len,
				  const char *src, int src_len)
{
	int i;
	int n = 0;

	if (!dst || dst_len == 0)
		return 0;

	dst[0] = '\0';
	if (!src || src_len <= 0)
		return 0;

	for (i = 0; i < src_len && n < (int)dst_len - 1; i++) {
		unsigned char c = src[i];

		if (c < 0x21 || c > 0x7e) {
			dst[0] = '\0';
			return 0;
		}
		dst[n++] = c;
	}

	dst[n] = '\0';
	return n > 0;
}

static int jmx_visible_token_is_valid(const char *src)
{
	int i;

	if (!src || !src[0])
		return 0;

	for (i = 0; src[i] != '\0'; i++) {
		unsigned char c = src[i];

		if (c < 0x21 || c > 0x7e)
			return 0;
	}

	return 1;
}

static int copy_feature_field(char *dst, size_t dst_len, const char *begin, size_t len,
			      const char *field_name, int appid)
{
	if (!dst || !begin || dst_len == 0)
		return -EINVAL;

	if (len >= dst_len)
	{
		AF_ERROR("skip appid=%d: %s too long (%zu >= %zu)\n",
			 appid, field_name, len + 1, dst_len);
		return -EINVAL;
	}

	memcpy(dst, begin, len);
	dst[len] = '\0';
	return 0;
}

static int copy_feature_cstr(char *dst, size_t dst_len, const char *src,
			     const char *field_name, int appid)
{
	ssize_t ret;

	if (!dst || dst_len == 0)
		return -EINVAL;

	ret = strscpy(dst, src ? src : "", dst_len);
	if (ret < 0)
	{
		AF_ERROR("skip appid=%d: %s too long for buffer (%zu)\n",
			 appid, field_name, dst_len);
		return -EINVAL;
	}

	return 0;
}

static int is_feature_item_start(const char *s)
{
	if (!s || !*s)
		return 0;

	/* 跳过逗号后的空白 */
	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
		s++;

	if (!strncmp(s, "tcp;", 4))
		return 1;
	if (!strncmp(s, "udp;", 4))
		return 1;

	return 0;
}

static int parse_feature_dict(af_feature_node_t *node, const char *dict, int appid)
{
	const char *p;
	const char *begin;
	char pos[256] = {0};
	int index = 0;
	int value = 0;
	int ret;
	int parsed = 0;

	if (!node || !dict || dict[0] == '\0')
		return 0;

	/* 这里只解析 idx:hex 形式，分隔符兼容 '|' 和 ',' */
	if (!strchr(dict, ':'))
		return 0;

	begin = dict;
	for (p = dict; ; p++) {
		if (*p != '|' && *p != ',' && *p != '\0')
			continue;

		if (p > begin) {
			memset(pos, 0, sizeof(pos));
			if (copy_feature_field(pos, sizeof(pos), begin, p - begin,
					       "dict_pos", appid) < 0)
				return -EINVAL;

			ret = sscanf(pos, "%d:%x", &index, &value);
			if (ret == 2) {
				if (node->pos_num >= MAX_POS_INFO_PER_FEATURE) {
					AF_WARN("skip appid=%d: pos_info is full (%d)\n",
						appid, MAX_POS_INFO_PER_FEATURE);
					return -ENOSPC;
				}

				node->pos_info[node->pos_num].pos = index;
				node->pos_info[node->pos_num].value = value;
				node->pos_num++;
				parsed++;
			} else {
				AF_DEBUG("skip appid=%d: unsupported dict token '%s'\n",
					 appid, pos);
			}
		}

		if (*p == '\0')
			break;

		begin = p + 1;
	}

	if (parsed == 0)
		AF_DEBUG("skip appid=%d: dict ignored (unsupported format)\n", appid);

	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(5,10,197)
extern void nf_send_reset(struct net *net, struct sock *sk, struct sk_buff *oldskb, int hook);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4,4,1)
extern void nf_send_reset(struct net *net,  struct sk_buff *oldskb, int hook);
#else
extern void nf_send_reset(sk_buff *oldskb, int hook);
#endif

char *ipv6_to_str(const struct in6_addr *addr, char *str)
{
	sprintf(str, "%pI6c", addr);
	return str;
}


int __add_app_feature(char *feature, int appid, char *name, int proto, int src_port,
		      port_info_t dport_info, char *host_url, char *request_url,
		      char *dict, char *search_str, int ignore)
{
	af_feature_node_t *node = NULL;
	int ret;

	if (g_feature_node_count >= g_feature_node_limit)
	{
		AF_ERROR("skip appid=%d: feature node limit reached (%u)\n",
			 appid, g_feature_node_limit);
		return -ENOSPC;
	}

	node = kzalloc(sizeof(af_feature_node_t), GFP_ATOMIC);
	if (node == NULL)
	{
		AF_ERROR("malloc feature memory error\n");
		return -ENOMEM;
	}

	node->app_id = appid;
	node->proto = proto;
	node->dport_info = dport_info;
	node->sport = src_port;
	node->ignore = ignore;

	if (copy_feature_cstr(node->app_name, sizeof(node->app_name), name,
			      "app_name", appid) < 0 ||
	    copy_feature_cstr(node->host_url, sizeof(node->host_url), host_url,
			      "host_url", appid) < 0 ||
	    copy_feature_cstr(node->request_url, sizeof(node->request_url), request_url,
			      "request_url", appid) < 0 ||
	    copy_feature_cstr(node->search_str, sizeof(node->search_str), search_str,
			      "search_str", appid) < 0 ||
	    copy_feature_cstr(node->feature, sizeof(node->feature), feature,
			      "feature", appid) < 0)
		goto fail;

	ret = parse_feature_dict(node, dict, appid);
	if (ret < 0)
		goto fail;

	if (ignore)
		AF_DEBUG("add feature %s, ignore = %d\n", feature, ignore);

	feature_list_write_lock();
	list_add_tail(&(node->head), &af_feature_head);
	g_feature_node_count++;
	feature_list_write_unlock();
	return 0;

fail:
	kfree(node);
	return -EINVAL;
}
int validate_range_value(char *range_str)
{
	if (!range_str)
		return 0;
	char *p = range_str;
	while (*p)
	{
		if (*p == ' ' || *p == '!' || *p == '-' ||
			((*p >= '0') && (*p <= '9')))
		{
			p++;
			continue;
		}
		else
		{
			return 0;
		}
	}
	return 1;
}

int parse_range_value(char *range_str, range_value_t *range)
{
	char pure_range[128] = {0};

	if (!validate_range_value(range_str))
	{
		printk("validate range str failed, value = %s\n", range_str);
		return -1;
	}
	k_trim(range_str);
	if (strlen(range_str) >= sizeof(pure_range))
	{
		AF_ERROR("range string too long: %s\n", range_str);
		return -EINVAL;
	}
	if (range_str[0] == '!')
	{
		range->not = 1;
		if (strscpy(pure_range, range_str + 1, sizeof(pure_range)) < 0)
			return -EINVAL;
	}
	else
	{
		range->not = 0;
		if (strscpy(pure_range, range_str, sizeof(pure_range)) < 0)
			return -EINVAL;
	}
	k_trim(pure_range);
	int start, end;
	if (strstr(pure_range, "-"))
	{
		if (2 != sscanf(pure_range, "%d-%d", &start, &end))
			return -1;
	}
	else
	{
		if (1 != sscanf(pure_range, "%d", &start))
			return -1;
		end = start;
	}
	range->start = start;
	range->end = end;
	return 0;
}

int parse_port_info(char *port_str, port_info_t *info)
{
	char *p;
	char *begin;
	char one_port_buf[128] = {0};

	if (!info)
		return -EINVAL;

	memset(info, 0, sizeof(*info));

	/* Empty dst_port means "match any port". This is valid. */
	if (!port_str)
		return 0;

	k_trim(port_str);
	if (strlen(port_str) == 0)
		return 0;

	p = port_str;
	begin = port_str;

	for (; *p; p++) {
		if (*p != '|')
			continue;

		memset(one_port_buf, 0x0, sizeof(one_port_buf));
		if (copy_feature_field(one_port_buf, sizeof(one_port_buf), begin,
				       p - begin, "port_range", -1) < 0)
			return -EINVAL;

		if (info->num >= MAX_PORT_RANGE_NUM) {
			AF_ERROR("port range count exceeds limit (%d)\n",
				 MAX_PORT_RANGE_NUM);
			return -ENOSPC;
		}

		if (parse_range_value(one_port_buf, &info->range_list[info->num]) == 0)
			info->num++;
		else
			return -EINVAL;

		begin = p + 1;
	}

	if (p > begin) {
		memset(one_port_buf, 0x0, sizeof(one_port_buf));
		if (copy_feature_field(one_port_buf, sizeof(one_port_buf), begin,
				       p - begin, "port_range", -1) < 0)
			return -EINVAL;

		if (info->num >= MAX_PORT_RANGE_NUM) {
			AF_ERROR("port range count exceeds limit (%d)\n",
				 MAX_PORT_RANGE_NUM);
			return -ENOSPC;
		}

		if (parse_range_value(one_port_buf, &info->range_list[info->num]) == 0)
			info->num++;
		else
			return -EINVAL;
	}

	return 0;
}

int af_match_port(port_info_t *info, int port)
{
	int i;
	int with_not = 0;
	if (info->num == 0)
		return 1;
	for (i = 0; i < info->num; i++)
	{
		if (info->range_list[i].not )
		{
			with_not = 1;
			break;
		}
	}
	for (i = 0; i < info->num; i++)
	{
		if (with_not)
		{
			if (info->range_list[i].not &&port >= info->range_list[i].start && port <= info->range_list[i].end)
			{
				return 0;
			}
		}
		else
		{
			if (port >= info->range_list[i].start && port <= info->range_list[i].end)
			{
				return 1;
			}
		}
	}
	if (with_not)
		return 1;
	else
		return 0;
}

int add_app_feature(int appid, char *name, char *feature)
{
	char proto_str[16] = {0};
	char src_port_str[16] = {0};
	port_info_t dport_info;
	char dst_port_str[32] = {0};
	char host_url[MAX_HOST_URL_LEN] = {0};
	char request_url[MAX_REQUEST_URL_LEN] = {0};
	char dict[1024] = {0};
	int proto = IPPROTO_TCP;
	int param_num = 0;
	int src_port = 0;
	char tmp_buf[32] = {0};
	int ignore = 0;
	char search_str[MAX_SEARCH_STR_LEN] = {0};
	char *p = feature;
	char *begin = feature;
	int ret;

	if (!name || !feature)
	{
		AF_ERROR("error, name or feature is null\n");
		return -1;
	}
	
	if (strlen(feature) < MIN_FEATURE_STR_LEN)
		return -1;

	memset(&dport_info, 0x0, sizeof(dport_info));
	while (*p++)
	{
		if (*p != ';')
			continue;

		switch (param_num)
		{
		case AF_PROTO_PARAM_INDEX:
			if (copy_feature_field(proto_str, sizeof(proto_str), begin, p - begin,
					      "proto", appid) < 0)
				return -EINVAL;
			break;
		case AF_SRC_PORT_PARAM_INDEX:
			if (copy_feature_field(src_port_str, sizeof(src_port_str), begin,
					      p - begin, "src_port", appid) < 0)
				return -EINVAL;
			break;
		case AF_DST_PORT_PARAM_INDEX:
			if (copy_feature_field(dst_port_str, sizeof(dst_port_str), begin,
					      p - begin, "dst_port", appid) < 0)
				return -EINVAL;
			break;
		case AF_HOST_URL_PARAM_INDEX:
			if (copy_feature_field(host_url, sizeof(host_url), begin, p - begin,
					      "host_url", appid) < 0)
				return -EINVAL;
			break;
		case AF_REQUEST_URL_PARAM_INDEX:
			if (copy_feature_field(request_url, sizeof(request_url), begin,
					      p - begin, "request_url", appid) < 0)
				return -EINVAL;
			break;
		case AF_DICT_PARAM_INDEX:
			if (copy_feature_field(dict, sizeof(dict), begin, p - begin,
					      "dict", appid) < 0)
				return -EINVAL;
			break;
		case AF_STR_PARAM_INDEX:
			if (copy_feature_field(search_str, sizeof(search_str), begin,
					      p - begin, "search_str", appid) < 0)
				return -EINVAL;
			break;
		case AF_IGNORE_PARAM_INDEX:
			if (copy_feature_field(tmp_buf, sizeof(tmp_buf), begin, p - begin,
					      "ignore", appid) < 0)
				return -EINVAL;
			ignore = k_atoi(tmp_buf);
			break;
		}
		param_num++;
		begin = p + 1;
	}

	if (param_num == AF_DICT_PARAM_INDEX)
	{
		if (copy_feature_field(dict, sizeof(dict), begin, p - begin,
				      "dict", appid) < 0)
			return -EINVAL;
	}

	if (param_num == AF_IGNORE_PARAM_INDEX)
	{
		if (copy_feature_field(tmp_buf, sizeof(tmp_buf), begin, p - begin,
				      "ignore", appid) < 0)
			return -EINVAL;
		ignore = k_atoi(tmp_buf);
	}

	if (0 == strcmp(proto_str, "tcp"))
		proto = IPPROTO_TCP;
	else if (0 == strcmp(proto_str, "udp"))
		proto = IPPROTO_UDP;
	else
	{
		printk("proto %s is not support, feature = %s\n", proto_str, feature);
		return -1;
	}
	sscanf(src_port_str, "%d", &src_port);

	ret = parse_port_info(dst_port_str, &dport_info);
	if (ret < 0)
	{
		AF_ERROR("skip appid=%d: invalid dst_port '%s'\n", appid, dst_port_str);
		return ret;
	}
	AF_DEBUG("host_url = %s, request = %s, dict = %s\n",  host_url, request_url, dict);

	ret = __add_app_feature(feature, appid, name, proto, src_port,
				dport_info, host_url, request_url, dict, search_str, ignore);
	if (ret == 0)
		AF_DEBUG("id = %d name = %s, add feature %s, ignore = %d\n", appid, name, feature, ignore);
	return ret;
}

void af_init_feature(char *feature_str)
{
	int app_id;
	char app_name[MAX_APP_NAME_LEN] = {0};
	char *feature_buf = NULL;
	char feature[MAX_FEATURE_STR_LEN] = {0};
	char *lbr = NULL;
	char *colon = NULL;
	char *end = NULL;
	char *p = NULL;
	char *begin = NULL;
	int len = 0;
	int added = 0;
	char header[128] = {0};
	int header_len = 0;

	if (!feature_str || feature_str[0] == '\0')
		return;

	while (*feature_str == ' ' || *feature_str == '\t' ||
	       *feature_str == '\r' || *feature_str == '\n')
		feature_str++;

	if (*feature_str == '#' || *feature_str == '\0')
		return;

	if (g_feature_line_count >= g_feature_line_limit) {
		AF_ERROR("skip feature line: line limit reached (%u)\n",
			 g_feature_line_limit);
		return;
	}

	lbr = strchr(feature_str, '[');
	if (!lbr) {
		AF_ERROR("skip malformed feature line(no '['): %s\n", feature_str);
		return;
	}

	colon = lbr;
	while (colon > feature_str &&
	       (*(colon - 1) == ' ' || *(colon - 1) == '\t'))
		colon--;

	if (colon <= feature_str || *(colon - 1) != ':') {
		AF_ERROR("skip malformed feature header(no ':' before '['): %s\n",
			 feature_str);
		return;
	}

	header_len = (colon - 1) - feature_str;
	while (header_len > 0 &&
	       (feature_str[header_len - 1] == ' ' ||
		feature_str[header_len - 1] == '\t'))
		header_len--;

	if (header_len <= 0 || header_len >= (int)sizeof(header)) {
		AF_ERROR("skip malformed feature header len=%d: %s\n",
			 header_len, feature_str);
		return;
	}

	memcpy(header, feature_str, header_len);
	header[header_len] = '\0';

	{
		char *space;
		char *name_start;

		space = strpbrk(header, " \t");
		if (!space) {
			AF_ERROR("skip malformed app name header(no space): %s\n",
				 header);
			return;
		}

		*space = '\0';
		name_start = space + 1;

		while (*name_start == ' ' || *name_start == '\t')
			name_start++;

		if (*name_start == '\0') {
			AF_ERROR("skip empty app name header: %s\n", feature_str);
			return;
		}

		if (kstrtoint(header, 10, &app_id)) {
			AF_ERROR("skip malformed appid header: %s\n", header);
			return;
		}

		if (strscpy(app_name, name_start, sizeof(app_name)) < 0) {
			AF_ERROR("skip appid=%d: app name too long\n", app_id);
			return;
		}
	}

	end = strrchr(lbr + 1, ']');
	if (!end || end <= lbr + 1) {
		AF_ERROR("skip appid=%d: feature body not found\n", app_id);
		return;
	}

	len = end - (lbr + 1);
	if (len <= 0) {
		AF_ERROR("skip appid=%d: empty feature body\n", app_id);
		return;
	}

	if (len >= MAX_FEATURE_LINE_LEN) {
		AF_ERROR("skip appid=%d: feature body too long (%d >= %d)\n",
			 app_id, len, MAX_FEATURE_LINE_LEN);
		return;
	}

	feature_buf = kmalloc(MAX_FEATURE_LINE_LEN, GFP_KERNEL);
	if (!feature_buf) {
		AF_ERROR("Failed to allocate memory for feature_buf\n");
		return;
	}

	memcpy(feature_buf, lbr + 1, len);
	feature_buf[len] = '\0';

	begin = feature_buf;
	for (p = feature_buf; *p; p++) {
		if (*p != ',')
			continue;

		/* 只有逗号后面是 tcp; / udp; 才认为是新 feature_item 的分隔符 */
		if (!is_feature_item_start(p + 1))
			continue;

		if (p > begin) {
			if (copy_feature_field(feature, sizeof(feature),
					       begin, p - begin,
					       "feature_item", app_id) < 0) {
				AF_WARN("skip appid=%d: one feature_item too long, continue next\n",
					app_id);
				begin = p + 1;
				continue;
			}

			if (add_app_feature(app_id, app_name, feature) == 0)
				added++;
		}

		begin = p + 1;
	}

	if (*begin) {
		if (copy_feature_field(feature, sizeof(feature),
				       begin, strlen(begin),
				       "feature_item", app_id) < 0) {
			AF_WARN("skip appid=%d: tail feature_item too long\n", app_id);
		} else {
			if (add_app_feature(app_id, app_name, feature) == 0)
				added++;
		}
	}

	if (added > 0)
		g_feature_line_count++;

	kfree(feature_buf);
}

void load_feature_buf_from_file(char **config_buf)
{
	struct inode *inode = NULL;
	struct file *fp = NULL;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 7, 19)
	mm_segment_t fs;
#endif
	off_t size;
	fp = filp_open(AF_FEATURE_CONFIG_FILE, O_RDONLY, 0);
	

	if (IS_ERR(fp))
	{
		return;
	}

	inode = fp->f_inode;
	size = inode->i_size;
	if (size == 0)
	{
		filp_close(fp, NULL);
		return;
	}
	*config_buf = (char *)kzalloc(sizeof(char) * (size + 1), GFP_ATOMIC);
	if (NULL == *config_buf)
	{
		AF_ERROR("alloc buf fail\n");
		filp_close(fp, NULL);
		return;
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 7, 19)
	fs = get_fs();
	set_fs(KERNEL_DS);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	kernel_read(fp, *config_buf, size, &(fp->f_pos));
#else
	vfs_read(fp, *config_buf, size, &(fp->f_pos));
#endif
	(*config_buf)[size] = '\0';

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 7, 19)
	set_fs(fs);
#endif
	filp_close(fp, NULL);
}

int load_feature_config(void)
{
	char *feature_buf = NULL;
	char *p;
	char *begin;
	char line[MAX_FEATURE_LINE_LEN] = {0};

	load_feature_buf_from_file(&feature_buf);
	if (!feature_buf)
	{
		return -1;
	}
	p = begin = feature_buf;
	while (*p++)
	{
		if (*p == '\n')
		{
			if (p - begin < MIN_FEATURE_LINE_LEN || p - begin > MAX_FEATURE_LINE_LEN)
			{
				begin = p + 1;
				continue;
			}
			memset(line, 0x0, sizeof(line));
			strncpy(line, begin, p - begin);
			af_init_feature(line);
			begin = p + 1;
		}
	}

	if (p != begin)
	{
		if (p - begin < MIN_FEATURE_LINE_LEN || p - begin > MAX_FEATURE_LINE_LEN)
			return 0;
		memset(line, 0x0, sizeof(line));
		strncpy(line, begin, p - begin);
		af_init_feature(line);
		begin = p + 1;
	}
	if (feature_buf)
		kfree(feature_buf);
	return 0;
}

static void af_clean_feature_list(void)
{
	af_feature_node_t *node;
	AF_INFO("clean feature list: lines=%u nodes=%u\n",
		g_feature_line_count, g_feature_node_count);
	feature_list_write_lock();
	while (!list_empty(&af_feature_head))
	{
		node = list_first_entry(&af_feature_head, af_feature_node_t, head);
		list_del(&(node->head));
		kfree(node);
	}
	g_feature_line_count = 0;
	g_feature_node_count = 0;
	feature_list_write_unlock();
}

void af_add_feature_msg_handle(char *data, int len)
{
	char feature[MAX_FEATURE_LINE_LEN] = {0};
	unsigned int before = g_feature_line_count;

	if (len <= 0 || len >= MAX_FEATURE_LINE_LEN){
		printk("warn, feature data len = %d\n", len);
		return;
	}
	if (g_feature_line_count >= g_feature_line_limit)
	{
		AF_ERROR("skip feature line: line limit reached (%u)\n",
			 g_feature_line_limit);
		return;
	}
	memcpy(feature, data, len);
	feature[len] = '\0';
	AF_INFO("add feature %s\n", feature);
	af_init_feature(feature);
	if (g_feature_line_count != before && (g_feature_line_count % 256) == 0)
		AF_INFO("feature load progress: lines=%u nodes=%u\n",
			g_feature_line_count, g_feature_node_count);
}

static unsigned char *read_skb(struct sk_buff *skb, unsigned int from, unsigned int len)
{
	struct skb_seq_state state;
	unsigned char *msg_buf = NULL;
	unsigned int consumed = 0;
#if 0
	if (from <= 0 || from > 1500)
		return NULL;

	if (len <= 0 || from+len > 1500)
		return NULL;
#endif

	msg_buf = kmalloc(len, GFP_KERNEL);
	if (!msg_buf)
		return NULL;

	skb_prepare_seq_read(skb, from, from + len, &state);
	while (1)
	{
		unsigned int avail;
		const u8 *ptr;
		avail = skb_seq_read(consumed, &ptr, &state);
		if (avail == 0)
		{
			break;
		}
		memcpy(msg_buf + consumed, ptr, avail);
		consumed += avail;
		if (consumed >= len)
		{
			skb_abort_seq_read(&state);
			break;
		}
	}
	return msg_buf;
}

int parse_flow_proto(struct sk_buff *skb, flow_info_t *flow)
{
	unsigned char *ipp;
	int ipp_len;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	if (!skb)
		return -1;
	switch (skb->protocol)
	{
	case htons(ETH_P_IP):
		iph = ip_hdr(skb);
		flow->src = iph->saddr;
		flow->dst = iph->daddr;
		flow->l4_protocol = iph->protocol;
		ipp = ((unsigned char *)iph) + iph->ihl * 4;
		ipp_len = ((unsigned char *)iph) + ntohs(iph->tot_len) - ipp;
		break;
	case htons(ETH_P_IPV6):
		ip6h = ipv6_hdr(skb);
		flow->src6 = &ip6h->saddr;
		flow->dst6 = &ip6h->daddr;
		flow->l4_protocol = ip6h->nexthdr;
		ipp = ((unsigned char *)ip6h) + sizeof(struct ipv6hdr);
		ipp_len = ntohs(ip6h->payload_len);
		break;
	default:
		return -1;
	}

	switch (flow->l4_protocol)
	{
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)ipp;
		flow->l4_len = ipp_len - tcph->doff * 4;
		flow->l4_data = ipp + tcph->doff * 4;
		flow->dport = ntohs(tcph->dest);
		flow->sport = ntohs(tcph->source);
		return 0;
	case IPPROTO_UDP:
		udph = (struct udphdr *)ipp;
		flow->l4_len = ntohs(udph->len) - 8;
		flow->l4_data = ipp + 8;
		flow->dport = ntohs(udph->dest);
		flow->sport = ntohs(udph->source);
		return 0;
	case IPPROTO_ICMP:
		break;
	default:
		return -1;
	}
	return -1;
}

int check_domain(char *h, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		if ((h[i] >= 'a' && h[i] <= 'z') || (h[i] >= 'A' && h[i] <= 'Z') ||
			(h[i] >= '0' && h[i] <= '9') || h[i] == '.' || h[i] == '-' ||  h[i] == ':')
		{
			continue;
		}
		else
			return 0;
	}
	return 1;
}

static inline u16 jmx_get_be16(const unsigned char *p)
{
	return ((u16)p[0] << 8) | (u16)p[1];
}

static inline u32 jmx_get_be24(const unsigned char *p)
{
	return ((u32)p[0] << 16) | ((u32)p[1] << 8) | (u32)p[2];
}

static int dpi_https_proto_loose(flow_info_t *flow)
{
	const unsigned char *p;
	int data_len;
	int i;
	u16 ext_len, list_len, name_len;

	if (!flow || !flow->l4_data || flow->l4_len <= 0)
		return -1;

	p = (const unsigned char *)flow->l4_data;
	data_len = flow->l4_len;

	/* 宽松模式：不要求当前 skb 从 TLS record 起始开始，
	 * 只要这一段里完整包含了 server_name 扩展，就尝试提取域名。
	 */
	for (i = 0; i + 9 < data_len; i++) {
		/* extension type: server_name = 0x0000 */
		if (p[i] != 0x00 || p[i + 1] != 0x00)
			continue;

		ext_len = jmx_get_be16(p + i + 2);
		if (ext_len < 5)
			continue;
		if (i + 4 + ext_len > data_len)
			continue;

		list_len = jmx_get_be16(p + i + 4);
		if (list_len < 3)
			continue;
		if (i + 6 + list_len > data_len)
			continue;

		/* name_type 必须是 host_name(0) */
		if (p[i + 6] != 0x00)
			continue;

		name_len = jmx_get_be16(p + i + 7);
		if (name_len < MIN_HOST_LEN || name_len > MAX_HOST_LEN)
			continue;
		if (i + 9 + name_len > data_len)
			continue;

		if (!check_domain((char *)p + i + 9, name_len))
			continue;

		flow->https.match = AF_TRUE;
		flow->https.url_pos = (char *)p + i + 9;
		flow->https.url_len = name_len;
		flow->client_hello = 0;
		return 0;
	}

	return -1;
}

int dpi_https_proto(flow_info_t *flow)
{
	const unsigned char *p;
	int data_len;
	int rec_len, hs_len, end;
	int sid_len, cs_len, comp_len, ext_len;
	int pos, sni_end, list_len, name_len;
	u16 ext_type, ext_size;
	u8 name_type;

	if (!flow) {
		AF_ERROR("flow is NULL\n");
		return -1;
	}

	p = (const unsigned char *)flow->l4_data;
	data_len = flow->l4_len;

	if (!p || data_len < 5) {
		/* 对后续分片，仍然给宽松扫描一个机会 */
		if (flow->client_hello)
			return dpi_https_proto_loose(flow);
		return -1;
	}

	/* 严格模式：当前 skb 从 TLS Handshake record 开始 */
	if (p[0] == 0x16 && p[1] == 0x03) {
		rec_len = jmx_get_be16(p + 3);

		/* 当前 skb 没装下完整 record，记住 client_hello，后续分片走宽松扫描 */
		if (rec_len + 5 > data_len) {
			flow->client_hello = 1;
			return dpi_https_proto_loose(flow);
		}

		pos = 5;
		if (pos + 4 > data_len)
			return -1;

		/* HandshakeType = client_hello */
		if (p[pos] != 0x01) {
			if (flow->client_hello)
				return dpi_https_proto_loose(flow);
			return -1;
		}

		hs_len = jmx_get_be24(p + pos + 1);
		pos += 4;
		end = pos + hs_len;

		if (end > data_len) {
			flow->client_hello = 1;
			return dpi_https_proto_loose(flow);
		}

		/* client_version(2) + random(32) */
		if (pos + 34 > end)
			return -1;
		pos += 34;

		/* session_id */
		if (pos + 1 > end)
			return -1;
		sid_len = p[pos];
		pos += 1 + sid_len;
		if (pos > end)
			return -1;

		/* cipher_suites */
		if (pos + 2 > end)
			return -1;
		cs_len = jmx_get_be16(p + pos);
		pos += 2 + cs_len;
		if (pos > end)
			return -1;

		/* compression_methods */
		if (pos + 1 > end)
			return -1;
		comp_len = p[pos];
		pos += 1 + comp_len;
		if (pos > end)
			return -1;

		/* extensions */
		if (pos + 2 > end) {
			flow->client_hello = 1;
			return dpi_https_proto_loose(flow);
		}
		ext_len = jmx_get_be16(p + pos);
		pos += 2;
		if (pos + ext_len > end) {
			flow->client_hello = 1;
			return dpi_https_proto_loose(flow);
		}

		while (pos + 4 <= end) {
			ext_type = jmx_get_be16(p + pos);
			ext_size = jmx_get_be16(p + pos + 2);
			pos += 4;

			if (pos + ext_size > end)
				return -1;

			if (ext_type == 0x0000) { /* server_name */
				sni_end = pos + ext_size;

				if (pos + 2 > sni_end)
					return -1;
				list_len = jmx_get_be16(p + pos);
				pos += 2;

				if (pos + list_len > sni_end)
					return -1;

				while (pos + 3 <= sni_end) {
					name_type = p[pos];
					name_len = jmx_get_be16(p + pos + 1);
					pos += 3;

					if (pos + name_len > sni_end)
						return -1;

					if (name_type == 0x00 &&
					    name_len >= MIN_HOST_LEN &&
					    name_len <= MAX_HOST_LEN &&
					    check_domain((char *)p + pos, name_len)) {
						flow->https.match = AF_TRUE;
						flow->https.url_pos = (char *)p + pos;
						flow->https.url_len = name_len;
						flow->client_hello = 0;
						return 0;
					}

					pos += name_len;
				}

				return -1;
			}

			pos += ext_size;
		}
	}

	/* 严格模式没命中时，给宽松模式一次机会：
	 * 1) 之前已经标记过 client_hello
	 * 2) 当前本身就是 443 流量
	 */
	if (flow->client_hello || flow->dport == 443 || flow->sport == 443)
		return dpi_https_proto_loose(flow);

	return -1;
}

void dpi_http_proto(flow_info_t *flow)
{
	int i = 0;
	int start = 0;
	char *data = NULL;
	int data_len = 0;
	if (!flow)
	{
		AF_ERROR("flow is null\n");
		return;
	}
	if (flow->l4_protocol != IPPROTO_TCP)
	{
		return;
	}

	data = flow->l4_data;
	data_len = flow->l4_len;
	if (data_len < MIN_HTTP_DATA_LEN)
	{
		return;
	}

	for (i = 0; i < data_len; i++)
	{
		if (data[i] == 0x0d && data[i + 1] == 0x0a)
		{
			if (0 == memcmp(&data[start], "POST ", 5))
			{
				flow->http.match = AF_TRUE;
				flow->http.method = HTTP_METHOD_POST;
				flow->http.url_pos = data + start + 5;
				flow->http.url_len = i - start - 5;
			}
			else if (0 == memcmp(&data[start], "GET ", 4))
			{
				flow->http.match = AF_TRUE;
				flow->http.method = HTTP_METHOD_GET;
				flow->http.url_pos = data + start + 4;
				flow->http.url_len = i - start - 4;
			}
			else if (0 == memcmp(&data[start], "Host:", 5))
			{
				flow->http.host_pos = data + start + 6;
				flow->http.host_len = i - start - 6;
			}
			if (data[i + 2] == 0x0d && data[i + 3] == 0x0a)
			{
				flow->http.data_pos = data + i + 4;
				flow->http.data_len = data_len - i - 4;
				break;
			}

			start = i + 2;
		}
	}
}

static void dump_http_flow_info(http_proto_t *http)
{
	if (!http)
	{
		AF_ERROR("http ptr is NULL\n");
		return;
	}
	if (!http->match)
		return;
	if (http->method == HTTP_METHOD_GET)
	{
		printk("Http method: " HTTP_GET_METHOD_STR "\n");
	}
	else if (http->method == HTTP_METHOD_POST)
	{
		printk("Http method: " HTTP_POST_METHOD_STR "\n");
	}
	if (http->url_len > 0 && http->url_pos)
	{
		dump_str("Request url", http->url_pos, http->url_len);
	}

	if (http->host_len > 0 && http->host_pos)
	{
		dump_str("Host", http->host_pos, http->host_len);
	}

	printk("--------------------------------------------------------\n\n\n");
}

static void dump_https_flow_info(https_proto_t *https)
{
	if (!https)
	{
		AF_ERROR("https ptr is NULL\n");
		return;
	}
	if (!https->match)
		return;

	if (https->url_len > 0 && https->url_pos)
	{
		dump_str("https server name", https->url_pos, https->url_len);
	}

	printk("--------------------------------------------------------\n\n\n");
}
static void dump_flow_info(flow_info_t *flow)
{
	if (!flow)
	{
		AF_ERROR("flow is null\n");
		return;
	}
	if (flow->l4_len > 0)
	{
		AF_LMT_INFO("src=" NIPQUAD_FMT ",dst=" NIPQUAD_FMT ",sport: %d, dport: %d, data_len: %d\n",
					NIPQUAD(flow->src), NIPQUAD(flow->dst), flow->sport, flow->dport, flow->l4_len);
	}

	if (flow->l4_protocol == IPPROTO_TCP)
	{
		if (AF_TRUE == flow->http.match)
		{
			printk("-------------------http protocol-------------------------\n");
			printk("protocol:TCP , sport: %-8d, dport: %-8d, data_len: %-8d\n",
				   flow->sport, flow->dport, flow->l4_len);
			dump_http_flow_info(&flow->http);
		}
		if (AF_TRUE == flow->https.match)
		{
			printk("-------------------https protocol-------------------------\n");
			dump_https_flow_info(&flow->https);
		}
	}
}


char *k_memstr(char *data, char *str, int size)
{
	char *p;
	char len = strlen(str);
	for (p = data; p <= (data - len + size); p++)
	{
		if (memcmp(p, str, len) == 0)
			return p; 
	}
	return NULL;
}

int af_match_by_pos(flow_info_t *flow, af_feature_node_t *node)
{
	int i;
	unsigned int pos = 0;

	if (!flow || !node)
		return AF_FALSE;
	if (node->pos_num > 0)
	{
		
		for (i = 0; i < node->pos_num && i < MAX_POS_INFO_PER_FEATURE; i++)
		{

			if (node->pos_info[i].pos < 0)
			{
				pos = flow->l4_len + node->pos_info[i].pos;
			}
			else
			{
				pos = node->pos_info[i].pos;
			}
			if (pos >= flow->l4_len)
			{
				return AF_FALSE;
			}
			if (flow->l4_data[pos] != node->pos_info[i].value)
			{
				return AF_FALSE;
			}
			else{
				AF_DEBUG("match pos[%d] = %x\n", pos, node->pos_info[i].value);
			}
		}
		if (strlen(node->search_str) > 0){
			if (k_memstr(flow->l4_data, node->search_str, flow->l4_len)){
				AF_DEBUG("match by search str, appid=%d, search_str=%s\n", node->app_id, node->search_str);
				return AF_TRUE;
			}
			else{
				return AF_FALSE;
			}
		}
		return AF_TRUE;
	}
	return AF_FALSE;
}

static void normalize_host(char *s)
{
	char *p;
	size_t len;

	if (!s || !*s)
		return;

	/* 去掉前后空白 */
	k_trim(s);

	/* 全转小写 */
	for (p = s; *p; p++) {
		if (*p >= 'A' && *p <= 'Z')
			*p = *p - 'A' + 'a';
	}

	len = strlen(s);

	/* 去掉末尾的 '.' */
	while (len > 0 && s[len - 1] == '.') {
		s[len - 1] = '\0';
		len--;
	}

	/* 去掉 host:port 里的端口，仅处理普通域名 */
	p = strchr(s, ':');
	if (p && strchr(s, '.') != NULL)
		*p = '\0';
}

static int is_regex_pattern(const char *s)
{
	if (!s)
		return 0;

	while (*s) {
		switch (*s) {
		case '^':
		case '$':
		case '[':
		case ']':
		case '(':
		case ')':
		case '+':
		case '?':
		case '|':
		case '\\':
			return 1;
		default:
			break;
		}
		s++;
	}
	return 0;
}

static int host_suffix_match(const char *host, const char *domain)
{
	size_t hlen, dlen;

	if (!host || !domain)
		return AF_FALSE;

	hlen = strlen(host);
	dlen = strlen(domain);

	if (hlen < dlen)
		return AF_FALSE;

	/* 完全相等 */
	if (!strcmp(host, domain))
		return AF_TRUE;

	/* 子域名匹配，必须是 ".domain" 结尾 */
	if (hlen > dlen &&
	    !strcmp(host + hlen - dlen, domain) &&
	    host[hlen - dlen - 1] == '.')
		return AF_TRUE;

	return AF_FALSE;
}

static int host_wildcard_match(const char *host, const char *pattern)
{
	/* pattern = "*.x.com" */
	const char *suffix;
	size_t hlen, slen;

	if (!host || !pattern)
		return AF_FALSE;

	if (strncmp(pattern, "*.", 2) != 0)
		return AF_FALSE;

	suffix = pattern + 2;   /* x.com */
	hlen = strlen(host);
	slen = strlen(suffix);

	/* 至少得是 a.x.com，不能直接是 x.com */
	if (hlen <= slen)
		return AF_FALSE;

	if (strcmp(host + hlen - slen, suffix) != 0)
		return AF_FALSE;

	/* 前一个字符必须是 '.' */
	if (host[hlen - slen - 1] != '.')
		return AF_FALSE;

	return AF_TRUE;
}

static int safe_host_match(const char *pattern_in, const char *host_in)
{
	char pattern[MAX_HOST_URL_LEN] = {0};
	char host[MAX_URL_MATCH_LEN] = {0};

	if (!pattern_in || !host_in)
		return AF_FALSE;

	strscpy(pattern, pattern_in, sizeof(pattern));
	strscpy(host, host_in, sizeof(host));

	normalize_host(pattern);
	normalize_host(host);

	if (pattern[0] == '\0' || host[0] == '\0')
		return AF_FALSE;

	/* 显式 *.x.com */
	if (!strncmp(pattern, "*.", 2))
		return host_wildcard_match(host, pattern);

	/* 明显正则才走 regex */
	if (is_regex_pattern(pattern))
		return regexp_match(pattern, host);

	/* 普通域名默认按边界后缀匹配 */
	return host_suffix_match(host, pattern);
}

static int af_feature_is_fallback_only(const af_feature_node_t *node)
{
	if (!node)
		return 0;

	return (node->request_url[0] == '\0' &&
		node->host_url[0] == '\0' &&
		node->pos_num == 0 &&
		node->search_str[0] == '\0');
}

static int af_is_shared_cdn_pattern(const char *pattern_in)
{
	char pattern[MAX_HOST_URL_LEN] = {0};

	static const char *shared_suffix[] = {
//		"myqcloud.com",
//		"aliyuncs.com",
//		"amazonaws.com",
//		"cloudfront.net",
//		"bytecdn.cn",
//		"bytedanceapi.com",
//		"bytegecko.com",
//		"bytetos.com",
//		"akadns.net",
//		"akamaihd.net",
//		"akamai.net",
//		"cdn20.com",
//		"00cdn.com",
//		"qpic.cn",
//		"gtimg.com",
//		"bdstatic.com",
//		"bcebos.com",
//		"icloud-content.com",
//		"hicloud.com",
//		"hwclouds-dns.com"
        "only-placeholder.com"
	};
	int i;

	if (!pattern_in || !pattern_in[0])
		return 0;

	strscpy(pattern, pattern_in, sizeof(pattern));
	normalize_host(pattern);

	if (!strncmp(pattern, "*.", 2))
		memmove(pattern, pattern + 2, strlen(pattern + 2) + 1);

	for (i = 0; i < ARRAY_SIZE(shared_suffix); i++) {
		if (!strcmp(pattern, shared_suffix[i]))
			return 1;
	}

	return 0;
}

static int af_allow_port_only_rule(const af_feature_node_t *node)
{
	if (!node)
		return 0;

	switch (node->app_id) {
	case 11001:
	case 11002:
	case 1000003:
    case 1000005:
		return 1;
	default:
		return 0;
	}
}

static int af_match_score(flow_info_t *flow, af_feature_node_t *node)
{
	char host_buf[MAX_URL_MATCH_LEN] = {0};
	char req_buf[MAX_URL_MATCH_LEN] = {0};
	int host_len = 0;

	if (!flow || !node)
		return 0;

	if (node->proto > 0 && flow->l4_protocol != node->proto)
		return 0;

	if (flow->l4_len == 0)
		return 0;

	if (node->sport != 0 && flow->sport != node->sport)
		return 0;

	if (!af_match_port(&node->dport_info, flow->dport))
		return 0;

	/* 1. request_url 最高优先级 */
	if (node->request_url[0]) {
		if (flow->http.match == AF_TRUE && flow->http.url_pos) {
			if (flow->http.url_len >= sizeof(req_buf))
				strncpy(req_buf, flow->http.url_pos, sizeof(req_buf) - 1);
			else
				strncpy(req_buf, flow->http.url_pos, flow->http.url_len);

			if (req_buf[0] && regexp_match(node->request_url, req_buf))
				return 10000 + strlen(node->request_url);
		}
	}

	/* 2. host_url 次高优先级 */
	if (node->host_url[0]) {
		if (flow->https.match == AF_TRUE && flow->https.url_pos) {
			if (flow->https.url_len >= sizeof(host_buf))
				strncpy(host_buf, flow->https.url_pos, sizeof(host_buf) - 1);
			else
				strncpy(host_buf, flow->https.url_pos, flow->https.url_len);
		} else if (flow->http.match == AF_TRUE && flow->http.host_pos) {
			if (flow->http.host_len >= sizeof(host_buf))
				strncpy(host_buf, flow->http.host_pos, sizeof(host_buf) - 1);
			else
				strncpy(host_buf, flow->http.host_pos, flow->http.host_len);
		}

		if (host_buf[0] && safe_host_match(node->host_url, host_buf)) {
			host_len = strlen(node->host_url);

			/* 共享 CDN/云厂商域名，没有其它佐证，不直接认 app */
			if (af_is_shared_cdn_pattern(node->host_url) &&
			    node->request_url[0] == '\0' &&
			    node->pos_num == 0 &&
			    node->search_str[0] == '\0')
				return 0;

			if (!strncmp(node->host_url, "*.", 2))
				return 8000 + host_len;
			else if (is_regex_pattern(node->host_url))
				return 7000 + host_len;
			else
				return 9000 + host_len;
		}
	}

	/* 3. pos + search */
	if (node->pos_num > 0) {
		if (af_match_by_pos(flow, node))
			return 6000 + node->pos_num * 10 + strlen(node->search_str);
		return 0;
	}

	/* 4. 纯 search_str */
	if (node->search_str[0]) {
		if (k_memstr(flow->l4_data, node->search_str, flow->l4_len))
			return 5000 + strlen(node->search_str);
		return 0;
	}

	/* 5. 纯端口/纯协议兜底 */
	if (af_feature_is_fallback_only(node)) {
		if (af_allow_port_only_rule(node))
			return 1000;
		return 0;
	}

	return 0;
}

int af_match_by_url(flow_info_t *flow, af_feature_node_t *node)
{
	char reg_url_buf[MAX_URL_MATCH_LEN] = {0};

	if (!flow || !node)
		return AF_FALSE;

	if (flow->https.match == AF_TRUE && flow->https.url_pos)
	{
		if (flow->https.url_len >= MAX_URL_MATCH_LEN)
			strncpy(reg_url_buf, flow->https.url_pos, MAX_URL_MATCH_LEN - 1);
		else
			strncpy(reg_url_buf, flow->https.url_pos, flow->https.url_len);
	}
	else if (flow->http.match == AF_TRUE && flow->http.host_pos)
	{
		if (flow->http.host_len >= MAX_URL_MATCH_LEN)
			strncpy(reg_url_buf, flow->http.host_pos, MAX_URL_MATCH_LEN - 1);
		else
			strncpy(reg_url_buf, flow->http.host_pos, flow->http.host_len);
	}
	if (strlen(reg_url_buf) > 0 &&
    strlen(node->host_url) > 0 &&
    safe_host_match(node->host_url, reg_url_buf))
	{
		AF_DEBUG("match url:%s	 reg = %s, appid=%d\n",
				 reg_url_buf, node->host_url, node->app_id);
		return AF_TRUE;
	}


	if (flow->http.match == AF_TRUE && flow->http.url_pos)
	{
		memset(reg_url_buf, 0x0, sizeof(reg_url_buf));
		if (flow->http.url_len >= MAX_URL_MATCH_LEN)
			strncpy(reg_url_buf, flow->http.url_pos, MAX_URL_MATCH_LEN - 1);
		else
			strncpy(reg_url_buf, flow->http.url_pos, flow->http.url_len);
		if (strlen(reg_url_buf) > 0 && strlen(node->request_url) && regexp_match(node->request_url, reg_url_buf))
		{
			AF_DEBUG("match request:%s   reg:%s appid=%d\n",
					 reg_url_buf, node->request_url, node->app_id);
			return AF_TRUE;
		}
	}
	return AF_FALSE;
}

int af_match_one(flow_info_t *flow, af_feature_node_t *node)
{
	return af_match_score(flow, node) > 0 ? AF_TRUE : AF_FALSE;
}

int match_feature(flow_info_t *flow)
{
	af_feature_node_t *node;
	af_feature_node_t *best = NULL;
	int best_score = 0;

	if (!flow)
		return AF_FALSE;

	feature_list_read_lock();

	list_for_each_entry(node, &af_feature_head, head)
	{
		int score = af_match_score(flow, node);

		if (score <= 0)
			continue;

		if (!best || score > best_score) {
			best = node;
			best_score = score;

			/* request_url 命中已经非常强，可以提前结束 */
			if (best_score >= 10000)
				break;
		}
	}

	if (best) {
		AF_LMT_INFO("match feature, appid=%d, score=%d, feature=%s\n",
			    best->app_id, best_score, best->feature);
		flow->app_id = best->app_id;
		flow->feature = best;
		strncpy(flow->app_name, best->app_name, sizeof(flow->app_name) - 1);
		feature_list_read_unlock();
		return AF_TRUE;
	}

	feature_list_read_unlock();
	return AF_FALSE;
}

int match_app_filter_rule(int appid, af_client_info_t *client)
{
	int rule_id = 0;

	if (!g_appfilter_enable) {
		return AF_FALSE;
	}
	
	if (jmx_match_app_filter_whitelist(client->mac)){
		AF_LMT_DEBUG("match appfilter whitelist mac = " MAC_FMT "\n", MAC_ARRAY(client->mac));
		return AF_FALSE;
	}

	if (jmx_match_app_filter_rule_record(appid, client->mac, &rule_id)) {
		AF_LMT_INFO("drop appid = %d, rule_id = %d\n", appid, rule_id);
		return AF_TRUE;
	}
	return AF_FALSE;
}

int match_mac_filter_rule(af_client_info_t *client)
{

	if (!g_mac_filter_enable) {
		return AF_FALSE;
	}
	
	if (jmx_match_mac_filter_whitelist(client->mac)){
		AF_LMT_DEBUG("match macfilter whitelist mac = " MAC_FMT "\n", MAC_ARRAY(client->mac));
		return AF_FALSE;
	}

	mac_filter_rule_t *rule = jmx_match_mac_filter_rule(client->mac);
	if (rule) {
		AF_LMT_INFO("drop mac, rule_id = %d, mac = " MAC_FMT "\n", rule->rule_id, MAC_ARRAY(client->mac));
		return AF_TRUE;
	}
	return AF_FALSE;
}

static int af_match_is_reliable(flow_info_t *flow)
{
    if (!flow)
        return 0;

    if (!flow->feature)
        return 0;

    /* 只认强特征 */
    if (flow->feature->host_url[0])
        return 1;

    if (flow->feature->request_url[0])
        return 1;

    if (flow->feature->pos_num > 0)
        return 1;

    if (flow->feature->search_str[0])
        return 1;

    /* 纯端口/纯协议/空规则，不进统计 */
    return 0;
}

int af_update_client_app_info(af_client_info_t *node, int app_id, int drop,
			      int from_conntrack, int is_http)
{
	app_visit_info_t *info;
	if (!node || app_id <= 0)
		return -1;

	spin_lock_bh(&node->visit_info_lock);

	info = get_or_create_visit_info(node, app_id);
	if (!info){
		spin_unlock_bh(&node->visit_info_lock);
		return -1;
	}
	
	info->total_num++;
	if (drop)
		info->drop_num++;
	info->latest_time = af_get_timestamp_sec();
	info->latest_action = drop;

if (!from_conntrack) {
	info->conn_count++;
	info->is_http = is_http;
}

/* 当前活跃 app 不要等 3 次，命中就立刻刷新 */
node->visiting.app_time = af_get_timestamp_sec();
node->visiting.visiting_app = app_id;
	
	spin_unlock_bh(&node->visit_info_lock);
	return 0;
}

int af_send_msg_to_user(char *pbuf, uint16_t len);
int af_match_bcast_packet(flow_info_t *f)
{
	if (!f)
		return 0;
	if (0 == f->src || 0 == f->dst || 0xffffffff == f->dst || 0 == f->dst)
		return 1;
	return 0;
}

int af_match_local_packet(flow_info_t *f)
{
	if (!f)
		return 0;
	if (0x0100007f == f->src || 0x0100007f == f->dst)
	{
		return 1;
	}
	return 0;
}


static int af_match_router_local_packet(flow_info_t *f)
{
	if (!f || !f->dst)
		return 0;
	return inet_addr_type(&init_net, f->dst) == RTN_LOCAL;
}

int update_url_visiting_info(af_client_info_t *client, flow_info_t *flow)
{
	char *host = NULL;
	unsigned int len = 0;
	if (!client || !flow)
		return -1;
	
	if (flow->https.match){
		host = flow->https.url_pos;

		len = flow->https.url_len;
	}
	else if (flow->http.match){
		host = flow->http.host_pos;
		len = flow->http.host_len;
	}
	if (!host || len < MIN_REPORT_URL_LEN || len >= MAX_REPORT_URL_LEN)
		return -1;

	memcpy(client->visiting.visiting_url, host, len);
	client->visiting.visiting_url[len] = 0x0; 
	client->visiting.url_time = af_get_timestamp_sec();
	return 0;
}

static int should_try_host_extract(flow_info_t *flow, unsigned long long total_packets, int client_hello)
{
	if (!flow)
		return 0;

	/* 先放宽，只要是 TCP 就尝试，先把 Host 刷新链路跑通 */
	if (flow->l4_protocol != IPPROTO_TCP)
		return 0;

	return 1;
}

int dpi_main(struct sk_buff *skb, flow_info_t *flow)
{
	dpi_http_proto(flow);
	dpi_https_proto(flow);
	if (TEST_MODE())
		dump_flow_info(flow);


	return 0;
}

static int af_get_smac(struct sk_buff *skb, u_int8_t *smac)
{
	const struct ethhdr *ethhdr;

	if (!skb || !smac)
		return -EINVAL;

	eth_zero_addr(smac);

	/* 没有可用的 MAC 头，直接失败，不再读 skb->cb[40] 这种不可靠缓存 */
	if (!skb_mac_header_was_set(skb))
		return -ENOENT;

	/* 确保以太网头可读 */
	if (!pskb_may_pull(skb, ETH_HLEN))
		return -EINVAL;

	ethhdr = eth_hdr(skb);
	if (!ethhdr)
		return -ENOENT;

	if (!is_valid_ether_addr(ethhdr->h_source))
		return -ENOENT;

	ether_addr_copy(smac, ethhdr->h_source);
	return 0;
}
int is_ipv4_broadcast(uint32_t ip)
{
	return (ip & 0x00FFFFFF) == 0x00FFFFFF;
}

int is_ipv4_multicast(uint32_t ip)
{
	return (ip & 0xF0000000) == 0xE0000000;
}
int af_check_bcast_ip(flow_info_t *f)
{

	if (0 == f->src || 0 == f->dst)
		return 1;
	if (is_ipv4_broadcast(ntohl(f->src)) || is_ipv4_broadcast(ntohl(f->dst)))
	{
		return 1;
	}
	if (is_ipv4_multicast(ntohl(f->src)) || is_ipv4_multicast(ntohl(f->dst)))
	{
		return 1;
	}

	return 0;
}

void send_reset_packet(struct sk_buff *skb, flow_info_t *flow){

	if (g_tcp_rst && flow->l4_protocol == IPPROTO_TCP){
		if (skb->protocol == htons(ETH_P_IP) && g_tcp_rst){
			#if LINUX_VERSION_CODE > KERNEL_VERSION(5,10,197)
				nf_send_reset(&init_net, skb->sk, skb, NF_INET_PRE_ROUTING);
			#elif LINUX_VERSION_CODE > KERNEL_VERSION(4,4,1)


			#else
				nf_send_reset(skb, NF_INET_PRE_ROUTING);
			#endif	
		}
	}
}


u_int32_t check_app_action_changed(int action, u_int32_t app_id, af_client_info_t *client)
{
	u_int8_t drop = 0;
	int changed = 0;
	u_int32_t max_jiffies = 30 * HZ;
	u_int32_t interval_jiffies = jiffies - g_appfilter_update_jiffies;

	if (interval_jiffies < max_jiffies){     
		AF_LMT_DEBUG("config changed, update app action\n");
		if (match_app_filter_rule(app_id, client)){
			AF_LMT_DEBUG("match appid = %d, action = %d\n", app_id, action);
			if (!action) // accept --> drop
				changed = 1;
		}    
		else{
			if (action) // drop --> accept
				changed = 1;
		}    
	} 
	return changed;
}

u_int32_t jmx_hook_bypass_handle(struct sk_buff *skb, struct net_device *dev)
{
	flow_info_t flow;
	af_conn_t *conn;
	u_int8_t smac[ETH_ALEN];
	af_client_info_t *client = NULL;
	u_int32_t ret = NF_ACCEPT;
	u_int8_t malloc_data = 0;

	if (!skb || !dev)
		return NF_ACCEPT;
	if (0 == jmx_lan_ip || 0 == jmx_lan_mask)
		return NF_ACCEPT;
	if (strstr(dev->name, "docker"))
		return NF_ACCEPT;

	memset((char *)&flow, 0x0, sizeof(flow_info_t));
	if (parse_flow_proto(skb, &flow) < 0)
		return NF_ACCEPT;

	if (flow.src || flow.dst)
	{
		if (jmx_lan_ip == flow.src || jmx_lan_ip == flow.dst)
		{
			return NF_ACCEPT;
		}
		if (af_check_bcast_ip(&flow) || af_match_local_packet(&flow))
			return NF_ACCEPT;

		if ((flow.src & jmx_lan_mask) != (jmx_lan_ip & jmx_lan_mask))
		{
			return NF_ACCEPT;
		}
	}
	else
	{
		return NF_ACCEPT;
	}
if (af_get_smac(skb, smac) < 0)
	return NF_ACCEPT;

AF_CLIENT_LOCK_W();
client = find_and_add_af_client(smac);
if (!client)
{
	AF_CLIENT_UNLOCK_W();
	return NF_ACCEPT;
}
	client->update_jiffies = jiffies;
	if (flow.src)
		client->ip = flow.src;
	AF_CLIENT_UNLOCK_W();


	spin_lock(&af_conn_lock);
   	conn = af_conn_find_and_add(flow.src, flow.dst, flow.sport, flow.dport, flow.l4_protocol);
	if (!conn){
		return NF_ACCEPT;
	}

	conn->last_jiffies = jiffies;
	conn->total_pkts++;
	spin_unlock(&af_conn_lock);


	if (conn->app_id == 0 && conn->drop == 1){
		send_reset_packet(skb, &flow);
		return NF_DROP;
	}

if (conn->app_id != 0)
{
	flow.app_id = conn->app_id;
	flow.drop = conn->drop;
	flow.client_hello = conn->client_hello;
	flow.ignore = conn->ignore;

	if (check_app_action_changed(flow.drop, flow.app_id, client)) {
		flow.drop = !flow.drop;
		AF_LMT_DEBUG("update appid %d action, new action = %s\n",
			     flow.app_id, flow.drop ? "drop" : "accept");
	}

	if (should_try_host_extract(&flow, conn->total_pkts, flow.client_hello)) {
		AF_DEBUG("bypass host try: appid=%u proto=%u sport=%u dport=%u pkts=%u hello=%u\n",
			 flow.app_id, flow.l4_protocol, flow.sport, flow.dport,
			 conn->total_pkts, flow.client_hello);

		if (skb_is_nonlinear(skb) && flow.l4_len < MAX_AF_SUPPORT_DATA_LEN) {
			flow.l4_data = read_skb(skb, flow.l4_data - skb->data, flow.l4_len);
			if (!flow.l4_data)
				return NF_ACCEPT;
			AF_LMT_DEBUG("##extract host from nonlinear skb, len = %d\n", flow.l4_len);
			malloc_data = 1;
		}

		dpi_main(skb, &flow);
		conn->client_hello = flow.client_hello;

		AF_DEBUG("bypass host result: appid=%u http=%u https=%u host_len=%u sni_len=%u\n",
			 flow.app_id, flow.http.match, flow.https.match,
			 flow.http.host_len, flow.https.url_len);

		update_url_visiting_info(client, &flow);
		af_update_active_host_list(client, &flow);

		if (flow.app_id > 0 && (flow.http.match || flow.https.match)) {
			if (!conn->ignore)
				af_update_active_app_list(client, &flow);
		}
	}
}
dpi_main(skb, &flow);
conn->client_hello = flow.client_hello;
	/* 已有 app_id 时，若当前包拿到了更强的 HTTP/HTTPS 特征，允许升级 */
	if (flow.http.match || flow.https.match) {
		flow_info_t cand = flow;

		cand.app_id = 0;
		cand.feature = NULL;
		cand.drop = 0;

		if (match_feature(&cand) &&
		    af_match_is_reliable(&cand) &&
		    cand.app_id > 0 &&
		    cand.app_id != conn->app_id) {
			AF_LMT_INFO("bypass upgrade appid: %u -> %u\n",
				    conn->app_id, cand.app_id);

			conn->app_id = cand.app_id;
			conn->ignore = (cand.feature && cand.feature->ignore) ? 1 : 0;

			flow.app_id = cand.app_id;
			flow.feature = cand.feature;
			flow.ignore = conn->ignore;
			strncpy(flow.app_name, cand.app_name,
				sizeof(flow.app_name) - 1);
		}
	}
else{
	if (g_by_pass_accl) {
		if (conn->total_pkts > 256)	{
			return NF_ACCEPT;
		}
	}

	if (skb_is_nonlinear(skb) && flow.l4_len < MAX_AF_SUPPORT_DATA_LEN)
	{
		flow.l4_data = read_skb(skb, flow.l4_data - skb->data, flow.l4_len);
		if (!flow.l4_data)
			return NF_ACCEPT;
		AF_LMT_DEBUG("##match nonlinear skb, len = %d\n", flow.l4_len);
		malloc_data = 1;
	}

	flow.client_hello = conn->client_hello;
	if (flow.client_hello > 0)
		AF_LMT_DEBUG("client hello is %d\n", flow.client_hello);

	dpi_main(skb, &flow);
	conn->client_hello = flow.client_hello;
	update_url_visiting_info(client, &flow);
	af_update_active_host_list(client, &flow);

	/* DEBUG: unconditional printk */
	if (flow.http.match || flow.https.match)
		JMX_DEBUG_RATELIMITED(2, "jmx_fallback: appid=%u ignore=%d http=%u https=%u host_len=%u sni_len=%u\n",
			flow.app_id, flow.ignore, flow.http.match, flow.https.match,
			flow.http.host_len, flow.https.url_len);

if (match_feature(&flow)){
    conn->app_id = flow.app_id;
    conn->drop = flow.drop;

    if (flow.feature && flow.feature->ignore){
        AF_LMT_DEBUG("match ignore feature, feature = %s, appid = %d\n",
                     flow.feature->feature, flow.app_id);
        conn->ignore = 1;
    } else {
        conn->ignore = 0;
    }

    conn->state = AF_CONN_DPI_FINISHED;

    if (!conn->ignore)
        af_update_active_app_list(client, &flow);

    /* 只在首次可靠命中时记一次统计 */
    if (g_record_enable && !conn->ignore && af_match_is_reliable(&flow)) {
        int is_http = (flow.http.match || flow.https.match) ? 1 : 0;
        af_update_client_app_info(client, flow.app_id, flow.drop, 0, is_http);
    }

    if (match_app_filter_rule(flow.app_id, client)) {
        flow.drop = 1;
        conn->drop = 1;
        AF_LMT_INFO("##Drop App filter rule, appid = %d, mac = " MAC_FMT "\n",
                    flow.app_id, MAC_ARRAY(client->mac));
        send_reset_packet(skb, &flow);
    }
}
}
	
	if (!flow.drop && match_mac_filter_rule(client)) {
		flow.drop = 1;
		conn->drop = 1;
		AF_LMT_INFO("##Drop MAC filter rule, mac = " MAC_FMT "\n", 
				MAC_ARRAY(client->mac));
		send_reset_packet(skb, &flow);
	}

// if (g_record_enable){
// 	if (!conn->ignore){
// 		int is_http = (flow.http.match || flow.https.match) ? 1 : 0;
// 		af_update_client_app_info(client, flow.app_id, flow.drop, 0, is_http);
// 
// 		if (flow.app_id > 0 && (flow.http.match || flow.https.match))
// 			af_update_active_app_list(client, &flow);
// 	}
// }

	if (flow.drop)
	{
		AF_LMT_INFO("drop appid = %d\n", flow.app_id);
		ret = NF_DROP;
	}

	if (malloc_data)
	{
		if (flow.l4_data)
		{
			kfree(flow.l4_data);
		}
	}
	return ret;
}


#if IS_ENABLED(CONFIG_NF_CONNTRACK_CHAIN_EVENTS)
static bool jmx_route_prepare_lifecycle(struct nf_conn *ct)
{
	struct nf_conntrack_ecache *ecache;

	if (!ct)
		return false;
	ecache = nf_ct_ecache_find(ct);
	if (!ecache && !nf_ct_is_confirmed(ct)) {
		nf_ct_ecache_ext_add(ct, BIT(IPCT_DESTROY), 0, GFP_ATOMIC);
		ecache = nf_ct_ecache_find(ct);
		/* nf_conntrack_events=2 skips this allocation without a ctnetlink
		 * listener, but JMX still needs DESTROY for active_conn accounting. */
		if (!ecache)
			ecache = nf_ct_ext_add(ct, NF_CT_EXT_ECACHE, GFP_ATOMIC);
	}
	if (!ecache)
		return false;

	ecache->ctmask |= BIT(IPCT_DESTROY);
	return true;
}
#endif

static bool jmx_route_maybe_bind(struct nf_conn *ct, const flow_info_t *flow)
{
	u32 fwmark = 0;
	u32 wan_generation = 0;
	u8 wan_id = 0;
	u8 route_source = JMX_ROUTE_SRC_DEFAULT;
	u16 rule_prio = 0;
	int select_rc;
	bool bound = false;
#if IS_ENABLED(CONFIG_NF_CONNTRACK_CHAIN_EVENTS)
	bool track_lifecycle;
#endif

	if (!ct || !flow)
		return false;
	if (flow->l4_protocol != IPPROTO_TCP && flow->l4_protocol != IPPROTO_UDP)
		return false;
	if (!(flow->src6 && flow->dst6) && (!flow->src || !flow->dst))
		return false;
	if (READ_ONCE(ct->jmx_data.route_mark))
		return false;

	spin_lock_bh(&ct->lock);
	if (ct->jmx_data.route_mark)
		goto out_unlock;
#if IS_ENABLED(CONFIG_NF_CONNTRACK_CHAIN_EVENTS)
	track_lifecycle = jmx_route_prepare_lifecycle(ct);
	if (flow->src6 && flow->dst6) {
		if (track_lifecycle)
			select_rc = jmx_route_select_wan6_acquire(
				flow->src6, flow->dst6, flow->sport, flow->dport,
				flow->l4_protocol, flow->app_id, &fwmark, &wan_id,
				&route_source, &rule_prio, &wan_generation);
		else
			select_rc = jmx_route_select_wan6(
				flow->src6, flow->dst6, flow->sport, flow->dport,
				flow->l4_protocol, flow->app_id, &fwmark, &wan_id,
				&route_source, &rule_prio);
	} else if (track_lifecycle) {
		select_rc = jmx_route_select_wan_acquire(
			flow->src, flow->dst, flow->sport, flow->dport,
			flow->l4_protocol, flow->app_id, &fwmark, &wan_id,
			&route_source, &rule_prio, &wan_generation);
	} else {
		select_rc = jmx_route_select_wan(
			flow->src, flow->dst, flow->sport, flow->dport,
			flow->l4_protocol, flow->app_id, &fwmark, &wan_id,
			&route_source, &rule_prio);
	}
#else
	if (flow->src6 && flow->dst6)
		select_rc = jmx_route_select_wan6(
			flow->src6, flow->dst6, flow->sport, flow->dport,
			flow->l4_protocol, flow->app_id, &fwmark, &wan_id,
			&route_source, &rule_prio);
	else
		select_rc = jmx_route_select_wan(
			flow->src, flow->dst, flow->sport, flow->dport,
			flow->l4_protocol, flow->app_id, &fwmark, &wan_id,
			&route_source, &rule_prio);
#endif
	if (select_rc == 0 && fwmark) {
		ct->jmx_data.route_mark = fwmark;
		ct->jmx_data.route_wan_id = wan_id;
		ct->jmx_data.route_source = route_source;
		ct->jmx_data.route_wan_generation = wan_generation;
		smp_store_release(&ct->jmx_data.route_counted,
				  wan_generation ? 1 : 0);
#if defined(CONFIG_NF_CONNTRACK_MARK)
		/* Export per-flow PBR attribution to ctnetlink. Encoding:
		 * bits 31..16 = route rule priority, bits 15..0 = selected WAN id.
		 * skb->mark still carries the actual fwmark for ip rule lookup.
		 */
		ct->mark = ((u32)rule_prio << 16) | (u32)wan_id;
#endif
		JMX_DEBUG_RATELIMITED(2,
			"jmx_route: bind appid=%u wan=%u mark=0x%x source=%u rule_prio=%u\n",
			flow->app_id, wan_id, fwmark, route_source, rule_prio);
		bound = true;
	}

out_unlock:
	spin_unlock_bh(&ct->lock);
	return bound;
}

static void jmx_route_account_rx(struct nf_conn *ct,
				 enum ip_conntrack_info ctinfo, unsigned int bytes)
{
	u32 generation = 0;
	u8 wan_id = 0;

	if (!ct || !bytes || CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY)
		return;

	if (smp_load_acquire(&ct->jmx_data.route_counted)) {
		wan_id = READ_ONCE(ct->jmx_data.route_wan_id);
		generation = READ_ONCE(ct->jmx_data.route_wan_generation);
	}

	if (wan_id && generation)
		jmx_wan_flow_account_rx(wan_id, generation, bytes);
}

u_int32_t jmx_hook_gateway_handle(struct sk_buff *skb, struct net_device *dev)
{
	unsigned long long total_packets = 0;
	int v2_matched = 0;
	flow_info_t flow;
	u_int8_t smac[ETH_ALEN];
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = NULL;
	struct nf_conn_acct *acct = NULL;
	af_client_info_t *client = NULL;
	u_int32_t ret = NF_ACCEPT;
	u_int32_t app_id = 0;
	u_int8_t drop = 0;
	u_int8_t malloc_data = 0;

	(void)dev;
	if (!skb)
		return NF_ACCEPT;

	memset((char *)&flow, 0x0, sizeof(flow_info_t));
	if (parse_flow_proto(skb, &flow) < 0)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (ct == NULL)
		return NF_ACCEPT;

	/* JMX makes DPI, policy-route and drop decisions from the conntrack
	 * sideband.  Keep gateway flows out of flow-table/SFE fast paths while
	 * those decisions are attached to this nf_conn.
	 */
	ct->jmx_data.match_status |= JMX_MATCH_STATUS_NO_OFFLOAD;

	/* Tuple/carrier PBR must bind on the first forwarded packet, including a
	 * TCP SYN with no payload.  The DPI path below intentionally skips pure TCP
	 * control packets, but route rules need the fwmark before the kernel route
	 * decision.  App-id rules are still evaluated later once DPI has identified
	 * the flow because appid=0 will not match app-specific rules here.
	 */
	jmx_route_maybe_bind(ct, &flow);
	jmx_route_account_rx(ct, ctinfo, skb->len);
	if (ct->jmx_data.route_mark)
		skb->mark = ct->jmx_data.route_mark;

/* 不要因为 ct 还没 confirmed 就跳过 TCP。
 * 在 FORWARD 钩子上，HTTP 请求头 / TLS ClientHello 往往就在 confirm 之前到达。
 * 这里只跳过“没有 L4 payload 的 TCP 包”，避免白白解析纯 SYN/ACK。
 */
if (flow.l4_protocol == IPPROTO_TCP && flow.l4_len <= 0) {
	return NF_ACCEPT;
}

/* Do not classify router local management/control traffic as Internet apps. */
if (af_match_router_local_packet(&flow))
	return NF_ACCEPT;

/* Mark forwarded DNS responses (UDP sport=53) so jmxd's nft queue rule can
 * learn DNS->IP mappings with bypass protection.  Do not return NF_QUEUE from
 * the kernel hook: if jmxd is restarting, DNS would be withheld from clients. */
if (flow.l4_protocol == IPPROTO_UDP && flow.sport == 53 && flow.l4_len >= 12 &&
    !af_match_router_local_packet(&flow)) {
	ct->jmx_data.match_status |= JMX_MATCH_STATUS_RELIABLE;
	skb->mark = 0x1F000001;
	return NF_ACCEPT;
}

AF_CLIENT_LOCK_R();

if (flow.src)
	client = find_af_client_by_ip(flow.src);
if (!client && flow.dst)
	client = find_af_client_by_ip(flow.dst);

if (!client && flow.src6)
	client = find_af_client_by_ipv6(flow.src6);
if (!client && flow.dst6)
	client = find_af_client_by_ipv6(flow.dst6);

if (client)
	client->update_jiffies = jiffies;

AF_CLIENT_UNLOCK_R();

if (ct->jmx_data.app_id != 0)
{
	app_id = ct->jmx_data.app_id;
	u_int32_t orig_action = ct->jmx_data.action;
	int ct_action = ct->jmx_data.action;

	flow.ignore = (ct->jmx_data.match_status & JMX_MATCH_STATUS_IGNORE) ? 1 : 0;

	if (client && check_app_action_changed(ct_action, app_id, client)) {
		ct_action = !ct_action;
		ct->jmx_data.action = ct_action;
		AF_LMT_DEBUG("update appid %d action to %s, action = %d-->%d\n",
			     app_id, ct_action ? "drop" : "accept",
			     orig_action, ct->jmx_data.action);
	}

if (client && g_record_enable && !flow.ignore &&
	    (ct->jmx_data.match_status & JMX_MATCH_STATUS_RELIABLE)) {
		af_update_client_app_info(client, app_id, ct_action, 1, 0);
	}

	if (client && g_appfilter_enable && ct_action) {
		AF_LMT_DEBUG("drop appid = %d, ct_action = %d\n", app_id, ct_action);
		return NF_DROP;
	}
}

	if (ct->jmx_data.action){
		AF_LMT_DEBUG("ct drop\n");
		return NF_DROP;
	}

if (ct->jmx_data.app_id != 0) {
	app_id = ct->jmx_data.app_id;
	flow.app_id = app_id;
	flow.drop = ct->jmx_data.action;
	flow.ignore = (ct->jmx_data.match_status & JMX_MATCH_STATUS_IGNORE) ? 1 : 0;
} else {
	app_id = 0;
	flow.app_id = 0;
	flow.drop = 0;
	flow.ignore = 0;
}

if (ct->jmx_data.match_status & JMX_MATCH_STATUS_CLIENT_HELLO)
	flow.client_hello = 1;

/*
 * 不要因为拿不到 conntrack accounting 就直接放过。
 * 某些机型/配置下 acct 扩展可能没挂上，但我们仍然应该继续做 DPI。
 */
acct = nf_conn_acct_find(ct);
if (acct) {
	total_packets =
		(unsigned long long)atomic64_read(&acct->counter[IP_CT_DIR_ORIGINAL].packets) +
		(unsigned long long)atomic64_read(&acct->counter[IP_CT_DIR_REPLY].packets);
} else {
	/* fallback：拿不到 acct 时，给一个保守值，允许继续做首包/前几包 DPI */
	total_packets = 1;
}

if (total_packets > MAX_DPI_PKT_NUM)
	return NF_ACCEPT;

if (should_try_host_extract(&flow, total_packets,
			    (ct->jmx_data.match_status & JMX_MATCH_STATUS_CLIENT_HELLO) ? 1 : 0)) {
	AF_DEBUG("gateway host try: appid=%u proto=%u sport=%u dport=%u pkts=%llu hello=%u\n",
		 flow.app_id, flow.l4_protocol, flow.sport, flow.dport,
		 total_packets, flow.client_hello);

	if (skb_is_nonlinear(skb) && flow.l4_len < MAX_AF_SUPPORT_DATA_LEN)
	{
		flow.l4_data = read_skb(skb, flow.l4_data - skb->data, flow.l4_len);
		if (!flow.l4_data)
			return NF_ACCEPT;
		malloc_data = 1;
	}

	dpi_main(skb, &flow);

	AF_DEBUG("gateway host result: appid=%u http=%u https=%u host_len=%u sni_len=%u\n",
		 flow.app_id, flow.http.match, flow.https.match,
		 flow.http.host_len, flow.https.url_len);

if (client) {
	update_url_visiting_info(client, &flow);
	af_update_active_host_list(client, &flow);

		if (jmx_debug_at_least(3))
		pr_info_ratelimited("jmx DBG: appid=%u ignore=%d http=%u https=%u host_len=%u sni_len=%u ct_appid=%u v2=%d\n",
			flow.app_id, flow.ignore, flow.http.match, flow.https.match,
			flow.http.host_len, flow.https.url_len,
			ct->jmx_data.app_id, v2_matched);
}

	if (flow.client_hello)
		ct->jmx_data.match_status |= JMX_MATCH_STATUS_CLIENT_HELLO;
	else
		ct->jmx_data.match_status &= ~JMX_MATCH_STATUS_CLIENT_HELLO;

	/* 已有 app_id 时，允许被更强的 host/request/pos 特征升级 */
	if (ct->jmx_data.app_id != 0 && (flow.http.match || flow.https.match)) {
		flow_info_t cand = flow;

		cand.app_id = 0;
		cand.feature = NULL;
		cand.drop = 0;

		if (match_feature(&cand) &&
		    af_match_is_reliable(&cand) &&
		    cand.app_id > 0 &&
		    cand.app_id != ct->jmx_data.app_id) {
			AF_LMT_INFO("gateway upgrade appid: %u -> %u\n",
				    ct->jmx_data.app_id, cand.app_id);

			ct->jmx_data.app_id = cand.app_id;
			ct->jmx_data.match_status |= JMX_MATCH_STATUS_RELIABLE;

			if (cand.feature && cand.feature->ignore) {
				ct->jmx_data.match_status |= JMX_MATCH_STATUS_IGNORE;
				flow.ignore = 1;
			} else {
				ct->jmx_data.match_status &= ~JMX_MATCH_STATUS_IGNORE;
				flow.ignore = 0;
			}

			flow.app_id = cand.app_id;
			flow.feature = cand.feature;
			strncpy(flow.app_name, cand.app_name,
				sizeof(flow.app_name) - 1);
		}
	}

if (client && flow.app_id > 0 && (flow.http.match || flow.https.match)) {
	/* ct->jmx_data.app_id may be a stale/weak cached match from earlier
	 * packets. Do not refresh active_app just because the current packet has
	 * an HTTP host; require a fresh reliable feature on this packet. */
	if (!flow.ignore && flow.feature && af_match_is_reliable(&flow))
		af_update_active_app_list(client, &flow);
}
}

if (ct->jmx_data.app_id == 0 && match_feature(&flow)) {
	if (!af_match_is_reliable(&flow)) {
		AF_LMT_DEBUG("ignore weak legacy feature, appid=%u feature=%s\n",
			flow.app_id, flow.feature ? flow.feature->feature : "");
		flow.app_id = 0;
		flow.feature = NULL;
	} else {
		ct->jmx_data.app_id = flow.app_id;
		ct->jmx_data.match_status |= JMX_MATCH_STATUS_RELIABLE;
		flow.app_id = ct->jmx_data.app_id;

		if (flow.feature && flow.feature->ignore) {
			ct->jmx_data.match_status |= JMX_MATCH_STATUS_IGNORE;
			flow.ignore = 1;
			AF_LMT_DEBUG("gateway set ignore bit, match_status = %u\n",
				     ct->jmx_data.match_status);
		} else {
			flow.ignore = 0;
		}

		/* 只在首次可靠识别时记一次统计 */
			if (client && g_record_enable && !flow.ignore) {
				int is_http = (flow.http.match || flow.https.match) ? 1 : 0;
				af_update_client_app_info(client, flow.app_id, flow.drop, 0, is_http);
			}

		if (client && match_app_filter_rule(flow.app_id, client)) {
			flow.drop = 1;
			ct->jmx_data.action = 1;
			AF_LMT_WARN("##Drop App filter rule, appid = %d, mac = " MAC_FMT "\n",
				    flow.app_id, MAC_ARRAY(client->mac));
			if (skb->protocol == htons(ETH_P_IP) && g_tcp_rst) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(5,10,197)
				nf_send_reset(&init_net, skb->sk, skb, NF_INET_PRE_ROUTING);
#elif LINUX_VERSION_CODE > KERNEL_VERSION(4,4,1)

#else
				nf_send_reset(skb, NF_INET_PRE_ROUTING);
#endif
			}
			ret = NF_DROP;
		}
	}
}

/* v2 protobuf rules fallback: if old feature matching didn't find anything */
if (ct->jmx_data.app_id == 0 && flow.l4_data && flow.l4_len > 0) {
	uint8_t v2_proto = 0;
	uint8_t v2_dir = 0;
	uint8_t v3_mode = JMX_V3_MODE_OFF;
	uint32_t v2_pkt_seq = 0;
	uint32_t v2_appid;
	uint32_t v2_priority;
	uint32_t v3_appid;
	uint32_t v3_active_appid;
	uint32_t v3_priority;

	if (flow.l4_protocol == IPPROTO_TCP) v2_proto = 1; /* JMX_V2_PROTO_TCP */
	else if (flow.l4_protocol == IPPROTO_UDP) v2_proto = 2; /* JMX_V2_PROTO_UDP */

	/* Phase 2.2: direction from conntrack */
	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY)
		v2_dir = 2; /* JMX_V2_DIR_REPLY */
	else
		v2_dir = 1; /* JMX_V2_DIR_ORIGINAL */

	/* Phase 2.3: per-direction packet sequence from conntrack accounting */
	if (acct) {
		if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY)
			v2_pkt_seq = (uint32_t)atomic64_read(
				&acct->counter[IP_CT_DIR_REPLY].packets);
		else
			v2_pkt_seq = (uint32_t)atomic64_read(
				&acct->counter[IP_CT_DIR_ORIGINAL].packets);
	}

	v3_appid = jmx_v3_match_payload(
		(const uint8_t *)flow.l4_data, flow.l4_len,
		v2_proto, v2_dir, flow.sport, flow.dport,
		&v3_priority, &v3_mode);
	v3_active_appid = jmx_v3_appid_for_commit(v3_appid, v3_mode);
	if (v3_appid > 0 && v3_mode == JMX_V3_MODE_SHADOW) {
		/* Shadow is observability-only: do not write app_id, reliable bits,
		 * policy state, or active-app accounting. */
		JMX_DEBUG_RATELIMITED(2, "jmx_v3_SHADOW: appid=%u pri=%u %pI4:%u -> %pI4:%u proto=%u len=%u\n",
			v3_appid, v3_priority, &flow.src, flow.sport,
			&flow.dst, flow.dport, v2_proto, flow.l4_len);
	}

	v2_appid = jmx_v2_match_payload(
		(const uint8_t *)flow.l4_data, flow.l4_len,
		v2_proto, v2_dir, flow.dport, v2_pkt_seq,
		&v2_priority);

	/* Lower numeric priority wins.  Preserve legacy v2 on a tie so switching
	 * v3 from shadow to active cannot silently replace an equal-priority match. */
	if (v2_appid > 0 &&
	    !(v3_active_appid > 0 &&
	      v3_priority < v2_priority)) {
		ct->jmx_data.app_id = v2_appid;
		ct->jmx_data.match_status |= JMX_MATCH_STATUS_RELIABLE;
		flow.app_id = v2_appid;
		v2_matched = 1;
		JMX_DEBUG_RATELIMITED(2, "jmx_v2_MATCH: appid=%u pri=%u %pI4:%u -> %pI4:%u proto=%u seq=%u len=%u\n",
			v2_appid, v2_priority, &flow.src, flow.sport,
			&flow.dst, flow.dport, v2_proto, v2_pkt_seq, flow.l4_len);
		AF_LMT_DEBUG("v2 match: appid=%u priority=%u dport=%u\n",
			v2_appid, v2_priority, flow.dport);
	} else if (v3_active_appid > 0) {
		ct->jmx_data.app_id = v3_active_appid;
		ct->jmx_data.match_status |= JMX_MATCH_STATUS_RELIABLE;
		flow.app_id = v3_active_appid;
		v2_matched = 1;
		JMX_DEBUG_RATELIMITED(2, "jmx_v3_MATCH: appid=%u pri=%u %pI4:%u -> %pI4:%u proto=%u len=%u\n",
			v3_active_appid, v3_priority, &flow.src, flow.sport,
			&flow.dst, flow.dport, v2_proto, flow.l4_len);
	}

	/* If still no match and regex/domain rules exist, keep the dataplane moving.
	 * Forwarded TLS ClientHello packets are often larger than one PPPoE frame;
	 * sending them through NFQUEUE makes user-space latency visible as HTTPS
	 * timeouts. DNS learning is handled by the dedicated UDP sport 53 path above. */
	if (ct->jmx_data.app_id == 0 && jmx_v2_has_regex_rules()) {
		AF_LMT_DEBUG("v2: skip NFQUEUE regex/domain candidate on dataplane\n");
	}

}

if (ret != NF_DROP && client){
	if (match_mac_filter_rule(client)) {
			flow.drop = 1;
			ct->jmx_data.action = 1;  
			AF_LMT_WARN("##Drop MAC filter rule, mac = " MAC_FMT "\n", 
					MAC_ARRAY(client->mac));
			if (skb->protocol == htons(ETH_P_IP) && g_tcp_rst){
			#if LINUX_VERSION_CODE > KERNEL_VERSION(5,10,197)
				nf_send_reset(&init_net, skb->sk, skb, NF_INET_PRE_ROUTING);
			#elif LINUX_VERSION_CODE > KERNEL_VERSION(4,4,1)


			#else
				nf_send_reset(skb, NF_INET_PRE_ROUTING);
			#endif
			}
			ret = NF_DROP;
		}
	}

if (jmx_route_maybe_bind(ct, &flow))
	jmx_route_account_rx(ct, ctinfo, skb->len);
if (ct->jmx_data.route_mark)
	skb->mark = ct->jmx_data.route_mark;

if (g_record_enable && client){
	if (!flow.ignore && flow.app_id > 0){
		int is_http = (flow.http.match || flow.https.match) ? 1 : 0;

		af_update_client_app_info(client, flow.app_id, flow.drop, 0, is_http);

		if (v2_matched ||
		    (flow.feature && af_match_is_reliable(&flow) &&
		     (flow.http.match || flow.https.match)))
			af_update_active_app_list(client, &flow);
	}

	/* Duplicate of the early-path fallback above; kept for safety.
	 * The early-path version at L2678+ already handles this. */

	if (flow.http.match || flow.https.match)
		af_update_active_host_list(client, &flow);

	AF_LMT_INFO("match %s %pI4(%d)--> %pI4(%d) len = %d, %d\n ",
		    IPPROTO_TCP == flow.l4_protocol ? "tcp" : "udp",
		    &flow.src, flow.sport, &flow.dst, flow.dport, skb->len, flow.app_id);
}
	
	if (malloc_data)
	{
		if (flow.l4_data)
		{
			kfree(flow.l4_data);
		}
	}
	return ret;
}

static u_int32_t jmx_hook_gateway_forward_enforce(struct sk_buff *skb)
{
	flow_info_t flow;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	af_client_info_t *client = NULL;
	enum jmx_client_packet_direction direction =
		JMX_CLIENT_PACKET_DIRECTION_UNKNOWN;

	if (!skb)
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return NF_ACCEPT;

	if (ct->jmx_data.action) {
		AF_LMT_DEBUG("gateway forward enforce drop, appid=%u\n",
			     ct->jmx_data.app_id);
		return NF_DROP;
	}

	if (g_record_enable && ct->jmx_data.app_id > 0 &&
	    (ct->jmx_data.match_status & JMX_MATCH_STATUS_RELIABLE) &&
	    !(ct->jmx_data.match_status & JMX_MATCH_STATUS_IGNORE)) {
		memset(&flow, 0, sizeof(flow));
		if (parse_flow_proto(skb, &flow) == 0) {
			AF_CLIENT_LOCK_R();
			if (flow.src) {
				client = find_af_client_by_ip(flow.src);
				if (client)
					direction = JMX_CLIENT_PACKET_DIRECTION_UPLOAD;
			}
			if (!client && flow.dst) {
				client = find_af_client_by_ip(flow.dst);
				if (client)
					direction = JMX_CLIENT_PACKET_DIRECTION_DOWNLOAD;
			}
			if (!client && flow.src6) {
				client = find_af_client_by_ipv6(flow.src6);
				if (client)
					direction = JMX_CLIENT_PACKET_DIRECTION_UPLOAD;
			}
			if (!client && flow.dst6) {
				client = find_af_client_by_ipv6(flow.dst6);
				if (client)
					direction = JMX_CLIENT_PACKET_DIRECTION_DOWNLOAD;
			}
			if (client)
				af_account_client_app_packet(client, ct->jmx_data.app_id,
							 direction, skb->len, false);
			AF_CLIENT_UNLOCK_R();
		}
	}

	if (ct->jmx_data.route_mark)
		skb->mark = ct->jmx_data.route_mark;

	return NF_ACCEPT;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static u_int32_t jmx_hook_local_dns_response(void *priv,
						     struct sk_buff *skb,
						     const struct nf_hook_state *state)
#else
static u_int32_t jmx_hook_local_dns_response(unsigned int hook,
						     struct sk_buff *skb,
						     const struct net_device *in,
						     const struct net_device *out,
						     int (*okfn)(struct sk_buff *))
#endif
{
	flow_info_t flow;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	(void)priv;
	(void)state;
#else
	(void)hook;
	(void)in;
	(void)out;
	(void)okfn;
#endif

	if (!skb)
		return NF_ACCEPT;

	memset(&flow, 0, sizeof(flow));
	if (parse_flow_proto(skb, &flow) < 0)
		return NF_ACCEPT;

	/* Local dnsmasq replies are LOCAL_OUT, not FORWARD/PRE_ROUTING.  Mark them
	 * for jmxd's nft queue rule, which is installed with bypass.  Do not return
	 * NF_QUEUE directly from the kernel hook: if userspace is slow or restarting,
	 * DNS replies are otherwise withheld from clients and local lookups time out. */
	if (flow.l4_protocol == IPPROTO_UDP && flow.sport == 53 && flow.l4_len >= 12) {
		skb->mark = 0x1F000001;
	}

	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static u_int32_t jmx_hook(void *priv,
								 struct sk_buff *skb,
								 const struct nf_hook_state *state)
{
#else
static u_int32_t jmx_hook(unsigned int hook,
								 struct sk_buff *skb,
								 const struct net_device *in,
								 const struct net_device *out,
								 int (*okfn)(struct sk_buff *))
{
#endif
	if (AF_MODE_BYPASS == af_work_mode)
		return NF_ACCEPT;

	/* 网关模式下，FORWARD 只做最终拦截，不再承担 DPI 分类 */
	return jmx_hook_gateway_forward_enforce(skb);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static u_int32_t jmx_by_pass_hook(void *priv,
										 struct sk_buff *skb,
										 const struct nf_hook_state *state)
{
#else
static u_int32_t jmx_by_pass_hook(unsigned int hook,
										 struct sk_buff *skb,
										 const struct net_device *in,
										 const struct net_device *out,
										 int (*okfn)(struct sk_buff *))
{
#endif
	/* 关键修复：
	 * 网关模式也在 PRE_ROUTING 做 DPI 分类。
	 * 旁路模式继续走原来的 bypass 逻辑。
	 */
	if (AF_MODE_GATEWAY == af_work_mode)
		return jmx_hook_gateway_handle(skb, skb->dev);

	return jmx_hook_bypass_handle(skb, skb->dev);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
static struct nf_hook_ops jmx_ops[] __read_mostly = {
	{
		.hook = jmx_hook,
		.pf = NFPROTO_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,

	},
	{
		.hook = jmx_by_pass_hook,
		.pf = NFPROTO_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
	{
		.hook = jmx_hook_local_dns_response,
		.pf = NFPROTO_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static struct nf_hook_ops jmx_ops[] __read_mostly = {
	{
		.hook = jmx_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
	{
		.hook = jmx_by_pass_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
	{
		.hook = jmx_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,

	},
	{
		.hook = jmx_by_pass_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
};
#else
static struct nf_hook_ops jmx_ops[] __read_mostly = {
	{
		.hook = jmx_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
	{
		.hook = jmx_hook,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_MANGLE + 1,
	},
};
#endif

struct timer_list jmx_timer;
int report_flag = 0;
#define JMX_TIMER_INTERVAL 1
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void jmx_timer_func(struct timer_list *t)
#else
static void jmx_timer_func(unsigned long ptr)
#endif
{
	static int count = 0;
	if (count % 60 == 0)
		check_client_expire();

	count++;
	af_conn_clean_timeout();

	mod_timer(&jmx_timer, jiffies + JMX_TIMER_INTERVAL * HZ);
}

void init_jmx_timer(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	timer_setup(&jmx_timer, jmx_timer_func, 0);
#else
	setup_timer(&jmx_timer, jmx_timer_func, JMX_TIMER_INTERVAL * HZ);
#endif
	mod_timer(&jmx_timer, jiffies + JMX_TIMER_INTERVAL * HZ);
	AF_INFO("init jmx timer...ok");
}

void fini_jmx_timer(void)
{
	jmx_timer_shutdown_sync(&jmx_timer);
    AF_INFO("del jmx timer...ok");
}

static struct sock *jmx_sock;
static struct proc_dir_entry *jmx_proc_parent;
static unsigned long jmx_init_state;

#if IS_ENABLED(CONFIG_NF_CONNTRACK_CHAIN_EVENTS)
static int jmx_route_conntrack_event(struct notifier_block *this,
				     unsigned long events, void *ptr)
{
	const struct nf_ct_event *item = ptr;
	struct nf_conn *ct;
	u32 generation = 0;
	u8 wan_id = 0;

	(void)this;
	if (!(events & (1UL << IPCT_DESTROY)) || !item || !item->ct)
		return NOTIFY_DONE;

	ct = item->ct;
	if (xchg(&ct->jmx_data.route_counted, 0)) {
		wan_id = READ_ONCE(ct->jmx_data.route_wan_id);
		generation = READ_ONCE(ct->jmx_data.route_wan_generation);
		WRITE_ONCE(ct->jmx_data.route_wan_generation, 0);
	}

	if (wan_id && generation)
		jmx_wan_flow_release(wan_id, generation);
	return NOTIFY_DONE;
}

static struct notifier_block jmx_route_ct_notifier = {
	.notifier_call = jmx_route_conntrack_event,
};
#endif

enum jmx_init_stage {
	JMX_INIT_PROC_DIRS       = BIT(0),
	JMX_INIT_CONN            = BIT(1),
	JMX_INIT_NETLINK         = BIT(2),
	JMX_INIT_LOG             = BIT(3),
	JMX_INIT_CLIENT_PROC     = BIT(4),
	JMX_INIT_CLIENT_HOOKS    = BIT(5),
	JMX_INIT_ACTIVE_APP_PROC = BIT(6),
	JMX_INIT_ACTIVE_HOST_PROC = BIT(7),
	JMX_INIT_CHARDEV         = BIT(8),
	JMX_INIT_MAC_FILTER      = BIT(9),
	JMX_INIT_APP_FILTER      = BIT(10),
	JMX_INIT_V2_RULES        = BIT(11),
	JMX_INIT_V3_RULES        = BIT(12),
	JMX_INIT_ROUTE           = BIT(13),
	JMX_INIT_ROUTE_PROC      = BIT(14),
	JMX_INIT_FILTER_HOOKS    = BIT(15),
	JMX_INIT_TIMER           = BIT(16),
	JMX_INIT_ROUTE_CT_EVENTS = BIT(17),
};

static int jmx_v3_reply_to_portid(u32 portid, u32 nlmsg_seq,
				  const void *data, u32 len)
{
	struct sk_buff *nl_skb;
	struct nlmsghdr *nlh;
	struct af_msg_hdr *header;
	u32 total;

	if (!jmx_sock || !portid || !nlmsg_seq || !data || !len ||
	    check_add_overflow(len, (u32)sizeof(*header), &total) ||
	    total >= MAX_JMX_NETLINK_MSG_LEN)
		return -EINVAL;
	nl_skb = nlmsg_new(total, GFP_KERNEL);
	if (!nl_skb)
		return -ENOMEM;
	nlh = nlmsg_put(nl_skb, 0, nlmsg_seq, JMX_NETLINK_ID, total, 0);
	if (!nlh) {
		nlmsg_free(nl_skb);
		return -EMSGSIZE;
	}
	header = nlmsg_data(nlh);
	header->magic = 0xa0b0c0d0;
	header->len = len;
	memcpy(header + 1, data, len);
	return netlink_unicast(jmx_sock, nl_skb, portid, MSG_DONTWAIT);
}

#define JMX_EXTRA_MSG_BUF_LEN 128
int af_send_msg_to_user(char *pbuf, uint16_t len)
{
	struct sk_buff *nl_skb;
	struct nlmsghdr *nlh;
	int buf_len = JMX_EXTRA_MSG_BUF_LEN + len;
	char *msg_buf = NULL;
	struct af_msg_hdr *hdr = NULL;
	char *p_data = NULL;
	int ret;
	if (!jmx_sock || !pbuf || !len || len >= MAX_JMX_NL_MSG_LEN)
		return -1;

	msg_buf = kmalloc(buf_len, GFP_ATOMIC);
	if (!msg_buf)
		return -1;

	memset(msg_buf, 0x0, buf_len);
	nl_skb = nlmsg_new(len + sizeof(struct af_msg_hdr), GFP_ATOMIC);
	if (!nl_skb)
	{
		ret = -1;
		goto fail;
	}

	nlh = nlmsg_put(nl_skb, 0, 0, JMX_NETLINK_ID, len + sizeof(struct af_msg_hdr), 0);
	if (nlh == NULL)
	{
		nlmsg_free(nl_skb);
		ret = -1;
		goto fail;
	}

	hdr = (struct af_msg_hdr *)msg_buf;
	hdr->magic = 0xa0b0c0d0;
	hdr->len = len;
	p_data = msg_buf + sizeof(struct af_msg_hdr);
	memcpy(p_data, pbuf, len);
	memcpy(nlmsg_data(nlh), msg_buf, len + sizeof(struct af_msg_hdr));
	ret = netlink_unicast(jmx_sock, nl_skb, 999, MSG_DONTWAIT);

fail:
	kfree(msg_buf);
	return ret;
}

static void jmx_user_msg_handle(char *data, int len, u32 portid,
				u32 nlmsg_seq)
{
	af_msg_t *msg;
	char *msg_data;

	if (len < sizeof(af_msg_t))
		return;
	msg = (af_msg_t *)data;
	msg_data = data + sizeof(*msg);
	switch (msg->action)
	{
	case JMX_NL_MSG_INIT:
		af_client_list_reset_report_num();
		report_flag = 1;
		break;
	case JMX_NL_MSG_ADD_FEATURE:
		af_add_feature_msg_handle(msg_data, len - sizeof(af_msg_t));
		break;
	case JMX_NL_MSG_CLEAN_FEATURE:
		AF_INFO("clean feature\n");
		af_clean_feature_list();
		break;
	default:
		/* v2 handler expects full message including action field */
		if (!jmx_v2_nl_handle(data, len, portid, nlmsg_seq,
				      jmx_v3_reply_to_portid))
			AF_WARN("unknown nl action: %d\n", msg->action);
		break;
	}
}
static void jmx_netlink_msg_rcv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;
	char *umsg = NULL;
	void *udata = NULL;
	struct af_msg_hdr *af_hdr = NULL;
	u32 outer_len;
	if (skb->len >= nlmsg_total_size(0))
	{
		nlh = nlmsg_hdr(skb);
		if (nlh->nlmsg_len < nlmsg_msg_size(sizeof(*af_hdr)) ||
		    nlh->nlmsg_len > skb->len)
			return;
		outer_len = nlmsg_len(nlh);
		umsg = NLMSG_DATA(nlh);
		af_hdr = (struct af_msg_hdr *)umsg;
		if (af_hdr->magic != 0xa0b0c0d0)
			return;
		if (af_hdr->len <= 0 || af_hdr->len >= MAX_JMX_NETLINK_MSG_LEN)
			return;
		if ((u32)af_hdr->len != outer_len - sizeof(*af_hdr))
			return;
		udata = umsg + sizeof(struct af_msg_hdr);

		if (udata)
			jmx_user_msg_handle(udata, af_hdr->len,
					    NETLINK_CB(skb).portid,
					    nlh->nlmsg_seq);
	}
}

int netlink_jmx_init(void)
{
	struct netlink_kernel_cfg nl_cfg = {0};
	nl_cfg.input = jmx_netlink_msg_rcv;
	jmx_sock = netlink_kernel_create(&init_net, JMX_NETLINK_ID, &nl_cfg);

	if (NULL == jmx_sock)
	{
		AF_ERROR("init jmx netlink failed, id=%d\n", JMX_NETLINK_ID);
		return -1;
	}
	AF_INFO("init jmx netlink ok, id = %d\n", JMX_NETLINK_ID);
	return 0;
}

static void netlink_jmx_exit(void)
{
	if (!jmx_sock)
		return;
	netlink_kernel_release(jmx_sock);
	jmx_sock = NULL;
}


int af_active_app_init_procfs(void);
void af_active_app_clean_procfs(void);
int af_active_host_init_procfs(void);
void af_active_host_clean_procfs(void);

static void jmx_cleanup(void)
{
	unsigned long state = jmx_init_state;

	/* Stop control-plane and packet ingress before releasing shared state. */
	jmx_init_state = 0;
	if (state & JMX_INIT_FILTER_HOOKS) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
		nf_unregister_net_hooks(&init_net, jmx_ops, ARRAY_SIZE(jmx_ops));
#else
		nf_unregister_hooks(jmx_ops, ARRAY_SIZE(jmx_ops));
#endif
	}
	if (state & JMX_INIT_TIMER)
		fini_jmx_timer();
	if (state & JMX_INIT_CLIENT_HOOKS)
		af_client_exit();
	if (state & JMX_INIT_NETLINK)
		netlink_jmx_exit();

#if IS_ENABLED(CONFIG_NF_CONNTRACK_CHAIN_EVENTS)
	if (state & JMX_INIT_ROUTE_CT_EVENTS)
		nf_conntrack_unregister_notifier(&init_net, &jmx_route_ct_notifier);
#endif

	if (state & JMX_INIT_ROUTE_PROC)
		jmx_route_exit_procfs();
	if (state & JMX_INIT_ROUTE)
		jmx_route_exit();
	if (state & JMX_INIT_V3_RULES)
		jmx_v3_rules_exit();
	if (state & JMX_INIT_V2_RULES)
		jmx_v2_rules_exit();
	if (state & JMX_INIT_APP_FILTER)
		jmx_app_filter_exit();
	if (state & JMX_INIT_MAC_FILTER)
		jmx_mac_filter_exit();
	if (state & JMX_INIT_CHARDEV)
		jmx_unregister_dev();

	if (state & JMX_INIT_ACTIVE_HOST_PROC)
		af_active_host_clean_procfs();
	if (state & JMX_INIT_ACTIVE_APP_PROC)
		af_active_app_clean_procfs();
	if (state & JMX_INIT_CLIENT_PROC)
		finit_af_client_procfs();
	af_clean_feature_list();
	af_clear_active_app_list();
	af_clear_active_host_list();
	if (state & JMX_INIT_LOG)
		af_log_exit();
	if (state & JMX_INIT_CONN)
		af_conn_exit();

	if (state & JMX_INIT_PROC_DIRS) {
		remove_proc_entry(JMX_PROC_JMX_NAME, jmx_proc_parent);
		jmx_proc_root = NULL;
		remove_proc_entry(JMX_PROC_ROOT_NAME, NULL);
		jmx_proc_parent = NULL;
	}
}

static int __init jmx_init(void)
{
	struct proc_dir_entry *dreamingwrt_dir;
	int err;

	jmx_init_state = 0;
	dreamingwrt_dir = proc_mkdir(JMX_PROC_ROOT_NAME, NULL);
	if (!dreamingwrt_dir) {
		printk(KERN_ERR "jmx: failed to create /proc/dreamingwrt\n");
		return -ENOMEM;
	}
	jmx_proc_parent = dreamingwrt_dir;
	jmx_proc_root = proc_mkdir(JMX_PROC_JMX_NAME, dreamingwrt_dir);
	if (!jmx_proc_root) {
		printk(KERN_ERR "jmx: failed to create /proc/dreamingwrt/jmx\n");
		remove_proc_entry(JMX_PROC_ROOT_NAME, NULL);
		jmx_proc_parent = NULL;
		return -ENOMEM;
	}
	jmx_init_state |= JMX_INIT_PROC_DIRS;

	err = af_conn_init();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_CONN;
	err = af_log_init();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_LOG;
	err = init_af_client_procfs();
	if (err) {
		/* This helper can fail after creating an earlier proc entry. */
		finit_af_client_procfs();
		goto fail;
	}
	jmx_init_state |= JMX_INIT_CLIENT_PROC;
	err = af_client_init();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_CLIENT_HOOKS;
	err = af_active_app_init_procfs();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_ACTIVE_APP_PROC;
	err = af_active_host_init_procfs();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_ACTIVE_HOST_PROC;
	err = jmx_register_dev();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_CHARDEV;
	err = jmx_mac_filter_init();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_MAC_FILTER;
	err = jmx_app_filter_init();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_APP_FILTER;
	err = jmx_v2_rules_init();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_V2_RULES;
	err = jmx_v3_rules_init();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_V3_RULES;
	err = jmx_route_init();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_ROUTE;
	err = jmx_route_init_procfs();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_ROUTE_PROC;
#if IS_ENABLED(CONFIG_NF_CONNTRACK_CHAIN_EVENTS)
	err = nf_conntrack_register_notifier(&init_net, &jmx_route_ct_notifier);
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_ROUTE_CT_EVENTS;
#else
	AF_WARN("jmx_route: conn_cnt accounting disabled without NF_CONNTRACK_CHAIN_EVENTS\n");
#endif
	err = netlink_jmx_init();
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_NETLINK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	err = nf_register_net_hooks(&init_net, jmx_ops, ARRAY_SIZE(jmx_ops));
#else
	err = nf_register_hooks(jmx_ops, ARRAY_SIZE(jmx_ops));
#endif
	if (err)
		goto fail;
	jmx_init_state |= JMX_INIT_FILTER_HOOKS;
	init_jmx_timer();
	jmx_init_state |= JMX_INIT_TIMER;
	printk("jmx: Driver ver. %s - Copyright(c) 2026, DreamingWrt, <www.LesterWrt.com>\n", AF_VERSION);
	printk("jmx: init ok\n");
	return 0;

fail:
	AF_ERROR("jmx init failed rc=%d; rolling back\n", err);
	jmx_cleanup();
	return err < 0 ? err : -EINVAL;
}

static void jmx_fini(void)
{
	AF_INFO("jmx module exit\n");
	jmx_cleanup();
}


static void af_active_app_clean_stale_locked(void)
{
	active_app_node_t *node = NULL, *tmp_node = NULL;
	unsigned long now = ktime_get_real_seconds();

	lockdep_assert_held(&active_app_list_lock);

	list_for_each_entry_safe(node, tmp_node, &active_app_list, list) {
		if (node->update_time > 0 && now > node->update_time &&
		    (now - node->update_time) > ACTIVE_APP_TIMEOUT_SEC) {
			list_del(&node->list);
			kfree(node);
		}
	}
}

void af_update_active_app_list(af_client_info_t *client, flow_info_t *flow)
{
	active_app_node_t *node = NULL, *tmp_node = NULL;
	active_app_node_t *new_node = NULL;
	int found = 0;
	int list_count = 0;
	
	if (!client || !flow || flow->app_id == 0)
		return;

	/* Keep the legacy /proc connection view consistent with the active-app
	 * runtime produced by the gateway conntrack path. */
	af_conn_record_match(flow->src, flow->dst, flow->sport, flow->dport,
			     flow->l4_protocol, flow->app_id, flow->drop);
		
	spin_lock_bh(&active_app_list_lock);

	/* Cleaning and updating share one critical section: this path runs from
	 * softirq context and can execute concurrently on multiple CPUs. */
	af_active_app_clean_stale_locked();
	
	list_for_each_entry_safe(node, tmp_node, &active_app_list, list) {
		list_count++;
		if (node->app_id == flow->app_id &&
    memcmp(node->mac, client->mac, MAC_ADDR_LEN) == 0) {
			
			memcpy(node->mac, client->mac, MAC_ADDR_LEN);
			node->src_ip = flow->src;
			node->dst_ip = flow->dst;
			if (flow->src6) {
				memcpy(&node->src_ip6, flow->src6, sizeof(struct in6_addr));
			}
			if (flow->dst6) {
				memcpy(&node->dst_ip6, flow->dst6, sizeof(struct in6_addr));
			}
			node->src_port = flow->sport;
			node->dst_port = flow->dport;
			node->l4_protocol = flow->l4_protocol;
			node->drop = flow->drop;
			
			
			if (flow->http.match) {
				node->proto_type = 1;  
				if (flow->http.host_pos && flow->http.host_len > 0) {
					jmx_copy_visible_token(node->host, sizeof(node->host),
							       flow->http.host_pos,
							       flow->http.host_len);
				} else {
					node->host[0] = '\0';
				}
				
				if (flow->http.url_pos && flow->http.url_len > 0) {
					jmx_copy_visible_token(node->uri, sizeof(node->uri),
							       flow->http.url_pos,
							       flow->http.url_len);
				} else {
					node->uri[0] = '\0';
				}
			} else if (flow->https.match) {
				node->proto_type = 2;  
				if (flow->https.url_pos && flow->https.url_len > 0) {
					jmx_copy_visible_token(node->host, sizeof(node->host),
							       flow->https.url_pos,
							       flow->https.url_len);
				} else {
					node->host[0] = '\0';
				}
				
				node->uri[0] = '\0';
			} else {
				node->proto_type = 0;  
				node->host[0] = '\0';
				node->uri[0] = '\0';
			}
			
			node->update_time = ktime_get_real_seconds();
			
			
			list_move(&node->list, &active_app_list);
			
			found = 1;
			break;
		}
	}
	
	
	if (!found) {
		
		if (list_count >= MAX_ACTIVE_APP_LIST_SIZE) {
			if (!list_empty(&active_app_list)) {
				node = list_last_entry(&active_app_list, active_app_node_t, list);
				list_del(&node->list);
				kfree(node);
			}
		}
		
		
		new_node = kzalloc(sizeof(active_app_node_t), GFP_ATOMIC);
		if (new_node) {
			INIT_LIST_HEAD(&new_node->list);
			new_node->app_id = flow->app_id;
			memcpy(new_node->mac, client->mac, MAC_ADDR_LEN);
			new_node->src_ip = flow->src;
			new_node->dst_ip = flow->dst;
			if (flow->src6) {
				memcpy(&new_node->src_ip6, flow->src6, sizeof(struct in6_addr));
			}
			if (flow->dst6) {
				memcpy(&new_node->dst_ip6, flow->dst6, sizeof(struct in6_addr));
			}
			new_node->src_port = flow->sport;
			new_node->dst_port = flow->dport;
			new_node->l4_protocol = flow->l4_protocol;
			new_node->drop = flow->drop;
			
			
			if (flow->http.match) {
				new_node->proto_type = 1;  
				if (flow->http.host_pos && flow->http.host_len > 0) {
					jmx_copy_visible_token(new_node->host, sizeof(new_node->host),
							       flow->http.host_pos,
							       flow->http.host_len);
				}
				
				if (flow->http.url_pos && flow->http.url_len > 0) {
					jmx_copy_visible_token(new_node->uri, sizeof(new_node->uri),
							       flow->http.url_pos,
							       flow->http.url_len);
				}
			} else if (flow->https.match) {
				new_node->proto_type = 2;  
				if (flow->https.url_pos && flow->https.url_len > 0) {
					jmx_copy_visible_token(new_node->host, sizeof(new_node->host),
							       flow->https.url_pos,
							       flow->https.url_len);
				}
				
				new_node->uri[0] = '\0';
			} else {
				new_node->proto_type = 0;  
				new_node->host[0] = '\0';
				new_node->uri[0] = '\0';
			}
			
			new_node->update_time = ktime_get_real_seconds();
			
			
			list_add(&new_node->list, &active_app_list);
		}
	}
	
	spin_unlock_bh(&active_app_list_lock);
}


void af_clear_active_app_list(void)
{
	active_app_node_t *node = NULL, *tmp_node = NULL;
	
	spin_lock_bh(&active_app_list_lock);
	list_for_each_entry_safe(node, tmp_node, &active_app_list, list) {
		list_del(&node->list);
		kfree(node);
	}
	spin_unlock_bh(&active_app_list_lock);
}


void af_update_active_host_list(af_client_info_t *client, flow_info_t *flow)
{
	active_host_node_t *node = NULL, *tmp_node = NULL;
	active_host_node_t *new_node = NULL;
	int found = 0;
	int list_count = 0;
	char host_buf[64] = {0};
	
	if (!client || !flow)
		return;
	
	
	if (!flow->http.match && !flow->https.match)
		return;
	
	
	if (flow->http.match && flow->http.host_pos && flow->http.host_len > 0) {
		if (!jmx_copy_visible_token(host_buf, sizeof(host_buf),
					    flow->http.host_pos, flow->http.host_len))
			return;
	} else if (flow->https.match && flow->https.url_pos && flow->https.url_len > 0) {
		if (!jmx_copy_visible_token(host_buf, sizeof(host_buf),
					    flow->https.url_pos, flow->https.url_len))
			return;
	} else {
		return;  
	}
	
	spin_lock_bh(&active_host_list_lock);
	
	
	list_for_each_entry_safe(node, tmp_node, &active_host_list, list) {
		list_count++;
		if (strncmp(node->host, host_buf, sizeof(node->host)) == 0 &&
    memcmp(node->mac, client->mac, MAC_ADDR_LEN) == 0) {
			
			memcpy(node->mac, client->mac, MAC_ADDR_LEN);
			node->src_ip = flow->src;
			node->dst_ip = flow->dst;
			if (flow->src6) {
				memcpy(&node->src_ip6, flow->src6, sizeof(struct in6_addr));
			}
			if (flow->dst6) {
				memcpy(&node->dst_ip6, flow->dst6, sizeof(struct in6_addr));
			}
			node->src_port = flow->sport;
			node->dst_port = flow->dport;
			node->l4_protocol = flow->l4_protocol;
			node->drop = flow->drop;
			
			
			if (flow->http.match) {
				node->proto_type = 1;  
			} else if (flow->https.match) {
				node->proto_type = 2;  
			} else {
				node->proto_type = 0;  
			}
			
			node->update_time = ktime_get_real_seconds();
			
			
			list_move(&node->list, &active_host_list);
			
			found = 1;
			break;
		}
	}
	
	
	if (!found) {
		
		if (list_count >= MAX_ACTIVE_HOST_LIST_SIZE) {
			if (!list_empty(&active_host_list)) {
				node = list_last_entry(&active_host_list, active_host_node_t, list);
				list_del(&node->list);
				kfree(node);
			}
		}
		
		
		new_node = kzalloc(sizeof(active_host_node_t), GFP_ATOMIC);
		if (new_node) {
			INIT_LIST_HEAD(&new_node->list);
			strncpy(new_node->host, host_buf, 63);
			new_node->host[63] = '\0';
			memcpy(new_node->mac, client->mac, MAC_ADDR_LEN);
			new_node->src_ip = flow->src;
			new_node->dst_ip = flow->dst;
			if (flow->src6) {
				memcpy(&new_node->src_ip6, flow->src6, sizeof(struct in6_addr));
			}
			if (flow->dst6) {
				memcpy(&new_node->dst_ip6, flow->dst6, sizeof(struct in6_addr));
			}
			new_node->src_port = flow->sport;
			new_node->dst_port = flow->dport;
			new_node->l4_protocol = flow->l4_protocol;
			new_node->drop = flow->drop;
			
			
			if (flow->http.match) {
				new_node->proto_type = 1;  
			} else if (flow->https.match) {
				new_node->proto_type = 2;  
			} else {
				new_node->proto_type = 0;  
			}
			
			new_node->update_time = ktime_get_real_seconds();
			
			
			list_add(&new_node->list, &active_host_list);
		}
	}
	
	spin_unlock_bh(&active_host_list_lock);
}


active_host_node_t *af_find_active_host(const char *host)
{
	active_host_node_t *node = NULL;
	
	if (!host || strlen(host) == 0)
		return NULL;
	
	spin_lock_bh(&active_host_list_lock);
	list_for_each_entry(node, &active_host_list, list) {
		if (strncmp(node->host, host, 64) == 0) {
			spin_unlock_bh(&active_host_list_lock);
			return node;
		}
	}
	spin_unlock_bh(&active_host_list_lock);
	
	return NULL;
}


void af_clear_active_host_list(void)
{
	active_host_node_t *node = NULL, *tmp_node = NULL;
	
	spin_lock_bh(&active_host_list_lock);
	list_for_each_entry_safe(node, tmp_node, &active_host_list, list) {
		list_del(&node->list);
		kfree(node);
	}
	spin_unlock_bh(&active_host_list_lock);
}


static void print_active_app_header(struct seq_file *s)
{
	seq_printf(s, "%-6s %-18s %-16s %-8s %-16s %-8s %-6s %-8s %-5s %-32s %-12s %-32s\n",
	           "AppID", "MAC", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "AppProto", "Drop", "Host", "LastUpdate", "URI");
}

static void *af_active_app_seq_start(struct seq_file *s, loff_t *pos)
{
	spin_lock_bh(&active_app_list_lock);
	return seq_list_start(&active_app_list, *pos);
}

static void *af_active_app_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return seq_list_next(v, &active_app_list, pos);
}

static void af_active_app_seq_stop(struct seq_file *s, void *v)
{
	spin_unlock_bh(&active_app_list_lock);
}

static int af_active_app_seq_show(struct seq_file *s, void *v)
{
	char mac_str[32] = {0};
	char src_ip_str[64] = {0};
	char dst_ip_str[64] = {0};
	char proto_str[8] = {0};
	const char *safe_host = "-";
	const char *safe_uri = "-";
	
	active_app_node_t *node = list_entry(v, active_app_node_t, list);

	/* Skip stale entries (older than 5 minutes) */
	if (node->update_time > 0) {
		unsigned long now = ktime_get_real_seconds();
		if (now > node->update_time && (now - node->update_time) > ACTIVE_APP_TIMEOUT_SEC)
			return 0;
	}
	
	
	if (v == active_app_list.next)
		print_active_app_header(s);
	
	
	sprintf(mac_str, MAC_FMT, MAC_ARRAY(node->mac));
	
	
	if (node->src_ip != 0) {
		sprintf(src_ip_str, "%pI4", &node->src_ip);
	} else {
		char ip6_str[64] = {0};
		ipv6_to_str(&node->src_ip6, ip6_str);
		sprintf(src_ip_str, "[%s]", ip6_str);
	}
	
	
	if (node->dst_ip != 0) {
		sprintf(dst_ip_str, "%pI4", &node->dst_ip);
	} else {
		char ip6_str[64] = {0};
		ipv6_to_str(&node->dst_ip6, ip6_str);
		sprintf(dst_ip_str, "[%s]", ip6_str);
	}
	
	
	switch (node->l4_protocol) {
		case IPPROTO_TCP:
			strcpy(proto_str, "TCP");
			break;
		case IPPROTO_UDP:
			strcpy(proto_str, "UDP");
			break;
		default:
			sprintf(proto_str, "%d", node->l4_protocol);
			break;
	}
	
	if (jmx_visible_token_is_valid(node->host))
		safe_host = node->host;
	if (node->proto_type == 1 && jmx_visible_token_is_valid(node->uri))
		safe_uri = node->uri;
	
	seq_printf(s, "%-6u %-18s %-16s %-8u %-16s %-8u %-6s %-8u %-5u %-32s  %-12u  %-32s\n",
	           node->app_id,
	           mac_str,
	           src_ip_str,
	         	 node->src_port,
	           dst_ip_str,
	           node->dst_port,
	           proto_str,
	           node->proto_type,  
	           node->drop,
	           safe_host,
	           node->update_time,
	           safe_uri

			);
	
	return 0;
}

static const struct seq_operations af_active_app_seq_ops = {
	.start = af_active_app_seq_start,
	.next = af_active_app_seq_next,
	.stop = af_active_app_seq_stop,
	.show = af_active_app_seq_show
};

static int af_active_app_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &af_active_app_seq_ops);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations af_active_app_fops = {
	.owner = THIS_MODULE,
	.open = af_active_app_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};
#else
static const struct proc_ops af_active_app_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_read = seq_read,
	.proc_open = af_active_app_open,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release_private,
};
#endif

#define AF_ACTIVE_APP_PROC_STR "af_active_app"


int af_active_app_init_procfs(void)
{
	struct proc_dir_entry *pde;
	
	pde = proc_create(AF_ACTIVE_APP_PROC_STR, 0444, jmx_proc_root, &af_active_app_fops);
	if (!pde) {
		AF_ERROR("af_active_app proc file created error\n");
		return -1;
	}
	return 0;
}


void af_active_app_clean_procfs(void)
{
	remove_proc_entry(AF_ACTIVE_APP_PROC_STR, jmx_proc_root);
}


static void print_active_host_header(struct seq_file *s)
{
	seq_printf(s, "%-48s %-18s %-16s %-8s %-16s %-8s %-6s %-8s %-5s %-12s\n",
	           "Host", "MAC", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "AppProto", "Drop", "LastUpdate");
}

static void *af_active_host_seq_start(struct seq_file *s, loff_t *pos)
{
	spin_lock_bh(&active_host_list_lock);
	return seq_list_start(&active_host_list, *pos);
}

static void *af_active_host_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	return seq_list_next(v, &active_host_list, pos);
}

static void af_active_host_seq_stop(struct seq_file *s, void *v)
{
	spin_unlock_bh(&active_host_list_lock);
}

static int af_active_host_seq_show(struct seq_file *s, void *v)
{
	char mac_str[32] = {0};
	char src_ip_str[64] = {0};
	char dst_ip_str[64] = {0};
	char proto_str[8] = {0};
	
	active_host_node_t *node = list_entry(v, active_host_node_t, list);
	
	
	if (v == active_host_list.next)
		print_active_host_header(s);

	if (!jmx_visible_token_is_valid(node->host))
		return 0;
	
	
	sprintf(mac_str, MAC_FMT, MAC_ARRAY(node->mac));
	
	
	if (node->src_ip != 0) {
		sprintf(src_ip_str, "%pI4", &node->src_ip);
	} else {
		char ip6_str[64] = {0};
		ipv6_to_str(&node->src_ip6, ip6_str);
		sprintf(src_ip_str, "[%s]", ip6_str);
	}
	
	
	if (node->dst_ip != 0) {
		sprintf(dst_ip_str, "%pI4", &node->dst_ip);
	} else {
		char ip6_str[64] = {0};
		ipv6_to_str(&node->dst_ip6, ip6_str);
		sprintf(dst_ip_str, "[%s]", ip6_str);
	}
	
	
	switch (node->l4_protocol) {
		case IPPROTO_TCP:
			strcpy(proto_str, "TCP");
			break;
		case IPPROTO_UDP:
			strcpy(proto_str, "UDP");
			break;
		default:
			sprintf(proto_str, "%d", node->l4_protocol);
			break;
	}
	
	
	seq_printf(s, "%-48s %-18s %-16s %-8u %-16s %-8u %-6s %-8u %-5u %-12u\n",
	           node->host,
	           mac_str,
	           src_ip_str,
	           node->src_port,
	           dst_ip_str,
	           node->dst_port,
	           proto_str,
	           node->proto_type,  
	           node->drop,
	           node->update_time);
	
	return 0;
}

static const struct seq_operations af_active_host_seq_ops = {
	.start = af_active_host_seq_start,
	.next = af_active_host_seq_next,
	.stop = af_active_host_seq_stop,
	.show = af_active_host_seq_show
};

static int af_active_host_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &af_active_host_seq_ops);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations af_active_host_fops = {
	.owner = THIS_MODULE,
	.open = af_active_host_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};
#else
static const struct proc_ops af_active_host_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_read = seq_read,
	.proc_open = af_active_host_open,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release_private,
};
#endif

#define AF_ACTIVE_HOST_PROC_STR "af_active_host"


int af_active_host_init_procfs(void)
{
	struct proc_dir_entry *pde;
	
	pde = proc_create(AF_ACTIVE_HOST_PROC_STR, 0444, jmx_proc_root, &af_active_host_fops);
	if (!pde) {
		AF_ERROR("af_active_host proc file created error\n");
		return -1;
	}
	return 0;
}


void af_active_host_clean_procfs(void)
{
	remove_proc_entry(AF_ACTIVE_HOST_PROC_STR, jmx_proc_root);
}

module_init(jmx_init);
module_exit(jmx_fini);
