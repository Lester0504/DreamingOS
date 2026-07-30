// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/

#include <linux/version.h>
#include <linux/timer.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/limits.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <linux/timer.h>
#include <linux/sort.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>

#include "jmx_client.h"
#include "jmx_client_fs.h"
#include "jmx_log.h"
#include "jmx_utils.h"
#include "jmx.h"
#include "k_json.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
#define JMX_FROM_TIMER(var, timer_ptr, timer_field) \
	timer_container_of(var, timer_ptr, timer_field)
#else
#define JMX_FROM_TIMER(var, timer_ptr, timer_field) \
	from_timer(var, timer_ptr, timer_field)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
#define jmx_timer_delete_sync(t) timer_delete_sync(t)
#define jmx_timer_shutdown_sync(t) timer_shutdown_sync(t)
#else
#define jmx_timer_delete_sync(t) del_timer_sync(t)
#define jmx_timer_shutdown_sync(t) del_timer_sync(t)
#endif

#ifndef NF_IP_PRI_FIRST
#define NF_IP_PRI_FIRST INT_MIN
#endif

#ifndef NF_IP_PRI_LAST
#define NF_IP_PRI_LAST INT_MAX
#endif

DEFINE_RWLOCK(af_client_lock);

static u32 total_client;
struct list_head af_client_list_table[MAX_AF_CLIENT_HASH_SIZE];

int g_max_app_report_count = 3;
int g_min_http_match_count = 3;
static atomic64_t client_counter_generation = ATOMIC64_INIT(0);

static void init_client_timer(af_client_info_t *client);
static void stop_client_timer(af_client_info_t *client);
static af_client_info_t *nf_client_add(unsigned char *mac);

static void af_client_release(af_client_info_t *client)
{
	int i;
	struct hlist_node *n;
	app_visit_info_t *info;

	if (!client)
		return;
	for (i = 0; i < MAX_VISIT_INFO_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(info, n, &client->visit_info_hash[i], hlist) {
			hlist_del(&info->hlist);
			kfree(info);
		}
	}
	kfree(client);
}

void af_client_put(af_client_info_t *client)
{
	if (client && refcount_dec_and_test(&client->refs))
		af_client_release(client);
}

bool af_client_get_if_live(af_client_info_t *client)
{
	bool acquired = false;

	if (!client)
		return false;
	AF_CLIENT_LOCK_R();
	if (!client->dying)
		acquired = refcount_inc_not_zero(&client->refs);
	AF_CLIENT_UNLOCK_R();
	return acquired;
}

static void nf_client_list_init(void)
{
	int i;

	AF_CLIENT_LOCK_W();
	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++)
		INIT_LIST_HEAD(&af_client_list_table[i]);
	AF_CLIENT_UNLOCK_W();

	AF_INFO("client list init......ok\n");
}

static void nf_client_list_clear(void)
{
	int i;
	af_client_info_t *p = NULL;
	af_client_info_t *next = NULL;
	char mac_str[32] = {0};
	LIST_HEAD(detached);

	AF_DEBUG("clean list\n");
	AF_CLIENT_LOCK_W();
	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++)
	{
		list_for_each_entry_safe(p, next, &af_client_list_table[i], hlist) {
			memset(mac_str, 0x0, sizeof(mac_str));
			sprintf(mac_str, MAC_FMT, MAC_ARRAY(p->mac));
			AF_DEBUG("clean mac:%s\n", mac_str);
			p->dying = true;
			list_move_tail(&p->hlist, &detached);
		}
	}
	total_client = 0;
	AF_CLIENT_UNLOCK_W();

	list_for_each_entry_safe(p, next, &detached, hlist) {
		list_del_init(&p->hlist);
		stop_client_timer(p);
		remove_client_proc_dir(p);
		af_client_put(p);
	}
}

void af_client_list_reset_report_num(void)
{
	int i;
	af_client_info_t *node = NULL;

	AF_CLIENT_LOCK_W();
	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++)
	{
		list_for_each_entry(node, &af_client_list_table[i], hlist)
			node->report_count = 0;
	}
	AF_CLIENT_UNLOCK_W();
}

static int get_mac_hash_code(unsigned char *mac)
{
	if (!mac)
		return 0;
	return mac[5] & (MAX_AF_CLIENT_HASH_SIZE - 1);
}

static af_client_info_t *find_af_client(unsigned char *mac)
{
	af_client_info_t *node;
	unsigned int index;

	index = get_mac_hash_code(mac);
	list_for_each_entry(node, &af_client_list_table[index], hlist)
	{
		if (memcmp(node->mac, mac, 6) == 0)
			return node;
	}
	return NULL;
}

af_client_info_t *find_and_add_af_client(unsigned char *mac)
{
	af_client_info_t *nfc;

	nfc = find_af_client(mac);
	if (!nfc)
		nfc = nf_client_add(mac);

	return nfc;
}

af_client_info_t *find_af_client_by_ip(unsigned int ip)
{
	af_client_info_t *node;
	int i;

	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++)
	{
		list_for_each_entry(node, &af_client_list_table[i], hlist)
		{
			if (node->ip == ip)
			{
				AF_LMT_DEBUG("match node->ip=%pI4, ip=%pI4\n", &node->ip, &ip);
				return node;
			}
		}
	}
	return NULL;
}

af_client_info_t *find_af_client_by_ipv6(struct in6_addr *ipv6)
{
	af_client_info_t *node;
	int i;
	char addr_str[64] = {0};

	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++)
	{
		list_for_each_entry(node, &af_client_list_table[i], hlist)
		{
			if (ipv6_addr_equal(&node->ipv6, ipv6))
			{
				AF_INFO("match node->ipv6=%s\n", ipv6_to_str(&node->ipv6, addr_str));
				return node;
			}
		}
	}
	return NULL;
}

af_client_info_t *af_client_get_by_ip(unsigned int ip)
{
	af_client_info_t *client;

	AF_CLIENT_LOCK_R();
	client = find_af_client_by_ip(ip);
	if (client && (client->dying || !refcount_inc_not_zero(&client->refs)))
		client = NULL;
	AF_CLIENT_UNLOCK_R();
	return client;
}

af_client_info_t *af_client_get_by_ipv6(struct in6_addr *ipv6)
{
	af_client_info_t *client;

	AF_CLIENT_LOCK_R();
	client = find_af_client_by_ipv6(ipv6);
	if (client && (client->dying || !refcount_inc_not_zero(&client->refs)))
		client = NULL;
	AF_CLIENT_UNLOCK_R();
	return client;
}

static af_client_info_t *nf_client_add(unsigned char *mac)
{
	af_client_info_t *node;
	int index = 0;
	int i;

	node = (af_client_info_t *)kmalloc(sizeof(af_client_info_t), GFP_ATOMIC);
	if (node == NULL)
	{
		AF_ERROR("kmalloc failed\n");
		return NULL;
	}

	memset(node, 0, sizeof(af_client_info_t));
	refcount_set(&node->refs, 1);
	memcpy(node->mac, mac, MAC_ADDR_LEN);

	node->create_jiffies = jiffies;
	node->update_jiffies = jiffies;
	node->timer_count = 0;
	spin_lock_init(&node->visit_info_lock);

	for (i = 0; i < MAX_VISIT_INFO_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&node->visit_info_hash[i]);

	index = get_mac_hash_code(mac);

	AF_LMT_INFO("new client mac=" MAC_FMT "\n", MAC_ARRAY(node->mac));
	total_client++;
	init_client_timer(node);
	list_add(&(node->hlist), &af_client_list_table[index]);
	create_client_proc_dir(node);
	return node;
}

void check_client_expire(void)
{
	af_client_info_t *node = NULL;
	int i;

	AF_CLIENT_LOCK_W();
	for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++)
	{
		list_for_each_entry(node, &af_client_list_table[i], hlist)
		{
			AF_DEBUG("mac:" MAC_FMT " update:%lu interval:%lu\n",
				 MAC_ARRAY(node->mac),
				 node->update_jiffies,
				 (jiffies - node->update_jiffies) / HZ);

			if (jiffies > (node->update_jiffies + MAX_CLIENT_ACTIVE_TIME * HZ))
			{
				AF_INFO("del client:" MAC_FMT "\n", MAC_ARRAY(node->mac));
				node->dying = true;
				list_del_init(&(node->hlist));
				if (total_client > 0)
					total_client--;
				AF_CLIENT_UNLOCK_W();
				stop_client_timer(node);
				remove_client_proc_dir(node);
				af_client_put(node);
				return;
			}
		}
	}
	AF_CLIENT_UNLOCK_W();
}

static inline int get_app_id_hash_code(unsigned int app_id)
{
	return app_id & (MAX_VISIT_INFO_HASH_SIZE - 1);
}

static app_visit_info_t *find_visit_info(af_client_info_t *node, unsigned int app_id)
{
	struct hlist_head *head;
	app_visit_info_t *info;

	head = &node->visit_info_hash[get_app_id_hash_code(app_id)];
	hlist_for_each_entry(info, head, hlist) {
		if (info->app_id == app_id)
			return info;
	}
	return NULL;
}

app_visit_info_t *get_or_create_visit_info(af_client_info_t *node, unsigned int app_id)
{
	app_visit_info_t *info;

	info = find_visit_info(node, app_id);
	if (info)
		return info;

	info = (app_visit_info_t *)kmalloc(sizeof(app_visit_info_t), GFP_ATOMIC);
	if (!info)
		return NULL;

	memset(info, 0, sizeof(app_visit_info_t));
	info->app_id = app_id;
	INIT_HLIST_NODE(&info->hlist);

	hlist_add_head(&info->hlist, &node->visit_info_hash[get_app_id_hash_code(app_id)]);
	return info;
}

int af_account_client_app_packet(af_client_info_t *node, unsigned int app_id,
				 enum jmx_client_packet_direction direction,
				 unsigned int bytes, bool blocked)
{
	app_visit_info_t *info;
	struct jmx_client_byte_counters counters;
	bool accounted;

	if (!node || !app_id || !bytes || blocked ||
	    direction == JMX_CLIENT_PACKET_DIRECTION_UNKNOWN)
		return 0;

	spin_lock_bh(&node->visit_info_lock);
	info = get_or_create_visit_info(node, app_id);
	if (!info) {
		spin_unlock_bh(&node->visit_info_lock);
		return -ENOMEM;
	}

	counters.in_bytes = info->in_bytes;
	counters.out_bytes = info->out_bytes;
	counters.total_bytes = info->total_bytes;
	accounted = jmx_account_client_packet(&counters, direction, bytes, blocked);
	if (accounted) {
		info->in_bytes = counters.in_bytes;
		info->out_bytes = counters.out_bytes;
		info->total_bytes = counters.total_bytes;
	}
	spin_unlock_bh(&node->visit_info_lock);

	return accounted ? 1 : 0;
}

unsigned long long af_client_counter_generation(void)
{
	return (unsigned long long)atomic64_read(&client_counter_generation);
}

#define VISIT_INFO_TIMEOUT_SEC 300

static void check_expired_visit_info(af_client_info_t *node)
{
	int i;
	u_int32_t cur_timep = 0;
	struct hlist_head *head;
	struct hlist_node *n;
	app_visit_info_t *info;
	HLIST_HEAD(expired);

	if (!node)
		return;

	cur_timep = af_get_timestamp_sec();

	spin_lock_bh(&node->visit_info_lock);
	for (i = 0; i < MAX_VISIT_INFO_HASH_SIZE; i++) {
		head = &node->visit_info_hash[i];
		hlist_for_each_entry_safe(info, n, head, hlist) {
			if (cur_timep >= info->latest_time &&
			    cur_timep - info->latest_time > VISIT_INFO_TIMEOUT_SEC) {
				hlist_del(&info->hlist);
				hlist_add_head(&info->hlist, &expired);
			}
		}
	}
	spin_unlock_bh(&node->visit_info_lock);

	hlist_for_each_entry_safe(info, n, &expired, hlist) {
		hlist_del(&info->hlist);
		kfree(info);
	}
}

struct visit_report_snapshot {
	unsigned int app_id;
	unsigned int total_num;
	unsigned int latest_action;
};

static int compare_visit_info_count(const void *a, const void *b)
{
	const struct visit_report_snapshot *info_a = a;
	const struct visit_report_snapshot *info_b = b;

	if (info_a->total_num > info_b->total_num)
		return -1;
	else if (info_a->total_num < info_b->total_num)
		return 1;
	return 0;
}

static cJSON *visit_report_json_create(int type)
{
	cJSON *item;

	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item)
		return NULL;
	item->type = type;
	return item;
}

static cJSON *visit_report_json_create_number(int value)
{
	cJSON *item;

	item = visit_report_json_create(cJSON_Number);
	if (item)
		item->valueint = value;
	return item;
}

static cJSON *visit_report_json_create_string(const char *value)
{
	cJSON *item;

	item = visit_report_json_create(cJSON_String);
	if (!item)
		return NULL;
	item->valuestring = kstrdup(value, GFP_KERNEL);
	if (!item->valuestring) {
		kfree(item);
		return NULL;
	}
	return item;
}

static void visit_report_json_append(cJSON *parent, cJSON *item)
{
	cJSON *tail;

	if (!parent->child) {
		parent->child = item;
		return;
	}

	tail = parent->child;
	while (tail->next)
		tail = tail->next;
	tail->next = item;
	item->prev = tail;
}

static int visit_report_json_add_item(cJSON *parent, const char *name,
				      cJSON *item)
{
	if (!item)
		return -ENOMEM;
	if (name) {
		item->string = kstrdup(name, GFP_KERNEL);
		if (!item->string)
			return -ENOMEM;
	}
	visit_report_json_append(parent, item);
	return 0;
}

static int visit_report_json_add_number(cJSON *object, const char *name,
					int value)
{
	cJSON *item;
	int ret;

	item = visit_report_json_create_number(value);
	ret = visit_report_json_add_item(object, name, item);
	if (ret)
		cJSON_Delete(item);
	return ret;
}

static int visit_report_json_add_string(cJSON *object, const char *name,
					const char *value)
{
	cJSON *item;
	int ret;

	item = visit_report_json_create_string(value);
	ret = visit_report_json_add_item(object, name, item);
	if (ret)
		cJSON_Delete(item);
	return ret;
}

static int __af_visit_info_report(af_client_info_t *node)
{
	unsigned char mac_str[32] = {0};
	unsigned char ip_str[32] = {0};
	int i;
	int total_count = 0;
	char *out = NULL;
	cJSON *visit_obj = NULL;
	cJSON *visit_info_array = NULL;
	cJSON *root_obj = NULL;
	struct hlist_head *head;
	app_visit_info_t *info;
	struct visit_report_snapshot snapshots[MAX_RECORD_APP_NUM];
	int report_count = 0;

	spin_lock_bh(&node->visit_info_lock);
	for (i = 0; i < MAX_VISIT_INFO_HASH_SIZE; i++) {
		head = &node->visit_info_hash[i];
		hlist_for_each_entry(info, head, hlist) {
			if (info->total_num == 0)
				continue;
			if (info->is_http && info->conn_count <= g_min_http_match_count) {
				info->total_num = 0;
				continue;
			}
			if (total_count < ARRAY_SIZE(snapshots)) {
				snapshots[total_count].app_id = info->app_id;
				snapshots[total_count].total_num = info->total_num;
				snapshots[total_count].latest_action = info->latest_action;
				total_count++;
			}
			info->total_num = 0;
		}
	}
	spin_unlock_bh(&node->visit_info_lock);

	if (total_count > 0) {
		sort(snapshots, total_count, sizeof(snapshots[0]),
		     compare_visit_info_count, NULL);
		report_count = total_count > g_max_app_report_count ? g_max_app_report_count : total_count;
		if (report_count < 0)
			report_count = 0;
	}

	root_obj = visit_report_json_create(cJSON_Object);
	visit_info_array = visit_report_json_create(cJSON_Array);
	if (!root_obj || !visit_info_array)
		goto json_failed;

	sprintf(mac_str, MAC_FMT, MAC_ARRAY(node->mac));
	sprintf(ip_str, "%pI4", &node->ip);
	if (visit_report_json_add_string(root_obj, "mac", mac_str) ||
	    visit_report_json_add_string(root_obj, "ip", ip_str) ||
	    visit_report_json_add_number(root_obj, "app_num", node->visit_app_num) ||
	    visit_report_json_add_number(root_obj, "up_flow",
					 (u32)(node->period_flow.up_bytes >> 10)) ||
	    visit_report_json_add_number(root_obj, "down_flow",
					 (u32)(node->period_flow.down_bytes >> 10)) ||
	    visit_report_json_add_number(root_obj, "active", node->active))
		goto json_failed;

	for (i = 0; i < report_count; i++) {
		visit_obj = visit_report_json_create(cJSON_Object);
		if (!visit_obj ||
		    visit_report_json_add_number(visit_obj, "appid",
						 snapshots[i].app_id) ||
		    visit_report_json_add_number(visit_obj, "latest_action",
						 snapshots[i].latest_action))
			goto json_failed;
		visit_report_json_append(visit_info_array, visit_obj);
		visit_obj = NULL;
	}

	if (visit_report_json_add_item(root_obj, "visit_info", visit_info_array))
		goto json_failed;
	visit_info_array = NULL;
	out = cJSON_Print(root_obj);
	if (!out)
		goto json_failed;
	cJSON_Minify(out);

	node->report_count++;
	af_send_msg_to_user(out, strlen(out));
	cJSON_Delete(root_obj);

	memset(&node->period_flow, 0x0, sizeof(node->period_flow));
	kfree(out);

	return 0;

json_failed:
	AF_ERROR("create visit report json failed\n");
	cJSON_Delete(visit_obj);
	cJSON_Delete(visit_info_array);
	cJSON_Delete(root_obj);
	kfree(out);
	return 0;
}

extern u_int32_t jmx_lan_ip;
extern u_int32_t jmx_lan_mask;

static inline int af_is_lan_v4(u32 ip)
{
	if (!jmx_lan_ip || !jmx_lan_mask || !ip)
		return 0;

	return (ip & jmx_lan_mask) == (jmx_lan_ip & jmx_lan_mask);
}

static inline int get_packet_dir(const struct net_device *in, struct sk_buff *skb)
{
	const struct iphdr *iph = NULL;

	if (skb && skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		if (iph) {
			if (af_is_lan_v4(iph->saddr) && !af_is_lan_v4(iph->daddr))
				return PKT_DIR_UP;

			if (!af_is_lan_v4(iph->saddr) && af_is_lan_v4(iph->daddr))
				return PKT_DIR_DOWN;
		}
	}

	if (in && strstr(in->name, g_lan_ifname))
		return PKT_DIR_UP;

	return PKT_DIR_DOWN;
}

static void af_update_client_status(af_client_info_t *node)
{
	if (node->last_flow.down_bytes > 0)
		node->period_flow.down_bytes += (node->flow.down_bytes - node->last_flow.down_bytes);

	if (node->last_flow.up_bytes > 0)
		node->period_flow.up_bytes += (node->flow.up_bytes - node->last_flow.up_bytes);

	AF_LMT_DEBUG("period flow down:%llu up: %llu pkg up %d\n",
		node->period_flow.down_bytes,
		node->period_flow.up_bytes,
		node->rate.pkt_up_rate);

	node->rate.up_rate = (node->flow.up_bytes - node->last_flow.up_bytes) >> 1;
	node->rate.down_rate = (node->flow.down_bytes - node->last_flow.down_bytes) >> 1;
	node->rate.pkt_up_rate = (node->flow.up_pkts - node->last_flow.up_pkts) >> 1;
	node->rate.pkt_down_rate = (node->flow.down_pkts - node->last_flow.down_pkts) >> 1;

	node->last_flow.up_bytes = node->flow.up_bytes;
	node->last_flow.down_bytes = node->flow.down_bytes;
	node->last_flow.up_pkts = node->flow.up_pkts;
	node->last_flow.down_pkts = node->flow.down_pkts;

	if (node->rate.pkt_down_rate > 20) {
		node->active_time++;
		node->inactive_time = 0;
		node->active = 1;
	} else {
		node->inactive_time++;
		node->active_time = 0;
		if (node->active && node->inactive_time > 30)
			node->active = 0;
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static u_int32_t af_client_hook(void *,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
{
#else
static u_int32_t af_client_hook(unsigned int hook,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
{
#endif
	struct ethhdr *ethhdr = NULL;
	unsigned char smac[ETH_ALEN];
	af_client_info_t *nfc = NULL;
	int pkt_dir = 0;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

	if (ct == NULL)
		return NF_ACCEPT;

	if (skb->protocol == htons(ETH_P_IPV6) && AF_MODE_GATEWAY != af_work_mode)
		return NF_ACCEPT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	pkt_dir = get_packet_dir(state ? state->in : skb->dev, skb);
#else
	if (!in) {
		AF_ERROR("in is NULL\n");
		return NF_ACCEPT;
	}
	pkt_dir = get_packet_dir(in, skb);
#endif

	if (PKT_DIR_UP != pkt_dir)
		return NF_ACCEPT;

	if (skb->protocol == htons(ETH_P_IP))
		iph = ip_hdr(skb);
	else if (skb->protocol == htons(ETH_P_IPV6))
		ip6h = ipv6_hdr(skb);

	ethhdr = skb_mac_header_was_set(skb) ? eth_hdr(skb) : NULL;
	if (ethhdr)
		memcpy(smac, ethhdr->h_source, ETH_ALEN);
	else
		eth_zero_addr(smac);

	AF_CLIENT_LOCK_W();

	if (iph)
		nfc = find_af_client_by_ip(iph->saddr);
	else if (ip6h)
		nfc = find_af_client_by_ipv6(&ip6h->saddr);

	if (!nfc && !is_zero_ether_addr(smac))
		nfc = find_af_client(smac);

	if (!nfc && !is_zero_ether_addr(smac))
		nfc = nf_client_add(smac);

	if (nfc) {
		if (iph && nfc->ip != iph->saddr) {
			AF_DEBUG("update node " MAC_FMT " ipv4 %pI4--->%pI4\n",
				 MAC_ARRAY(nfc->mac), &nfc->ip, &iph->saddr);
			nfc->ip = iph->saddr;
		} else if (ip6h && !ipv6_addr_equal(&nfc->ipv6, &ip6h->saddr)) {
			nfc->ipv6 = ip6h->saddr;
		}

		nfc->flow.up_bytes += skb->len;
		nfc->flow.up_pkts++;
		nfc->update_jiffies = jiffies;
	}

	AF_CLIENT_UNLOCK_W();
	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
static u_int32_t af_client_hook2(void *,
				 struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
#else
static u_int32_t af_client_hook2(unsigned int hook,
				 struct sk_buff *skb,
				 const struct net_device *in,
				 const struct net_device *out,
				 int (*okfn)(struct sk_buff *))
{
#endif
	af_client_info_t *nfc = NULL;
	int pkt_dir = 0;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

	if (ct == NULL)
		return NF_ACCEPT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	pkt_dir = get_packet_dir(state ? state->in : skb->dev, skb);
#else
	if (!in) {
		AF_ERROR("in is NULL\n");
		return NF_ACCEPT;
	}
	pkt_dir = get_packet_dir(in, skb);
#endif

	if (PKT_DIR_DOWN != pkt_dir)
		return NF_ACCEPT;

	AF_CLIENT_LOCK_R();

	if (skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		if (iph)
			nfc = find_af_client_by_ip(iph->daddr);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		ip6h = ipv6_hdr(skb);
		if (ip6h)
			nfc = find_af_client_by_ipv6(&ip6h->daddr);

		if (nfc)
			AF_LMT_DEBUG("found ipv6 %pI6 client\n", &ip6h->daddr);
		else if (ip6h)
			AF_LMT_DEBUG("not found ipv6 %pI6 client\n", &ip6h->daddr);
	}

	if (nfc) {
		nfc->flow.down_bytes += skb->len;
		nfc->flow.down_pkts++;
		nfc->update_jiffies = jiffies;
	}

	AF_CLIENT_UNLOCK_R();
	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
static struct nf_hook_ops af_client_ops[] = {
	{
		.hook = af_client_hook,
		.pf = NFPROTO_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FIRST + 1,
	},
	{
		.hook = af_client_hook2,
		.pf = NFPROTO_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_LAST - 1,
	},
};
#else
static struct nf_hook_ops af_client_ops[] = {
	{
		.hook = af_client_hook,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FIRST + 1,
	},
	{
		.hook = af_client_hook,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FIRST + 1,
	},
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
static void client_timer_handler(struct timer_list *t)
{
	af_client_info_t *client = JMX_FROM_TIMER(client, t, client_timer);
#else
static void client_timer_handler(unsigned long data)
{
	af_client_info_t *client = (af_client_info_t *)data;
#endif
	if (!client) {
		AF_ERROR("client timer handler: invalid client\n");
		return;
	}

	if (client->timer_count >= 30) {
		__af_visit_info_report(client);
		client->timer_count = 0;
	}

	check_expired_visit_info(client);
	af_update_client_status(client);
	client->timer_count++;
	mod_timer(&client->client_timer, jiffies + HZ * 2);
}

static void init_client_timer(af_client_info_t *client)
{
	if (!client) {
		AF_ERROR("init_client_timer: invalid client\n");
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
	timer_setup(&client->client_timer, client_timer_handler, 0);
#else
	setup_timer(&client->client_timer, client_timer_handler, (unsigned long)client);
#endif

	mod_timer(&client->client_timer, jiffies + HZ * 1);
}

static void stop_client_timer(af_client_info_t *client)
{
	if (!client) {
		AF_ERROR("stop_client_timer: invalid client\n");
		return;
	}

	jmx_timer_shutdown_sync(&client->client_timer);
}

int af_client_init(void)
{
	int err;
	u64 generation_seed;

	generation_seed = ktime_get_real_ns();
	if (!generation_seed)
		generation_seed = ((u64)jiffies << 32) | 1;
	atomic64_set(&client_counter_generation, (s64)generation_seed);
	nf_client_list_init();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	err = nf_register_net_hooks(&init_net, af_client_ops, ARRAY_SIZE(af_client_ops));
#else
	err = nf_register_hooks(af_client_ops, ARRAY_SIZE(af_client_ops));
#endif
	if (err)
		AF_ERROR("register client hooks failed!\n");

	return 0;
}

void af_client_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
	nf_unregister_net_hooks(&init_net, af_client_ops, ARRAY_SIZE(af_client_ops));
#else
	nf_unregister_hooks(af_client_ops, ARRAY_SIZE(af_client_ops));
#endif
	nf_client_list_clear();
}
