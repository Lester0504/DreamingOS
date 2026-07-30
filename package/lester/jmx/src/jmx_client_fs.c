
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/netlink.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/version.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/netfilter_bridge.h>
#include <linux/version.h>
#include <linux/time.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/sysctl.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include "jmx_utils.h"

#include "k_json.h"
#include "jmx_log.h"

static inline char *jmx_client_fs_compat_strncpy(char *dst, const char *src, size_t count)
{
	if (!count)
		return dst;
	strscpy(dst, src ? src : "", count);
	return dst;
}

#ifndef strncpy
#define strncpy jmx_client_fs_compat_strncpy
#endif
#include "jmx_client.h"
#include "jmx_client_fs.h"
struct af_client_iter_state
{
    unsigned int bucket;
    void *head;
};

static void *af_client_get_first(struct seq_file *seq)
{
    struct af_client_iter_state *st = seq->private;
    for (st->bucket = 0; st->bucket < MAX_AF_CLIENT_HASH_SIZE; st->bucket++)
    {
        if (!list_empty(&(af_client_list_table[st->bucket])))
        {
            st->head = &(af_client_list_table[st->bucket]);
            return af_client_list_table[st->bucket].next;
        }
    }
    return NULL;
}

static void *af_client_get_next(struct seq_file *seq,
                                void *head)
{
    struct af_client_iter_state *st = seq->private;
    struct hlist_node *node = (struct hlist_node *)head;

    node = node->next;
    if (node != st->head)
    {
        return node;
    }
    else
    {
        st->bucket++;
        for (; st->bucket < MAX_AF_CLIENT_HASH_SIZE; st->bucket++)
        {
            if (!list_empty(&(af_client_list_table[st->bucket])))
            {
                st->head = &(af_client_list_table[st->bucket]);
                return af_client_list_table[st->bucket].next;
            }
        }
        return NULL;
    }
}

static void *af_client_get_idx(struct seq_file *seq, loff_t pos)
{
    void *head = af_client_get_first(seq);

    if (head)
        while (pos && (head = af_client_get_next(seq, head)))
            pos--;

    return pos ? NULL : head;
}

static void *af_client_seq_start(struct seq_file *s, loff_t *pos)
{
    AF_CLIENT_LOCK_R();
    if (*pos == 0)
    {
        return SEQ_START_TOKEN;
    }

    return af_client_get_idx(s, *pos - 1);
}

static void *af_client_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
    (*pos)++;
    if (v == SEQ_START_TOKEN)
        return af_client_get_idx(s, 0);

    return af_client_get_next(s, v);
}

static void af_client_seq_stop(struct seq_file *, void *)
{
    AF_CLIENT_UNLOCK_R();
}

static int af_client_seq_show(struct seq_file *s, void *v)
{
    unsigned char mac_str[32] = {0};
    unsigned char ip_str[32] = {0};
	unsigned char ipv6_str[128];

    static int index = 0;
    af_client_info_t *node = (af_client_info_t *)v;
    if (v == SEQ_START_TOKEN)
    {
        index = 0;
        seq_printf(s, "%-4s %-20s %-20s %-32s  %-16s %-16s\n", "Id", "Mac", "IP", "IPv6", "UpRate", "DownRate");
        return 0;
    }
    index++;
    sprintf(mac_str, MAC_FMT, MAC_ARRAY(node->mac));
    sprintf(ip_str, "%pI4", &node->ip);
	ipv6_to_str(&node->ipv6, ipv6_str);

    seq_printf(s, "%-4d %-20s %-20s %-32s %-16d %-16d\n", index, mac_str, ip_str, ipv6_str, node->rate.up_rate, node->rate.down_rate);
    return 0;
}

static const struct seq_operations nf_client_seq_ops = {
    .start = af_client_seq_start,
    .next = af_client_seq_next,
    .stop = af_client_seq_stop,
    .show = af_client_seq_show};

static int af_client_open(struct inode *, struct file *file)
{
    struct seq_file *seq;
    struct af_client_iter_state *iter;
    int err;

    iter = kzalloc(sizeof(*iter), GFP_KERNEL);
    if (!iter)
        return -ENOMEM;

    err = seq_open(file, &nf_client_seq_ops);
    if (err)
    {
        kfree(iter);
        return err;
    }

    seq = file->private_data;
    seq->private = iter;
    return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations af_client_fops = {
    .owner = THIS_MODULE,
    .open = af_client_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release_private,
};
#else
static const struct proc_ops af_client_fops = {
    .proc_flags = PROC_ENTRY_PERMANENT,
    .proc_read = seq_read,
    .proc_open = af_client_open,
    .proc_lseek = seq_lseek,
    .proc_release = seq_release_private,
};
#endif

#define AF_CLIENT_PROC_STR "af_client"




static int af_visiting_seq_show(struct seq_file *s, void *v)
{
	unsigned char mac_str[32] = {0};
	af_client_info_t *node = (af_client_info_t *)v;
	if (v == SEQ_START_TOKEN)
	{
		seq_printf(s, "%-20s %-12s %-32s\n", "Mac", "Appid", "Url");
		return 0;
	}
	
	sprintf(mac_str, MAC_FMT, MAC_ARRAY(node->mac));
	int visiting_app = 0;
	char visiting_url[64] = {0};
	if (af_get_timestamp_sec()  - node->visiting.app_time < 120){
		visiting_app = node->visiting.visiting_app;
	}
	if ( af_get_timestamp_sec()  - node->visiting.url_time < 120 ){
		strncpy(visiting_url, node->visiting.visiting_url, sizeof(visiting_url));
	}
	else{
		strcpy(visiting_url, "none");
	}
	seq_printf(s, "%-20s %-12d %-32s\n", mac_str, visiting_app, visiting_url);
	
    return 0;
}

static const struct seq_operations nf_visiting_seq_ops = {
    .start = af_client_seq_start,
    .next = af_client_seq_next,
    .stop = af_client_seq_stop,
    .show = af_visiting_seq_show
};


static int af_visiting_open(struct inode *, struct file *file)
{
    struct seq_file *seq;
    struct af_client_iter_state *iter;
    int err;

    iter = kzalloc(sizeof(*iter), GFP_KERNEL);
    if (!iter)
        return -ENOMEM;

    err = seq_open(file, &nf_visiting_seq_ops);
    if (err)
    {
        kfree(iter);
        return err;
    }

    seq = file->private_data;
    seq->private = iter;
    return 0;
}




#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations af_visiting_fops = {
    .owner = THIS_MODULE,
    .open = af_visiting_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release_private,
};
#else
static const struct proc_ops af_visiting_fops = {
    .proc_flags = PROC_ENTRY_PERMANENT,
    .proc_read = seq_read,
    .proc_open = af_visiting_open,
    .proc_lseek = seq_lseek,
    .proc_release = seq_release_private,
};
#endif
#define AF_VISIT_INFO "af_visit"
#define AF_CLIENT_VISIT_LIST "af_client_visit_list"
#define AF_CLIENT_BASE_DIR "jmx_client"


static struct proc_dir_entry *g_af_client_base_dir = NULL;

static DEFINE_MUTEX(af_client_base_dir_mutex);





struct af_client_visit_iter_state
{
	unsigned int client_bucket;
	unsigned int visit_bucket;
	af_client_info_t *current_client;
	struct hlist_node *current_visit_node;
};

static void *af_client_visit_get_first_client(struct seq_file *seq)
{
	struct af_client_visit_iter_state *st = seq->private;
	af_client_info_t *client;

	st->current_client = NULL;
	st->current_visit_node = NULL;
	st->visit_bucket = 0;
	
	for (st->client_bucket = 0; st->client_bucket < MAX_AF_CLIENT_HASH_SIZE; st->client_bucket++) {
		if (!list_empty(&af_client_list_table[st->client_bucket])) {
			client = list_first_entry(&af_client_list_table[st->client_bucket], af_client_info_t, hlist);
			st->current_client = client;
			return client;
		}
	}
	return NULL;
}

static void *af_client_visit_get_next_visit(struct seq_file *seq, af_client_info_t *client)
{
	struct af_client_visit_iter_state *st = seq->private;
	struct hlist_head *head;
	app_visit_info_t *info;
	
	if (!client)
		return NULL;
	
	for (; st->visit_bucket < MAX_VISIT_INFO_HASH_SIZE; st->visit_bucket++) {
		head = &client->visit_info_hash[st->visit_bucket];
		if (!hlist_empty(head)) {
			info = hlist_entry(head->first, app_visit_info_t, hlist);
			st->current_visit_node = head->first;
			return info;
		}
	}
	return NULL;
}

static void *af_client_visit_get_next(struct seq_file *seq)
{
	struct af_client_visit_iter_state *st = seq->private;
	app_visit_info_t *info;
	struct hlist_node *next;
	struct hlist_head *head;
	
	if (!st->current_client)
		return NULL;
	
	if (st->current_visit_node) {
		next = st->current_visit_node->next;
		if (next) {
			st->current_visit_node = next;
			info = hlist_entry(next, app_visit_info_t, hlist);
			return info;
		}
		st->visit_bucket++;
		st->current_visit_node = NULL;
	}
	
	for (; st->visit_bucket < MAX_VISIT_INFO_HASH_SIZE; st->visit_bucket++) {
		head = &st->current_client->visit_info_hash[st->visit_bucket];
		if (!hlist_empty(head)) {
			st->current_visit_node = head->first;
			info = hlist_entry(head->first, app_visit_info_t, hlist);
			return info;
		}
	}
	
	return NULL;
}

static void *af_client_visit_get_next_client(struct seq_file *seq)
{
	struct af_client_visit_iter_state *st = seq->private;
	af_client_info_t *client;
	struct list_head *next;
	void *visit;
	
	if (!st->current_client)
		return NULL;

	for (;;) {
		next = st->current_client->hlist.next;
		if (next != &af_client_list_table[st->client_bucket]) {
			client = list_entry(next, af_client_info_t, hlist);
		} else {
			st->client_bucket++;
			while (st->client_bucket < MAX_AF_CLIENT_HASH_SIZE &&
			       list_empty(&af_client_list_table[st->client_bucket]))
				st->client_bucket++;

			if (st->client_bucket >= MAX_AF_CLIENT_HASH_SIZE) {
				st->current_client = NULL;
				return NULL;
			}

			client = list_first_entry(&af_client_list_table[st->client_bucket],
						  af_client_info_t, hlist);
		}

		st->current_client = client;
		st->visit_bucket = 0;
		st->current_visit_node = NULL;
		visit = af_client_visit_get_next_visit(seq, client);
		if (visit)
			return visit;
	}
}

static void *af_client_visit_seq_start(struct seq_file *s, loff_t *pos)
{
	loff_t remaining = *pos;
	void *v = NULL;
	
	AF_CLIENT_LOCK_R();
	
	if (*pos == 0) {
		return SEQ_START_TOKEN;
	}
	
	v = af_client_visit_get_first_client(s);
	if (!v)
		return NULL;
	
	v = af_client_visit_get_next_visit(s, (af_client_info_t *)v);
	if (!v)
		v = af_client_visit_get_next_client(s);

	/* Position zero is the header; rebuild record positions without
	 * modifying seq_file's persistent cursor. */
	while (remaining > 1 && v) {
		v = af_client_visit_get_next(s);
		if (!v)
			v = af_client_visit_get_next_client(s);
		remaining--;
	}
	
	return v;
}

static void *af_client_visit_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	void *next;
	
	(*pos)++;
	
	if (v == SEQ_START_TOKEN) {
		next = af_client_visit_get_first_client(s);
		if (!next)
			return NULL;
		next = af_client_visit_get_next_visit(s, (af_client_info_t *)next);
		if (!next)
			next = af_client_visit_get_next_client(s);
		return next;
	}
	
	next = af_client_visit_get_next(s);
	if (!next) {
		next = af_client_visit_get_next_client(s);
	}
	
	return next;
}

static void af_client_visit_seq_stop(struct seq_file *, void *)
{
	AF_CLIENT_UNLOCK_R();
}

static void print_client_visit_header(struct seq_file *s)
{
	seq_printf(s, "%-20s %-8s %-8s %-8s %-8s %-8s %-12s %-12s %-10s %-14s %-14s %-14s %-20s %s\n",
		   "MAC", "AppID", "TotalNum", "DropNum", "Conn", "IsHttp",
		   "LatestTime", "LatestAction", "OfflineTime", "InBytes",
		   "OutBytes", "TotalBytes", "counter_generation", "byte_semantics");
}

static int af_client_visit_seq_show(struct seq_file *s, void *v)
{
	unsigned char mac_str[32] = {0};
	app_visit_info_t *info = (app_visit_info_t *)v;
	struct af_client_visit_iter_state *st = s->private;
	
	if (v == SEQ_START_TOKEN) {
		print_client_visit_header(s);
		return 0;
	}
	
	if (!info || !st->current_client)
		return 0;

	/* Skip stale entries (no activity for 10 minutes) */
	{
		u_int32_t now = af_get_timestamp_sec();
		u_int32_t stale = (now > info->latest_time) ? (now - info->latest_time) : 0;
		if (stale > 600)
			return 0;
	}
	
	sprintf(mac_str, MAC_FMT, MAC_ARRAY(st->current_client->mac));
	
	spin_lock_bh(&st->current_client->visit_info_lock);
	u_int32_t cur_time = af_get_timestamp_sec();
	u_int32_t offline_time = (cur_time > info->latest_time) ? (cur_time - info->latest_time) : 0;
	seq_printf(s, "%-20s  %-8u %-8u %-8u  %-8u %-8u %-12lu %-12u %-10u %-14llu %-14llu %-14llu %-20llu %s\n",
	           mac_str,
	           info->app_id,
	           info->total_num,
	           info->drop_num,
	           info->conn_count,
	           info->is_http,
	           info->latest_time,
	           info->latest_action,
	           offline_time,
	           info->in_bytes,
	           info->out_bytes,
	           info->total_bytes,
	           af_client_counter_generation(),
	           JMX_CLIENT_BYTE_SEMANTICS);
	spin_unlock_bh(&st->current_client->visit_info_lock);
	
	return 0;
}

static const struct seq_operations af_client_visit_seq_ops = {
	.start = af_client_visit_seq_start,
	.next = af_client_visit_seq_next,
	.stop = af_client_visit_seq_stop,
	.show = af_client_visit_seq_show
};

static int af_client_visit_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	struct af_client_visit_iter_state *iter;
	int err;
	
	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter)
		return -ENOMEM;
	
	err = seq_open(file, &af_client_visit_seq_ops);
	if (err) {
		kfree(iter);
		return err;
	}
	
	seq = file->private_data;
	seq->private = iter;
	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations af_client_visit_fops = {
	.owner = THIS_MODULE,
	.open = af_client_visit_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};
#else
static const struct proc_ops af_client_visit_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_read = seq_read,
	.proc_open = af_client_visit_open,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release_private,
};
#endif

int init_af_client_procfs(void)
{
	struct proc_dir_entry *pde;
	pde = proc_create(AF_CLIENT_PROC_STR, 0440, jmx_proc_root, &af_client_fops);

    if (!pde)
    {
        AF_ERROR("nf_client proc file created error\n");
        return -1;
    }

    pde = proc_create(AF_VISIT_INFO, 0440, jmx_proc_root, &af_visiting_fops);
	if (!pde)
	{
	  AF_ERROR("nf_client visiting info proc file created error\n");
	  return -1;
	}
	
	pde = proc_create(AF_CLIENT_VISIT_LIST, 0440, jmx_proc_root, &af_client_visit_fops);
	if (!pde)
	{
		AF_ERROR("nf_client visit list proc file created error\n");
		return -1;
	}
    return 0;
}

void finit_af_client_procfs(void)
{
	int i;
    af_client_info_t *client;
    
    mutex_lock(&af_client_base_dir_mutex);
    

    if (g_af_client_base_dir) {
        AF_CLIENT_LOCK_R();
        for (i = 0; i < MAX_AF_CLIENT_HASH_SIZE; i++) {
            list_for_each_entry(client, &af_client_list_table[i], hlist) {
                if (client && client->proc_dir) {
                    remove_client_proc_dir(client);
                }
            }
        }
        AF_CLIENT_UNLOCK_R();
    }
    

    remove_proc_entry(AF_CLIENT_PROC_STR, jmx_proc_root);
    remove_proc_entry(AF_VISIT_INFO, jmx_proc_root);
    remove_proc_entry(AF_CLIENT_VISIT_LIST, jmx_proc_root);
    

    remove_proc_entry(AF_CLIENT_BASE_DIR, jmx_proc_root);
    g_af_client_base_dir = NULL;  // 重置静态变量
    mutex_unlock(&af_client_base_dir_mutex);
}

static void print_single_client_visit_header(struct seq_file *s)
{
	seq_printf(s, "%-8s %-8s %-8s %-8s %-8s %-12s %-12s %-10s\n",
	           "AppID", "TotalNum", "DropNum", "Conn", "IsHttp", "LatestTime", "LatestAction", "OfflineTime");
}

struct single_client_visit_iter_state
{
	af_client_info_t *client;
	struct single_client_visit_snapshot *snapshots;
	unsigned int snapshot_count;
	bool snapshot_truncated;
};

struct single_client_visit_snapshot
{
	unsigned int app_id;
	unsigned int total_num;
	unsigned int drop_num;
	unsigned int conn_count;
	unsigned int is_http;
	unsigned long latest_time;
	unsigned int latest_action;
};

static void single_client_visit_take_snapshot(struct single_client_visit_iter_state *st)
{
	app_visit_info_t *info;
	unsigned int bucket;

	spin_lock_bh(&st->client->visit_info_lock);
	for (bucket = 0; bucket < MAX_VISIT_INFO_HASH_SIZE; bucket++) {
		hlist_for_each_entry(info, &st->client->visit_info_hash[bucket], hlist) {
			struct single_client_visit_snapshot *snapshot;

			if (st->snapshot_count >= MAX_RECORD_APP_NUM) {
				st->snapshot_truncated = true;
				goto out_unlock;
			}

			snapshot = &st->snapshots[st->snapshot_count++];
			snapshot->app_id = info->app_id;
			snapshot->total_num = info->total_num;
			snapshot->drop_num = info->drop_num;
			snapshot->conn_count = info->conn_count;
			snapshot->is_http = info->is_http;
			snapshot->latest_time = info->latest_time;
			snapshot->latest_action = info->latest_action;
		}
	}

out_unlock:
	spin_unlock_bh(&st->client->visit_info_lock);
}

static void *single_client_visit_seq_start(struct seq_file *s, loff_t *pos)
{
	struct single_client_visit_iter_state *st = s->private;
	loff_t index;

	if (!st || !st->snapshots || !st->client || *pos < 0)
		return NULL;

	if (*pos == 0)
		return SEQ_START_TOKEN;

	index = *pos - 1;
	return index < st->snapshot_count ? &st->snapshots[index] : NULL;
}

static void *single_client_visit_seq_next(struct seq_file *s, void *, loff_t *pos)
{
	struct single_client_visit_iter_state *st = s->private;
	loff_t index;

	(*pos)++;
	index = *pos - 1;
	return index < st->snapshot_count ? &st->snapshots[index] : NULL;
}

static void single_client_visit_seq_stop(struct seq_file *, void *)
{
}

static int single_client_visit_seq_show(struct seq_file *s, void *v)
{
	struct single_client_visit_snapshot *snapshot = v;
	u_int32_t cur_time;
	u_int32_t offline_time;
	
	if (v == SEQ_START_TOKEN) {
		print_single_client_visit_header(s);
		return 0;
	}
	
	if (!snapshot)
		return 0;
	
	cur_time = af_get_timestamp_sec();
	offline_time = (cur_time > snapshot->latest_time) ?
		(cur_time - snapshot->latest_time) : 0;
	seq_printf(s, "%-8u %-8u %-8u %-8u %-8u %-12lu %-12u %-10u\n",
	           snapshot->app_id,
	           snapshot->total_num,
	           snapshot->drop_num,
	           snapshot->conn_count,
	           snapshot->is_http,
	           snapshot->latest_time,
	           snapshot->latest_action,
	           offline_time);
	
	return 0;
}

static const struct seq_operations single_client_visit_seq_ops = {
	.start = single_client_visit_seq_start,
	.next = single_client_visit_seq_next,
	.stop = single_client_visit_seq_stop,
	.show = single_client_visit_seq_show
};

static int single_client_visit_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	struct single_client_visit_iter_state *iter;
	af_client_info_t *client;
	int err;
	
#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
	client = PDE_DATA(inode);
#else
	client = (af_client_info_t *)proc_get_parent_data(inode);
#endif
	
	if (!client)
		return -ENOENT;
	if (!af_client_get_if_live(client))
		return -ENOENT;
	
	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter) {
		af_client_put(client);
		return -ENOMEM;
	}

	iter->client = client;
	iter->snapshots = kcalloc(MAX_RECORD_APP_NUM,
	                           sizeof(*iter->snapshots), GFP_KERNEL);
	if (!iter->snapshots) {
		kfree(iter);
		af_client_put(client);
		return -ENOMEM;
	}
	single_client_visit_take_snapshot(iter);

	err = seq_open(file, &single_client_visit_seq_ops);
	if (err) {
		kfree(iter->snapshots);
		kfree(iter);
		af_client_put(client);
		return err;
	}
	
	seq = file->private_data;
	seq->private = iter;
	return 0;
}

static int single_client_visit_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct single_client_visit_iter_state *iter = seq ? seq->private : NULL;
	af_client_info_t *client = iter ? iter->client : NULL;
	struct single_client_visit_snapshot *snapshots =
		iter ? iter->snapshots : NULL;
	int ret;

	kfree(snapshots);
	ret = seq_release_private(inode, file);

	af_client_put(client);
	return ret;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 5, 0)
static const struct file_operations single_client_visit_fops = {
	.owner = THIS_MODULE,
	.open = single_client_visit_open,
	.read = seq_read,
	.llseek = seq_lseek,
		.release = single_client_visit_release,
};
#else
static const struct proc_ops single_client_visit_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_read = seq_read,
	.proc_open = single_client_visit_open,
	.proc_lseek = seq_lseek,
	.proc_release = single_client_visit_release,
};
#endif

int create_client_proc_dir(af_client_info_t *client)
{
	struct proc_dir_entry *client_dir;
	struct proc_dir_entry *visit_file;
	char mac_str[32] = {0};
	
	if (!client)
		return -1;
	
	sprintf(mac_str, MAC_FMT, MAC_ARRAY(client->mac));
	
	mutex_lock(&af_client_base_dir_mutex);
	if (!g_af_client_base_dir) {

		g_af_client_base_dir = proc_mkdir(AF_CLIENT_BASE_DIR, jmx_proc_root);
		if (!g_af_client_base_dir) {
			mutex_unlock(&af_client_base_dir_mutex);
			AF_ERROR("create af_client base dir failed\n");
			return -1;
		}
	}
	mutex_unlock(&af_client_base_dir_mutex);
	
	client_dir = proc_mkdir_data(mac_str, 0555, g_af_client_base_dir, client);
	if (!client_dir) {
		AF_ERROR("create client dir failed: %s\n", mac_str);
		return -1;
	}
	
	client->proc_dir = client_dir;
	refcount_inc(&client->refs);
	client->proc_ref_held = true;
	
	visit_file = proc_create_data("visit_list", 0444, client_dir, &single_client_visit_fops, client);
	if (!visit_file) {
		AF_ERROR("create visit_list file failed for client: %s\n", mac_str);
		proc_remove(client_dir);
		client->proc_dir = NULL;
		client->proc_ref_held = false;
		af_client_put(client);
		return -1;
	}
	
	return 0;
}

void remove_client_proc_dir(af_client_info_t *client)
{
	bool put_ref;

	if (!client || !client->proc_dir)
		return;
	put_ref = client->proc_ref_held;
	proc_remove(client->proc_dir);
	client->proc_dir = NULL;
	client->proc_ref_held = false;
	if (put_ref)
		af_client_put(client);
}
