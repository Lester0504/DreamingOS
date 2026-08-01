
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/etherdevice.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include "k_json.h"
#include "jmx.h"
#include "jmx_app_filter.h"
#include "jmx_mac.h"
#include "jmx_log.h"

static DEFINE_RWLOCK(app_filter_lock);

#define app_filter_read_lock() read_lock_bh(&app_filter_lock);
#define app_filter_read_unlock() read_unlock_bh(&app_filter_lock);
#define app_filter_write_lock() write_lock_bh(&app_filter_lock);
#define app_filter_write_unlock() write_unlock_bh(&app_filter_lock);
int g_appfilter_enable = 0;
u_int32_t g_appfilter_update_jiffies = 0;

static int g_app_rule_count = 0;
static LIST_HEAD(app_filter_rule_list);
static struct proc_dir_entry *app_filter_rules_proc;


static mac_config_t g_app_filter_whitelist;

static u64 jmx_app_filter_mix_id(u32 value)
{
    u64 mixed = (u64)value + 0x9e3779b97f4a7c15ULL;

    mixed = (mixed ^ (mixed >> 30)) * 0xbf58476d1ce4e5b9ULL;
    mixed = (mixed ^ (mixed >> 27)) * 0x94d049bb133111ebULL;
    return mixed ^ (mixed >> 31);
}

static u64 jmx_app_filter_mac_value(const unsigned char *mac)
{
    u64 value = 0;

    for (int i = 0; i < ETH_ALEN; i++)
        value = (value << 8) | mac[i];
    return value;
}


static void app_id_config_init(app_id_config_t *config) {
    int i;
    for (i = 0; i < 256; i++) {
        INIT_HLIST_HEAD(&config->hash_table[i]);
    }
    config->count = 0;
}


static void flush_app_id_list(app_id_config_t *config) {
    int i;
    app_id_node_t *node;
    struct hlist_node *n;
    
    for (i = 0; i < 256; i++) {
        hlist_for_each_entry_safe(node, n, &config->hash_table[i], hlist) {
            hlist_del(&node->hlist);
            kfree(node);
        }
    }
    config->count = 0;
}


static app_id_node_t *find_app_id_node(app_id_config_t *config, int app_id) {
    int hash = app_id % 256;
    app_id_node_t *node;
    
    hlist_for_each_entry(node, &config->hash_table[hash], hlist) {
        if (node->app_id == app_id) {
            return node;
        }
    }
    return NULL;
}


static int add_app_id_node(app_id_config_t *config, int app_id) {
    app_id_node_t *node;
    int hash;
    

    if (find_app_id_node(config, app_id)) {
        return 0;  // 已存在，返回成功
    }
    
    if (config->count >= MAX_APP_ID_PER_RULE) {
        AF_ERROR("app id count exceeds limit\n");
        return -1;
    }
    
    node = kmalloc(sizeof(app_id_node_t), GFP_ATOMIC);
    if (!node) {
        AF_ERROR("kmalloc app_id_node failed\n");
        return -1;
    }
    
    node->app_id = app_id;
    hash = app_id % 256;
    hlist_add_head(&node->hlist, &config->hash_table[hash]);
    config->count++;
    
    return 0;
}

static int jmx_app_filter_rules_proc_show(struct seq_file *s, void *v)
{
    app_filter_rule_t *rule;

    seq_puts(s, "rule_id enabled app_count mac_count app_hash_xor app_hash_sum mac_value hits last_hit_s\n");
    app_filter_read_lock();
    list_for_each_entry(rule, &app_filter_rule_list, list) {
        int mac_count = 0;
        int i;
        struct mac_node *mac_node;
        app_id_node_t *app_node;
        u64 app_hash_xor = 0;
        u64 app_hash_sum = 0;
        u64 mac_value = 0;

        for (i = 0; i < MAC_HASH_SIZE; i++) {
            hlist_for_each_entry(mac_node, &rule->mac_list.hash_table[i], hlist) {
                mac_count++;
                mac_value ^= jmx_app_filter_mac_value(mac_node->mac);
            }
        }
        for (i = 0; i < 256; i++) {
            hlist_for_each_entry(app_node, &rule->app_id_list.hash_table[i], hlist) {
                u64 mixed = jmx_app_filter_mix_id((u32)app_node->app_id);
                app_hash_xor ^= mixed;
                app_hash_sum += mixed;
            }
        }
        seq_printf(s, "%d %d %d %d %016llx %016llx %012llx %lld %lld\n",
                   rule->rule_id, rule->enable, rule->app_id_list.count,
                   mac_count, (unsigned long long)app_hash_xor,
                   (unsigned long long)app_hash_sum,
                   (unsigned long long)mac_value,
                   (long long)atomic64_read(&rule->hit_count),
                   (long long)atomic64_read(&rule->last_hit_s));
    }
    app_filter_read_unlock();
    return 0;
}

static int jmx_app_filter_rules_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, jmx_app_filter_rules_proc_show, NULL);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
static const struct file_operations jmx_app_filter_rules_proc_ops = {
    .owner = THIS_MODULE,
    .open = jmx_app_filter_rules_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
#else
static const struct proc_ops jmx_app_filter_rules_proc_ops = {
    .proc_open = jmx_app_filter_rules_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#endif

int jmx_app_filter_init(void) {
    app_filter_write_lock();
    INIT_LIST_HEAD(&app_filter_rule_list);
    g_app_rule_count = 0;
    jmx_mac_config_init(&g_app_filter_whitelist);
    app_filter_write_unlock();

    app_filter_rules_proc = proc_create("app_filter_rules", 0444,
                                        jmx_proc_root,
                                        &jmx_app_filter_rules_proc_ops);
    if (!app_filter_rules_proc) {
        AF_ERROR("failed to create app_filter_rules proc entry\n");
        return -ENOMEM;
    }
    
    AF_INFO("app filter init...ok\n");
    return 0;
}

void jmx_app_filter_exit(void) {
    app_filter_rule_t *rule, *next;

    if (app_filter_rules_proc) {
        remove_proc_entry("app_filter_rules", jmx_proc_root);
        app_filter_rules_proc = NULL;
    }
    app_filter_write_lock();
    list_for_each_entry_safe(rule, next, &app_filter_rule_list, list) {
        flush_app_id_list(&rule->app_id_list);
        jmx_flush_mac_list(&rule->mac_list);
        list_del(&rule->list);
        kfree(rule);
    }
    g_app_rule_count = 0;
    jmx_flush_mac_list(&g_app_filter_whitelist);
    app_filter_write_unlock();
    AF_INFO("app filter exit...ok\n");
}

static app_filter_rule_t *jmx_find_app_filter_rule(int rule_id) {
    app_filter_rule_t *rule;
    list_for_each_entry(rule, &app_filter_rule_list, list) {
        if (rule->rule_id == rule_id) {
            return rule;
        }
    }
    return NULL;
}

static void jmx_update_appfilter_jiffies(void){
    g_appfilter_update_jiffies = jiffies;
}



static int jmx_add_app_filter_rule(int rule_id) {
    app_filter_rule_t *rule;
    
    if (g_app_rule_count >= MAX_APP_FILTER_RULE_NUM) {
        AF_ERROR("app filter rule count exceeds limit\n");
        return -1;
    }
    
    if (jmx_find_app_filter_rule(rule_id)) {
        AF_ERROR("app filter rule %d already exists\n", rule_id);
        return -1;
    }
    
    rule = kmalloc(sizeof(app_filter_rule_t), GFP_ATOMIC);
    if (!rule) {
        AF_ERROR("kmalloc app filter rule failed\n");
        return -1;
    }
    
    rule->rule_id = rule_id;
    rule->enable = 1;
    atomic64_set(&rule->hit_count, 0);
    atomic64_set(&rule->last_hit_s, 0);
    jmx_mac_config_init(&rule->mac_list);
    app_id_config_init(&rule->app_id_list);
    INIT_LIST_HEAD(&rule->list);
    
    app_filter_write_lock();
    list_add(&rule->list, &app_filter_rule_list);
    g_app_rule_count++;
    app_filter_write_unlock();
	
    AF_INFO("add app filter rule %d ok\n", rule_id);
    return 0;
}

static int jmx_del_app_filter_rule(int rule_id) {
    app_filter_rule_t *rule;
    
    app_filter_write_lock();
    rule = jmx_find_app_filter_rule(rule_id);
    if (rule) {
        flush_app_id_list(&rule->app_id_list);
        jmx_flush_mac_list(&rule->mac_list);
        list_del(&rule->list);
        kfree(rule);
        g_app_rule_count--;
        app_filter_write_unlock();
        AF_INFO("del app filter rule %d ok\n", rule_id);
        return 0;
    }
    app_filter_write_unlock();
    
    AF_ERROR("app filter rule %d not found\n", rule_id);
    return -1;
}

static int jmx_del_app_id_from_rule(int rule_id, int app_id) {
    app_filter_rule_t *rule;
    app_id_node_t *node;
    int hash;
    
    app_filter_write_lock();
    rule = jmx_find_app_filter_rule(rule_id);
    if (rule) {
        hash = app_id % 256;
        hlist_for_each_entry(node, &rule->app_id_list.hash_table[hash], hlist) {
            if (node->app_id == app_id) {
                hlist_del(&node->hlist);
                kfree(node);
                rule->app_id_list.count--;
                app_filter_write_unlock();
                return 0;
            }
        }
    }
    app_filter_write_unlock();
    
    AF_ERROR("app_id %d or rule %d not found\n", app_id, rule_id);
    return -1;
}


int jmx_match_app_filter_rule_record(int app_id, const unsigned char *mac,
                                     int *rule_id)
{
    app_filter_rule_t *rule;
    app_id_node_t *node;
    struct mac_node *mac_node;
    int i;
    int mac_list_empty;

    app_filter_read_lock();
    list_for_each_entry(rule, &app_filter_rule_list, list) {
        if (!rule->enable)
            continue;
        mac_node = jmx_find_mac_node(&rule->mac_list, mac);
        if (!mac_node) {
            mac_list_empty = 1;
            for (i = 0; i < MAC_HASH_SIZE; i++) {
                if (!hlist_empty(&rule->mac_list.hash_table[i])) {
                    mac_list_empty = 0;
                    break;
                }
            }
            if (!mac_list_empty)
                continue;
        }
        node = find_app_id_node(&rule->app_id_list, app_id);
        if (!node)
            continue;
        atomic64_inc(&rule->hit_count);
        atomic64_set(&rule->last_hit_s, (s64)ktime_get_real_seconds());
        if (rule_id)
            *rule_id = rule->rule_id;
        app_filter_read_unlock();
        return 1;
    }
    app_filter_read_unlock();
    return 0;
}

int jmx_api_add_app_filter_rule(cJSON *data_obj) {
    cJSON *rule_id_obj;
    
    if (!data_obj) {
        return -1;
    }
    
    rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
    
    if (!rule_id_obj) {
        AF_ERROR("invalid rule format\n");
        return -1;
    }
    
	jmx_update_appfilter_jiffies();

    if (jmx_add_app_filter_rule(rule_id_obj->valueint) < 0) {
        return -1;
    }
    AF_INFO("add app filter rule %d ok\n", rule_id_obj->valueint);
    
    return 0;
}

int jmx_api_mod_app_filter_rule(cJSON *data_obj) {
    int i;
    cJSON *rule_id_obj;
    cJSON *app_id_array;
    cJSON *app_id_obj;
    cJSON *action_obj;
    cJSON *enable_obj;
    app_filter_rule_t *rule = NULL;
    
    if (!data_obj) {
        return -1;
    }
    
    rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
    action_obj = cJSON_GetObjectItem(data_obj, "app_action");
    cJSON *mac_action_obj = cJSON_GetObjectItem(data_obj, "mac_action");
    
    if (!rule_id_obj) {
        AF_ERROR("rule_id not found\n");
        return -1;
    }
    

    rule = jmx_find_app_filter_rule(rule_id_obj->valueint);
    if (!rule) {
        AF_ERROR("rule %d not found\n", rule_id_obj->valueint);
        return -1;
    }
    

    if (mac_action_obj) {
        if (mac_action_obj->valueint == 1 || mac_action_obj->valueint == 2) {
            cJSON *mac_array = cJSON_GetObjectItem(data_obj, "mac_list");
            if (mac_array) {
                app_filter_write_lock();
                if (mac_action_obj->valueint == 1) {  // flush old
                    jmx_flush_mac_list(&rule->mac_list);
                }
                for (i = 0; i < cJSON_GetArraySize(mac_array); i++) {
                    cJSON *mac_obj = cJSON_GetArrayItem(mac_array, i);
                    u8 mac_bin[ETH_ALEN] = {0};
                    if (mac_obj && mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
                        jmx_add_mac_node(&rule->mac_list, mac_bin);
                    }
                }
                app_filter_write_unlock();
            }
        } else if (mac_action_obj->valueint == 3) {
            cJSON *mac_obj = cJSON_GetObjectItem(data_obj, "mac");
            if (mac_obj) {
                app_filter_write_lock();
                u8 mac_bin[ETH_ALEN] = {0};
                if (mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
                    jmx_add_mac_node(&rule->mac_list, mac_bin);
                }
                app_filter_write_unlock();
            }
        } else {

            app_filter_write_lock();
            jmx_flush_mac_list(&rule->mac_list);
            app_filter_write_unlock();
        }
    }
    

    if (action_obj) {
        if (action_obj->valueint == 1 || action_obj->valueint == 2) {

            app_id_array = cJSON_GetObjectItem(data_obj, "app_id_list");
            if (app_id_array) {
                app_filter_write_lock();
                if (action_obj->valueint == 1) {  // flush old
                    flush_app_id_list(&rule->app_id_list);
                }
                for (i = 0; i < cJSON_GetArraySize(app_id_array); i++) {
                    app_id_obj = cJSON_GetArrayItem(app_id_array, i);
                    if (app_id_obj) {
                        add_app_id_node(&rule->app_id_list, app_id_obj->valueint);
                    }
                }
                app_filter_write_unlock();
            }
        } else if (action_obj->valueint == 3) {

            app_id_obj = cJSON_GetObjectItem(data_obj, "app_id");
            if (app_id_obj) {
                app_filter_write_lock();
                add_app_id_node(&rule->app_id_list, app_id_obj->valueint);
                app_filter_write_unlock();
            }
        } else {

            app_filter_write_lock();
            flush_app_id_list(&rule->app_id_list);
            app_filter_write_unlock();
        }
    }
    
    enable_obj = cJSON_GetObjectItem(data_obj, "enable");
    if (enable_obj) {
        rule->enable = enable_obj->valueint;
    }
    
	jmx_update_appfilter_jiffies();
    return 0;
}

int jmx_api_del_app_filter_rule(cJSON *data_obj) {
    cJSON *rule_id_obj;
    cJSON *app_id_obj;
    
    if (!data_obj) {
        return -1;
    }
    
    rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
    if (!rule_id_obj) {
        AF_ERROR("rule_id not found\n");
        return -1;
    }
    
	jmx_update_appfilter_jiffies();
    app_id_obj = cJSON_GetObjectItem(data_obj, "app_id");
    if (app_id_obj) {

        return jmx_del_app_id_from_rule(rule_id_obj->valueint, app_id_obj->valueint);
    } else {

        return jmx_del_app_filter_rule(rule_id_obj->valueint);
    }
}

int jmx_api_dump_app_filter_rule(cJSON *data_obj) {
    app_filter_rule_t *rule;
    app_id_node_t *node;
    struct mac_node *mac_node;
    int app_count = 0;
    int mac_count = 0;
    int i;
    
    if (!data_obj) {
        return -1;
    }
    
    cJSON *rule_id_obj = cJSON_GetObjectItem(data_obj, "rule_id");
    
    app_filter_read_lock();
    

    printk("\n");
    printk("+--------+-------+------------------+------------------+\n");
    printk("| RuleID | Enable| MAC List         | App ID List      |\n");
    printk("+--------+-------+------------------+------------------+\n");
    
    if (rule_id_obj) {
        rule = jmx_find_app_filter_rule(rule_id_obj->valueint);
        if (rule) {

            for (i = 0; i < MAC_HASH_SIZE; i++) {
                hlist_for_each_entry(mac_node, &rule->mac_list.hash_table[i], hlist) {
                    mac_count++;
                }
            }
            for (i = 0; i < 256; i++) {
                hlist_for_each_entry(node, &rule->app_id_list.hash_table[i], hlist) {
                    app_count++;
                }
            }
            

            printk(KERN_CONT "| %-6d | %-5d | ", rule->rule_id, rule->enable);
            

            if (mac_count == 0) {
                printk(KERN_CONT "%-16s | ", "(all MACs)");
            } else {
                int total_mac_count = mac_count;
                mac_count = 0;
                for (i = 0; i < MAC_HASH_SIZE; i++) {
                    hlist_for_each_entry(mac_node, &rule->mac_list.hash_table[i], hlist) {
                        if (mac_count > 0) {
                            printk(KERN_CONT ", ");
                        }
                        printk(KERN_CONT "%pM", mac_node->mac);
                        mac_count++;
                        if (mac_count >= 3) {  // 最多显示3个MAC
                            if (mac_count < total_mac_count) {
                                printk(KERN_CONT "...");
                            }
                            break;
                        }
                    }
                }
                printk(KERN_CONT " | ");
            }
            

            if (app_count == 0) {
                printk(KERN_CONT "%-16s |\n", "(empty)");
            } else {
                int total_app_count = app_count;
                int printed_count = 0;
                int should_break = 0;
                app_count = 0;
                for (i = 0; i < 256 && !should_break; i++) {
                    hlist_for_each_entry(node, &rule->app_id_list.hash_table[i], hlist) {
                        if (printed_count > 0) {
                            printk(KERN_CONT ", ");
                        }
                        printk(KERN_CONT "%d", node->app_id);
                        printed_count++;
                        app_count++;
                        if (printed_count >= 5) {  // 最多显示5个App ID
                            if (app_count < total_app_count) {
                                printk(KERN_CONT "...");
                            }
                            should_break = 1;
                            break;
                        }
                    }
                }
                printk(KERN_CONT " |\n");
            }
        }
    } else {
        list_for_each_entry(rule, &app_filter_rule_list, list) {
            app_count = 0;
            mac_count = 0;
            

            for (i = 0; i < MAC_HASH_SIZE; i++) {
                hlist_for_each_entry(mac_node, &rule->mac_list.hash_table[i], hlist) {
                    mac_count++;
                }
            }
            for (i = 0; i < 256; i++) {
                hlist_for_each_entry(node, &rule->app_id_list.hash_table[i], hlist) {
                    app_count++;
                }
            }
            

            printk(KERN_CONT "| %-6d | %-5d | ", rule->rule_id, rule->enable);
            

            if (mac_count == 0) {
                printk(KERN_CONT "%-16s | ", "(all MACs)");
            } else {
                int total_mac_count = mac_count;
                mac_count = 0;
                for (i = 0; i < MAC_HASH_SIZE; i++) {
                    hlist_for_each_entry(mac_node, &rule->mac_list.hash_table[i], hlist) {
                        if (mac_count > 0) {
                            printk(KERN_CONT ", ");
                        }
                        printk(KERN_CONT "%pM", mac_node->mac);
                        mac_count++;
                        if (mac_count >= 3) {  // 最多显示3个MAC
                            if (mac_count < total_mac_count) {
                                printk(KERN_CONT "...");
                            }
                            break;
                        }
                    }
                }
                printk(KERN_CONT " | ");
            }
            

            if (app_count == 0) {
                printk(KERN_CONT "%-16s |\n", "(empty)");
            } else {
                int total_app_count = app_count;
                int printed_count = 0;
                int should_break = 0;
                app_count = 0;
                for (i = 0; i < 256 && !should_break; i++) {
                    hlist_for_each_entry(node, &rule->app_id_list.hash_table[i], hlist) {
                        if (printed_count > 0) {
                            printk(KERN_CONT ", ");
                        }
                        printk(KERN_CONT "%d", node->app_id);
                        printed_count++;
                        app_count++;
                        if (printed_count >= 5) {  // 最多显示5个App ID
                            if (app_count < total_app_count) {
                                printk(KERN_CONT "...");
                            }
                            should_break = 1;
                            break;
                        }
                    }
                }
                printk(KERN_CONT " |\n");
            }
        }
    }
    
    printk("+--------+-------+------------------+------------------+\n");
    

    printk("\n");
    printk("App Filter Whitelist:\n");
    printk("+----------------------------------------+\n");
    printk("| MAC Address                           |\n");
    printk("+----------------------------------------+\n");
    
    int total_whitelist_count = 0;
    struct mac_node *whitelist_node;
    for (i = 0; i < MAC_HASH_SIZE; i++) {
        hlist_for_each_entry(whitelist_node, &g_app_filter_whitelist.hash_table[i], hlist) {
            total_whitelist_count++;
        }
    }
    
    if (total_whitelist_count == 0) {
        printk(KERN_CONT "| %-38s |\n", "(empty)");
    } else {
        int printed_count = 0;
        int should_break = 0;
        
        for (i = 0; i < MAC_HASH_SIZE && !should_break; i++) {
            hlist_for_each_entry(whitelist_node, &g_app_filter_whitelist.hash_table[i], hlist) {
                printk(KERN_CONT "| %-38pM |\n", whitelist_node->mac);
                printed_count++;
                if (printed_count >= 10) {  // 最多显示10个MAC
                    if (printed_count < total_whitelist_count) {
                        printk(KERN_CONT "| %-38s |\n", "...");
                    }
                    should_break = 1;
                    break;
                }
            }
        }
    }
    
    printk("+----------------------------------------+\n");
    printk("Total whitelist entries: %d\n", total_whitelist_count);
    
    app_filter_read_unlock();
    
    return 0;
}

int jmx_api_flush_app_filter_rule(cJSON *data_obj) {
    app_filter_rule_t *rule, *next;
    
    app_filter_write_lock();
    list_for_each_entry_safe(rule, next, &app_filter_rule_list, list) {
        flush_app_id_list(&rule->app_id_list);
        list_del(&rule->list);
        kfree(rule);
    }
    g_app_rule_count = 0;
    app_filter_write_unlock();
    
	jmx_update_appfilter_jiffies();
    return 0;
}


int jmx_match_app_filter_whitelist(const unsigned char *mac) {
    struct mac_node *node;
    int ret = 0;

    app_filter_read_lock();
    node = jmx_find_mac_node(&g_app_filter_whitelist, mac);
    ret = (node != NULL);
    app_filter_read_unlock();

    return ret;
}


int jmx_api_add_app_filter_whitelist(cJSON *data_obj) {
    cJSON *mac_array;
    int i;
    u8 mac_bin[ETH_ALEN];

    if (!data_obj) {
        return -1;
    }

    mac_array = cJSON_GetObjectItem(data_obj, "mac_list");
    if (!mac_array) {
        printk("mac_list not found\n");
        return -1;
    }

    app_filter_write_lock();
    for (i = 0; i < cJSON_GetArraySize(mac_array); i++) {
        cJSON *mac_obj = cJSON_GetArrayItem(mac_array, i);
        if (mac_obj && mac_str_to_bin(mac_obj->valuestring, mac_bin)) {
            jmx_add_mac_node(&g_app_filter_whitelist, mac_bin);
        }
    }
    app_filter_write_unlock();
	
	jmx_update_appfilter_jiffies();
    return 0;
}


int jmx_api_flush_app_filter_whitelist(cJSON *data_obj) {
    app_filter_write_lock();
    jmx_flush_mac_list(&g_app_filter_whitelist);
    app_filter_write_unlock();
	
	jmx_update_appfilter_jiffies();
    return 0;
}
