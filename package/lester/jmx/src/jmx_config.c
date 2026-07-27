
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <linux/init.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <linux/cdev.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/version.h>

#include "jmx_config.h"
#include "k_json.h"
#include "jmx.h"
#include "jmx_mac_filter.h"
#include "jmx_app_filter.h"
static struct mutex jmx_cdev_mutex;
struct jmx_config_dev
{
	dev_t id;
	struct cdev char_dev;
	struct class *c;
};
struct jmx_config_dev g_jmx_dev;

struct jmx_cdev_file
{
	size_t size;
	char buf[256 << 10];
};

k_request_item_t k_request_api_list[]={
	{"add_mac_filter_rule", jmx_api_add_mac_filter_rule},
	{"del_mac_filter_rule", jmx_api_del_mac_filter_rule},
	{"mod_mac_filter_rule", jmx_api_mod_mac_filter_rule},
	{"dump_mac_filter_rule", jmx_api_dump_mac_filter_rule},
	{"flush_mac_filter_rule", jmx_api_flush_mac_filter_rule},
	{"add_app_filter_rule", jmx_api_add_app_filter_rule},
	{"del_app_filter_rule", jmx_api_del_app_filter_rule},
	{"mod_app_filter_rule", jmx_api_mod_app_filter_rule},
	{"dump_app_filter_rule", jmx_api_dump_app_filter_rule},
	{"flush_app_filter_rule", jmx_api_flush_app_filter_rule},
	{"add_mac_filter_whitelist", jmx_api_add_mac_filter_whitelist},
	{"del_mac_filter_whitelist", jmx_api_del_mac_filter_whitelist},
	{"flush_mac_filter_whitelist", jmx_api_flush_mac_filter_whitelist},
	{"add_app_filter_whitelist", jmx_api_add_app_filter_whitelist},
	{"flush_app_filter_whitelist", jmx_api_flush_app_filter_whitelist},
};

int jmx_config_handle(char *config, unsigned int len)
{
	int i;
	cJSON *config_obj = NULL;
	cJSON *api_obj = NULL;
	cJSON *data_obj = NULL;
	if (!config || len == 0)
		return -1;
	
	config_obj = cJSON_Parse(config);
	if (!config_obj){
		printk("parse json failed, value = %s\n", config);
		return -1;
	}
	api_obj = cJSON_GetObjectItem(config_obj, "api");
	data_obj = cJSON_GetObjectItem(config_obj, "data");
	if (!api_obj){
		printk("error, api obj not set\n");
		cJSON_Delete(config_obj);
		return -1;
	}

	cJSON *temp_data_obj = NULL;
	if (!data_obj){
		temp_data_obj = cJSON_CreateObject();  // 创建一个空的data对象
		data_obj = temp_data_obj;
	}

	for (i = 0; i < ARRAY_SIZE(k_request_api_list); i++){
		k_request_item_t *req_item = &k_request_api_list[i];
		if (0 == strcmp(req_item->api, api_obj->valuestring)){
			req_item->handle(data_obj);
			break;
		}
	}
	

	if (temp_data_obj){
		cJSON_Delete(temp_data_obj);
	}
	cJSON_Delete(config_obj);
	return 0;
}

static int jmx_cdev_open(struct inode *inode, struct file *filp)
{
	struct jmx_cdev_file *file;
	file = vzalloc(sizeof(*file));
	if (!file)
		return -EINVAL;

	mutex_lock(&jmx_cdev_mutex);
	filp->private_data = file;
	return 0;
}

static ssize_t jmx_cdev_read(struct file *filp, char *buf, size_t count, loff_t *off)
{
	return 0;
}

static int jmx_cdev_release(struct inode *inode, struct file *filp)
{
	struct jmx_cdev_file *file = filp->private_data;
	jmx_config_handle(file->buf, file->size);
	filp->private_data = NULL;
	mutex_unlock(&jmx_cdev_mutex);
	vfree(file);
	return 0;
}

static ssize_t jmx_cdev_write(struct file *filp, const char *buffer, size_t count, loff_t *off)
{
	struct jmx_cdev_file *file = filp->private_data;
	int ret;
	if (file->size + count > sizeof(file->buf))
		return -EINVAL;

	ret = copy_from_user(file->buf + file->size, buffer, count);
	if (ret != 0)
		return -EINVAL;

	file->size += count;
	return count;
}

static struct file_operations jmx_cdev_ops = {
	owner : THIS_MODULE,
	release : jmx_cdev_release,
	open : jmx_cdev_open,
	write : jmx_cdev_write,
	read : jmx_cdev_read,
};

int jmx_register_dev(void)
{
	struct device *dev;
	int res;
	mutex_init(&jmx_cdev_mutex);

	res = alloc_chrdev_region(&g_jmx_dev.id, 0, 1, JMX_CHAR_DEV);
	if (res != 0)
		return -EINVAL;

	cdev_init(&g_jmx_dev.char_dev, &jmx_cdev_ops);
	res = cdev_add(&g_jmx_dev.char_dev, g_jmx_dev.id, 1);
	if (res < 0)
		goto REGION_OUT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	g_jmx_dev.c = class_create(THIS_MODULE, JMX_CHAR_DEV);
#else
 	g_jmx_dev.c = class_create(JMX_CHAR_DEV);
#endif

	if (IS_ERR_OR_NULL(g_jmx_dev.c))
		goto CDEV_OUT;

	dev = device_create(g_jmx_dev.c, NULL, g_jmx_dev.id, NULL, JMX_CHAR_DEV);
	if (IS_ERR_OR_NULL(dev))
		goto CLASS_OUT;
	return 0;

CLASS_OUT:
	class_destroy(g_jmx_dev.c);
CDEV_OUT:
	cdev_del(&g_jmx_dev.char_dev);
REGION_OUT:
	unregister_chrdev_region(g_jmx_dev.id, 1);
	printk("register char dev....fail\n");
	return -EINVAL;
}

void jmx_unregister_dev(void)
{
	device_destroy(g_jmx_dev.c, g_jmx_dev.id);
	class_destroy(g_jmx_dev.c);
	cdev_del(&g_jmx_dev.char_dev);
	unregister_chrdev_region(g_jmx_dev.id, 1);
}

