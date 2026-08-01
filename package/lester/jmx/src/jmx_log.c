
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include "jmx.h"
#include "jmx_log.h"
#include "jmx_mac_filter.h"
#include "jmx_app_filter.h"
#include "jmx_client.h"
int af_log_lvl = 0;
static int jmx_debug;
static int jmx_debug_max = 3;
static struct kobject *dreamingwrt_kobj;
int jmx_test_mode = 0;

int g_record_enable = 1;
int g_by_pass_accl = 1;
int g_user_mode = 0;
int af_work_mode = AF_MODE_GATEWAY;
unsigned int jmx_lan_ip = 0;
unsigned int jmx_lan_mask = 0;
char g_lan_ifname[64] = "br-lan";
int g_tcp_rst = 1;
int g_feature_init = 0;
static char g_jmx_version[64] = JMX_VERSION;
int g_feature_count = 0;

static struct ctl_table jmx_table[] = {
	{
		.procname	= "debug",
		.data		= &jmx_debug,
		.maxlen 	= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &jmx_debug_max,
	},
	{
		.procname	= "feature_init",
		.data		= &g_feature_init,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "version",
		.data		= g_jmx_version,
		.maxlen 	= 64,
		.mode		= 0444,
		.proc_handler = proc_dostring,
	},
	{
		.procname	= "feature_count",
		.data		= &g_feature_count,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "test_mode",
		.data		= &jmx_test_mode,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "appfilter_enable",
		.data		= &g_appfilter_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "macfilter_enable",
		.data		= &g_mac_filter_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "by_pass_accl",
		.data		= &g_by_pass_accl,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "tcp_rst",
		.data		= &g_tcp_rst,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "lan_ifname",
		.data		= g_lan_ifname,
		.maxlen 	= 64,
		.mode		= 0666,
		.proc_handler = proc_dostring,
	},
	{
		.procname	= "record_enable",
		.data		= &g_record_enable,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "user_mode",
		.data		= &g_user_mode,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "work_mode",
		.data		= &af_work_mode,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "lan_ip",
		.data		= &jmx_lan_ip,
		.maxlen = 	sizeof(unsigned int),
		.mode		= 0666,
		.proc_handler	= proc_douintvec,
	},
	{
		.procname = "lan_mask",
		.data = &jmx_lan_mask,
		.maxlen = sizeof(unsigned int),
		.mode = 0666,
		.proc_handler = proc_douintvec,
	},
	{
		.procname	= "max_app_report_count",
		.data		= &g_max_app_report_count,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "min_http_match_count",
		.data		= &g_min_http_match_count,
		.maxlen 	= sizeof(int),
		.mode		= 0666,
		.proc_handler	= proc_dointvec,
	},
		
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0))
	{
	}
#endif
};
#define JMX_SYS_PROC_DIR "dreamingwrt/jmx"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
static struct ctl_table jmx_drt_table[] = {
	{
		.procname	= "jmx",
		.mode		= 0555,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
		.child		= jmx_table,
#endif
	},
	{}
};

static struct ctl_table jmx_root_table[] = {
	{
		.procname	= "dreamingwrt",
		.mode		= 0555,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
		.child		= jmx_drt_table,
#endif
	},
	{}
};
#endif
static struct ctl_table_header *jmx_table_header;

int jmx_debug_level(void)
{
	return READ_ONCE(jmx_debug);
}

bool jmx_debug_at_least(int level)
{
	return level > 0 && jmx_debug_level() >= level;
}

static ssize_t debug_show(struct kobject *kobj,
			  struct kobj_attribute *attr, char *buf)
{
	(void)kobj;
	(void)attr;
	return sysfs_emit(buf, "%d\n", jmx_debug_level());
}

static ssize_t debug_store(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	(void)kobj;
	(void)attr;

	int level;

	if (kstrtoint(buf, 0, &level) || level < 0 || level > jmx_debug_max)
		return -EINVAL;
	WRITE_ONCE(jmx_debug, level);

	return count;
}

static struct kobj_attribute debug_attribute =
	__ATTR(debug, 0644, debug_show, debug_store);

static int af_init_log_sysfs(void)
{
	struct kobject *module_root = THIS_MODULE->mkobj.kobj.parent;
	int rc;

	if (!module_root)
		return -ENODEV;

	dreamingwrt_kobj = kobject_create_and_add("dreamingwrt", module_root);
	if (!dreamingwrt_kobj)
		return -ENOMEM;

	rc = sysfs_create_file(dreamingwrt_kobj, &debug_attribute.attr);
	if (rc) {
		kobject_put(dreamingwrt_kobj);
		dreamingwrt_kobj = NULL;
		return rc;
	}

	return 0;
}

static void af_fini_log_sysfs(void)
{
	if (!dreamingwrt_kobj)
		return;

	sysfs_remove_file(dreamingwrt_kobj, &debug_attribute.attr);
	kobject_put(dreamingwrt_kobj);
	dreamingwrt_kobj = NULL;
}


static int af_init_log_sysctl(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
		jmx_table_header = register_sysctl_table(jmx_root_table);
#else
	jmx_table_header = register_sysctl("dreamingwrt/jmx", jmx_table);
#endif
	if (jmx_table_header == NULL){
		printk("init log sysctl...failed\n");
		return -ENOMEM;
	}
	return 0;
}

static int af_fini_log_sysctl(void)
{
	if (jmx_table_header)
		unregister_sysctl_table(jmx_table_header);
	return 0;
}

int af_log_init(void){
	int rc;

	WRITE_ONCE(jmx_debug, 0);
	rc = af_init_log_sysctl();
	if (rc)
		return rc;
	rc = af_init_log_sysfs();
	if (rc) {
		af_fini_log_sysctl();
		return rc;
	}
	return 0;
}

int af_log_exit(void){
	af_fini_log_sysfs();
	af_fini_log_sysctl();
	return 0;
}
