/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_hosttype.h - Device/host type identification
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_HOSTTYPE_H__
#define __JMX_HOSTTYPE_H__

#include <stdint.h>

#define JMX_HT_MAX_ENTRIES    16384
#define JMX_HT_HASH_BUCKETS   2048
#define JMX_HT_MAX_PATTERN    128
#define JMX_HT_MAX_DESC       64
#define JMX_HT_OUI_ENTRIES    1024
#define JMX_HT_OUI_PREFIX_LEN 8  /* "AA:BB:CC" */

/* Host type categories */
typedef enum {
	JMX_HT_CAT_UNKNOWN = 0,
	JMX_HT_CAT_PHONE,
	JMX_HT_CAT_TABLET,
	JMX_HT_CAT_PC,
	JMX_HT_CAT_TV,
	JMX_HT_CAT_ROUTER,
	JMX_HT_CAT_IOT,
	JMX_HT_CAT_PRINTER,
	JMX_HT_CAT_CAMERA,
	JMX_HT_CAT_GAMING,
	JMX_HT_CAT_MAX
} jmx_ht_category_t;

/* UA/host fingerprint entry */
typedef struct {
	uint16_t category_id;
	char     brand[JMX_HT_MAX_DESC];
	char     os[JMX_HT_MAX_DESC];
	char     pattern[JMX_HT_MAX_PATTERN];
	char     description[JMX_HT_MAX_DESC];
} jmx_ht_fingerprint_t;

/* MAC OUI entry */
typedef struct {
	char     prefix[JMX_HT_OUI_PREFIX_LEN]; /* "AA:BB:CC" */
	char     vendor[JMX_HT_MAX_DESC];
} jmx_ht_oui_t;

/* Initialize hosttype matcher */
int jmx_hosttype_init(void);
void jmx_hosttype_exit(void);

/* Load hosttype data files */
int jmx_hosttype_load_oui(const char *path);        /* vendor.json */
int jmx_hosttype_load_ua(const char *path);          /* useragent.txt */
int jmx_hosttype_load_host(const char *path);        /* host.txt */
int jmx_hosttype_load_dhcp(const char *path);        /* dhcp.txt */
int jmx_hosttype_load_nmap(const char *path);        /* nmap-mac-prefixes */

/* Match User-Agent string → category_id, fills brand/os/desc if not NULL */
uint16_t jmx_ht_match_ua(const char *ua, int ua_len,
			 char *brand, int brand_size,
			 char *os, int os_size,
			 char *desc, int desc_size);

/* Match MAC prefix → vendor name (needs OUI data) */
const char *jmx_ht_match_mac(const uint8_t *mac);

/* Match iKuai vendor ID → vendor name */
const char *jmx_ht_match_vendor_id(const char *vendor_id);

/* Match DHCP fingerprint → OS name */
const char *jmx_ht_match_dhcp(const char *options, int opt_len);

/* Stats */
uint32_t jmx_ht_ua_count(void);
uint32_t jmx_ht_oui_count(void);
uint32_t jmx_ht_nmap_oui_count(void);

#endif /* __JMX_HOSTTYPE_H__ */
