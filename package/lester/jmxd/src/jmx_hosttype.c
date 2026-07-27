// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_hosttype.c - Device/host type identification
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <json-c/json.h>
#include "jmx_hosttype.h"
#include "jmx.h"

/* ── UA fingerprint storage ── */

static jmx_ht_fingerprint_t *g_ua_fps;
static uint32_t g_ua_count;

/* ── OUI storage ── */

static jmx_ht_oui_t *g_oui_table;
static uint32_t g_oui_count;

/* ── MAC OUI sparse lookup ── */
typedef struct {
	uint32_t prefix;
	const char *vendor;
} jmx_ht_nmap_oui_t;

static jmx_ht_nmap_oui_t *g_nmap_ouis;
static uint32_t g_nmap_oui_count;
static char *g_oui_strings; /* string pool */

static void oui_flat_free(void)
{
    if (g_nmap_ouis) { free(g_nmap_ouis); g_nmap_ouis = NULL; }
    g_nmap_oui_count = 0;
    if (g_oui_strings) { free(g_oui_strings); g_oui_strings = NULL; }
}

static int nmap_oui_cmp(const void *a, const void *b)
{
	const jmx_ht_nmap_oui_t *oa = (const jmx_ht_nmap_oui_t *)a;
	const jmx_ht_nmap_oui_t *ob = (const jmx_ht_nmap_oui_t *)b;

	if (oa->prefix < ob->prefix)
		return -1;
	if (oa->prefix > ob->prefix)
		return 1;
	return 0;
}

/* ── Init / Exit ── */

int jmx_hosttype_init(void)
{
	g_ua_fps = calloc(JMX_HT_MAX_ENTRIES, sizeof(jmx_ht_fingerprint_t));
	g_ua_count = 0;
	g_oui_table = NULL;
	g_oui_count = 0;
	return g_ua_fps ? 0 : -1;
}

void jmx_hosttype_exit(void)
{
	free(g_ua_fps); g_ua_fps = NULL; g_ua_count = 0;
	free(g_oui_table); g_oui_table = NULL; g_oui_count = 0;
	oui_flat_free();
}

/* ── Load MAC OUI from vendor.json ── */
/* vendor.json format: {"AA:BB:CC": "VendorName", ...} */

int jmx_hosttype_load_oui(const char *path)
{
	FILE *f;
	long fsize;
	char *buf;
	json_object *root, *vendor_obj;
	int count = 0;

	if (!g_oui_table) {
		g_oui_table = calloc(JMX_HT_OUI_ENTRIES, sizeof(jmx_ht_oui_t));
		if (!g_oui_table) return -1;
	}
	g_oui_count = 0;

	f = fopen(path, "r");
	if (!f) { LOG_ERROR("hosttype: nmap fopen failed: %s\n", path); return -1; }
	fseek(f, 0, SEEK_END); fsize = ftell(f); fseek(f, 0, SEEK_SET);
	buf = malloc(fsize + 1);
	if (!buf) { fclose(f); return -1; }
	fread(buf, 1, fsize, f); buf[fsize] = '\0';
	fclose(f);

	root = json_tokener_parse(buf);
	free(buf);
	if (!root) return -1;

	/* Parse "vendor" object: {"000":"苹果","001":"华为",...} */
	vendor_obj = NULL;
	json_object_object_get_ex(root, "vendor", &vendor_obj);
	if (vendor_obj) {
		json_object_object_foreach(vendor_obj, key, v) {
			if (g_oui_count >= JMX_HT_OUI_ENTRIES) break;
			if (json_object_get_type(v) != json_type_string) continue;

			strncpy(g_oui_table[g_oui_count].prefix, key,
				JMX_HT_OUI_PREFIX_LEN - 1);
			strncpy(g_oui_table[g_oui_count].vendor,
				json_object_get_string(v), JMX_HT_MAX_DESC - 1);
			g_oui_count++;
			count++;
		}
	}

	json_object_put(root);
	fprintf(stderr, "hosttype: loaded %d vendor entries from %s\n", count, path);
	return count;
}

/* ── Load useragent.txt ── */
/* Format: category_id,brand,os,ua_pattern,description */

int jmx_hosttype_load_ua(const char *path)
{
	FILE *f;
	char line[512];
	int count = 0;

	f = fopen(path, "r");
	if (!f) return -1;

	while (fgets(line, sizeof(line), f) && g_ua_count < JMX_HT_MAX_ENTRIES) {
		char *p = line;
		char *fields[5] = {0};
		int fi = 0;

		/* Skip comments */
		while (*p == ' ' || *p == '\t') p++;
		if (*p == '#' || *p == '\n' || *p == '\0') continue;

		/* Parse CSV fields */
		fields[0] = p;
		for (; *p && fi < 4; p++) {
			if (*p == ',') {
				*p = '\0';
				fi++;
				fields[fi] = p + 1;
			}
		}
		/* Strip trailing newline from last field */
		char *nl = strchr(fields[fi], '\n');
		if (nl) *nl = '\0';
		nl = strchr(fields[fi], '\r');
		if (nl) *nl = '\0';

		if (!fields[0] || !fields[1] || !fields[3]) continue;

		jmx_ht_fingerprint_t *fp = &g_ua_fps[g_ua_count];
		fp->category_id = (uint16_t)atoi(fields[0]);
		strncpy(fp->brand, fields[1], JMX_HT_MAX_DESC - 1);
		strncpy(fp->os, fields[2] ? fields[2] : "", JMX_HT_MAX_DESC - 1);
		strncpy(fp->pattern, fields[3], JMX_HT_MAX_PATTERN - 1);
		strncpy(fp->description, fields[4] ? fields[4] : "", JMX_HT_MAX_DESC - 1);

		g_ua_count++;
		count++;
	}

	fclose(f);
	fprintf(stderr, "hosttype: loaded %d UA fingerprints from %s\n", count, path);
	return count;
}

/* ── Load host.txt ── */
/* Format: category_id,type,brand,model_prefix,model_pattern,description */

int jmx_hosttype_load_host(const char *path)
{
	/* host.txt uses same pattern-matching approach as UA,
	 * but for DHCP hostnames / device names.
	 * Reuse UA storage for simplicity. */
	FILE *f;
	char line[512];
	int count = 0;

	f = fopen(path, "r");
	if (!f) return -1;

	while (fgets(line, sizeof(line), f) && g_ua_count < JMX_HT_MAX_ENTRIES) {
		char *p = line;
		char *fields[6] = {0};
		int fi = 0;

		while (*p == ' ' || *p == '\t') p++;
		if (*p == '#' || *p == '\n' || *p == '\0') continue;

		fields[0] = p;
		for (; *p && fi < 5; p++) {
			if (*p == ',') {
				*p = '\0';
				fi++;
				fields[fi] = p + 1;
			}
		}
		char *nl = strchr(fields[fi], '\n');
		if (nl) *nl = '\0';

		if (!fields[0] || !fields[3]) continue;

		/* Use model_pattern (field 4) as the match pattern */
		jmx_ht_fingerprint_t *fp = &g_ua_fps[g_ua_count];
		fp->category_id = (uint16_t)atoi(fields[0]);
		strncpy(fp->brand, fields[2] ? fields[2] : "", JMX_HT_MAX_DESC - 1);
		strncpy(fp->os, "", JMX_HT_MAX_DESC - 1);
		strncpy(fp->pattern, fields[4] ? fields[4] : fields[3], JMX_HT_MAX_PATTERN - 1);
		strncpy(fp->description, fields[5] ? fields[5] : "", JMX_HT_MAX_DESC - 1);

		g_ua_count++;
		count++;
	}

	fclose(f);
	fprintf(stderr, "hosttype: loaded %d host fingerprints from %s\n", count, path);
	return count;
}

/* ── Load dhcp.txt ── */
/* Format: option1,option2,...|OS_name */

int jmx_hosttype_load_dhcp(const char *path)
{
	/* DHCP fingerprints are stored as patterns for matching
	 * DHCP option lists. For now, load into UA table with
	 * pattern = option_list, description = OS name */
	FILE *f;
	char line[512];
	int count = 0;

	f = fopen(path, "r");
	if (!f) return -1;

	while (fgets(line, sizeof(line), f) && g_ua_count < JMX_HT_MAX_ENTRIES) {
		char *p = line;
		char *pipe;

		while (*p == ' ' || *p == '\t') p++;
		if (*p == '#' || *p == '\n' || *p == '\0') continue;

		pipe = strchr(p, '|');
		if (!pipe) continue;
		*pipe = '\0';

		char *nl = strchr(pipe + 1, '\n');
		if (nl) *nl = '\0';
		nl = strchr(pipe + 1, '\r');
		if (nl) *nl = '\0';

		jmx_ht_fingerprint_t *fp = &g_ua_fps[g_ua_count];
		fp->category_id = 0;
		strncpy(fp->brand, "", JMX_HT_MAX_DESC - 1);
		strncpy(fp->os, pipe + 1, JMX_HT_MAX_DESC - 1);
		strncpy(fp->pattern, p, JMX_HT_MAX_PATTERN - 1);
		strncpy(fp->description, pipe + 1, JMX_HT_MAX_DESC - 1);

		g_ua_count++;
		count++;
	}

	fclose(f);
	fprintf(stderr, "hosttype: loaded %d DHCP fingerprints from %s\n", count, path);
	return count;
}

/* ── UA pattern matching ── */
/* Pattern uses % as wildcard (like iKuai) */

static int pattern_match(const char *pattern, const char *text, int text_len)
{
	const char *p = pattern;
	int ti = 0;

	while (*p && ti < text_len) {
		if (*p == '%') {
			p++;
			if (!*p) return 1; /* trailing % matches everything */
			/* Find next literal char after % */
			while (ti < text_len) {
				if (tolower(text[ti]) == tolower(*p))
					break;
				ti++;
			}
			if (ti >= text_len) return 0;
			p++;
			ti++;
		} else {
			if (tolower(text[ti]) != tolower(*p))
				return 0;
			p++;
			ti++;
		}
	}

	/* Pattern consumed or text exhausted */
	while (*p == '%') p++;
	return (*p == '\0') ? 1 : 0;
}

uint16_t jmx_ht_match_ua(const char *ua, int ua_len,
			 char *brand, int brand_size,
			 char *os, int os_size,
			 char *desc, int desc_size)
{
	uint32_t i;

	if (!ua || ua_len <= 0) return 0;

	for (i = 0; i < g_ua_count; i++) {
		if (g_ua_fps[i].pattern[0] == '\0') continue;
		if (g_ua_fps[i].category_id != 0) continue; /* skip non-UA entries */

		if (pattern_match(g_ua_fps[i].pattern, ua, ua_len)) {
			if (brand && brand_size > 0)
				strncpy(brand, g_ua_fps[i].brand, brand_size - 1);
			if (os && os_size > 0)
				strncpy(os, g_ua_fps[i].os, os_size - 1);
			if (desc && desc_size > 0)
				strncpy(desc, g_ua_fps[i].description, desc_size - 1);
			return g_ua_fps[i].category_id;
		}
	}

	/* Also check host patterns (non-zero category_id) */
	for (i = 0; i < g_ua_count; i++) {
		if (g_ua_fps[i].pattern[0] == '\0') continue;
		if (g_ua_fps[i].category_id == 0) continue;

		if (pattern_match(g_ua_fps[i].pattern, ua, ua_len)) {
			if (brand && brand_size > 0)
				strncpy(brand, g_ua_fps[i].brand, brand_size - 1);
			if (os && os_size > 0)
				strncpy(os, g_ua_fps[i].os, os_size - 1);
			if (desc && desc_size > 0)
				strncpy(desc, g_ua_fps[i].description, desc_size - 1);
			return g_ua_fps[i].category_id;
		}
	}

	return 0;
}

/* ── Vendor ID lookup (iKuai vendor.json) ── */

int __attribute__((used)) jmx_hosttype_load_nmap(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) return -1;
	/* First pass: count rows and total string bytes. */
	long total_bytes = 0;
	char line[256];
	int count = 0;
	while (fgets(line, sizeof(line), f)) {
		/* Format: "AABBCC Vendor Name" */
		if (strlen(line) < 7 || !isxdigit((unsigned char)line[0])) continue;
		char *sp = strchr(line, ' ');
		if (!sp) continue;
		total_bytes += strlen(sp); /* includes the space and newline */
		count++;
	}
	oui_flat_free();
	if (count <= 0) {
		fclose(f);
		return -1;
	}
	g_nmap_ouis = calloc((size_t)count, sizeof(*g_nmap_ouis));
	g_oui_strings = malloc(total_bytes + 1);
	if (!g_nmap_ouis || !g_oui_strings) { fclose(f); oui_flat_free(); return -1; }
	/* Second pass: populate */
	rewind(f);
	char *sp_ptr = g_oui_strings;
	int loaded = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strlen(line) < 7 || !isxdigit((unsigned char)line[0])) continue;
		char *sp = strchr(line, ' ');
		if (!sp) continue;
		/* Parse 6 hex chars = 3 bytes */
		unsigned int b0, b1, b2;
		if (sscanf(line, "%2x%2x%2x", &b0, &b1, &b2) != 3) continue;
		uint32_t idx = (b0 << 16) | (b1 << 8) | b2;
		/* Copy vendor name into pool, trim whitespace */
		sp++; /* skip the space */
		size_t len = strlen(sp);
		while (len > 0 && (sp[len-1]=='\n'||sp[len-1]=='\r'||sp[len-1]==' ')) len--;
		memcpy(sp_ptr, sp, len);
		sp_ptr[len] = '\0';
		g_nmap_ouis[loaded].prefix = idx;
		g_nmap_ouis[loaded].vendor = sp_ptr;
		sp_ptr += len + 1;
		loaded++;
	}
	fclose(f);
	if (loaded > 1)
		qsort(g_nmap_ouis, (size_t)loaded, sizeof(*g_nmap_ouis), nmap_oui_cmp);
	g_nmap_oui_count = (uint32_t)loaded;
	fprintf(stderr, "hosttype: loaded %d OUI entries from %s\n", loaded, path);
	LOG_WARN("hosttype: loaded %d OUI entries from %s\n", loaded, path);
	return 0;
}

const char *jmx_ht_match_mac(const uint8_t *mac)
{
	uint32_t idx = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | mac[2];
	int lo = 0;
	int hi = (int)g_nmap_oui_count - 1;

	if (!mac || !g_nmap_ouis || g_nmap_oui_count == 0)
		return NULL;
	while (lo <= hi) {
		int mid = lo + (hi - lo) / 2;
		uint32_t have = g_nmap_ouis[mid].prefix;

		if (have == idx)
			return g_nmap_ouis[mid].vendor;
		if (have < idx)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return NULL;
}

const char *jmx_ht_match_vendor_id(const char *vendor_id)
{
	uint32_t i;
	if (!vendor_id || !g_oui_table || g_oui_count == 0) return NULL;
	for (i = 0; i < g_oui_count; i++) {
		if (strcmp(g_oui_table[i].prefix, vendor_id) == 0)
			return g_oui_table[i].vendor;
	}
	return NULL;
}

/* ── DHCP option matching ── */

const char *jmx_ht_match_dhcp(const char *options, int opt_len)
{
	uint32_t i;

	if (!options || opt_len <= 0) return NULL;

	for (i = 0; i < g_ua_count; i++) {
		if (g_ua_fps[i].pattern[0] == '\0') continue;
		if (g_ua_fps[i].os[0] == '\0') continue;

		/* DHCP fingerprints: pattern is "opt1,opt2,..." */
		if (strstr(options, g_ua_fps[i].pattern))
			return g_ua_fps[i].os;
	}
	return NULL;
}

uint32_t jmx_ht_ua_count(void) { return g_ua_count; }
uint32_t jmx_ht_oui_count(void) { return g_nmap_oui_count ? g_nmap_oui_count : g_oui_count; }
uint32_t jmx_ht_nmap_oui_count(void) { return g_nmap_oui_count; }
