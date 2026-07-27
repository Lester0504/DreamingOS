/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * jmx_isp.h - ISP/carrier detection via public IP + CIDR matching
 * Inspired by iKuai interface_update_isp()
 */
#ifndef JMX_ISP_H
#define JMX_ISP_H

#define JMX_ISP_UNKNOWN   0
#define JMX_ISP_CTCC      1  /* China Telecom */
#define JMX_ISP_CUCC      2  /* China Unicom */
#define JMX_ISP_CMCC      3  /* China Mobile */
#define JMX_ISP_CERNET    4  /* CERNET / China Education */

#define JMX_ISP_MAX_WANS  8
#define JMX_ISP_CACHE_DIR "/tmp/jmxd_isp"

/* Public IP + ISP info for one WAN */
typedef struct {
    int    wan_id;
    char   ifname[32];        /* e.g. "wan", "wan2" */
    char   public_ip[48];     /* fetched via curl --interface */
    int    isp;               /* JMX_ISP_* */
    char   carrier_key[16];   /* "mobile", "unicom", "telecom", "edu", "unknown" */
    char   carrier_name[32];  /* "China Mobile", etc. */
    int    confidence;         /* 0-100 */
    char   source[64];         /* public-ip endpoint that succeeded */
    char   error[64];
    int    pending;           /* 1 = async lookup in progress */
} jmx_isp_entry_t;

/* Initialize ISP module: load CIDR tables, start background updater */
int  jmx_isp_init(void);
void jmx_isp_exit(void);

/* Get cached ISP info for a given ifname. Returns 0 on success, -1 if not yet known.
 * If not cached, triggers an async background lookup. */
int  jmx_isp_get(const char *ifname, jmx_isp_entry_t *out);

/* Force refresh for a specific WAN (e.g. after WAN reconnect) */
void jmx_isp_refresh(const char *ifname);

/* Synchronous low-frequency detection used by setup/test APIs. */
int jmx_isp_detect_sync(const char *wan_id, const char *l3_ifname,
                        jmx_isp_entry_t *out);

/* Match an already-known public IPv4 against the signature DB without
 * fetching it again. Useful when ifstatus/runtime already has the WAN IP. */
int jmx_isp_detect_public_ip(const char *public_ip, const char *source,
                             jmx_isp_entry_t *out);

#endif
