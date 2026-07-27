/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __WEBD_MMDB_H__
#define __WEBD_MMDB_H__

#include <stddef.h>

#define WEBD_GEOIP_COUNTRY_MMDB_DEFAULT "/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb"
#define WEBD_GEOIP_CITY_MMDB_DEFAULT "/etc/dreamingwrt/geoip/GeoLite2-City.mmdb"
#define WEBD_GEOIP_MMDB_DEFAULT WEBD_GEOIP_COUNTRY_MMDB_DEFAULT

typedef struct webd_mmdb webd_mmdb_t;

typedef struct {
    int found;
    char country_code[8];
    char country_name[128];
    char registered_country_code[8];
    char registered_country_name[128];
    char continent_code[8];
    char continent_name[128];
} webd_mmdb_country_t;

typedef struct {
    int found;
    int has_location;
    char country_code[8];
    char country_name[128];
    char registered_country_code[8];
    char registered_country_name[128];
    char continent_code[8];
    char continent_name[128];
    char region_code[32];
    char region_name[128];
    char city_name[128];
    char time_zone[128];
    double latitude;
    double longitude;
    int accuracy_radius;
} webd_mmdb_city_t;

int webd_mmdb_open(const char *path, webd_mmdb_t **out, char *err, size_t err_len);
void webd_mmdb_close(webd_mmdb_t *db);
int webd_mmdb_lookup_country(webd_mmdb_t *db, const char *ip, const char *language,
                             webd_mmdb_country_t *out);
int webd_mmdb_country_lookup(const char *path, const char *ip, const char *language,
                             webd_mmdb_country_t *out);
int webd_mmdb_lookup_city(webd_mmdb_t *db, const char *ip, const char *language,
                          webd_mmdb_city_t *out);
int webd_mmdb_city_lookup(const char *path, const char *ip, const char *language,
                          webd_mmdb_city_t *out);

#endif
