// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_AEGIS_INTERNAL_H
#define WEBD_API_AEGIS_INTERNAL_H

struct json_object;

/*
 * dnsmasq-restart budget for aegis apply / content-policy / domain-override
 * writes. Shared by api_aegis.c (moved branches) and jmx_app_api.c (the two
 * content-policy/domain-override strncmp prefix branches that stay behind), so
 * both TUs include this header.
 */
#define WEBD_AEGIS_DNSMASQ_APPLY_TIMEOUT_MS 20000

/*
 * Borrowed from jmx_app_api.c (definitions stay there; other callers remain).
 * De-static'd so api_aegis.c can reuse a single implementation of each.
 */
int app_parse_positive_int_segment(const char *s, int *out);
int app_parse_nonnegative_int_segment(const char *s, int *out);
int webd_aegis_certificate_http_status(struct json_object *response);
void webd_insights_add_client_attribution(struct json_object *obj,
                                          const char *source_ip,
                                          const char *source_mac);

#endif /* WEBD_API_AEGIS_INTERNAL_H */
