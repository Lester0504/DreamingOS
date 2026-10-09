// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGOS_CLOUD_SERVICE_HOST_H
#define DREAMINGOS_CLOUD_SERVICE_HOST_H

#include "webframe.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

/* Stable per-device/service origin; the registry still enforces unique ownership.
 * This identifier is public, not an authentication secret. */
static inline int cw_application_host(const char *router_id, const char *service_id,
                                       char *out, size_t cap)
{
    char message[160], label[33];
    unsigned char digest[32];
    unsigned int length = 0;
    if (!router_id || strlen(router_id) != 39 || strncmp(router_id, "router-", 7) ||
        strspn(router_id + 7, "0123456789abcdef") != 32 ||
        !cw_web_is_service_id(service_id) || !strcmp(service_id, "web"))
        return -1;
    int n = snprintf(message, sizeof(message),
        "dreamingos-cloud-web-v1\napplication-host\n%s\n%s", router_id, service_id);
    if (n < 0 || (size_t)n >= sizeof(message) ||
        EVP_Digest(message, (size_t)n, digest, &length, EVP_sha256(), NULL) != 1 ||
        length != 32)
        return -1;
    for (int i = 0; i < 16; ++i) snprintf(label + i * 2, 3, "%02x", digest[i]);
    n = snprintf(out, cap, "s-%s.apps.dreamingnet.com", label);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}
#endif
