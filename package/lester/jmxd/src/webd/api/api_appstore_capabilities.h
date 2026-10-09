// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef API_APPSTORE_CAPABILITIES_H
#define API_APPSTORE_CAPABILITIES_H

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <json-c/json.h>
#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#endif

#ifndef APPSTORE_TUN_DEVICE
#define APPSTORE_TUN_DEVICE "/dev/net/tun"
#endif

/* These are the production paths used by the platform network transaction.
 * Overrides are restricted to isolated tests, just like APPSTORE_TUN_DEVICE. */
#ifndef APPSTORE_NETWORK_UCI
#define APPSTORE_NETWORK_UCI "/sbin/uci"
#endif
#ifndef APPSTORE_NETWORK_FW4
#define APPSTORE_NETWORK_FW4 "/sbin/fw4"
#endif
#ifndef APPSTORE_NETWORK_NFT
#define APPSTORE_NETWORK_NFT "/usr/sbin/nft"
#endif
#ifndef APPSTORE_NETWORK_UTPL
#define APPSTORE_NETWORK_UTPL "/usr/bin/utpl"
#endif
#ifndef APPSTORE_NETWORK_MAIN
#define APPSTORE_NETWORK_MAIN "/usr/share/firewall4/main.uc"
#endif
#ifndef APPSTORE_NETWORK_LIBRARY
#define APPSTORE_NETWORK_LIBRARY "/usr/share/ucode/fw4.uc"
#endif
#ifndef APPSTORE_NETWORK_RULESET
#define APPSTORE_NETWORK_RULESET "/usr/share/firewall4/templates/ruleset.uc"
#endif
#ifndef APPSTORE_NETWORK_CONFIG_DIR
#define APPSTORE_NETWORK_CONFIG_DIR "/etc/config"
#endif
#ifndef APPSTORE_NETWORK_FIREWALL
#define APPSTORE_NETWORK_FIREWALL APPSTORE_NETWORK_CONFIG_DIR "/firewall"
#endif

/* TUNGETFEATURES reads driver support; it does not create a network interface. */
static inline int appstore_tun_available(const char **reason)
{
#ifdef __linux__
    struct stat st;
    if (stat(APPSTORE_TUN_DEVICE, &st) != 0) {
        *reason = "tun_missing";
        return 0;
    }
    if (!S_ISCHR(st.st_mode)) {
        *reason = "tun_not_character_device";
        return 0;
    }
    int fd = open(APPSTORE_TUN_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        *reason = "tun_unavailable";
        return 0;
    }
    unsigned int features = 0;
    int rc = ioctl(fd, TUNGETFEATURES, &features);
    close(fd);
    if (rc < 0 || !(features & IFF_TUN)) {
        *reason = "tun_driver_unavailable";
        return 0;
    }
    *reason = "";
    return 1;
#else
    *reason = "tun_platform_unsupported";
    return 0;
#endif
}

/* Advertise the implemented v1 contract only when its local dependencies can
 * be used. This probe performs stat/access and TUNGETFEATURES only; it never
 * creates interfaces, edits UCI or invokes fw4/nft. Per-app readiness remains
 * the transactional --network-ensure check immediately before core startup. */
static inline int appstore_network_policy_available(const char **reason)
{
    if (!appstore_tun_available(reason)) return 0;
    static const struct {
        const char *path;
        int mode;
        const char *reason;
    } dependencies[] = {
        { APPSTORE_NETWORK_UCI, X_OK, "network_policy_uci_unavailable" },
        { APPSTORE_NETWORK_FW4, X_OK, "network_policy_fw4_unavailable" },
        { APPSTORE_NETWORK_NFT, X_OK, "network_policy_nft_unavailable" },
        { APPSTORE_NETWORK_UTPL, X_OK, "network_policy_renderer_unavailable" },
        { APPSTORE_NETWORK_MAIN, R_OK, "network_policy_fw4_runtime_unavailable" },
        { APPSTORE_NETWORK_LIBRARY, R_OK, "network_policy_fw4_runtime_unavailable" },
        { APPSTORE_NETWORK_RULESET, R_OK, "network_policy_fw4_runtime_unavailable" },
        { APPSTORE_NETWORK_FIREWALL, R_OK, "network_policy_firewall_unavailable" }
    };
    struct stat st;
    for (size_t i=0;i<sizeof(dependencies)/sizeof(dependencies[0]);i++) {
        if (stat(dependencies[i].path,&st)!=0 || !S_ISREG(st.st_mode) ||
            access(dependencies[i].path,dependencies[i].mode)!=0) {
            *reason=dependencies[i].reason;
            return 0;
        }
    }
    if (stat(APPSTORE_NETWORK_CONFIG_DIR,&st)!=0 || !S_ISDIR(st.st_mode) ||
        access(APPSTORE_NETWORK_CONFIG_DIR,W_OK|X_OK)!=0) {
        *reason="network_policy_config_not_writable";
        return 0;
    }
    *reason="";
    return 1;
}

static inline int appstore_capability_available(const char *name, const char **reason)
{
    if (!strcmp(name, "app-service-v1")) {
        *reason = "";
        return 1;
    }
    if (!strcmp(name, "tun"))
        return appstore_tun_available(reason);
    if (!strcmp(name, "app-network-policy-v1"))
        return appstore_network_policy_available(reason);
    *reason = "capability_unknown";
    return 0;
}

/* Older descriptors may omit requires; the verified manifest is checked again.
 * Return 1 for an unavailable capability, -1 for malformed requirements. */
static inline int appstore_requirements_check(struct json_object *requires,
                                              char *missing, size_t size,
                                              const char **reason)
{
    struct json_object *caps = NULL;
    missing[0] = '\0';
    *reason = "";
    if (!requires)
        return 0;
    if (!json_object_is_type(requires, json_type_object))
        goto invalid;
    if (!json_object_object_get_ex(requires, "capabilities", &caps))
        return 0;
    if (!json_object_is_type(caps, json_type_array) || json_object_array_length(caps) > 32)
        goto invalid;
    for (size_t i = 0; i < json_object_array_length(caps); i++) {
        struct json_object *value = json_object_array_get_idx(caps, i);
        if (!json_object_is_type(value, json_type_string))
            goto invalid;
        const char *name = json_object_get_string(value);
        if (!name[0] || strlen(name) > 64)
            goto invalid;
        if (!appstore_capability_available(name, reason)) {
            snprintf(missing, size, "%s", name);
            return 1;
        }
    }
    return 0;
invalid:
    *reason = "requirements_invalid";
    return -1;
}

#endif
