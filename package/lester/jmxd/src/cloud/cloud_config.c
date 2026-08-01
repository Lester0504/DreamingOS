// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * UCI configuration for the relay client.
 *
 *   config relay 'service'
 *       option enabled    '0'
 *       option host       'relay.example.com'
 *       option port       '443'
 *       option auth_token '<shared secret issued by the relay operator>'
 *       option tls_verify '1'
 *       option ca_path    ''        # optional pinned CA bundle
 *
 * Defaults are deliberately closed: disabled, no host, verification on. An
 * operator has to make a positive choice before the router dials out.
 */
#include "cloud_internal.h"

#define CLOUD_UCI_PACKAGE "relay"
#define CLOUD_UCI_SECTION "service"

static int cloud_config_host_valid(const char *value)
{
    size_t length = value ? strlen(value) : 0;
    size_t i;

    if (!length || length > 253)
        return 0;
    /*
     * Hostname or IP literal only. The value is used for DNS resolution and TLS
     * name verification, so anything that could smuggle a scheme, path, port or
     * whitespace past those checks is refused here.
     */
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':')
            continue;
        return 0;
    }
    /* A leading dot or dash is never a valid hostname and confuses resolvers. */
    if (value[0] == '.' || value[0] == '-')
        return 0;
    return 1;
}

/*
 * The tunnel token is sent to the relay as-is inside a JSON frame, so control
 * characters and quotes have no business being here. Length floor mirrors the
 * relay's own refusal to accept a short secret.
 */
static int cloud_config_token_valid(const char *value)
{
    size_t length = value ? strlen(value) : 0;
    size_t i;

    if (length < 32 || length > 255)
        return 0;
    for (i = 0; i < length; i++) {
        unsigned char c = (unsigned char)value[i];

        if (c <= 0x20 || c == 0x7f || c == '"' || c == '\\')
            return 0;
    }
    return 1;
}

static int cloud_config_path_valid(const char *value)
{
    size_t length = value ? strlen(value) : 0;

    if (!length)
        return 1;   /* empty means "use the system trust store" */
    if (length > 255 || value[0] != '/' || strstr(value, ".."))
        return 0;
    return 1;
}

static const char *cloud_uci_option(struct uci_context *ctx,
                                    struct uci_package *package,
                                    const char *name)
{
    struct uci_section *section;

    (void)ctx;
    section = uci_lookup_section(ctx, package, CLOUD_UCI_SECTION);
    if (!section)
        return NULL;
    return uci_lookup_option_string(ctx, section, name);
}

static int cloud_uci_bool(const char *value, int fallback)
{
    if (!value || !value[0])
        return fallback;
    if (!strcmp(value, "1") || !strcasecmp(value, "true") ||
        !strcasecmp(value, "yes") || !strcasecmp(value, "on"))
        return 1;
    if (!strcmp(value, "0") || !strcasecmp(value, "false") ||
        !strcasecmp(value, "no") || !strcasecmp(value, "off"))
        return 0;
    return fallback;
}

int cloud_config_load(struct cloud_config *out)
{
    struct uci_context *ctx;
    struct uci_package *package = NULL;
    const char *value;
    long port;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    out->port = 443;
    out->tls_verify = 1;

    ctx = uci_alloc_context();
    if (!ctx)
        return -1;
    if (uci_load(ctx, CLOUD_UCI_PACKAGE, &package) != UCI_OK || !package) {
        /* No config file yet is a normal first-boot state, not an error: the
         * daemon stays idle and reports why. */
        uci_free_context(ctx);
        return 0;
    }

    out->enabled = cloud_uci_bool(cloud_uci_option(ctx, package, "enabled"), 0);

    value = cloud_uci_option(ctx, package, "host");
    if (value && cloud_config_host_valid(value))
        snprintf(out->host, sizeof(out->host), "%s", value);

    value = cloud_uci_option(ctx, package, "port");
    if (value && value[0]) {
        char *end = NULL;

        port = strtol(value, &end, 10);
        if (end && !*end && port > 0 && port <= 65535)
            out->port = (uint16_t)port;
    }

    value = cloud_uci_option(ctx, package, "auth_token");
    if (value && cloud_config_token_valid(value))
        snprintf(out->auth_token, sizeof(out->auth_token), "%s", value);

    out->tls_verify = cloud_uci_bool(cloud_uci_option(ctx, package,
                                                      "tls_verify"), 1);

    value = cloud_uci_option(ctx, package, "ca_path");
    if (value && cloud_config_path_valid(value))
        snprintf(out->ca_path, sizeof(out->ca_path), "%s", value);

    uci_unload(ctx, package);
    uci_free_context(ctx);
    return 0;
}

void cloud_config_cleanse(struct cloud_config *config)
{
    if (!config)
        return;
    OPENSSL_cleanse(config->auth_token, sizeof(config->auth_token));
    memset(config, 0, sizeof(*config));
}
