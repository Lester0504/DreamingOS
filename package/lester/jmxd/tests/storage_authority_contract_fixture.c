// SPDX-License-Identifier: GPL-2.0-or-later
#include "storage/storage_provider.h"
#include "authority/authority_diagnostics.h"

#include <stdio.h>

/* The host fixture links storage_provider.c without storage_supervisor.c,
 * which needs libubus.  Standing in for it with "never ready" is the honest
 * model of this environment: no ubus context is bound, so no consumer can be
 * frozen, and the provider must report migration_supported=false.  Linking the
 * real supervisor here would test ubus availability on the build host rather
 * than the contract. */
int jmx_storage_supervisor_ready(void)
{
    return 0;
}

/* Linux block-device policy is exercised separately with sysfs fixtures. */
struct json_object *jmx_storage_policy_evaluate(int prepare, char *selected,
        size_t selected_len, char *provider, size_t provider_len)
{
    (void)prepare;
    if (selected && selected_len) selected[0] = '\0';
    if (provider && provider_len) provider[0] = '\0';
    return json_object_new_object();
}

#ifndef STORAGE_BINDING_TEST_ONLY
int main(void)
{
    struct json_object *providers = jmx_storage_provider_status_json();
    struct json_object *authority = jmx_authority_diagnostics_json();

    if (!providers || !authority)
        return 1;
    puts(json_object_to_json_string_ext(providers, JSON_C_TO_STRING_PLAIN));
    puts(json_object_to_json_string_ext(authority, JSON_C_TO_STRING_PLAIN));
    json_object_put(providers);
    json_object_put(authority);
    return 0;
}
#endif
