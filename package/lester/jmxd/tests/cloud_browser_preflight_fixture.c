// SPDX-License-Identifier: GPL-2.0-or-later
#include "../src/cloud/cloud_browser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int bound = 1, reads;
static int service_reachable = 1;
static int quota;
struct json_object *cwc_service_probe(const struct cwc_service *service)
{
    (void)service;
    return json_tokener_parse(service_reachable ? "{\"reachable\":true}" : "{\"reachable\":false}");
}
int cwc_publication_read(const struct cwc_config *c, struct cwc_publication *r)
{
    (void)c;
    ++reads;
    memset(r, 0, sizeof(*r));
    strcpy(r->cloud_id, "01234567890123456789012345678901");
    strcpy(r->canonical_host, "localhost");
    strcpy(r->error, "binding_required");
    r->generation = 1; r->revision = 1;
    if (quota) {
        r->quota_known = 1;
        r->account_service_limit = 2;
        r->account_services = quota;
        r->device_services = 1;
    }
    return bound ? 0 : -1;
}
static int allowed(struct cwc_config *c)
{
    struct json_object *r = cloud_browser_preflight(c), *v = NULL;
    int ok = json_object_object_get_ex(r, "enable_allowed", &v) && json_object_get_boolean(v);
    puts(json_object_to_json_string_ext(r, JSON_C_TO_STRING_PLAIN));
    json_object_put(r);
    return ok;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d\n", __LINE__); exit(1); } } while (0)
int main(int argc, char **argv)
{
    CHECK(argc == 3);
    struct cwc_config c = {.n_services = 1};
    strcpy(c.tunnel_host, "localhost");
    c.tunnel_port = (uint16_t)atoi(argv[2]);
    snprintf(c.ca_path, sizeof(c.ca_path), "%s", argv[1]);
    struct cwc_service *s = &c.services[0];
    strcpy(s->id, "web"); strcpy(s->public_host, "localhost"); s->management = 1;
    snprintf(s->ca_path, sizeof(s->ca_path), "%s", argv[1]);
    CHECK(allowed(&c));
    bound = 0; CHECK(!allowed(&c)); bound = 1;
    s->ca_path[0] = 0; CHECK(!allowed(&c));
    snprintf(s->ca_path, sizeof(s->ca_path), "%s", argv[1]);
    c.ca_path[0] = 0; CHECK(!allowed(&c));
    snprintf(c.ca_path, sizeof(c.ca_path), "%s", argv[1]);
    strcpy(s->public_host, "127.0.0.1"); CHECK(!allowed(&c));
    CHECK(reads == 5);
    strcpy(s->public_host, "localhost");
    c.n_services = 2;
    strcpy(c.services[1].id, "nas");
    CHECK(allowed(&c));
    service_reachable = 0;
    CHECK(!allowed(&c));
    service_reachable = 1;
    quota = 2;
    CHECK(!allowed(&c));
    quota = 1;
    CHECK(allowed(&c));
    puts("browser preflight: 9 TLS/DNS/binding/service/quota scenarios passed");
    return 0;
}
