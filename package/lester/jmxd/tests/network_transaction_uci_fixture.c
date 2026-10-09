// SPDX-License-Identifier: GPL-2.0-or-later
#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../src/netconfig/network_transaction_uci.h"

static char config_dir[256], delta_dir[256], package[64];

static char *read_network(void)
{
    char path[PATH_MAX], *text;
    snprintf(path, sizeof(path), "%s/%s", config_dir, package);
    FILE *f = fopen(path, "r");
    assert(f && fseek(f, 0, SEEK_END) == 0);
    long size = ftell(f);
    assert(size >= 0 && fseek(f, 0, SEEK_SET) == 0);
    text = calloc((size_t)size + 1, 1);
    assert(text && fread(text, 1, (size_t)size, f) == (size_t)size);
    assert(fclose(f) == 0);
    return text;
}

static struct uci_context *context(void)
{
    struct uci_context *ctx = uci_alloc_context();
    assert(ctx);
    assert(uci_set_confdir(ctx, config_dir) == UCI_OK);
    assert(uci_set_savedir(ctx, delta_dir) == UCI_OK);
    return ctx;
}

static void set(struct uci_context *ctx, const char *key, const char *value, int list)
{
    struct uci_ptr ptr = {0};
    char lookup[128];
    snprintf(lookup, sizeof(lookup), "%s.%s", package, key);
    assert(uci_lookup_ptr(ctx, &ptr, lookup, true) == UCI_OK);
    ptr.value = value;
    assert((list ? uci_add_list(ctx, &ptr) : uci_set(ctx, &ptr)) == UCI_OK);
}

int main(void)
{
    char tmp[] = "/tmp/f17-uci-stage-XXXXXX", path[PATH_MAX];
    struct uci_package *pkg = NULL;
    struct json_object *files = json_object_new_object();
    assert(mkdtemp(tmp));
    snprintf(package, sizeof(package), "%s", strrchr(tmp, '/') + 1);
    snprintf(config_dir, sizeof(config_dir), "%s/config", tmp);
    snprintf(delta_dir, sizeof(delta_dir), "%s/delta", tmp);
    assert(mkdir(config_dir, 0700) == 0 && mkdir(delta_dir, 0700) == 0);
    snprintf(path, sizeof(path), "%s/%s", config_dir, package);
    FILE *f = fopen(path, "w");
    assert(f && fputs("config interface 'lan'\n\toption proto 'static'\n"
                     "\tlist ipaddr '192.0.2.1/24'\n\n"
                     "config route\n\toption target '198.51.100.0/24'\n", f) >= 0);
    assert(fclose(f) == 0);
    char *before = read_network();
    struct uci_context *ctx = context();
    assert(uci_load(ctx, package, &pkg) == UCI_OK);
    set(ctx, "lan.disabled", "1", 0);
    set(ctx, "lan.note", "quote' and \\backslash", 0);
    set(ctx, "lan.dns", "192.0.2.53", 1);
    set(ctx, "lan.dns", "192.0.2.54", 1);
    assert(nc_tx_prepare_package(ctx, pkg, files) == 0);
    char *unchanged = read_network();
    assert(!strcmp(before, unchanged));
    free(unchanged);
    assert(uci_commit(ctx, &pkg, false) == UCI_OK);
    char *committed = read_network();
    assert(!strcmp(committed, json_object_get_string(json_object_object_get(files, package))));
    assert(strcmp(before, committed));
    uci_free_context(ctx);
    json_object_put(files);
    free(before);

    ctx = context();
    assert(uci_load(ctx, package, &pkg) == UCI_OK);
    set(ctx, "lan.proto", "dhcp", 0);
    assert(uci_save(ctx, pkg) == UCI_OK);
    uci_free_context(ctx);
    ctx = context();
    assert(uci_load(ctx, package, &pkg) == UCI_OK);
    files = json_object_new_object();
    assert(nc_tx_prepare_package(ctx, pkg, files) != 0);
    assert(json_object_object_length(files) == 0);
    unchanged = read_network();
    assert(!strcmp(committed, unchanged));
    free(committed); free(unchanged);
    json_object_put(files);
    uci_free_context(ctx);
    printf("ok: real libuci staged bytes equal commit; pending external delta refused (%s)\n", tmp);
    return 0;
}
