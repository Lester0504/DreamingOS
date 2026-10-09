#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "runtime.inc"

struct uci_context { int unused; };
struct uci_package { int unused; };
typedef struct { int query; int steps; } sqlite3_stmt;
#define SQLITE_ROW 100
#define UCI_OK 0
static struct uci_context context;
static struct uci_package package;
static sqlite3_stmt statement;
static int g_nc_upnp_readback_failed;
static int restores, reloads, mismatch, commit_fail;
static int desired[15] = {1, 1, 1, 0, 0, 100, 20, 30, 0, 1, 1, 0, 3479, 1, 60};
static const char *conf_path;
static const char *rendered_host = "stun.example.org";
static int nc_prepare(sqlite3_stmt **out, const char *query) {
    statement = (sqlite3_stmt){ .query = strstr(query, "SELECT enabled,") ? 1 : 0 };
    *out = &statement;
    return 0;
}
static int sqlite3_step(sqlite3_stmt *s) { return s->query && !s->steps++ ? SQLITE_ROW : 101; }
static int sqlite3_column_int(sqlite3_stmt *s, int i) { return desired[i]; }
static const unsigned char *sqlite3_column_text(sqlite3_stmt *s, int i) {
    return (const unsigned char *)(i == 11 ? "stun.example.org" : "");
}
static void sqlite3_finalize(sqlite3_stmt *s) {}
static int jmx_netconfig_db_init(void) { return 0; }
static int nc_upnp_import_uci_once(void) { return 0; }
static int nc_backup_config(const char *name, char *buf, size_t size) { snprintf(buf, size, "fixture-backup"); return 0; }
static struct uci_context *uci_alloc_context(void) { return &context; }
static int uci_load(struct uci_context *ctx, const char *name, struct uci_package **pkg) { *pkg = &package; return 0; }
static int nc_uci_ensure_section(struct uci_context *ctx, struct uci_package *pkg, const char *a, const char *b, const char *c) { return 0; }
static int nc_uci_set_pkg(struct uci_context *ctx, const char *a, const char *b, const char *c, const char *d) { return 0; }
static int nc_uci_delete_pkg(struct uci_context *ctx, const char *a, const char *b, const char *c) { return 0; }
static int nc_uci_add_list_pkg(struct uci_context *ctx, const char *a, const char *b, const char *c, const char *d) { return 0; }
static int nc_uci_delete_managed_sections(struct uci_context *ctx, struct uci_package *pkg, const char *a, const char *b, const char *c) { return 0; }
static int jmx_uci_commit(struct uci_context *ctx, const char *a) { return commit_fail ? -1 : 0; }
static int nc_file_exists(const char *path) { return 1; }
static int nc_run_quiet(const char *cmd) {
    FILE *fp = fopen(conf_path, "w");
    assert(fp);
    ++reloads;
    fprintf(fp, "ext_perform_stun=yes\next_stun_host=%s\next_stun_port=%d\nenable_pcp_pmp=yes\nclean_ruleset_interval=60\n",
            rendered_host, mismatch ? 3480 : 3479);
    fclose(fp);
    return 0;
}
static int nc_upnp_runtime_readback(void) {
    return nc_upnp_config_matches(conf_path, desired[10], "stun.example.org", desired[12], desired[13], desired[14]);
}
static void uci_free_context(struct uci_context *ctx) {}
static void nc_restore_config(const char *a, const char *b) { ++restores; }
static void nc_cleanup_backup(const char *path) {}
#include "apply.inc"

static void write_config(const char *text) {
    FILE *fp = fopen(conf_path, "w"); assert(fp); fputs(text, fp); fclose(fp);
}
int main(int argc, char **argv) {
    assert(argc == 2); conf_path = argv[1];
    assert(jmx_upnp_service_apply() == 0);
    assert(reloads == 1 && restores == 0 && !g_nc_upnp_readback_failed);
    mismatch = 1;
    assert(jmx_upnp_service_apply() == -5);
    assert(reloads == 3 && restores == 1 && g_nc_upnp_readback_failed);
    mismatch = 0;
    rendered_host = "wrong.example.org";
    assert(jmx_upnp_service_apply() == -5);
    assert(restores == 2);
    rendered_host = "stun.example.org";
    assert(jmx_upnp_service_apply() == 0 && !g_nc_upnp_readback_failed);
    commit_fail = 1;
    int prior = reloads;
    assert(jmx_upnp_service_apply() != 0 && reloads == prior && restores == 3);
    write_config("ext_perform_stun=no\nenable_pcp_pmp=no\nclean_ruleset_interval=0\n");
    assert(nc_upnp_config_matches(conf_path, 0, "", 3478, 0, 0) == 0);
    assert(nc_upnp_config_matches(conf_path, 0, "", 3478, 1, 0) != 0);
    assert(nc_upnp_config_matches(conf_path, 0, "", 3478, 0, 60) != 0);
    write_config("ext_perform_stun=yes\next_stun_host=stun.example.org\nenable_pcp_pmp=yes\nclean_ruleset_interval=60\n");
    assert(nc_upnp_config_matches(conf_path, 1, "stun.example.org", 3479, 1, 60) != 0);
    write_config("ext_perform_stun=no\next_perform_stun=no\nenable_pcp_pmp=no\nclean_ruleset_interval=0\n");
    assert(nc_upnp_config_matches(conf_path, 0, "", 3478, 0, 0) != 0);
    remove(conf_path);
    assert(nc_upnp_config_matches(conf_path, 0, "", 3478, 0, 0) != 0);
    puts("PASS: generated config STUN/PCP/cleanup readback; mismatch restores UCI and reloads; missing/duplicate keys rejected");
    return 0;
}
