/* Fixture for the validate -> write -> read cycle in src/routed/jmx_route_db.c.
 *
 * route_validate_payload(), route_replace_tables() and route_read_config() are
 * extracted from the shipped source and compiled here, so this exercises real
 * production code against a real SQLite database built from the real schema.
 *
 * The property under test is the one jmx_route_db_replace_begin() enforces: it
 * commits only when the canonical payload compares equal to the post-write
 * readback.  Once the export started splitting members into wan_ids and
 * dangling_wan_ids, any disagreement between the validator and the exporter
 * turned into "config.db transactional readback mismatch" and rolled the whole
 * write back -- including the ordinary case of deleting a WAN that a rule still
 * references.
 *
 *   argv[1] = scenario name
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#include "jmx_route.h"

#define ROUTE_HEALTH_FAIL_DEFAULT 2
#define ROUTE_HEALTH_RECOVER_DEFAULT 6
#define ROUTE_HEALTH_THRESHOLD_MAX 60

struct jmx_route_db_tx { sqlite3 *db; };

#include "route_dangling_extracted.h"

static sqlite3 *open_seeded(const char *const *statements)
{
    sqlite3 *db = NULL;
    int i;

    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
        return NULL;
    if (route_exec(db, route_schema_sql) != 0)
        return NULL;
    for (i = 0; statements[i]; i++) {
        if (route_exec(db, statements[i]) != 0) {
            fprintf(stderr, "seed failed: %s\n", statements[i]);
            return NULL;
        }
    }
    return db;
}

static struct json_object *wan_entry(int id, const char *name, const char *ifname)
{
    struct json_object *wan = json_object_new_object();

    json_object_object_add(wan, "id", json_object_new_int(id));
    json_object_object_add(wan, "name", json_object_new_string(name));
    json_object_object_add(wan, "ifname", json_object_new_string(ifname));
    return wan;
}

/* Report the cycle's verdict as JSON so the Python side asserts on values. */
static int run_cycle(sqlite3 *db, struct json_object *request)
{
    struct json_object *canonical = NULL, *readback = NULL;
    char error[256] = "";
    int equal;

    if (route_validate_payload(request, &canonical, error, sizeof(error)) != 0) {
        printf("{\"accepted\":false,\"error\":\"%s\"}\n", error);
        return 0;
    }
    if (route_replace_tables(db, canonical) != 0 ||
        route_read_config(db, &readback) != 0) {
        printf("{\"accepted\":true,\"write_failed\":true}\n");
        return 0;
    }
    equal = json_object_equal(canonical, readback);
    printf("{\"accepted\":true,\"committed\":%s,\"canonical\":%s,\"readback\":%s}\n",
           equal ? "true" : "false",
           json_object_to_json_string(canonical),
           json_object_to_json_string(readback));
    return 0;
}

/* The 30.1 shape: lines [1,2] configured, one rule still naming [1,2,3,4]. */
static const char *const seed_30_1[] = {
    "INSERT INTO route_global(id,enabled,all_down_action) VALUES(1,1,'main_route')",
    "INSERT INTO route_wan(id,position,name,ifname,fwmark,table_id)"
    " VALUES(1,0,'wan','eth1',101,101)",
    "INSERT INTO route_wan(id,position,name,ifname,fwmark,table_id)"
    " VALUES(2,1,'wan2','eth2',102,102)",
    "INSERT INTO route_rule(rule_id,position,name,enabled,prio,sticky_mode)"
    " VALUES(1,0,'default-lowest-rx-load',1,1000,'hash_src')",
    "INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,0,1)",
    "INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,1,2)",
    "INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,2,3)",
    "INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,3,4)",
    NULL,
};

/* A rule pinned only to lines that are gone: nothing resolves. */
static const char *const seed_all_stale[] = {
    "INSERT INTO route_global(id,enabled,all_down_action) VALUES(1,1,'main_route')",
    "INSERT INTO route_wan(id,position,name,ifname,fwmark,table_id)"
    " VALUES(1,0,'wan','eth1',101,101)",
    "INSERT INTO route_rule(rule_id,position,name,enabled,prio,sticky_mode)"
    " VALUES(1,0,'pinned-stale',1,1000,'hash_src')",
    "INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,0,3)",
    "INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,1,4)",
    NULL,
};

/* Two lines, one rule naming both: the starting point for deleting a WAN. */
static const char *const seed_two_live[] = {
    "INSERT INTO route_global(id,enabled,all_down_action) VALUES(1,1,'main_route')",
    "INSERT INTO route_wan(id,position,name,ifname,fwmark,table_id)"
    " VALUES(1,0,'wan','eth1',101,101)",
    "INSERT INTO route_wan(id,position,name,ifname,fwmark,table_id)"
    " VALUES(2,1,'wan2','eth2',102,102)",
    "INSERT INTO route_rule(rule_id,position,name,enabled,prio,sticky_mode)"
    " VALUES(1,0,'default',1,1000,'hash_src')",
    "INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,0,1)",
    "INSERT INTO route_rule_wan(rule_id,position,wan_id) VALUES(1,1,2)",
    NULL,
};

int main(int argc, char **argv)
{
    const char *scenario = argc > 1 ? argv[1] : "";
    struct json_object *request = NULL, *wans = NULL;
    sqlite3 *db = NULL;

    if (!strcmp(scenario, "readback_roundtrip") ||
        !strcmp(scenario, "all_stale_roundtrip")) {
        /* Read the config and write it straight back, the read-modify-write an
         * unrelated edit performs. */
        db = open_seeded(!strcmp(scenario, "readback_roundtrip")
                         ? seed_30_1 : seed_all_stale);
        if (!db || route_read_config(db, &request) != 0)
            return 2;
        return run_cycle(db, request);
    }
    if (!strcmp(scenario, "delete_referenced_wan")) {
        /* Drop WAN 2 while the rule still names it. */
        db = open_seeded(seed_two_live);
        if (!db || route_read_config(db, &request) != 0)
            return 2;
        json_object_object_get_ex(request, "wans", &wans);
        while (json_object_array_length(wans) > 1)
            json_object_array_del_idx(wans, 1, 1);
        return run_cycle(db, request);
    }
    if (!strcmp(scenario, "restore_stale_wan")) {
        /* Add WAN 3 back; its stale member must become a live target again. */
        db = open_seeded(seed_all_stale);
        if (!db || route_read_config(db, &request) != 0)
            return 2;
        json_object_object_get_ex(request, "wans", &wans);
        json_object_array_add(wans, wan_entry(3, "wan3", "eth3"));
        return run_cycle(db, request);
    }
    if (!strcmp(scenario, "no_members_no_carrier")) {
        /* Still invalid: an enabled rule naming nothing and matching nothing. */
        struct json_object *rules, *rule;

        db = open_seeded(seed_two_live);
        if (!db)
            return 2;
        request = json_object_new_object();
        wans = json_object_new_array();
        json_object_array_add(wans, wan_entry(1, "wan", "eth1"));
        json_object_object_add(request, "wans", wans);
        rules = json_object_new_array();
        rule = json_object_new_object();
        json_object_object_add(rule, "name", json_object_new_string("empty"));
        json_object_object_add(rule, "enabled", json_object_new_int(1));
        json_object_object_add(rule, "prio", json_object_new_int(1000));
        json_object_object_add(rule, "wan_ids", json_object_new_array());
        json_object_array_add(rules, rule);
        json_object_object_add(request, "rules", rules);
        return run_cycle(db, request);
    }
    if (!strcmp(scenario, "stale_id_out_of_range")) {
        /* A malformed stale id must name itself, not the carrier complaint. */
        struct json_object *rules, *rule, *stale;

        db = open_seeded(seed_two_live);
        if (!db)
            return 2;
        request = json_object_new_object();
        wans = json_object_new_array();
        json_object_array_add(wans, wan_entry(1, "wan", "eth1"));
        json_object_object_add(request, "wans", wans);
        rules = json_object_new_array();
        rule = json_object_new_object();
        json_object_object_add(rule, "name", json_object_new_string("bad-stale"));
        json_object_object_add(rule, "enabled", json_object_new_int(1));
        json_object_object_add(rule, "prio", json_object_new_int(1000));
        json_object_object_add(rule, "wan_ids", json_object_new_array());
        stale = json_object_new_array();
        json_object_array_add(stale, json_object_new_int(999));
        json_object_object_add(rule, "dangling_wan_ids", stale);
        json_object_array_add(rules, rule);
        json_object_object_add(request, "rules", rules);
        return run_cycle(db, request);
    }
    fprintf(stderr, "unknown scenario: %s\n", scenario);
    return 2;
}
