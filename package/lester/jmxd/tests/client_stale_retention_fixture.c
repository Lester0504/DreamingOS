/*
 * Fixture for the offline-client retention filter.
 *
 * Acceptance found /api/v1/clients returning 26 rows of which 23 were offline,
 * median last_seen 16.7 days and the oldest 20.6 days. This drives the real
 * predicate (jmx_db_client_row_stale, lifted verbatim by the test harness) over
 * the shapes from that report plus the rows that must survive the filter.
 *
 * One line per scenario: "<name> stale=<0|1>".
 */
#include <stdio.h>
#include <stdint.h>
#include <json-c/json.h>

int jmx_db_client_row_stale(struct json_object *client, int64_t now,
                            int64_t retention_sec);
int db_mac_is_locally_administered_probe(const char *mac);

#define NOW ((int64_t)1785000000)
#define DAY ((int64_t)86400)
#define RETENTION (7 * DAY)

struct scenario {
    const char *name;
    double days_ago;      /* negative marks "no usable last_seen" */
    int pinned;
    const char *custom_name;
    const char *note;
};

static const struct scenario scenarios[] = {
    /* The reported pile-up: oldest and median from Acceptance's measurement. */
    { "oldest_20_6_days",        20.6, 0, "", "" },
    { "median_16_7_days",        16.7, 0, "", "" },
    { "eight_days",               8.0, 0, "", "" },
    /* Boundary: retention is 7 days, so just inside must stay. */
    { "just_inside_retention",    6.9, 0, "", "" },
    { "exactly_at_retention",     7.0, 0, "", "" },
    { "just_outside_retention",   7.1, 0, "", "" },
    /* Acceptance's most recent offline row, 22.4h. Must not vanish. */
    { "recent_offline_22h",     0.933, 0, "", "" },
    { "seen_minutes_ago",       0.003, 0, "", "" },
    /* User intent is exempt even when ancient. */
    { "ancient_but_pinned",      20.6, 1, "", "" },
    { "ancient_but_renamed",     20.6, 0, "Lester iPad", "" },
    { "ancient_but_noted",       20.6, 0, "", "spare laptop" },
    /* Observed once, never resolved: no usable timestamp. */
    { "no_last_seen",            -1.0, 0, "", "" },
    { "no_last_seen_pinned",     -1.0, 1, "", "" },
};

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
        const struct scenario *s = &scenarios[i];
        struct json_object *row = json_object_new_object();
        int64_t last_seen = s->days_ago < 0 ? 0 :
            NOW - (int64_t)(s->days_ago * (double)DAY);

        json_object_object_add(row, "last_seen", json_object_new_int64(last_seen));
        json_object_object_add(row, "online", json_object_new_boolean(0));
        json_object_object_add(row, "pinned", json_object_new_boolean(s->pinned));
        json_object_object_add(row, "custom_name", json_object_new_string(s->custom_name));
        json_object_object_add(row, "note", json_object_new_string(s->note));

        printf("%s stale=%d\n", s->name,
               jmx_db_client_row_stale(row, NOW, RETENTION));
        json_object_put(row);
    }

    /* A retention of 0 or less means "no ageing at all": the filter must be
     * switchable off without special-casing at every call site. */
    {
        struct json_object *row = json_object_new_object();

        json_object_object_add(row, "last_seen",
                               json_object_new_int64(NOW - 100 * DAY));
        json_object_object_add(row, "pinned", json_object_new_boolean(0));
        json_object_object_add(row, "custom_name", json_object_new_string(""));
        json_object_object_add(row, "note", json_object_new_string(""));
        printf("retention_disabled stale=%d\n",
               jmx_db_client_row_stale(row, NOW, 0));
        json_object_put(row);
    }

    /* Clock went backwards (NTP step). Do not delete the future. */
    {
        struct json_object *row = json_object_new_object();

        json_object_object_add(row, "last_seen",
                               json_object_new_int64(NOW + 10 * DAY));
        json_object_object_add(row, "pinned", json_object_new_boolean(0));
        json_object_object_add(row, "custom_name", json_object_new_string(""));
        json_object_object_add(row, "note", json_object_new_string(""));
        printf("last_seen_in_future stale=%d\n",
               jmx_db_client_row_stale(row, NOW, RETENTION));
        json_object_put(row);
    }

    printf("null_row stale=%d\n", jmx_db_client_row_stale(NULL, NOW, RETENTION));

    /* Randomized-MAC detection, on the addresses from Acceptance's report. The
     * first four are the ones it could not resolve to a vendor; the last two are
     * real OUIs that must not be mislabelled. */
    {
        static const struct { const char *mac; const char *name; } macs[] = {
            { "ea:6a:9a:62:3d:96", "mac_ea6a_reported" },
            { "02:00:5e:a0:80:11", "mac_30_222" },
            { "3e:64:a9:93:c5:f5", "mac_30_199" },
            { "02:00:00:00:00:99", "mac_30_199_alt" },
            { "b8:27:eb:11:22:33", "mac_real_oui_rpi" },
            { "00:1a:2b:3c:4d:5e", "mac_real_oui_plain" },
            { "",                  "mac_empty" },
            { "zz:zz:zz:zz:zz:zz", "mac_unparseable" },
        };
        size_t j;

        for (j = 0; j < sizeof(macs) / sizeof(macs[0]); j++)
            printf("%s randomized=%d\n", macs[j].name,
                   db_mac_is_locally_administered_probe(macs[j].mac));
        printf("mac_null randomized=%d\n",
               db_mac_is_locally_administered_probe(NULL));
    }
    return 0;
}
