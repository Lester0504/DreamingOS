// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * App device registry lookups.
 *
 * webd stores the App's uploaded key material in app_devices.public_key during
 * pairing (jmx_app_api.c, jmx_app_pair_init_ex). The column holds the JSON the
 * App uploaded:
 *
 *   {"v":1,"kex":"x25519","kex_pub":"<b64 32B>","sig":"ed25519",
 *    "sig_pub":"<b64 32B>"}
 *
 * This daemon is the first consumer of that column. It only ever reads
 * app_devices; webd remains the sole writer of pairing state, so there is no
 * two-writer hazard on the pairing rows. The one write below is a bounded
 * UPDATE of remote-access telemetry columns this daemon owns.
 *
 * Only devices that completed pairing (paired_at > 0) and are still enabled can
 * authorize a relay frame; a pending or revoked device is refused.
 */
#include "cloud_internal.h"

static sqlite3 *g_cloud_app_db;

static sqlite3 *cloud_devices_db(void)
{
    if (g_cloud_app_db)
        return g_cloud_app_db;
    /* Read-only handle: this process must not be able to alter pairing rows
     * even by accident. The remote-access telemetry update below uses its own
     * short-lived writable handle. */
    if (sqlite3_open_v2(CLOUD_APP_DB_PATH, &g_cloud_app_db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (g_cloud_app_db) {
            sqlite3_close(g_cloud_app_db);
            g_cloud_app_db = NULL;
        }
        return NULL;
    }
    sqlite3_busy_timeout(g_cloud_app_db, 3000);
    return g_cloud_app_db;
}

/*
 * Extracts sig_pub from the stored JSON. Anything that is not the expected
 * shape, or not a 32-byte Ed25519 key, yields no match: an App that never
 * uploaded real key material simply cannot use the relay path.
 */
static int cloud_devices_parse_signing_key(const char *stored,
                                           unsigned char *out)
{
    struct json_object *root;
    struct json_object *value = NULL;
    const char *encoded;
    int rc = -1;

    if (!stored || !stored[0])
        return -1;
    root = json_tokener_parse(stored);
    if (!root || !json_object_is_type(root, json_type_object))
        goto done;
    if (!json_object_object_get_ex(root, "sig", &value) || !value ||
        !json_object_is_type(value, json_type_string) ||
        strcmp(json_object_get_string(value), "ed25519"))
        goto done;
    if (!json_object_object_get_ex(root, "sig_pub", &value) || !value ||
        !json_object_is_type(value, json_type_string))
        goto done;
    encoded = json_object_get_string(value);
    if (cloud_base64_decode_fixed(encoded, out, CLOUD_ED25519_KEY_LEN) != 0)
        goto done;
    rc = 0;
done:
    if (root)
        json_object_put(root);
    return rc;
}

int cloud_devices_signing_key_known(const unsigned char *signing_key,
                                    char *device_id, size_t device_id_size)
{
    sqlite3 *db = cloud_devices_db();
    sqlite3_stmt *st = NULL;
    int found = 0;

    if (!db || !signing_key)
        return 0;
    if (sqlite3_prepare_v2(db,
            "SELECT id,public_key FROM app_devices "
            "WHERE enabled=1 AND paired_at>0 AND public_key<>''",
            -1, &st, NULL) != SQLITE_OK)
        return 0;

    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *id = sqlite3_column_text(st, 0);
        const unsigned char *stored = sqlite3_column_text(st, 1);
        unsigned char candidate[CLOUD_ED25519_KEY_LEN];

        if (!id || !stored)
            continue;
        if (cloud_devices_parse_signing_key((const char *)stored,
                                            candidate) != 0)
            continue;
        /* Constant-time compare: this runs on attacker-supplied input and the
         * loop's timing should not leak which prefix matched. */
        if (CRYPTO_memcmp(candidate, signing_key, CLOUD_ED25519_KEY_LEN) == 0) {
            if (device_id && device_id_size)
                snprintf(device_id, device_id_size, "%s", (const char *)id);
            found = 1;
            OPENSSL_cleanse(candidate, sizeof(candidate));
            break;
        }
        OPENSSL_cleanse(candidate, sizeof(candidate));
    }
    sqlite3_finalize(st);
    return found;
}

/*
 * Base64 Ed25519 public keys of every paired, enabled App.
 *
 * The keys are re-encoded from the parsed 32 raw bytes rather than passed
 * through from the stored JSON, so a row with odd padding or whitespace cannot
 * produce a string the relay decodes differently than this daemon validated.
 */
struct json_object *cloud_devices_signing_keys(void)
{
    sqlite3 *db = cloud_devices_db();
    struct json_object *array;
    sqlite3_stmt *st = NULL;
    int emitted = 0;

    array = json_object_new_array();
    if (!array)
        return NULL;
    if (!db)
        return array;
    if (sqlite3_prepare_v2(db,
            "SELECT public_key FROM app_devices "
            "WHERE enabled=1 AND paired_at>0 AND public_key<>''",
            -1, &st, NULL) != SQLITE_OK)
        return array;

    while (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *stored = sqlite3_column_text(st, 0);
        unsigned char raw[CLOUD_ED25519_KEY_LEN];
        char *encoded = NULL;

        /* Bounded so a large pairing table cannot inflate the hello frame past
         * the 64 KiB wire limit; the relay caps its own side at 64 keys. */
        if (emitted >= CLOUD_MAX_AUTHORIZED_APPS)
            break;
        if (!stored)
            continue;
        if (cloud_devices_parse_signing_key((const char *)stored, raw) != 0)
            continue;
        if (cloud_base64_encode(raw, sizeof(raw), &encoded) == 0 && encoded) {
            json_object_array_add(array, json_object_new_string(encoded));
            free(encoded);
            emitted++;
        }
        OPENSSL_cleanse(raw, sizeof(raw));
    }
    sqlite3_finalize(st);
    return array;
}

int cloud_devices_count(int *out)
{
    sqlite3 *db = cloud_devices_db();
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!db || !out)
        return -1;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM app_devices "
            "WHERE enabled=1 AND paired_at>0 AND public_key<>''",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *out = sqlite3_column_int(st, 0);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

/*
 * Records that a device was last reached over the relay. This is the GAP-RL-06
 * audit signal: it lets the UI distinguish local from remote access.
 *
 * Opened write-capable per call and closed immediately, so this process holds
 * no long-lived write lock on a database whose primary writer is webd. Failure
 * is non-fatal; losing a telemetry timestamp must never drop a request.
 */
int cloud_devices_touch_remote(const char *device_id, int64_t when)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    int rc = -1;

    if (!device_id || !device_id[0] || when <= 0)
        return -1;
    if (sqlite3_open_v2(CLOUD_APP_DB_PATH, &db, SQLITE_OPEN_READWRITE,
                        NULL) != SQLITE_OK)
        goto done;
    sqlite3_busy_timeout(db, 2000);

    /* Columns are created by webd's schema migration. If an older webd is
     * running they will be absent, and prepare fails harmlessly. */
    if (sqlite3_prepare_v2(db,
            "UPDATE app_devices SET last_remote_seen=?1,last_access_path='relay' "
            "WHERE id=?2 AND enabled=1 AND paired_at>0",
            -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, when);
    sqlite3_bind_text(st, 2, device_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_DONE)
        rc = 0;
done:
    if (st)
        sqlite3_finalize(st);
    if (db)
        sqlite3_close(db);
    return rc;
}
