// SPDX-License-Identifier: GPL-2.0-or-later
#define AC_DB_TEST_STANDALONE
#define AC_DB_TELEMETRY_TEST_STANDALONE
#include "../src/ac/ac_db.c"
#include <assert.h>

#define AP "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
#define CERT "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
#define ENROLL "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
#define OTHER_CERT "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
#define EPOCH "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define OLD_EPOCH "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

static int scalar(const char *sql)
{
    sqlite3_stmt *st = NULL;
    assert(sqlite3_prepare_v2(g_ac_db, sql, -1, &st, NULL) == SQLITE_OK);
    assert(sqlite3_step(st) == SQLITE_ROW);
    int value = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return value;
}

int main(void)
{
    struct ac_pairing_token_secret token;
    struct ac_ap_unbind_request request, repeated, ready, ack;
    assert(ac_db_init() == 0);
    assert(ac_db_pairing_token_create(600, 5, "", "", &token) == 0);
    char *sql = sqlite3_mprintf(
        "INSERT INTO ac_aps(ap_id,adoption_state) VALUES('" AP "','adopted');"
        "INSERT INTO ac_device_certificates(certificate_id,ap_id,serial,key_id,"
        "not_before,not_after,state) VALUES('" CERT "','" AP "','serial','key',"
        "1,9999999999,'active'),('" OTHER_CERT "','" AP "','old','key',"
        "1,9999999999,'expired');"
        "UPDATE ac_pairing_tokens SET consumed_at=1,consumed_enrollment_id='" ENROLL "' "
        "WHERE token_id='%q';"
        "INSERT INTO ac_enrollments(enrollment_id,token_id,ap_id,site_id,key_id,"
        "public_key,csr_der,csr_sha256,client_nonce,challenge_id,state,claim_expires_at,"
        "certificate_id,created_at,updated_at) VALUES('" ENROLL "','%q','" AP "',"
        "'default','key',zeroblob(32),X'01',zeroblob(32),zeroblob(32),"
        "'challenge','adopted',1,'" CERT "',1,1);",
        token.token_id, token.token_id);
    assert(sql && ac_exec(sql) == 0);
    sqlite3_free(sql);
    assert(ac_enrollment_state_validate() == 0);

    /* Offline: no runtime row or AP connection is required. */
    assert(ac_db_ap_unbind_request_create(AP, &request) == AC_AP_UNBIND_OK);
    assert(!strcmp(request.state, "pending"));
    assert(scalar("SELECT COUNT(*) FROM ac_aps WHERE adoption_state='adopted'") == 0);
    assert(scalar("SELECT COUNT(*) FROM ac_ap_runtime") == 0);
    assert(ac_db_ap_unbind_request_create(AP, &repeated) == AC_AP_UNBIND_OK);
    assert(!strcmp(request.request_id, repeated.request_id));
    assert(ac_enrollment_state_validate() == 0);
    ac_db_close();
    assert(ac_db_init() == 0);
    assert(ac_db_ap_unbind_request_pending(AP, &repeated) == AC_AP_UNBIND_OK);
    assert(!strcmp(request.request_id, repeated.request_id));

    /* Reconnection is cleanup-only, never a new writable adoption. */
    assert(ac_db_ap_session_begin_with_capabilities_and_unbind(
        AP, EPOCH, 3, 1, ac_now_s(), &ready) == 0);
    assert(!strcmp(request.request_id, ready.request_id));
    assert(scalar("SELECT write_capable FROM ac_ap_runtime WHERE ap_id='" AP "'") == 0);
    assert(!ac_db_ap_session_is_current(AP, EPOCH));
    assert(ac_db_ap_unbind_request_ack(AP, OLD_EPOCH, request.request_id,
        1, "", &ack) != AC_AP_UNBIND_OK);
    assert(ac_db_ap_unbind_request_ack(AP, EPOCH, OTHER_CERT,
        1, "", &ack) != AC_AP_UNBIND_OK);
    assert(ac_db_ap_unbind_request_ack(AP, EPOCH, request.request_id,
        0, "credentials_unpair_failed", &ack) == AC_AP_UNBIND_OK);
    assert(!strcmp(ack.state, "pending"));
    assert(!strcmp(ack.error_code, "credentials_unpair_failed"));
    assert(scalar("SELECT COUNT(*) FROM ac_aps WHERE adoption_state='adopted'") == 0);
    assert(ac_db_ap_unbind_request_ack(AP, EPOCH, request.request_id,
        1, "", &ack) == AC_AP_UNBIND_OK);
    assert(!strcmp(ack.state, "completed") && ack.acknowledged_at > 0);
    assert(scalar("SELECT state='revoked' FROM ac_device_certificates "
                  "WHERE certificate_id='" CERT "'") == 1);
    assert(scalar("SELECT state='expired' FROM ac_device_certificates "
                  "WHERE certificate_id='" OTHER_CERT "'") == 1);
    assert(scalar("SELECT state='revoked' FROM ac_enrollments "
                  "WHERE enrollment_id='" ENROLL "'") == 1);
    assert(scalar("SELECT adoption_state='pending_pairing' FROM ac_aps "
                  "WHERE ap_id='" AP "'") == 1);
    ac_db_close();
    assert(ac_db_init() == 0);
    assert(ac_db_ap_unbind_request_pending(AP, &ready) == AC_AP_UNBIND_NOT_FOUND);
    assert(ac_db_ap_unbind_request_status(AP, &ready) == AC_AP_UNBIND_OK);
    assert(!strcmp(ready.state, "completed"));
    assert(ac_db_ap_unbind_request_create(AP, &repeated) == AC_AP_UNBIND_OK);
    assert(!strcmp(repeated.request_id, request.request_id));
    ac_db_close();
    puts("PASS: offline immediate detach, restart, idempotency, cleanup-only session, "
         "wrong ACK rejection, failed ACK retry, precise revocation");
    return 0;
}
