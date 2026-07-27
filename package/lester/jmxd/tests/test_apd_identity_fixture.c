// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define APD_AP_ID_LEN 36
#define APD_ED25519_KEY_LEN 32
#define APD_KEY_ID_LEN 71
#define APD_PAIRING_VALUE_LEN 128

struct apd_node_identity {
    char ap_id[APD_AP_ID_LEN + 1];
    char key_id[APD_KEY_ID_LEN + 1];
    unsigned char public_key[APD_ED25519_KEY_LEN];
    int64_t created_at;
};

struct apd_pairing_status {
    char state[32];
    char controller_id[APD_PAIRING_VALUE_LEN + 1];
    char request_id[APD_PAIRING_VALUE_LEN + 1];
    int challenge_present;
    int attempts;
    int64_t expires_at;
    int64_t updated_at;
};

int apd_db_init(void);
void apd_db_close(void);
int apd_db_identity_get(struct apd_node_identity *out);
int apd_db_pairing_status_get(struct apd_pairing_status *out);
int apd_db_pairing_begin(const char *controller_id, const char *request_id,
                         int64_t expires_at);
int apd_db_pairing_set_challenge(const char *request_id,
                                 const unsigned char *challenge,
                                 size_t challenge_len);
int apd_db_pairing_verify_challenge(const char *request_id,
                                    const unsigned char *challenge,
                                    size_t challenge_len);
int apd_db_pairing_reset(const char *request_id);

static void print_hex(const unsigned char *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static int print_identity(void)
{
    struct apd_node_identity identity;

    memset(&identity, 0, sizeof(identity));
    if (apd_db_identity_get(&identity) != 0)
        return 1;
    printf("ap_id=%s\nalgorithm=Ed25519\nkey_id=%s\npublic_key=",
           identity.ap_id, identity.key_id);
    print_hex(identity.public_key, sizeof(identity.public_key));
    printf("\ncreated_at=%lld\nkey_exportable=false\n",
           (long long)identity.created_at);
    memset(&identity, 0, sizeof(identity));
    return 0;
}

static int print_pairing(void)
{
    struct apd_pairing_status status;

    memset(&status, 0, sizeof(status));
    if (apd_db_pairing_status_get(&status) != 0)
        return 1;
    printf("state=%s\ncontroller_id=%s\nrequest_id=%s\nchallenge_present=%s\n"
           "attempts=%d\nexpires_at=%lld\nmtls_ready=false\nadopted=false\n",
           status.state, status.controller_id, status.request_id,
           status.challenge_present ? "true" : "false", status.attempts,
           (long long)status.expires_at);
    memset(&status, 0, sizeof(status));
    return 0;
}

int main(int argc, char **argv)
{
    static const unsigned char challenge[] =
        "phase1b-local-challenge-material-00000001";
    static const unsigned char wrong[] =
        "phase1b-local-challenge-material-00000002";
    const char *command = argc > 1 ? argv[1] : "identity";
    int rc = 1;

    if (apd_db_init() != 0)
        return 2;
    if (strcmp(command, "identity") == 0) {
        rc = print_identity();
    } else if (strcmp(command, "pairing-status") == 0) {
        rc = print_pairing();
    } else if (strcmp(command, "pairing-begin") == 0) {
        rc = apd_db_pairing_begin("controller-test", "request-test",
                                  (int64_t)time(NULL) + 300);
    } else if (strcmp(command, "pairing-begin-short") == 0) {
        rc = apd_db_pairing_begin("controller-test", "request-test",
                                  (int64_t)time(NULL) + 1);
    } else if (strcmp(command, "pairing-challenge") == 0) {
        rc = apd_db_pairing_set_challenge("request-test", challenge,
                                          sizeof(challenge) - 1);
    } else if (strcmp(command, "pairing-wrong") == 0) {
        rc = apd_db_pairing_verify_challenge("request-test", wrong,
                                             sizeof(wrong) - 1) == 1 ? 0 : 1;
    } else if (strcmp(command, "pairing-verify") == 0) {
        rc = apd_db_pairing_verify_challenge("request-test", challenge,
                                             sizeof(challenge) - 1);
    } else if (strcmp(command, "pairing-reset") == 0) {
        rc = apd_db_pairing_reset("request-test");
    }
    apd_db_close();
    return rc == 0 ? 0 : 1;
}
