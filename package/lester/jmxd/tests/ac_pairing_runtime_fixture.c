// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AC_PAIRING_TOKEN_ID_LEN 36
#define AC_PAIRING_TOKEN_LEN 43
#define AC_PAIRING_SITE_ID_LEN 64
#define AC_PAIRING_HARDWARE_DIGEST_LEN 71

enum ac_pairing_redeem_result {
    AC_PAIRING_REDEEM_ERROR = -1,
    AC_PAIRING_REDEEM_OK = 0,
    AC_PAIRING_REDEEM_INVALID = 1,
    AC_PAIRING_REDEEM_EXPIRED = 2,
    AC_PAIRING_REDEEM_REVOKED = 3,
    AC_PAIRING_REDEEM_CONSUMED = 4,
    AC_PAIRING_REDEEM_EXHAUSTED = 5,
};

struct ac_pairing_token_secret {
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char token[AC_PAIRING_TOKEN_LEN + 1];
    int64_t created_at;
    int64_t expires_at;
    int max_attempts;
};

struct ac_pairing_token_status {
    char token_id[AC_PAIRING_TOKEN_ID_LEN + 1];
    char site_id[AC_PAIRING_SITE_ID_LEN + 1];
    int hardware_bound;
    int attempts;
    int max_attempts;
    int64_t created_at;
    int64_t expires_at;
    int64_t consumed_at;
    int64_t revoked_at;
    int64_t claimed_at;
    char state[16];
};

typedef int (*ac_pairing_token_visit_fn)(
    const struct ac_pairing_token_status *status, void *opaque);

int ac_db_init(void);
void ac_db_close(void);
int ac_db_pairing_token_create(int64_t ttl_seconds, int max_attempts,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_secret *out);
int ac_db_pairing_token_status(const char *token_id,
                               struct ac_pairing_token_status *out);
int ac_db_pairing_token_list(ac_pairing_token_visit_fn visit, void *opaque);
int ac_db_pairing_token_revoke(const char *token_id);
int ac_db_pairing_token_redeem(const char *token_id, const char *token,
                               const char *site_id,
                               const char *hardware_digest,
                               struct ac_pairing_token_status *out);

static void print_status(const struct ac_pairing_token_status *status)
{
    printf("token_id=%s state=%s site_id=%s hardware_bound=%d attempts=%d "
           "max_attempts=%d created_at=%lld expires_at=%lld consumed_at=%lld "
           "revoked_at=%lld\n",
           status->token_id, status->state, status->site_id,
           status->hardware_bound, status->attempts, status->max_attempts,
           (long long)status->created_at, (long long)status->expires_at,
           (long long)status->consumed_at, (long long)status->revoked_at);
}

static int list_visit(const struct ac_pairing_token_status *status, void *opaque)
{
    (void)opaque;
    print_status(status);
    return 0;
}

int main(int argc, char **argv)
{
    struct ac_pairing_token_secret secret;
    struct ac_pairing_token_status status;
    const char *command;
    int rc = 1;
    int result;

    if (argc < 2 || ac_db_init() != 0)
        return 2;
    command = argv[1];
    if (strcmp(command, "init") == 0) {
        rc = 0;
    } else if (strcmp(command, "create") == 0 && argc == 6) {
        if (ac_db_pairing_token_create(strtoll(argv[2], NULL, 10),
                atoi(argv[3]), argv[4], argv[5], &secret) == 0) {
            printf("token_id=%s token=%s created_at=%lld expires_at=%lld max_attempts=%d\n",
                   secret.token_id, secret.token, (long long)secret.created_at,
                   (long long)secret.expires_at, secret.max_attempts);
            rc = 0;
        }
    } else if (strcmp(command, "status") == 0 && argc == 3) {
        if (ac_db_pairing_token_status(argv[2], &status) == 0) {
            print_status(&status);
            rc = 0;
        }
    } else if (strcmp(command, "list") == 0) {
        result = ac_db_pairing_token_list(list_visit, NULL);
        if (result >= 0) {
            printf("count=%d\n", result);
            rc = 0;
        }
    } else if (strcmp(command, "revoke") == 0 && argc == 3) {
        rc = ac_db_pairing_token_revoke(argv[2]) == 0 ? 0 : 1;
    } else if (strcmp(command, "redeem") == 0 && argc == 6) {
        memset(&status, 0, sizeof(status));
        result = ac_db_pairing_token_redeem(argv[2], argv[3], argv[4], argv[5],
                                            &status);
        printf("result=%d", result);
        if (status.token_id[0]) {
            printf(" ");
            print_status(&status);
        } else {
            printf("\n");
        }
        rc = result == AC_PAIRING_REDEEM_ERROR ? 1 : 0;
    } else if (strcmp(command, "commit-failure-create") == 0) {
        setenv("AC_DB_TEST_FAIL_COMMIT_ONCE", "1", 1);
        if (ac_db_pairing_token_create(600, 5, "", "", &secret) != 0 &&
            ac_db_pairing_token_create(600, 5, "", "", &secret) == 0) {
            printf("recovered_token_id=%s\n", secret.token_id);
            rc = 0;
        }
    } else if (strcmp(command, "commit-failure-redeem") == 0 && argc == 4) {
        setenv("AC_DB_TEST_FAIL_COMMIT_ONCE", "1", 1);
        memset(&status, 0, sizeof(status));
        result = ac_db_pairing_token_redeem(argv[2], argv[3], "", "", &status);
        if (result == AC_PAIRING_REDEEM_ERROR) {
            memset(&status, 0, sizeof(status));
            result = ac_db_pairing_token_redeem(argv[2], argv[3], "", "", &status);
            printf("recovered_result=%d\n", result);
            rc = result == AC_PAIRING_REDEEM_OK ? 0 : 1;
        }
    }
    ac_db_close();
    return rc;
}
