// SPDX-License-Identifier: GPL-2.0-or-later
#include "webd_admin_transaction.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fake_step {
    const char *name;
    int value;
    int target;
    int preflight_fail;
    int snapshot_fail;
    int apply_fail_after_write;
    int restore_fail;
    int apply_calls;
    int restore_calls;
    char *order;
    size_t order_len;
};

struct fake_snapshot {
    int value;
};

static void order_append(struct fake_step *step, char marker)
{
    size_t length;

    if (!step->order || step->order_len < 2)
        return;
    length = strlen(step->order);
    if (length + 1 < step->order_len) {
        step->order[length] = marker;
        step->order[length + 1] = '\0';
    }
}

static int fake_preflight(void *context, char *error, size_t error_len)
{
    struct fake_step *step = context;

    order_append(step, 'p');
    if (!step->preflight_fail)
        return 0;
    snprintf(error, error_len, "%s_preflight", step->name);
    return -1;
}

static int fake_snapshot(void *context, void **snapshot, char *error,
                         size_t error_len)
{
    struct fake_step *step = context;
    struct fake_snapshot *copy;

    order_append(step, 's');
    if (step->snapshot_fail) {
        snprintf(error, error_len, "%s_snapshot", step->name);
        return -1;
    }
    copy = malloc(sizeof(*copy));
    assert(copy);
    copy->value = step->value;
    *snapshot = copy;
    return 0;
}

static int fake_apply(void *context, char *error, size_t error_len)
{
    struct fake_step *step = context;

    order_append(step, 'a');
    step->apply_calls++;
    step->value = step->target;
    if (!step->apply_fail_after_write)
        return 0;
    snprintf(error, error_len, "%s_apply_after_write", step->name);
    return -1;
}

static int fake_restore(void *context, void *snapshot, char *error,
                        size_t error_len)
{
    struct fake_step *step = context;
    struct fake_snapshot *copy = snapshot;

    order_append(step, 'r');
    step->restore_calls++;
    if (step->restore_fail) {
        snprintf(error, error_len, "%s_restore", step->name);
        return -1;
    }
    step->value = copy->value;
    return 0;
}

static void fake_snapshot_free(void *context, void *snapshot)
{
    struct fake_step *step = context;

    order_append(step, 'f');
    free(snapshot);
}

static struct webd_admin_txn_step reversible(struct fake_step *step)
{
    struct webd_admin_txn_step result = {
        .name = step->name,
        .context = step,
        .preflight = fake_preflight,
        .snapshot = fake_snapshot,
        .apply = fake_apply,
        .restore = fake_restore,
        .snapshot_free = fake_snapshot_free,
    };

    return result;
}

static struct webd_admin_txn_step irreversible(struct fake_step *step)
{
    struct webd_admin_txn_step result = {
        .name = step->name,
        .flags = WEBD_ADMIN_TXN_IRREVERSIBLE,
        .context = step,
        .preflight = fake_preflight,
        .apply = fake_apply,
    };

    return result;
}

static void test_success_and_order(void)
{
    char order[64] = "";
    struct fake_step settings = {.name = "settings", .value = 1, .target = 2,
                                 .order = order, .order_len = sizeof(order)};
    struct fake_step avatar = {.name = "avatar", .value = 10, .target = 20,
                               .order = order, .order_len = sizeof(order)};
    struct fake_step identity = {.name = "identity_password", .value = 100,
                                 .target = 200, .order = order,
                                 .order_len = sizeof(order)};
    struct webd_admin_txn_step steps[] = {
        reversible(&settings), reversible(&avatar), irreversible(&identity),
    };
    struct webd_admin_txn_result result;

    assert(webd_admin_txn_execute(steps, 3, &result) == WEBD_ADMIN_TXN_OK);
    assert(result.status == WEBD_ADMIN_TXN_OK);
    assert(result.phase == WEBD_ADMIN_TXN_PHASE_DONE);
    assert(result.applied_steps == 3);
    assert(result.irreversible_attempted == 1);
    assert(settings.value == 2 && avatar.value == 20 && identity.value == 200);
    assert(!strcmp(order, "pppssaaaff"));
}

static void test_preflight_and_snapshot_fail_without_apply(void)
{
    struct fake_step first = {.name = "first", .value = 1, .target = 2};
    struct fake_step second = {.name = "second", .value = 3, .target = 4,
                               .preflight_fail = 1};
    struct webd_admin_txn_step steps[] = {
        reversible(&first), reversible(&second),
    };
    struct webd_admin_txn_result result;

    assert(webd_admin_txn_execute(steps, 2, &result) ==
           WEBD_ADMIN_TXN_PREFLIGHT_FAILED);
    assert(result.failed_step_index == 1);
    assert(!strcmp(result.error, "second_preflight"));
    assert(first.apply_calls == 0 && second.apply_calls == 0);

    second.preflight_fail = 0;
    second.snapshot_fail = 1;
    assert(webd_admin_txn_execute(steps, 2, &result) ==
           WEBD_ADMIN_TXN_SNAPSHOT_FAILED);
    assert(result.failed_step_index == 1);
    assert(first.apply_calls == 0 && second.apply_calls == 0);
}

static void test_partial_current_step_is_restored_in_reverse_order(void)
{
    char order[64] = "";
    struct fake_step first = {.name = "settings", .value = 1, .target = 2,
                              .order = order, .order_len = sizeof(order)};
    struct fake_step second = {.name = "avatar", .value = 10, .target = 20,
                               .apply_fail_after_write = 1, .order = order,
                               .order_len = sizeof(order)};
    struct fake_step identity = {.name = "identity_password", .value = 100,
                                 .target = 200, .order = order,
                                 .order_len = sizeof(order)};
    struct webd_admin_txn_step steps[] = {
        reversible(&first), reversible(&second), irreversible(&identity),
    };
    struct webd_admin_txn_result result;

    assert(webd_admin_txn_execute(steps, 3, &result) ==
           WEBD_ADMIN_TXN_APPLY_FAILED);
    assert(result.phase == WEBD_ADMIN_TXN_PHASE_APPLY);
    assert(result.failed_step_index == 1);
    assert(!strcmp(result.failed_step, "avatar"));
    assert(!strcmp(result.error, "avatar_apply_after_write"));
    assert(!strcmp(result.apply_failed_step, "avatar"));
    assert(!strcmp(result.apply_error, "avatar_apply_after_write"));
    assert(result.rollback_error[0] == '\0');
    assert(result.apply_attempted == 2 && result.applied_steps == 1);
    assert(result.rollback_attempted == 2 && result.rollback_failed == 0);
    assert(result.irreversible_attempted == 0);
    assert(first.value == 1 && second.value == 10 && identity.value == 100);
    assert(identity.apply_calls == 0);
    assert(!strcmp(order, "pppssaarrff"));
}

static void test_rollback_failure_is_truthful(void)
{
    struct fake_step first = {.name = "settings", .value = 1, .target = 2,
                              .restore_fail = 1};
    struct fake_step second = {.name = "avatar", .value = 10, .target = 20,
                               .apply_fail_after_write = 1};
    struct webd_admin_txn_step steps[] = {
        reversible(&first), reversible(&second),
    };
    struct webd_admin_txn_result result;

    assert(webd_admin_txn_execute(steps, 2, &result) ==
           WEBD_ADMIN_TXN_ROLLBACK_FAILED);
    assert(result.phase == WEBD_ADMIN_TXN_PHASE_ROLLBACK);
    assert(result.failed_step_index == 0);
    assert(!strcmp(result.failed_step, "settings"));
    assert(!strcmp(result.error, "settings_restore"));
    assert(!strcmp(result.apply_failed_step, "avatar"));
    assert(!strcmp(result.apply_error, "avatar_apply_after_write"));
    assert(!strcmp(result.rollback_failed_step, "settings"));
    assert(!strcmp(result.rollback_error, "settings_restore"));
    assert(result.rollback_attempted == 2 && result.rollback_failed == 1);
    assert(first.value == 2);
    assert(second.value == 10);
}

static void test_atomic_irreversible_failure_rolls_back_prior_steps(void)
{
    struct fake_step settings = {.name = "settings", .value = 1, .target = 2};
    struct fake_step identity = {.name = "identity_password", .value = 100,
                                 .target = 100,
                                 .apply_fail_after_write = 1};
    struct webd_admin_txn_step steps[] = {
        reversible(&settings), irreversible(&identity),
    };
    struct webd_admin_txn_result result;

    /* target==value models an internally atomic identity callback failure. */
    assert(webd_admin_txn_execute(steps, 2, &result) ==
           WEBD_ADMIN_TXN_APPLY_FAILED);
    assert(result.irreversible_attempted == 1);
    assert(result.apply_attempted == 2 && result.applied_steps == 1);
    assert(result.rollback_attempted == 1 && result.rollback_failed == 0);
    assert(!strcmp(result.apply_failed_step, "identity_password"));
    assert(settings.value == 1 && identity.value == 100);
}

static void test_irreversible_contract(void)
{
    struct fake_step password = {.name = "password", .value = 1, .target = 2};
    struct fake_step avatar = {.name = "avatar", .value = 3, .target = 4};
    struct webd_admin_txn_step not_last[] = {
        irreversible(&password), reversible(&avatar),
    };
    struct webd_admin_txn_step multiple[] = {
        irreversible(&password), irreversible(&password),
    };
    struct webd_admin_txn_result result;

    assert(webd_admin_txn_execute(not_last, 2, &result) ==
           WEBD_ADMIN_TXN_IRREVERSIBLE_ORDER);
    assert(webd_admin_txn_execute(multiple, 2, &result) ==
           WEBD_ADMIN_TXN_IRREVERSIBLE_ORDER);
    assert(password.apply_calls == 0 && avatar.apply_calls == 0);
}

int main(void)
{
    test_success_and_order();
    test_preflight_and_snapshot_fail_without_apply();
    test_partial_current_step_is_restored_in_reverse_order();
    test_rollback_failure_is_truthful();
    test_atomic_irreversible_failure_rolls_back_prior_steps();
    test_irreversible_contract();
    puts("webd_admin_transaction_runtime_ok");
    return 0;
}
