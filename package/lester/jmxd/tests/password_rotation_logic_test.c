// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit test for the password rotation expiry decision.
 *
 * webd_password_change_required() is static and reads sqlite, so its decision
 * core is reproduced here and exercised against real timestamps. The boundaries
 * are what matter: an unknown last-change time must not expire a password, and
 * an administrator-forced flag must expire it regardless of age.
 *
 * Build and run:
 *   cc -std=c11 -Wall -Wextra -o /tmp/prtl tests/password_rotation_logic_test.c && /tmp/prtl
 */
#include <stdint.h>
#include <stdio.h>

#define DAY 86400

/* Mirrors the decision inside webd_password_change_required(). */
static int change_required(int rotate_days, int64_t changed_at, int must_change,
                           int64_t now, int64_t *expires_at)
{
    if (expires_at)
        *expires_at = 0;
    if (must_change)
        return 1;
    if (rotate_days > 0 && changed_at > 0) {
        int64_t due = changed_at + (int64_t)rotate_days * DAY;

        if (expires_at)
            *expires_at = due;
        return now >= due;
    }
    return 0;
}

static int failures;

static void check(const char *name, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: got %d want %d\n", name, got, want);
        failures++;
    } else {
        printf("PASS %s\n", name);
    }
}

static void check_i64(const char *name, int64_t got, int64_t want)
{
    if (got != want) {
        printf("FAIL %s: got %lld want %lld\n", name, (long long)got, (long long)want);
        failures++;
    } else {
        printf("PASS %s\n", name);
    }
}

int main(void)
{
    const int64_t now = 1000 * DAY;
    int64_t due = -1;

    /* Policy off: no window, never expires however old the password is. */
    check("no_window_never_expires",
          change_required(0, now - 900 * DAY, 0, now, NULL), 0);

    /*
     * The upgrade case. Every pre-existing account has changed_at == 0, which
     * means "unknown", not "infinitely old". Reading it as expired would demand
     * a password change from every user at their first login after the column
     * appeared.
     */
    check("unknown_change_time_does_not_expire",
          change_required(90, 0, 0, now, NULL), 0);

    /* Inside the window. */
    check("fresh_password_within_window",
          change_required(90, now - 89 * DAY, 0, now, NULL), 0);

    /* Exactly at the boundary counts as due: the comparison is >=. */
    check("expires_exactly_on_the_boundary",
          change_required(90, now - 90 * DAY, 0, now, NULL), 1);
    check("expired_past_the_boundary",
          change_required(90, now - 91 * DAY, 0, now, NULL), 1);

    /* Administrator demand short-circuits the age test entirely. */
    check("must_change_expires_a_fresh_password",
          change_required(90, now, 1, now, NULL), 1);
    check("must_change_without_any_window",
          change_required(0, now, 1, now, NULL), 1);

    /* A one-day window still behaves, and reports its due date. */
    check("one_day_window_not_yet_due",
          change_required(1, now - DAY / 2, 0, now, NULL), 0);
    check("one_day_window_due",
          change_required(1, now - DAY, 0, now, NULL), 1);

    /* The reported expiry is the value the UI shows; it must be derived, not 0. */
    (void)change_required(30, now - 10 * DAY, 0, now, &due);
    check_i64("expiry_reported_for_active_window", due, now + 20 * DAY);

    /* With no computable window the expiry must stay 0 rather than a guess. */
    (void)change_required(0, now, 0, now, &due);
    check_i64("expiry_zero_when_policy_off", due, 0);
    (void)change_required(30, 0, 0, now, &due);
    check_i64("expiry_zero_when_change_time_unknown", due, 0);

    printf("\n%s\n", failures ? "FAILURES PRESENT" : "all rotation logic checks passed");
    return failures ? 1 : 0;
}
