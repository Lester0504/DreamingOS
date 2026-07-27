// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_TEST_ULOOP_H
#define DREAMINGWRT_TEST_ULOOP_H

struct uloop_timeout {
    void (*cb)(struct uloop_timeout *timeout);
};

int uloop_timeout_set(struct uloop_timeout *timeout, int milliseconds);
int uloop_timeout_cancel(struct uloop_timeout *timeout);

#endif
