// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#ifndef WEBD_API_NOTIFYD_INTERNAL_H
#define WEBD_API_NOTIFYD_INTERNAL_H

/*
 * Borrowed from jmx_app_api.c (definitions stay there; ~23 other callers remain
 * for each). De-static'd so the preferences/me handler in api_notifyd.c can reuse
 * a single implementation of the session-identity resolvers.
 */
int webd_identity_is_user(const char *identity);
const char *webd_identity_username(const char *identity);

#endif /* WEBD_API_NOTIFYD_INTERNAL_H */
