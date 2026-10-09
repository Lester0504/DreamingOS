// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_API_APPEARANCE_INTERNAL_H
#define WEBD_API_APPEARANCE_INTERNAL_H

#include <sqlite3.h>

/* Shared configuration DB handle owned by the main webd TU (jmx_app_api.c). */
extern sqlite3 *g_config_db;

#endif /* WEBD_API_APPEARANCE_INTERNAL_H */
