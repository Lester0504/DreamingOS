// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_OTAD_INVENTORY_TRANSACTION_H
#define DREAMINGWRT_OTAD_INVENTORY_TRANSACTION_H

#include <stddef.h>
#include <sqlite3.h>

typedef int (*otad_inventory_transaction_work)(void *opaque);

int otad_inventory_run_transaction(sqlite3 *db,
                                   otad_inventory_transaction_work work,
                                   void *opaque, int *inventory_unchanged,
                                   char *error, size_t error_len);

#endif
