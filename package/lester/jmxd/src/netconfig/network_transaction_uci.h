// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DWRT_NETWORK_TRANSACTION_UCI_H
#define DWRT_NETWORK_TRANSACTION_UCI_H

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <openssl/crypto.h>
#include <uci.h>

/* Use libuci's commit serializer, without publishing files or saving deltas.
 * A pre-existing saved delta belongs to another writer, not this transaction. */
static int nc_tx_prepare_package(struct uci_context *ctx, struct uci_package *pkg,
                                 struct json_object *files)
{
    char *bytes = NULL;
    size_t size = 0;
    FILE *stream;
    int rc;
    if (!pkg || !files || !uci_list_empty(&pkg->saved_delta)) return -1;
    stream = open_memstream(&bytes, &size);
    if (!stream) return -1;
    rc = uci_export(ctx, stream, pkg, false);
    if (fclose(stream) != 0) rc = -1;
    if (rc == UCI_OK && size <= INT_MAX)
        json_object_object_add(files, pkg->e.name, json_object_new_string_len(bytes, (int)size));
    else rc = -1;
    if (bytes) OPENSSL_cleanse(bytes, size);
    free(bytes);
    return rc == UCI_OK ? 0 : -1;
}

#endif
