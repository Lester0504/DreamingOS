/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Atomic bootstrap file writer shared by apdctl and apd BLE commit.
 *
 * Both callers build their own JSON (apdctl from paircode, BLE from the
 * staged request) and pass it here for the tmp + fsync + rename that
 * must be identical everywhere a bootstrap is written.
 */
#ifndef DREAMINGWRT_APD_BOOTSTRAP_WRITE_H
#define DREAMINGWRT_APD_BOOTSTRAP_WRITE_H

#include <stddef.h>

struct json_object;

/* Write root as a JSON file at the given path using tmp + fsync + rename.
 * The parent directory is created if missing. root is not consumed. */
int apd_bootstrap_write_json(struct json_object *root, const char *path);

/* The same primitive for secret bytes such as the controller CA. */
int apd_bootstrap_write_bytes(const void *data, size_t length,
                              const char *path);

#define APD_BOOTSTRAP_PKI_DIR   "/etc/dreamingwrt/apd-pki"
#define APD_BOOTSTRAP_FILE      "bootstrap.json"
#define APD_BOOTSTRAP_PATH      APD_BOOTSTRAP_PKI_DIR "/" APD_BOOTSTRAP_FILE
#define APD_BOOTSTRAP_CA_PATH   APD_BOOTSTRAP_PKI_DIR "/controller-ca.pem"

#endif /* DREAMINGWRT_APD_BOOTSTRAP_WRITE_H */
