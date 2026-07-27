// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef WEBD_INIT_CONTROL_H
#define WEBD_INIT_CONTROL_H

#include <stddef.h>

#define WEBD_INIT_CONTROL_SOCKET "/var/run/dreamingwrt-init.sock"

/*
 * Send one allow-listed config-restore action to dreamingwrt-init. The caller
 * owns the malloc-allocated JSON response and must free it.
 */
int webd_init_config_restore_request_at(const char *socket_path,
                                        const char *action,
                                        char **response,
                                        size_t *response_len,
                                        char *err,
                                        size_t err_len);

int webd_init_config_restore_request(const char *action,
                                     char **response,
                                     size_t *response_len,
                                     char *err,
                                     size_t err_len);

#endif
