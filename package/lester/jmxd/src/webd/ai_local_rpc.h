// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __DREAMINGWRT_WEBD_AI_LOCAL_RPC_H__
#define __DREAMINGWRT_WEBD_AI_LOCAL_RPC_H__

#include <sys/types.h>

struct webd_ai_local_rpc_hooks {
    void (*worker_prepare)(void);
    int (*worker_track)(pid_t pid);
};

int webd_ai_local_rpc_init(const struct webd_ai_local_rpc_hooks *hooks);
void webd_ai_local_rpc_done(void);

#endif
