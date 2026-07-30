// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_IDENTIFICATION_RUNTIME_H
#define DREAMINGWRT_IDENTIFICATION_RUNTIME_H

#include <stdint.h>

#ifndef JMX_IDENTITY_RUNTIME_STATE_PATH
#define JMX_IDENTITY_RUNTIME_STATE_PATH "/run/dreamingwrt/identityd-state.json"
#endif

#ifndef JMX_RECORD_ENABLE_PATH
#define JMX_RECORD_ENABLE_PATH "/proc/sys/dreamingwrt/jmx/record_enable"
#endif

struct jmx_identification_runtime {
    int kernel_readback_available;
    int kernel_record_enabled;
    int identityd_readback_available;
    int identityd_process_running;
    int identityd_state_fresh;
    int identityd_mode_matches;
    int collector_requested;
    int collector_ready;
    int collector_active;
    int traffic_dataplane_matches;
    int device_dataplane_matches;
    int applied;
    int listeners_ready;
    int64_t identityd_pid;
    int64_t updated_at;
    int64_t last_tick_at;
    int64_t tick_count;
    char runtime_mode[32];
    char reason[64];
};

int jmx_identification_runtime_probe(const char *configured_mode,
                                     int configured_record,
                                     struct jmx_identification_runtime *out);

#endif
