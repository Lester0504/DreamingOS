// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_STORAGE_BINDING_H
#define DREAMINGWRT_STORAGE_BINDING_H

#include <stddef.h>

/* Overridable only so host tests can run the real code under a scratch dir. */
#ifndef JMX_STORAGE_PARENT_DIR
#define JMX_STORAGE_PARENT_DIR "/etc/dreamingwrt"
#endif
#define JMX_STORAGE_DIR JMX_STORAGE_PARENT_DIR "/storage"
#define JMX_STORAGE_ASSIGNMENTS_PATH JMX_STORAGE_DIR "/assignments.json"
#define JMX_STORAGE_BINDING_VERSION 1

/* Read the persisted binding for one use. Empty active_path means local default. */
int jmx_storage_binding_read(const char *use, char *provider_id, size_t provider_len,
                             char *active_path, size_t path_len,
                             char *state, size_t state_len,
                             char *reason, size_t reason_len);

/* Atomically update one use while preserving the other assignments. */
int jmx_storage_binding_write(const char *use, const char *provider_id,
                              const char *active_path, const char *state,
                              const char *reason, int rollback_available);

/* Commit only if the assignment still matches the boot-time snapshot. */
int jmx_storage_binding_commit(const char *use, const char *expected_provider,
                               const char *expected_path, const char *provider_id,
                               const char *active_path, const char *state,
                               const char *reason, int rollback_available);

const char *jmx_storage_binding_default_path(const char *use);
const char *jmx_storage_binding_use(size_t index);

/* Startup gate for a persisted external assignment. */
int jmx_storage_binding_path_ready(const char *path, int expect_dir);

#endif
