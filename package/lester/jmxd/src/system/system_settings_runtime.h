// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_SYSTEM_SETTINGS_RUNTIME_H
#define DREAMINGWRT_SYSTEM_SETTINGS_RUNTIME_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define SSR_ERROR_MAX 96U
#define SSR_FIELD_MAX 48U
#define SSR_TIME_SERVERS_MAX 8U
#define SSR_SERVER_MAX 254U
#define SSR_PATH_MAX 512U
#define SSR_OUTPUT_MAX 4096U
#define SSR_RESULT_FIELDS_MAX 12U

struct ssr_paths {
    const char *system_config;
    const char *root_crontab;
    const char *zoneinfo_dir;
    const char *meminfo;
    const char *proc_swaps;
    const char *zram_sysfs;
    const char *zram_device;
    const char *uci;
    const char *init_system;
    const char *init_sysntpd;
    const char *init_log;
    const char *init_cron;
    const char *busybox;
    const char *ntpd;
};

typedef int (*ssr_command_fn)(void *opaque, const char *const argv[],
                              const char *input, char *output,
                              size_t output_len);

struct ssr_executor {
    ssr_command_fn command;
    void *opaque;
};

struct ssr_field_result {
    char field[SSR_FIELD_MAX];
    int persisted;
    int applied;
    int running;
    int rollback;
    char error[SSR_ERROR_MAX];
};

struct ssr_result {
    int ok;
    int rollback_attempted;
    int rollback_ok;
    int reboot_required;
    char stage[24];
    char error[SSR_ERROR_MAX];
    size_t field_count;
    struct ssr_field_result fields[SSR_RESULT_FIELDS_MAX];
};

struct ssr_probe {
    int available;
    int persistent;
    int apply_supported;
    int readback_supported;
    int rollback_supported;
    char reason[SSR_ERROR_MAX];
};

struct ssr_time_settings {
    char timezone[64];
    int client_enabled;
    int server_enabled;
    int use_dhcp;
    char interval[8];
    size_t server_count;
    char servers[SSR_TIME_SERVERS_MAX][SSR_SERVER_MAX + 1U];
};

struct ssr_time_state {
    struct ssr_time_settings settings;
    int service_running;
    int cron_service_running;
    int cron_managed;
};

struct ssr_log_settings {
    char local_level[16];
    char kernel_level[16];
    char cron_level[16];
    unsigned int buffer_kib;
    int remote_enabled;
    char remote_host[SSR_SERVER_MAX + 1U];
    unsigned int remote_port;
    char remote_protocol[4];
    char file_path[SSR_PATH_MAX];
};

struct ssr_log_state {
    struct ssr_log_settings settings;
    int log_service_running;
    int cron_service_running;
};

struct ssr_zram_settings {
    uint64_t size_mib;
    char algorithm[32];
};

struct ssr_zram_state {
    struct ssr_zram_settings settings;
    int active;
    int priority;
};

struct ssr_file_snapshot {
    char *data;
    size_t length;
    mode_t mode;
    int existed;
};

struct ssr_time_snapshot {
    struct ssr_file_snapshot system_config;
    struct ssr_file_snapshot root_crontab;
    struct ssr_time_state state;
    int valid;
};

struct ssr_log_snapshot {
    struct ssr_file_snapshot system_config;
    struct ssr_log_state state;
    int valid;
};

struct ssr_zram_snapshot {
    struct ssr_file_snapshot system_config;
    struct ssr_zram_state state;
    int valid;
};

void ssr_paths_default(struct ssr_paths *paths);
void ssr_result_reset(struct ssr_result *result);

int ssr_time_probe(const struct ssr_paths *paths, struct ssr_probe *probe);
int ssr_time_validate(const struct ssr_paths *paths,
                      const struct ssr_time_settings *settings,
                      char *error, size_t error_len);
int ssr_time_readback(const struct ssr_paths *paths,
                      const struct ssr_executor *executor,
                      struct ssr_time_state *state,
                      char *error, size_t error_len);
int ssr_time_snapshot_capture(const struct ssr_paths *paths,
                              const struct ssr_executor *executor,
                              struct ssr_time_snapshot *snapshot,
                              char *error, size_t error_len);
int ssr_time_apply(const struct ssr_paths *paths,
                   const struct ssr_executor *executor,
                   const struct ssr_time_settings *settings,
                   struct ssr_result *result);
int ssr_time_rollback(const struct ssr_paths *paths,
                      const struct ssr_executor *executor,
                      const struct ssr_time_snapshot *snapshot,
                      struct ssr_result *result);
void ssr_time_snapshot_clear(struct ssr_time_snapshot *snapshot);

int ssr_log_probe(const struct ssr_paths *paths, struct ssr_probe *probe);
int ssr_log_validate(const struct ssr_paths *paths,
                     const struct ssr_log_settings *settings,
                     char *error, size_t error_len);
int ssr_log_readback(const struct ssr_paths *paths,
                     const struct ssr_executor *executor,
                     struct ssr_log_state *state,
                     char *error, size_t error_len);
int ssr_log_snapshot_capture(const struct ssr_paths *paths,
                             const struct ssr_executor *executor,
                             struct ssr_log_snapshot *snapshot,
                             char *error, size_t error_len);
int ssr_log_apply(const struct ssr_paths *paths,
                  const struct ssr_executor *executor,
                  const struct ssr_log_settings *settings,
                  struct ssr_result *result);
int ssr_log_rollback(const struct ssr_paths *paths,
                     const struct ssr_executor *executor,
                     const struct ssr_log_snapshot *snapshot,
                     struct ssr_result *result);
void ssr_log_snapshot_clear(struct ssr_log_snapshot *snapshot);

int ssr_zram_probe(const struct ssr_paths *paths, struct ssr_probe *probe);
int ssr_zram_validate(const struct ssr_paths *paths,
                      const struct ssr_zram_settings *settings,
                      char *error, size_t error_len);
int ssr_zram_readback(const struct ssr_paths *paths,
                      const struct ssr_executor *executor,
                      struct ssr_zram_state *state,
                      char *error, size_t error_len);
int ssr_zram_snapshot_capture(const struct ssr_paths *paths,
                              const struct ssr_executor *executor,
                              struct ssr_zram_snapshot *snapshot,
                              char *error, size_t error_len);
int ssr_zram_apply(const struct ssr_paths *paths,
                   const struct ssr_executor *executor,
                   const struct ssr_zram_settings *settings,
                   struct ssr_result *result);
int ssr_zram_rollback(const struct ssr_paths *paths,
                      const struct ssr_executor *executor,
                      const struct ssr_zram_snapshot *snapshot,
                      struct ssr_result *result);
void ssr_zram_snapshot_clear(struct ssr_zram_snapshot *snapshot);

#endif
