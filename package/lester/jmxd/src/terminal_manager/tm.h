// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_TERMINAL_MANAGER_H
#define DREAMINGWRT_TERMINAL_MANAGER_H
#define _GNU_SOURCE
#include <json-c/json.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <sys/types.h>
#include <libssh2.h>
#include <libssh2_sftp.h>
#include "../ac/ac_secrets.h"

#define TM_SOCKET "/var/run/dreamingwrt-terminal-manager.sock"
#define TM_STORE "/etc/dreamingwrt/terminal-manager.db"
#define TM_SECRET_KEY "/etc/dreamingwrt/ac-secrets.key"
#define TM_MAX_SESSIONS 8
#define TM_MAX_TRANSFERS 8
#define TM_FRAME_MAX (128U * 1024U)
#define TM_CHUNK 32768
#ifndef TM_LEASE_SECONDS
#define TM_LEASE_SECONDS 120
#endif
#define TM_IDLE_SECONDS 1800
typedef struct json_object J;
extern sqlite3 *tm_db;
extern struct ac_secrets *tm_secrets;
extern pthread_mutex_t tm_store_lock;
extern char tm_spool[512];
const char *tm_str(J *, const char *, const char *);
int64_t tm_int(J *, const char *, int64_t);
int tm_bool(J *, const char *, int);
J *tm_get(J *, const char *);
J *tm_copy(J *);
J *tm_error(int *, int, const char *, const char *);
void tm_string(J *, const char *, const char *);
void tm_number(J *, const char *, int64_t);
void tm_boolean(J *, const char *, int);
void tm_uuid(char out[33]);
int64_t tm_now(void);
void tm_scrub(J *);
int tm_write_all(int, const void *, size_t);
int tm_read_all(int, void *, size_t);
int tm_send_json(int, J *);
J *tm_receive_json(int);
char *tm_base64(const void *, size_t);
unsigned char *tm_unbase64(const char *, size_t *);
int tm_store_open(const char *, const char *);
J *tm_store_route(const char *, const char *, const char *, J *, int *);
J *tm_store_host(const char *, const char *, int);
J *tm_defaults(void);
int tm_known_key(const char *, const char *, int, char [96]);
int tm_trust_key(const char *, const char *, int, const char *, const char *);
void tm_host_success(const char *, const char *);
const char *tm_validate_host(J *);

struct tm_session {
    pthread_mutex_t lock;
    char id[33], owner[128], workspace[96], state[48], reason[96];
    char fingerprint[96], old_fingerprint[96];
    J *host, *auth, *sample;
    int used, finished, stop, ws, stream, serial, trusted, readonly;
    int transfer_refs, cols, rows, exit_code, telnet_state, telnet_cmd;
    unsigned char wsbuf[TM_FRAME_MAX + 32];
    size_t wslen, fraglen;
    char fragment[TM_FRAME_MAX + 1];
    int fragop;
    int64_t created, ready, ended, lease, activity;
    pid_t child;
    char docker_exec[65];
    int docker_pidfd;
    int lxc_pidfd;
    LIBSSH2_SESSION *ssh;
    LIBSSH2_CHANNEL *channel;
    LIBSSH2_SFTP *sftp;
    char cwd[4096], cwd_source[32];
};
extern struct tm_session tm_sessions[TM_MAX_SESSIONS];
extern pthread_mutex_t tm_sessions_lock;
J *tm_sessions_route(const char *, const char *, const char *, J *, int, int, int *);
J *tm_session_json(struct tm_session *);
J *tm_capabilities(int);
J *tm_serial_ports(void);
struct tm_session *tm_find_session(const char *, const char *);
void tm_state(struct tm_session *, const char *, const char *);
int tm_ws_send(struct tm_session *, int, const void *, size_t);
int tm_connect_ssh(struct tm_session *);
int tm_engine_open(struct tm_session *);
int tm_engine_read(struct tm_session *);
int tm_engine_input(struct tm_session *, const char *, size_t);
void tm_engine_resize(struct tm_session *, int, int);
void tm_engine_close(struct tm_session *);
const char *tm_lxc_validate(J *);
J *tm_lxc_capabilities(int);
int tm_lxc_open(struct tm_session *);
void tm_lxc_close(struct tm_session *);
const char *tm_docker_validate(J *);
J *tm_docker_capabilities(int);
int tm_docker_open(struct tm_session *);
void tm_docker_resize(struct tm_session *, int, int);
void tm_docker_close(struct tm_session *);
J *tm_files_route(struct tm_session *, const char *, J *, int *);
int tm_path_valid(const char *);
J *tm_telemetry(struct tm_session *, const char *, int *);
J *tm_transfers_route(const char *, const char *, const char *, J *, int, int *);
int tm_transfers_init(void);
void tm_sessions_init(void);
#endif
