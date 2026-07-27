// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_HONEYPOTD_INTERNAL_H
#define DREAMINGWRT_HONEYPOTD_INTERNAL_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define HP_RUNTIME_PATH "/run/dreamingwrt/aegis/honeypot-runtime.json"
#define HP_AEGIS_UBUS_OBJECT "dreamingwrt.aegis"
#define HP_AEGIS_UBUS_METHOD "honeypot_event_ingest"

#define HP_MAX_LISTENERS 64
#define HP_MAX_SESSIONS 128
#define HP_MAX_PER_SOURCE_HARD 8
#define HP_MAX_SOURCE_RATES 256
#define HP_MAX_EVENTS 256
#define HP_CAPTURE_HARD_LIMIT 4096
#define HP_OUTPUT_LIMIT 4096
#define HP_EVENT_JSON_LIMIT 4096
#define HP_RUNTIME_FILE_LIMIT (256U * 1024U)
#define HP_UBUS_TIMEOUT_MS 250

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif
#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif
#ifndef IP_ORIGDSTADDR
#define IP_ORIGDSTADDR IP_RECVORIGDSTADDR
#endif

enum hp_transport {
    HP_TRANSPORT_TCP = 1,
    HP_TRANSPORT_UDP = 2,
};

enum hp_service {
    HP_SERVICE_SSH = 1,
    HP_SERVICE_TELNET,
    HP_SERVICE_HTTP,
    HP_SERVICE_FTP,
    HP_SERVICE_DNS,
};

struct hp_limits {
    unsigned int max_sessions;
    unsigned int max_per_source;
    unsigned int source_rate_per_minute;
    unsigned int idle_timeout_seconds;
    unsigned int session_timeout_seconds;
    unsigned int capture_limit;
};

struct hp_listener {
    int fd;
    enum hp_transport transport;
    enum hp_service service;
    struct sockaddr_storage bind_addr;
    socklen_t bind_len;
    char honeypot_id[64];
    char address[INET6_ADDRSTRLEN];
    char ifname[32];
    char profile[64];
    uint16_t listen_port;
    uint16_t external_port;
    uint8_t dns_rcode;
};

struct hp_runtime {
    bool enabled;
    char ingest_token[65];
    struct hp_limits limits;
    struct hp_listener listeners[HP_MAX_LISTENERS];
    size_t listener_count;
};

struct hp_session {
    bool active;
    int fd;
    size_t listener_index;
    uint64_t started_ms;
    uint64_t last_activity_ms;
    size_t captured;
    unsigned int protocol_state;
    bool close_after_write;
    char source_ip[INET6_ADDRSTRLEN];
    uint16_t source_port;
    unsigned char input[HP_CAPTURE_HARD_LIMIT + 1];
    size_t input_len;
    size_t parse_offset;
    unsigned char output[HP_OUTPUT_LIMIT];
    size_t output_len;
    size_t output_offset;
    char username[128];
};

struct hp_source_rate {
    bool used;
    char address[INET6_ADDRSTRLEN];
    uint64_t window_started_ms;
    unsigned int accepted;
    uint64_t last_seen_ms;
};

struct hp_event_queue {
    char items[HP_MAX_EVENTS][HP_EVENT_JSON_LIMIT];
    size_t head;
    size_t count;
    uint64_t dropped;
    uint64_t next_retry_ms;
    struct ubus_context *ubus;
};

struct hp_state {
    struct hp_runtime runtime;
    struct hp_session sessions[HP_MAX_SESSIONS];
    struct hp_source_rate source_rates[HP_MAX_SOURCE_RATES];
    struct hp_event_queue events;
    size_t active_sessions;
};

uint64_t hp_monotonic_ms(void);
uint64_t hp_realtime_ms(void);
const char *hp_service_name(enum hp_service service);

int hp_runtime_load(struct hp_runtime *runtime, const char *path);
void hp_runtime_close(struct hp_runtime *runtime);
int hp_runtime_open_listeners(struct hp_runtime *runtime);
ssize_t hp_runtime_mapping_for_original(const struct hp_runtime *runtime,
                                        size_t socket_index,
                                        const struct sockaddr_in *original);

void hp_protocol_on_accept(struct hp_state *state, struct hp_session *session);
void hp_protocol_on_data(struct hp_state *state, struct hp_session *session);
void hp_protocol_handle_dns(struct hp_state *state, size_t socket_index);
bool hp_session_queue(struct hp_session *session, const void *data, size_t len);

int hp_events_init(struct hp_event_queue *queue);
void hp_events_close(struct hp_event_queue *queue);
void hp_events_flush(struct hp_event_queue *queue, uint64_t now_ms);
void hp_emit_session_event(struct hp_state *state, const struct hp_session *session,
                           const char *stage, struct json_object *payload);
void hp_emit_datagram_event(struct hp_state *state, const struct hp_listener *listener,
                            const struct sockaddr_storage *source, socklen_t source_len,
                            const char *stage, struct json_object *payload);
bool hp_source_rate_allow(struct hp_state *state, const char *source_ip, uint64_t now_ms);
void hp_payload_add_password_digest(struct json_object *payload,
                                    const unsigned char *password, size_t length,
                                    bool present);

#endif
