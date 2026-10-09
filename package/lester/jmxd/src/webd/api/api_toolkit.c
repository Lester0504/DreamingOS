// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com> */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "api_error.h"
#include "api_json.h"
#include "api_request.h"
#include "api_toolkit.h"
#include "api_ubus.h"

struct json_object *webd_toolkit_exec(const char *command,
                                      struct json_object *params,
                                      const char *actor,
                                      int timeout_ms,
                                      int *http_status)
{
#ifdef WEBD_TOOLKIT_BINARY
    const char *binary = WEBD_TOOLKIT_BINARY;
#else
    const char *binary = "/usr/bin/dreamingwrt-toolkit";
#endif
    int input_pipe[2] = {-1, -1}, output_pipe[2] = {-1, -1};
    pid_t pid;
    char *request = NULL, *output = NULL;
    size_t request_len, request_off = 0, output_len = 0, output_cap = 16384;
    int status = 0, elapsed = 0, child_done = 0;
    struct json_object *body = params ? json_object_get(params) : json_object_new_object();
    struct json_object *resp = NULL;

    if (!command || !command[0] || access(binary, X_OK) != 0) {
        if (body) json_object_put(body);
        if (http_status) *http_status = 501;
        return webd_error("toolkit_unavailable", "dreamingwrt-toolkit is not installed",
                          binary, "webd.toolkit");
    }
    json_object_object_del(body, "actor");
    json_object_object_add(body, "actor", json_object_new_string(actor ? actor : ""));
    request = strdup(json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN));
    json_object_put(body);
    if (!request || pipe(input_pipe) != 0 || pipe(output_pipe) != 0) goto failed;
    request_len = strlen(request);
    pid = fork();
    if (pid < 0) goto failed;
    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        dup2(input_pipe[0], STDIN_FILENO);
        dup2(output_pipe[1], STDOUT_FILENO);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        close(input_pipe[0]); close(input_pipe[1]);
        close(output_pipe[0]); close(output_pipe[1]);
        execl(binary, binary, command, (char *)NULL);
        _exit(127);
    }
    close(input_pipe[0]); input_pipe[0] = -1;
    close(output_pipe[1]); output_pipe[1] = -1;
    fcntl(input_pipe[1], F_SETFL, fcntl(input_pipe[1], F_GETFL, 0) | O_NONBLOCK);
    fcntl(output_pipe[0], F_SETFL, fcntl(output_pipe[0], F_GETFL, 0) | O_NONBLOCK);
    output = malloc(output_cap);
    if (!output) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); goto failed; }
    while (!child_done || output_pipe[0] >= 0) {
        if (input_pipe[1] >= 0) {
            ssize_t wrote = write(input_pipe[1], request + request_off, request_len - request_off);
            if (wrote > 0) request_off += (size_t)wrote;
            if (request_off == request_len || (wrote < 0 && errno != EAGAIN && errno != EINTR)) {
                close(input_pipe[1]); input_pipe[1] = -1;
            }
        }
        if (output_pipe[0] >= 0) {
            char chunk[4096];
            ssize_t got = read(output_pipe[0], chunk, sizeof(chunk));
            if (got > 0) {
                if (output_len + (size_t)got + 1 > 2 * 1024 * 1024) {
                    kill(pid, SIGKILL); waitpid(pid, NULL, 0); child_done = 1;
                    close(output_pipe[0]); output_pipe[0] = -1;
                    break;
                }
                if (output_len + (size_t)got + 1 > output_cap) {
                    size_t next_cap = output_cap * 2;
                    char *next;
                    while (next_cap < output_len + (size_t)got + 1) next_cap *= 2;
                    next = realloc(output, next_cap);
                    if (!next) { kill(pid, SIGKILL); waitpid(pid, NULL, 0); child_done = 1; break; }
                    output = next; output_cap = next_cap;
                }
                memcpy(output + output_len, chunk, (size_t)got); output_len += (size_t)got;
            } else if (got == 0) { close(output_pipe[0]); output_pipe[0] = -1; }
        }
        if (!child_done && waitpid(pid, &status, WNOHANG) == pid) child_done = 1;
        if (!child_done && elapsed >= timeout_ms) {
            kill(pid, SIGTERM); usleep(100000); kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            child_done = 1;
        }
        if ((!child_done || output_pipe[0] >= 0) && elapsed < timeout_ms + 1000) {
            usleep(10000); elapsed += 10;
        } else if (child_done && output_pipe[0] < 0) break;
    }
    if (input_pipe[1] >= 0) close(input_pipe[1]);
    if (output_pipe[0] >= 0) close(output_pipe[0]);
    output[output_len] = 0;
    resp = output_len ? json_tokener_parse(output) : NULL;
    free(output); free(request);
    if (!resp || !json_object_is_type(resp, json_type_object)) {
        if (resp) json_object_put(resp);
        if (http_status) *http_status = elapsed >= timeout_ms ? 504 : 502;
        return webd_error(elapsed >= timeout_ms ? "toolkit_timeout" : "toolkit_invalid_response",
                          elapsed >= timeout_ms ? "Toolkit command timed out" : "Toolkit returned invalid JSON",
                          command, "webd.toolkit");
    }
    if (http_status) {
        const char *error = app_nc_json_str(resp, "error", "");
        if (app_nc_json_bool(resp, "ok", 0)) *http_status = 200;
        else if (!strcmp(error, "capability_unavailable") ||
                 !strcmp(error, "provider_not_implemented")) *http_status = 501;
        else if (strstr(error, "not_found")) *http_status = 404;
        else if (strstr(error, "unavailable")) *http_status = 503;
        else *http_status = 400;
    }
    return resp;
failed:
    if (input_pipe[0] >= 0) close(input_pipe[0]);
    if (input_pipe[1] >= 0) close(input_pipe[1]);
    if (output_pipe[0] >= 0) close(output_pipe[0]);
    if (output_pipe[1] >= 0) close(output_pipe[1]);
    free(request); free(output);
    if (http_status) *http_status = 500;
    return webd_error("toolkit_exec_failed", "Could not start toolkit command",
                      command ? command : "", "webd.toolkit");
}

static struct json_object *toolkit_status(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("status", ctx->body, ctx->device_id, 3000, &ctx->status);
}

static struct json_object *toolkit_router_check(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("router-check", ctx->body, ctx->device_id, 5000, &ctx->status);
}

static struct json_object *toolkit_port_mirror_list(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("port-mirror-list", ctx->body, ctx->device_id, 3000, &ctx->status);
}

static struct json_object *toolkit_port_mirror_set(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("port-mirror-set", ctx->body, ctx->device_id, 7000, &ctx->status);
}

static struct json_object *toolkit_port_mirror_delete(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("port-mirror-delete", ctx->body, ctx->device_id, 5000, &ctx->status);
}

static struct json_object *toolkit_ddns_list(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("ddns-list", ctx->body, ctx->device_id, 3000, &ctx->status);
}

static struct json_object *toolkit_ddns_set(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("ddns-set", ctx->body, ctx->device_id, 4000, &ctx->status);
}

static struct json_object *toolkit_ddns_update(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("ddns-update", ctx->body, ctx->device_id, 25000, &ctx->status);
}

static struct json_object *toolkit_ddns_delete(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("ddns-delete", ctx->body, ctx->device_id, 4000, &ctx->status);
}

static struct json_object *toolkit_wake_on_lan(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("wake-on-lan", ctx->body, ctx->device_id, 3000, &ctx->status);
}

static struct json_object *toolkit_throughput_start(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("throughput-start", ctx->body, ctx->device_id, 4000, &ctx->status);
}

static struct json_object *toolkit_throughput_status(struct jmx_api_ctx *ctx)
{
    char id[96] = "";
    struct json_object *params = json_object_new_object();
    struct json_object *resp;

    webd_query_get(ctx->req->query, "id", id, sizeof(id));
    json_object_object_add(params, "id", json_object_new_string(id));
    resp = webd_toolkit_exec("throughput-status", params, ctx->device_id, 3000,
                             &ctx->status);
    json_object_put(params);
    return resp;
}

static struct json_object *toolkit_throughput_stop(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("throughput-stop", ctx->body, ctx->device_id, 3000, &ctx->status);
}

static struct json_object *diagnostics_ping(struct jmx_api_ctx *ctx)
{
    return app_ubus_route_or_error("dreamingwrt", "ping", ctx->body, 4000,
                                   &ctx->status);
}

static struct json_object *diagnostics_traceroute(struct jmx_api_ctx *ctx)
{
    return app_ubus_route_or_error("dreamingwrt", "traceroute", ctx->body, 30000,
                                   &ctx->status);
}

static struct json_object *diagnostics_nslookup(struct jmx_api_ctx *ctx)
{
    return app_ubus_route_or_error("dreamingwrt", "nslookup", ctx->body, 10000,
                                   &ctx->status);
}

static struct json_object *diagnostics_speedtest(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("speedtest-start", ctx->body, ctx->device_id, 5000,
                             &ctx->status);
}

static struct json_object *diagnostics_speedtest_status(struct jmx_api_ctx *ctx)
{
    char id[96] = "";
    struct json_object *params = json_object_new_object();
    struct json_object *resp;

    webd_query_get(ctx->req->query, "id", id, sizeof(id));
    json_object_object_add(params, "id", json_object_new_string(id));
    resp = webd_toolkit_exec("speedtest-status", params, ctx->device_id, 3000,
                             &ctx->status);
    json_object_put(params);
    return resp;
}

static struct json_object *diagnostics_speedtest_stop(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("speedtest-stop", ctx->body, ctx->device_id, 3000,
                             &ctx->status);
}

/* --- RoceOS-parity network diagnostics (toolkit_net.c) --- */

static struct json_object *diagnostics_port_scan(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("port-scan", ctx->body, ctx->device_id, 60000, &ctx->status);
}

static struct json_object *diagnostics_port_check(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("port-check", ctx->body, ctx->device_id, 15000, &ctx->status);
}

static struct json_object *diagnostics_tcp_udp_test(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("tcp-udp-test", ctx->body, ctx->device_id, 12000, &ctx->status);
}

static struct json_object *diagnostics_ssl_check(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("ssl-check", ctx->body, ctx->device_id, 15000, &ctx->status);
}

static struct json_object *diagnostics_http_request(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("http-request", ctx->body, ctx->device_id, 130000, &ctx->status);
}

static struct json_object *diagnostics_headers(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("headers", ctx->body, ctx->device_id, 60000, &ctx->status);
}

static struct json_object *diagnostics_website_check(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("website-check", ctx->body, ctx->device_id, 120000, &ctx->status);
}

static struct json_object *diagnostics_local_ports(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("local-ports", ctx->body, ctx->device_id, 5000, &ctx->status);
}

static struct json_object *diagnostics_local_info(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("local-info", ctx->body, ctx->device_id, 6000, &ctx->status);
}

static struct json_object *diagnostics_arp_scan(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("arp-scan", ctx->body, ctx->device_id, 12000, &ctx->status);
}

static struct json_object *diagnostics_mtu_detect(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("mtu-detect", ctx->body, ctx->device_id, 45000, &ctx->status);
}

static struct json_object *diagnostics_latency_monitor(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("latency-monitor", ctx->body, ctx->device_id, 200000, &ctx->status);
}

static struct json_object *diagnostics_whois(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("whois", ctx->body, ctx->device_id, 30000, &ctx->status);
}

static struct json_object *diagnostics_dns_query(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("dns-query", ctx->body, ctx->device_id, 20000, &ctx->status);
}

static struct json_object *diagnostics_public_ip(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("public-ip", ctx->body, ctx->device_id, 20000, &ctx->status);
}

static struct json_object *diagnostics_ip_geo(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("ip-geo", ctx->body, ctx->device_id, 20000, &ctx->status);
}

static struct json_object *diagnostics_mac_lookup(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("mac-lookup", ctx->body, ctx->device_id, 20000, &ctx->status);
}

static struct json_object *diagnostics_mdns(struct jmx_api_ctx *ctx)
{
    return webd_toolkit_exec("mdns", ctx->body, ctx->device_id, 20000, &ctx->status);
}

const struct jmx_api_route toolkit_api_routes[] = {
    JMX_API_ROUTE(596, "/api/v1/toolkit", "GET", JMX_API_EXACT, toolkit_status),
    JMX_API_ROUTE(597, "/api/v1/toolkit/router-check", "GET,POST", JMX_API_EXACT, toolkit_router_check),
    JMX_API_ROUTE(598, "/api/v1/toolkit/port-mirror", "GET", JMX_API_EXACT, toolkit_port_mirror_list),
    JMX_API_ROUTE(599, "/api/v1/toolkit/port-mirror", "POST,PUT", JMX_API_EXACT, toolkit_port_mirror_set),
    JMX_API_ROUTE(600, "/api/v1/toolkit/port-mirror", "DELETE", JMX_API_EXACT, toolkit_port_mirror_delete),
    JMX_API_ROUTE(602, "/api/v1/toolkit/ddns", "GET", JMX_API_EXACT, toolkit_ddns_list),
    JMX_API_ROUTE(603, "/api/v1/toolkit/ddns", "POST,PUT", JMX_API_EXACT, toolkit_ddns_set),
    JMX_API_ROUTE(604, "/api/v1/toolkit/ddns", "DELETE", JMX_API_EXACT, toolkit_ddns_delete),
    JMX_API_ROUTE(605, "/api/v1/toolkit/ddns/update", "POST", JMX_API_EXACT, toolkit_ddns_update),
    JMX_API_ROUTE(606, "/api/v1/toolkit/wake-on-lan", "POST", JMX_API_EXACT, toolkit_wake_on_lan),
    JMX_API_ROUTE(607, "/api/v1/toolkit/throughput", "POST", JMX_API_EXACT, toolkit_throughput_start),
    JMX_API_ROUTE(608, "/api/v1/toolkit/throughput/status", "GET", JMX_API_EXACT, toolkit_throughput_status),
    JMX_API_ROUTE(609, "/api/v1/toolkit/throughput/stop", "POST", JMX_API_EXACT, toolkit_throughput_stop),
    JMX_API_ROUTE(610, "/api/v1/diagnostics/ping", "POST,PUT", JMX_API_EXACT, diagnostics_ping),
    JMX_API_ROUTE(611, "/api/v1/diagnostics/traceroute", "POST,PUT", JMX_API_EXACT, diagnostics_traceroute),
    JMX_API_ROUTE(612, "/api/v1/diagnostics/nslookup", "POST,PUT", JMX_API_EXACT, diagnostics_nslookup),
    JMX_API_ROUTE(613, "/api/v1/diagnostics/speedtest", "POST,PUT", JMX_API_EXACT, diagnostics_speedtest),
    JMX_API_ROUTE(960, "/api/v1/diagnostics/port-scan", "POST,PUT", JMX_API_EXACT, diagnostics_port_scan),
    JMX_API_ROUTE(961, "/api/v1/diagnostics/port-check", "POST,PUT", JMX_API_EXACT, diagnostics_port_check),
    JMX_API_ROUTE(962, "/api/v1/diagnostics/tcp-udp-test", "POST,PUT", JMX_API_EXACT, diagnostics_tcp_udp_test),
    JMX_API_ROUTE(963, "/api/v1/diagnostics/ssl-check", "POST,PUT", JMX_API_EXACT, diagnostics_ssl_check),
    JMX_API_ROUTE(964, "/api/v1/diagnostics/http-request", "POST,PUT", JMX_API_EXACT, diagnostics_http_request),
    JMX_API_ROUTE(965, "/api/v1/diagnostics/headers", "POST,PUT", JMX_API_EXACT, diagnostics_headers),
    JMX_API_ROUTE(966, "/api/v1/diagnostics/website-check", "POST,PUT", JMX_API_EXACT, diagnostics_website_check),
    JMX_API_ROUTE(967, "/api/v1/diagnostics/local-ports", "GET", JMX_API_EXACT, diagnostics_local_ports),
    JMX_API_ROUTE(968, "/api/v1/diagnostics/local-info", "GET", JMX_API_EXACT, diagnostics_local_info),
    JMX_API_ROUTE(969, "/api/v1/diagnostics/arp-scan", "POST,PUT", JMX_API_EXACT, diagnostics_arp_scan),
    JMX_API_ROUTE(970, "/api/v1/diagnostics/mtu-detect", "POST,PUT", JMX_API_EXACT, diagnostics_mtu_detect),
    JMX_API_ROUTE(971, "/api/v1/diagnostics/latency-monitor", "POST,PUT", JMX_API_EXACT, diagnostics_latency_monitor),
    JMX_API_ROUTE(972, "/api/v1/diagnostics/whois", "POST,PUT", JMX_API_EXACT, diagnostics_whois),
    JMX_API_ROUTE(973, "/api/v1/diagnostics/dns-query", "POST,PUT", JMX_API_EXACT, diagnostics_dns_query),
    JMX_API_ROUTE(974, "/api/v1/diagnostics/public-ip", "GET", JMX_API_EXACT, diagnostics_public_ip),
    JMX_API_ROUTE(975, "/api/v1/diagnostics/ip-geo", "POST,PUT", JMX_API_EXACT, diagnostics_ip_geo),
    JMX_API_ROUTE(976, "/api/v1/diagnostics/mac-lookup", "POST,PUT", JMX_API_EXACT, diagnostics_mac_lookup),
    JMX_API_ROUTE(977, "/api/v1/diagnostics/speedtest/status", "GET", JMX_API_EXACT, diagnostics_speedtest_status),
    JMX_API_ROUTE(978, "/api/v1/diagnostics/speedtest/stop", "POST", JMX_API_EXACT, diagnostics_speedtest_stop),
    JMX_API_ROUTE(981, "/api/v1/diagnostics/mdns", "POST,PUT", JMX_API_EXACT, diagnostics_mdns),
    JMX_API_ROUTE_END,
};
