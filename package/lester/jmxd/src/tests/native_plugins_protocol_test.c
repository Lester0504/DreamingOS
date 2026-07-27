// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../webd/native_plugins.c"

static int sent_status;
static size_t sent_body_len;
static char sent_body[256];

int http_send_raw(int fd, int status, const char *content_type,
                  const void *body, size_t body_len,
                  const char *cache_control)
{
    (void)fd;
    (void)content_type;
    (void)cache_control;
    assert(body_len < sizeof(sent_body));
    sent_status = status;
    sent_body_len = body_len;
    memcpy(sent_body, body, body_len);
    sent_body[body_len] = '\0';
    return 0;
}

static int relay(const char *method, const char *wire)
{
    char response[1024];
    size_t len = strlen(wire);

    assert(len < sizeof(response));
    memcpy(response, wire, len + 1);
    sent_status = 0;
    sent_body_len = 0;
    sent_body[0] = '\0';
    return relay_response(-1, method, response, len);
}

int main(void)
{
    assert(relay("GET",
        "HTTP/1.1 201 Created\r\n"
        "Content-Type: application/json\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "7\r\n{\"ok\":1\r\n1\r\n}\r\n0\r\nX-Trace: yes\r\n\r\n") == 0);
    assert(sent_status == 201);
    assert(sent_body_len == 8 && !strcmp(sent_body, "{\"ok\":1}"));

    assert(relay("GET",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n") == -1);
    assert(relay("GET",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\nextra") == -1);
    assert(relay("GET",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: 3\r\n\r\n{}") == -1);
    assert(relay("GET",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Transfer-Encoding: gzip\r\n\r\n{}") == -1);
    assert(relay("GET",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}") == -1);
    assert(relay("GET",
        "HTTP/1.1 100 Continue\r\nContent-Type: application/json\r\n"
        "Content-Length: 2\r\n\r\n{}") == -1);
    assert(relay("HEAD",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: 2\r\n\r\n{}") == -1);
    assert(relay("HEAD",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: 2\r\n\r\n") == 0);
    assert(sent_status == 200 && sent_body_len == 0);
    assert(relay("GET", "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n") == 0);
    assert(sent_status == 204 && sent_body_len == 0);
    assert(relay("GET", "HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\n{}") == -1);

    puts("native_plugins_protocol_test: ok");
    return 0;
}
