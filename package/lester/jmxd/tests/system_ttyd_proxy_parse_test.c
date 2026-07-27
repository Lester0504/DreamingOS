// SPDX-License-Identifier: GPL-2.0-or-later
#include <assert.h>
#include <string.h>

/* Keep the parser test in the implementation translation unit. */
#include "../src/webd/system_ttyd_proxy.c"

static void expect_valid(const char *raw, size_t body_len, int websocket)
{
    struct proxy_http_request request;
    const char *error = NULL;

    assert(proxy_parse_request(raw, strlen(raw), &request, &error) == 0);
    assert(error == NULL);
    assert(request.body_len == body_len);
    assert(request.websocket == websocket);
}

int main(void)
{
    struct proxy_http_request request;
    struct proxy_response_head response;
    struct proxy_dynamic rewritten = {0};
    const char *error = NULL;
    const char raw_response[] =
        "HTTP/1.1 200 OK\r\n"
        "server: ttyd/1.7.7\r\n"
        "content-type: text/html\r\n"
        "content-length: 729693\r\n\r\n";

    expect_valid("GET /terminal/ HTTP/1.1\r\n"
                 "Host: router.example\r\n\r\n", 0, 0);
    expect_valid("GET /terminal/?q=1 HTTP/1.1\r\n"
                 "Host: router.example\r\n"
                 "Origin: https://router.example\r\n"
                 "Accept: text/html\r\n\r\n", 0, 0);
    expect_valid("POST /terminal/token HTTP/1.1\r\n"
                 "Host: router.example\r\n"
                 "Content-Length: 2\r\n\r\n{}", 2, 0);
    expect_valid("GET /terminal/ws HTTP/1.1\r\n"
                 "Host: router.example\r\n"
                 "Connection: keep-alive, Upgrade\r\n"
                 "Upgrade: websocket\r\n"
                 "Sec-WebSocket-Protocol: tty\r\n\r\n", 0, 1);

    assert(proxy_parse_request("GET /terminal/ HTTP/1.1\r\n"
                               "Host: router.example\r\n",
                               strlen("GET /terminal/ HTTP/1.1\r\n"
                                      "Host: router.example\r\n"),
                               &request, &error) != 0);
    assert(error && !strcmp(error, "ttyd_proxy_incomplete_headers"));

    memset(&response, 0, sizeof(response));
    memcpy(response.data, raw_response, sizeof(raw_response) - 1);
    response.length = sizeof(raw_response) - 1;
    response.header_length = response.length;
    assert(proxy_response_parse_status(&response) == 0);
    assert(response.status == 200);
    assert(proxy_response_parse_framing(&response) == 0);
    assert(response.content_length_present);
    assert(response.content_length == 729693);
    assert(proxy_build_response_header(&response, 0, &rewritten) == 0);
    assert(memmem(rewritten.data, rewritten.length,
                  "content-length: 729693\r\n", 24) != NULL);
    free(rewritten.data);

    memset(&response, 0, sizeof(response));
    memcpy(response.data,
           "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
           sizeof("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n") - 1);
    response.length = sizeof("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n") - 1;
    response.header_length = response.length;
    assert(proxy_response_parse_framing(&response) != 0);
    return 0;
}
