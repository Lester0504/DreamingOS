/* Fixture for the webd request-framing path.
 *
 * http_content_length_from_raw() is extracted verbatim from
 * src/webd/jmx_app_api.c so this exercises shipped code. The fixture then
 * replays the exact two-stage sequence webd uses in production:
 *
 *   1. the parent's nonblocking prefetch decides where the header ends
 *      (app_api_pending_header) and parses Content-Length,
 *   2. the child re-derives the body from the same buffer
 *      (parse_http_request's body/body_len computation),
 *
 * and reports the body bytes the child would hand to parse_body_json(). The
 * regression under test is the parent writing a NUL at the body's first byte.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define APP_API_MAX_BODY (1024 * 1024)

/* Verbatim from src/webd/jmx_app_api.c via the harness. */
#include "http_framing_extracted.h"

/* Mirrors struct http_req's framing fields only. */
struct fixture_req {
    const char *body;
    int body_len;
};

/* The body computation from parse_http_request(). The statements between the
 * markers are extracted verbatim from src/webd/jmx_app_api.c by the harness,
 * so a change to production framing shows up here instead of drifting.
 */
static int fixture_parse_body(const char *raw, int raw_len,
                              struct fixture_req *out)
{
    const char *hdr_end;
    struct fixture_req *fixture_out = out;

    memset(out, 0, sizeof(*out));
    hdr_end = memmem(raw, (size_t)raw_len, "\r\n\r\n", 4);
    if (!hdr_end)
        return -1;
#define out fixture_out
#include "http_body_len_extracted.h"
#undef out
    return 0;
}

/* app_api_pending_header(), verbatim in behavior: returns the offset just past
 * the CRLFCRLF, which is also the body's first byte.
 */
enum {
    PENDING_WAIT = 0,
    PENDING_READY = 1,
    PENDING_BAD = -1,
};

static int fixture_pending_header(const char *buf, size_t len,
                                  size_t *header_len)
{
    size_t i;
    size_t line_start = 0;

    if (header_len)
        *header_len = 0;
    for (i = 0; i < len; i++) {
        if (buf[i] == '\0' ||
            (buf[i] == '\n' && (i == 0 || buf[i - 1] != '\r')) ||
            (buf[i] == '\r' && (i + 1 >= len || buf[i + 1] != '\n'))) {
            if (buf[i] == '\r' && i + 1 == len)
                return PENDING_WAIT;
            return PENDING_BAD;
        }
        if (buf[i] != '\n')
            continue;
        if (i == line_start + 1 && buf[line_start] == '\r') {
            if (header_len)
                *header_len = i + 1;
            return PENDING_READY;
        }
        line_start = i + 1;
    }
    return PENDING_WAIT;
}

static void emit_escaped(const char *data, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];

        if (c == '\0')
            fputs("\\u0000", stdout);
        else if (c == '"')
            fputs("\\\"", stdout);
        else if (c == '\\')
            fputs("\\\\", stdout);
        else if (c == '\r')
            fputs("\\r", stdout);
        else if (c == '\n')
            fputs("\\n", stdout);
        else if (c < 0x20 || c > 0x7e)
            printf("\\u%04x", c);
        else
            putchar((int)c);
    }
}

/* Reads a request from stdin as raw bytes.
 *
 *   argv[1] = bytes present in the parent's first recv(). This models TCP
 *             segmentation: when it equals the whole request, header and body
 *             arrived together, which is the case that used to corrupt body[0].
 *   argv[2] = "1" when the real source still writes a NUL terminator at
 *             pending->header[header_len] before parsing framing. The harness
 *             derives this from src/webd/jmx_app_api.c, so reintroducing that
 *             write in production code is reproduced here and caught.
 *   argv[3] = "1" to run stage 1 against an exactly-sized heap copy of the
 *             prefetched bytes, with no readable byte at [header_len]. Under
 *             ASAN this turns any leftover NUL-terminated scan inside
 *             http_content_length_from_raw() into a reported overflow.
 */
int main(int argc, char **argv)
{
    static char buffer[APP_API_MAX_BODY + 65536];
    size_t total = 0;
    size_t prefetch;
    size_t header_len = 0;
    int parent_terminates = 0;
    int exact_alloc = 0;
    int state;
    int content_len = -1;
    int framing_rc;
    struct fixture_req req;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <prefetch_bytes> [parent_writes_nul] "
                        "[exact_alloc]\n", argv[0]);
        return 2;
    }
    while (total < sizeof(buffer)) {
        size_t n = fread(buffer + total, 1, sizeof(buffer) - total, stdin);

        if (n == 0)
            break;
        total += n;
    }
    prefetch = (size_t)strtoul(argv[1], NULL, 10);
    if (prefetch == 0 || prefetch > total)
        prefetch = total;
    if (argc > 2)
        parent_terminates = (int)strtol(argv[2], NULL, 10);
    if (argc > 3)
        exact_alloc = (int)strtol(argv[3], NULL, 10);

    /* Stage 1: the parent sees only the prefetched bytes. */
    state = fixture_pending_header(buffer, prefetch, &header_len);
    printf("{\"prefetch\":%zu,\"total\":%zu,\"pending_state\":%d,"
           "\"header_len\":%zu,\"parent_writes_nul\":%s",
           prefetch, total, state, header_len,
           parent_terminates ? "true" : "false");
    if (state != PENDING_READY) {
        printf(",\"body\":null,\"body_len\":-1,\"framing_rc\":-1,"
               "\"content_len\":-1,\"body_first_is_nul\":false}\n");
        return 0;
    }
    if (parent_terminates && header_len < sizeof(buffer))
        buffer[header_len] = '\0';
    if (exact_alloc) {
        /* No slack and no terminator: exactly the header bytes webd hands in. */
        char *tight = malloc(header_len);

        if (!tight) {
            fprintf(stderr, "allocation failed\n");
            return 2;
        }
        memcpy(tight, buffer, header_len);
        framing_rc = http_content_length_from_raw(tight, (int)header_len,
                                                  &content_len);
        free(tight);
    } else {
        framing_rc = http_content_length_from_raw(buffer, (int)header_len,
                                                  &content_len);
    }
    printf(",\"framing_rc\":%d,\"content_len\":%d", framing_rc, content_len);

    /* Stage 2: the child parses the same buffer, body included. */
    if (fixture_parse_body(buffer, (int)total, &req) != 0) {
        printf(",\"body\":null,\"body_len\":-1,\"body_first_is_nul\":false}\n");
        return 0;
    }
    printf(",\"body_len\":%d,\"body_first_is_nul\":%s,\"body\":\"",
           req.body_len,
           (req.body_len > 0 && req.body[0] == '\0') ? "true" : "false");
    emit_escaped(req.body, req.body_len);
    printf("\"}\n");
    return 0;
}
