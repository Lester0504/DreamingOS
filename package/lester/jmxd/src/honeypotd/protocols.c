// SPDX-License-Identifier: GPL-2.0-or-later
#include "honeypotd_internal.h"

static const char hp_http_body[] =
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>Device Login</title>"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head>"
    "<body><main><h1>Device Login</h1><form method=\"post\" action=\"/login\">"
    "<label>Username<input name=\"username\" autocomplete=\"username\"></label>"
    "<label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\"></label>"
    "<button type=\"submit\">Sign in</button></form></main></body></html>";

static void hp_text_copy(char *output, size_t output_size, const unsigned char *input, size_t length)
{
    size_t used = 0;

    if (!output_size)
        return;
    for (size_t i = 0; i < length && used + 1 < output_size; i++) {
        unsigned char c = input[i];

        if (c == '\t' || (c >= 0x20 && c <= 0x7e))
            output[used++] = (char)c;
    }
    output[used] = '\0';
}

static void hp_secure_clear(void *data, size_t length)
{
    volatile unsigned char *value = data;

    while (length--)
        *value++ = 0;
}

static const unsigned char *hp_find_bytes(const unsigned char *haystack, size_t haystack_len,
                                          const char *needle, size_t needle_len)
{
    if (!needle_len || needle_len > haystack_len)
        return NULL;
    for (size_t i = 0; i + needle_len <= haystack_len; i++) {
        if (!memcmp(haystack + i, needle, needle_len))
            return haystack + i;
    }
    return NULL;
}

static bool hp_next_line(struct hp_session *session, const unsigned char **line, size_t *length)
{
    size_t start = session->parse_offset;

    for (size_t i = start; i < session->input_len; i++) {
        if (session->input[i] != '\n')
            continue;
        *line = session->input + start;
        *length = i - start;
        if (*length && (*line)[*length - 1] == '\r')
            (*length)--;
        session->parse_offset = i + 1;
        return true;
    }
    return false;
}

bool hp_session_queue(struct hp_session *session, const void *data, size_t len)
{
    size_t pending;

    if (!data || len == 0)
        return true;
    pending = session->output_len - session->output_offset;
    if (pending && session->output_offset) {
        memmove(session->output, session->output + session->output_offset, pending);
        session->output_len = pending;
        session->output_offset = 0;
    }
    if (len > sizeof(session->output) - session->output_len)
        return false;
    memcpy(session->output + session->output_len, data, len);
    session->output_len += len;
    return true;
}

static void hp_json_add_text(struct json_object *payload, const char *name,
                             const unsigned char *data, size_t length)
{
    char value[512];

    hp_text_copy(value, sizeof(value), data, length);
    json_object_object_add(payload, name, json_object_new_string(value));
}

void hp_protocol_on_accept(struct hp_state *state, struct hp_session *session)
{
    const struct hp_listener *listener = &state->runtime.listeners[session->listener_index];
    static const char ssh_banner[] = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n";
    static const char ftp_banner[] = "220 NAS FTP server ready\r\n";

    hp_emit_session_event(state, session, "connect", NULL);
    switch (listener->service) {
    case HP_SERVICE_SSH:
        hp_session_queue(session, ssh_banner, sizeof(ssh_banner) - 1);
        break;
    case HP_SERVICE_TELNET: {
        static const unsigned char hello[] = { 255, 251, 1, 255, 251, 3, 255, 253, 31,
                                               '\r', '\n', 'l', 'o', 'g', 'i', 'n', ':', ' ' };
        hp_session_queue(session, hello, sizeof(hello));
        break;
    }
    case HP_SERVICE_FTP:
        hp_session_queue(session, ftp_banner, sizeof(ftp_banner) - 1);
        break;
    case HP_SERVICE_HTTP:
        break;
    default:
        session->close_after_write = true;
        break;
    }
}

static void hp_handle_ssh(struct hp_state *state, struct hp_session *session)
{
    const unsigned char *line;
    size_t length;

    if (session->protocol_state || !hp_next_line(session, &line, &length))
        return;
    struct json_object *payload = json_object_new_object();
    hp_json_add_text(payload, "client_banner", line, length);
    hp_emit_session_event(state, session, "protocol", payload);
    json_object_put(payload);
    session->protocol_state = 1;
    session->close_after_write = true;
}

static void hp_handle_telnet(struct hp_state *state, struct hp_session *session)
{
    const unsigned char *line;
    size_t length;
    static const char password_prompt[] = "Password: ";
    static const char login_failed[] = "\r\nLogin incorrect\r\n";

    while (hp_next_line(session, &line, &length)) {
        char cleaned[128];

        hp_text_copy(cleaned, sizeof(cleaned), line, length);
        if (!cleaned[0] && session->protocol_state == 0)
            continue;
        if (session->protocol_state == 0) {
            snprintf(session->username, sizeof(session->username), "%s", cleaned);
            hp_session_queue(session, password_prompt, sizeof(password_prompt) - 1);
            session->protocol_state = 1;
            continue;
        }
        if (session->protocol_state == 1) {
            struct json_object *payload = json_object_new_object();

            json_object_object_add(payload, "username", json_object_new_string(session->username));
            hp_payload_add_password_digest(payload, (const unsigned char *)cleaned,
                                           strlen(cleaned), true);
            hp_emit_session_event(state, session, "credentials", payload);
            json_object_put(payload);
            hp_secure_clear(cleaned, sizeof(cleaned));
            hp_session_queue(session, login_failed, sizeof(login_failed) - 1);
            session->protocol_state = 2;
            session->close_after_write = true;
            return;
        }
    }
}

static int hp_ascii_case_equal(const unsigned char *value, size_t value_len, const char *expected)
{
    size_t expected_len = strlen(expected);

    return value_len == expected_len && !strncasecmp((const char *)value, expected, value_len);
}

static bool hp_ftp_command(const unsigned char *line, size_t length, const char *command)
{
    size_t command_len = strlen(command);

    return length >= command_len &&
           hp_ascii_case_equal(line, command_len, command) &&
           (length == command_len || line[command_len] == ' ' || line[command_len] == '\t');
}

static void hp_handle_ftp(struct hp_state *state, struct hp_session *session)
{
    const unsigned char *line;
    size_t length;
    static const char password_required[] = "331 Password required\r\n";
    static const char login_failed[] = "530 Login incorrect\r\n";
    static const char goodbye[] = "221 Goodbye\r\n";
    static const char login_required[] = "530 Please login with USER and PASS\r\n";

    while (hp_next_line(session, &line, &length)) {
        const unsigned char *argument = line;
        size_t argument_len = length;

        while (argument_len && *argument != ' ' && *argument != '\t') {
            argument++;
            argument_len--;
        }
        while (argument_len && (*argument == ' ' || *argument == '\t')) {
            argument++;
            argument_len--;
        }
        if (hp_ftp_command(line, length, "USER")) {
            hp_text_copy(session->username, sizeof(session->username), argument, argument_len);
            hp_session_queue(session, password_required, sizeof(password_required) - 1);
        } else if (hp_ftp_command(line, length, "PASS")) {
            char password[128];
            struct json_object *payload = json_object_new_object();

            hp_text_copy(password, sizeof(password), argument, argument_len);
            json_object_object_add(payload, "username", json_object_new_string(session->username));
            hp_payload_add_password_digest(payload, (const unsigned char *)password,
                                           strlen(password), true);
            hp_emit_session_event(state, session, "credentials", payload);
            json_object_put(payload);
            hp_secure_clear(password, sizeof(password));
            hp_session_queue(session, login_failed, sizeof(login_failed) - 1);
            session->close_after_write = true;
            return;
        } else if (hp_ftp_command(line, length, "QUIT")) {
            hp_session_queue(session, goodbye, sizeof(goodbye) - 1);
            session->close_after_write = true;
            return;
        } else {
            hp_session_queue(session, login_required, sizeof(login_required) - 1);
        }
    }
}

static const unsigned char *hp_http_header_value(const unsigned char *headers, size_t headers_len,
                                                 const char *name, size_t *value_len)
{
    size_t name_len = strlen(name);
    size_t offset = 0;

    while (offset < headers_len) {
        const unsigned char *end = hp_find_bytes(headers + offset, headers_len - offset, "\r\n", 2);
        size_t line_len = end ? (size_t)(end - (headers + offset)) : headers_len - offset;

        if (line_len > name_len + 1 &&
            !strncasecmp((const char *)(headers + offset), name, name_len) &&
            headers[offset + name_len] == ':') {
            const unsigned char *value = headers + offset + name_len + 1;
            const unsigned char *line_end = headers + offset + line_len;

            while (value < line_end && (*value == ' ' || *value == '\t'))
                value++;
            *value_len = (size_t)(line_end - value);
            return value;
        }
        if (!end)
            break;
        offset += line_len + 2;
    }
    return NULL;
}

static unsigned int hp_http_content_length(const unsigned char *headers, size_t headers_len)
{
    const unsigned char *value;
    size_t value_len = 0;
    char number[24];
    char *end = NULL;
    unsigned long parsed;

    value = hp_http_header_value(headers, headers_len, "Content-Length", &value_len);
    if (!value || value_len == 0 || value_len >= sizeof(number))
        return 0;
    memcpy(number, value, value_len);
    number[value_len] = '\0';
    errno = 0;
    parsed = strtoul(number, &end, 10);
    if (errno || !end || *end || parsed > HP_CAPTURE_HARD_LIMIT)
        return HP_CAPTURE_HARD_LIMIT + 1;
    return (unsigned int)parsed;
}

static int hp_hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hp_form_value(const unsigned char *body, size_t body_len, const char *name,
                          char *output, size_t output_size)
{
    size_t name_len = strlen(name);
    size_t used = 0;

    output[0] = '\0';
    for (size_t i = 0; i < body_len;) {
        size_t pair_end = i;
        size_t equal = i;

        while (pair_end < body_len && body[pair_end] != '&')
            pair_end++;
        while (equal < pair_end && body[equal] != '=')
            equal++;
        if (equal - i == name_len && !memcmp(body + i, name, name_len)) {
            for (size_t p = equal < pair_end ? equal + 1 : pair_end;
                 p < pair_end && used + 1 < output_size; p++) {
                unsigned char c = body[p];

                if (c == '+') c = ' ';
                else if (c == '%' && p + 2 < pair_end) {
                    int high = hp_hex_value(body[p + 1]);
                    int low = hp_hex_value(body[p + 2]);
                    if (high >= 0 && low >= 0) {
                        c = (unsigned char)((high << 4) | low);
                        p += 2;
                    }
                }
                if (c == '\t' || (c >= 0x20 && c <= 0x7e))
                    output[used++] = (char)c;
            }
            output[used] = '\0';
            return true;
        }
        i = pair_end < body_len ? pair_end + 1 : body_len;
    }
    return false;
}

static void hp_http_respond(struct hp_session *session)
{
    char header[512];
    int length = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\nCache-Control: no-store\r\nConnection: close\r\n"
        "X-Content-Type-Options: nosniff\r\n\r\n", strlen(hp_http_body));

    if (length > 0 && (size_t)length < sizeof(header) &&
        hp_session_queue(session, header, (size_t)length))
        hp_session_queue(session, hp_http_body, strlen(hp_http_body));
    session->close_after_write = true;
}

static void hp_handle_http(struct hp_state *state, struct hp_session *session)
{
    const unsigned char *header_end;
    const unsigned char *request_line_end;
    size_t header_len;
    size_t content_length;
    const unsigned char *method_end;
    const unsigned char *uri_end;
    struct json_object *payload;
    bool credentials = false;

    if (session->protocol_state)
        return;
    header_end = hp_find_bytes(session->input, session->input_len, "\r\n\r\n", 4);
    if (!header_end)
        return;
    header_len = (size_t)(header_end - session->input) + 4;
    content_length = hp_http_content_length(session->input, header_len);
    if (content_length > HP_CAPTURE_HARD_LIMIT || header_len + content_length > session->input_len) {
        if (header_len + content_length <= state->runtime.limits.capture_limit)
            return;
        content_length = session->input_len - header_len;
    }
    request_line_end = hp_find_bytes(session->input, header_len, "\r\n", 2);
    method_end = memchr(session->input, ' ', request_line_end ?
                        (size_t)(request_line_end - session->input) : header_len);
    if (!request_line_end || !method_end) {
        hp_http_respond(session);
        session->protocol_state = 1;
        return;
    }
    uri_end = memchr(method_end + 1, ' ', (size_t)(request_line_end - method_end - 1));
    payload = json_object_new_object();
    hp_json_add_text(payload, "method", session->input, (size_t)(method_end - session->input));
    if (uri_end)
        hp_json_add_text(payload, "uri", method_end + 1, (size_t)(uri_end - method_end - 1));
    for (size_t i = 0; i < 2; i++) {
        const char *name = i == 0 ? "Host" : "User-Agent";
        const char *field = i == 0 ? "host" : "user_agent";
        size_t value_len = 0;
        const unsigned char *value = hp_http_header_value(session->input, header_len, name, &value_len);
        if (value)
            hp_json_add_text(payload, field, value, value_len);
    }
    if (content_length) {
        char username[128];
        char password[128];
        bool password_field;

        (void)hp_form_value(session->input + header_len, content_length, "username",
                            username, sizeof(username));
        if (!username[0])
            (void)hp_form_value(session->input + header_len, content_length, "user",
                                username, sizeof(username));
        password_field = hp_form_value(session->input + header_len, content_length,
                                       "password", password, sizeof(password));
        if (!password_field)
            password_field = hp_form_value(session->input + header_len, content_length,
                                           "pass", password, sizeof(password));
        if (username[0]) {
            json_object_object_add(payload, "username", json_object_new_string(username));
            credentials = true;
        }
        hp_payload_add_password_digest(payload, (const unsigned char *)password,
                                       strlen(password), password_field);
        if (password_field)
            credentials = true;
        hp_secure_clear(password, sizeof(password));
    }
    hp_emit_session_event(state, session, credentials ? "credentials" : "request", payload);
    json_object_put(payload);
    hp_http_respond(session);
    session->protocol_state = 1;
}

void hp_protocol_on_data(struct hp_state *state, struct hp_session *session)
{
    const struct hp_listener *listener = &state->runtime.listeners[session->listener_index];

    switch (listener->service) {
    case HP_SERVICE_SSH: hp_handle_ssh(state, session); break;
    case HP_SERVICE_TELNET: hp_handle_telnet(state, session); break;
    case HP_SERVICE_HTTP: hp_handle_http(state, session); break;
    case HP_SERVICE_FTP: hp_handle_ftp(state, session); break;
    default: session->close_after_write = true; break;
    }
}

static int hp_dns_question(const unsigned char *packet, size_t length, size_t *question_end,
                           char *qname, size_t qname_size, uint16_t *qtype)
{
    size_t offset = 12;
    size_t used = 0;

    if (length < 17 || (packet[2] & 0x80) || packet[4] != 0 || packet[5] != 1)
        return -1;
    while (offset < length) {
        unsigned int label_len = packet[offset++];

        if (label_len == 0)
            break;
        if ((label_len & 0xc0) || label_len > 63 || offset + label_len > length)
            return -1;
        if (used && used + 1 < qname_size)
            qname[used++] = '.';
        if (used + label_len >= qname_size)
            return -1;
        for (unsigned int i = 0; i < label_len; i++) {
            unsigned char c = packet[offset + i];
            if (!(c == '-' || c == '_' || (c >= '0' && c <= '9') ||
                  (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
                return -1;
            qname[used++] = (char)c;
        }
        offset += label_len;
    }
    if (offset + 4 > length || used == 0)
        return -1;
    qname[used] = '\0';
    *qtype = (uint16_t)((packet[offset] << 8) | packet[offset + 1]);
    *question_end = offset + 4;
    return 0;
}

void hp_protocol_handle_dns(struct hp_state *state, size_t socket_index)
{
    const struct hp_listener *listener;

    if (socket_index >= state->runtime.listener_count)
        return;
    listener = &state->runtime.listeners[socket_index];
    for (unsigned int handled = 0; handled < 32; handled++) {
        unsigned char packet[HP_CAPTURE_HARD_LIMIT];
        struct sockaddr_storage source;
        char source_ip[INET6_ADDRSTRLEN] = "";
        char qname[256];
        uint16_t qtype;
        size_t question_end;
        ssize_t got;

        memset(&source, 0, sizeof(source));
        socklen_t source_len = sizeof(source);
        got = recvfrom(listener->fd, packet, sizeof(packet), MSG_DONTWAIT,
                       (struct sockaddr *)&source, &source_len);
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return;
        if (source.ss_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)&source;
            inet_ntop(AF_INET, &sin->sin_addr, source_ip, sizeof(source_ip));
        }
        if (!source_ip[0] || !hp_source_rate_allow(state, source_ip, hp_monotonic_ms()))
            continue;
        if (hp_dns_question(packet, (size_t)got, &question_end, qname,
                            sizeof(qname), &qtype) != 0)
            continue;
        packet[2] = (unsigned char)(0x80 | (packet[2] & 0x79));
        packet[3] = (unsigned char)((packet[3] & 0x10) | listener->dns_rcode);
        packet[4] = 0; packet[5] = 1;
        memset(packet + 6, 0, 6);
        (void)sendto(listener->fd, packet, question_end, MSG_DONTWAIT,
                     (struct sockaddr *)&source, source_len);
        struct json_object *payload = json_object_new_object();
        json_object_object_add(payload, "qname", json_object_new_string(qname));
        json_object_object_add(payload, "qtype", json_object_new_int(qtype));
        json_object_object_add(payload, "rcode", json_object_new_string(
            listener->dns_rcode == 3 ? "nxdomain" : "refused"));
        hp_emit_datagram_event(state, listener, &source, source_len,
                               "query", payload);
        json_object_put(payload);
    }
}
