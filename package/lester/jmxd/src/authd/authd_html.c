// SPDX-License-Identifier: GPL-2.0-or-later
#include "authd_internal.h"

#include <libxml/HTMLparser.h>
#include <libxml/tree.h>

struct authd_html_buffer {
    char *data;
    size_t len;
    size_t cap;
    size_t max;
    int failed;
};

static int authd_html_append(struct authd_html_buffer *buf, const char *text, size_t len)
{
    size_t needed;
    char *grown;

    if (!buf || buf->failed || !text || len == 0)
        return buf && !buf->failed ? 0 : -1;
    if (len > buf->max || buf->len > buf->max - len) {
        buf->failed = 1;
        return -1;
    }
    needed = buf->len + len + 1;
    if (needed > buf->cap) {
        size_t next = buf->cap ? buf->cap : 256;
        while (next < needed && next < buf->max + 1)
            next = next > (buf->max + 1) / 2 ? buf->max + 1 : next * 2;
        grown = realloc(buf->data, next);
        if (!grown) {
            buf->failed = 1;
            return -1;
        }
        buf->data = grown;
        buf->cap = next;
    }
    memcpy(buf->data + buf->len, text, len);
    buf->len += len;
    buf->data[buf->len] = '\0';
    return 0;
}

static int authd_html_name_allowed(const char *name)
{
    static const char *allowed[] = {
        "p", "br", "strong", "b", "em", "i", "u", "ul", "ol", "li",
        "h2", "h3", "a", NULL
    };
    int i;
    for (i = 0; allowed[i]; i++)
        if (!strcasecmp(name ? name : "", allowed[i]))
            return 1;
    return 0;
}

static int authd_html_href_ok(const char *href)
{
    if (!href || !href[0] || strchr(href, '\n') || strchr(href, '\r'))
        return 0;
    if (!strncasecmp(href, "https://", 8) || !strncasecmp(href, "http://", 7))
        return strlen(href) <= 2048;
    return href[0] == '/' && href[1] != '/' && !strstr(href, "..") && strlen(href) <= 2048;
}

static void authd_html_walk(xmlNode *node, struct authd_html_buffer *buf)
{
    for (; node && !buf->failed; node = node->next) {
        if (node->type == XML_TEXT_NODE) {
            xmlChar *escaped = xmlEncodeSpecialChars(NULL, node->content);
            if (escaped) {
                authd_html_append(buf, (const char *)escaped, xmlStrlen(escaped));
                xmlFree(escaped);
            }
            continue;
        }
        if (node->type != XML_ELEMENT_NODE)
            continue;
        if (!strcasecmp((const char *)node->name, "script") ||
            !strcasecmp((const char *)node->name, "style"))
            continue;
        if (authd_html_name_allowed((const char *)node->name)) {
            const char *name = (const char *)node->name;
            authd_html_append(buf, "<", 1);
            authd_html_append(buf, name, strlen(name));
            if (!strcasecmp(name, "a")) {
                xmlChar *href = xmlGetProp(node, BAD_CAST "href");
                if (href && authd_html_href_ok((const char *)href)) {
                    xmlChar *escaped = xmlEncodeSpecialChars(NULL, href);
                    authd_html_append(buf, " href=\"", 7);
                    if (escaped) {
                        authd_html_append(buf, (const char *)escaped, xmlStrlen(escaped));
                        xmlFree(escaped);
                    }
                    authd_html_append(buf, "\"", 1);
                }
                if (href) xmlFree(href);
                authd_html_append(buf, " rel=\"noopener noreferrer\"", 26);
            }
            authd_html_append(buf, ">", 1);
            if (strcasecmp(name, "br")) {
                authd_html_walk(node->children, buf);
                authd_html_append(buf, "</", 2);
                authd_html_append(buf, name, strlen(name));
                authd_html_append(buf, ">", 1);
            }
        } else {
            authd_html_walk(node->children, buf);
        }
    }
}

char *authd_html_sanitize(const char *input, size_t max_output)
{
    static const char prefix[] = "<div id=\"authd-root\">";
    static const char suffix[] = "</div>";
    struct authd_html_buffer buf = {.max = max_output};
    htmlDocPtr doc = NULL;
    xmlNode *root = NULL;
    char *wrapped = NULL;
    size_t input_len = strlen(input ? input : "");
    size_t wrapped_len;

    if (max_output < 1 || input_len > 32768)
        return NULL;
    wrapped_len = sizeof(prefix) - 1 + input_len + sizeof(suffix);
    wrapped = malloc(wrapped_len);
    if (!wrapped)
        return NULL;
    memcpy(wrapped, prefix, sizeof(prefix) - 1);
    memcpy(wrapped + sizeof(prefix) - 1, input ? input : "", input_len);
    memcpy(wrapped + sizeof(prefix) - 1 + input_len, suffix, sizeof(suffix));
    doc = htmlReadMemory(wrapped, (int)wrapped_len, NULL, "UTF-8",
                         HTML_PARSE_NONET | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING |
                         HTML_PARSE_RECOVER | HTML_PARSE_COMPACT);
    free(wrapped);
    if (!doc)
        return NULL;
    root = xmlDocGetRootElement(doc);
    while (root && strcasecmp((const char *)root->name, "html"))
        root = root->next;
    if (root) {
        xmlNode *body;
        for (body = root->children; body; body = body->next)
            if (body->type == XML_ELEMENT_NODE &&
                !strcasecmp((const char *)body->name, "body"))
                break;
        if (body) {
            xmlNode *div;
            for (div = body->children; div; div = div->next) {
                xmlChar *id;
                if (div->type != XML_ELEMENT_NODE || strcasecmp((const char *)div->name, "div"))
                    continue;
                id = xmlGetProp(div, BAD_CAST "id");
                if (id && !strcmp((const char *)id, "authd-root")) {
                    xmlFree(id);
                    authd_html_walk(div->children, &buf);
                    break;
                }
                if (id) xmlFree(id);
            }
        }
    }
    xmlFreeDoc(doc);
    if (buf.failed) {
        free(buf.data);
        return NULL;
    }
    if (!buf.data)
        buf.data = strdup("");
    return buf.data;
}
