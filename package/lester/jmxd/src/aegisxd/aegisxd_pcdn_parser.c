// SPDX-License-Identifier: GPL-2.0-or-later
#include "aegisxd_pcdn_parser.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static void pcdn_trim(char *s)
{
    char *p;
    size_t n;

    if (!s)
        return;
    p = s;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
}

static int pcdn_domain_ok(const char *domain)
{
    size_t n;
    int dots = 0;
    size_t label = 0;

    if (!domain || !(n = strlen(domain)) || n > 253)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)domain[i];

        if (c == '.') {
            if (!label || domain[i - 1] == '-')
                return 0;
            dots++;
            label = 0;
            continue;
        }
        if (!isalnum(c) && c != '-')
            return 0;
        if (!label && c == '-')
            return 0;
        if (++label > 63)
            return 0;
    }
    return dots > 0 && label > 0 && domain[n - 1] != '-';
}

int aegisxd_pcdn_parse_line(char *line, char *out, size_t out_len)
{
    char *domain;
    char *end;
    char first[INET6_ADDRSTRLEN];
    unsigned char addr[sizeof(struct in6_addr)];

    if (!line || !out || out_len < AEGISXD_PCDN_DOMAIN_BUFSZ)
        return -1;
    out[0] = '\0';
    pcdn_trim(line);
    if (!line[0] || line[0] == '#' || line[0] == '!')
        return 0;

    /* Exceptions, regexes, URLs and wildcard filters are not executable input. */
    if (!strncmp(line, "@@", 2) || line[0] == '/' || strstr(line, "://") ||
        strchr(line, '*') || strchr(line, '?') || strchr(line, '[') ||
        strchr(line, ']') || strchr(line, '{') || strchr(line, '}'))
        return -1;

    domain = line;
    if (!strncmp(domain, "||", 2)) {
        domain += 2;
        end = strchr(domain, '^');
        if (end)
            *end = '\0';
    } else {
        size_t first_len = strcspn(domain, " \t");

        if (first_len < sizeof(first)) {
            memcpy(first, domain, first_len);
            first[first_len] = '\0';
            if (inet_pton(AF_INET, first, addr) == 1 ||
                inet_pton(AF_INET6, first, addr) == 1) {
                domain += first_len;
                while (*domain && isspace((unsigned char)*domain))
                    domain++;
                if (!domain[0])
                    return -1;
            }
        }
    }
    pcdn_trim(domain);
    end = strpbrk(domain, " \t#^");
    if (end)
        *end = '\0';
    while (domain[0] == '.')
        domain++;
    end = domain + strlen(domain);
    while (end > domain && end[-1] == '.')
        *--end = '\0';
    for (char *p = domain; *p; p++)
        *p = (char)tolower((unsigned char)*p);
    if (!pcdn_domain_ok(domain) || inet_pton(AF_INET, domain, addr) == 1 ||
        inet_pton(AF_INET6, domain, addr) == 1)
        return -1;
    snprintf(out, out_len, "%s", domain);
    return 1;
}
