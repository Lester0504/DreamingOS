// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef DREAMINGWRT_AEGISXD_PCDN_PARSER_H
#define DREAMINGWRT_AEGISXD_PCDN_PARSER_H

#include <stddef.h>

#define AEGISXD_PCDN_DOMAIN_BUFSZ 254

/* Returns 1 for a domain, 0 for an ignorable line, and -1 for a rejected rule. */
int aegisxd_pcdn_parse_line(char *line, char *domain, size_t domain_len);

#endif
