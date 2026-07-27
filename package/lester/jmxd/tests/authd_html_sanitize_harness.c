// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "authd/authd_internal.h"

static int expect_output(const char *name, const char *input, const char *expected)
{
    char *output = authd_html_sanitize(input, 4096);
    int failed = !output || strcmp(output, expected);

    if (failed)
        fprintf(stderr, "%s: expected [%s], got [%s]\n",
                name, expected, output ? output : "<null>");
    free(output);
    return failed;
}

int main(void)
{
    char oversized[32770];
    char *output;
    int failed = 0;

    failed |= expect_output(
        "dangerous-nodes-and-attributes",
        "<p onclick=\"bad()\">ok<script>alert(1)</script>"
        "<style>p{display:none}</style><img src=x onerror=bad>"
        "<a href=\"javascript:bad\" style=\"x\">bad</a>"
        "<a href=\"https://example.com/a?b=1&c=2\">good</a></p>",
        "<p>ok<a rel=\"noopener noreferrer\">bad</a>"
        "<a href=\"https://example.com/a?b=1&amp;c=2\" "
        "rel=\"noopener noreferrer\">good</a></p>");
    failed |= expect_output(
        "safe-relative-and-text-escaping",
        "<h2>Notice & status</h2><a href=\"/portal/help\">Help</a>"
        "<a href=\"//evil.example\">No</a><a href=\"../admin\">No</a>",
        "<h2>Notice &amp; status</h2>"
        "<a href=\"/portal/help\" rel=\"noopener noreferrer\">Help</a>"
        "<a rel=\"noopener noreferrer\">No</a>"
        "<a rel=\"noopener noreferrer\">No</a>");
    failed |= expect_output(
        "attribute-quote-escaping",
        "<a href=\"https://example.com/&quot; onclick=&quot;bad\">safe</a>",
        "<a href=\"https://example.com/&quot; onclick=&quot;bad\" "
        "rel=\"noopener noreferrer\">safe</a>");

    memset(oversized, 'a', sizeof(oversized) - 1);
    oversized[sizeof(oversized) - 1] = '\0';
    output = authd_html_sanitize(oversized, 4096);
    if (output) {
        fprintf(stderr, "oversized-input: expected rejection\n");
        free(output);
        failed = 1;
    }

    if (!failed)
        puts("ok: authd HTML sanitizer runtime contract");
    return failed ? 1 : 0;
}
