// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_STRBUF_H__
#define __JMX_STRBUF_H__

#include <stddef.h>
#include <string.h>

/*
 * Truncating string copy with an explicit, checkable result.
 *
 * This replaces snprintf(dst, sizeof(dst), "%s", src). That idiom is correct,
 * but from GCC 16 onwards every call whose source bound exceeds the
 * destination raises -Wformat-truncation=, and the only way to silence it
 * through snprintf is to consume the return value at each call site -- casting
 * the call to (void) does not help. Copying through memcpy states the same
 * "copy what fits, always NUL-terminate" contract without a format string, so
 * the diagnostic no longer applies and deliberate truncation stays visible
 * instead of hiding behind a suppression.
 *
 * Returns 0 when the whole source fit and -1 when it was truncated. The result
 * is deliberately not warn_unused_result: most callers are copying an already
 * length-validated token into a field sized for it, and only the ones where a
 * short field changes behaviour need to look.
 */
static inline int jmx_strbuf_copy(char *dst, size_t dst_size, const char *src)
{
    size_t len;

    if (!dst || dst_size == 0)
        return -1;
    if (!src) {
        dst[0] = '\0';
        return 0;
    }
    len = strlen(src);
    if (len >= dst_size) {
        memcpy(dst, src, dst_size - 1);
        dst[dst_size - 1] = '\0';
        return -1;
    }
    memcpy(dst, src, len + 1);
    return 0;
}

/*
 * Same, for a destination whose extent sizeof() knows. Never pass a pointer:
 * sizeof would then be the pointer width and the copy would be truncated to
 * 7 bytes. Use jmx_strbuf_copy() directly when the size arrives as a
 * parameter.
 */
#define JMX_STRBUF_COPY(dst, src) jmx_strbuf_copy((dst), sizeof(dst), (src))

#endif /* __JMX_STRBUF_H__ */
