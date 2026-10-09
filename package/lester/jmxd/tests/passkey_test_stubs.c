#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <sys/types.h>

#include <openssl/rand.h>

#include "uci.h"

struct uci_context *uci_alloc_context(void)
{
    return NULL;
}

void uci_free_context(struct uci_context *ctx)
{
    (void)ctx;
}

int uci_load(struct uci_context *ctx, const char *name,
             struct uci_package **package)
{
    (void)ctx;
    (void)name;
    if (package)
        *package = NULL;
    return -1;
}

const char *uci_lookup_option_string(struct uci_context *ctx,
                                     struct uci_section *section,
                                     const char *name)
{
    (void)ctx;
    (void)section;
    (void)name;
    return NULL;
}

ssize_t getrandom(void *buffer, size_t length, unsigned int flags)
{
    unsigned char *cursor = buffer;
    size_t remaining = length;

    (void)flags;
    while (remaining > 0) {
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;

        if (RAND_bytes(cursor, chunk) != 1) {
            errno = EIO;
            return -1;
        }
        cursor += chunk;
        remaining -= (size_t)chunk;
    }
    return (ssize_t)length;
}
