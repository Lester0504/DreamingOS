#include "flowd/flowd_internal.h"

#include <stdio.h>

struct sample {
    const char *value;
    int expected;
};

int main(void)
{
    static const struct sample samples[] = {
        {"", 1},
        {"any", 1},
        {"443", 1},
        {"80,443", 1},
        {"1000-2000", 1},
        {"1-65535", 1},
        {"80,443,8080-8090", 1},
        {"65536", 0},
        {"abc", 0},
        {"80--90", 0},
        {"90-80", 0},
        {"80,", 0},
        {"80:90", 0},
        {"0", 0},
        {"-1", 0},
    };
    size_t i;

    for (i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
        int actual = flowd_port_expr_ok(samples[i].value);
        if (actual != samples[i].expected) {
            fprintf(stderr, "mismatch value=%s expected=%d actual=%d\n",
                    samples[i].value, samples[i].expected, actual);
            return 1;
        }
    }
    puts("ok: flowd port grammar");
    return 0;
}
