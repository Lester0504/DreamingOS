#ifndef JMX_EXEC_H
#define JMX_EXEC_H

#include <stddef.h>

struct jmx_exec_result {
    char *output;
    size_t output_len;
    int exit_code;
    int term_signal;
    int timed_out;
    int truncated;
};

int jmx_exec_capture(const char *path, char *const argv[], size_t output_limit,
                     int timeout_ms, struct jmx_exec_result *result);
int jmx_exec_wait(const char *path, char *const argv[], int timeout_ms,
                  struct jmx_exec_result *result);
void jmx_exec_result_free(struct jmx_exec_result *result);

#endif
