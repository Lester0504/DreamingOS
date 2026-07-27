#ifndef PROC_PATH_H
#define PROC_PATH_H

#include <stdio.h>
#include <string.h>

static inline FILE* jmx_fopen_af(const char *filename, const char *mode) {
    char path[256];
    FILE *fp;
    
    /* Try /proc/dreamingwrt/jmx/ first (new kernel module path) */
    snprintf(path, sizeof(path), "/proc/dreamingwrt/jmx/%s", filename);
    fp = fopen(path, mode);
    if (fp) return fp;
    
    /* Fallback to /proc/net/ (old kernel module path) */
    snprintf(path, sizeof(path), "/proc/net/%s", filename);
    return fopen(path, mode);
}

#endif
