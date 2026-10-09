// SPDX-License-Identifier: GPL-2.0-or-later
/* Interpret actual HLS segments and their wall-clock timestamps. Configured
 * retention is never used as evidence that a historical interval exists. */
#define _GNU_SOURCE
#include "iptv.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static double number(struct json_object *o, const char *key)
{ struct json_object *v = NULL; json_object_object_get_ex(o, key, &v); return json_object_get_double(v); }
static double timestamp(const char *text)
{
    struct tm value = {0}; char *p = strptime(text, "%Y-%m-%dT%H:%M:%S", &value);
    if (!p) return 0;
    double fraction = 0;
    if (*p == '.') fraction = strtod(p, &p);
    int offset = 0;
    if (*p == '+' || *p == '-') {
        int sign = *p++ == '+' ? 1 : -1, hour = 0, minute = 0;
        if (sscanf(p, "%2d:%2d", &hour, &minute) != 2 && sscanf(p, "%2d%2d", &hour, &minute) != 2) return 0;
        if (hour > 14 || minute > 59) return 0;
        offset = sign * (hour * 3600 + minute * 60);
    } else if (*p != 'Z') return 0;
    return (double)timegm(&value) - offset + fraction;
}
static int segment_name(const char *name)
{
    if (strncmp(name, "seg", 3)) return 0;
    const char *p = name + 3; if (*p < '0' || *p > '9') return 0;
    while (*p >= '0' && *p <= '9') p++;
    return !strcmp(p, ".ts") || !strcmp(p, ".m4s");
}
struct json_object *iptv_window_read(const char *directory, struct iptv_error *e)
{
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/window.m3u8", directory) >= (int)sizeof(path)) return iptv_fail(e, 503, "window_unavailable", "");
    FILE *f = fopen(path, "r"); if (!f) return iptv_fail(e, 503, "first_segment_pending", "");
    struct json_object *result = json_object_new_object(), *rows = json_object_new_array();
    struct json_object *intervals = json_object_new_array(), *interval = NULL;
    double start = 0, duration = 0, last_end = 0; int discontinuity = 0, missing = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(line, "#EXT-X-PROGRAM-DATE-TIME:", 25)) start = timestamp(line + 25);
        else if (!strncmp(line, "#EXTINF:", 8)) duration = strtod(line + 8, NULL);
        else if (!strcmp(line, "#EXT-X-DISCONTINUITY")) discontinuity = 1;
        else if (!strncmp(line, "#EXT-X-MAP:", 11)) json_object_object_add(result, "fmp4", json_object_new_boolean(1));
        else if (segment_name(line) && start > 0 && duration > 0 && duration < 3600) {
            struct stat st;
            if (snprintf(path, sizeof(path), "%s/%s", directory, line) >= (int)sizeof(path) || lstat(path, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0) {
                missing++; start += duration; discontinuity = 1; continue;
            }
            if (json_object_array_length(rows) >= 3600) break;
            int gap = discontinuity || (last_end > 0 && fabs(last_end - start) > .25);
            struct json_object *row = json_object_new_object();
            json_object_object_add(row, "name", json_object_new_string(line));
            json_object_object_add(row, "start", json_object_new_double(start));
            json_object_object_add(row, "end", json_object_new_double(start + duration));
            json_object_object_add(row, "duration", json_object_new_double(duration));
            json_object_object_add(row, "bytes", json_object_new_int64(st.st_size));
            json_object_object_add(row, "discontinuity", json_object_new_boolean(gap));
            json_object_array_add(rows, row);
            if (!interval || gap) {
                interval = json_object_new_object(); json_object_array_add(intervals, interval);
                json_object_object_add(interval, "start", json_object_new_double(start));
            }
            json_object_object_add(interval, "end", json_object_new_double(start + duration));
            last_end = start + duration; start = last_end; discontinuity = 0;
        }
    }
    fclose(f); json_object_object_add(result, "segments", rows); json_object_object_add(result, "intervals", intervals);
    size_t count = json_object_array_length(rows);
    json_object_object_add(result, "available", json_object_new_boolean(count > 0));
    json_object_object_add(result, "start", count ? json_object_new_double(number(json_object_array_get_idx(rows, 0), "start")) : NULL);
    json_object_object_add(result, "end", count ? json_object_new_double(last_end) : NULL);
    json_object_object_add(result, "missing_segments", json_object_new_int(missing));
    json_object_object_add(result, "server_time", json_object_new_int64(time(NULL))); return result;
}
int iptv_window_playlist(struct json_object *window, double from, int live_count,
    char **data, size_t *length, struct iptv_error *e)
{
    struct json_object *rows = NULL; json_object_object_get_ex(window, "segments", &rows);
    size_t count = json_object_array_length(rows), first = 0;
    if (!count) {iptv_fail(e, 503, "first_segment_pending", ""); return -1;}
    if (from > 0) {
        if (from < number(window, "start") || from >= number(window, "end")) {
            iptv_fail(e, 410, "timeshift_window_expired", "start"); return -1;
        }
        for (; first < count; first++) if (number(json_object_array_get_idx(rows, first), "end") > from) break;
        if (first == count || number(json_object_array_get_idx(rows, first), "start") > from) {
            iptv_fail(e, 410, "timeshift_gap", "start"); return -1;
        }
    } else if (live_count > 0 && count > (size_t)live_count) first = count - (size_t)live_count;
    FILE *f = open_memstream(data, length); if (!f) {iptv_fail(e, 503, "out_of_memory", ""); return -1;}
    double maximum = 1; for (size_t i = first; i < count; i++) {
        double d = number(json_object_array_get_idx(rows, i), "duration"); if (d > maximum) maximum = d;
    }
    const char *first_name = iptv_string(json_object_array_get_idx(rows, first), "name");
    unsigned long sequence = strtoul(first_name + 3, NULL, 10);
    fprintf(f, "#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:%d\n#EXT-X-MEDIA-SEQUENCE:%lu\n", (int)ceil(maximum), sequence);
    if (iptv_integer(window, "fmp4", 0)) fputs("#EXT-X-MAP:URI=\"init.mp4\"\n", f);
    if (from > 0) fprintf(f, "#EXT-X-START:TIME-OFFSET=%.3f,PRECISE=YES\n", from - number(json_object_array_get_idx(rows, first), "start"));
    for (size_t i = first; i < count; i++) {
        struct json_object *row = json_object_array_get_idx(rows, i);
        if (iptv_integer(row, "discontinuity", 0)) fputs("#EXT-X-DISCONTINUITY\n", f);
        time_t t = (time_t)number(row, "start"); struct tm tm; char stamp[40];
        gmtime_r(&t, &tm); strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", &tm);
        fprintf(f, "#EXT-X-PROGRAM-DATE-TIME:%s.%03dZ\n#EXTINF:%.6f,\n%s\n", stamp,
            (int)((number(row, "start") - t) * 1000), number(row, "duration"), iptv_string(row, "name"));
    }
    fclose(f); return 0;
}
