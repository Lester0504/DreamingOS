/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Minimal MaxMind DB Country/City reader for webd Insights.
 *
 * This intentionally implements only the MMDB pieces needed for GeoLite2
 * lookups: metadata, search tree traversal, maps, arrays, pointers, strings,
 * booleans, unsigned integers, float and double.
 */
#include "webd_mmdb.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MMDB_METADATA_MARKER "\xab\xcd\xefMaxMind.com"
#define MMDB_METADATA_MARKER_LEN 14
#define MMDB_MAX_DEPTH 64

struct webd_mmdb {
    int fd;
    const unsigned char *buf;
    size_t len;
    uint32_t node_count;
    uint16_t record_size;
    uint16_t ip_version;
    size_t tree_size;
    size_t data_base;
};

typedef struct {
    int type;
    uint64_t size;
    size_t next;
    int pointer;
} mmdb_ctrl_t;

static void mmdb_set_err(char *err, size_t err_len, const char *msg)
{
    if (!err || err_len == 0)
        return;
    snprintf(err, err_len, "%s", msg ? msg : "mmdb_error");
}

static void mmdb_copy(char *out, size_t out_len, const char *s)
{
    if (!out || out_len == 0)
        return;
    if (!s)
        s = "";
    snprintf(out, out_len, "%s", s);
}

static int mmdb_read_ctrl(webd_mmdb_t *db, size_t pos, mmdb_ctrl_t *ctrl)
{
    unsigned int c;
    unsigned int type;
    uint64_t size;

    if (!db || !ctrl || pos >= db->len)
        return -1;
    memset(ctrl, 0, sizeof(*ctrl));
    c = db->buf[pos++];
    type = c >> 5;
    size = c & 0x1f;

    if (type == 0) {
        if (pos >= db->len)
            return -1;
        type = (unsigned int)db->buf[pos++] + 7;
    }

    if (type == 1) {
        unsigned int ptr_size = (unsigned int)((size >> 3) & 0x3);
        uint64_t ptr = size & 0x7;

        if (ptr_size == 0) {
            if (pos >= db->len)
                return -1;
            ptr = (ptr << 8) | db->buf[pos++];
        } else if (ptr_size == 1) {
            if (pos + 1 >= db->len)
                return -1;
            ptr = (ptr << 16) | ((uint64_t)db->buf[pos] << 8) | db->buf[pos + 1];
            ptr += 2048;
            pos += 2;
        } else if (ptr_size == 2) {
            if (pos + 2 >= db->len)
                return -1;
            ptr = (ptr << 24) | ((uint64_t)db->buf[pos] << 16) |
                  ((uint64_t)db->buf[pos + 1] << 8) | db->buf[pos + 2];
            ptr += 526336;
            pos += 3;
        } else {
            if (pos + 3 >= db->len)
                return -1;
            ptr = ((uint64_t)db->buf[pos] << 24) |
                  ((uint64_t)db->buf[pos + 1] << 16) |
                  ((uint64_t)db->buf[pos + 2] << 8) |
                  db->buf[pos + 3];
            pos += 4;
        }
        ctrl->type = 1;
        ctrl->size = ptr;
        ctrl->next = pos;
        ctrl->pointer = 1;
        return 0;
    }

    if (size == 29) {
        if (pos >= db->len)
            return -1;
        size = 29 + db->buf[pos++];
    } else if (size == 30) {
        if (pos + 1 >= db->len)
            return -1;
        size = 285 + ((uint64_t)db->buf[pos] << 8) + db->buf[pos + 1];
        pos += 2;
    } else if (size == 31) {
        if (pos + 2 >= db->len)
            return -1;
        size = 65821 + ((uint64_t)db->buf[pos] << 16) +
               ((uint64_t)db->buf[pos + 1] << 8) + db->buf[pos + 2];
        pos += 3;
    }

    ctrl->type = (int)type;
    ctrl->size = size;
    ctrl->next = pos;
    return 0;
}

static int mmdb_value_payload_end(webd_mmdb_t *db, const mmdb_ctrl_t *ctrl, size_t *end)
{
    size_t n;

    if (!db || !ctrl || !end)
        return -1;
    if (ctrl->size > (uint64_t)(SIZE_MAX - ctrl->next))
        return -1;
    n = ctrl->next + (size_t)ctrl->size;
    if (n > db->len)
        return -1;
    *end = n;
    return 0;
}

static int mmdb_skip_value(webd_mmdb_t *db, size_t base, size_t pos,
                           size_t *next, int depth);

static int mmdb_pointer_target(webd_mmdb_t *db, size_t base, const mmdb_ctrl_t *ctrl,
                               size_t *target)
{
    if (!db || !ctrl || !target || !ctrl->pointer)
        return -1;
    if (ctrl->size > (uint64_t)(SIZE_MAX - base))
        return -1;
    *target = base + (size_t)ctrl->size;
    return *target < db->len ? 0 : -1;
}

static int mmdb_decode_string(webd_mmdb_t *db, size_t base, size_t pos,
                              char *out, size_t out_len, size_t *next, int depth)
{
    mmdb_ctrl_t ctrl;
    size_t end;

    if (!db || depth > MMDB_MAX_DEPTH)
        return -1;
    if (out && out_len)
        out[0] = '\0';
    if (mmdb_read_ctrl(db, pos, &ctrl) != 0)
        return -1;
    if (ctrl.pointer) {
        size_t target;
        int rc;

        if (next)
            *next = ctrl.next;
        if (mmdb_pointer_target(db, base, &ctrl, &target) != 0)
            return -1;
        rc = mmdb_decode_string(db, base, target, out, out_len, NULL, depth + 1);
        return rc;
    }
    if (ctrl.type != 2 || mmdb_value_payload_end(db, &ctrl, &end) != 0)
        return -1;
    if (out && out_len) {
        size_t n = (size_t)ctrl.size;

        if (n >= out_len)
            n = out_len - 1;
        memcpy(out, db->buf + ctrl.next, n);
        out[n] = '\0';
    }
    if (next)
        *next = end;
    return 0;
}

static int mmdb_decode_uint(webd_mmdb_t *db, size_t base, size_t pos,
                            uint64_t *out, size_t *next, int depth)
{
    mmdb_ctrl_t ctrl;
    size_t end;
    uint64_t v = 0;
    size_t i;

    if (!db || !out || depth > MMDB_MAX_DEPTH)
        return -1;
    *out = 0;
    if (mmdb_read_ctrl(db, pos, &ctrl) != 0)
        return -1;
    if (ctrl.pointer) {
        size_t target;
        int rc;

        if (next)
            *next = ctrl.next;
        if (mmdb_pointer_target(db, base, &ctrl, &target) != 0)
            return -1;
        rc = mmdb_decode_uint(db, base, target, out, NULL, depth + 1);
        return rc;
    }
    if ((ctrl.type != 4 && ctrl.type != 5 && ctrl.type != 6 &&
         ctrl.type != 8 && ctrl.type != 9 && ctrl.type != 10) ||
        mmdb_value_payload_end(db, &ctrl, &end) != 0 ||
        ctrl.size > 8)
        return -1;
    for (i = ctrl.next; i < end; i++)
        v = (v << 8) | db->buf[i];
    *out = v;
    if (next)
        *next = end;
    return 0;
}

static int mmdb_decode_double(webd_mmdb_t *db, size_t base, size_t pos,
                              double *out, size_t *next, int depth)
{
    mmdb_ctrl_t ctrl;
    size_t end;
    uint64_t bits = 0;
    size_t i;

    if (!db || !out || depth > MMDB_MAX_DEPTH)
        return -1;
    *out = 0.0;
    if (mmdb_read_ctrl(db, pos, &ctrl) != 0)
        return -1;
    if (ctrl.pointer) {
        size_t target;
        int rc;

        if (next)
            *next = ctrl.next;
        if (mmdb_pointer_target(db, base, &ctrl, &target) != 0)
            return -1;
        rc = mmdb_decode_double(db, base, target, out, NULL, depth + 1);
        return rc;
    }
    if (mmdb_value_payload_end(db, &ctrl, &end) != 0)
        return -1;
    if (ctrl.type == 3 && ctrl.size == 8) {
        union {
            uint64_t u;
            double d;
        } cvt;

        for (i = ctrl.next; i < end; i++)
            bits = (bits << 8) | db->buf[i];
        cvt.u = bits;
        *out = cvt.d;
    } else if (ctrl.type == 15 && ctrl.size == 4) {
        union {
            uint32_t u;
            float f;
        } cvt;
        uint32_t fb = 0;

        for (i = ctrl.next; i < end; i++)
            fb = (fb << 8) | db->buf[i];
        cvt.u = fb;
        *out = (double)cvt.f;
    } else if ((ctrl.type == 4 || ctrl.type == 5 || ctrl.type == 6 ||
                ctrl.type == 8 || ctrl.type == 9 || ctrl.type == 10) &&
               ctrl.size <= 8) {
        for (i = ctrl.next; i < end; i++)
            bits = (bits << 8) | db->buf[i];
        *out = (double)bits;
    } else {
        return -1;
    }
    if (next)
        *next = end;
    return isfinite(*out) ? 0 : -1;
}

static int mmdb_skip_value(webd_mmdb_t *db, size_t base, size_t pos,
                           size_t *next, int depth)
{
    mmdb_ctrl_t ctrl;
    size_t p;
    uint64_t i;

    if (!db || !next || depth > MMDB_MAX_DEPTH)
        return -1;
    if (mmdb_read_ctrl(db, pos, &ctrl) != 0)
        return -1;
    if (ctrl.pointer) {
        *next = ctrl.next;
        return 0;
    }

    if (ctrl.type == 7) {
        p = ctrl.next;
        for (i = 0; i < ctrl.size; i++) {
            if (mmdb_skip_value(db, base, p, &p, depth + 1) != 0 ||
                mmdb_skip_value(db, base, p, &p, depth + 1) != 0)
                return -1;
        }
        *next = p;
        return 0;
    }
    if (ctrl.type == 11) {
        p = ctrl.next;
        for (i = 0; i < ctrl.size; i++) {
            if (mmdb_skip_value(db, base, p, &p, depth + 1) != 0)
                return -1;
        }
        *next = p;
        return 0;
    }
    if (ctrl.type == 14) {
        *next = ctrl.next;
        return 0;
    }
    return mmdb_value_payload_end(db, &ctrl, next);
}

static int mmdb_map_find(webd_mmdb_t *db, size_t base, size_t pos,
                         const char *key, size_t *value_pos,
                         size_t *next, int depth)
{
    mmdb_ctrl_t ctrl;
    size_t p;
    uint64_t i;

    if (!db || !key || !value_pos || depth > MMDB_MAX_DEPTH)
        return 0;
    if (mmdb_read_ctrl(db, pos, &ctrl) != 0)
        return 0;
    if (ctrl.pointer) {
        size_t target;

        if (next)
            *next = ctrl.next;
        if (mmdb_pointer_target(db, base, &ctrl, &target) != 0)
            return 0;
        return mmdb_map_find(db, base, target, key, value_pos, NULL, depth + 1);
    }
    if (ctrl.type != 7)
        return 0;

    p = ctrl.next;
    for (i = 0; i < ctrl.size; i++) {
        char k[96];
        size_t value_start;
        size_t after_value;

        if (mmdb_decode_string(db, base, p, k, sizeof(k), &value_start, depth + 1) != 0)
            return 0;
        if (!strcmp(k, key)) {
            *value_pos = value_start;
            if (next && mmdb_skip_value(db, base, value_start, next, depth + 1) != 0)
                *next = value_start;
            return 1;
        }
        if (mmdb_skip_value(db, base, value_start, &after_value, depth + 1) != 0)
            return 0;
        p = after_value;
    }
    if (next)
        *next = p;
    return 0;
}

static int mmdb_find_marker(webd_mmdb_t *db, size_t *metadata_pos)
{
    const unsigned char marker[] = MMDB_METADATA_MARKER;
    size_t i;

    if (!db || !metadata_pos || db->len < MMDB_METADATA_MARKER_LEN)
        return -1;
    for (i = db->len - MMDB_METADATA_MARKER_LEN + 1; i-- > 0;) {
        if (!memcmp(db->buf + i, marker, MMDB_METADATA_MARKER_LEN)) {
            *metadata_pos = i + MMDB_METADATA_MARKER_LEN;
            return 0;
        }
        if (i == 0)
            break;
    }
    return -1;
}

static int mmdb_parse_metadata(webd_mmdb_t *db, char *err, size_t err_len)
{
    size_t meta;
    size_t vpos;
    uint64_t v;

    if (mmdb_find_marker(db, &meta) != 0) {
        mmdb_set_err(err, err_len, "metadata_marker_missing");
        return -1;
    }
    if (!mmdb_map_find(db, meta, meta, "node_count", &vpos, NULL, 0) ||
        mmdb_decode_uint(db, meta, vpos, &v, NULL, 0) != 0 ||
        v == 0 || v > UINT32_MAX) {
        mmdb_set_err(err, err_len, "metadata_node_count_invalid");
        return -1;
    }
    db->node_count = (uint32_t)v;

    if (!mmdb_map_find(db, meta, meta, "record_size", &vpos, NULL, 0) ||
        mmdb_decode_uint(db, meta, vpos, &v, NULL, 0) != 0 ||
        (v != 24 && v != 28 && v != 32)) {
        mmdb_set_err(err, err_len, "metadata_record_size_invalid");
        return -1;
    }
    db->record_size = (uint16_t)v;

    if (!mmdb_map_find(db, meta, meta, "ip_version", &vpos, NULL, 0) ||
        mmdb_decode_uint(db, meta, vpos, &v, NULL, 0) != 0 ||
        (v != 4 && v != 6)) {
        mmdb_set_err(err, err_len, "metadata_ip_version_invalid");
        return -1;
    }
    db->ip_version = (uint16_t)v;

    db->tree_size = ((size_t)db->record_size * 2 / 8) * (size_t)db->node_count;
    db->data_base = db->tree_size + 16;
    if (db->data_base >= db->len) {
        mmdb_set_err(err, err_len, "metadata_tree_size_invalid");
        return -1;
    }
    return 0;
}

int webd_mmdb_open(const char *path, webd_mmdb_t **out, char *err, size_t err_len)
{
    webd_mmdb_t *db = NULL;
    struct stat st;
    int fd = -1;

    if (!out)
        return -1;
    *out = NULL;
    if (!path || !path[0])
        path = WEBD_GEOIP_MMDB_DEFAULT;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        mmdb_set_err(err, err_len, errno == ENOENT ? "mmdb_missing" : "mmdb_open_failed");
        return -1;
    }
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        close(fd);
        mmdb_set_err(err, err_len, "mmdb_invalid_file");
        return -1;
    }
    db = calloc(1, sizeof(*db));
    if (!db) {
        close(fd);
        mmdb_set_err(err, err_len, "oom");
        return -1;
    }
    db->fd = fd;
    db->len = (size_t)st.st_size;
    db->buf = mmap(NULL, db->len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (db->buf == MAP_FAILED) {
        free(db);
        close(fd);
        mmdb_set_err(err, err_len, "mmdb_mmap_failed");
        return -1;
    }
    if (mmdb_parse_metadata(db, err, err_len) != 0) {
        webd_mmdb_close(db);
        return -1;
    }
    *out = db;
    return 0;
}

void webd_mmdb_close(webd_mmdb_t *db)
{
    if (!db)
        return;
    if (db->buf && db->buf != MAP_FAILED)
        munmap((void *)db->buf, db->len);
    if (db->fd >= 0)
        close(db->fd);
    free(db);
}

static uint32_t mmdb_node_record(webd_mmdb_t *db, uint32_t node, int bit)
{
    size_t off;

    if (!db || node >= db->node_count)
        return db ? db->node_count : 0;
    off = (size_t)node * (size_t)db->record_size * 2 / 8;
    if (db->record_size == 24) {
        off += bit ? 3 : 0;
        return ((uint32_t)db->buf[off] << 16) |
               ((uint32_t)db->buf[off + 1] << 8) |
               db->buf[off + 2];
    }
    if (db->record_size == 28) {
        if (bit == 0) {
            return (((uint32_t)db->buf[off + 3] >> 4) << 24) |
                   ((uint32_t)db->buf[off] << 16) |
                   ((uint32_t)db->buf[off + 1] << 8) |
                   db->buf[off + 2];
        }
        return (((uint32_t)db->buf[off + 3] & 0x0f) << 24) |
               ((uint32_t)db->buf[off + 4] << 16) |
               ((uint32_t)db->buf[off + 5] << 8) |
               db->buf[off + 6];
    }
    off += bit ? 4 : 0;
    return ((uint32_t)db->buf[off] << 24) |
           ((uint32_t)db->buf[off + 1] << 16) |
           ((uint32_t)db->buf[off + 2] << 8) |
           db->buf[off + 3];
}

static int mmdb_lookup_record_pos(webd_mmdb_t *db, const char *ip, size_t *record_pos)
{
    unsigned char packed[16];
    unsigned char addr4[4];
    const unsigned char *addr = packed;
    int addr_len = 16;
    uint32_t node = 0;
    int i, bit;

    if (!db || !ip || !record_pos)
        return -1;
    memset(packed, 0, sizeof(packed));
    if (inet_pton(AF_INET, ip, addr4) == 1) {
        if (db->ip_version == 4) {
            memcpy(packed, addr4, 4);
            addr_len = 4;
        } else {
            memcpy(packed + 12, addr4, 4);
            addr_len = 16;
        }
    } else if (inet_pton(AF_INET6, ip, packed) == 1) {
        if (db->ip_version != 6)
            return -1;
        addr_len = 16;
    } else {
        return -1;
    }

    for (i = 0; i < addr_len; i++) {
        for (bit = 7; bit >= 0; bit--) {
            uint32_t val = mmdb_node_record(db, node, (addr[i] >> bit) & 1);

            if (val == db->node_count)
                return 0;
            if (val > db->node_count) {
                uint64_t delta = (uint64_t)val - db->node_count;

                if (delta < 16 || delta > (uint64_t)(SIZE_MAX - db->data_base))
                    return -1;
                *record_pos = db->data_base + (size_t)delta - 16;
                return *record_pos < db->len ? 1 : -1;
            }
            node = val;
        }
    }
    return 0;
}

static int mmdb_map_string_child(webd_mmdb_t *db, size_t base, size_t map_pos,
                                 const char *key, char *out, size_t out_len)
{
    size_t vpos;

    if (!mmdb_map_find(db, base, map_pos, key, &vpos, NULL, 0))
        return 0;
    return mmdb_decode_string(db, base, vpos, out, out_len, NULL, 0) == 0;
}

static int mmdb_map_uint_child(webd_mmdb_t *db, size_t base, size_t map_pos,
                               const char *key, uint64_t *out)
{
    size_t vpos;

    if (!out || !mmdb_map_find(db, base, map_pos, key, &vpos, NULL, 0))
        return 0;
    return mmdb_decode_uint(db, base, vpos, out, NULL, 0) == 0;
}

static int mmdb_map_double_child(webd_mmdb_t *db, size_t base, size_t map_pos,
                                 const char *key, double *out)
{
    size_t vpos;

    if (!out || !mmdb_map_find(db, base, map_pos, key, &vpos, NULL, 0))
        return 0;
    return mmdb_decode_double(db, base, vpos, out, NULL, 0) == 0;
}

static int mmdb_array_first_map(webd_mmdb_t *db, size_t base, size_t pos,
                                size_t *first_map_pos)
{
    mmdb_ctrl_t ctrl;
    size_t target;

    if (!db || !first_map_pos)
        return 0;
    if (mmdb_read_ctrl(db, pos, &ctrl) != 0)
        return 0;
    if (ctrl.pointer) {
        if (mmdb_pointer_target(db, base, &ctrl, &target) != 0)
            return 0;
        return mmdb_array_first_map(db, base, target, first_map_pos);
    }
    if (ctrl.type != 11 || ctrl.size <= 0)
        return 0;
    *first_map_pos = ctrl.next;
    return 1;
}

static int mmdb_map_name_child(webd_mmdb_t *db, size_t base, size_t map_pos,
                               const char *language, char *out, size_t out_len)
{
    size_t names_pos;

    if (!mmdb_map_find(db, base, map_pos, "names", &names_pos, NULL, 0))
        return 0;
    if (language && language[0] &&
        mmdb_map_string_child(db, base, names_pos, language, out, out_len))
        return 1;
    if (mmdb_map_string_child(db, base, names_pos, "zh-CN", out, out_len))
        return 1;
    if (mmdb_map_string_child(db, base, names_pos, "en", out, out_len))
        return 1;
    return 0;
}

int webd_mmdb_lookup_country(webd_mmdb_t *db, const char *ip, const char *language,
                             webd_mmdb_country_t *out)
{
    size_t record_pos = 0;
    size_t country_pos = 0;
    size_t registered_pos = 0;
    size_t continent_pos = 0;
    int rc;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (!db || !ip || !ip[0])
        return -1;

    rc = mmdb_lookup_record_pos(db, ip, &record_pos);
    if (rc <= 0)
        return rc;

    if (mmdb_map_find(db, db->data_base, record_pos, "country", &country_pos, NULL, 0)) {
        mmdb_map_string_child(db, db->data_base, country_pos, "iso_code",
                              out->country_code, sizeof(out->country_code));
        mmdb_map_name_child(db, db->data_base, country_pos, language,
                            out->country_name, sizeof(out->country_name));
    }
    if (mmdb_map_find(db, db->data_base, record_pos, "registered_country",
                      &registered_pos, NULL, 0)) {
        mmdb_map_string_child(db, db->data_base, registered_pos, "iso_code",
                              out->registered_country_code,
                              sizeof(out->registered_country_code));
        mmdb_map_name_child(db, db->data_base, registered_pos, language,
                            out->registered_country_name,
                            sizeof(out->registered_country_name));
    }
    if (mmdb_map_find(db, db->data_base, record_pos, "continent",
                      &continent_pos, NULL, 0)) {
        mmdb_map_string_child(db, db->data_base, continent_pos, "code",
                              out->continent_code, sizeof(out->continent_code));
        mmdb_map_name_child(db, db->data_base, continent_pos, language,
                            out->continent_name, sizeof(out->continent_name));
    }

    if (!out->country_code[0])
        mmdb_copy(out->country_code, sizeof(out->country_code),
                  out->registered_country_code);
    if (!out->country_name[0])
        mmdb_copy(out->country_name, sizeof(out->country_name),
                  out->registered_country_name);
    out->found = out->country_code[0] != '\0';
    return out->found ? 1 : 0;
}

int webd_mmdb_lookup_city(webd_mmdb_t *db, const char *ip, const char *language,
                          webd_mmdb_city_t *out)
{
    size_t record_pos = 0;
    size_t country_pos = 0;
    size_t registered_pos = 0;
    size_t continent_pos = 0;
    size_t city_pos = 0;
    size_t location_pos = 0;
    size_t subdivisions_pos = 0;
    size_t subdivision_pos = 0;
    uint64_t v = 0;
    int rc;

    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (!db || !ip || !ip[0])
        return -1;

    rc = mmdb_lookup_record_pos(db, ip, &record_pos);
    if (rc <= 0)
        return rc;

    if (mmdb_map_find(db, db->data_base, record_pos, "country", &country_pos, NULL, 0)) {
        mmdb_map_string_child(db, db->data_base, country_pos, "iso_code",
                              out->country_code, sizeof(out->country_code));
        mmdb_map_name_child(db, db->data_base, country_pos, language,
                            out->country_name, sizeof(out->country_name));
    }
    if (mmdb_map_find(db, db->data_base, record_pos, "registered_country",
                      &registered_pos, NULL, 0)) {
        mmdb_map_string_child(db, db->data_base, registered_pos, "iso_code",
                              out->registered_country_code,
                              sizeof(out->registered_country_code));
        mmdb_map_name_child(db, db->data_base, registered_pos, language,
                            out->registered_country_name,
                            sizeof(out->registered_country_name));
    }
    if (mmdb_map_find(db, db->data_base, record_pos, "continent",
                      &continent_pos, NULL, 0)) {
        mmdb_map_string_child(db, db->data_base, continent_pos, "code",
                              out->continent_code, sizeof(out->continent_code));
        mmdb_map_name_child(db, db->data_base, continent_pos, language,
                            out->continent_name, sizeof(out->continent_name));
    }
    if (mmdb_map_find(db, db->data_base, record_pos, "city", &city_pos, NULL, 0))
        mmdb_map_name_child(db, db->data_base, city_pos, language,
                            out->city_name, sizeof(out->city_name));
    if (mmdb_map_find(db, db->data_base, record_pos, "subdivisions",
                      &subdivisions_pos, NULL, 0) &&
        mmdb_array_first_map(db, db->data_base, subdivisions_pos, &subdivision_pos)) {
        mmdb_map_string_child(db, db->data_base, subdivision_pos, "iso_code",
                              out->region_code, sizeof(out->region_code));
        mmdb_map_name_child(db, db->data_base, subdivision_pos, language,
                            out->region_name, sizeof(out->region_name));
    }
    if (mmdb_map_find(db, db->data_base, record_pos, "location", &location_pos, NULL, 0)) {
        double lat = 0.0;
        double lon = 0.0;

        if (mmdb_map_double_child(db, db->data_base, location_pos, "latitude", &lat) &&
            mmdb_map_double_child(db, db->data_base, location_pos, "longitude", &lon)) {
            out->latitude = lat;
            out->longitude = lon;
            out->has_location = 1;
        }
        if (mmdb_map_uint_child(db, db->data_base, location_pos, "accuracy_radius", &v))
            out->accuracy_radius = (int)v;
        mmdb_map_string_child(db, db->data_base, location_pos, "time_zone",
                              out->time_zone, sizeof(out->time_zone));
    }

    if (!out->country_code[0])
        mmdb_copy(out->country_code, sizeof(out->country_code),
                  out->registered_country_code);
    if (!out->country_name[0])
        mmdb_copy(out->country_name, sizeof(out->country_name),
                  out->registered_country_name);
    out->found = out->country_code[0] != '\0' || out->has_location;
    return out->found ? 1 : 0;
}

int webd_mmdb_country_lookup(const char *path, const char *ip, const char *language,
                             webd_mmdb_country_t *out)
{
    webd_mmdb_t *db = NULL;
    int rc;

    rc = webd_mmdb_open(path, &db, NULL, 0);
    if (rc != 0)
        return -1;
    rc = webd_mmdb_lookup_country(db, ip, language, out);
    webd_mmdb_close(db);
    return rc;
}

int webd_mmdb_city_lookup(const char *path, const char *ip, const char *language,
                          webd_mmdb_city_t *out)
{
    webd_mmdb_t *db = NULL;
    int rc;

    rc = webd_mmdb_open(path, &db, NULL, 0);
    if (rc != 0)
        return -1;
    rc = webd_mmdb_lookup_city(db, ip, language, out);
    webd_mmdb_close(db);
    return rc;
}
