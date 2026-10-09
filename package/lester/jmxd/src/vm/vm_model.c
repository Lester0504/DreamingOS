// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Small helpers shared across the VM daemon: the vm.v1 envelope-inner shapes and
 * UUID handling. The outer envelope (ok/meta) is added by webd's gateway; these
 * builders produce the { ok, data|error } body the ubus layer returns so the
 * gateway can forward it with the shape the contract froze.
 */
#include "vm_internal.h"

struct json_object *vm_error_obj(const char *code, const char *message,
                                 struct json_object *details)
{
    struct json_object *root = json_object_new_object();
    struct json_object *err;

    if (!root) {
        json_object_put(details);
        return NULL;
    }
    err = json_object_new_object();
    if (!err) {
        json_object_put(root);
        json_object_put(details);
        return NULL;
    }
    json_object_object_add(err, "code", json_object_new_string(code ? code : "error"));
    json_object_object_add(err, "message",
                           json_object_new_string(message ? message : ""));
    if (details)
        json_object_object_add(err, "details", details);
    json_object_object_add(root, "ok", json_object_new_boolean(0));
    json_object_object_add(root, "error", err);
    return root;
}

struct json_object *vm_data_obj(struct json_object *data)
{
    struct json_object *root = json_object_new_object();

    if (!root) {
        json_object_put(data);
        return NULL;
    }
    if (!data)
        data = json_object_new_object();
    /* schema is a hard invariant of every vm.v1 data payload. Set it here so no
     * individual builder can forget it. */
    if (!json_object_object_get_ex(data, "schema", NULL))
        json_object_object_add(data, "schema", json_object_new_string(VM_SCHEMA));
    json_object_object_add(root, "ok", json_object_new_boolean(1));
    json_object_object_add(root, "data", data);
    return root;
}

bool vm_uuid_valid(const char *s)
{
    int i;

    if (!s)
        return false;
    /* 8-4-4-4-12 lowercase/uppercase hex with dashes. */
    for (i = 0; i < 36; i++) {
        char c = s[i];

        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                     (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return s[36] == '\0';
}

void vm_uuid_generate(char *out /* >=37 */)
{
    FILE *f = fopen("/proc/sys/kernel/random/uuid", "re");
    unsigned char b[16];
    size_t got = 0;

    out[0] = '\0';
    if (f) {
        if (fgets(out, 37, f))
            out[strcspn(out, "\r\n")] = '\0';
        fclose(f);
    }
    if (vm_uuid_valid(out))
        return;
    /* Fallback: build an RFC 4122 v4 UUID straight from the kernel CSPRNG. We do
     * NOT call libvirt's virUUIDGenerate here: those helpers are exported only
     * under the LIBVIRT_PRIVATE_* version node and are absent from the public
     * headers, so linking a consumer against them is fragile across releases. */
    f = fopen("/dev/urandom", "re");
    if (f) {
        got = fread(b, 1, sizeof(b), f);
        fclose(f);
    }
    if (got != sizeof(b)) {
        /* Last resort if /dev/urandom is unavailable: mix monotonic time and pid.
         * Non-cryptographic, but never blocks and never leaves out[] empty. */
        struct timespec ts;
        unsigned seed;
        size_t i;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        seed = (unsigned)ts.tv_nsec ^ ((unsigned)ts.tv_sec << 8) ^
               ((unsigned)getpid() << 16);
        for (i = 0; i < sizeof(b); i++) {
            seed = seed * 1103515245u + 12345u;
            b[i] = (unsigned char)(seed >> 16);
        }
    }
    b[6] = (unsigned char)((b[6] & 0x0f) | 0x40); /* version 4 */
    b[8] = (unsigned char)((b[8] & 0x3f) | 0x80); /* RFC 4122 variant */
    snprintf(out, 37,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}
