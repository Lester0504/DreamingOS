// SPDX-License-Identifier: GPL-2.0-or-later
/* Runtime truth for System -> Web access controls. */
#include "webd_system_web_access.h"
#include "webd_upload_staging.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define WA_NGINX "/etc/nginx/nginx.conf"
#define WA_RESTRICT "/etc/nginx/restrict_locally"
#define WA_CONF "/etc/nginx/conf.d/*.conf"
#define WA_LOCATIONS "/etc/nginx/conf.d/*.locations"
#define WA_CERT "/etc/dreamingwrt/tls/console.crt"
#define WA_PROC "/proc/[0-9]*/cmdline"
#define WA_PID "/var/run/nginx.pid"
#define WA_MAX (256U * 1024U)
#define WA_EXEC "/usr/libexec/dreamingwrt/dreamingwrt-web-access-apply"

struct wa_files { char *nginx, *all, *luci, *restrict_file, *restrict_console; };
struct wa_ports { int http, https, luci, webd, http_ok, https_ok, luci_ok, webd_ok; };

static void wa_str(struct json_object *o, const char *k, const char *v)
{ json_object_object_add(o, k, json_object_new_string(v ? v : "")); }

static char *wa_read(const char *path)
{
    struct stat st;
    int fd;
    char *buf;
    ssize_t n;
    size_t len;

    if (!path || stat(path, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > WA_MAX)
        return NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    len = (size_t)st.st_size;
    buf = calloc(1, len + 1);
    if (!buf) { close(fd); return NULL; }
    n = read(fd, buf, len);
    close(fd);
    if (n < 0 || (size_t)n != len) { free(buf); return NULL; }
    buf[len] = 0;
    return buf;
}

static char *wa_read_cmdline(const char *path)
{
    int fd;
    char *buf;
    ssize_t n;
    size_t i;

    if (!path)
        return NULL;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    buf = calloc(1, 4096);
    if (!buf) {
        close(fd);
        return NULL;
    }
    n = read(fd, buf, 4095);
    close(fd);
    if (n <= 0) {
        free(buf);
        return NULL;
    }
    for (i = 0; i < (size_t)n; i++)
        if (!buf[i])
            buf[i] = ' ';
    buf[n] = 0;
    return buf;
}

static char *wa_concat(const char *pattern)
{
    glob_t g;
    char *out;
    size_t total = 1, used = 0, i;

    memset(&g, 0, sizeof(g));
    if (glob(pattern, 0, NULL, &g))
        return calloc(1, 1);
    for (i = 0; i < g.gl_pathc; i++) {
        struct stat st;
        if (!stat(g.gl_pathv[i], &st) && S_ISREG(st.st_mode))
            total += (size_t)st.st_size + 1;
    }
    if (total > WA_MAX || !(out = calloc(1, total))) {
        globfree(&g);
        return NULL;
    }
    for (i = 0; i < g.gl_pathc; i++) {
        char *part = wa_read(g.gl_pathv[i]);
        size_t len;
        if (!part) continue;
        len = strlen(part);
        memcpy(out + used, part, len);
        used += len;
        out[used++] = '\n';
        free(part);
    }
    out[used] = 0;
    globfree(&g);
    return out;
}

static int wa_load(struct wa_files *f)
{
    glob_t g;
    char *locations;
    size_t i;

    memset(f, 0, sizeof(*f));
    f->nginx = wa_read(WA_NGINX);
    f->restrict_file = wa_read(WA_RESTRICT);
    f->restrict_console = wa_read("/etc/nginx/restrict_console");
    f->all = wa_concat(WA_CONF);
    if (!f->all) f->all = calloc(1, 1);
    locations = wa_concat(WA_LOCATIONS);
    if (locations) {
        size_t old_len = strlen(f->all);
        size_t add_len = strlen(locations);
        char *combined = realloc(f->all, old_len + add_len + 1);

        if (combined) {
            memcpy(combined + old_len, locations, add_len + 1);
            f->all = combined;
        }
        free(locations);
    }
    memset(&g, 0, sizeof(g));
    if (!glob(WA_CONF, 0, NULL, &g)) {
        for (i = 0; i < g.gl_pathc; i++) {
            char *text = wa_read(g.gl_pathv[i]);
            if (!text) continue;
            if (!f->luci && strstr(text, "include conf.d/luci.locations;"))
                f->luci = text;
            else
                free(text);
        }
    }
    globfree(&g);
    return f->nginx != NULL;
}

static void wa_free(struct wa_files *f)
{
    free(f->nginx); free(f->all); free(f->luci); free(f->restrict_file); free(f->restrict_console);
    memset(f, 0, sizeof(*f));
}

static int wa_parse_listen(const char *line, int *port)
{
    const char *p = strstr(line, "listen");
    char *end;
    long n;

    if (!p || (p > line && !isspace((unsigned char)p[-1])) ||
        (p[6] && !isspace((unsigned char)p[6])))
        return 0;
    p += 6;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '[') { p = strchr(p, ']'); if (!p || p[1] != ':') return 0; p++; }
    else if (*p == '*') { p++; if (*p != ':') return 0; }
    if (*p == ':') p++;
    errno = 0;
    n = strtol(p, &end, 10);
    if (errno || end == p || n < 1 || n > 65535) return 0;
    *port = (int)n;
    return 1;
}

static int wa_find(const char *text, const char *needle, int require_ssl, int *port)
{
    const char *p = text;
    while (p && *p) {
        const char *end = strchr(p, '\n');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        char line[1024];
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len); line[len] = 0;
        while (isspace((unsigned char)line[0])) memmove(line, line + 1, strlen(line));
        if (line[0] != '#' && (!needle || strstr(line, needle)) &&
            (!require_ssl || strstr(line, "ssl")) && wa_parse_listen(line, port))
            return 1;
        p = end ? end + 1 : p + strlen(p);
    }
    return 0;
}

static int wa_listener(int port, int *v4, int *v6)
{
    const char *paths[] = { "/proc/net/tcp", "/proc/net/tcp6", NULL };
    int found = 0, i;
    if (v4)
        *v4 = 0;
    if (v6)
        *v6 = 0;
    for (i = 0; paths[i]; i++) {
        FILE *fp = fopen(paths[i], "r");
        char line[512];
        if (!fp) continue;
        while (fgets(line, sizeof(line), fp)) {
            char a[64], b[64], c[64], state[8], *colon, *end;
            unsigned long n;
            if (sscanf(line, "%63s %63s %63s %7s", a, b, c, state) != 4 || strcmp(state, "0A")) continue;
            colon = strrchr(b, ':');
            if (!colon) continue;
            errno = 0; n = strtoul(colon + 1, &end, 16);
            if (errno || end == colon + 1 || n != (unsigned long)port) continue;
            found = 1;
            if (i) { if (v6) *v6 = 1; } else if (v4) *v4 = 1;
        }
        fclose(fp);
    }
    return found;
}

static int wa_webd_port(int *port)
{
    glob_t g;
    size_t i;
    memset(&g, 0, sizeof(g));
    if (glob(WA_PROC, 0, NULL, &g)) return 0;
    for (i = 0; i < g.gl_pathc; i++) {
        char *cmd = wa_read_cmdline(g.gl_pathv[i]), *p, *end;
        if (!cmd || strncmp(cmd, "/usr/bin/dreamingwrt-webd", 25) ||
            (cmd[25] && !isspace((unsigned char)cmd[25]))) {
            free(cmd);
            continue;
        }
        p = cmd + 25;
        while (*p && isspace((unsigned char)*p)) p++;
        errno = 0;
        {
            long n = strtol(p, &end, 10);
            if (!errno && end != p && n > 0 && n <= 65535) {
                *port = (int)n;
                free(cmd);
                globfree(&g);
                return wa_listener(*port, NULL, NULL);
            }
        }
        free(cmd);
    }
    globfree(&g);
    return 0;
}

static int wa_time(const ASN1_TIME *value, int64_t *out)
{
    struct tm tmv;
    if (!value || !out || ASN1_TIME_to_tm(value, &tmv) != 1) return 0;
#if defined(__APPLE__) || defined(__GLIBC__)
    *out = (int64_t)timegm(&tmv);
#else
    *out = (int64_t)mktime(&tmv);
#endif
    return *out > 0;
}

static int wa_certificate(struct json_object *data, const char *path)
{
    struct json_object *c = json_object_new_object();
    BIO *bio = path && path[0] ? BIO_new_file(path, "r") : NULL;
    X509 *x = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    char *subject = NULL;
    int64_t expires = 0;
    size_t i;
    if (bio) BIO_free(bio);
    json_object_object_add(c, "available", json_object_new_boolean(1));
    json_object_object_add(c, "configured", json_object_new_boolean(0));
    wa_str(c, "subject", ""); json_object_object_add(c, "expires_at", json_object_new_int64(0));
    wa_str(c, "fingerprint", ""); wa_str(c, "reason", "certificate_not_configured");
    if (!x || !wa_time(X509_get0_notAfter(x), &expires) || X509_digest(x, EVP_sha256(), digest, &digest_len) != 1 || digest_len != 32 || !(subject = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0))) {
        wa_str(c, "reason", "certificate_read_failed");
        if (subject)
            OPENSSL_free(subject);
        if (x)
            X509_free(x);
        json_object_object_add(data, "ssl_certificate", c); return 0;
    }
    json_object_object_add(c, "configured", json_object_new_boolean(1));
    wa_str(c, "subject", subject); json_object_object_add(c, "expires_at", json_object_new_int64(expires));
    {
        char fp[3 * 32];
        memset(fp, 0, sizeof(fp));
        for (i = 0; i < 32; i++) snprintf(fp + i * 3, sizeof(fp) - i * 3, i == 31 ? "%02X" : "%02X:", digest[i]);
        wa_str(c, "fingerprint", fp);
    }
    wa_str(c, "reason", ""); OPENSSL_free(subject); X509_free(x);
    json_object_object_add(data, "ssl_certificate", c);
    return 1;
}

static int wa_certificate_path(const char *text, char *out, size_t out_len)
{
    const char *p = text;

    if (!out || out_len == 0)
        return 0;
    out[0] = 0;
    while (p && *p) {
        const char *end = strchr(p, '\n');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        char line[1024];
        char *value;
        char *stop;

        if (len >= sizeof(line))
            len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = 0;
        while (isspace((unsigned char)line[0]))
            memmove(line, line + 1, strlen(line));
        if (line[0] != '#' && !strncmp(line, "ssl_certificate", 15) &&
            isspace((unsigned char)line[15])) {
            value = line + 15;
            while (isspace((unsigned char)*value))
                value++;
            stop = value;
            while (*stop && !isspace((unsigned char)*stop) && *stop != ';')
                stop++;
            if (stop != value) {
                size_t value_len = (size_t)(stop - value);
                if (value_len < out_len) {
                    memcpy(out, value, value_len);
                    out[value_len] = 0;
                    return 1;
                }
            }
        }
        p = end ? end + 1 : p + strlen(p);
    }
    return 0;
}

static void wa_state(struct json_object *states, const char *field, int available, const char *reason)
{
    struct json_object *s = json_object_new_object();
    json_object_object_add(s, "available", json_object_new_boolean(available));
    wa_str(s, "reason", reason); json_object_object_add(states, field, s);
}

static int wa_executor_ready(void)
{
    return access(WA_EXEC, X_OK) == 0;
}

static int wa_nginx_control_ready(void)
{
    char *pid_text = wa_read(WA_PID);
    char path[64], *cmd;
    char *end;
    long pid;

    if (!pid_text)
        return 0;
    errno = 0;
    pid = strtol(pid_text, &end, 10);
    if (errno || end == pid_text || pid <= 1 || pid > 4194304) {
        free(pid_text);
        return 0;
    }
    free(pid_text);
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
    cmd = wa_read_cmdline(path);
    if (!cmd)
        return 0;
    if (!strstr(cmd, "nginx: master process") &&
        !strstr(cmd, "/usr/sbin/nginx -c")) {
        free(cmd);
        return 0;
    }
    free(cmd);
    return 1;
}

static void wa_capabilities(struct json_object *data)
{
    struct json_object *c = json_object_new_object(), *r = json_object_new_object();
    int executor_ready = wa_executor_ready();
    int control_ready = executor_ready && wa_nginx_control_ready();
    const char *reason = !executor_ready ? "write_executor_unavailable" :
                         (control_ready ? "" : "nginx_control_unavailable");

    json_object_object_add(c, "force_https_write", json_object_new_boolean(control_ready));
    json_object_object_add(c, "http_port_write", json_object_new_boolean(control_ready));
    json_object_object_add(c, "https_port_write", json_object_new_boolean(control_ready));
    json_object_object_add(c, "ssl_certificate_upload", json_object_new_boolean(control_ready));
    json_object_object_add(c, "external_access_write", json_object_new_boolean(control_ready));
    wa_str(r, "force_https_write", reason); wa_str(r, "http_port_write", reason);
    wa_str(r, "https_port_write", reason); wa_str(r, "external_access_write", reason);
    wa_str(r, "ssl_certificate_upload", reason);
    json_object_object_add(c, "reasons", r);
    wa_str(c, "executor", executor_ready ? "web_access_apply_v1" : "");
    json_object_object_add(c, "executor_available", json_object_new_boolean(executor_ready));
    json_object_object_add(c, "nginx_control_available", json_object_new_boolean(control_ready));
    json_object_object_add(data, "capabilities", c);
}

struct json_object *webd_system_web_access_data(int *http_status)
{
    struct wa_files f; struct wa_ports p; struct json_object *d, *states, *listener;
    int config_ok, restricted, cert_ok, v4 = 0, v6 = 0;
    const char *external_mode;
    char cert_path[PATH_MAX];
    memset(&p, 0, sizeof(p)); d = json_object_new_object(); states = json_object_new_object();
    config_ok = wa_load(&f) == 1;
    if (config_ok) {
        p.http_ok = wa_find(f.nginx, "default_server", 0, &p.http);
        p.https_ok = wa_find(f.all, NULL, 1, &p.https);
        p.luci_ok = wa_find(f.luci, NULL, 0, &p.luci);
    }
    p.webd_ok = wa_webd_port(&p.webd);
    restricted = f.restrict_file && f.all &&
                (strstr(f.all, "restrict_locally") || strstr(f.all, "restrict_console"));
    external_mode = NULL;
    if (f.restrict_console && strstr(f.all, "include restrict_console;")) {
        if (strstr(f.restrict_console, "allow ::/0;") &&
            strstr(f.restrict_console, "allow 0.0.0.0/0;"))
            external_mode = "dual";
        else if (strstr(f.restrict_console, "allow 0.0.0.0/0;"))
            external_mode = "ipv4";
        else if (strstr(f.restrict_console, "allow ::/0;"))
            external_mode = "ipv6";
        else
            external_mode = "disabled";
    } else if (restricted) {
        external_mode = "disabled";
    }
    if (config_ok)
        json_object_object_add(d, "force_https", json_object_new_boolean(
            (strstr(f.nginx, "return 301 https") || strstr(f.nginx, "return 302 https")) ||
            (strstr(f.all, "return 301 https") || strstr(f.all, "return 302 https"))));
    else
        json_object_object_add(d, "force_https", NULL);
    json_object_object_add(d, "http_port", p.http_ok ? json_object_new_int(p.http) : NULL);
    json_object_object_add(d, "https_port", p.https_ok ? json_object_new_int(p.https) : NULL);
    json_object_object_add(d, "luci_port", p.luci_ok ? json_object_new_int(p.luci) : NULL);
    json_object_object_add(d, "webd_internal_port", p.webd_ok ? json_object_new_int(p.webd) : NULL);
    wa_state(states, "force_https", config_ok, config_ok ? "" : "nginx_config_unavailable");
    wa_state(states, "http_port", p.http_ok, p.http_ok ? "" : "http_console_listener_unavailable");
    wa_state(states, "https_port", p.https_ok, p.https_ok ? "" : "https_console_listener_unavailable");
    wa_state(states, "luci_port", p.luci_ok, p.luci_ok ? "" : "luci_listener_unavailable");
    wa_state(states, "webd_internal_port", p.webd_ok, p.webd_ok ? "" : "webd_listener_unavailable");
    wa_state(states, "external_access", restricted, restricted ? "" : "external_access_policy_not_explicit");
    json_object_object_add(d, "field_state", states);
    if (p.http_ok) wa_listener(p.http, &v4, &v6);
    listener = json_object_new_object(); json_object_object_add(listener, "active", json_object_new_boolean(v4 || v6));
    json_object_object_add(listener, "ipv4", json_object_new_boolean(v4)); json_object_object_add(listener, "ipv6", json_object_new_boolean(v6)); json_object_object_add(d, "http_listener", listener);
    if (external_mode)
        wa_str(d, "external_access", external_mode);
    else
        json_object_object_add(d, "external_access", NULL);
    json_object_object_add(d, "external_access_available",
                           json_object_new_boolean(restricted || f.restrict_console));
    cert_path[0] = 0;
    cert_ok = wa_certificate_path(f.all, cert_path, sizeof(cert_path));
    cert_ok = wa_certificate(d, cert_ok ? cert_path : NULL);
    wa_state(states, "ssl_certificate", cert_ok,
             cert_ok ? "" : (cert_path[0] ? "certificate_read_failed" :
             "certificate_path_unavailable"));
    wa_capabilities(d); wa_str(d, "runtime_source", "active_nginx_proc_and_tls"); wa_free(&f);
    if (http_status)
        *http_status = 200;
    return d;
}

static struct json_object *wa_error(const char *code, const char *message, const char *field, int status)
{
    struct json_object *r = json_object_new_object(), *e = json_object_new_object(), *d = json_object_new_object();
    json_object_object_add(r, "ok", json_object_new_boolean(0)); wa_str(e, "code", code); wa_str(e, "message", message);
    if (field)
        wa_str(d, "field", field);
    json_object_object_add(e, "details", d);
    json_object_object_add(r, "error", e);
    json_object_object_add(r, "http_status", json_object_new_int(status));
    return r;
}

static int wa_port(struct json_object *body, const char *key, int *out)
{
    struct json_object *v = NULL; int64_t n;
    if (!json_object_object_get_ex(body, key, &v)) return 0;
    if (!v || !json_object_is_type(v, json_type_int)) return -1;
    n = json_object_get_int64(v); if (n < 1 || n > 65535) return -1; *out = (int)n; return 1;
}

static struct json_object *wa_exec_result(const char *cmdline)
{
    FILE *fp;
    char buf[16384];
    size_t n;
    struct json_tokener *tok;
    struct json_object *obj;
    enum json_tokener_error jerr;

    if (!cmdline)
        return NULL;
    fp = popen(cmdline, "r");
    if (!fp)
        return NULL;
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = 0;
    while (fgetc(fp) != EOF) {}
    pclose(fp);
    tok = json_tokener_new();
    if (!tok)
        return NULL;
    obj = json_tokener_parse_ex(tok, buf, n);
    jerr = json_tokener_get_error(tok);
    json_tokener_free(tok);
    if (jerr != json_tokener_success || !obj) {
        if (obj)
            json_object_put(obj);
        return NULL;
    }
    return obj;
}

static const char *wa_child_str(struct json_object *parent, const char *key,
                                const char *fallback)
{
    struct json_object *v = NULL;
    if (parent && json_object_object_get_ex(parent, key, &v) &&
        json_object_is_type(v, json_type_string))
        return json_object_get_string(v);
    return fallback;
}

static int wa_current_int(struct json_object *current, const char *key, int fallback)
{
    struct json_object *v = NULL;
    if (current && json_object_object_get_ex(current, key, &v) &&
        json_object_is_type(v, json_type_int))
        return json_object_get_int(v);
    return fallback;
}

static int wa_current_bool(struct json_object *current, const char *key, int fallback)
{
    struct json_object *v = NULL;
    if (current && json_object_object_get_ex(current, key, &v) &&
        json_object_is_type(v, json_type_boolean))
        return json_object_get_boolean(v) ? 1 : 0;
    return fallback;
}

static int wa_reserved_port(int port)
{
    return port == 12517 || port == 12518 || port == 11504;
}

static int wa_exec_status(const char *code)
{
    if (!code || !code[0])
        return 500;
    if (!strncmp(code, "invalid_", 8) || !strcmp(code, "missing_field") ||
        !strcmp(code, "certificate_upload_invalid") ||
        !strcmp(code, "certificate_parse_failed") ||
        !strcmp(code, "private_key_parse_failed") ||
        !strcmp(code, "private_key_mismatch") ||
        !strcmp(code, "certificate_expired"))
        return 400;
    if (!strcmp(code, "port_conflict") || !strcmp(code, "port_in_use"))
        return 409;
    return 500;
}

static struct json_object *wa_write_error(struct json_object *current,
                                          struct json_object *details,
                                          const char *code,
                                          const char *message,
                                          const char *field,
                                          int status)
{
    struct json_object *r = wa_error(code, message, field, status);
    if (current)
        json_object_object_add(r, "data", current);
    if (details)
        json_object_object_add(r, "error_details", details);
    return r;
}

static struct json_object *wa_write_ok(struct json_object *current,
                                       const char *backup)
{
    struct json_object *r = json_object_new_object();
    json_object_object_add(r, "ok", json_object_new_boolean(1));
    json_object_object_add(r, "data", current ? current : json_object_new_object());
    if (backup && backup[0])
        wa_str(r, "backup", backup);
    wa_str(r, "executor", "web_access_apply_v1");
    return r;
}

static int wa_child_bool(struct json_object *parent, const char *key)
{
    struct json_object *v = NULL;
    return parent && json_object_object_get_ex(parent, key, &v) &&
           json_object_is_type(v, json_type_boolean) &&
           json_object_get_boolean(v);
}

static const char *wa_error_child(struct json_object *exec_out, const char *key,
                                  const char *fallback)
{
    struct json_object *e = NULL;
    if (exec_out && json_object_object_get_ex(exec_out, "error", &e) && e)
        return wa_child_str(e, key, fallback);
    return fallback;
}

static const char *wa_error_field(struct json_object *exec_out, const char *fallback)
{
    struct json_object *e = NULL, *d = NULL;
    if (exec_out && json_object_object_get_ex(exec_out, "error", &e) && e &&
        json_object_object_get_ex(e, "details", &d) && d)
        return wa_child_str(d, "field", fallback);
    return fallback;
}

static struct json_object *wa_apply_executor(struct json_object *body,
                                             struct json_object *current,
                                             struct json_object *details,
                                             int *http_status)
{
    struct json_object *value = NULL, *force_value = NULL, *http_value = NULL;
    struct json_object *https_value = NULL, *exec_out, *r;
    const char *mode;
    int force_https, http_port, https_port, have_fh, have_hp, have_sp;
    char cmd[2048];

    force_https = wa_current_bool(current, "force_https", 0);
    http_port = wa_current_int(current, "http_port", 80);
    https_port = wa_current_int(current, "https_port", 443);
    mode = wa_child_str(current, "external_access", "disabled");
    have_fh = json_object_object_get_ex(body, "force_https", &force_value);
    have_hp = json_object_object_get_ex(body, "http_port", &http_value);
    have_sp = json_object_object_get_ex(body, "https_port", &https_value);
    if (have_fh) {
        if (!json_object_is_type(force_value, json_type_boolean)) {
            *http_status = 400;
            return wa_write_error(current, details, "invalid_boolean",
                                  "force_https must be a boolean", "force_https", 400);
        }
        force_https = json_object_get_boolean(force_value) ? 1 : 0;
    }
    if (have_hp || have_sp) {
        int hp = 0, sp = 0;
        if (have_hp) {
            if (!json_object_is_type(http_value, json_type_int) ||
                json_object_get_int64(http_value) < 1 ||
                json_object_get_int64(http_value) > 65535) {
                *http_status = 400;
                return wa_write_error(current, details, "invalid_port",
                                      "port must be an integer from 1 through 65535",
                                      "http_port", 400);
            }
            hp = (int)json_object_get_int64(http_value);
            if (wa_reserved_port(hp)) {
                *http_status = 400;
                return wa_write_error(current, details, "reserved_port",
                                      "port is reserved for another DreamingWrt service",
                                      "http_port", 400);
            }
        }
        if (have_sp) {
            if (!json_object_is_type(https_value, json_type_int) ||
                json_object_get_int64(https_value) < 1 ||
                json_object_get_int64(https_value) > 65535) {
                *http_status = 400;
                return wa_write_error(current, details, "invalid_port",
                                      "port must be an integer from 1 through 65535",
                                      "https_port", 400);
            }
            sp = (int)json_object_get_int64(https_value);
            if (wa_reserved_port(sp)) {
                *http_status = 400;
                return wa_write_error(current, details, "reserved_port",
                                      "port is reserved for another DreamingWrt service",
                                      "https_port", 400);
            }
        }
        if (have_hp)
            http_port = hp;
        if (have_sp)
            https_port = sp;
        if (http_port == https_port) {
            *http_status = 409;
            return wa_write_error(current, details, "port_conflict",
                                  "HTTP and HTTPS ports must be different",
                                  "https_port", 409);
        }
    }
    if (json_object_object_get_ex(body, "external_access", &value)) {
        if (!json_object_is_type(value, json_type_string)) {
            *http_status = 400;
            return wa_write_error(current, details, "invalid_external_access",
                                  "external_access must be one of disabled, ipv4, ipv6, dual",
                                  "external_access", 400);
        }
        mode = json_object_get_string(value);
        if (strcmp(mode, "disabled") && strcmp(mode, "ipv4") &&
            strcmp(mode, "ipv6") && strcmp(mode, "dual")) {
            *http_status = 400;
            return wa_write_error(current, details, "invalid_external_access",
                                  "external_access must be one of disabled, ipv4, ipv6, dual",
                                  "external_access", 400);
        }
    }
    if (!wa_executor_ready()) {
        *http_status = 501;
        return wa_write_error(current, details, "capability_disabled",
                              "web access executor is not deployed",
                              "system.web_access.write", 501);
    }
    if (!wa_nginx_control_ready()) {
        *http_status = 503;
        return wa_write_error(current, details, "nginx_control_unavailable",
                              "nginx master process is not controllable; refusing to change web access config",
                              "system.web_access.write", 503);
    }
    snprintf(cmd, sizeof(cmd),
             "%s apply --force-https %d --http-port %d --https-port %d "
             "--external-access %s 2>/dev/null",
             WA_EXEC, force_https, http_port, https_port, mode);
    exec_out = wa_exec_result(cmd);
    if (!exec_out) {
        *http_status = 500;
        return wa_write_error(current, details, "executor_unavailable",
                              "web access executor did not return a result",
                              "system.web_access.write", 500);
    }
    if (!wa_child_bool(exec_out, "ok")) {
        const char *code = wa_error_child(exec_out, "code", "web_access_apply_failed");
        const char *message = wa_error_child(exec_out, "message",
                                             "web access apply failed");
        *http_status = wa_exec_status(code);
        r = wa_write_error(current, details, code, message,
                           wa_error_field(exec_out, ""), *http_status);
        json_object_put(exec_out);
        return r;
    }
    r = wa_write_ok(webd_system_web_access_data(NULL),
                    wa_child_str(exec_out, "backup", ""));
    json_object_put(exec_out);
    *http_status = 200;
    return r;
}

static struct json_object *wa_certificate_executor(struct json_object *body,
                                                   const char *owner_id,
                                                   struct json_object *current,
                                                   struct json_object *details,
                                                   int *http_status)
{
    struct json_object *value = NULL, *exec_out, *r;
    const char *upload_id = NULL;
    char err[160] = "";
    char tmp[64] = "/tmp/wa-cert-XXXXXX";
    int src = -1, dst = -1;
    struct webd_upload_meta upload_meta;
    char cmd[1024];
    char buf[65536];
    ssize_t n;
    int cert_delete = 0;

    if (json_object_object_get_ex(body, "ssl_certificate_delete", &value)) {
        if (!json_object_is_type(value, json_type_boolean) ||
            !json_object_get_boolean(value)) {
            *http_status = 400;
            return wa_write_error(current, details, "invalid_certificate_delete",
                                  "ssl_certificate_delete must be true",
                                  "ssl_certificate_delete", 400);
        }
        cert_delete = 1;
    }
    if (json_object_object_get_ex(body, "ssl_certificate_upload", &value)) {
        if (!json_object_is_type(value, json_type_object)) {
            *http_status = 415;
            return wa_write_error(current, details,
                                  "certificate_upload_requires_opaque_upload",
                                  "certificate upload requires an opaque finalized upload_id",
                                  "ssl_certificate_upload", 415);
        }
        upload_id = wa_child_str(value, "upload_id", "");
        if (!upload_id || !upload_id[0]) {
            *http_status = 400;
            return wa_write_error(current, details, "certificate_upload_id_required",
                                  "ssl_certificate_upload.upload_id is required",
                                  "ssl_certificate_upload", 400);
        }
    }
    if (cert_delete && upload_id) {
        *http_status = 400;
        return wa_write_error(current, details,
                              "certificate_patch_must_be_exclusive",
                              "certificate upload and reset cannot be combined",
                              "ssl_certificate", 400);
    }
    if (!cert_delete && !upload_id) {
        *http_status = 400;
        return wa_write_error(current, details,
                              "certificate_patch_requires_upload_or_delete",
                              "ssl_certificate_upload.upload_id or ssl_certificate_delete is required",
                              "ssl_certificate", 400);
    }
    if (!wa_executor_ready()) {
        *http_status = 501;
        return wa_write_error(current, details, "capability_disabled",
                              "web access executor is not deployed",
                              "ssl_certificate_upload", 501);
    }
    if (!wa_nginx_control_ready()) {
        *http_status = 503;
        return wa_write_error(current, details, "nginx_control_unavailable",
                              "nginx master process is not controllable; refusing to change the TLS certificate",
                              "ssl_certificate_upload", 503);
    }
    if (!cert_delete) {
        if (!owner_id || !owner_id[0]) {
            *http_status = 500;
            return wa_write_error(current, details, "certificate_owner_unavailable",
                                  "authenticated owner identity is unavailable",
                                  "ssl_certificate_upload", 500);
        }
        memset(&upload_meta, 0, sizeof(upload_meta));
        if (webd_upload_get(owner_id, upload_id, &upload_meta, err, sizeof(err)) != 0 ||
            strcmp(upload_meta.status, "finalized") ||
            strcmp(upload_meta.upload_type, "ssl-certificate")) {
            *http_status = 404;
            return wa_write_error(current, details,
                                  err[0] ? err : "certificate_upload_unavailable",
                                  "finalized ssl-certificate upload is not readable",
                                  "ssl_certificate_upload", 404);
        }
        src = webd_upload_open_final_readonly(owner_id, upload_id, err, sizeof(err));
        if (src < 0) {
            *http_status = 404;
            return wa_write_error(current, details,
                                  err[0] ? err : "certificate_upload_unavailable",
                                  "finalized certificate upload is not readable",
                                  "ssl_certificate_upload", 404);
        }
        dst = mkstemp(tmp);
        if (dst < 0) {
            close(src);
            *http_status = 500;
            return wa_write_error(current, details, "certificate_staging_failed",
                                  "could not stage certificate upload",
                                  "ssl_certificate_upload", 500);
        }
        if (lseek(src, 0, SEEK_SET) < 0) {
            close(src); close(dst); unlink(tmp);
            *http_status = 500;
            return wa_write_error(current, details, "certificate_staging_failed",
                                  "could not read certificate upload",
                                  "ssl_certificate_upload", 500);
        }
        for (;;) {
            n = read(src, buf, sizeof(buf));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                break;
            if (write(dst, buf, (size_t)n) != n) {
                n = -1;
                break;
            }
        }
        close(src); close(dst);
        if (n < 0) {
            unlink(tmp);
            *http_status = 500;
            return wa_write_error(current, details, "certificate_staging_failed",
                                  "could not copy certificate upload",
                                  "ssl_certificate_upload", 500);
        }
        snprintf(cmd, sizeof(cmd), "%s certificate-install %s 2>/dev/null",
                 WA_EXEC, tmp);
    } else {
        snprintf(cmd, sizeof(cmd), "%s certificate-reset 2>/dev/null", WA_EXEC);
    }
    exec_out = wa_exec_result(cmd);
    if (tmp[0] == '/')
        unlink(tmp);
    if (!exec_out) {
        *http_status = 500;
        return wa_write_error(current, details, "executor_unavailable",
                              "web access executor did not return a result",
                              "ssl_certificate", 500);
    }
    if (!wa_child_bool(exec_out, "ok")) {
        const char *code = wa_error_child(exec_out, "code", "certificate_apply_failed");
        const char *message = wa_error_child(exec_out, "message",
                                             "certificate apply failed");
        *http_status = wa_exec_status(code);
        r = wa_write_error(current, details, code, message,
                           wa_error_field(exec_out, "ssl_certificate"), *http_status);
        json_object_put(exec_out);
        return r;
    }
    r = wa_write_ok(webd_system_web_access_data(NULL),
                    wa_child_str(exec_out, "backup", ""));
    json_object_put(exec_out);
    *http_status = 200;
    return r;
}

struct json_object *webd_system_web_access_write(struct json_object *body,
                                                 const char *owner_id,
                                                 int *http_status)
{
    static const char *known[] = {
        "force_https", "http_port", "https_port", "external_access",
        "ssl_certificate", "ssl_certificate_upload", "custom_ssl_certificate",
        "ssl_certificate_delete", "private_key", "certificate", "key", NULL
    };
    struct json_object *current = NULL, *details, *fields, *r;
    int certificate_only = 0;
    size_t i;

    if (http_status)
        *http_status = 400;
    if (!body || !json_object_is_type(body, json_type_object))
        return wa_error("invalid_payload", "web access patch must be a JSON object",
                        "body", 400);
    if (!json_object_object_length(body))
        return wa_error("empty_patch", "web access patch must contain at least one field",
                        "body", 400);
    {
    json_object_object_foreach(body, key, value) {
        int found = 0;
        for (i = 0; known[i]; i++)
            if (!strcmp(key, known[i])) { found = 1; break; }
        if (!found)
            return wa_error("invalid_field", "field is not part of the web access contract",
                            key, 400);
        if (!strcmp(key, "private_key") || !strcmp(key, "key"))
            return wa_error("private_key_json_forbidden",
                            "private key material is not accepted in ordinary JSON",
                            key, 400);
        if (!strcmp(key, "custom_ssl_certificate"))
            return wa_error("certificate_upload_requires_multipart",
                            "certificate upload requires an opaque upload transaction",
                            key, 415);
        if (!strcmp(key, "ssl_certificate_upload") ||
            !strcmp(key, "ssl_certificate_delete") ||
            !strcmp(key, "ssl_certificate"))
            certificate_only = 1;
    }
    }
    current = webd_system_web_access_data(NULL);
    if (!current)
        current = json_object_new_object();
    details = json_object_new_object();
    fields = json_object_new_array();
    {
    json_object_object_foreach(body, key, value)
        json_object_array_add(fields, json_object_new_string(key));
    }
    json_object_object_add(details, "fields", fields);
    wa_str(details, "executor", "web_access_apply_v1");

    if (certificate_only) {
        size_t other = 0;
        json_object_object_foreach(body, key, value) {
            if (strcmp(key, "ssl_certificate_upload") &&
                strcmp(key, "ssl_certificate_delete") &&
                strcmp(key, "ssl_certificate"))
                other++;
        }
        if (other > 0) {
            *http_status = 400;
            return wa_write_error(current, details,
                                  "certificate_patch_must_be_exclusive",
                                  "certificate operations cannot be combined with other fields",
                                  "ssl_certificate", 400);
        }
        return wa_certificate_executor(body, owner_id, current, details, http_status);
    }
    return wa_apply_executor(body, current, details, http_status);
}
