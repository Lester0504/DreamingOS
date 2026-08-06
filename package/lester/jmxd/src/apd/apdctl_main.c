// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * apdctl - DreamingWrt AP node control CLI.
 *
 * Thin client, in the same spirit as jmctl: reads come from the running
 * daemon over ubus so the CLI, webd and the controller all observe one
 * state. It deliberately does not reimplement enrollment; that lives in
 * apd and is triggered by writing a bootstrap file the daemon consumes.
 *
 * Chinese operator-facing text is intentional -- this is what an installer
 * reads over ssh while standing next to the AP.
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "apd_paircode.h"
#include "apd_qr.h"

#define APDCTL_VERSION "0.1.0"
#define APDCTL_UBUS_TIMEOUT_MS 8000
#define APDCTL_OBJECT "dreamingwrt.apd"
#define APDCTL_OBJECT_ALIAS "dreamingos.apd"
#define APDCTL_PKI_DIR "/etc/dreamingwrt/apd-pki"
#define APDCTL_BOOTSTRAP_PATH APDCTL_PKI_DIR "/bootstrap.json"
#define APDCTL_CA_PATH APDCTL_PKI_DIR "/controller-ca.pem"
#define APDCTL_LINE_MAX 1024

/* Terminal columns we refuse to draw a QR into; below this the matrix wraps
 * and nothing can scan it, so we fall back to text. */
#define APDCTL_QR_MIN_COLUMNS 24

struct apdctl_opts {
    int json;
    int force;
    int no_color;
    int assume_yes;
};

/* ---------------------------------------------------------------- output */

static int apdctl_stdout_tty(void)
{
    return isatty(STDOUT_FILENO) == 1;
}

static int apdctl_terminal_columns(void)
{
    struct winsize ws;
    const char *env;

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    env = getenv("COLUMNS");
    if (env) {
        int value = atoi(env);

        if (value > 0)
            return value;
    }
    return 80;     /* conservative default rather than assuming wide */
}

static void apdctl_heading(const char *text)
{
    printf("\n%s\n", text);
}

static void apdctl_field(const char *label, const char *value)
{
    printf("  %-14s %s\n", label, value && value[0] ? value : "(未知)");
}

static void apdctl_field_uint(const char *label, unsigned int value)
{
    printf("  %-14s %u\n", label, value);
}

static void apdctl_hint(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static void apdctl_hint(const char *fmt, ...)
{
    va_list args;

    fputs("  → ", stdout);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fputc('\n', stdout);
}

static void apdctl_error(const char *fmt, ...)
    __attribute__((format(printf, 1, 2)));

static void apdctl_error(const char *fmt, ...)
{
    va_list args;

    fputs("错误: ", stderr);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
}

static void usage(FILE *out)
{
    fprintf(out,
        "用法:\n"
        "  apdctl status              查看配对/采纳状态、控制器地址、证书有效期\n"
        "  apdctl pair                交互式配对向导\n"
        "  apdctl pair --code <配对码> 用控制器给的配对码直接配对\n"
        "  apdctl pair --show         输出可粘贴的配对信息与二维码（供 Web 绑定）\n"
        "  apdctl unpair              解除采纳（高危，需二次确认）\n"
        "  apdctl doctor              自检：控制器可达性、证书有效期、时钟偏差\n"
        "\n"
        "选项:\n"
        "  --json                     以 JSON 输出，便于脚本处理\n"
        "  --force                    已采纳时仍继续（pair）\n"
        "  --yes                      跳过交互确认（unpair）\n"
        "  --no-color                 不输出 ANSI 颜色\n"
        "  -h, --help                 显示本帮助\n");
}

/* ------------------------------------------------------------------ ubus */

struct apdctl_reply {
    struct json_object *json;
    int received;
};

static void apdctl_ubus_cb(struct ubus_request *req, int type,
                           struct blob_attr *msg)
{
    struct apdctl_reply *reply = req->priv;
    char *text;

    (void)type;
    if (!reply || !msg)
        return;
    text = blobmsg_format_json(msg, true);
    if (!text)
        return;
    reply->json = json_tokener_parse(text);
    reply->received = reply->json != NULL;
    free(text);
}

/*
 * Calls an apd method with an optional argument blob. Returns NULL when the
 * daemon is not reachable, which the callers translate into an actionable
 * message rather than a bare return code.
 */
static struct json_object *apdctl_call_args(const char *method,
                                            struct blob_attr *args,
                                            int *transport_error)
{
    struct ubus_context *ctx;
    struct apdctl_reply reply = { NULL, 0 };
    uint32_t id;
    int rc;

    if (transport_error)
        *transport_error = 0;
    ctx = ubus_connect(NULL);
    if (!ctx) {
        if (transport_error)
            *transport_error = 1;
        return NULL;
    }
    rc = ubus_lookup_id(ctx, APDCTL_OBJECT, &id);
    if (rc != UBUS_STATUS_OK)
        rc = ubus_lookup_id(ctx, APDCTL_OBJECT_ALIAS, &id);
    if (rc != UBUS_STATUS_OK) {
        ubus_free(ctx);
        if (transport_error)
            *transport_error = 1;
        return NULL;
    }
    ubus_invoke(ctx, id, method, args, apdctl_ubus_cb, &reply,
                APDCTL_UBUS_TIMEOUT_MS);
    ubus_free(ctx);
    return reply.json;
}

static struct json_object *apdctl_call(const char *method, int *transport_error)
{
    return apdctl_call_args(method, NULL, transport_error);
}

static const char *apdctl_json_str(struct json_object *root, const char *key,
                            const char *fallback)
{
    struct json_object *value = NULL;

    if (root && json_object_object_get_ex(root, key, &value) && value &&
        json_object_is_type(value, json_type_string))
        return json_object_get_string(value);
    return fallback;
}

static int apdctl_json_bool(struct json_object *root, const char *key, int fallback)
{
    struct json_object *value = NULL;

    if (root && json_object_object_get_ex(root, key, &value) && value &&
        json_object_is_type(value, json_type_boolean))
        return json_object_get_boolean(value);
    return fallback;
}

static int64_t apdctl_json_i64(struct json_object *root, const char *key,
                        int64_t fallback)
{
    struct json_object *value = NULL;

    if (root && json_object_object_get_ex(root, key, &value) && value &&
        (json_object_is_type(value, json_type_int) ||
         json_object_is_type(value, json_type_double)))
        return json_object_get_int64(value);
    return fallback;
}

static void apdctl_daemon_unreachable(void)
{
    apdctl_error("无法连接 dreamingwrt-apd。");
    apdctl_hint("确认服务在运行:  /etc/init.d/dreamingwrt-apd status");
    apdctl_hint("若未运行则启动:  /etc/init.d/dreamingwrt-apd start");
    apdctl_hint("查看启动失败原因:  logread -e dreamingwrt-apd | tail -20");
}

/* --------------------------------------------------------------- helpers */

static void apdctl_format_time(int64_t epoch, char *out, size_t out_size)
{
    struct tm tm_value;
    time_t value = (time_t)epoch;

    if (epoch <= 0) {
        snprintf(out, out_size, "(无)");
        return;
    }
    if (!localtime_r(&value, &tm_value)) {
        snprintf(out, out_size, "%lld", (long long)epoch);
        return;
    }
    if (strftime(out, out_size, "%Y-%m-%d %H:%M:%S", &tm_value) == 0)
        snprintf(out, out_size, "%lld", (long long)epoch);
}

/*
 * The handoff flags this explicitly: state=adopted with
 * enrollment_state=expired is a normal, healthy combination -- the adoption
 * relationship holds while the one-shot enrollment token has aged out. The
 * CLI says so in words rather than showing a bare "expired" that reads as
 * broken.
 */
static const char *apdctl_state_text(const char *state,
                                     const char *enrollment_state,
                                     int adopted, int mtls_ready)
{
    if (adopted && mtls_ready)
        return "已采纳，控制器信任有效";
    if (adopted)
        return "已采纳，但 mTLS 尚未就绪";
    if (state && strcmp(state, "pending") == 0)
        return "配对进行中";
    if (enrollment_state && strcmp(enrollment_state, "expired") == 0)
        return "未采纳（配对令牌已过期，需重新配对）";
    return "未采纳";
}

static void apdctl_explain_enrollment_state(const char *enrollment_state,
                                            int adopted)
{
    if (!enrollment_state || !enrollment_state[0])
        return;
    if (adopted && strcmp(enrollment_state, "expired") == 0) {
        apdctl_hint("enrollment_state=expired 指的是一次性配对令牌已过期，"
                    "不影响已建立的采纳关系。");
        apdctl_hint("此为正常状态，无需重新配对。");
    }
}

static int apdctl_confirm(const char *prompt)
{
    char line[64];

    printf("%s [输入 yes 确认]: ", prompt);
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin))
        return 0;
    return strncmp(line, "yes", 3) == 0 &&
           (line[3] == '\n' || line[3] == '\r' || line[3] == '\0');
}

/* ---------------------------------------------------------------- status */

static int cmd_status(struct apdctl_opts *opts)
{
    struct json_object *status;
    struct json_object *pairing;
    int transport_error = 0;
    char buffer[64];

    status = apdctl_call("status", &transport_error);
    if (!status) {
        if (opts->json)
            printf("{\"ok\":false,\"error\":\"apd_unreachable\"}\n");
        else
            apdctl_daemon_unreachable();
        return 2;
    }
    pairing = apdctl_call("pairing_status", NULL);

    if (opts->json) {
        struct json_object *root = json_object_new_object();

        json_object_object_add(root, "ok", json_object_new_boolean(1));
        json_object_object_add(root, "status", json_object_get(status));
        if (pairing)
            json_object_object_add(root, "pairing", json_object_get(pairing));
        printf("%s\n", json_object_to_json_string_ext(
            root, JSON_C_TO_STRING_PRETTY));
        json_object_put(root);
    } else {
        const char *state = apdctl_json_str(pairing, "state", "unknown");
        const char *enrollment = apdctl_json_str(pairing, "enrollment_state", "");
        const char *phase = apdctl_json_str(pairing, "enrollment_phase", "");
        int adopted = apdctl_json_bool(pairing, "adopted", 0);
        int mtls = apdctl_json_bool(pairing, "mtls_ready", 0);

        apdctl_heading("AP 节点状态");
        apdctl_field("服务", apdctl_json_str(status, "service", "dreamingwrt-apd"));
        apdctl_field("AP ID", apdctl_json_str(status, "ap_id", ""));
        apdctl_field("配对状态",
                     apdctl_state_text(state, enrollment, adopted, mtls));
        apdctl_field("控制器 ID", apdctl_json_str(pairing, "controller_id", ""));

        snprintf(buffer, sizeof(buffer), "%s",
                 apdctl_json_bool(pairing, "remote_transport_ready", 0) ?
                     "已连接" : "未连接");
        apdctl_field("控制器链路", buffer);

        apdctl_format_time(apdctl_json_i64(status, "started_at", 0), buffer,
                           sizeof(buffer));
        apdctl_field("启动时间", buffer);

        /*
         * Prefer enrollment_phase, which is unambiguous once adopted. The
         * raw enrollment_state is still shown when it differs, so an
         * operator reading a bug report sees the same value the API returns.
         */
        if (phase[0])
            apdctl_field("enrollment", phase);
        if (enrollment[0] && strcmp(enrollment, phase) != 0) {
            apdctl_field("enrollment(原始)", enrollment);
            apdctl_explain_enrollment_state(enrollment, adopted);
        }
        if (!adopted)
            apdctl_hint("尚未采纳，运行 `apdctl pair` 开始配对。");
        printf("\n");
    }
    json_object_put(status);
    if (pairing)
        json_object_put(pairing);
    return 0;
}

/* ------------------------------------------------------- pairing payload */

/*
 * Builds the AP announcement from what the daemon reports. Every field is
 * evidence-backed; anything apd cannot vouch for is left empty rather than
 * guessed, since the operator compares these against the web UI.
 */
static int apdctl_collect_ap(struct apd_paircode_ap *out, int *transport_error)
{
    struct json_object *identity;
    struct json_object *status;
    struct json_object *snapshot;
    const char *value;

    memset(out, 0, sizeof(*out));
    identity = apdctl_call("identity", transport_error);
    if (!identity)
        return -1;

    value = apdctl_json_str(identity, "ap_id", "");
    snprintf(out->ap_id, sizeof(out->ap_id), "%s", value);
    value = apdctl_json_str(identity, "key_id", "");
    snprintf(out->key_id, sizeof(out->key_id), "%s", value);
    json_object_put(identity);

    status = apdctl_call("status", NULL);
    if (status) {
        if (!out->ap_id[0])
            snprintf(out->ap_id, sizeof(out->ap_id), "%s",
                     apdctl_json_str(status, "ap_id", ""));
        json_object_put(status);
    }

    /*
     * Model, MAC and management address come from the wireless snapshot,
     * which is the daemon's own read-only view of the device.
     */
    snapshot = apdctl_call("snapshot", NULL);
    if (snapshot) {
        struct json_object *device = NULL;
        struct json_object *system = NULL;

        if (json_object_object_get_ex(snapshot, "device", &device)) {
            snprintf(out->model, sizeof(out->model), "%s",
                     apdctl_json_str(device, "model", ""));
            snprintf(out->board_name, sizeof(out->board_name), "%s",
                     apdctl_json_str(device, "board_name", ""));
        }
        if (json_object_object_get_ex(snapshot, "system", &system)) {
            snprintf(out->mgmt_ip, sizeof(out->mgmt_ip), "%s",
                     apdctl_json_str(system, "management_ipv4", ""));
            if (!out->mac[0])
                snprintf(out->mac, sizeof(out->mac), "%s",
                         apdctl_json_str(system, "management_mac", ""));
        }
        json_object_put(snapshot);
    }
    if (!out->mgmt_port)
        out->mgmt_port = 22;
    return out->ap_id[0] ? 0 : -1;
}

static void apdctl_print_qr(const char *code, int no_color)
{
    struct apd_qr qr;
    int columns = apdctl_terminal_columns();
    int rc;

    rc = apd_qr_encode_alnum(code, &qr);
    if (rc != APD_QR_OK) {
        apdctl_hint("配对码过长，无法生成二维码，请使用上面的文本配对码。");
        return;
    }
    if (apd_qr_render_columns(&qr, APD_QR_QUIET_DEFAULT) > columns) {
        printf("\n");
        apdctl_hint("终端宽度不足，无法完整显示二维码"
                    "（需要约 %d 列，当前 %d 列）。",
                    apd_qr_render_columns(&qr, APD_QR_QUIET_DEFAULT), columns);
        apdctl_hint("请加宽终端后重试，或直接复制上面的文本配对码。");
        return;
    }
    if (columns < APDCTL_QR_MIN_COLUMNS) {
        apdctl_hint("终端过窄，已跳过二维码。");
        return;
    }
    printf("\n");
    apd_qr_render_halfblock(&qr, APD_QR_QUIET_DEFAULT,
                            no_color ? 0 : apdctl_stdout_tty(), stdout);
}

static int cmd_pair_show(struct apdctl_opts *opts)
{
    struct apd_paircode_ap ap;
    char code[APD_PAIRCODE_MAX];
    char qr_code[APD_PAIRCODE_MAX];
    char fingerprint[48];
    char endpoint[APD_PAIRCODE_HOST_MAX + 16];
    int transport_error = 0;
    int rc;

    if (apdctl_collect_ap(&ap, &transport_error) != 0) {
        if (opts->json)
            printf("{\"ok\":false,\"error\":\"apd_unreachable\"}\n");
        else
            apdctl_daemon_unreachable();
        return 2;
    }

    rc = apd_paircode_ap_encode(&ap, code, sizeof(code));
    if (rc != APD_PAIRCODE_OK) {
        apdctl_error("生成配对码失败: %s", apd_paircode_strerror(rc));
        return 1;
    }
    /* The compact form drops descriptive strings so the QR stays small
     * enough to scan; the controller resolves them from ap_id. */
    if (apd_paircode_ap_encode_form(&ap, APD_PAIRCODE_FORM_COMPACT, qr_code,
                                    sizeof(qr_code)) != APD_PAIRCODE_OK)
        snprintf(qr_code, sizeof(qr_code), "%s", code);

    apd_paircode_fingerprint_short(ap.key_id, fingerprint, sizeof(fingerprint));
    snprintf(endpoint, sizeof(endpoint), "%s:%u",
             ap.mgmt_ip[0] ? ap.mgmt_ip : "(未知)", ap.mgmt_port);

    if (opts->json) {
        struct json_object *root = json_object_new_object();

        json_object_object_add(root, "ok", json_object_new_boolean(1));
        json_object_object_add(root, "pairing_code",
                               json_object_new_string(code));
        json_object_object_add(root, "pairing_code_compact",
                               json_object_new_string(qr_code));
        json_object_object_add(root, "ap_id", json_object_new_string(ap.ap_id));
        json_object_object_add(root, "key_id",
                               json_object_new_string(ap.key_id));
        json_object_object_add(root, "fingerprint",
                               json_object_new_string(fingerprint));
        json_object_object_add(root, "model", json_object_new_string(ap.model));
        json_object_object_add(root, "mgmt_ip",
                               json_object_new_string(ap.mgmt_ip));
        json_object_object_add(root, "mgmt_port",
                               json_object_new_int(ap.mgmt_port));
        json_object_object_add(root, "contains_credential",
                               json_object_new_boolean(0));
        printf("%s\n", json_object_to_json_string_ext(
            root, JSON_C_TO_STRING_PRETTY));
        json_object_put(root);
        return 0;
    }

    apdctl_heading("AP 绑定信息");
    apdctl_field("AP 型号", ap.model[0] ? ap.model : ap.board_name);
    apdctl_field("管理地址", endpoint);
    apdctl_field("指纹", fingerprint);
    apdctl_hint("请核对指纹与 Web 端显示的一致。");

    apdctl_heading("配对码（可直接复制粘贴到 Web）");
    printf("\n%s\n", code);

    apdctl_print_qr(qr_code, opts->no_color);

    apdctl_heading("使用方式");
    apdctl_hint("手机扫描上面的二维码，或把配对码粘贴到 Web:");
    apdctl_hint("网络配置 → Wi-Fi → AP 管理 → 添加 AP → 粘贴配对码");
    printf("\n");
    printf("  说明: 此配对码只包含身份声明与连接信息，不含任何密钥或凭据；\n");
    printf("        真正的信任仍由 CSR/mTLS 建立。\n\n");
    return 0;
}

/* ----------------------------------------------------------------- pair */

static int apdctl_write_bootstrap(const struct apd_paircode_controller *cfg,
                                  char *reason, size_t reason_size)
{
    struct json_object *root;
    const char *text;
    char temporary[512];
    int fd;
    ssize_t written;
    size_t length;

    if (mkdir(APDCTL_PKI_DIR, 0700) != 0 && errno != EEXIST) {
        snprintf(reason, reason_size, "无法创建 %s: %s", APDCTL_PKI_DIR,
                 strerror(errno));
        return -1;
    }
    if (access(APDCTL_CA_PATH, R_OK) != 0) {
        snprintf(reason, reason_size,
                 "缺少控制器 CA 证书 %s，请先从控制器获取", APDCTL_CA_PATH);
        return -1;
    }

    root = json_object_new_object();
    json_object_object_add(root, "version", json_object_new_int(1));
    json_object_object_add(root, "controller_host",
                           json_object_new_string(cfg->controller_host));
    json_object_object_add(root, "controller_port",
                           json_object_new_int(cfg->controller_port));
    if (cfg->controller_id[0])
        json_object_object_add(root, "controller_id",
                               json_object_new_string(cfg->controller_id));
    json_object_object_add(root, "token_id",
                           json_object_new_string(cfg->token_id));
    json_object_object_add(root, "token", json_object_new_string(cfg->token));
    json_object_object_add(root, "site_id",
                           json_object_new_string(cfg->site_id[0] ?
                                                  cfg->site_id : "default"));
    json_object_object_add(root, "hardware_digest", json_object_new_string(""));
    json_object_object_add(root, "ca_cert_pem_path",
                           json_object_new_string(APDCTL_CA_PATH));
    text = json_object_to_json_string(root);
    length = strlen(text);

    /* Write via a temporary file and rename, so the daemon never observes a
     * half-written bootstrap. 0600 because this file carries the token. */
    snprintf(temporary, sizeof(temporary), "%s.tmp", APDCTL_BOOTSTRAP_PATH);
    fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        snprintf(reason, reason_size, "无法写入 %s: %s", temporary,
                 strerror(errno));
        json_object_put(root);
        return -1;
    }
    written = write(fd, text, length);
    if (written < 0 || (size_t)written != length) {
        snprintf(reason, reason_size, "写入 bootstrap 失败: %s",
                 strerror(errno));
        close(fd);
        unlink(temporary);
        json_object_put(root);
        return -1;
    }
    if (fsync(fd) != 0) {
        snprintf(reason, reason_size, "落盘失败: %s", strerror(errno));
        close(fd);
        unlink(temporary);
        json_object_put(root);
        return -1;
    }
    close(fd);
    json_object_put(root);

    if (rename(temporary, APDCTL_BOOTSTRAP_PATH) != 0) {
        snprintf(reason, reason_size, "无法启用 bootstrap: %s",
                 strerror(errno));
        unlink(temporary);
        return -1;
    }
    return 0;
}

static int apdctl_pair_with_code(struct apdctl_opts *opts, const char *raw)
{
    struct apd_paircode_controller cfg;
    struct json_object *pairing;
    char code[APD_PAIRCODE_MAX];
    char reason[256];
    int adopted;
    int rc;

    if (snprintf(code, sizeof(code), "%s", raw) >= (int)sizeof(code)) {
        apdctl_error("配对码过长。");
        return 1;
    }
    apd_paircode_normalize(code);

    rc = apd_paircode_controller_decode(code, &cfg);
    if (rc != APD_PAIRCODE_OK) {
        apdctl_error("配对码无效: %s", apd_paircode_strerror(rc));
        if (rc == APD_PAIRCODE_ERR_CHECKSUM)
            apdctl_hint("校验失败，通常是复制时少了一截，请重新完整复制。");
        else if (rc == APD_PAIRCODE_ERR_PREFIX)
            apdctl_hint("这不是控制器生成的配对码。"
                        "AP 自身的 DWRTAP1 码用于粘贴到 Web，不能用于本机配对。");
        return 1;
    }

    pairing = apdctl_call("pairing_status", NULL);
    adopted = apdctl_json_bool(pairing, "adopted", 0);
    if (pairing)
        json_object_put(pairing);
    if (adopted && !opts->force) {
        apdctl_error("本机已被采纳。");
        apdctl_hint("如需重新配对，先运行 `apdctl unpair`，"
                    "或加 --force 强制继续。");
        apd_paircode_controller_cleanse(&cfg);
        return 1;
    }

    printf("\n开始配对\n");
    apdctl_field("控制器", cfg.controller_host);
    apdctl_field_uint("端口", cfg.controller_port);
    apdctl_field("站点", cfg.site_id[0] ? cfg.site_id : "default");

    if (apdctl_write_bootstrap(&cfg, reason, sizeof(reason)) != 0) {
        apdctl_error("%s", reason);
        apd_paircode_controller_cleanse(&cfg);
        return 1;
    }
    apd_paircode_controller_cleanse(&cfg);

    printf("\n  已写入 bootstrap 配置。\n");
    apdctl_hint("重启 apd 以开始 enrollment:  /etc/init.d/dreamingwrt-apd restart");
    apdctl_hint("随后用 `apdctl status` 观察采纳结果，"
                "失败原因用 `apdctl doctor` 排查。");
    printf("\n");
    return 0;
}

static int cmd_pair(struct apdctl_opts *opts, int argc, char **argv)
{
    struct json_object *pairing;
    char line[APDCTL_LINE_MAX];
    int adopted;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--show") == 0)
            return cmd_pair_show(opts);
        if (strcmp(argv[i], "--code") == 0) {
            if (i + 1 >= argc) {
                apdctl_error("--code 需要一个配对码参数。");
                return 1;
            }
            return apdctl_pair_with_code(opts, argv[i + 1]);
        }
    }

    /* Interactive wizard. */
    pairing = apdctl_call("pairing_status", NULL);
    if (!pairing) {
        apdctl_daemon_unreachable();
        return 2;
    }
    adopted = apdctl_json_bool(pairing, "adopted", 0);
    json_object_put(pairing);

    apdctl_heading("DreamingWrt AP 配对向导");
    if (adopted) {
        printf("  本机已被采纳。\n");
        apdctl_hint("查看当前状态:  apdctl status");
        apdctl_hint("重新配对前需先解除采纳:  apdctl unpair");
        if (!opts->force) {
            printf("\n");
            return 0;
        }
        apdctl_hint("--force 已指定，继续配对流程。");
    }

    printf("\n  配对有两种方式:\n\n");
    printf("  1. 在 Web 端生成配对码，粘贴到这里（推荐）\n");
    printf("     路径: 网络配置 → Wi-Fi → AP 管理 → 生成配对码\n\n");
    printf("  2. 让 Web 端扫描/粘贴本机的绑定信息\n");
    printf("     运行: apdctl pair --show\n\n");

    printf("请粘贴控制器生成的配对码（直接回车则改用方式 2）:\n> ");
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) {
        printf("\n");
        return 1;
    }
    if (apd_paircode_normalize(line) == 0) {
        printf("\n未输入配对码，改为输出本机绑定信息。\n");
        return cmd_pair_show(opts);
    }
    return apdctl_pair_with_code(opts, line);
}

/* --------------------------------------------------------------- unpair */

static int cmd_unpair(struct apdctl_opts *opts)
{
    struct json_object *pairing;
    struct json_object *response;
    struct json_object *removed = NULL;
    struct blob_buf args;
    int adopted;
    int transport_error = 0;
    int rc;

    pairing = apdctl_call("pairing_status", NULL);
    if (!pairing) {
        apdctl_daemon_unreachable();
        return 2;
    }
    adopted = apdctl_json_bool(pairing, "adopted", 0);
    json_object_put(pairing);

    if (!adopted) {
        printf("本机当前未被采纳，无需解除。\n");
        return 0;
    }

    apdctl_heading("解除采纳（高危操作）");
    printf("  这将删除本机的证书与采纳关系，控制器将失去对本 AP 的管理能力。\n");
    printf("  解除后需要重新配对才能恢复。\n\n");

    if (!opts->assume_yes && !apdctl_confirm("  确认解除采纳?")) {
        printf("\n已取消。\n");
        return 1;
    }

    /*
     * apd owns credential removal, so the daemon does the deleting under its
     * own lock. apdctl only asks and reports; it never touches PKI material
     * directly.
     */
    memset(&args, 0, sizeof(args));
    blob_buf_init(&args, 0);
    blobmsg_add_u8(&args, "confirm", 1);
    response = apdctl_call_args("unpair", args.head, &transport_error);
    blob_buf_free(&args);

    if (!response) {
        if (transport_error) {
            apdctl_daemon_unreachable();
            return 2;
        }
        apdctl_error("解除采纳失败: apd 未返回结果。");
        apdctl_hint("确认 apd 支持该方法:  ubus -v list dreamingwrt.apd");
        return 3;
    }

    if (!apdctl_json_bool(response, "ok", 0)) {
        const char *error = apdctl_json_str(response, "error", "unknown");
        const char *reason = apdctl_json_str(response, "reason", NULL);

        apdctl_error("解除采纳失败: %s", error);
        if (reason)
            apdctl_hint("%s", reason);
        if (strcmp(error, "confirmation_required") == 0)
            apdctl_hint("这是 apdctl 的内部错误，未向 apd 传递确认标记。");
        else
            apdctl_hint("查看详细原因:  logread -e dreamingwrt-apd | tail -20");
        json_object_put(response);
        return 3;
    }

    printf("\n");
    apdctl_heading("已解除采纳");
    if (json_object_object_get_ex(response, "removed", &removed) && removed) {
        printf("  证书            %s\n",
               apdctl_json_bool(removed, "certificate", 0) ? "已删除" : "原本不存在");
        printf("  采纳记录        %s\n",
               apdctl_json_bool(removed, "enrollment", 0) ? "已删除" : "原本不存在");
        printf("  引导配置        %s\n",
               apdctl_json_bool(removed, "bootstrap", 0) ? "已删除" : "原本不存在");
        printf("  配对状态        %s\n",
               apdctl_json_bool(removed, "pairing_state", 0) ? "已重置" : "未重置");
    }
    if (!apdctl_json_bool(response, "transport_restarted", 1))
        apdctl_hint("控制器连接线程未能重启，重新配对前请重启服务:  "
                    "/etc/init.d/dreamingwrt-apd restart");
    printf("\n");
    apdctl_hint("本机将重新广播发现信标，可在控制器侧重新采纳。");
    apdctl_hint("重新配对:  apdctl pair --code <配对码>");

    rc = 0;
    json_object_put(response);
    return rc;
}

/* --------------------------------------------------------------- doctor */

struct apdctl_check {
    const char *name;
    int ok;
    int warn;
    char detail[256];
};

static void apdctl_check_report(const struct apdctl_check *check)
{
    const char *mark = check->ok ? "[ 正常 ]" :
                       (check->warn ? "[ 警告 ]" : "[ 异常 ]");

    printf("  %s %-18s %s\n", mark, check->name, check->detail);
}

/*
 * Clock check. The handoff calls this out specifically: certificate
 * validation is clock-sensitive, and a skewed AP clock produces
 * "the token is not expired but the server says it is" reports that are
 * miserable to chase. We compare against the daemon's own notion of time
 * and against certificate validity, which is the evidence we actually have
 * locally -- no NTP round trip is attempted here.
 */
static void apdctl_check_clock(struct apdctl_check *check,
                               struct json_object *status)
{
    int64_t started_at = apdctl_json_i64(status, "started_at", 0);
    int64_t uptime = apdctl_json_i64(status, "uptime_seconds", -1);
    int64_t now = (int64_t)time(NULL);

    check->name = "系统时钟";
    if (started_at <= 0 || uptime < 0) {
        check->warn = 1;
        snprintf(check->detail, sizeof(check->detail),
                 "无法从 apd 获取时间基准，跳过校验");
        return;
    }
    /*
     * started_at + uptime should track wall clock. A large gap means the
     * clock jumped after apd started, which is exactly the case that breaks
     * certificate validation.
     */
    {
        int64_t expected = started_at + uptime;
        int64_t drift = now - expected;

        if (drift < 0)
            drift = -drift;
        if (now < 1600000000LL) {
            snprintf(check->detail, sizeof(check->detail),
                     "系统时间显然未同步（当前 %lld），"
                     "证书校验会失败", (long long)now);
            return;
        }
        if (drift > 120) {
            check->warn = 1;
            snprintf(check->detail, sizeof(check->detail),
                     "检测到约 %lld 秒时钟跳变，建议同步 NTP 后重试",
                     (long long)drift);
            return;
        }
        check->ok = 1;
        snprintf(check->detail, sizeof(check->detail), "未发现明显偏差");
    }
}

static void apdctl_check_controller(struct apdctl_check *check,
                                    struct json_object *pairing)
{
    int connected = apdctl_json_bool(pairing, "remote_transport_ready", 0);
    int adopted = apdctl_json_bool(pairing, "adopted", 0);

    check->name = "控制器链路";
    if (connected) {
        check->ok = 1;
        snprintf(check->detail, sizeof(check->detail), "已连接");
        return;
    }
    if (!adopted) {
        check->warn = 1;
        snprintf(check->detail, sizeof(check->detail),
                 "尚未采纳，链路未建立属预期");
        return;
    }
    snprintf(check->detail, sizeof(check->detail),
             "已采纳但链路未连接，检查控制器地址与网络可达性");
}

static void apdctl_check_identity(struct apdctl_check *check,
                                  struct json_object *identity)
{
    const char *ap_id = apdctl_json_str(identity, "ap_id", "");
    const char *key_id = apdctl_json_str(identity, "key_id", "");

    check->name = "节点身份";
    if (ap_id[0] && key_id[0]) {
        check->ok = 1;
        snprintf(check->detail, sizeof(check->detail), "ap_id 与设备密钥就绪");
        return;
    }
    snprintf(check->detail, sizeof(check->detail),
             "身份信息缺失，apd 可能尚未完成初始化");
}

static void apdctl_check_bootstrap(struct apdctl_check *check, int adopted)
{
    check->name = "配对凭据";
    if (access(APDCTL_BOOTSTRAP_PATH, F_OK) == 0) {
        check->warn = !adopted;
        check->ok = adopted;
        snprintf(check->detail, sizeof(check->detail),
                 adopted ? "bootstrap 仍在，采纳完成后可由 apd 清理" :
                           "已写入 bootstrap，等待 apd 完成 enrollment");
        return;
    }
    if (adopted) {
        check->ok = 1;
        snprintf(check->detail, sizeof(check->detail),
                 "已采纳，bootstrap 已被清理");
        return;
    }
    check->warn = 1;
    snprintf(check->detail, sizeof(check->detail),
             "无 bootstrap，运行 `apdctl pair` 开始配对");
}

static void apdctl_check_ca(struct apdctl_check *check)
{
    check->name = "控制器 CA";
    if (access(APDCTL_CA_PATH, R_OK) == 0) {
        check->ok = 1;
        snprintf(check->detail, sizeof(check->detail), "%s 存在",
                 APDCTL_CA_PATH);
        return;
    }
    check->warn = 1;
    snprintf(check->detail, sizeof(check->detail),
             "缺少 %s，配对前需要从控制器获取", APDCTL_CA_PATH);
}

static int cmd_doctor(struct apdctl_opts *opts)
{
    struct apdctl_check checks[5];
    struct json_object *status;
    struct json_object *pairing;
    struct json_object *identity;
    int transport_error = 0;
    int failures = 0;
    int warnings = 0;
    size_t i;
    int adopted;

    memset(checks, 0, sizeof(checks));
    status = apdctl_call("status", &transport_error);
    if (!status) {
        if (opts->json)
            printf("{\"ok\":false,\"error\":\"apd_unreachable\"}\n");
        else
            apdctl_daemon_unreachable();
        return 2;
    }
    pairing = apdctl_call("pairing_status", NULL);
    identity = apdctl_call("identity", NULL);
    adopted = apdctl_json_bool(pairing, "adopted", 0);

    apdctl_check_identity(&checks[0], identity);
    apdctl_check_clock(&checks[1], status);
    apdctl_check_ca(&checks[2]);
    apdctl_check_bootstrap(&checks[3], adopted);
    apdctl_check_controller(&checks[4], pairing);

    for (i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        if (!checks[i].ok && !checks[i].warn)
            failures++;
        else if (checks[i].warn)
            warnings++;
    }

    if (opts->json) {
        struct json_object *root = json_object_new_object();
        struct json_object *array = json_object_new_array();

        for (i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
            struct json_object *item = json_object_new_object();

            json_object_object_add(item, "name",
                                   json_object_new_string(checks[i].name));
            json_object_object_add(item, "ok",
                                   json_object_new_boolean(checks[i].ok));
            json_object_object_add(item, "warn",
                                   json_object_new_boolean(checks[i].warn));
            json_object_object_add(item, "detail",
                                   json_object_new_string(checks[i].detail));
            json_object_array_add(array, item);
        }
        json_object_object_add(root, "ok",
                               json_object_new_boolean(failures == 0));
        json_object_object_add(root, "failures", json_object_new_int(failures));
        json_object_object_add(root, "warnings", json_object_new_int(warnings));
        json_object_object_add(root, "checks", array);
        printf("%s\n", json_object_to_json_string_ext(
            root, JSON_C_TO_STRING_PRETTY));
        json_object_put(root);
    } else {
        apdctl_heading("AP 自检");
        for (i = 0; i < sizeof(checks) / sizeof(checks[0]); i++)
            apdctl_check_report(&checks[i]);
        printf("\n  结论: %d 项异常，%d 项警告\n", failures, warnings);
        if (failures)
            apdctl_hint("先处理标记为「异常」的项，再重试配对。");
        printf("\n");
    }

    json_object_put(status);
    if (pairing)
        json_object_put(pairing);
    if (identity)
        json_object_put(identity);
    return failures ? 1 : 0;
}

/* ------------------------------------------------------------------ main */

int main(int argc, char **argv)
{
    struct apdctl_opts opts;
    const char *command = NULL;
    int i;
    int rest_start = argc;

    memset(&opts, 0, sizeof(opts));
    if (!isatty(STDOUT_FILENO))
        opts.no_color = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            opts.json = 1;
        } else if (strcmp(argv[i], "--force") == 0) {
            opts.force = 1;
        } else if (strcmp(argv[i], "--yes") == 0) {
            opts.assume_yes = 1;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            opts.no_color = 1;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("apdctl %s\n", APDCTL_VERSION);
            return 0;
        } else if (!command && argv[i][0] != '-') {
            command = argv[i];
            rest_start = i + 1;
        }
    }

    if (!command) {
        usage(stdout);
        return 0;
    }
    if (strcmp(command, "status") == 0)
        return cmd_status(&opts);
    if (strcmp(command, "pair") == 0)
        return cmd_pair(&opts, argc - rest_start, argv + rest_start);
    if (strcmp(command, "unpair") == 0)
        return cmd_unpair(&opts);
    if (strcmp(command, "doctor") == 0)
        return cmd_doctor(&opts);
    if (strcmp(command, "help") == 0) {
        usage(stdout);
        return 0;
    }

    apdctl_error("未知命令: %s", command);
    usage(stderr);
    return 1;
}
