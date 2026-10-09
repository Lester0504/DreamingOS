// SPDX-License-Identifier: GPL-2.0-or-later
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DREAMINGWRT_APD_INTERNAL_H
#define APD_TXPOWER_PARAM_PATH "./param"
#define APD_TXPOWER_PERSIST_PATH "./persisted"
#define APD_TXPOWER_BOOT_CONFIG_PATH "./modules.conf"

struct apd_device_model {
    char board_name[128];
};
struct uloop_timeout {
    void (*cb)(struct uloop_timeout *);
};

static struct uloop_timeout *scheduled;
static int file_writes, radio_calls, reg_writes;
static int layout, low_power, inventory_error, wrong_board;
static int up_layout, high_power, stuck_interface, fail_world_once, fail_up_once;
static int fail_country_once, per_radio_calls, unsafe_reg_writes;
static char country[3];

static int uloop_timeout_set(struct uloop_timeout *timer, int delay)
{
    (void)delay;
    scheduled = timer;
    return 0;
}

static int uloop_timeout_cancel(struct uloop_timeout *timer)
{
    if (scheduled == timer)
        scheduled = NULL;
    return 0;
}

static void apd_backend_device_model_collect(struct apd_device_model *model)
{
    snprintf(model->board_name, sizeof(model->board_name), "%s",
             wrong_board ? "other,board" : "gemtek,w1700k-ubi");
}

static int fixture_access(const char *path, int mode)
{
    (void)mode;
    return !strcmp(path, "/usr/sbin/iw") || !strcmp(path, "/sbin/uci") ||
           !strcmp(path, "/sbin/wifi") ? 0 : -1;
}

static DIR *fixture_opendir(const char *path)
{
    return opendir(!strcmp(path, "/sys/class/ieee80211") ? "./phys" : path);
}

static ssize_t fixture_write(int fd, const void *data, size_t length)
{
    file_writes++;
    return write(fd, data, length);
}

static int fixture_usleep(useconds_t delay)
{
    (void)delay;
    return 0;
}

#define access fixture_access
#define opendir fixture_opendir
#define write fixture_write
#define usleep fixture_usleep
#include "../src/apd/apd_txpower_mode.c"
#undef access
#undef opendir
#undef write
#undef usleep

#define CHECK(label, condition) do { \
    if (!(condition)) { fprintf(stderr, "FAIL %s\n", label); return 1; } \
} while (0)

static int write_text(const char *path, const char *text)
{
    FILE *file = fopen(path, "w");
    int ok;

    if (!file)
        return -1;
    ok = fputs(text, file) >= 0;
    return fclose(file) == 0 && ok ? 0 : -1;
}

static int param_value(void)
{
    FILE *file = fopen(APD_TXPOWER_PARAM_PATH, "r");
    int value;

    if (!file)
        return 0;
    value = fgetc(file) == '1';
    fclose(file);
    return value;
}

static void reset_fixture(const char *persisted, int param, int interfaces)
{
    apd_txpower_mode_restore_stop();
    if (write_text(APD_TXPOWER_PARAM_PATH, param ? "1\n" : "0\n") != 0)
        abort();
    if (persisted) {
        if (write_text(APD_TXPOWER_PERSIST_PATH, persisted) != 0)
            abort();
    } else {
        unlink(APD_TXPOWER_PERSIST_PATH);
    }
    if (write_text(APD_TXPOWER_BOOT_CONFIG_PATH,
            persisted && !strcmp(persisted, "regulatory\n") ?
            "options mt7996e txpower_from_regdb=1 # dreamingwrt-apd\n" :
            "options mt7996e txpower_from_regdb=0 # dreamingwrt-apd\n") != 0)
        abort();
    layout = interfaces;
    up_layout = interfaces ? interfaces : 1;
    low_power = inventory_error = wrong_board = 0;
    high_power = stuck_interface = fail_world_once = fail_up_once = 0;
    fail_country_once = per_radio_calls = unsafe_reg_writes = 0;
    snprintf(country, sizeof(country), "US");
    file_writes = radio_calls = reg_writes = 0;
    apd_txpower_restore_pending = apd_txpower_restore_attempts = 0;
    apd_txpower_restore_reason[0] = '\0';
}

static int fire_timer(void)
{
    struct uloop_timeout *timer = scheduled;

    scheduled = NULL;
    if (!timer)
        return 0;
    timer->cb(timer);
    return 1;
}

int apd_readonly_command(const char *path, char *const argv[],
                         struct apd_command_result *result)
{
    char text[2048] = {0};
    int power = param_value() ? 35 : 30;
    int active_power = param_value() && high_power ? 36 :
                       param_value() && low_power ? 28 : power;

    if (!strcmp(path, "/usr/sbin/iw")) {
        if (!strcmp(argv[1], "reg") && !strcmp(argv[2], "get")) {
            snprintf(text, sizeof(text),
                     "global\ncountry %s: DFS-FCC\n"
                     "\t(5925 - 7125 @ 320), (N/A, 35), (N/A)\n", country);
        } else if (!strcmp(argv[1], "reg") && !strcmp(argv[2], "set")) {
            reg_writes++;
            if (layout)
                unsafe_reg_writes++;
            if (!strcmp(argv[3], "00")) {
                snprintf(country, sizeof(country), "00");
                if (fail_world_once) {
                    fail_world_once = 0;
                    return -1;
                }
            } else {
                if (fail_country_once) {
                    fail_country_once = 0;
                    return -1;
                }
                snprintf(country, sizeof(country), "%s", argv[3]);
            }
        } else if (!strcmp(argv[1], "phy")) {
            snprintf(text, sizeof(text), "Wiphy phy0\n"
                     "\t* 6775 MHz [165] (%d.0 dBm)\n", power);
        } else if (!strcmp(argv[1], "dev")) {
            if (inventory_error)
                return -1;
            switch (layout) {
            case 0:
                break;
            case 1:
                snprintf(text, sizeof(text),
                         "phy#0\n\tInterface phy0.2-ap0\n\t\ttype AP\n"
                         "\t\tchannel 165 (6775 MHz), width: 320 MHz\n"
                         "\t\ttxpower %d.00 dBm\n",
                         active_power);
                break;
            case 2:
                /* 6 GHz is deliberately not the last MLO link. */
                snprintf(text, sizeof(text),
                         "phy#0\n\tInterface ap-mld0\n\t\ttype AP\n"
                         "\t\tMLD with links:\n"
                         "\t\t - link ID 2 link addr 82:58:28:09:22:aa\n"
                         "\t\t   channel 165 (6775 MHz), width: 320 MHz\n"
                         "\t\t   txpower %d.00 dBm\n"
                         "\t\t - link ID 0 link addr 00:58:28:09:22:aa\n"
                         "\t\t   channel 2 (2417 MHz), width: 20 MHz\n"
                         "\t\t   txpower 28.00 dBm\n",
                         active_power);
                break;
            case 3:
                snprintf(text, sizeof(text),
                         "phy#0\n\tInterface phy0.0-ap0\n\t\ttype AP\n"
                         "\t\tchannel 2 (2417 MHz), width: 20 MHz\n"
                         "\t\ttxpower 28.00 dBm\n");
                break;
            case 4:
                snprintf(text, sizeof(text),
                         "phy#0\n\tInterface backhaul\n\t\ttype managed\n");
                break;
            }
        } else {
            return -1;
        }
    } else if (!strcmp(path, "/sbin/uci")) {
        snprintf(text, sizeof(text), "wireless.radio2.band='6g'\n");
    } else if (!strcmp(path, "/sbin/wifi")) {
        radio_calls++;
        if (argv[2])
            per_radio_calls++;
        if (!strcmp(argv[1], "up")) {
            if (fail_up_once) {
                fail_up_once = 0;
                return -1;
            }
            layout = up_layout;
        } else if (!stuck_interface) {
            layout = 0;
        }
    } else {
        return -1;
    }
    result->text = strdup(text);
    result->length = strlen(text);
    return result->text ? 0 : -1;
}

int apd_readonly_command_bounded(const char *path, char *const argv[],
                                 int timeout_ms, size_t output_limit,
                                 struct apd_command_result *result)
{
    (void)timeout_ms;
    (void)output_limit;
    return apd_readonly_command(path, argv, result);
}

void apd_command_result_free(struct apd_command_result *result)
{
    free(result->text);
    free(result->stderr_text);
    memset(result, 0, sizeof(*result));
}

int main(void)
{
    struct apd_txpower_mode_state state;
    struct json_object *result;
    char persisted[APD_TXPOWER_MODE_MAX + 1];
    int i;

    CHECK("fixture phy root", mkdir("phys", 0700) == 0);
    CHECK("fixture phy", mkdir("phys/phy0", 0700) == 0);

    reset_fixture(NULL, 0, 1);
    CHECK("no preference", apd_txpower_mode_restore_start() == 0 &&
          !scheduled && !file_writes && !radio_calls);
    reset_fixture("calibrated\n", 0, 1);
    CHECK("default is inert", apd_txpower_mode_restore_start() == 0 &&
          !scheduled && !file_writes && !radio_calls);

    reset_fixture("regulatory\n", 1, 2);
    low_power = 1;
    CHECK("warm start", apd_txpower_mode_restore_start() == 0 && fire_timer());
    CHECK("matching ceiling is idempotent", !scheduled &&
          !apd_txpower_restore_pending && !file_writes &&
          !radio_calls && !reg_writes && param_value() == 1);
    CHECK("MLO telemetry still honest", apd_txpower_mode_state_collect(&state) == 0 &&
          state.active_6ghz_interface_count == 1 &&
          state.active_6ghz_txpower_dbm_x10[0] == 280);

    for (i = 1; i <= 4; i++) {
        reset_fixture("regulatory\n", 0, i);
        CHECK("live start", apd_txpower_mode_restore_start() == 0 && fire_timer());
        CHECK("no shared-radio teardown", !scheduled && !radio_calls &&
              !reg_writes && !file_writes && param_value() == 0);
        CHECK("deferred, not restored", !apd_txpower_restore_pending &&
              !strcmp(apd_txpower_restore_reason,
                      "active_wireless_requires_explicit_apply"));
        CHECK("intent preserved", apd_txpower_persist_read(persisted) == 0 &&
              !strcmp(persisted, "regulatory"));
    }

    reset_fixture("regulatory\n", 0, 0);
    CHECK("cold start", apd_txpower_mode_restore_start() == 0 && fire_timer());
    CHECK("cold restore still works", !scheduled &&
          !apd_txpower_restore_pending && !apd_txpower_restore_reason[0] &&
          radio_calls == 2 && reg_writes == 2 && param_value() == 1);

    reset_fixture("regulatory\n", 0, 0);
    high_power = 1;
    CHECK("cold failure", apd_txpower_mode_restore_start() == 0 && fire_timer());
    CHECK("one apply and rollback only", radio_calls == 4 && reg_writes == 4 &&
          !scheduled && !apd_txpower_restore_pending &&
          !strcmp(apd_txpower_restore_reason, "restore_failed") &&
          param_value() == 0);
    CHECK("no repeated mutation", !fire_timer() && radio_calls == 4);
    CHECK("failed apply keeps intent", apd_txpower_persist_read(persisted) == 0 &&
          !strcmp(persisted, "regulatory"));

    reset_fixture("regulatory\n", 0, 0);
    low_power = 1;
    CHECK("lower BSS power is not a failed ceiling",
          apd_txpower_mode_restore_start() == 0 && fire_timer() &&
          !scheduled && !apd_txpower_restore_reason[0] &&
          param_value() == 1 && radio_calls == 2 &&
          !per_radio_calls && !unsafe_reg_writes);

    reset_fixture("regulatory\n", 0, 1);
    inventory_error = 1;
    CHECK("inventory retry start", apd_txpower_mode_restore_start() == 0);
    for (i = 0; i < APD_TXPOWER_RESTORE_MAX_ATTEMPTS; i++)
        CHECK("readiness retry", fire_timer());
    CHECK("exhausted is not pending", !scheduled &&
          !apd_txpower_restore_pending &&
          !strcmp(apd_txpower_restore_reason, "retry_exhausted") &&
          !radio_calls && !reg_writes && !file_writes);

    reset_fixture("regulatory\n", 0, 0);
    CHECK("remove driver fixture", unlink(APD_TXPOWER_PARAM_PATH) == 0);
    CHECK("missing driver", apd_txpower_mode_restore_start() == 0 && fire_timer());
    CHECK("missing driver is read-only", scheduled && !file_writes &&
          !radio_calls && !reg_writes);

    reset_fixture("regulatory\n", 0, 0);
    wrong_board = 1;
    CHECK("wrong board start", apd_txpower_mode_restore_start() == 0 && fire_timer());
    CHECK("hardware gate retained", !scheduled && !file_writes &&
          !radio_calls && !reg_writes);

    reset_fixture("regulatory\n", 0, 1);
    result = apd_txpower_mode_set_json("regulatory", 0);
    CHECK("explicit confirmation retained", result &&
          !json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !file_writes && !radio_calls && !reg_writes);
    json_object_put(result);

    reset_fixture("regulatory\n", 1, 2);
    low_power = 1;
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("explicit matching mode is non-mutating",
          json_object_get_boolean(json_object_object_get(result, "ok")) &&
          json_object_get_boolean(json_object_object_get(result, "already_applied")) &&
          !file_writes && !radio_calls && !reg_writes && layout == 2);
    json_object_put(result);

    reset_fixture("calibrated\n", 0, 2);
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("shared PHY apply",
          json_object_get_boolean(json_object_object_get(result, "ok")) &&
          radio_calls == 2 && reg_writes == 2 && layout == 2 &&
          !per_radio_calls && !unsafe_reg_writes && !strcmp(country, "US"));
    CHECK("persisted readback is current",
          !strcmp(json_object_get_string(json_object_object_get(result,
                                                               "persisted_mode")),
                  "regulatory"));
    CHECK("restart scope is explicit",
          !strcmp(json_object_get_string(json_object_object_get(result,
                                                               "radio_reload_scope")),
                  "shared_phy"));
    json_object_put(result);

    reset_fixture("regulatory\n", 1, 2);
    result = apd_txpower_mode_set_json("calibrated", 0);
    CHECK("calibrated restart also requires confirmation",
          !json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !file_writes && !radio_calls && !reg_writes);
    json_object_put(result);
    result = apd_txpower_mode_set_json("calibrated", 1);
    CHECK("calibrated shared PHY apply",
          json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !param_value() && layout == 2 && radio_calls == 2 &&
          !per_radio_calls && !unsafe_reg_writes);
    json_object_put(result);

    for (i = 0; i < 3; i++) {
        reset_fixture("calibrated\n", 0, 2);
        fail_world_once = i == 0;
        fail_country_once = i == 1;
        fail_up_once = i == 2;
        result = apd_txpower_mode_set_json("regulatory", 1);
        CHECK("failed apply rolls back exactly once",
              !json_object_get_boolean(json_object_object_get(result, "ok")) &&
              json_object_get_boolean(json_object_object_get(result, "rollback_ok")) &&
              radio_calls == 4 && reg_writes == 4 && !param_value() &&
              !strcmp(country, "US") && layout == 2 &&
              !per_radio_calls && !unsafe_reg_writes);
        json_object_put(result);
    }

    reset_fixture("calibrated\n", 0, 2);
    stuck_interface = 1;
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("cannot quiesce means no regulatory or parameter mutation",
          !json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !json_object_get_boolean(json_object_object_get(result, "rollback_ok")) &&
          !reg_writes && !file_writes && !param_value() && layout == 2);
    json_object_put(result);

    reset_fixture("calibrated\n", 0, 2);
    snprintf(country, sizeof(country), "00");
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("unknown operating country is not guessed",
          !json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !radio_calls && !reg_writes && !file_writes);
    json_object_put(result);

    reset_fixture("calibrated\n", 0, 2);
    CHECK("second PHY fixture", mkdir("phys/phy1", 0700) == 0);
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("unrelated PHY is not restarted",
          !json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !radio_calls && !reg_writes && !file_writes);
    json_object_put(result);
    CHECK("remove second PHY fixture", rmdir("phys/phy1") == 0);

    reset_fixture("calibrated\n", 0, 2);
    inventory_error = 1;
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("missing inventory refuses before any restart",
          !json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !radio_calls && !reg_writes && !file_writes && layout == 2);
    json_object_put(result);

    reset_fixture("regulatory\n", 1, 2);
    CHECK("legacy boot file", write_text(APD_TXPOWER_BOOT_CONFIG_PATH,
          "# keep this comment\noptions mt7996e disable_offload=1\n"
          "options other value=7\n") == 0);
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("legacy selection gains boot persistence without a radio restart",
          json_object_get_boolean(json_object_object_get(result, "ok")) &&
          json_object_get_boolean(json_object_object_get(result, "boot_mode_persisted")) &&
          !radio_calls && !reg_writes && file_writes == 1);
    json_object_put(result);
    {
        FILE *boot = fopen(APD_TXPOWER_BOOT_CONFIG_PATH, "r");
        char text[512] = {0};
        CHECK("boot configuration readable", boot != NULL);
        CHECK("boot configuration content", fread(text, 1, sizeof(text) - 1, boot) > 0);
        fclose(boot);
        CHECK("unrelated options preserved",
              !strcmp(text, "# keep this comment\n"
                      "options mt7996e disable_offload=1\noptions other value=7\n"
                      "options mt7996e txpower_from_regdb=1 # dreamingwrt-apd\n"));
    }
    file_writes = 0;
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("boot persistence is also idempotent",
          json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !file_writes && !radio_calls && !reg_writes);
    json_object_put(result);

    reset_fixture("calibrated\n", 0, 2);
    CHECK("operator boot option", write_text(APD_TXPOWER_BOOT_CONFIG_PATH,
          "options mt7996e txpower_from_regdb=0\n") == 0);
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("unowned boot option is not overridden",
          !json_object_get_boolean(json_object_object_get(result, "ok")) &&
          !strcmp(json_object_get_string(json_object_object_get(result, "reason")),
                  "boot_module_config_conflict") &&
          !radio_calls && !reg_writes && !file_writes);
    json_object_put(result);

    reset_fixture("calibrated\n", 0, 2);
    CHECK("simulate preference write failure",
          mkdir("./persisted.tmp", 0700) == 0);
    result = apd_txpower_mode_set_json("regulatory", 1);
    CHECK("failed durable selection restores boot and live calibrated state",
          !json_object_get_boolean(json_object_object_get(result, "ok")) &&
          json_object_get_boolean(json_object_object_get(result, "rollback_ok")) &&
          !param_value() && apd_txpower_boot_config("calibrated", 0) == 0);
    json_object_put(result);
    CHECK("clear preference failure", rmdir("./persisted.tmp") == 0);
    file_writes = 0;
    CHECK("boot option restored to previous mode",
          apd_txpower_boot_config("calibrated", 1) == 0 && !file_writes);

    puts("ok");
    return 0;
}
