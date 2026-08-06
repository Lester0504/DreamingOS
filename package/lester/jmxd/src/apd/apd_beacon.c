// SPDX-License-Identifier: GPL-2.0-or-later
/* AP discovery beacon sender. See apd_beacon.h for scope and rationale. */
#include "apd_beacon.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "apd_internal.h"

static struct uloop_timeout g_beacon_timer;
static int g_beacon_socket = -1;
static int g_beacon_active;
static char g_beacon_reason[128] = "beacon_not_started";

static void apd_beacon_set_reason(const char *reason)
{
    snprintf(g_beacon_reason, sizeof(g_beacon_reason), "%s",
             reason ? reason : "");
}

int apd_beacon_active(void)
{
    return g_beacon_active;
}

const char *apd_beacon_reason(void)
{
    return g_beacon_reason;
}

/*
 * Builds the announcement. Only fields the daemon can vouch for are
 * included; anything unknown is omitted rather than guessed, since a
 * controller shows these to an operator for confirmation.
 */
static struct json_object *apd_beacon_payload(void)
{
    struct json_object *root = json_object_new_object();
    struct apd_node_identity identity;
    struct apd_device_model model;

    memset(&identity, 0, sizeof(identity));
    memset(&model, 0, sizeof(model));

    json_object_object_add(root, "magic",
                           json_object_new_string(APD_BEACON_MAGIC));
    json_object_object_add(root, "contract_version",
                           json_object_new_string(APD_CONTRACT_VERSION));

    if (apd_db_identity_get(&identity) != 0) {
        /* Without an ap_id the beacon is meaningless to a listener. */
        json_object_put(root);
        OPENSSL_cleanse(&identity, sizeof(identity));
        return NULL;
    }
    json_object_object_add(root, "ap_id",
                           json_object_new_string(identity.ap_id));
    json_object_object_add(root, "key_id",
                           json_object_new_string(identity.key_id));

    if (apd_backend_device_model_collect(&model) == 0) {
        json_object_object_add(root, "model",
                               json_object_new_string(model.model));
        json_object_object_add(root, "board_name",
                               json_object_new_string(model.board_name));
    }

    OPENSSL_cleanse(&identity, sizeof(identity));
    return root;
}

static void apd_beacon_send(struct uloop_timeout *timeout)
{
    struct json_object *payload;
    struct sockaddr_in destination;
    const char *text;

    /*
     * Stop announcing once adopted. Reschedule anyway so that an unpair
     * brings the beacon back without a restart.
     */
    if (!apd_transport_adopted() && g_beacon_socket >= 0) {
        payload = apd_beacon_payload();
        if (payload) {
            text = json_object_to_json_string(payload);
            memset(&destination, 0, sizeof(destination));
            destination.sin_family = AF_INET;
            destination.sin_addr.s_addr = htonl(INADDR_BROADCAST);
            destination.sin_port = htons(APD_BEACON_PORT);
            if (sendto(g_beacon_socket, text, strlen(text), 0,
                       (struct sockaddr *)&destination,
                       sizeof(destination)) < 0)
                apd_beacon_set_reason("beacon_send_failed");
            else
                apd_beacon_set_reason("announcing");
            json_object_put(payload);
        } else {
            apd_beacon_set_reason("beacon_identity_unavailable");
        }
    } else if (apd_transport_adopted()) {
        apd_beacon_set_reason("adopted_beacon_suppressed");
    }

    uloop_timeout_set(timeout, APD_BEACON_INTERVAL_SECONDS * 1000);
}

int apd_beacon_start(void)
{
    int broadcast = 1;

    g_beacon_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_beacon_socket < 0) {
        apd_beacon_set_reason("beacon_socket_failed");
        return -1;
    }
    if (setsockopt(g_beacon_socket, SOL_SOCKET, SO_BROADCAST, &broadcast,
                   sizeof(broadcast)) != 0) {
        close(g_beacon_socket);
        g_beacon_socket = -1;
        apd_beacon_set_reason("beacon_broadcast_unavailable");
        return -1;
    }

    memset(&g_beacon_timer, 0, sizeof(g_beacon_timer));
    g_beacon_timer.cb = apd_beacon_send;
    /* First announcement goes out promptly so a freshly flashed AP appears
     * in the controller list without a 30 second wait. */
    uloop_timeout_set(&g_beacon_timer, 2000);
    g_beacon_active = 1;
    apd_beacon_set_reason("starting");
    return 0;
}

void apd_beacon_stop(void)
{
    uloop_timeout_cancel(&g_beacon_timer);
    if (g_beacon_socket >= 0) {
        close(g_beacon_socket);
        g_beacon_socket = -1;
    }
    g_beacon_active = 0;
    apd_beacon_set_reason("beacon_stopped");
}
