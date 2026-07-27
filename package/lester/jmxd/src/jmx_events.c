// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "jmx_events.h"

#define JMX_EVENTS_SOCKET "/tmp/dreamingwrt-webd-events.sock"
#define JMX_EVENTS_MAX_MESSAGE 4096

static int events_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void jmx_events_emit(const char *topic, const char *type, struct json_object *data)
{
    static long long evt_seq = 0;
    int fd;
    struct sockaddr_un addr;
    struct json_object *evt;
    const char *payload;
    char buf[JMX_EVENTS_MAX_MESSAGE];
    int len;

    evt = json_object_new_object();
    if (!evt)
        return;
    json_object_object_add(evt, "id", json_object_new_int64(++evt_seq));
    json_object_object_add(evt, "ts", json_object_new_int64((int64_t)time(NULL)));
    json_object_object_add(evt, "topic", json_object_new_string(topic ? topic : ""));
    json_object_object_add(evt, "type", json_object_new_string(type ? type : "updated"));
    if (data)
        json_object_object_add(evt, "data", json_object_get(data));

    payload = json_object_to_json_string(evt);
    len = snprintf(buf, sizeof(buf), "%s", payload ? payload : "{}");
    json_object_put(evt);
    if (len <= 0 || len >= (int)sizeof(buf))
        return;

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
        return;
    if (events_set_nonblock(fd) != 0) {
        close(fd);
        return;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", JMX_EVENTS_SOCKET);
    sendto(fd, buf, (size_t)len, 0, (struct sockaddr *)&addr, sizeof(addr));
    close(fd);
}
