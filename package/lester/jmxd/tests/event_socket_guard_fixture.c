/* Fixture for webd's shared event-socket single-instance guard.
 *
 * app_event_socket_init() and the ownership-gated teardown are extracted from
 * src/webd/jmx_app_api.c, so this exercises shipped code. Two fixture
 * processes race for the same path, which is exactly the situation that
 * silently killed SSE delivery on a live router: a second webd unlinked and
 * rebound the shared socket, then deleted the path when it exited.
 *
 *   argv[1] = socket path
 *   argv[2] = "hold" to take the socket and wait for stdin, "try" to attempt
 *             acquisition, report, and release immediately
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* Substituted by the harness from the real source. */
#define APP_API_EVENT_SOCKET      g_socket_path
#define APP_API_EVENT_SOCKET_LOCK g_socket_lock
#define APP_API_EVENT_LOCK_RETRY_MS 100
#define APP_API_EVENT_LOCK_WAIT_MS  600

/* sun_path is 108 bytes, so keep the test path well inside it and leave room
 * for the ".lock" suffix. */
static char g_socket_path[96];
static char g_socket_lock[108];

static int g_event_lock_fd = -1;
static int g_event_socket_owned;
static int g_event_sock_fd = -1;

static int app_api_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* The acquisition body below is the extracted production logic, with the uloop
 * registration replaced by storing the fd. */
static int app_event_socket_init(void)
{
    int fd;
    int lock_fd;
    int waited_ms = 0;
    struct sockaddr_un addr;

    lock_fd = open(APP_API_EVENT_SOCKET_LOCK, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0)
        return -1;
    while (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno != EWOULDBLOCK || waited_ms >= APP_API_EVENT_LOCK_WAIT_MS) {
            close(lock_fd);
            return -1;
        }
        usleep(APP_API_EVENT_LOCK_RETRY_MS * 1000);
        waited_ms += APP_API_EVENT_LOCK_RETRY_MS;
    }
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        close(lock_fd);
        return -1;
    }
    unlink(APP_API_EVENT_SOCKET);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", APP_API_EVENT_SOCKET);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        close(lock_fd);
        return -1;
    }
    if (app_api_set_nonblock(fd) != 0) {
        close(fd);
        close(lock_fd);
        return -1;
    }
    g_event_lock_fd = lock_fd;
    g_event_socket_owned = 1;
    g_event_sock_fd = fd;
    return 0;
}

/* The ownership-gated teardown from jmx_app_api_done(). */
static void app_event_socket_done(void)
{
    if (g_event_sock_fd >= 0) {
        close(g_event_sock_fd);
        g_event_sock_fd = -1;
        if (g_event_socket_owned)
            unlink(APP_API_EVENT_SOCKET);
    }
    g_event_socket_owned = 0;
    if (g_event_lock_fd >= 0) {
        flock(g_event_lock_fd, LOCK_UN);
        close(g_event_lock_fd);
        g_event_lock_fd = -1;
    }
}

static int path_exists(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0;
}

int main(int argc, char **argv)
{
    int rc;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <socket_path> hold|try\n", argv[0]);
        return 2;
    }
    snprintf(g_socket_path, sizeof(g_socket_path), "%s", argv[1]);
    snprintf(g_socket_lock, sizeof(g_socket_lock), "%s.lock", argv[1]);

    rc = app_event_socket_init();

    if (!strcmp(argv[2], "hold")) {
        printf("{\"acquired\":%s,\"owned\":%s,\"socket_present\":%s}\n",
               rc == 0 ? "true" : "false",
               g_event_socket_owned ? "true" : "false",
               path_exists(g_socket_path) ? "true" : "false");
        fflush(stdout);
        /* Stay alive holding the socket until the harness closes stdin. */
        (void)getchar();
        app_event_socket_done();
        printf("{\"released\":true,\"socket_present\":%s}\n",
               path_exists(g_socket_path) ? "true" : "false");
        return 0;
    }

    /* "try": report, then run the teardown a losing instance would run. */
    printf("{\"acquired\":%s,\"owned\":%s,",
           rc == 0 ? "true" : "false",
           g_event_socket_owned ? "true" : "false");
    app_event_socket_done();
    printf("\"socket_present_after_exit\":%s}\n",
           path_exists(g_socket_path) ? "true" : "false");
    return 0;
}
