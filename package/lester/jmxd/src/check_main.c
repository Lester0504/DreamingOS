
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include "jmx.h"
#include "jmx_utils.h"
#include "check_main.h"

#define INTERNET_CHECK_INTERVAL 30
#define LOG_DIR_PATH "/tmp/log"
#define LOG_DIR_MAX_SIZE_KB 10240

static pthread_t check_thread;
static int check_thread_running = 0;
static int check_thread_exit = 0;
static int check_thread_started = 0;

static struct {
    u_int32_t last_exec_time;    
} g_internet_check_state = {0};

static int check_tcp_connect(const char *host, int port, int timeout_sec) {
    struct addrinfo hints, *result = NULL, *rp = NULL;
    int ret = -1;
    char ip_str[INET6_ADDRSTRLEN] = {0};

    LOG_DEBUG("check_tcp_connect: host=%s, port=%d, timeout_sec=%d\n", host, port, timeout_sec);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(host, NULL, &hints, &result);
    if (ret != 0) {
        LOG_DEBUG("check_tcp_connect: getaddrinfo() failed for %s: %s\n", host, gai_strerror(ret));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        int sockfd = -1;
        int flags;
        int connect_result;
        int so_error = 0;
        socklen_t len;
        struct timeval timeout;
        fd_set write_fds;
        struct sockaddr_storage server_addr;
        socklen_t server_len = 0;

        if (rp->ai_family != AF_INET && rp->ai_family != AF_INET6)
            continue;

        memset(&server_addr, 0, sizeof(server_addr));
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&server_addr;
            memcpy(sin, rp->ai_addr, sizeof(*sin));
            sin->sin_port = htons(port);
            server_len = sizeof(*sin);
            if (inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str)) == NULL)
                continue;
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&server_addr;
            memcpy(sin6, rp->ai_addr, sizeof(*sin6));
            sin6->sin6_port = htons(port);
            server_len = sizeof(*sin6);
            if (inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str)) == NULL)
                continue;
        }

        sockfd = socket(rp->ai_family, SOCK_STREAM, 0);
        if (sockfd < 0) {
            LOG_DEBUG("check_tcp_connect: socket() failed for %s: %s\n", ip_str, strerror(errno));
            continue;
        }

        flags = fcntl(sockfd, F_GETFL, 0);
        if (flags < 0 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(sockfd);
            continue;
        }

        connect_result = connect(sockfd, (struct sockaddr *)&server_addr, server_len);
        if (connect_result == 0) {
            LOG_DEBUG("check_tcp_connect: tcp connect to %s:%d success\n", ip_str, port);
            close(sockfd);
            freeaddrinfo(result);
            return 0;
        }
        if (errno != EINPROGRESS) {
            LOG_DEBUG("check_tcp_connect: connect() failed for %s:%d: %s\n", ip_str, port, strerror(errno));
            close(sockfd);
            continue;
        }

        FD_ZERO(&write_fds);
        FD_SET(sockfd, &write_fds);
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;

        if (select(sockfd + 1, NULL, &write_fds, NULL, &timeout) > 0 && FD_ISSET(sockfd, &write_fds)) {
            len = sizeof(so_error);
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) == 0 && so_error == 0) {
                LOG_DEBUG("check_tcp_connect: tcp connect to %s:%d success\n", ip_str, port);
                close(sockfd);
                freeaddrinfo(result);
                return 0;
            }
            LOG_DEBUG("check_tcp_connect: tcp connect to %s:%d failed: %s\n", ip_str, port, strerror(so_error));
        }

        close(sockfd);
    }

    freeaddrinfo(result);
    LOG_DEBUG("check_tcp_connect: failed to connect to %s:%d\n", host, port);
    return -1;
}


static int check_ping(const char *host) {
    char cmd_buf[256];
    char result_buf[256];

	memset(result_buf, 0x0, sizeof(result_buf));
    snprintf(cmd_buf, sizeof(cmd_buf), "ping -c 1 -W 1 %s 2>/dev/null | grep 'bytes from'", host);
    exec_with_result_line(cmd_buf, result_buf, sizeof(result_buf));
	if (strlen(result_buf) > 0){
		return 0;
	}
    return -1;  
}

static int __check_internet_connectivity(void) {
    if (check_ping("www.baidu.com") == 0) {
		return 1;
    }
    if (check_tcp_connect("www.baidu.com", 443, 2) == 0) {
		return 1;
    }
	return 0;
}


static void check_internet_connectivity(void) {
	static int fail_count = 0;
	static int last_internet = -1;
	int status = __check_internet_connectivity();
	if (status){
		g_jmx_status.internet = 1; 
		fail_count = 0;
	}
	else{
		fail_count++;
		if (fail_count > 2){
			g_jmx_status.internet = 0; 
		}
	}
	if (last_internet != -1 && last_internet != g_jmx_status.internet){
		LOG_WARN("internet change %d--->%d\n", last_internet, g_jmx_status.internet);
	}	
	last_internet = g_jmx_status.internet;
}

static void check_and_cleanup_log_dir(void) {
    char cmd_buf[256];
    char result_buf[64];
    memset(result_buf, 0, sizeof(result_buf));
    snprintf(cmd_buf, sizeof(cmd_buf), "du -sk %s 2>/dev/null | awk '{print $1}'", LOG_DIR_PATH);
    exec_with_result_line(cmd_buf, result_buf, sizeof(result_buf));
    if (result_buf[0] == '\0')
        return;
    int size_kb = atoi(result_buf);
    LOG_INFO("check_and_cleanup_log_dir: log dir size = %d KB\n", size_kb);
    if (size_kb <= LOG_DIR_MAX_SIZE_KB)
        return;
    snprintf(cmd_buf, sizeof(cmd_buf), "rm -rf %s/*", LOG_DIR_PATH);
    system(cmd_buf);
}

static void* check_thread_func(void *arg) {
    LOG_DEBUG("check_thread: thread function started\n");
    
    check_thread_running = 1;
    LOG_DEBUG("check_thread: running\n");
    
    check_internet_connectivity();
    check_and_cleanup_log_dir();
    g_internet_check_state.last_exec_time = time(NULL);
    
    while (!check_thread_exit) {
        sleep(INTERNET_CHECK_INTERVAL);
        
        if (!check_thread_exit) {
            check_internet_connectivity();
            check_and_cleanup_log_dir();
            g_internet_check_state.last_exec_time = time(NULL);
        }
    }
    
    check_thread_running = 0;
    LOG_DEBUG("check_thread: exited\n");
    return NULL;
}

int start_check_thread(void) {
    int ret;
    
    check_thread_exit = 0;
    check_thread_running = 0;
    check_thread_started = 0;
    
    ret = pthread_create(&check_thread, NULL, check_thread_func, NULL);
    if (ret != 0) {
        LOG_ERROR("Failed to create check_thread: %s\n", strerror(ret));
        return -1;
    }
    check_thread_started = 1;
    LOG_INFO("check_thread: created\n");
    return 0;
}

void stop_check_thread(void) {
    if (!check_thread_started) {
        return;
    }
    check_thread_exit = 1;
    pthread_join(check_thread, NULL);
    check_thread_started = 0;

}
