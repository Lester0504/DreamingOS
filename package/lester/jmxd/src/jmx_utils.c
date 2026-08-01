
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>  
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>

#include "jmx_utils.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#ifndef JMX_PROC_SYS_ROOT
#define JMX_PROC_SYS_ROOT "/proc/sys/dreamingwrt/jmx"
#endif

char *str_trim(char *s) {
    if (!s) return s;
    char *start, *last, *bk;
    int len;

    start = s;
    while (isspace(*start))
        start++;

    bk = last = s + strlen(s) - 1;
    while (last > start && isspace(*last))
        last--;

    if ((s != start) || (bk != last)) {
        len = last - start + 1;
        strncpy(s, start, len);
        s[len] = '\0';
    }   
    return s;
}

int jmx_send_msg_to_kernel(char *buf){

    if (access("/dev/jmx", F_OK) != 0) {
        return 0; // Device doesn't exist, silently skip
    }
    
    FILE *fp = fopen("/dev/jmx", "w");
    if (fp) {
        fprintf(fp, "%s", buf);
        fclose(fp);
    }
    return 0;
}

int check_same_network(char *ip1, char *netmask, char *ip2) {
    struct in_addr addr1, addr2, mask;

    if (inet_pton(AF_INET, ip1, &addr1) != 1) {
        printf("Invalid IP address: %s\n", ip1);
        return -1;
    }
    if (inet_pton(AF_INET, netmask, &mask) != 1) {
        printf("Invalid netmask: %s\n", netmask);
        return -1;
    }
    if (inet_pton(AF_INET, ip2, &addr2) != 1) {
        printf("Invalid IP address: %s\n", ip2);
        return -1;
    }

    if ((addr1.s_addr & mask.s_addr) == (addr2.s_addr & mask.s_addr)) {
        return 1;
    } else {
        return 0;
    }
}


int af_read_file_value(const char *file_path, char *value, int value_len) {
    FILE *file = fopen(file_path, "r");
    if (!file) {
        perror("Failed to open file");
        return -1;
    }

    if (fgets(value, value_len, file) == NULL) {
        perror("Failed to read line from file");
        fclose(file);
        return -1;
    }

    size_t len = strlen(value);
    if (len > 0 && value[len - 1] == '\n') {
        value[len - 1] = '\0';
    }

    fclose(file);
    return 0;
}

int af_read_file_int_value(const char *file_path, int *value) {
    char line_buf[128] = {0};
    if (af_read_file_value(file_path, line_buf, sizeof(line_buf)) < 0){
        return -1;
    }
    *value = atoi(line_buf);
    return 0;
}

/**
 * Parse time_str from UCI format into time period structures
 * Format: "HH:MM-HH:MM-w1,w2,w3 HH:MM-HH:MM-w4,w5 ..."
 * Example: "00:00-23:59-2,3,6 00:00-02:05-1,2,3,0"
 */
int jmx_parse_time_str(const char *time_str, jmx_time_period_t *periods, int max_periods) {
    if (!time_str || !periods || max_periods <= 0) {
        return -1;
    }

    int period_count = 0;
    char *save_ptr1 = NULL;
    char *save_ptr2 = NULL;
    
    
    char time_str_copy[512] = {0};
    strncpy(time_str_copy, time_str, sizeof(time_str_copy) - 1);
    
    
    char *time_period = strtok_r(time_str_copy, " ", &save_ptr1);
    while (time_period && period_count < max_periods) {
        jmx_time_period_t *period = &periods[period_count];
        memset(period, 0, sizeof(jmx_time_period_t));
        
        char start[16] = {0};
        char end[16] = {0};
        char weekdays[64] = {0};
        
        
        char *first_delim = strchr(time_period, '-');
        if (!first_delim) {
            
            time_period = strtok_r(NULL, " ", &save_ptr1);
            continue;
        }
        
        
        strncpy(start, time_period, first_delim - time_period);
        start[first_delim - time_period] = '\0';
        
        
        char *second_delim = strchr(first_delim + 1, '-');
        if (second_delim) {
            
            strncpy(end, first_delim + 1, second_delim - first_delim - 1);
            end[second_delim - first_delim - 1] = '\0';
            strncpy(weekdays, second_delim + 1, sizeof(weekdays) - 1);
        } else {
            
            strncpy(end, first_delim + 1, sizeof(end) - 1);
        }
        
        
        strncpy(period->start_time, start, sizeof(period->start_time) - 1);
        strncpy(period->end_time, end, sizeof(period->end_time) - 1);
        
        
        if (strlen(weekdays) > 0) {
            char weekdays_copy[64] = {0};
            strncpy(weekdays_copy, weekdays, sizeof(weekdays_copy) - 1);
            
            char *weekday_str = strtok_r(weekdays_copy, ",", &save_ptr2);
            while (weekday_str && period->weekday_count < MAX_WEEKDAYS) {
                int weekday = atoi(weekday_str);
                if (weekday >= 0 && weekday <= 6) {
                    period->weekdays[period->weekday_count] = weekday;
                    period->weekday_count++;
                }
                weekday_str = strtok_r(NULL, ",", &save_ptr2);
            }
        }
        
        period_count++;
        time_period = strtok_r(NULL, " ", &save_ptr1);
    }
    
    return period_count;
}


enum jmx_proc_value_kind {
    JMX_PROC_VALUE_U32,
    JMX_PROC_VALUE_IFNAME,
};

struct jmx_proc_value_target {
    const char *key;
    const char *path;
    enum jmx_proc_value_kind kind;
};

static const struct jmx_proc_value_target jmx_proc_value_targets[] = {
    { "lan_ifname", JMX_PROC_SYS_ROOT "/lan_ifname", JMX_PROC_VALUE_IFNAME },
    { "lan_ip", JMX_PROC_SYS_ROOT "/lan_ip", JMX_PROC_VALUE_U32 },
    { "lan_mask", JMX_PROC_SYS_ROOT "/lan_mask", JMX_PROC_VALUE_U32 },
    { "record_enable", JMX_PROC_SYS_ROOT "/record_enable", JMX_PROC_VALUE_U32 },
    { "work_mode", JMX_PROC_SYS_ROOT "/work_mode", JMX_PROC_VALUE_U32 },
};

static const struct jmx_proc_value_target *jmx_proc_value_target(const char *key)
{
    size_t i;

    if (!key)
        return NULL;
    for (i = 0; i < sizeof(jmx_proc_value_targets) / sizeof(jmx_proc_value_targets[0]); i++) {
        if (strcmp(jmx_proc_value_targets[i].key, key) == 0)
            return &jmx_proc_value_targets[i];
    }
    return NULL;
}

static int jmx_proc_ifname_value_valid(const char *value)
{
    size_t i, len;

    if (!value || !(len = strlen(value)) || len >= IFNAMSIZ)
        return 0;
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)value[i];

        if (!isalnum(ch) && ch != '_' && ch != '-' && ch != '.' && ch != ':')
            return 0;
    }
    return if_nametoindex(value) != 0;
}

static int jmx_proc_u32_value_valid(const char *value)
{
    unsigned long long number = 0;
    size_t i;

    if (!value || !value[0])
        return 0;
    for (i = 0; value[i]; i++) {
        unsigned int digit;

        if (!isdigit((unsigned char)value[i]))
            return 0;
        digit = (unsigned int)(value[i] - '0');
        if (number > (0xffffffffULL - digit) / 10ULL)
            return 0;
        number = number * 10ULL + digit;
    }
    return 1;
}

static int jmx_proc_readback(const char *path, char *value, size_t value_len)
{
    ssize_t count;
    int fd;

    if (!path || !value || value_len < 2)
        return -1;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    do {
        count = read(fd, value, value_len - 1);
    } while (count < 0 && errno == EINTR);
    close(fd);
    if (count < 0 || (size_t)count >= value_len - 1)
        return -1;
    value[count] = '\0';
    while (count > 0 && isspace((unsigned char)value[count - 1]))
        value[--count] = '\0';
    return 0;
}

int jmx_update_proc_value(const char *key, const char *value)
{
    const struct jmx_proc_value_target *target = jmx_proc_value_target(key);
    char readback[128] = {0};
    size_t offset = 0, value_len;
    int fd;

    if (!target || !value || !(value_len = strlen(value)) ||
        value_len >= sizeof(readback))
        return -1;
    if ((target->kind == JMX_PROC_VALUE_IFNAME && !jmx_proc_ifname_value_valid(value)) ||
        (target->kind == JMX_PROC_VALUE_U32 && !jmx_proc_u32_value_valid(value)))
        return -1;
    if (jmx_proc_readback(target->path, readback, sizeof(readback)) == 0 &&
        strcmp(readback, value) == 0)
        return 0;

    fd = open(target->path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    while (offset < value_len) {
        ssize_t count = write(fd, value + offset, value_len - offset);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)count;
    }
    if (close(fd) != 0)
        return -1;
    if (jmx_proc_readback(target->path, readback, sizeof(readback)) != 0)
        return -1;
    return strcmp(readback, value) == 0 ? 0 : -1;
}

void update_jmx_proc_value(char *key, char *value){
    (void)jmx_update_proc_value(key, value);
}

void update_jmx_proc_u32_value(char *key, u_int32_t value){
    char buf[32] = {0};
    sprintf(buf, "%u", value);
    update_jmx_proc_value(key, buf);
}
