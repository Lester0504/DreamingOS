// SPDX-License-Identifier: GPL-2.0-or-later
#include "wan_probe.h"

#include <ares.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <math.h>
#include <net/if.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct probe_context {
    const struct wan_probe_request *request;
    struct wan_probe_result *result;
    struct sockaddr_storage destination;
    socklen_t destination_len;
    int done, resolved;
    int64_t deadline_ms;
};

static int64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int remaining(struct probe_context *c)
{
    int64_t ms = c->deadline_ms - monotonic_ms();
    return ms > 0 ? (int)ms : 0;
}

static void failure(struct probe_context *c, const char *reason, int valid)
{
    c->result->valid = valid;
    snprintf(c->result->error_class, sizeof(c->result->error_class), "%s", reason);
}

static int literal(const char *host, struct sockaddr_storage *address)
{
    struct sockaddr_in *v4 = (struct sockaddr_in *)address;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)address;
    memset(address, 0, sizeof(*address));
    if (inet_pton(AF_INET, host, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        return sizeof(*v4);
    }
    if (inet_pton(AF_INET6, host, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        return sizeof(*v6);
    }
    return 0;
}

static int bind_source(struct probe_context *c, int fd, int family)
{
    struct ifaddrs *addresses = NULL, *a;
    int rc = -1;
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, c->request->ifname,
                   strlen(c->request->ifname) + 1) != 0) {
        failure(c, "bind_failed", 0);
        return -1;
    }
    if (getifaddrs(&addresses) != 0) {
        failure(c, "source_address_unavailable", 0);
        return -1;
    }
    for (a = addresses; a; a = a->ifa_next) {
        void *source;
        socklen_t length;
        struct sockaddr_storage local;
        if (!a->ifa_addr || strcmp(a->ifa_name, c->request->ifname) ||
            a->ifa_addr->sa_family != family || !(a->ifa_flags & IFF_UP)) continue;
        length = family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        memset(&local, 0, sizeof(local));
        memcpy(&local, a->ifa_addr, length);
        if (family == AF_INET) {
            struct sockaddr_in *v4 = (struct sockaddr_in *)&local;
            v4->sin_port = 0;
            source = &v4->sin_addr;
        } else {
            struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&local;
            v6->sin6_port = 0;
            source = &v6->sin6_addr;
            if (IN6_IS_ADDR_LINKLOCAL(&v6->sin6_addr)) continue;
        }
        if (bind(fd, (struct sockaddr *)&local, length) != 0) continue;
        inet_ntop(family, source, c->result->source_address, sizeof(c->result->source_address));
        c->result->address_family = family == AF_INET ? 4 : 6;
        rc = 0;
        break;
    }
    freeifaddrs(addresses);
    if (rc) failure(c, "source_address_unavailable", 0);
    return rc;
}

static int dns_socket(ares_socket_t fd, int type, void *arg)
{
    struct probe_context *c = arg;
    struct sockaddr_storage local;
    socklen_t length = sizeof(local);
    (void)type;
    if (getsockname(fd, (struct sockaddr *)&local, &length)) return -1;
    return bind_source(c, fd, local.ss_family);
}

static void dns_result(void *arg, int status, int timeouts, struct ares_addrinfo *answer)
{
    struct probe_context *c = arg;
    struct ares_addrinfo_node *node;
    (void)timeouts;
    c->done = 1;
    if (status == ARES_SUCCESS && answer) {
        for (node = answer->nodes; node; node = node->ai_next) {
            if ((node->ai_family != AF_INET && node->ai_family != AF_INET6) ||
                node->ai_addrlen > sizeof(c->destination)) continue;
            memcpy(&c->destination, node->ai_addr, node->ai_addrlen);
            c->destination_len = node->ai_addrlen;
            c->resolved = 1;
            break;
        }
    }
    if (answer) ares_freeaddrinfo(answer);
}

struct dns_sockets {
    struct pollfd *fds;
    size_t count;
    int failed;
};

static void dns_socket_state(void *arg, ares_socket_t fd, int readable, int writable)
{
    struct dns_sockets *sockets = arg;
    size_t i;
    for (i = 0; i < sockets->count; i++)
        if (sockets->fds[i].fd == fd) break;
    if (!readable && !writable) {
        if (i < sockets->count) sockets->fds[i] = sockets->fds[--sockets->count];
        return;
    }
    if (i == sockets->count) {
        struct pollfd *fds = realloc(sockets->fds, (sockets->count + 1) * sizeof(*fds));
        if (!fds) { sockets->failed = 1; return; }
        sockets->fds = fds;
        sockets->count++;
    }
    sockets->fds[i] = (struct pollfd){.fd = fd,
        .events = (readable ? POLLIN : 0) | (writable ? POLLOUT : 0)};
}

static int resolve(struct probe_context *c, const char *host, const char *servers)
{
    ares_channel_t *channel = NULL;
    struct ares_options options;
    struct ares_addrinfo_hints hints;
    struct dns_sockets sockets = {0};
    int length = literal(host, &c->destination);
    int64_t start = monotonic_ms();
    if (length) { c->destination_len = length; return 0; }
    memset(&options, 0, sizeof(options));
    options.timeout = remaining(c);
    options.tries = 1;
    options.lookups = "b"; /* Do not satisfy WAN DNS evidence from /etc/hosts. */
    options.sock_state_cb = dns_socket_state;
    options.sock_state_cb_data = &sockets;
    if (!options.timeout || ares_init_options(&channel, &options,
            ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_LOOKUPS |
            ARES_OPT_SOCK_STATE_CB) != ARES_SUCCESS) {
        failure(c, "resolver_unavailable", 0);
        free(sockets.fds);
        return -1;
    }
    ares_set_socket_configure_callback(channel, dns_socket, c);
    if (servers && servers[0] && ares_set_servers_ports_csv(channel, servers) != ARES_SUCCESS) {
        failure(c, "invalid_dns_server", 0);
        ares_destroy(channel);
        free(sockets.fds);
        return -1;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = ARES_AI_NOSORT; /* Avoid c-ares' unbound route-sorting sockets. */
    ares_getaddrinfo(channel, host, NULL, &hints, dns_result, c);
    while (!c->done && !sockets.failed && remaining(c)) {
        struct timeval timeout, maximum, *tv;
        int wait_ms = remaining(c), rc;
        size_t count = sockets.count, ready_count = 0;
        ares_fd_events_t *ready = count ? calloc(count, sizeof(*ready)) : NULL;
        if (count && !ready) { sockets.failed = 1; break; }
        maximum.tv_sec = wait_ms / 1000;
        maximum.tv_usec = (wait_ms % 1000) * 1000;
        tv = ares_timeout(channel, &maximum, &timeout);
        wait_ms = (int)(tv->tv_sec * 1000 + (tv->tv_usec + 999) / 1000);
        rc = poll(sockets.fds, count, wait_ms);
        if (rc < 0) {
            int interrupted = errno == EINTR;
            free(ready);
            if (interrupted) continue;
            break;
        }
        for (size_t i = 0; i < count; i++) {
            short revents = sockets.fds[i].revents;
            unsigned events = 0;
            if (revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) events |= ARES_FD_EVENT_READ;
            if (revents & POLLOUT) events |= ARES_FD_EVENT_WRITE;
            if (events) ready[ready_count++] = (ares_fd_events_t){sockets.fds[i].fd, events};
        }
        /* Processing may add/remove sockets; keep the ready snapshot separate.
         * An empty batch still advances c-ares' query timeouts. */
        rc = ares_process_fds(channel, ready, ready_count, ARES_PROCESS_FLAG_NONE);
        free(ready);
        if (rc != ARES_SUCCESS) { sockets.failed = 1; break; }
    }
    ares_destroy(channel);
    free(sockets.fds);
    if (sockets.failed) {
        c->resolved = 0;
        failure(c, "resolver_unavailable", 0);
    }
    c->result->dns_ms = monotonic_ms() - start;
    if (!c->resolved) {
        if (!c->result->error_class[0]) failure(c, "dns_no_answer", 1);
        return -1;
    }
    return 0;
}

struct parsed_target {
    char host[256], query[256];
    unsigned port;
    CURLU *url;
};

static void parsed_free(struct parsed_target *p)
{
    if (p->url) curl_url_cleanup(p->url);
}

static int parse(const struct wan_probe_request *r, struct parsed_target *p)
{
    char *host = NULL, *scheme = NULL, *port = NULL, *user = NULL, *path = NULL;
    char *end;
    int ok = 0;
    memset(p, 0, sizeof(*p));
    if (!r || !r->method || !r->target || !*r->target || strlen(r->target) > 256 ||
        r->timeout_ms < 100 || r->timeout_ms > 60000) return -1;
    if (!strcmp(r->method, "icmp")) {
        struct sockaddr_storage address;
        /* Hostname ICMP would otherwise silently depend on a different WAN's DNS. */
        if (!literal(r->target, &address)) return -1;
        snprintf(p->host, sizeof(p->host), "%s", r->target);
        return 0;
    }
    if (strcmp(r->method,"tcp") && strcmp(r->method,"dns") &&
        strcmp(r->method,"http") && strcmp(r->method,"https")) return -1;
    p->url = curl_url();
    if (!p->url || curl_url_set(p->url, CURLUPART_URL, r->target, CURLU_NON_SUPPORT_SCHEME) ||
        curl_url_get(p->url,CURLUPART_SCHEME,&scheme,0) || strcmp(scheme,r->method) ||
        curl_url_get(p->url,CURLUPART_HOST,&host,0) || !host || !*host || strlen(host)>=sizeof(p->host)) goto done;
    if (!curl_url_get(p->url,CURLUPART_USER,&user,0)) goto done;
    if (host[0]=='[') {
        size_t n=strlen(host);
        if(n<3 || host[n-1]!=']') goto done;
        memcpy(p->host,host+1,n-2);p->host[n-2]='\0';
    } else snprintf(p->host,sizeof(p->host),"%s",host);
    if (!curl_url_get(p->url,CURLUPART_PORT,&port,0)) {
        unsigned long value=strtoul(port,&end,10);
        if (!*port || *end || !value || value>65535) goto done;
        p->port=(unsigned)value;
    } else p->port=!strcmp(r->method,"https")?443:!strcmp(r->method,"http")?80:!strcmp(r->method,"dns")?53:0;
    if (!p->port) goto done;
    if (!strcmp(r->method,"dns")) {
        struct sockaddr_storage server;
        if (!literal(p->host,&server) || curl_url_get(p->url,CURLUPART_PATH,&path,0) ||
            !path || path[0]!='/' || !path[1] || strlen(path+1)>=sizeof(p->query)) goto done;
        for (const char *s=path+1;*s;s++)
            if (!((*s>='a'&&*s<='z')||(*s>='A'&&*s<='Z')||(*s>='0'&&*s<='9')||*s=='.'||*s=='-')) goto done;
        if (literal(path+1,&server)) goto done;
        snprintf(p->query,sizeof(p->query),"%s",path+1);
    }
    if (r->expected_status_count > 16 ||
        (r->expected_status_count && !r->expected_status) ||
        (r->body_marker && strlen(r->body_marker)>256)) goto done;
    for(unsigned i=0;i<r->expected_status_count;i++)
        if(r->expected_status[i]<100 || r->expected_status[i]>599) goto done;
    ok=1;
done:
    curl_free(host);curl_free(scheme);curl_free(port);curl_free(user);curl_free(path);
    if(!ok) { parsed_free(p);p->url=NULL; }
    return ok?0:-1;
}

int wan_probe_validate(const struct wan_probe_request *r)
{
    struct parsed_target p;
    int rc=parse(r,&p);
    if (!rc) parsed_free(&p);
    return rc;
}

static int wait_socket(struct probe_context *c,int fd,short events)
{
    struct pollfd p={.fd=fd,.events=events};
    int rc;
    do { rc=poll(&p,1,remaining(c)); } while(rc<0 && errno==EINTR && remaining(c));
    return rc>0 ? 0:-1;
}

static int tcp_probe(struct probe_context *c,unsigned port)
{
    int fd=socket(c->destination.ss_family,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    int error=0,rc=-1;
    socklen_t len=sizeof(error);
    int64_t start=monotonic_ms();
    if(fd<0){failure(c,"socket_unavailable",0);return -1;}
    if(bind_source(c,fd,c->destination.ss_family))goto done;
    if(c->destination.ss_family==AF_INET)((struct sockaddr_in *)&c->destination)->sin_port=htons(port);
    else ((struct sockaddr_in6 *)&c->destination)->sin6_port=htons(port);
    if(connect(fd,(struct sockaddr *)&c->destination,c->destination_len) &&
        (errno!=EINPROGRESS || wait_socket(c,fd,POLLOUT)))goto failed;
    if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&len) || error)goto failed;
    c->result->tcp_ms=monotonic_ms()-start;rc=0;goto done;
failed:
    failure(c,"tcp_connect_failed",1);
done:
    close(fd);return rc;
}

static uint16_t checksum(const unsigned char *data,size_t length)
{
    unsigned sum=0;
    while(length>1){sum+=((unsigned)data[0]<<8)|data[1];data+=2;length-=2;}
    if(length)sum+=(unsigned)data[0]<<8;
    while(sum>>16)sum=(sum&65535)+(sum>>16);
    return htons((uint16_t)~sum);
}

static int icmp_probe(struct probe_context *c)
{
    unsigned char packet[24]={0},reply[256];
    int family=c->destination.ss_family;
    int fd=socket(family,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,family==AF_INET?IPPROTO_ICMP:IPPROTO_ICMPV6);
    int rc=-1;
    uint64_t nonce=(uint64_t)monotonic_ms() ^ ((uint64_t)getpid()<<32);
    uint16_t sum;
    if(fd<0){failure(c,"icmp_socket_unavailable",0);return -1;}
    if(bind_source(c,fd,family))goto done;
    packet[0]=family==AF_INET?ICMP_ECHO:ICMP6_ECHO_REQUEST;
    packet[7]=1;
    memcpy(packet+8,&nonce,sizeof(nonce));
    if(family==AF_INET){sum=checksum(packet,sizeof(packet));memcpy(packet+2,&sum,2);}
    if(connect(fd,(struct sockaddr *)&c->destination,c->destination_len) ||
        send(fd,packet,sizeof(packet),0)!=(ssize_t)sizeof(packet))goto failed;
    while(remaining(c)) {
        ssize_t n;
        if(wait_socket(c,fd,POLLIN))break;
        n=recv(fd,reply,sizeof(reply),0);
        if(n<16)continue;
        if(reply[0]!=(family==AF_INET?ICMP_ECHOREPLY:ICMP6_ECHO_REPLY) || reply[1] ||
            reply[7]!=1 || memcmp(reply+8,&nonce,sizeof(nonce)))continue;
        rc=0;goto done;
    }
failed:
    failure(c,"icmp_no_reply",1);
done:
    close(fd);return rc;
}

static curl_socket_t http_socket(void *arg,curlsocktype purpose,struct curl_sockaddr *address)
{
    struct probe_context *c=arg;
    int fd;
    (void)purpose;
    fd=socket(address->family,address->socktype|SOCK_CLOEXEC,address->protocol);
    if(fd<0){failure(c,"socket_unavailable",0);return CURL_SOCKET_BAD;}
    if(bind_source(c,fd,address->family)){close(fd);return CURL_SOCKET_BAD;}
    return fd;
}

struct http_body { char text[65537]; size_t length; };
static size_t http_body_write(char *data,size_t size,size_t count,void *arg)
{
    struct http_body *b=arg;
    size_t n=size*count;
    if(n>sizeof(b->text)-1-b->length)return 0;
    memcpy(b->text+b->length,data,n);b->length+=n;b->text[b->length]='\0';return n;
}

static int http_probe(struct probe_context *c,struct parsed_target *p)
{
    CURL *curl=curl_easy_init();
    struct curl_slist *hosts=NULL;
    struct http_body *body=calloc(1,sizeof(*body));
    char address[INET6_ADDRSTRLEN],resolve_entry[600];
    void *ip=c->destination.ss_family==AF_INET ?
        (void *)&((struct sockaddr_in *)&c->destination)->sin_addr:
        (void *)&((struct sockaddr_in6 *)&c->destination)->sin6_addr;
    CURLcode code;
    long status=0;
    double connect=0,tls=0;
    int rc=-1;
    if(!curl||!body){failure(c,"http_unavailable",0);goto done;}
    inet_ntop(c->destination.ss_family,ip,address,sizeof(address));
    snprintf(resolve_entry,sizeof(resolve_entry),"%s:%u:%s%s%s",p->host,p->port,
        c->destination.ss_family==AF_INET6?"[":"",address,c->destination.ss_family==AF_INET6?"]":"");
    hosts=curl_slist_append(NULL,resolve_entry);
    if(!hosts){failure(c,"http_unavailable",0);goto done;}
#define OPT(k,v) do {if(curl_easy_setopt(curl,k,v)!=CURLE_OK){failure(c,"http_option_unavailable",0);goto done;}}while(0)
    OPT(CURLOPT_URL,c->request->target);
    OPT(CURLOPT_PROXY,"");
    OPT(CURLOPT_RESOLVE,hosts);
    OPT(CURLOPT_OPENSOCKETFUNCTION,http_socket);OPT(CURLOPT_OPENSOCKETDATA,c);
    OPT(CURLOPT_NOSIGNAL,1L);OPT(CURLOPT_TIMEOUT_MS,(long)remaining(c));
    OPT(CURLOPT_CONNECTTIMEOUT_MS,(long)remaining(c));
    OPT(CURLOPT_FOLLOWLOCATION,0L);OPT(CURLOPT_MAXREDIRS,0L);
    OPT(CURLOPT_SSL_VERIFYPEER,1L);OPT(CURLOPT_SSL_VERIFYHOST,2L);
    OPT(CURLOPT_WRITEFUNCTION,http_body_write);OPT(CURLOPT_WRITEDATA,body);
#undef OPT
    code=curl_easy_perform(curl);
    curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    curl_easy_getinfo(curl,CURLINFO_CONNECT_TIME,&connect);
    curl_easy_getinfo(curl,CURLINFO_APPCONNECT_TIME,&tls);
    c->result->http_status=(int)status;c->result->tcp_ms=connect*1000;
    c->result->tls_ms=tls>connect?(tls-connect)*1000:0;
    if(code!=CURLE_OK){
        if(!c->result->error_class[0])failure(c,
            code==CURLE_PEER_FAILED_VERIFICATION?"tls_verification_failed":
            code==CURLE_OPERATION_TIMEDOUT?"http_timeout":"http_transfer_failed",1);
        goto done;
    }
    if(c->request->expected_status_count) {
        unsigned i;
        for(i=0;i<c->request->expected_status_count;i++)if(status==c->request->expected_status[i])break;
        if(i==c->request->expected_status_count){failure(c,"http_status_mismatch",1);goto done;}
    } else if(status<200||status>=300){failure(c,"http_status_mismatch",1);goto done;}
    if(c->request->body_marker && *c->request->body_marker && !strstr(body->text,c->request->body_marker)) {
        failure(c,"http_body_mismatch",1);goto done;
    }
    rc=0;
done:
    if(curl)curl_easy_cleanup(curl);
    curl_slist_free_all(hosts);free(body);return rc;
}

int wan_probe_run(const struct wan_probe_request *request,struct wan_probe_result *result)
{
    struct probe_context c={.request=request,.result=result};
    struct parsed_target p;
    int64_t start=monotonic_ms();
    int rc=-1;
    if(!result)return -1;
    memset(result,0,sizeof(*result));result->started_at=time(NULL);
    result->latency_ms=result->dns_ms=result->tcp_ms=result->tls_ms=-1;
    if(parse(request,&p)){failure(&c,"invalid_target",0);goto done;}
    if(!request->ifname || !*request->ifname || strlen(request->ifname)>=sizeof(result->source_ifname) ||
        !if_nametoindex(request->ifname)){failure(&c,"wan_device_unavailable",0);goto parsed_done;}
    snprintf(result->source_ifname,sizeof(result->source_ifname),"%s",request->ifname);
    c.deadline_ms=start+request->timeout_ms;
    if(curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK || ares_library_init(ARES_LIB_INIT_ALL)!=ARES_SUCCESS) {
        failure(&c,"probe_library_unavailable",0);goto parsed_done;
    }
    if(!strcmp(request->method,"dns")) {
        char server[320];
        snprintf(server,sizeof(server),strchr(p.host,':')?"[%s]:%u":"%s:%u",p.host,p.port);
        rc=resolve(&c,p.query,server);
    } else if(resolve(&c,p.host,request->dns_servers)==0) {
        if(!remaining(&c))failure(&c,"probe_timeout",1);
        else if(!strcmp(request->method,"icmp"))rc=icmp_probe(&c);
        else if(!strcmp(request->method,"tcp"))rc=tcp_probe(&c,p.port);
        else rc=http_probe(&c,&p);
    }
    ares_library_cleanup();curl_global_cleanup();
    if(!rc){result->ok=1;result->valid=1;result->error_class[0]='\0';}
parsed_done:
    parsed_free(&p);
done:
    result->finished_at=time(NULL);result->latency_ms=monotonic_ms()-start;
    return result->ok?0:-1;
}
