/* SPDX-License-Identifier: GPL-2.0-or-later
 * DreamingWrt device/domain DNS policy. Independently authored; uses dnsmasq's
 * validated name parser and normal upstream/DNSSEC machinery. Never learns or
 * installs an IP blocklist. The file is an atomic projection of AegisX state.
 */
#include "dnsmasq.h"
#include "dwrt_dns_policy.h"
#include <fcntl.h>
#include <sys/file.h>

#define DWP_MAX_ROWS 4096
#define DWP_LOG_MAX (4 * 1024 * 1024)
struct dwp_row {
  char kind, action, match;
  char mac[18], ip[64], domain[254], id[96];
  time_t expires;
};
static struct dwp_row *dwp_rows;
static size_t dwp_count;
static unsigned long long dwp_revision;
static ino_t dwp_inode;
static off_t dwp_size;
static time_t dwp_mtime;
static int dwp_valid;
static int dwp_observed(union mysockaddr *,time_t);
static void dwp_log(unsigned,time_t,const char *);

/* An invalid/missing snapshot never widens a DNS allow. An old open file is
 * discarded after replacement; no daemon restart/reload is required. */
static void dwp_reload(void)
{
  struct stat st;
  FILE *f;
  char line[640], magic[16];
  unsigned long long revision;
  size_t count = 0;
  struct dwp_row *next;
  if (stat(DWRT_DNS_POLICY_FILE, &st) || !S_ISREG(st.st_mode) || st.st_size > 3*1024*1024)
    { dwp_valid = 0; dwp_count = 0; return; }
  if (dwp_valid && st.st_ino == dwp_inode && st.st_size == dwp_size && st.st_mtime == dwp_mtime)
    return;
  if (!(f = fopen(DWRT_DNS_POLICY_FILE, "r")))
    { dwp_valid = 0; dwp_count = 0; return; }
  next = calloc(DWP_MAX_ROWS, sizeof(*next));
  if (!next || !fgets(line, sizeof(line), f) ||
      sscanf(line, "%15s %llu", magic, &revision) != 2 || strcmp(magic, "DWAD1"))
    goto invalid;
  while (fgets(line, sizeof(line), f))
    {
      struct dwp_row *r;
      long long expiry;
      char extra;
      if (count == DWP_MAX_ROWS || !strchr(line, '\n')) goto invalid;
      r = &next[count];
      if (sscanf(line, " %c %95s %17s %63s %lld %c %c %253s %c", &r->kind, r->id,
                 r->mac, r->ip, &expiry, &r->action, &r->match, r->domain, &extra) != 8 ||
          (r->kind != 'R' && r->kind != 'O') || expiry < 0 ||
          (r->action != 'B' && r->action != 'A' && r->action != '-') ||
          (r->match != 'E' && r->match != 'S' && r->match != '-') ||
          (r->kind == 'R' && (r->action == '-' || r->match == '-'))) goto invalid;
      r->expires = (time_t)expiry;
      count++;
    }
  if (ferror(f)) goto invalid;
  fclose(f);
  free(dwp_rows); dwp_rows = next; dwp_count = count; dwp_revision = revision;
  dwp_inode = st.st_ino; dwp_size = st.st_size; dwp_mtime = st.st_mtime; dwp_valid = 1;
  return;
invalid:
  free(next); fclose(f); dwp_valid = 0; dwp_count = 0;
}

static void dwp_address(union mysockaddr *source, char ip[64])
{
  void *address = source->sa.sa_family == AF_INET ? (void *)&source->in.sin_addr :
                                                     (void *)&source->in6.sin6_addr;
  if (!inet_ntop(source->sa.sa_family, address, ip, 64)) ip[0] = 0;
}

static int dwp_target(const struct dwp_row *r, const char *ip,
                      const char *mac, time_t now)
{
  if (r->expires && r->expires <= now) return 0;
  if (strcmp(r->ip, "*") && strcmp(r->ip, ip)) return 0;
  /* MAC must come from dnsmasq's DHCP/ARP/ND identity, not from the rule file.
   * '*' is reserved for explicit IP-only observations and global rules. */
  return !strcmp(r->mac, "*") || (mac[0] && !strcasecmp(r->mac, mac));
}

static void dwp_identity(union mysockaddr *source, char ip[64], char mac[18], time_t now)
{
  unsigned char raw[DHCP_CHADDR_MAX];
  int size;
  mac[0] = 0; dwp_address(source, ip);
#ifdef HAVE_DHCP
  if (source->sa.sa_family == AF_INET)
    {
      struct dhcp_lease *lease = lease_find_by_addr(source->in.sin_addr);
      if (lease && lease->hwaddr_len == 6 && (!lease->expires || lease->expires > now))
        {
          snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", lease->hwaddr[0],
                   lease->hwaddr[1], lease->hwaddr[2], lease->hwaddr[3], lease->hwaddr[4], lease->hwaddr[5]);
          return;
        }
    }
#endif
  size = find_mac(source, raw, 0, now);
  if (size == 6)
    snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]);
}

static int dwp_match(const struct dwp_row *r, const char *name)
{
  size_t n = strlen(name), d = strlen(r->domain);
  if (!strcasecmp(name, r->domain)) return 1;
  return r->match == 'S' && n > d && name[n-d-1] == '.' && !strcasecmp(name+n-d, r->domain);
}

int dwrt_dns_decide(union mysockaddr *source, const char *name, time_t now)
{
  char ip[64], mac[18];
  int action = 0, rank = -1, observed;
  struct dwp_row *matched = NULL;
  dwp_reload();
  if (!dwp_count || !name) return 0;
  observed=dwp_observed(source,now);
  dwp_identity(source, ip, mac, now);
  for (size_t i = 0; i < dwp_count; i++)
    {
      struct dwp_row *r = &dwp_rows[i];
      int candidate;
      if (r->kind != 'R' || !dwp_target(r, ip, mac, now) || !dwp_match(r, name)) continue;
      /* Device > global; temporary > permanent; longest name; exact > suffix.
       * Same-priority contradictions are rejected by the control plane. */
      candidate = (strcmp(r->mac, "*") ? 10000 : 0) + (r->expires ? 1000 : 0) +
                  (int)strlen(r->domain)*2 + (r->match == 'E');
      if (candidate > rank) { matched=r;rank = candidate; action = r->action == 'B' ? 1 : 2; }
    }
  if(matched&&observed) {
    char event[768];snprintf(event,sizeof(event),"policy %s is %s rule=%s matched=%s match=%s",name,action==1?"block":"allow",matched->id,matched->domain,matched->match=='E'?"exact":"suffix");
    dwp_log(daemon->log_id,now,event);
  }
  return action;
}

static unsigned char *dwp_answer(struct dns_header *header, size_t size)
{
  unsigned char *end;
  if (ntohs(header->qdcount) != 1 || OPCODE(header) != QUERY ||
      !(end = skip_questions(header, size))) return NULL;
  header->hb3 = (header->hb3 & HB3_RD) | HB3_QR;
  header->hb4 = HB4_RA;
  header->ancount = header->nscount = header->arcount = 0;
  return end;
}

size_t dwrt_dns_block(struct dns_header *header, size_t size, size_t capacity)
{
  char name[MAXDNAME];
  unsigned short type, cls;
  unsigned char *p;
  if (!extract_request(header, size, name, &type, &cls) || cls != C_IN ||
      !(p = dwp_answer(header, size))) return 0;
  if (type == T_A || type == T_AAAA)
    {
      size_t length = type == T_A ? 4 : 16;
      if ((size_t)(p-(unsigned char *)header)+12+length > capacity) return 0;
      PUTSHORT(0xc00c, p); PUTSHORT(type, p); PUTSHORT(C_IN, p); PUTLONG(0, p);
      PUTSHORT(length, p); memset(p, 0, length); p += length;
      header->ancount = htons(1);
    }
  return p-(unsigned char *)header;
}

size_t dwrt_dns_probe(struct dns_header *header, size_t size, size_t capacity,
                      union mysockaddr *source, time_t now)
{
  char name[MAXDNAME], value[96];
  unsigned short type, cls;
  unsigned char *p;
  size_t n;
  (void)now;
  if ((source->sa.sa_family == AF_INET && (ntohl(source->in.sin_addr.s_addr)>>24) != 127) ||
      (source->sa.sa_family == AF_INET6 && !IN6_IS_ADDR_LOOPBACK(&source->in6.sin6_addr))) return 0;
  if (!extract_request(header, size, name, &type, &cls) || type != T_TXT || cls != C_IN ||
      strcmp(name, "_dwrt-ad-policy.invalid")) return 0;
  dwp_reload();
  snprintf(value, sizeof(value), "DWAD1 %llu %u", dwp_revision, dwp_valid);
  n = strlen(value);
  if (!(p = dwp_answer(header, size)) || (size_t)(p-(unsigned char *)header)+13+n > capacity) return 0;
  PUTSHORT(0xc00c, p); PUTSHORT(T_TXT, p); PUTSHORT(C_IN, p); PUTLONG(0, p);
  PUTSHORT(n+1, p); *p++ = n; memcpy(p, value, n); p += n;
  header->ancount = htons(1);
  return p-(unsigned char *)header;
}

static int dwp_observed(union mysockaddr *source, time_t now)
{
  char ip[64], mac[18];
  dwp_reload();
  if (!dwp_count) return 0;
  dwp_identity(source, ip, mac, now);
  for (size_t i = 0; i < dwp_count; i++)
    if (dwp_rows[i].kind == 'O' && dwp_target(&dwp_rows[i], ip, mac, now)) return 1;
  return 0;
}

static void dwp_log(unsigned serial, time_t now, const char *event)
{
  struct stat st;
  struct tm tm;
  char line[1024], date[40];
  int fd = open(DWRT_DNS_POLICY_LOG, O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW);
  if (fd < 0) return;
  if (flock(fd, LOCK_EX)) { close(fd); return; }
  if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return; }
  if (st.st_size >= DWP_LOG_MAX && ftruncate(fd, 0)) { close(fd); return; }
  localtime_r(&now, &tm); strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", &tm);
  int n = snprintf(line, sizeof(line), "%s dnsmasq[%ld]: %u %s\n", date, (long)getpid(), serial, event);
  if (n > 0 && n < (int)sizeof(line)) (void)!write(fd, line, n);
  close(fd);
}

void dwrt_dns_query(struct dns_header *header, size_t size,
                     union mysockaddr *source, unsigned int serial, time_t now)
{
  char name[MAXDNAME], ip[64], event[640], qtype[20];
  unsigned short type, cls;
  if (!dwp_observed(source, now) || !extract_request(header, size, name, &type, &cls)) return;
  dwp_address(source, ip);
  snprintf(qtype, sizeof(qtype), "TYPE%u", type);
  const char *type_name = type == T_A ? "A" : type == T_AAAA ? "AAAA" : type == T_CNAME ? "CNAME" : qtype;
  snprintf(event, sizeof(event), "query[%s] %s from %s", type_name, name, ip);
  dwp_log(serial, now, event);
}

void dwrt_dns_reply(struct dns_header *header, size_t size,
                     union mysockaddr *source, unsigned int serial, time_t now)
{
  unsigned char *p;
  char name[MAXDNAME], event[640], address[64];
  unsigned short type, cls, len;
  if (!dwp_observed(source, now) || !(p = skip_questions(header, size))) return;
  if (RCODE(header))
    {
      if (!extract_request(header, size, name, &type, &cls)) return;
      const char *reason = RCODE(header) == NXDOMAIN ? "NXDOMAIN" : RCODE(header) == SERVFAIL ? "SERVFAIL" :
                           RCODE(header) == REFUSED ? "REFUSED" : "UNKNOWN_RCODE";
      snprintf(event, sizeof(event), "reply %s is %s", name, reason); dwp_log(serial, now, event);
    }
  if(!RCODE(header)&&!ntohs(header->ancount)&&extract_request(header,size,name,&type,&cls)) {
    snprintf(event,sizeof(event),"reply %s is NODATA",name);dwp_log(serial,now,event);
  }
  for (unsigned i = 0; i < ntohs(header->ancount) && i < 128; i++)
    {
      if (!extract_name(header, size, &p, name, EXTR_NAME_EXTRACT, 10)) return;
      GETSHORT(type, p); GETSHORT(cls, p); p += 4; GETSHORT(len, p);
      if (!CHECK_LEN(header, p, size, len)) return;
      if (cls == C_IN && ((type == T_A && len == 4) || (type == T_AAAA && len == 16)))
        {
          inet_ntop(type == T_A ? AF_INET : AF_INET6, p, address, sizeof(address));
          snprintf(event, sizeof(event), "reply %s is %s", name, address); dwp_log(serial, now, event);
        }
      else if (cls == C_IN && type == T_CNAME)
        {
          unsigned char *target = p;
          char cname[MAXDNAME];
          if (extract_name(header, size, &target, cname, EXTR_NAME_EXTRACT, 0)) {
            snprintf(event, sizeof(event), "reply %s is <CNAME> %s", name, cname);
            dwp_log(serial, now, event);
          }
        }
      p += len;
    }
}

/* Do not leave trial allows cached on clients after their lease is revoked.
 * DNSSEC RRSIG bytes remain intact; only ordinary RR TTL fields are reduced. */
void dwrt_dns_uncache(struct dns_header *header, size_t size)
{
  unsigned char *p = skip_questions(header, size);
  char name[MAXDNAME];
  unsigned count = ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount);
  if (!p) return;
  for (unsigned i = 0; i < count; i++) {
    unsigned short type, len;
    if (!extract_name(header, size, &p, name, EXTR_NAME_EXTRACT, 10)) return;
    GETSHORT(type, p); p += 2;
    if (type != T_OPT) memset(p, 0, 4);
    p += 4; GETSHORT(len, p);
    if (!CHECK_LEN(header, p, size, len)) return;
    p += len;
  }
}
