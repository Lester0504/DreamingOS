/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "terminal_policy.h"
#include <sqlite3.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <libgen.h>
#include <sys/stat.h>
#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <limits.h>

static struct json_object *tp_json_arr_from_text(const char *text) {
    struct json_object *arr=json_object_new_array();
    if(!text||!text[0])return arr;
    char buf[512]; strncpy(buf,text,sizeof(buf)-1); buf[sizeof(buf)-1]=0;
    char *tok=strtok(buf,",");
    while(tok){while(*tok==' ')tok++;if(tok[0])json_object_array_add(arr,json_object_new_string(tok));tok=strtok(NULL,",");}
    return arr;
}

static sqlite3 *g_tp_db=NULL;
static pthread_mutex_t g_tp_mtx=PTHREAD_MUTEX_INITIALIZER;

static int tp_sql(sqlite3 *db,const char *q,char **e){int rc=sqlite3_exec(db,q,NULL,NULL,e);if(rc!=SQLITE_OK&&e){fprintf(stderr,"[tp] sql: %s\n",*e);sqlite3_free(*e);}return rc;}

int tp_db_init(void){
    int rc; char *err=NULL,*cdir=NULL; struct stat st;
    if (g_tp_db)
        return 0;
    cdir=strdup(TP_DB_PATH); if(!cdir)return -1;
    {char *d=dirname(cdir); if(stat(d,&st)!=0)mkdir(d,0755);}
    free(cdir);
    rc=sqlite3_open_v2(TP_DB_PATH,&g_tp_db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE,NULL);
    if(rc!=SQLITE_OK){fprintf(stderr,"[tp] open: %s\n",sqlite3_errmsg(g_tp_db));g_tp_db=NULL;return -1;}
    tp_sql(g_tp_db,"PRAGMA journal_mode=WAL",NULL);
    tp_sql(g_tp_db,"PRAGMA busy_timeout=5000",NULL);
    tp_sql(g_tp_db,"PRAGMA foreign_keys=ON",NULL);
    const char *stmt[]={
        "CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,name TEXT NOT NULL DEFAULT '',"
        "remark TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1,"
        "rate_upload_kbps INTEGER NOT NULL DEFAULT 0,rate_download_kbps INTEGER NOT NULL DEFAULT 0,"
        "rate_mode TEXT NOT NULL DEFAULT 'per_ip',"
        "started_at INTEGER NOT NULL DEFAULT 0,duration_count INTEGER NOT NULL DEFAULT 0,duration_unit TEXT NOT NULL DEFAULT 'days',deadline_at INTEGER NOT NULL DEFAULT 0,"
        "quota_bytes INTEGER NOT NULL DEFAULT 0,quota_accounting TEXT NOT NULL DEFAULT 'upload_plus_download',quota_mode TEXT NOT NULL DEFAULT 'per_ip',"
        "deny_protocols TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'active',last_transition_at INTEGER NOT NULL DEFAULT 0,"
        "generation INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,"
        "CHECK(rate_upload_kbps>=0),CHECK(rate_download_kbps>=0),CHECK(duration_count>=0),CHECK(quota_bytes>=0))",
        "CREATE INDEX IF NOT EXISTS idx_pe ON policies(enabled)",
        "CREATE INDEX IF NOT EXISTS idx_ps ON policies(status)",
        "CREATE INDEX IF NOT EXISTS idx_pd ON policies(deadline_at)",
        "CREATE TABLE IF NOT EXISTS targets(policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,"
        "family INTEGER NOT NULL,kind TEXT NOT NULL,prefix TEXT NOT NULL,prefix_len INTEGER NOT NULL,"
        "PRIMARY KEY(policy_id,family,prefix))",
        "CREATE TABLE IF NOT EXISTS quota_usage(policy_id TEXT PRIMARY KEY REFERENCES policies(id) ON DELETE CASCADE,"
        "used_upload_bytes INTEGER NOT NULL DEFAULT 0,used_download_bytes INTEGER NOT NULL DEFAULT 0,"
        "used_bytes INTEGER NOT NULL DEFAULT 0,checkpoint_at INTEGER NOT NULL DEFAULT 0)",
        "CREATE TABLE IF NOT EXISTS quota_usage_ip(policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,"
        "family INTEGER NOT NULL,client_ip TEXT NOT NULL,used_upload_bytes INTEGER NOT NULL DEFAULT 0,"
        "used_download_bytes INTEGER NOT NULL DEFAULT 0,used_bytes INTEGER NOT NULL DEFAULT 0,"
        "checkpoint_at INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(policy_id,family,client_ip))",
        "CREATE INDEX IF NOT EXISTS idx_quota_usage_ip_policy ON quota_usage_ip(policy_id)",
        "CREATE TABLE IF NOT EXISTS quota_blocks(policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,"
        "family INTEGER NOT NULL,client_ip TEXT NOT NULL,blocked_at INTEGER NOT NULL,"
        "PRIMARY KEY(policy_id,family,client_ip))"
    };
    for(size_t i=0;i<sizeof(stmt)/sizeof(stmt[0]);i++){
        if((rc=tp_sql(g_tp_db,stmt[i],&err))!=SQLITE_OK){fprintf(stderr,"[tp] schema[%zu]: %s\n",i,err?err:"?");sqlite3_free(err);tp_db_close();return -1;}
    }
    {
        /* Older devices already have a quota_usage table with only used_bytes. */
        sqlite3_stmt *q = NULL;
        int has_up = 0, has_down = 0;
        if (sqlite3_prepare_v2(g_tp_db, "PRAGMA table_info(quota_usage)", -1, &q, NULL) == SQLITE_OK) {
            while (sqlite3_step(q) == SQLITE_ROW) {
                const char *name = (const char *)sqlite3_column_text(q, 1);
                if (!name)
                    continue;
                if (!strcmp(name, "used_upload_bytes"))
                    has_up = 1;
                else if (!strcmp(name, "used_download_bytes"))
                    has_down = 1;
            }
            sqlite3_finalize(q);
        }
        if (!has_up)
            tp_sql(g_tp_db, "ALTER TABLE quota_usage ADD COLUMN used_upload_bytes INTEGER NOT NULL DEFAULT 0", NULL);
        if (!has_down)
            tp_sql(g_tp_db, "ALTER TABLE quota_usage ADD COLUMN used_download_bytes INTEGER NOT NULL DEFAULT 0", NULL);
    }
    /* Keep an explicitly configured shared quota intact.  Only the retired
     * accounting label needs migration; changing the mode here silently
     * changes the user's quota semantics on every daemon restart. */
    tp_sql(g_tp_db, "UPDATE policies SET quota_accounting='upload_plus_download' WHERE quota_accounting='bidirectional'", NULL);
    return 0;
}
void tp_db_close(void){if(g_tp_db){sqlite3_close(g_tp_db);g_tp_db=NULL;}}

static inline time_t tp_now_s(void){struct timespec ts;clock_gettime(CLOCK_REALTIME,&ts);return (time_t)ts.tv_sec;}

static const char *jsd(struct json_object *o,const char *k,const char *d){struct json_object *v;if(!o||!json_object_object_get_ex(o,k,&v)||!v)return d;return json_object_get_string(v);}
static int jbd(struct json_object *o,const char *k,int d){struct json_object *v;if(!o||!json_object_object_get_ex(o,k,&v)||!v)return d;return json_object_get_boolean(v);}
static long long ji64(struct json_object *o,const char *k,long long d){struct json_object *v;if(!o||!json_object_object_get_ex(o,k,&v)||!v)return d;return (long long)json_object_get_int64(v);}
static void copy_col(char *dst,const char *src,size_t n){if(!src){dst[0]=0;return;}snprintf(dst,n,"%s",src);}
static void tp_load_usage(sqlite3 *db, tp_policy_t *p);

static int tp_days_in_month(int year, int month)
{
    static const int days[] = { 31, 28, 31, 30, 31, 30,
                                31, 31, 30, 31, 30, 31 };
    int leap = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0));

    return days[month] + (month == 1 && leap ? 1 : 0);
}

static int tp_compute_deadline(int64_t started,int64_t count,const char *unit,time_t *out){
    struct tm tm; time_t base;
    if(count<=0){*out=0;return 0;}
    if(!strcmp(unit,"months")||!strcmp(unit,"years")){
        int64_t delta_months;
        int64_t source_months;
        int64_t target_months;
        int64_t target_year;
        int target_month;
        int original_day;

        base=(time_t)started;
        if (localtime_r(&base,&tm) == NULL)
            return -1;
        if (!strcmp(unit,"years")) {
            if (count > INT64_MAX / 12)
                return -1;
            delta_months = count * 12;
        } else {
            delta_months = count;
        }
        source_months = (int64_t)tm.tm_year * 12 + tm.tm_mon;
        if (source_months > INT64_MAX - delta_months)
            return -1;
        target_months = source_months + delta_months;
        target_year = target_months / 12;
        target_month = (int)(target_months % 12);
        if (target_year < INT_MIN || target_year > INT_MAX)
            return -1;
        original_day = tm.tm_mday;
        tm.tm_year = (int)target_year;
        tm.tm_mon = target_month;
        tm.tm_mday = original_day > tp_days_in_month(tm.tm_year + 1900, target_month) ?
                     tp_days_in_month(tm.tm_year + 1900, target_month) : original_day;
        tm.tm_isdst = -1;
        *out = mktime(&tm);
        if (*out == (time_t)-1)
            return -1;
    }else{
        int64_t s;
        if(!strcmp(unit,"hours")){if(count>INT64_MAX/3600)return -1;s=count*3600;}
        else if(!strcmp(unit,"days")){if(count>INT64_MAX/86400)return -1;s=count*86400;}
        else if(!strcmp(unit,"weeks")){if(count>INT64_MAX/604800)return -1;s=count*604800;}
        else return -1;
        if(started>INT64_MAX-s)return -1;
        *out=(time_t)(started+s);
    }
    return 0;
}
int tp_valid_unit(const char *u){return u&&(!strcmp(u,"hours")||!strcmp(u,"days")||!strcmp(u,"weeks")||!strcmp(u,"months")||!strcmp(u,"years"));}

static uint32_t tp4u(const char *s){struct in_addr a;return inet_pton(AF_INET,s,&a)==1?ntohl(a.s_addr):(uint32_t)-1;}
static void tp4s(uint32_t ip,char *b,size_t l){snprintf(b,l,"%u.%u.%u.%u",(ip>>24)&0xFF,(ip>>16)&0xFF,(ip>>8)&0xFF,ip&0xFF);}
static int tp_cidrs(uint32_t s,uint32_t e,char **o,int mx){
    int n=0;
    while(s<=e){
        int best=-1;
        if (n >= mx) {
            while (n > 0)
                free(o[--n]);
            return -1;
        }
        for(int b=31;b>=0;b--){uint32_t mask=~((1U<<b)-1);if((s&mask)!=s)continue;if(s+(1U<<b)-1<=e){best=b;break;}}
        if(best<0)best=0;
        char tmp[64];tp4s(s,tmp,sizeof(tmp));snprintf(tmp+strlen(tmp),sizeof(tmp)-strlen(tmp),"/%d",32-best);
        o[n++]=strdup(tmp);
        uint32_t inc=1U<<best;
        uint64_t next=(uint64_t)s+(uint64_t)inc;
        if(next>UINT32_MAX)break;
        s=(uint32_t)next;
    }
    return n;
}

static int tp6_compare(const unsigned char *a, const unsigned char *b)
{
    return memcmp(a, b, 16);
}

static void tp6_increment(unsigned char *addr)
{
    int i;

    for (i = 15; i >= 0; i--)
        if (++addr[i] != 0)
            break;
}

static int tp6_is_max(const unsigned char *addr)
{
    int i;

    for (i = 0; i < 16; i++)
        if (addr[i] != 0xff)
            return 0;
    return 1;
}

static int tp6_block_end(const unsigned char *start, int prefix,
                         unsigned char *end)
{
    int hostbits = 128 - prefix;
    int bit;

    memcpy(end, start, 16);
    for (bit = 0; bit < hostbits; bit++) {
        int pos = 127 - bit;
        int byte = pos / 8;
        int mask = 1 << (7 - (pos % 8));

        if (start[byte] & mask)
            return -1;
        end[byte] |= (unsigned char)mask;
    }
    return 0;
}

static int tp6_cidrs(const unsigned char *start, const unsigned char *last,
                     char **out, int max)
{
    unsigned char current[16];
    unsigned char block_end[16];
    int count = 0;

    memcpy(current, start, sizeof(current));
    while (tp6_compare(current, last) <= 0) {
        int prefix;
        int selected = -1;
        char text[INET6_ADDRSTRLEN];
        char value[320];

        if (count >= max) {
            while (count > 0)
                free(out[--count]);
            return -1;
        }

        for (prefix = 0; prefix <= 128; prefix++) {
            if (tp6_block_end(current, prefix, block_end) == 0 &&
                tp6_compare(block_end, last) <= 0) {
                selected = prefix;
                break;
            }
        }
        if (selected < 0 || !inet_ntop(AF_INET6, current, text, sizeof(text)))
            break;
        snprintf(value, sizeof(value), "%s/%d", text, selected);
        out[count] = strdup(value);
        if (!out[count])
            break;
        count++;
        memcpy(current, block_end, sizeof(current));
        if (tp6_is_max(current))
            break;
        tp6_increment(current);
    }
    return count;
}

typedef struct{int f;char pr[257];int pl;}tr_t;
#define MX_TR 4096

static void tp_mask_prefix(unsigned char *addr, int bits, int prefix)
{
    int byte;
    int rem;

    if (!addr || bits <= 0 || prefix < 0 || prefix > bits)
        return;
    byte = prefix / 8;
    rem = prefix % 8;
    if (byte < bits / 8) {
        if (rem)
            addr[byte] &= (unsigned char)(0xffU << (8 - rem));
        else
            addr[byte] = 0;
        for (byte += 1; byte < bits / 8; byte++)
            addr[byte] = 0;
    }
}

static int tp_normalize_prefix(int family, const char *text, int prefix,
                               char *out, size_t out_len)
{
    unsigned char addr[16];
    int af = family == 4 ? AF_INET : AF_INET6;
    int bits = family == 4 ? 32 : 128;

    if (!text || !out || !out_len || (family != 4 && family != 6) ||
        prefix < 0 || prefix > bits || inet_pton(af, text, addr) != 1)
        return -1;
    tp_mask_prefix(addr, bits, prefix);
    if (!inet_ntop(af, addr, out, out_len))
        return -1;
    return 0;
}

static int tp_prefix_overlap(int family, const char *a, int apl,
                             const char *b, int bpl)
{
    unsigned char aa[16], bb[16];
    int af = family == 4 ? AF_INET : AF_INET6;
    int bits = family == 4 ? 32 : 128;
    int common;
    int bytes;
    int rem;

    if ((family != 4 && family != 6) || apl < 0 || bpl < 0 ||
        apl > bits || bpl > bits ||
        inet_pton(af, a, aa) != 1 || inet_pton(af, b, bb) != 1)
        return 0;
    common = apl < bpl ? apl : bpl;
    bytes = common / 8;
    if (bytes && memcmp(aa, bb, (size_t)bytes) != 0)
        return 0;
    rem = common % 8;
    if (rem && ((aa[bytes] ^ bb[bytes]) & (unsigned char)(0xffU << (8 - rem))))
        return 0;
    return 1;
}

static int tp_rows_overlap(const tr_t *rows, int nrows, int family,
                           const char *prefix, int prefix_len)
{
    int i;

    if (!rows || nrows < 0 || !prefix)
        return 0;
    for (i = 0; i < nrows; i++)
        if (rows[i].f == family &&
            tp_prefix_overlap(family, rows[i].pr, rows[i].pl,
                              prefix, prefix_len))
            return 1;
    return 0;
}

static int tp_dedupe_rows(tr_t *rows, int *count)
{
    int i;
    int j;

    if (!rows || !count || *count < 0 || *count > MX_TR)
        return -1;
    for (i = 0; i < *count; i++) {
        for (j = i + 1; j < *count; j++) {
            if (rows[i].f != rows[j].f || rows[i].pl != rows[j].pl ||
                strcmp(rows[i].pr, rows[j].pr) != 0)
                continue;
            memmove(&rows[j], &rows[j + 1],
                    (size_t)(*count - j - 1) * sizeof(rows[0]));
            (*count)--;
            j--;
        }
    }
    return 0;
}

static int tp_check_enabled_overlap(sqlite3 *db, const char *self_id,
                                    int enabled, const tr_t *rows, int nrows,
                                    tp_error_t *err)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (!enabled || !db || !rows || nrows <= 0)
        return 0;
    rc = sqlite3_prepare_v2(db,
        "SELECT p.id,t.family,t.prefix,t.prefix_len "
        "FROM policies p JOIN targets t ON t.policy_id=p.id "
        "WHERE p.enabled=1 AND p.id<>? ORDER BY p.id,t.family,t.prefix",
        -1, &st, NULL);
    if (rc != SQLITE_OK) {
        if (err) {
            snprintf(err->detail, sizeof(err->detail), "overlap query failed");
            err->code = "db_query";
        }
        return -1;
    }
    sqlite3_bind_text(st, 1, self_id ? self_id : "", -1, SQLITE_STATIC);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *id = (const char *)sqlite3_column_text(st, 0);
        const char *prefix = (const char *)sqlite3_column_text(st, 2);
        int family = sqlite3_column_int(st, 1);
        int prefix_len = sqlite3_column_int(st, 3);

        if (id && prefix && tp_rows_overlap(rows, nrows, family, prefix, prefix_len)) {
            if (err) {
                snprintf(err->detail, sizeof(err->detail),
                         "targets overlap with enabled policy '%s'", id);
                err->code = "conflict";
            }
            sqlite3_finalize(st);
            return 1;
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        if (err) {
            snprintf(err->detail, sizeof(err->detail), "overlap scan failed");
            err->code = "db_query";
        }
        return -1;
    }
    return 0;
}

static int tp_expand(struct json_object *tt,tr_t *rows,int *cnt,tp_error_t *err){
    int c=0;size_t i;
    if(!json_object_is_type(tt,json_type_array)){snprintf(err->detail,sizeof(err->detail),"targets must be array");err->code="bad_targets";return -1;}
    for(i=0;i<json_object_array_length(tt);i++){
        struct json_object *t=json_object_array_get_idx(tt,i);
        if (c >= MX_TR) {
            snprintf(err->detail, sizeof(err->detail), "targets normalize to more than %d prefixes", MX_TR);
            err->code = "too_many_targets";
            return -1;
        }
        if(!t||!json_object_is_type(t,json_type_object))continue;
        const char *kind=jsd(t,"kind","ip"),*val=jsd(t,"value",""),*si=jsd(t,"start",""),*ei=jsd(t,"end","");
        tr_t *r=&rows[c];memset(r,0,sizeof(*r));
        if(!strcmp(kind,"ip")){
            struct in_addr v4;struct in6_addr v6;
            if(inet_pton(AF_INET,val,&v4)==1){r->f=4;r->pl=32;if(tp_normalize_prefix(r->f,val,r->pl,r->pr,sizeof(r->pr))!=0){snprintf(err->detail,sizeof(err->detail),"targets[%zu]: invalid ip '%s'",i,val);err->code="bad_ip";return -1;}c++;}
            else if(inet_pton(AF_INET6,val,&v6)==1){r->f=6;r->pl=128;if(tp_normalize_prefix(r->f,val,r->pl,r->pr,sizeof(r->pr))!=0){snprintf(err->detail,sizeof(err->detail),"targets[%zu]: invalid ip '%s'",i,val);err->code="bad_ip";return -1;}c++;}
            else{snprintf(err->detail,sizeof(err->detail),"targets[%zu]: invalid ip '%s'",i,val);err->code="bad_ip";return -1;}
        }else if(!strcmp(kind,"cidr")){
            char buf[256],*sl; struct in_addr v4; struct in6_addr v6;
            snprintf(buf,sizeof(buf),"%s",val);sl=strchr(buf,'/');
            if(sl){r->pl=atoi(sl+1);*sl=0;}else r->pl=32;
            if(inet_pton(AF_INET,buf,&v4)==1){r->f=4;if(r->pl>32 || r->pl<0 || tp_normalize_prefix(r->f,buf,r->pl,r->pr,sizeof(r->pr))!=0){snprintf(err->detail,sizeof(err->detail),"targets[%zu]: invalid IPv4 prefix",i);err->code="bad_cidr";return -1;}}
            else if(inet_pton(AF_INET6,buf,&v6)==1){r->f=6;if(!sl)r->pl=128;if(r->pl>128 || r->pl<0 || tp_normalize_prefix(r->f,buf,r->pl,r->pr,sizeof(r->pr))!=0){snprintf(err->detail,sizeof(err->detail),"targets[%zu]: invalid IPv6 prefix",i);err->code="bad_cidr";return -1;}}
            else{snprintf(err->detail,sizeof(err->detail),"targets[%zu]: invalid CIDR",i);err->code="bad_cidr";return -1;}
            c++;
        }else if(!strcmp(kind,"range")){
            uint32_t s4=tp4u(si),e4=tp4u(ei);
            if(!si[0]||!ei[0]){snprintf(err->detail,sizeof(err->detail),"targets[%zu]: bad range",i);err->code="bad_range";return -1;}
            if(s4!=(uint32_t)-1||e4!=(uint32_t)-1){
                char *cid[MX_TR];int n;
                if(s4==(uint32_t)-1||e4==(uint32_t)-1||s4>e4){snprintf(err->detail,sizeof(err->detail),"targets[%zu]: bad range",i);err->code="bad_range";return -1;}
                n=tp_cidrs(s4,e4,cid,MX_TR-c);
                if (n < 0) {
                    snprintf(err->detail, sizeof(err->detail), "targets normalize to more than %d prefixes", MX_TR);
                    err->code = "too_many_targets";
                    return -1;
                }
                for(int q=0;q<n;q++){strncpy(rows[c].pr,cid[q],sizeof(rows[c].pr)-1);rows[c].pr[sizeof(rows[c].pr)-1]=0;char *sl2=strchr(rows[c].pr,'/');if(sl2){*sl2=0;rows[c].pl=atoi(sl2+1);}else rows[c].pl=32;rows[c].f=4;free(cid[q]);c++;}
            } else {
                struct in6_addr s6,e6;
                char *cid[MX_TR];int n;
                if(inet_pton(AF_INET6,si,&s6)!=1||inet_pton(AF_INET6,ei,&e6)!=1||tp6_compare(s6.s6_addr,e6.s6_addr)>0){snprintf(err->detail,sizeof(err->detail),"targets[%zu]: bad range",i);err->code="bad_range";return -1;}
                n=tp6_cidrs(s6.s6_addr,e6.s6_addr,cid,MX_TR-c);
                if (n < 0) {
                    snprintf(err->detail, sizeof(err->detail), "targets normalize to more than %d prefixes", MX_TR);
                    err->code = "too_many_targets";
                    return -1;
                }
                for(int q=0;q<n;q++){strncpy(rows[c].pr,cid[q],sizeof(rows[c].pr)-1);rows[c].pr[sizeof(rows[c].pr)-1]=0;char *sl2=strchr(rows[c].pr,'/');if(sl2){*sl2=0;rows[c].pl=atoi(sl2+1);}else rows[c].pl=128;rows[c].f=6;free(cid[q]);c++;}
            }
        }else{snprintf(err->detail,sizeof(err->detail),"targets[%zu]: unknown kind",i);err->code="bad_kind";return -1;}
    }
    *cnt=c;return 0;
}

static void tp_check_status(tp_policy_t *p){
    time_t now=tp_now_s();
    int per_ip_blocked = 0;
    if(!p->enabled){
        snprintf(p->status,sizeof(p->status),"%s",TP_STATUS_DISABLED);
        return;
    }
    if(p->started_at>(int64_t)now){
        snprintf(p->status,sizeof(p->status),"%s",TP_STATUS_SCHEDULED);
        return;
    }
    /* A per-IP quota has no single aggregate counter that represents the
     * policy state.  The lifecycle executor records exhausted clients in
     * quota_blocks; readback must consult that authoritative block table or
     * an exhausted client briefly appears active after a restart/API read. */
    if (p->quota_bytes > 0 && !strcmp(p->quota_mode, TP_QUOTA_PER_IP) &&
        g_tp_db) {
        sqlite3_stmt *blocked = NULL;
        if (sqlite3_prepare_v2(g_tp_db,
            "SELECT 1 FROM quota_blocks WHERE policy_id=? LIMIT 1",
            -1, &blocked, NULL) == SQLITE_OK) {
            sqlite3_bind_text(blocked, 1, p->id, -1, SQLITE_STATIC);
            per_ip_blocked = sqlite3_step(blocked) == SQLITE_ROW;
            sqlite3_finalize(blocked);
        }
    }
    if (per_ip_blocked) {
        snprintf(p->status,sizeof(p->status),"%s",TP_STATUS_BLOCKED_QUOTA);
        p->last_transition_at=(int64_t)now;
        return;
    }
    if(p->quota_bytes>0&&strcmp(p->quota_mode, TP_QUOTA_PER_IP)!=0&&p->used_bytes>=p->quota_bytes){
        snprintf(p->status,sizeof(p->status),"%s",TP_STATUS_BLOCKED_QUOTA);
        p->last_transition_at=(int64_t)now;
        return;
    }
    if(p->duration_count>0&&p->deadline_at>0&&now>=(time_t)p->deadline_at){
        snprintf(p->status,sizeof(p->status),"%s",TP_STATUS_BLOCKED_TIME);
        p->last_transition_at=(int)now;
        return;
    }
    if(!p->status[0] || !strcmp(p->status,TP_STATUS_SCHEDULED) || !strcmp(p->status,TP_STATUS_BLOCKED_TIME) || !strcmp(p->status,TP_STATUS_BLOCKED_QUOTA) || !strcmp(p->status,TP_STATUS_DISABLED)){
        snprintf(p->status,sizeof(p->status),"%s",TP_STATUS_ACTIVE);
    }
}

struct json_object *tp_json_from_policy(tp_policy_t *p,int inc_targets){
    struct json_object*o=json_object_new_object();time_t now=tp_now_s();long long rem=0;
    json_object_object_add(o,"id",json_object_new_string(p->id));
    json_object_object_add(o,"name",json_object_new_string(p->name));
    json_object_object_add(o,"remark",json_object_new_string(p->remark));
    json_object_object_add(o,"enabled",json_object_new_boolean(p->enabled));
    json_object_object_add(o,"rate_upload_kbps",json_object_new_int(p->rate_upload_kbps));
    json_object_object_add(o,"rate_download_kbps",json_object_new_int(p->rate_download_kbps));
    json_object_object_add(o,"rate_mode",json_object_new_string(p->rate_mode));
    json_object_object_add(o,"started_at",json_object_new_int64(p->started_at));
    json_object_object_add(o,"duration_count",json_object_new_int64(p->duration_count));
    json_object_object_add(o,"duration_unit",json_object_new_string(p->duration_unit));
    json_object_object_add(o,"deadline_at",json_object_new_int64(p->deadline_at));
    json_object_object_add(o,"quota_bytes",json_object_new_int64(p->quota_bytes));
    json_object_object_add(o,"quota_accounting",json_object_new_string(p->quota_accounting));
    json_object_object_add(o,"quota_mode",json_object_new_string(p->quota_mode));
    json_object_object_add(o,"used_upload_bytes",json_object_new_int64(p->used_upload_bytes));
    json_object_object_add(o,"used_download_bytes",json_object_new_int64(p->used_download_bytes));
    json_object_object_add(o,"used_bytes",json_object_new_int64(p->used_bytes));
    {
        struct json_object*a=json_object_new_array();char buf[64];strncpy(buf,p->deny_protocols,sizeof(buf)-1);buf[sizeof(buf)-1]=0;
        char*tk=strtok(buf,",");while(tk){while(*tk==' ')tk++;if(tk[0])json_object_array_add(a,json_object_new_string(tk));tk=strtok(NULL,",");}
        json_object_object_add(o,"deny_protocols",a);
    }
    json_object_object_add(o,"status",json_object_new_string(p->status));
    json_object_object_add(o,"runtime_reason",json_object_new_string(tp_expand_status_to_reason(p->status)));
    json_object_object_add(o,"last_transition_at",json_object_new_int64(p->last_transition_at));
    json_object_object_add(o,"generation",json_object_new_uint64(p->generation));
    if(p->duration_count>0&&p->deadline_at>0&&!strcmp(p->status,TP_STATUS_ACTIVE))rem=(long long)p->deadline_at-now;
    else rem=0;
    json_object_object_add(o,"remaining_seconds",json_object_new_int64(rem<0?0:rem));
    if (p->quota_bytes > 0 && strcmp(p->quota_mode, TP_QUOTA_PER_IP) == 0)
        json_object_object_add(o,"remaining_bytes",json_object_new_null());
    else
        json_object_object_add(o,"remaining_bytes",json_object_new_int64(p->quota_bytes>0?(p->quota_bytes-p->used_bytes):0));
    json_object_object_add(o,"created_at",json_object_new_int64(p->created_at));
    json_object_object_add(o,"updated_at",json_object_new_int64(p->updated_at));
    {
        struct json_object *rate = json_object_new_object();
        struct json_object *quota = json_object_new_object();
        struct json_object *life = json_object_new_object();
        struct json_object *runtime = json_object_new_object();
        json_object_object_add(rate, "upload_kbps", json_object_new_int(p->rate_upload_kbps));
        json_object_object_add(rate, "download_kbps", json_object_new_int(p->rate_download_kbps));
        json_object_object_add(rate, "mode", json_object_new_string(p->rate_mode));
        json_object_object_add(quota, "limit_bytes", json_object_new_int64(p->quota_bytes));
        json_object_object_add(quota, "accounting", json_object_new_string(p->quota_accounting));
        json_object_object_add(quota, "mode", json_object_new_string(p->quota_mode));
        json_object_object_add(quota, "used_upload_bytes", json_object_new_int64(p->used_upload_bytes));
        json_object_object_add(quota, "used_download_bytes", json_object_new_int64(p->used_download_bytes));
        json_object_object_add(quota, "used_total_bytes", json_object_new_int64(p->used_bytes));
        json_object_object_add(quota, "usage_scope", json_object_new_string(
            strcmp(p->quota_mode, TP_QUOTA_PER_IP) == 0 ? "per_ip_clients_aggregate" : "policy"));
        json_object_object_add(life, "starts_at", json_object_new_int64(p->started_at));
        json_object_object_add(life, "count", json_object_new_int64(p->duration_count));
        json_object_object_add(life, "unit", json_object_new_string(p->duration_unit));
        json_object_object_add(runtime, "state", json_object_new_string(p->status));
        json_object_object_add(runtime, "runtime_applied", json_object_new_boolean(0));
        json_object_object_add(runtime, "runtime_reason", json_object_new_string("dataplane_executor_pending"));
        json_object_object_add(runtime, "reason", json_object_new_string(tp_expand_status_to_reason(p->status)));
        json_object_object_add(runtime, "generation", json_object_new_uint64(p->generation));
        json_object_object_add(o, "rate", rate);
        json_object_object_add(o, "quota", quota);
        json_object_object_add(o, "lifetime", life);
        json_object_object_add(o, "runtime", runtime);
    }
    {
        struct json_object *clients = json_object_new_array();
        int truncated = 0;
        sqlite3_stmt *cu = NULL;
        if (g_tp_db && sqlite3_prepare_v2(g_tp_db,
            "SELECT u.family,u.client_ip,u.used_upload_bytes,u.used_download_bytes,u.used_bytes,"
            "EXISTS(SELECT 1 FROM quota_blocks b WHERE b.policy_id=u.policy_id AND b.family=u.family AND b.client_ip=u.client_ip) "
            "FROM quota_usage_ip u WHERE u.policy_id=? ORDER BY u.family,u.client_ip LIMIT 257",
            -1, &cu, NULL) == SQLITE_OK) {
            sqlite3_bind_text(cu, 1, p->id, -1, SQLITE_STATIC);
            while (sqlite3_step(cu) == SQLITE_ROW) {
                if (json_object_array_length(clients) >= 256) {
                    truncated = 1;
                    break;
                }
                struct json_object *client = json_object_new_object();
                json_object_object_add(client, "family", json_object_new_int(sqlite3_column_int(cu, 0)));
                json_object_object_add(client, "client_ip", json_object_new_string(
                    (const char *)sqlite3_column_text(cu, 1)));
                json_object_object_add(client, "used_upload_bytes", json_object_new_int64(sqlite3_column_int64(cu, 2)));
                json_object_object_add(client, "used_download_bytes", json_object_new_int64(sqlite3_column_int64(cu, 3)));
                json_object_object_add(client, "used_total_bytes", json_object_new_int64(sqlite3_column_int64(cu, 4)));
                json_object_object_add(client, "remaining_bytes", json_object_new_int64(
                    p->quota_bytes > sqlite3_column_int64(cu, 4) ?
                    p->quota_bytes - sqlite3_column_int64(cu, 4) : 0));
                json_object_object_add(client, "blocked", json_object_new_boolean(sqlite3_column_int(cu, 5)));
                json_object_array_add(clients, client);
            }
            sqlite3_finalize(cu);
        }
        json_object_object_add(o, "quota_clients", clients);
        json_object_object_add(o, "quota_clients_truncated", json_object_new_boolean(truncated));
    }
    if(inc_targets){
        if(g_tp_db){
            sqlite3_stmt*ts;struct json_object*a=json_object_new_array();
            if(sqlite3_prepare_v2(g_tp_db,"SELECT family,kind,prefix,prefix_len FROM targets WHERE policy_id=? ORDER BY family,prefix",-1,&ts,NULL)==SQLITE_OK){
                sqlite3_bind_text(ts,1,p->id,-1,SQLITE_STATIC);
                while(sqlite3_step(ts)==SQLITE_ROW){struct json_object*t=json_object_new_object();const char *prefix=(const char*)sqlite3_column_text(ts,2);int plen=sqlite3_column_int(ts,3);char value[320];snprintf(value,sizeof(value),"%s/%d",prefix?prefix:"",plen);json_object_object_add(t,"family",json_object_new_int(sqlite3_column_int(ts,0)));json_object_object_add(t,"kind",json_object_new_string("cidr"));json_object_object_add(t,"value",json_object_new_string(value));json_object_array_add(a,t);}
                sqlite3_finalize(ts);
            }
            json_object_object_add(o,"targets",a);
        }
    }
    return o;
}
struct json_object *tp_policy_list(void){
    pthread_mutex_lock(&g_tp_mtx);if(!g_tp_db){pthread_mutex_unlock(&g_tp_mtx);return NULL;}
    sqlite3_stmt*st=NULL;struct json_object*arr=json_object_new_array();
    if(sqlite3_prepare_v2(g_tp_db,"SELECT id,name,remark,enabled,rate_upload_kbps,rate_download_kbps,rate_mode,started_at,duration_count,duration_unit,deadline_at,quota_bytes,quota_accounting,quota_mode,deny_protocols,status,last_transition_at,generation,created_at,updated_at FROM policies ORDER BY created_at DESC",-1,&st,NULL)!=SQLITE_OK){json_object_put(arr);pthread_mutex_unlock(&g_tp_mtx);return NULL;}
    while(sqlite3_step(st)==SQLITE_ROW){tp_policy_t p;memset(&p,0,sizeof(p));size_t nb=(size_t)sqlite3_column_bytes(st,0);memcpy(p.id,(char*)sqlite3_column_text(st,0),nb<sizeof(p.id)?nb:sizeof(p.id)-1);nb=(size_t)sqlite3_column_bytes(st,1);memcpy(p.name,(char*)sqlite3_column_text(st,1),nb<sizeof(p.name)?nb:sizeof(p.name)-1);nb=(size_t)sqlite3_column_bytes(st,2);memcpy(p.remark,(char*)sqlite3_column_text(st,2),nb<sizeof(p.remark)?nb:sizeof(p.remark)-1);p.enabled=sqlite3_column_int(st,3);p.rate_upload_kbps=sqlite3_column_int(st,4);p.rate_download_kbps=sqlite3_column_int(st,5);copy_col(p.rate_mode,(const char*)sqlite3_column_text(st,6),sizeof(p.rate_mode));p.started_at=sqlite3_column_int64(st,7);p.duration_count=sqlite3_column_int64(st,8);copy_col(p.duration_unit,(const char*)sqlite3_column_text(st,9),sizeof(p.duration_unit));p.deadline_at=sqlite3_column_int64(st,10);p.quota_bytes=sqlite3_column_int64(st,11);copy_col(p.quota_accounting,(const char*)sqlite3_column_text(st,12),sizeof(p.quota_accounting));copy_col(p.quota_mode,(const char*)sqlite3_column_text(st,13),sizeof(p.quota_mode));nb=(size_t)sqlite3_column_bytes(st,14);memcpy(p.deny_protocols,(char*)sqlite3_column_text(st,14),nb<sizeof(p.deny_protocols)?nb:sizeof(p.deny_protocols)-1);copy_col(p.status,(const char*)sqlite3_column_text(st,15),sizeof(p.status));p.last_transition_at=sqlite3_column_int64(st,16);p.generation=(unsigned)sqlite3_column_int64(st,17);p.created_at=sqlite3_column_int64(st,18);p.updated_at=sqlite3_column_int64(st,19);tp_load_usage(g_tp_db,&p);tp_check_status(&p);struct json_object*o=tp_json_from_policy(&p,1);if(o)json_object_array_add(arr,o);}
    sqlite3_finalize(st);pthread_mutex_unlock(&g_tp_mtx);return arr;
}
struct json_object *tp_policy_get(const char *id,int expand){
    pthread_mutex_lock(&g_tp_mtx);if(!g_tp_db){pthread_mutex_unlock(&g_tp_mtx);return NULL;}
    sqlite3_stmt*st=NULL;struct json_object*res=NULL;
    if(sqlite3_prepare_v2(g_tp_db,"SELECT id,name,remark,enabled,rate_upload_kbps,rate_download_kbps,rate_mode,started_at,duration_count,duration_unit,deadline_at,quota_bytes,quota_accounting,quota_mode,deny_protocols,status,last_transition_at,generation,created_at,updated_at FROM policies WHERE id=?",-1,&st,NULL)!=SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);return NULL;}
    sqlite3_bind_text(st,1,id,-1,SQLITE_STATIC);
    if(sqlite3_step(st)==SQLITE_ROW){tp_policy_t p;memset(&p,0,sizeof(p));size_t nb=(size_t)sqlite3_column_bytes(st,0);memcpy(p.id,(char*)sqlite3_column_text(st,0),nb<sizeof(p.id)?nb:sizeof(p.id)-1);nb=(size_t)sqlite3_column_bytes(st,1);memcpy(p.name,(char*)sqlite3_column_text(st,1),nb<sizeof(p.name)?nb:sizeof(p.name)-1);nb=(size_t)sqlite3_column_bytes(st,2);memcpy(p.remark,(char*)sqlite3_column_text(st,2),nb<sizeof(p.remark)?nb:sizeof(p.remark)-1);p.enabled=sqlite3_column_int(st,3);p.rate_upload_kbps=sqlite3_column_int(st,4);p.rate_download_kbps=sqlite3_column_int(st,5);copy_col(p.rate_mode,(const char*)sqlite3_column_text(st,6),sizeof(p.rate_mode));p.started_at=sqlite3_column_int64(st,7);p.duration_count=sqlite3_column_int64(st,8);copy_col(p.duration_unit,(const char*)sqlite3_column_text(st,9),sizeof(p.duration_unit));p.deadline_at=sqlite3_column_int64(st,10);p.quota_bytes=sqlite3_column_int64(st,11);copy_col(p.quota_accounting,(const char*)sqlite3_column_text(st,12),sizeof(p.quota_accounting));copy_col(p.quota_mode,(const char*)sqlite3_column_text(st,13),sizeof(p.quota_mode));nb=(size_t)sqlite3_column_bytes(st,14);memcpy(p.deny_protocols,(char*)sqlite3_column_text(st,14),nb<sizeof(p.deny_protocols)?nb:sizeof(p.deny_protocols)-1);copy_col(p.status,(const char*)sqlite3_column_text(st,15),sizeof(p.status));p.last_transition_at=sqlite3_column_int64(st,16);p.generation=(unsigned)sqlite3_column_int64(st,17);p.created_at=sqlite3_column_int64(st,18);p.updated_at=sqlite3_column_int64(st,19);tp_load_usage(g_tp_db,&p);tp_check_status(&p);res=tp_json_from_policy(&p,expand);}
    sqlite3_finalize(st);pthread_mutex_unlock(&g_tp_mtx);return res;
}

static void tp_load_usage(sqlite3 *db, tp_policy_t *p)
{
    sqlite3_stmt *us = NULL;

    if (!db || !p)
        return;
    p->used_upload_bytes = 0;
    p->used_download_bytes = 0;
    p->used_bytes = 0;
    if (sqlite3_prepare_v2(db,
        "SELECT used_upload_bytes,used_download_bytes,used_bytes "
        "FROM quota_usage WHERE policy_id=?", -1, &us, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(us, 1, p->id, -1, SQLITE_STATIC);
    if (sqlite3_step(us) == SQLITE_ROW) {
        p->used_upload_bytes = sqlite3_column_int64(us, 0);
        p->used_download_bytes = sqlite3_column_int64(us, 1);
        p->used_bytes = sqlite3_column_int64(us, 2);
    }
    sqlite3_finalize(us);
}

/* CRUD helper to load existing row into tp_policy_t (must hold mutex) */
static int tp_load_locked(sqlite3 *db,const char *id,tp_policy_t *p){
    sqlite3_stmt*st=NULL;
    if(sqlite3_prepare_v2(db,"SELECT id,name,remark,enabled,rate_upload_kbps,rate_download_kbps,rate_mode,started_at,duration_count,duration_unit,deadline_at,quota_bytes,quota_accounting,quota_mode,deny_protocols,status,last_transition_at,generation,created_at,updated_at FROM policies WHERE id=?",-1,&st,NULL)!=SQLITE_OK)return -1;
    sqlite3_bind_text(st,1,id,-1,SQLITE_STATIC);
    int rc=-1;
    if(sqlite3_step(st)==SQLITE_ROW){
        memset(p,0,sizeof(*p));
        size_t nb=(size_t)sqlite3_column_bytes(st,0);memcpy(p->id,(char*)sqlite3_column_text(st,0),nb<sizeof(p->id)?nb:sizeof(p->id)-1);
        nb=(size_t)sqlite3_column_bytes(st,1);memcpy(p->name,(char*)sqlite3_column_text(st,1),nb<sizeof(p->name)?nb:sizeof(p->name)-1);
        nb=(size_t)sqlite3_column_bytes(st,2);memcpy(p->remark,(char*)sqlite3_column_text(st,2),nb<sizeof(p->remark)?nb:sizeof(p->remark)-1);
        p->enabled=sqlite3_column_int(st,3);p->rate_upload_kbps=sqlite3_column_int(st,4);p->rate_download_kbps=sqlite3_column_int(st,5);
        copy_col(p->rate_mode,(const char*)sqlite3_column_text(st,6),sizeof(p->rate_mode));
        p->started_at=sqlite3_column_int64(st,7);p->duration_count=sqlite3_column_int64(st,8);
        copy_col(p->duration_unit,(const char*)sqlite3_column_text(st,9),sizeof(p->duration_unit));
        p->deadline_at=sqlite3_column_int64(st,10);p->quota_bytes=sqlite3_column_int64(st,11);
        copy_col(p->quota_accounting,(const char*)sqlite3_column_text(st,12),sizeof(p->quota_accounting));
        copy_col(p->quota_mode,(const char*)sqlite3_column_text(st,13),sizeof(p->quota_mode));
        nb=(size_t)sqlite3_column_bytes(st,14);memcpy(p->deny_protocols,(char*)sqlite3_column_text(st,14),nb<sizeof(p->deny_protocols)?nb:sizeof(p->deny_protocols)-1);
        copy_col(p->status,(const char*)sqlite3_column_text(st,15),sizeof(p->status));
        p->last_transition_at=sqlite3_column_int64(st,16);p->generation=(unsigned)sqlite3_column_int64(st,17);p->created_at=sqlite3_column_int64(st,18);p->updated_at=sqlite3_column_int64(st,19);tp_load_usage(db,p);
        rc=0;
    }
    sqlite3_finalize(st);
    return rc;
}
static void tp_load_free(tp_policy_t *p){
    /* these point into sqlite heap; do NOT free unless duplicated. We strduped? adjust here later => skip. */
    (void)p;
}
static int tp_generate_default_id(const char *prefix,char *out,size_t out_len){
    static unsigned seq=0;
    snprintf(out,out_len,"%s_%ld_%u",prefix?prefix:"tp",(long)tp_now_s(),(seq++)&0xffff);
    return 0;
}

struct json_object *tp_policy_create(struct json_object *body,tp_error_t *err){
    memset(err,0,sizeof(*err));
    if(!body||!json_object_is_type(body,json_type_object)){snprintf(err->detail,sizeof(err->detail),"body must be object");err->code="bad_body";return NULL;}
    const char *name=jsd(body,"name",""),*id_in=jsd(body,"id","");
    int enabled=jbd(body,"enabled",1);
    int rate_up=(int)ji64(body,"rate_upload_kbps",0),rate_down=(int)ji64(body,"rate_download_kbps",0);
    const char *rate_mode=jsd(body,"rate_mode","per_ip");
    int64_t started=ji64(body,"started_at",0),dcount=ji64(body,"duration_count",0);
    const char *dunit=jsd(body,"duration_unit","days");
    long long quota=ji64(body,"quota_bytes",0);
    const char *qacct=jsd(body,"quota_accounting","upload_plus_download"),*qmode=jsd(body,"quota_mode","per_ip");
    const char *deny=jsd(body,"deny_protocols","");
    struct json_object *tar=NULL;
    if(!json_object_object_get_ex(body,"targets",&tar)||!tar){snprintf(err->detail,sizeof(err->detail),"targets required");err->code="bad_targets";return NULL;}
    tr_t rows[MX_TR];int nrows=0;
    if(tp_expand(tar,rows,&nrows,err)<0)return NULL;
    if (tp_dedupe_rows(rows, &nrows) != 0 || nrows <= 0) {
        snprintf(err->detail, sizeof(err->detail), "targets must contain at least one valid target");
        err->code = "bad_targets";
        return NULL;
    }

    if(strcasecmp(rate_mode,"per_ip") && strcasecmp(rate_mode,"shared")){snprintf(err->detail,sizeof(err->detail),"rate_mode must be per_ip or shared");err->code="unsupported_rate_mode";return NULL;}
    if(strcasecmp(qmode, TP_QUOTA_PER_IP) && strcasecmp(qmode, TP_QUOTA_SHARED)){snprintf(err->detail,sizeof(err->detail),"quota_mode must be per_ip or shared");err->code="unsupported_quota_mode";return NULL;}
    if(strcmp(qacct,"upload_plus_download")){snprintf(err->detail,sizeof(err->detail),"only upload_plus_download accounting supported");err->code="bad_quota_acct";return NULL;}
    if(!tp_valid_unit(dunit)){snprintf(err->detail,sizeof(err->detail),"bad duration unit");err->code="bad_unit";return NULL;}
    if(rate_up<0||rate_down<0||dcount<0||quota<0){snprintf(err->detail,sizeof(err->detail),"negative value");err->code="bad_value";return NULL;}
    if ((rate_up > 0 || rate_down > 0) && !strcasecmp(rate_mode, "per_ip")) {
        for (int i = 0; i < nrows; i++) {
            if ((rows[i].f == 4 && rows[i].pl != 32) ||
                (rows[i].f == 6 && rows[i].pl != 128)) {
                snprintf(err->detail, sizeof(err->detail),
                         "per_ip rate limiting requires host targets; targets[%d] is a prefix",
                         i);
                err->code = "rate_target_requires_host";
                return NULL;
            }
        }
    }
    /* validate protocols tokens */
    {char buf[256];snprintf(buf,sizeof(buf),"%s",deny);char*tk=strtok(buf,",");while(tk){while(*tk==' ')tk++;if(tk[0]&&strcasecmp(tk,"tcp")&&strcasecmp(tk,"udp")&&strcasecmp(tk,"icmp")){snprintf(err->detail,sizeof(err->detail),"bad deny protocol '%s'",tk);err->code="bad_proto";return NULL;}tk=strtok(NULL,",");}}

    pthread_mutex_lock(&g_tp_mtx);
    if(!g_tp_db){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"db not init");err->code="db_down";return NULL;}
    char id[65];if(id_in[0]){strncpy(id,id_in,sizeof(id)-1);id[sizeof(id)-1]=0;}else tp_generate_default_id("tp",id,sizeof(id));
    /* duplicate check */
    sqlite3_stmt*chk;if(sqlite3_prepare_v2(g_tp_db,"SELECT id FROM policies WHERE id=?",-1,&chk,NULL)==SQLITE_OK){sqlite3_bind_text(chk,1,id,-1,SQLITE_STATIC);if(sqlite3_step(chk)==SQLITE_ROW){sqlite3_finalize(chk);pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"id exists");err->code="dup_id";return NULL;}sqlite3_finalize(chk);}
    {
        int overlap = tp_check_enabled_overlap(g_tp_db, id, enabled, rows, nrows, err);
        if (overlap != 0) {
            pthread_mutex_unlock(&g_tp_mtx);
            return NULL;
        }
    }
    time_t now=tp_now_s();if(started==0)started=(int64_t)now;
    time_t dl=0;if(dcount>0){if(tp_compute_deadline(started,dcount,dunit,&dl)<0){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"time overflow");err->code="overflow";return NULL;}}
    if(tp_sql(g_tp_db,"BEGIN",NULL)!=SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"begin failed");err->code="txn";return NULL;}
    sqlite3_stmt*ins=NULL;int ok=0;
    if(sqlite3_prepare_v2(g_tp_db,"INSERT INTO policies(id,name,remark,enabled,rate_upload_kbps,rate_download_kbps,rate_mode,started_at,duration_count,duration_unit,deadline_at,quota_bytes,quota_accounting,quota_mode,deny_protocols,status,last_transition_at,generation,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",-1,&ins,NULL)==SQLITE_OK){
        sqlite3_bind_text(ins,1,id,-1,SQLITE_STATIC);sqlite3_bind_text(ins,2,name,-1,SQLITE_STATIC);sqlite3_bind_text(ins,3,jsd(body,"remark",""),-1,SQLITE_STATIC);sqlite3_bind_int(ins,4,enabled);
        sqlite3_bind_int(ins,5,rate_up);sqlite3_bind_int(ins,6,rate_down);sqlite3_bind_text(ins,7,rate_mode,-1,SQLITE_STATIC);sqlite3_bind_int64(ins,8,started);sqlite3_bind_int64(ins,9,dcount);sqlite3_bind_text(ins,10,dunit,-1,SQLITE_STATIC);sqlite3_bind_int64(ins,11,(sqlite3_int64)dl);
        sqlite3_bind_int64(ins,12,quota);sqlite3_bind_text(ins,13,qacct,-1,SQLITE_STATIC);sqlite3_bind_text(ins,14,qmode,-1,SQLITE_STATIC);sqlite3_bind_text(ins,15,deny,-1,SQLITE_STATIC);
        sqlite3_bind_text(ins,16,started > (int64_t)now ? TP_STATUS_SCHEDULED : (enabled ? TP_STATUS_ACTIVE : TP_STATUS_DISABLED),-1,SQLITE_STATIC);sqlite3_bind_int64(ins,17,(sqlite3_int64)now);sqlite3_bind_int(ins,18,1);sqlite3_bind_int64(ins,19,now);sqlite3_bind_int64(ins,20,now);
        if(sqlite3_step(ins)==SQLITE_DONE)ok=1;sqlite3_finalize(ins);
    }
    if(!ok){tp_sql(g_tp_db,"ROLLBACK",NULL);pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"insert failed");err->code="insert";return NULL;}
    ok=0;if(sqlite3_prepare_v2(g_tp_db,"INSERT INTO targets(policy_id,family,kind,prefix,prefix_len) VALUES(?,?,?,?,?)",-1,&ins,NULL)==SQLITE_OK){
        for(int i=0;i<nrows;i++){sqlite3_bind_text(ins,1,id,-1,SQLITE_STATIC);sqlite3_bind_int(ins,2,rows[i].f);sqlite3_bind_text(ins,3,"cidr",-1,SQLITE_STATIC);sqlite3_bind_text(ins,4,rows[i].pr,-1,SQLITE_STATIC);sqlite3_bind_int(ins,5,rows[i].pl);if(sqlite3_step(ins)!=SQLITE_DONE){sqlite3_reset(ins);break;}sqlite3_reset(ins);if(i==nrows-1)ok=1;}
        sqlite3_finalize(ins);
    }
    if(!ok){tp_sql(g_tp_db,"ROLLBACK",NULL);pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"targets insert failed");err->code="insert";return NULL;}
    if(tp_sql(g_tp_db,"COMMIT",NULL)!=SQLITE_OK){tp_sql(g_tp_db,"ROLLBACK",NULL);pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"commit failed");err->code="txn";return NULL;}
    pthread_mutex_unlock(&g_tp_mtx);
    struct json_object*res=tp_policy_get(id,1);if(res)return res;
    snprintf(err->detail,sizeof(err->detail),"saved but readback failed");err->code="readback";return NULL;
}

struct json_object *tp_policy_update(const char *id,struct json_object *body,tp_error_t *err){
    memset(err,0,sizeof(*err));
    if(!id||!id[0]||!body||!json_object_is_type(body,json_type_object)){snprintf(err->detail,sizeof(err->detail),"bad id/body");err->code="bad_body";return NULL;}
    pthread_mutex_lock(&g_tp_mtx);if(!g_tp_db){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"db down");err->code="db_down";return NULL;}
    tp_policy_t old;memset(&old,0,sizeof(old));
    if(tp_load_locked(g_tp_db,id,&old)<0){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"not found");err->code="not_found";return NULL;}
    const char *name=jsd(body,"name",old.name);
    int enabled=jbd(body,"enabled",old.enabled);
    int rate_up=(int)ji64(body,"rate_upload_kbps",old.rate_upload_kbps);
    int rate_down=(int)ji64(body,"rate_download_kbps",old.rate_download_kbps);
    const char *rate_mode=jsd(body,"rate_mode",old.rate_mode);
    int64_t started=ji64(body,"started_at",old.started_at);
    int64_t dcount=ji64(body,"duration_count",old.duration_count);
    const char *dunit=jsd(body,"duration_unit",old.duration_unit);
    long long quota=ji64(body,"quota_bytes",old.quota_bytes);
    const char *qacct=jsd(body,"quota_accounting",old.quota_accounting[0] ? old.quota_accounting : "upload_plus_download");
    const char *qmode=jsd(body,"quota_mode",old.quota_mode[0] ? old.quota_mode : "per_ip");
    const char *deny=jsd(body,"deny_protocols",old.deny_protocols);
    int reset_usage = jbd(body, "reset_usage", 0);
    struct json_object*tar=NULL;tr_t rows[MX_TR];int nrows=0;
    if(json_object_object_get_ex(body,"targets",&tar)){
        if(tp_expand(tar,rows,&nrows,err)<0){pthread_mutex_unlock(&g_tp_mtx);return NULL;}
        if (tp_dedupe_rows(rows, &nrows) != 0 || nrows <= 0) {
            pthread_mutex_unlock(&g_tp_mtx);
            snprintf(err->detail, sizeof(err->detail), "targets must contain at least one valid target");
            err->code = "bad_targets";
            return NULL;
        }
    } else {
        /* A partial update still has to validate the effective target set.
         * Otherwise changing only a rate could silently bypass the host-only
         * classifier constraint for an existing CIDR/range rule. */
        sqlite3_stmt *old_targets = NULL;
        if(sqlite3_prepare_v2(g_tp_db,
            "SELECT family,prefix,prefix_len FROM targets WHERE policy_id=? ORDER BY family,prefix",
            -1, &old_targets, NULL) != SQLITE_OK){
            pthread_mutex_unlock(&g_tp_mtx);
            snprintf(err->detail,sizeof(err->detail),"targets query failed");
            err->code="db_query";
            return NULL;
        }
        sqlite3_bind_text(old_targets,1,id,-1,SQLITE_STATIC);
        while(sqlite3_step(old_targets)==SQLITE_ROW){
            const char *prefix=(const char *)sqlite3_column_text(old_targets,1);
            if(nrows >= MX_TR || !prefix){
                sqlite3_finalize(old_targets);
                pthread_mutex_unlock(&g_tp_mtx);
                snprintf(err->detail,sizeof(err->detail),"too many targets");
                err->code="too_many_targets";
                return NULL;
            }
            rows[nrows].f=sqlite3_column_int(old_targets,0);
            rows[nrows].pl=sqlite3_column_int(old_targets,2);
            snprintf(rows[nrows].pr,sizeof(rows[nrows].pr),"%s",prefix);
            nrows++;
        }
        sqlite3_finalize(old_targets);
    }
    if(strcasecmp(rate_mode,"per_ip") && strcasecmp(rate_mode,"shared")){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"rate_mode must be per_ip or shared");err->code="unsupported_rate_mode";return NULL;}
    if(strcasecmp(qmode, TP_QUOTA_PER_IP) && strcasecmp(qmode, TP_QUOTA_SHARED)){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"quota_mode must be per_ip or shared");err->code="unsupported_quota_mode";return NULL;}
    if(!tp_valid_unit(dunit)){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"bad unit");err->code="bad_unit";return NULL;}
    if(rate_up<0||rate_down<0||dcount<0||quota<0){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"negative");err->code="bad_value";return NULL;}
    if ((rate_up > 0 || rate_down > 0) && !strcasecmp(rate_mode, "per_ip")) {
        for (int i = 0; i < nrows; i++) {
            if ((rows[i].f == 4 && rows[i].pl != 32) ||
                (rows[i].f == 6 && rows[i].pl != 128)) {
                pthread_mutex_unlock(&g_tp_mtx);
                snprintf(err->detail, sizeof(err->detail),
                         "per_ip rate limiting requires host targets; targets[%d] is a prefix",
                         i);
                err->code = "rate_target_requires_host";
                return NULL;
            }
        }
    }
    if(started==0)started=old.started_at;
    time_t dl=old.deadline_at;if(dcount>0){if(tp_compute_deadline(started,dcount,dunit,&dl)<0){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"overflow");err->code="overflow";return NULL;}}else dl=0;
    /* validate protocols */
    {char buf[256];snprintf(buf,sizeof(buf),"%s",deny);char*tk=strtok(buf,",");while(tk){while(*tk==' ')tk++;if(tk[0]&&strcasecmp(tk,"tcp")&&strcasecmp(tk,"udp")&&strcasecmp(tk,"icmp")){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"bad proto");err->code="bad_proto";return NULL;}tk=strtok(NULL,",");}}
    {
        int overlap = tp_check_enabled_overlap(g_tp_db, id, enabled, rows, nrows, err);
        if (overlap != 0) {
            pthread_mutex_unlock(&g_tp_mtx);
            return NULL;
        }
    }
    if(tp_sql(g_tp_db,"BEGIN",NULL)!=SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"txn");err->code="txn";return NULL;}
    sqlite3_stmt*up=NULL;int uok=0;time_t now=tp_now_s();
    if(strcmp(qacct,"upload_plus_download")){tp_sql(g_tp_db,"ROLLBACK",NULL);pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"only upload_plus_download accounting supported");err->code="bad_quota_acct";return NULL;}
    if(sqlite3_prepare_v2(g_tp_db,"UPDATE policies SET name=?,remark=?,enabled=?,rate_upload_kbps=?,rate_download_kbps=?,rate_mode=?,started_at=?,duration_count=?,duration_unit=?,deadline_at=?,quota_bytes=?,quota_accounting=?,quota_mode=?,deny_protocols=?,status=?,last_transition_at=?,generation=generation+1,updated_at=? WHERE id=?",-1,&up,NULL)==SQLITE_OK){
        sqlite3_bind_text(up,1,name,-1,SQLITE_STATIC);sqlite3_bind_text(up,2,jsd(body,"remark",old.remark),-1,SQLITE_STATIC);sqlite3_bind_int(up,3,enabled);sqlite3_bind_int(up,4,rate_up);sqlite3_bind_int(up,5,rate_down);sqlite3_bind_text(up,6,rate_mode,-1,SQLITE_STATIC);sqlite3_bind_int64(up,7,started);sqlite3_bind_int64(up,8,dcount);sqlite3_bind_text(up,9,dunit,-1,SQLITE_STATIC);sqlite3_bind_int64(up,10,(sqlite3_int64)dl);sqlite3_bind_int64(up,11,quota);sqlite3_bind_text(up,12,qacct,-1,SQLITE_STATIC);sqlite3_bind_text(up,13,qmode,-1,SQLITE_STATIC);sqlite3_bind_text(up,14,deny,-1,SQLITE_STATIC);sqlite3_bind_text(up,15,started > (int64_t)now ? TP_STATUS_SCHEDULED : (enabled ? TP_STATUS_ACTIVE : TP_STATUS_DISABLED),-1,SQLITE_STATIC);sqlite3_bind_int64(up,16,(sqlite3_int64)now);sqlite3_bind_int64(up,17,(sqlite3_int64)now);sqlite3_bind_text(up,18,id,-1,SQLITE_STATIC);
        if(sqlite3_step(up)==SQLITE_DONE)uok=1;sqlite3_finalize(up);
    }
    if(!uok){tp_sql(g_tp_db,"ROLLBACK",NULL);pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"update failed");err->code="update";return NULL;}
    if(tar){
        sqlite3_stmt*d=NULL;
        if(sqlite3_prepare_v2(g_tp_db,"DELETE FROM targets WHERE policy_id=?",-1,&d,NULL)==SQLITE_OK){sqlite3_bind_text(d,1,id,-1,SQLITE_STATIC);sqlite3_step(d);sqlite3_finalize(d);}
        if(sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_blocks WHERE policy_id=?",-1,&d,NULL)==SQLITE_OK){sqlite3_bind_text(d,1,id,-1,SQLITE_STATIC);sqlite3_step(d);sqlite3_finalize(d);}
        sqlite3_stmt*in=NULL;
        if(sqlite3_prepare_v2(g_tp_db,"INSERT INTO targets(policy_id,family,kind,prefix,prefix_len) VALUES(?,?,?,?,?)",-1,&in,NULL)==SQLITE_OK){for(int i=0;i<nrows;i++){sqlite3_bind_text(in,1,id,-1,SQLITE_STATIC);sqlite3_bind_int(in,2,rows[i].f);sqlite3_bind_text(in,3,"cidr",-1,SQLITE_STATIC);sqlite3_bind_text(in,4,rows[i].pr,-1,SQLITE_STATIC);sqlite3_bind_int(in,5,rows[i].pl);sqlite3_step(in);sqlite3_reset(in);}sqlite3_finalize(in);}
    }
    /* Disabling a rule must immediately remove per-client blocks.  A later
     * re-enable should start from the stored usage, not from stale kernel
     * deny state.  Explicit reset_usage is atomic with a renewal/update so a
     * failed dataplane apply can restore both the deadline and the counters. */
    if (!enabled || reset_usage || quota <= 0) {
        sqlite3_stmt *d = NULL;
        if (sqlite3_prepare_v2(g_tp_db,
            "DELETE FROM quota_blocks WHERE policy_id=?", -1, &d, NULL) != SQLITE_OK) {
            tp_sql(g_tp_db,"ROLLBACK",NULL); pthread_mutex_unlock(&g_tp_mtx);
            snprintf(err->detail,sizeof(err->detail),"quota block cleanup failed"); err->code="update"; return NULL;
        }
        sqlite3_bind_text(d,1,id,-1,SQLITE_STATIC);
        if (sqlite3_step(d) != SQLITE_DONE) {
            sqlite3_finalize(d); tp_sql(g_tp_db,"ROLLBACK",NULL); pthread_mutex_unlock(&g_tp_mtx);
            snprintf(err->detail,sizeof(err->detail),"quota block cleanup failed"); err->code="update"; return NULL;
        }
        sqlite3_finalize(d);
    }
    if (reset_usage) {
        sqlite3_stmt *d = NULL;
        if (sqlite3_prepare_v2(g_tp_db,
            "DELETE FROM quota_usage_ip WHERE policy_id=?", -1, &d, NULL) != SQLITE_OK) {
            tp_sql(g_tp_db,"ROLLBACK",NULL); pthread_mutex_unlock(&g_tp_mtx);
            snprintf(err->detail,sizeof(err->detail),"quota usage reset failed"); err->code="update"; return NULL;
        }
        sqlite3_bind_text(d,1,id,-1,SQLITE_STATIC);
        if (sqlite3_step(d) != SQLITE_DONE) {
            sqlite3_finalize(d); tp_sql(g_tp_db,"ROLLBACK",NULL); pthread_mutex_unlock(&g_tp_mtx);
            snprintf(err->detail,sizeof(err->detail),"quota usage reset failed"); err->code="update"; return NULL;
        }
        sqlite3_finalize(d);
        if (sqlite3_prepare_v2(g_tp_db,
            "DELETE FROM quota_usage WHERE policy_id=?", -1, &d, NULL) != SQLITE_OK) {
            tp_sql(g_tp_db,"ROLLBACK",NULL); pthread_mutex_unlock(&g_tp_mtx);
            snprintf(err->detail,sizeof(err->detail),"quota usage reset failed"); err->code="update"; return NULL;
        }
        sqlite3_bind_text(d,1,id,-1,SQLITE_STATIC);
        if (sqlite3_step(d) != SQLITE_DONE) {
            sqlite3_finalize(d); tp_sql(g_tp_db,"ROLLBACK",NULL); pthread_mutex_unlock(&g_tp_mtx);
            snprintf(err->detail,sizeof(err->detail),"quota usage reset failed"); err->code="update"; return NULL;
        }
        sqlite3_finalize(d);
    }
    if(tp_sql(g_tp_db,"COMMIT",NULL)!=SQLITE_OK){tp_sql(g_tp_db,"ROLLBACK",NULL);pthread_mutex_unlock(&g_tp_mtx);snprintf(err->detail,sizeof(err->detail),"commit");err->code="txn";return NULL;}
    pthread_mutex_unlock(&g_tp_mtx);
    return tp_policy_get(id,1);
}

/* Capture an exact storage generation for rollback.  tp_policy_get() is a
 * display view: it runs status recomputation and caps quota clients at 256,
 * neither of which is acceptable for restoring a previous write.  This
 * function keeps the raw columns and every quota row instead. */
struct json_object *tp_policy_snapshot(const char *id)
{
    struct json_object *out = NULL;
    struct json_object *targets = NULL;
    struct json_object *clients = NULL;
    sqlite3_stmt *st = NULL;
    tp_policy_t p;

    pthread_mutex_lock(&g_tp_mtx);
    if (!g_tp_db || !id || !id[0] || tp_load_locked(g_tp_db, id, &p) < 0)
        goto out;
    out = json_object_new_object();
    if (!out)
        goto out;
    json_object_object_add(out, "_tp_snapshot", json_object_new_int(1));
    json_object_object_add(out, "id", json_object_new_string(p.id));
    json_object_object_add(out, "name", json_object_new_string(p.name));
    json_object_object_add(out, "remark", json_object_new_string(p.remark));
    json_object_object_add(out, "enabled", json_object_new_boolean(p.enabled));
    json_object_object_add(out, "rate_upload_kbps", json_object_new_int(p.rate_upload_kbps));
    json_object_object_add(out, "rate_download_kbps", json_object_new_int(p.rate_download_kbps));
    json_object_object_add(out, "rate_mode", json_object_new_string(p.rate_mode));
    json_object_object_add(out, "started_at", json_object_new_int64(p.started_at));
    json_object_object_add(out, "duration_count", json_object_new_int64(p.duration_count));
    json_object_object_add(out, "duration_unit", json_object_new_string(p.duration_unit));
    json_object_object_add(out, "deadline_at", json_object_new_int64(p.deadline_at));
    json_object_object_add(out, "quota_bytes", json_object_new_int64(p.quota_bytes));
    json_object_object_add(out, "quota_accounting", json_object_new_string(p.quota_accounting));
    json_object_object_add(out, "quota_mode", json_object_new_string(p.quota_mode));
    json_object_object_add(out, "deny_protocols", json_object_new_string(p.deny_protocols));
    json_object_object_add(out, "status", json_object_new_string(p.status));
    json_object_object_add(out, "last_transition_at", json_object_new_int64(p.last_transition_at));
    json_object_object_add(out, "generation", json_object_new_uint64(p.generation));
    json_object_object_add(out, "created_at", json_object_new_int64(p.created_at));
    json_object_object_add(out, "updated_at", json_object_new_int64(p.updated_at));

    targets = json_object_new_array();
    if (sqlite3_prepare_v2(g_tp_db,
        "SELECT family,prefix,prefix_len FROM targets WHERE policy_id=? ORDER BY family,prefix",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *prefix = (const char *)sqlite3_column_text(st, 1);
            int family = sqlite3_column_int(st, 0);
            int plen = sqlite3_column_int(st, 2);
            struct json_object *t = json_object_new_object();
            char value[320];

            if (!prefix || !t)
                continue;
            snprintf(value, sizeof(value), "%s/%d", prefix, plen);
            json_object_object_add(t, "family", json_object_new_int(family));
            json_object_object_add(t, "kind", json_object_new_string("cidr"));
            json_object_object_add(t, "value", json_object_new_string(value));
            json_object_array_add(targets, t);
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    json_object_object_add(out, "targets", targets);

    clients = json_object_new_array();
    if (sqlite3_prepare_v2(g_tp_db,
        "SELECT u.family,u.client_ip,u.used_upload_bytes,u.used_download_bytes,"
        "u.used_bytes,u.checkpoint_at,b.blocked_at "
        "FROM quota_usage_ip u "
        "LEFT JOIN quota_blocks b ON b.policy_id=u.policy_id AND b.family=u.family "
        "AND b.client_ip=u.client_ip "
        "WHERE u.policy_id=? ORDER BY u.family,u.client_ip",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *ip = (const char *)sqlite3_column_text(st, 1);
            struct json_object *c = json_object_new_object();

            if (!ip || !c)
                continue;
            json_object_object_add(c, "family", json_object_new_int(sqlite3_column_int(st, 0)));
            json_object_object_add(c, "client_ip", json_object_new_string(ip));
            json_object_object_add(c, "used_upload_bytes", json_object_new_int64(sqlite3_column_int64(st, 2)));
            json_object_object_add(c, "used_download_bytes", json_object_new_int64(sqlite3_column_int64(st, 3)));
            json_object_object_add(c, "used_total_bytes", json_object_new_int64(sqlite3_column_int64(st, 4)));
            json_object_object_add(c, "checkpoint_at", json_object_new_int64(sqlite3_column_int64(st, 5)));
            if (sqlite3_column_type(st, 6) != SQLITE_NULL)
                json_object_object_add(c, "blocked_at", json_object_new_int64(sqlite3_column_int64(st, 6)));
            json_object_array_add(clients, c);
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    json_object_object_add(out, "quota_clients", clients);

    if (sqlite3_prepare_v2(g_tp_db,
        "SELECT used_upload_bytes,used_download_bytes,used_bytes,checkpoint_at "
        "FROM quota_usage WHERE policy_id=?",
        -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) {
            json_object_object_add(out, "has_quota_usage", json_object_new_boolean(1));
            json_object_object_add(out, "used_upload_bytes", json_object_new_int64(sqlite3_column_int64(st, 0)));
            json_object_object_add(out, "used_download_bytes", json_object_new_int64(sqlite3_column_int64(st, 1)));
            json_object_object_add(out, "used_bytes", json_object_new_int64(sqlite3_column_int64(st, 2)));
            json_object_object_add(out, "checkpoint_at", json_object_new_int64(sqlite3_column_int64(st, 3)));
        } else {
            json_object_object_add(out, "has_quota_usage", json_object_new_boolean(0));
        }
        sqlite3_finalize(st);
        st = NULL;
    }
out:
    if (st)
        sqlite3_finalize(st);
    pthread_mutex_unlock(&g_tp_mtx);
    return out;
}

/* Restore an exact generation captured by tp_policy_snapshot().  recreate=1
 * also inserts the policy row, which is how a failed DELETE or a failed
 * create is rolled back.  This is a storage-level transaction: generation,
 * raw status, targets, aggregate usage, every per-client row and quota blocks
 * are put back together or not at all. */
int tp_policy_restore_snapshot(const char *id, struct json_object *snapshot,
                               int recreate, tp_error_t *err)
{
    struct json_object *targets = NULL, *clients = NULL, *v = NULL;
    sqlite3_stmt *st = NULL;
    int ok = 0;
    int has_usage = 1;
    size_t i;

    if (err)
        memset(err, 0, sizeof(*err));
    if (!id || !id[0] || !snapshot || !json_object_is_type(snapshot, json_type_object)) {
        if (err) { err->code = "bad_snapshot"; snprintf(err->detail, sizeof(err->detail), "snapshot is required"); }
        return -1;
    }
    pthread_mutex_lock(&g_tp_mtx);
    if (!g_tp_db) {
        pthread_mutex_unlock(&g_tp_mtx);
        if (err) { err->code = "db_down"; snprintf(err->detail, sizeof(err->detail), "db not initialized"); }
        return -1;
    }
    if (tp_sql(g_tp_db, "BEGIN", NULL) != SQLITE_OK)
        goto fail;
    if (json_object_object_get_ex(snapshot, "has_quota_usage", &v) &&
        json_object_is_type(v, json_type_boolean))
        has_usage = json_object_get_boolean(v);
    if (recreate) {
        if (sqlite3_prepare_v2(g_tp_db,
            "INSERT INTO policies(id,name,remark,enabled,rate_upload_kbps,rate_download_kbps,"
            "rate_mode,started_at,duration_count,duration_unit,deadline_at,quota_bytes,"
            "quota_accounting,quota_mode,deny_protocols,status,last_transition_at,generation,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK)
            goto fail;
    } else {
        if (sqlite3_prepare_v2(g_tp_db,
            "UPDATE policies SET name=?,remark=?,enabled=?,rate_upload_kbps=?,rate_download_kbps=?,"
            "rate_mode=?,started_at=?,duration_count=?,duration_unit=?,deadline_at=?,quota_bytes=?,"
            "quota_accounting=?,quota_mode=?,deny_protocols=?,status=?,last_transition_at=?,generation=?,"
            "created_at=?,updated_at=? WHERE id=?", -1, &st, NULL) != SQLITE_OK)
            goto fail;
    }
    if (recreate) {
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, jsd(snapshot, "name", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 3, jsd(snapshot, "remark", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 4, jbd(snapshot, "enabled", 1));
        sqlite3_bind_int64(st, 5, ji64(snapshot, "rate_upload_kbps", 0));
        sqlite3_bind_int64(st, 6, ji64(snapshot, "rate_download_kbps", 0));
        sqlite3_bind_text(st, 7, jsd(snapshot, "rate_mode", TP_RATE_PER_IP), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 8, ji64(snapshot, "started_at", 0));
        sqlite3_bind_int64(st, 9, ji64(snapshot, "duration_count", 0));
        sqlite3_bind_text(st, 10, jsd(snapshot, "duration_unit", TP_UNIT_DAYS), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 11, ji64(snapshot, "deadline_at", 0));
        sqlite3_bind_int64(st, 12, ji64(snapshot, "quota_bytes", 0));
        sqlite3_bind_text(st, 13, jsd(snapshot, "quota_accounting", "upload_plus_download"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, jsd(snapshot, "quota_mode", TP_QUOTA_PER_IP), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 15, jsd(snapshot, "deny_protocols", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 16, jsd(snapshot, "status", TP_STATUS_ACTIVE), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 17, ji64(snapshot, "last_transition_at", 0));
        sqlite3_bind_int64(st, 18, ji64(snapshot, "generation", 1));
        sqlite3_bind_int64(st, 19, ji64(snapshot, "created_at", 0));
        sqlite3_bind_int64(st, 20, ji64(snapshot, "updated_at", 0));
    } else {
        sqlite3_bind_text(st, 1, jsd(snapshot, "name", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, jsd(snapshot, "remark", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 3, jbd(snapshot, "enabled", 1));
        sqlite3_bind_int64(st, 4, ji64(snapshot, "rate_upload_kbps", 0));
        sqlite3_bind_int64(st, 5, ji64(snapshot, "rate_download_kbps", 0));
        sqlite3_bind_text(st, 6, jsd(snapshot, "rate_mode", TP_RATE_PER_IP), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 7, ji64(snapshot, "started_at", 0));
        sqlite3_bind_int64(st, 8, ji64(snapshot, "duration_count", 0));
        sqlite3_bind_text(st, 9, jsd(snapshot, "duration_unit", TP_UNIT_DAYS), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 10, ji64(snapshot, "deadline_at", 0));
        sqlite3_bind_int64(st, 11, ji64(snapshot, "quota_bytes", 0));
        sqlite3_bind_text(st, 12, jsd(snapshot, "quota_accounting", "upload_plus_download"), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 13, jsd(snapshot, "quota_mode", TP_QUOTA_PER_IP), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 14, jsd(snapshot, "deny_protocols", ""), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 15, jsd(snapshot, "status", TP_STATUS_ACTIVE), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 16, ji64(snapshot, "last_transition_at", 0));
        sqlite3_bind_int64(st, 17, ji64(snapshot, "generation", 1));
        sqlite3_bind_int64(st, 18, ji64(snapshot, "created_at", 0));
        sqlite3_bind_int64(st, 19, ji64(snapshot, "updated_at", 0));
        sqlite3_bind_text(st, 20, id, -1, SQLITE_TRANSIENT);
    }
    if (sqlite3_step(st) != SQLITE_DONE || sqlite3_changes(g_tp_db) != 1)
        goto fail;
    sqlite3_finalize(st); st = NULL;

    if (sqlite3_prepare_v2(g_tp_db, "DELETE FROM targets WHERE policy_id=?", -1, &st, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) goto fail;
    sqlite3_finalize(st); st = NULL;
    if (!json_object_object_get_ex(snapshot, "targets", &targets) ||
        !json_object_is_type(targets, json_type_array) ||
        json_object_array_length(targets) == 0)
        goto fail;
    for (i = 0; i < json_object_array_length(targets); i++) {
        struct json_object *target = json_object_array_get_idx(targets, i);
        const char *value = jsd(target, "value", "");
        const char *prefix = jsd(target, "prefix", "");
        const char *slash;
        char addr[INET6_ADDRSTRLEN];
        char *end = NULL;
        long family = ji64(target, "family", 0);
        long plen = ji64(target, "prefix_len", -1);

        if (value[0]) {
            slash = strrchr(value, '/');
            if (!slash || slash == value || strlen(slash + 1) > 3)
                goto fail;
            plen = strtol(slash + 1, &end, 10);
            if (!end || *end || (size_t)(slash - value) >= sizeof(addr))
                goto fail;
            memcpy(addr, value, (size_t)(slash - value));
            addr[slash - value] = '\0';
        } else if (prefix[0]) {
            if (plen < 0 || snprintf(addr, sizeof(addr), "%s", prefix) >= (int)sizeof(addr))
                goto fail;
        } else {
            goto fail;
        }
        {
            struct in_addr v4;
            struct in6_addr v6;
        if ((family != 4 && family != 6) || plen < 0 ||
            (family == 4 && (plen > 32 || inet_pton(AF_INET, addr, &v4) != 1)) ||
            (family == 6 && (plen > 128 || inet_pton(AF_INET6, addr, &v6) != 1)))
            goto fail;
        }
        if (sqlite3_prepare_v2(g_tp_db,
            "INSERT INTO targets(policy_id,family,kind,prefix,prefix_len) VALUES(?,?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 2, (int)family);
        sqlite3_bind_text(st, 3, "cidr", -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 4, addr, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(st, 5, (int)plen);
        if (sqlite3_step(st) != SQLITE_DONE) goto fail;
        sqlite3_finalize(st); st = NULL;
    }

    {
        static const char *const tables[] = {
            "quota_usage_ip", "quota_blocks", "quota_usage"
        };
        for (i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
            char sql[160];
            snprintf(sql, sizeof(sql), "DELETE FROM %s WHERE policy_id=?", tables[i]);
            if (sqlite3_prepare_v2(g_tp_db, sql, -1, &st, NULL) != SQLITE_OK) goto fail;
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(st) != SQLITE_DONE) goto fail;
            sqlite3_finalize(st); st = NULL;
        }
    }
    if (has_usage) {
        if (sqlite3_prepare_v2(g_tp_db,
            "INSERT INTO quota_usage(policy_id,used_upload_bytes,used_download_bytes,used_bytes,checkpoint_at) VALUES(?,?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK) goto fail;
        sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, ji64(snapshot, "used_upload_bytes", 0));
        sqlite3_bind_int64(st, 3, ji64(snapshot, "used_download_bytes", 0));
        sqlite3_bind_int64(st, 4, ji64(snapshot, "used_bytes", 0));
        sqlite3_bind_int64(st, 5, ji64(snapshot, "checkpoint_at", 0));
        if (sqlite3_step(st) != SQLITE_DONE) goto fail;
        sqlite3_finalize(st); st = NULL;
    }

    if (json_object_object_get_ex(snapshot, "quota_clients", &clients) &&
        json_object_is_type(clients, json_type_array)) {
        for (i = 0; i < json_object_array_length(clients); i++) {
            struct json_object *client = json_object_array_get_idx(clients, i);
            int family = (int)ji64(client, "family", 0);
            const char *ip = jsd(client, "client_ip", "");
            if ((family != 4 && family != 6) || !ip[0]) goto fail;
            if (sqlite3_prepare_v2(g_tp_db,
                "INSERT INTO quota_usage_ip(policy_id,family,client_ip,used_upload_bytes,used_download_bytes,used_bytes,checkpoint_at) VALUES(?,?,?,?,?,?,?)",
                -1, &st, NULL) != SQLITE_OK) goto fail;
            sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 2, family);
            sqlite3_bind_text(st, 3, ip, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 4, ji64(client, "used_upload_bytes", 0));
            sqlite3_bind_int64(st, 5, ji64(client, "used_download_bytes", 0));
            sqlite3_bind_int64(st, 6, ji64(client, "used_total_bytes", 0));
            sqlite3_bind_int64(st, 7, ji64(client, "checkpoint_at",
                                          ji64(snapshot, "updated_at", 0)));
            if (sqlite3_step(st) != SQLITE_DONE) goto fail;
            sqlite3_finalize(st); st = NULL;
            if (json_object_object_get_ex(client, "blocked_at", &v) ||
                jbd(client, "blocked", 0)) {
                int64_t blocked_at = ji64(client, "blocked_at",
                                          ji64(snapshot, "updated_at", 0));
                if (sqlite3_prepare_v2(g_tp_db,
                    "INSERT INTO quota_blocks(policy_id,family,client_ip,blocked_at) VALUES(?,?,?,?)",
                    -1, &st, NULL) != SQLITE_OK) goto fail;
                sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(st, 2, family);
                sqlite3_bind_text(st, 3, ip, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(st, 4, blocked_at);
                if (sqlite3_step(st) != SQLITE_DONE) goto fail;
                sqlite3_finalize(st); st = NULL;
            }
        }
    }
    if (tp_sql(g_tp_db, "COMMIT", NULL) != SQLITE_OK) {
        tp_sql(g_tp_db, "ROLLBACK", NULL);
        goto fail_no_txn;
    }
    ok = 1;
fail:
    if (st) sqlite3_finalize(st);
    if (!ok) tp_sql(g_tp_db, "ROLLBACK", NULL);
fail_no_txn:
    pthread_mutex_unlock(&g_tp_mtx);
    if (!ok && err) { err->code = "restore_failed"; snprintf(err->detail, sizeof(err->detail), "snapshot restore failed"); }
    return ok ? 0 : -1;
}

int tp_policy_delete(const char *id){
    pthread_mutex_lock(&g_tp_mtx);
    if(!g_tp_db||!id||!id[0]){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    if(tp_sql(g_tp_db,"BEGIN",NULL)!=SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    sqlite3_stmt*s=NULL;int rc=-1;
    if(sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_blocks WHERE policy_id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);sqlite3_step(s);sqlite3_finalize(s);s=NULL;}
    if(sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_usage_ip WHERE policy_id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);sqlite3_step(s);sqlite3_finalize(s);s=NULL;}
    if(sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_usage WHERE policy_id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);sqlite3_step(s);sqlite3_finalize(s);s=NULL;}
    if(sqlite3_prepare_v2(g_tp_db,"DELETE FROM policies WHERE id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);if(sqlite3_step(s)==SQLITE_DONE)rc=sqlite3_changes(g_tp_db)>0?0:-1;sqlite3_finalize(s);}
    if(rc==0&&tp_sql(g_tp_db,"COMMIT",NULL)==SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);return 0;}
    tp_sql(g_tp_db,"ROLLBACK",NULL);pthread_mutex_unlock(&g_tp_mtx);return -1;
}

static int tp_canonical_client_ip(int family, const char *client_ip,
                                  char *out, size_t out_len)
{
    unsigned char addr[16];
    int af = family == 4 ? AF_INET : (family == 6 ? AF_INET6 : family);
    if (!client_ip || !client_ip[0] || !out || !out_len ||
        (af != AF_INET && af != AF_INET6) ||
        inet_pton(af, client_ip, addr) != 1)
        return -1;
    return inet_ntop(af, addr, out, out_len) ? 0 : -1;
}

int tp_policy_account_usage_for_client(const char *id, int family,
                                       const char *client_ip,
                                       int64_t upload_delta,
                                       int64_t download_delta,
                                       int64_t *used_out,
                                       int *exhausted_out)
{
    pthread_mutex_lock(&g_tp_mtx);
    if (used_out) *used_out = 0;
    if (exhausted_out) *exhausted_out = 0;
    if(!g_tp_db||!id||!id[0]||upload_delta<0||download_delta<0){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    tp_policy_t p;
    char ip[INET6_ADDRSTRLEN];
    if(tp_load_locked(g_tp_db,id,&p)<0||tp_canonical_client_ip(family,client_ip,ip,sizeof(ip))!=0){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    if(p.quota_bytes<=0){pthread_mutex_unlock(&g_tp_mtx);return 0;}
    if(upload_delta > INT64_MAX - download_delta){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    if(tp_sql(g_tp_db,"BEGIN",NULL)!=SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    int64_t up=0,down=0,used=0;sqlite3_stmt *s=NULL;
    if(sqlite3_prepare_v2(g_tp_db,"SELECT used_upload_bytes,used_download_bytes,used_bytes FROM quota_usage_ip WHERE policy_id=? AND family=? AND client_ip=?",-1,&s,NULL)!=SQLITE_OK)goto fail;
    sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);sqlite3_bind_int(s,2,family==4||family==AF_INET?4:6);sqlite3_bind_text(s,3,ip,-1,SQLITE_STATIC);
    if(sqlite3_step(s)==SQLITE_ROW){up=sqlite3_column_int64(s,0);down=sqlite3_column_int64(s,1);used=sqlite3_column_int64(s,2);}sqlite3_finalize(s);s=NULL;
    if(up>INT64_MAX-upload_delta||down>INT64_MAX-download_delta||used>INT64_MAX-(upload_delta+download_delta))goto fail;
    up+=upload_delta;down+=download_delta;used+=upload_delta+download_delta;
    if(sqlite3_prepare_v2(g_tp_db,"INSERT INTO quota_usage_ip(policy_id,family,client_ip,used_upload_bytes,used_download_bytes,used_bytes,checkpoint_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(policy_id,family,client_ip) DO UPDATE SET used_upload_bytes=excluded.used_upload_bytes,used_download_bytes=excluded.used_download_bytes,used_bytes=excluded.used_bytes,checkpoint_at=excluded.checkpoint_at",-1,&s,NULL)!=SQLITE_OK)goto fail;
    sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);sqlite3_bind_int(s,2,family==4||family==AF_INET?4:6);sqlite3_bind_text(s,3,ip,-1,SQLITE_STATIC);sqlite3_bind_int64(s,4,up);sqlite3_bind_int64(s,5,down);sqlite3_bind_int64(s,6,used);sqlite3_bind_int64(s,7,(sqlite3_int64)time(NULL));
    if(sqlite3_step(s)!=SQLITE_DONE){sqlite3_finalize(s);s=NULL;goto fail;}sqlite3_finalize(s);s=NULL;
    {
        sqlite3_stmt *sum=NULL;int64_t sumup=0,sumdown=0,sumtotal=0;
        if(sqlite3_prepare_v2(g_tp_db,"SELECT COALESCE(SUM(used_upload_bytes),0),COALESCE(SUM(used_download_bytes),0),COALESCE(SUM(used_bytes),0) FROM quota_usage_ip WHERE policy_id=?",-1,&sum,NULL)!=SQLITE_OK)goto fail;
        sqlite3_bind_text(sum,1,id,-1,SQLITE_STATIC);if(sqlite3_step(sum)==SQLITE_ROW){sumup=sqlite3_column_int64(sum,0);sumdown=sqlite3_column_int64(sum,1);sumtotal=sqlite3_column_int64(sum,2);}sqlite3_finalize(sum);
        if(sqlite3_prepare_v2(g_tp_db,"INSERT INTO quota_usage(policy_id,used_upload_bytes,used_download_bytes,used_bytes,checkpoint_at) VALUES(?,?,?,?,?) ON CONFLICT(policy_id) DO UPDATE SET used_upload_bytes=excluded.used_upload_bytes,used_download_bytes=excluded.used_download_bytes,used_bytes=excluded.used_bytes,checkpoint_at=excluded.checkpoint_at",-1,&s,NULL)!=SQLITE_OK)goto fail;
        sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);sqlite3_bind_int64(s,2,sumup);sqlite3_bind_int64(s,3,sumdown);sqlite3_bind_int64(s,4,sumtotal);sqlite3_bind_int64(s,5,(sqlite3_int64)time(NULL));
        if(sqlite3_step(s)!=SQLITE_DONE){sqlite3_finalize(s);s=NULL;goto fail;}sqlite3_finalize(s);s=NULL;
    }
    if(used>=p.quota_bytes){
        if(sqlite3_prepare_v2(g_tp_db,"INSERT INTO quota_blocks(policy_id,family,client_ip,blocked_at) VALUES(?,?,?,?) ON CONFLICT(policy_id,family,client_ip) DO NOTHING",-1,&s,NULL)!=SQLITE_OK)goto fail;
        sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);sqlite3_bind_int(s,2,family==4||family==AF_INET?4:6);sqlite3_bind_text(s,3,ip,-1,SQLITE_STATIC);sqlite3_bind_int64(s,4,(sqlite3_int64)time(NULL));
        if(sqlite3_step(s)!=SQLITE_DONE){sqlite3_finalize(s);s=NULL;goto fail;}sqlite3_finalize(s);s=NULL;if(exhausted_out)*exhausted_out=1;
    }
    if(tp_sql(g_tp_db,"COMMIT",NULL)!=SQLITE_OK)goto fail_no_txn;
    if(used_out)*used_out=used;pthread_mutex_unlock(&g_tp_mtx);return 0;
fail:
    if(s)sqlite3_finalize(s);tp_sql(g_tp_db,"ROLLBACK",NULL);
fail_no_txn:
    pthread_mutex_unlock(&g_tp_mtx);return -1;
}

int tp_policy_account_usage(const char *id, int64_t upload_delta,
                            int64_t download_delta, int64_t *used_out){
    pthread_mutex_lock(&g_tp_mtx);
    if(!g_tp_db || !id || upload_delta < 0 || download_delta < 0){ pthread_mutex_unlock(&g_tp_mtx); return -1; }
    tp_policy_t p;
    if(tp_load_locked(g_tp_db,id,&p)<0){ pthread_mutex_unlock(&g_tp_mtx); return -1; }
    if(p.quota_bytes <= 0){ pthread_mutex_unlock(&g_tp_mtx); return 0; }
    int64_t used_up = 0, used_down = 0, used = 0;
    sqlite3_stmt *s = NULL;
    if(sqlite3_prepare_v2(g_tp_db,"SELECT used_upload_bytes,used_download_bytes,used_bytes FROM quota_usage WHERE policy_id=?",-1,&s,NULL)!=SQLITE_OK){ pthread_mutex_unlock(&g_tp_mtx); return -1; }
    sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);
    if(sqlite3_step(s)==SQLITE_ROW){ used_up = sqlite3_column_int64(s,0); used_down = sqlite3_column_int64(s,1); used = sqlite3_column_int64(s,2); }
    sqlite3_finalize(s);
    if (upload_delta > INT64_MAX - download_delta ||
        used_up > INT64_MAX - upload_delta ||
        used_down > INT64_MAX - download_delta ||
        used > INT64_MAX - (upload_delta + download_delta)) {
        pthread_mutex_unlock(&g_tp_mtx);
        return -1;
    }
    used_up += upload_delta;
    used_down += download_delta;
    used += upload_delta + download_delta;
    sqlite3_stmt *up = NULL;
    int64_t now = (int64_t)time(NULL);
    if(sqlite3_prepare_v2(g_tp_db,"INSERT INTO quota_usage(policy_id,used_upload_bytes,used_download_bytes,used_bytes,checkpoint_at) VALUES(?,?,?,?,?) ON CONFLICT(policy_id) DO UPDATE SET used_upload_bytes=excluded.used_upload_bytes,used_download_bytes=excluded.used_download_bytes,used_bytes=excluded.used_bytes,checkpoint_at=excluded.checkpoint_at",-1,&up,NULL)!=SQLITE_OK){ pthread_mutex_unlock(&g_tp_mtx); return -1; }
    sqlite3_bind_text(up,1,id,-1,SQLITE_STATIC);
    sqlite3_bind_int64(up,2,(sqlite3_int64)used_up);
    sqlite3_bind_int64(up,3,(sqlite3_int64)used_down);
    sqlite3_bind_int64(up,4,(sqlite3_int64)used);
    sqlite3_bind_int64(up,5,(sqlite3_int64)now);
    if(sqlite3_step(up)!=SQLITE_DONE){ sqlite3_finalize(up); pthread_mutex_unlock(&g_tp_mtx); return -1; }
    sqlite3_finalize(up);
    if(used_out) *used_out = used;
    if(used >= p.quota_bytes && strcmp(p.status, TP_STATUS_BLOCKED_QUOTA) != 0){
        sqlite3_stmt *st = NULL;
        if(sqlite3_prepare_v2(g_tp_db,"UPDATE policies SET status=?,last_transition_at=?,generation=generation+1,updated_at=? WHERE id=?",-1,&st,NULL)!=SQLITE_OK){
            pthread_mutex_unlock(&g_tp_mtx); return -1;
        }
        sqlite3_bind_text(st,1,TP_STATUS_BLOCKED_QUOTA,-1,SQLITE_STATIC);
        sqlite3_bind_int64(st,2,(sqlite3_int64)now);
        sqlite3_bind_int64(st,3,(sqlite3_int64)now);
        sqlite3_bind_text(st,4,id,-1,SQLITE_STATIC);
        int ok = sqlite3_step(st)==SQLITE_DONE;
        sqlite3_finalize(st);
        if(!ok){ pthread_mutex_unlock(&g_tp_mtx); return -1; }
        pthread_mutex_unlock(&g_tp_mtx);
        return 1;
    }
    pthread_mutex_unlock(&g_tp_mtx);
    return 0;
}

int tp_policy_reset_usage(const char *id){
    pthread_mutex_lock(&g_tp_mtx);
    if(!g_tp_db){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    tp_policy_t p;
    if(tp_load_locked(g_tp_db,id,&p)<0){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    if(tp_sql(g_tp_db,"BEGIN",NULL)!=SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    sqlite3_stmt*s=NULL;int ok=0;
    if(sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_usage_ip WHERE policy_id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);ok=sqlite3_step(s)==SQLITE_DONE;sqlite3_finalize(s);s=NULL;}
    if(ok&&sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_blocks WHERE policy_id=?",-1,&s,NULL)==SQLITE_OK){sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC);ok=sqlite3_step(s)==SQLITE_DONE;sqlite3_finalize(s);s=NULL;}
    if(ok&&sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_usage WHERE policy_id=?",-1,&s,NULL)==SQLITE_OK){
        sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC); ok=sqlite3_step(s)==SQLITE_DONE; sqlite3_finalize(s);
    }
    if(ok&&sqlite3_prepare_v2(g_tp_db,"UPDATE policies SET status=?,last_transition_at=?,generation=generation+1,updated_at=? WHERE id=?",-1,&s,NULL)==SQLITE_OK){
        time_t now=tp_now_s();
        const time_t now_s = now;
        const char *next = !p.enabled ? TP_STATUS_DISABLED :
                           (p.started_at > (int64_t)now_s) ? TP_STATUS_SCHEDULED :
                           (p.duration_count > 0 && p.deadline_at > 0 &&
                            now_s >= (time_t)p.deadline_at) ? TP_STATUS_BLOCKED_TIME :
                           TP_STATUS_ACTIVE;
        sqlite3_bind_text(s,1,next,-1,SQLITE_STATIC);
        sqlite3_bind_int64(s,2,(sqlite3_int64)now); sqlite3_bind_int64(s,3,(sqlite3_int64)now); sqlite3_bind_text(s,4,id,-1,SQLITE_STATIC);
        ok=sqlite3_step(s)==SQLITE_DONE; sqlite3_finalize(s);
    }
    if(ok&&tp_sql(g_tp_db,"COMMIT",NULL)==SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);return 0;}
    tp_sql(g_tp_db,"ROLLBACK",NULL); pthread_mutex_unlock(&g_tp_mtx); return -1;
}

int tp_policy_renew(const char *id,int64_t count,const char *unit,int keep_quota_usage){
    if(!id||!id[0]||count<=0||!unit||!tp_valid_unit(unit))return -1;
    pthread_mutex_lock(&g_tp_mtx);
    if(!g_tp_db){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    tp_policy_t p;
    if(tp_load_locked(g_tp_db,id,&p)<0){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    if(!p.enabled){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    if(tp_sql(g_tp_db,"BEGIN",NULL)!=SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);return -1;}
    time_t now=tp_now_s();
    time_t new_dl=0;
    if(tp_compute_deadline((int64_t)now,count,unit,&new_dl)<0){
        tp_sql(g_tp_db,"ROLLBACK",NULL); pthread_mutex_unlock(&g_tp_mtx); return -1;
    }
    int ok=1;
    sqlite3_stmt*s=NULL;
    if(!keep_quota_usage){
        if(sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_usage_ip WHERE policy_id=?",-1,&s,NULL)==SQLITE_OK){
            sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC); ok=sqlite3_step(s)==SQLITE_DONE; sqlite3_finalize(s); s=NULL;
        }
        if(ok&&sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_usage WHERE policy_id=?",-1,&s,NULL)==SQLITE_OK){
            sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC); ok=sqlite3_step(s)==SQLITE_DONE; sqlite3_finalize(s); s=NULL;
        }
    }
    if(ok&&sqlite3_prepare_v2(g_tp_db,"DELETE FROM quota_blocks WHERE policy_id=?",-1,&s,NULL)==SQLITE_OK){
        sqlite3_bind_text(s,1,id,-1,SQLITE_STATIC); ok=sqlite3_step(s)==SQLITE_DONE; sqlite3_finalize(s); s=NULL;
    }
    const char *next = (p.started_at > (int64_t)now) ? TP_STATUS_SCHEDULED : TP_STATUS_ACTIVE;
    if(ok&&sqlite3_prepare_v2(g_tp_db,
        "UPDATE policies SET deadline_at=?,duration_count=?,duration_unit=?,"
        "status=?,last_transition_at=?,generation=generation+1,updated_at=? WHERE id=?",-1,&s,NULL)==SQLITE_OK){
        sqlite3_bind_int64(s,1,(sqlite3_int64)new_dl);
        sqlite3_bind_int64(s,2,count);
        sqlite3_bind_text(s,3,unit,-1,SQLITE_STATIC);
        sqlite3_bind_text(s,4,next,-1,SQLITE_STATIC);
        sqlite3_bind_int64(s,5,(sqlite3_int64)now);
        sqlite3_bind_int64(s,6,(sqlite3_int64)now);
        sqlite3_bind_text(s,7,id,-1,SQLITE_STATIC);
        ok=sqlite3_step(s)==SQLITE_DONE; sqlite3_finalize(s);
    }
    if(ok&&tp_sql(g_tp_db,"COMMIT",NULL)==SQLITE_OK){pthread_mutex_unlock(&g_tp_mtx);return 0;}
    tp_sql(g_tp_db,"ROLLBACK",NULL); pthread_mutex_unlock(&g_tp_mtx); return -1;
}

const char *tp_expand_status_to_reason(const char *status){
    if(!status)return "unknown";
    if(!strcmp(status,TP_STATUS_ACTIVE))return "no reason";
    if(!strcmp(status,TP_STATUS_BLOCKED_TIME))return "duration expired";
    if(!strcmp(status,TP_STATUS_BLOCKED_QUOTA))return "quota exceeded";
    if(!strcmp(status,TP_STATUS_APPLY_FAILED))return "data-plane apply failed";
    return "disabled by operator";
}

struct json_object *tp_capabilities(void){
    struct json_object *cap=json_object_new_object();
    json_object_object_add(cap,"terminal_policy_write",json_object_new_boolean(1));
    json_object_object_add(cap,"target_kinds",tp_json_arr_from_text("ip,cidr,range"));
    json_object_object_add(cap,"address_families",tp_json_arr_from_text("ipv4,ipv6"));
    json_object_object_add(cap,"batch_targets",json_object_new_boolean(1));
    json_object_object_add(cap,"rate_modes",tp_json_arr_from_text("per_ip,shared"));
    json_object_object_add(cap,"quota_modes",tp_json_arr_from_text("per_ip,shared"));
    json_object_object_add(cap,"quota_accounting",json_object_new_string("upload_plus_download"));
    json_object_object_add(cap,"lifetime_units",tp_json_arr_from_text("hours,days,weeks,months,years"));
    json_object_object_add(cap,"deny_protocols",tp_json_arr_from_text("tcp,udp,icmp"));
    json_object_object_add(cap,"exhausted_actions",tp_json_arr_from_text("block"));
    json_object_object_add(cap,"block_scopes",tp_json_arr_from_text("internet_forward"));
    json_object_object_add(cap,"runtime_readback",json_object_new_boolean(0));
    json_object_object_add(cap,"runtime_apply_supported",json_object_new_boolean(0));
    json_object_object_add(cap,"dataplane",json_object_new_string("storage_only"));
    json_object_object_add(cap,"runtime_quota_accounting",json_object_new_boolean(1));
    json_object_object_add(cap,"max_targets_per_rule",json_object_new_int(MX_TR));
    json_object_object_add(cap,"max_rules_total",json_object_new_int(256));
    return cap;
}
