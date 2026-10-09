#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <json-c/json.h>
#define VM_SCHEMA "vm.v1"
#define VIR_UUID_STRING_BUFLEN 37
#define VIR_CONNECT_LIST_STORAGE_POOLS_DIR 64
struct ref { const char *id, *name, *xml; int active; };
typedef struct ref *virStoragePoolPtr;
typedef struct ref *virStorageVolPtr;
typedef struct ref *virNetworkPtr;
typedef void *virConnectPtr;
typedef struct { int state; unsigned long long capacity, allocation, available; } virStoragePoolInfo;
typedef struct { int type; unsigned long long capacity, allocation; } virStorageVolInfo;
static int offline, list_fail;
static struct ref pool={"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","vm-data", "",1};
static struct ref vol={"","disk.qcow2","",1};
static struct ref nets[]={
 {"11111111-1111-4111-8111-111111111111","default","<network><dns><forwarder addr='1.1.1.1'/></dns><forward mode='nat'/></network>",1},
 {"22222222-2222-4222-8222-222222222222","private","<network/>",1},
 {"33333333-3333-4333-8333-333333333333","lan","<network><forward mode=\"bridge\"/></network>",0},
 {"44444444-4444-4444-8444-444444444444","ovs","<network><forward mode='bridge'/><virtualport type='openvswitch'/></network>",1}
};
static virConnectPtr vm_conn(void){return offline?NULL:&pool;}
static int virConnectListAllStoragePools(virConnectPtr c,virStoragePoolPtr **p,unsigned flags){assert(flags==VIR_CONNECT_LIST_STORAGE_POOLS_DIR);if(list_fail)return -1;*p=malloc(sizeof(**p));(*p)[0]=&pool;return 1;}
static const char *virStoragePoolGetName(virStoragePoolPtr p){return p->name;}
static int virStoragePoolIsActive(virStoragePoolPtr p){return p->active;}
static int virStoragePoolGetUUIDString(virStoragePoolPtr p,char *s){strcpy(s,p->id);return 0;}
static int virStoragePoolGetInfo(virStoragePoolPtr p,virStoragePoolInfo *i){*i=(virStoragePoolInfo){0,1099511627776ULL,4294967296ULL,1095216660480ULL};return 0;}
static int virStoragePoolListAllVolumes(virStoragePoolPtr p,virStorageVolPtr **v,unsigned f){*v=malloc(sizeof(**v));(*v)[0]=&vol;return 1;}
static const char *virStorageVolGetName(virStorageVolPtr v){return v->name;}
static int virStorageVolGetInfo(virStorageVolPtr v,virStorageVolInfo *i){*i=(virStorageVolInfo){0,68719476736ULL,4294967296ULL};return 0;}
static int virStorageVolFree(virStorageVolPtr v){return 0;}
static int virStoragePoolFree(virStoragePoolPtr p){return 0;}
static int virConnectListAllNetworks(virConnectPtr c,virNetworkPtr **p,unsigned flags){if(list_fail)return -1;*p=malloc(4*sizeof(**p));for(int i=0;i<4;i++)(*p)[i]=&nets[i];return 4;}
static const char *virNetworkGetName(virNetworkPtr p){return p->name;}
static int virNetworkIsActive(virNetworkPtr p){return p->active;}
static int virNetworkGetUUIDString(virNetworkPtr p,char *s){strcpy(s,p->id);return 0;}
static char *virNetworkGetXMLDesc(virNetworkPtr p,unsigned flags){return strdup(p->xml);}
static int virNetworkFree(virNetworkPtr p){return 0;}
#include "lists.inc"
static struct json_object *get(struct json_object *o,const char *k){struct json_object *v=NULL;assert(json_object_object_get_ex(o,k,&v));return v;}
static const char *str(struct json_object *o,const char *k){return json_object_get_string(get(o,k));}
int main(void){
 int status=0;
 struct json_object *p=vm_pool_list_json(1,50,NULL,NULL,&status);assert(status==200);
 struct json_object *item=json_object_array_get_idx(get(p,"items"),0);assert(!strcmp(str(item,"id"),pool.id));
 assert(json_object_get_int64(get(item,"capacity_bytes"))==1099511627776LL);
 assert(!strstr(json_object_to_json_string(p),"/var/"));assert(json_object_array_length(get(item,"volumes"))==1);json_object_put(p);
 p=vm_network_list_json(1,50,NULL,NULL,&status);assert(status==200&&json_object_get_int(get(p,"total"))==4);
 const char *modes[]={"nat","isolated","bridge","ovs"};
 for(int i=0;i<4;i++){item=json_object_array_get_idx(get(p,"items"),i);assert(!strcmp(str(item,"id"),nets[i].id));assert(!strcmp(str(item,"mode"),modes[i]));}
 item=json_object_array_get_idx(get(p,"items"),0);assert(!strcmp(str(item,"name"),"default")&&strcmp(str(item,"id"),"default"));json_object_put(p);
 p=vm_network_list_json(2,2,NULL,NULL,&status);assert(json_object_array_length(get(p,"items"))==2);assert(!strcmp(str(json_object_array_get_idx(get(p,"items"),0),"id"),nets[2].id));json_object_put(p);
 p=vm_network_list_json(1,50,"default","active",&status);assert(json_object_get_int(get(p,"total"))==1);json_object_put(p);
 p=vm_network_list_json(INT_MAX,200,NULL,NULL,&status);assert(!p&&status==400);
 list_fail=1;assert(!vm_network_list_json(1,50,NULL,NULL,&status)&&status==503);list_fail=0;
 offline=1;assert(!vm_pool_list_json(1,50,NULL,NULL,&status)&&status==503);assert(!vm_network_list_json(1,50,NULL,NULL,&status)&&status==503);
 puts("PASS: VM pools/networks exact UUIDs, int64 capacities, NAT/bridge/isolated/OVS modes, paging/filter and degraded 503");
}
