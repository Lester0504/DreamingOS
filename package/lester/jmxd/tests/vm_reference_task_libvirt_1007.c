/* Uses libvirt's in-memory test:///default driver, never the host QEMU URI. */
#include "../src/vm/vm_internal.h"
#include <assert.h>
#include <stdarg.h>

int64_t g_vm_started_at;
int64_t vm_now_s(void) { return 1000; }
/* The fixture must not send synthetic task events to the build host's syslog. */
void syslog(int priority, const char *format, ...) { (void)priority; (void)format; }

static struct json_object *field(struct json_object *o, const char *name)
{
    struct json_object *v = NULL;
    assert(o && json_object_object_get_ex(o, name, &v));
    return v;
}
int main(void)
{
    int status = 0;
    assert(!strcmp(VM_LIBVIRT_URI, "test:///default"));
    if (!vm_conn()) { fprintf(stderr, "test driver unavailable\n"); return 77; }
    assert(uloop_init() == 0 && vm_store_open() == 0 && vm_task_init() == 0);
    struct json_object *pools = vm_pool_list_json(1, 50, NULL, "active", &status);
    assert(status == 200 && pools);
    struct json_object *nets = vm_network_list_json(1, 50, NULL, "active", &status);
    assert(status == 200 && nets);
    assert(json_object_array_length(field(pools, "items")) > 0);
    assert(json_object_array_length(field(nets, "items")) > 0);
    struct json_object *pool = json_object_array_get_idx(field(pools, "items"), 0);
    struct json_object *net = json_object_array_get_idx(field(nets, "items"), 0);
    const char *pool_id = json_object_get_string(field(pool, "id"));
    const char *net_id = json_object_get_string(field(net, "id"));
    assert(vm_uuid_valid(pool_id) && vm_uuid_valid(net_id));
    struct json_object *config = json_tokener_parse(
        "{\"name\":\"reference-fixture\",\"guest_arch\":\"x86_64\",\"accelerator\":\"tcg\","
        "\"machine\":\"q35\",\"firmware\":\"bios\",\"cpu\":{\"sockets\":1,\"cores\":1,\"threads\":1},"
        "\"memory_bytes\":268435456,\"disks\":[{\"source\":\"new\",\"capacity_bytes\":67108864,"
        "\"format\":\"qcow2\",\"bus\":\"virtio\"}],\"nics\":[{\"model\":\"virtio\",\"mac\":\"auto\"}],"
        "\"start_after_create\":false}");
    struct json_object *disk = json_object_array_get_idx(field(config, "disks"), 0);
    struct json_object *nic = json_object_array_get_idx(field(config, "nics"), 0);
    json_object_object_add(disk, "pool_id", json_object_new_string(pool_id));
    json_object_object_add(nic, "network_id", json_object_new_string(net_id));
    struct json_object *valid = vm_instance_validate(config, &status);
    assert(status == 200 && json_object_get_boolean(field(field(valid, "data"), "valid")));
    json_object_put(valid);
    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "request_id", json_object_new_string("reference-fixture-request"));
    json_object_object_add(payload, "config", config);
    struct json_object *task = vm_task_submit("instance_create", NULL, payload, &status);
    assert(status == 202 && task);
    char task_id[40];
    snprintf(task_id, sizeof(task_id), "%s", json_object_get_string(field(task, "task_id")));
    json_object_put(task);
    uloop_run_timeout(50);
    task = vm_task_get_json(task_id, &status);
    assert(status == 200 && task);
    if (strcmp(json_object_get_string(field(task, "state")), "succeeded")) {
        fprintf(stderr, "%s\n", json_object_to_json_string(task)); return 1;
    }
    struct json_object *replay = vm_task_submit("instance_create", NULL, payload, &status);
    assert(status == 202 && !strcmp(json_object_get_string(field(replay, "task_id")), task_id));
    json_object_put(replay); json_object_put(task); json_object_put(payload);
    json_object_put(pools); json_object_put(nets);
    vm_task_shutdown(); vm_store_close(); vm_conn_close(); uloop_done();
    puts("PASS: libvirt test driver real pool/network UUIDs -> validate -> 202 task -> succeeded; request replay same task");
    return 0;
}
