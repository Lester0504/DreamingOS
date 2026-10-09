// SPDX-License-Identifier: GPL-2.0-or-later
#include "event_semantics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define DW_RENDER_TITLE_MAX 256
#define DW_RENDER_BODY_MAX 2048
#define DW_RENDER_ARG_MAX 256

#define DW_EVENT(id, category, en, zh, producer, recovery, recovers, reason, severity, key, available) \
    { id, category, en, zh, producer, recovery, recovers, reason, severity, key, 1, available }

const struct dw_event_definition dw_event_definitions[] = {
    DW_EVENT("STORAGE_SMART_FAILED", "STORAGE", "SMART Health Check Failed", "SMART 健康检查失败", "dreamingwrt-core.storage", "STORAGE_SMART_RECOVERED", "", "", "error", "storage.smart_failed", 1),
    DW_EVENT("STORAGE_SMART_RECOVERED", "STORAGE", "SMART Health Check Passed Again", "SMART 健康检查恢复通过", "dreamingwrt-core.storage", "STORAGE_SMART_FAILED", "STORAGE_SMART_FAILED", "", "info", "storage.smart_recovered", 1),
    DW_EVENT("STORAGE_DEVICE_OBSERVED", "STORAGE", "Disk Discovered", "发现磁盘", "dreamingwrt.logd.collector.resource", "", "", "", "info", "storage.device_observed", 1),
    DW_EVENT("STORAGE_DEVICE_REMOVED", "STORAGE", "Disk Removed", "磁盘已移除", "dreamingwrt.logd.collector.resource", "", "", "", "notice", "storage.device_removed", 1),
    DW_EVENT("STORAGE_IO_ERROR", "STORAGE", "Storage I/O Error", "存储读写错误", "dreamingwrt.logd.collector.kernel_log", "", "", "", "error", "storage.io_error", 1),
    DW_EVENT("STORAGE_READ_ONLY", "STORAGE", "Filesystem Became Read Only", "文件系统转为只读", "dreamingwrt.logd.collector.kernel_log", "", "", "", "error", "storage.read_only", 1),
    DW_EVENT("SYSTEM_BOOT_OBSERVED", "SYSTEM", "System Boot Observed", "系统启动记录", "dreamingwrt.logd.collector.resource", "", "", "", "info", "system.boot_observed", 1),
    DW_EVENT("SYSTEM_RESOURCE_RECOVERED", "SYSTEM", "Resource Usage Recovered", "系统资源用量已恢复", "dreamingwrt.logd.collector.resource", "", "SYSTEM_RESOURCE_THRESHOLD", "", "info", "system.resource_recovered", 1),
    DW_EVENT("VM_ACTION_RESULT", "VIRTUALIZATION", "VM Action Result", "虚拟机控制结果", "dreamingos-vm", "", "", "", "info", "vm.action_result", 1),
    DW_EVENT("CONFIG_RESTORE_STATE", "BACKUP", "Configuration Restore State", "配置恢复状态", "dreamingwrt-init.state", "", "", "", "info", "backup.restore_state", 1),
    DW_EVENT("CONFIG_BACKUP_FINISHED", "BACKUP", "Configuration Backup Finished", "配置备份结束", "dreamingwrt-webd", "", "", "", "info", "backup.config_finished", 1),
    DW_EVENT("SYSTEM_POWER_ACTION", "SYSTEM", "System Power Action", "系统电源操作", "dreamingwrt-core.power", "", "", "", "info", "system.power_action", 1),
    DW_EVENT("NFS_TARGET_UNREACHABLE", "FILES", "NFS Target Unreachable", "NFS目标暂不可达", "dreamingwrt.logd.collector.system_log", "", "", "", "warning", "nfs.target_unreachable", 1),
    DW_EVENT("NFS_MOUNT_RETRYING", "FILES", "NFS Mount Retrying", "NFS挂载正在重试", "dreamingwrt.logd.collector.system_log", "", "", "", "warning", "nfs.mount_retrying", 1),
    DW_EVENT("FTP_CONNECTION", "AUTH", "FTP Connection", "FTP 连接", "vsftpd", "", "", "", "info", "ftp.connection", 1),
    DW_EVENT("FTP_AUTH_RESULT", "AUTH", "FTP Login Result", "FTP 登录结果", "vsftpd", "", "", "", "info", "ftp.auth_result", 1),
    DW_EVENT("FTP_TRANSFER_FINISHED", "FILES", "FTP Transfer Finished", "FTP 传输结束", "vsftpd", "", "", "", "info", "ftp.transfer_finished", 1),
    DW_EVENT("FTP_FILE_ACTION", "FILES", "FTP File Operation", "FTP 文件操作", "vsftpd", "", "", "", "info", "ftp.file_action", 1),
    DW_EVENT("APP_OPERATION_FINISHED", "APPLICATIONS", "Application Operation Finished", "应用操作结束", "dwrt-appstore-worker", "", "", "", "info", "application.operation_finished", 1),
    DW_EVENT("VM_OPERATION_FINISHED", "VIRTUALIZATION", "VM Operation Finished", "虚拟机操作结束", "dreamingos-vm", "", "", "", "info", "vm.operation_finished", 1),
    DW_EVENT("STORAGE_MIGRATION_FINISHED", "STORAGE", "Storage Migration Finished", "存储迁移结束", "dreamingwrt-core.storage", "", "", "", "info", "storage.migration_finished", 1),
    DW_EVENT("REMOTE_BUILD_PUBLISHED", "SYSTEM", "Remote Build Published", "遥控编译已发布", "dreamingos.dist", "", "", "", "info", "remote_build.published", 1),
    DW_EVENT("REMOTE_BUILD_FAILED", "SYSTEM", "Remote Build Failed", "遥控编译失败", "dreamingos.dist", "", "", "", "error", "remote_build.failed", 1),
    DW_EVENT("FIRMWARE_UPDATE_AVAILABLE", "SYSTEM", "Firmware Update Available", "发现新固件版本", "dreamingwrt.webd", "", "", "", "warning", "system.firmware_update_available", 1),
    DW_EVENT("SYSTEM_RESOURCE_THRESHOLD", "SYSTEM", "System Resource Threshold", "系统资源超过阈值", "dreamingwrt.logd.collector.resource", "", "", "", "warning", "system.resource_threshold", 1),
    DW_EVENT("SYSTEM_LOG", "SYSTEM", "System Log", "系统日志", "dreamingwrt.logd", "", "", "", "notice", "system.log", 1),
    DW_EVENT("KERNEL_OUT_OF_MEMORY", "SYSTEM", "Kernel Out of Memory", "内核内存不足", "dreamingwrt.logd.collector.kernel_log", "", "", "", "critical", "kernel.out_of_memory", 1),
    DW_EVENT("KERNEL_PANIC", "SYSTEM", "Kernel Panic", "内核发生严重故障", "dreamingwrt.logd.collector.kernel_log", "", "", "", "critical", "kernel.panic", 1),
    DW_EVENT("KERNEL_THERMAL_SHUTDOWN", "SYSTEM", "Thermal Shutdown", "系统触发过热关机", "dreamingwrt.logd.collector.kernel_log", "", "", "", "critical", "kernel.thermal_shutdown", 1),
    DW_EVENT("SERVICE_WORKER_RESTARTED", "SYSTEM", "Service Worker Restarted", "服务工作进程已重启", "dreamingwrt.logd.collector.system_log", "", "", "", "error", "service.worker_restarted", 1),
    DW_EVENT("CALLBACKS_SUPPRESSED", "SYSTEM", "Callbacks Suppressed", "内核回调日志受到抑制", "dreamingwrt.logd", "", "", "", "warning", "kernel.callbacks_suppressed", 1),
    DW_EVENT("PACKET_CAPTURE_STARTED", "SYSTEM", "Packet Capture Started", "抓包任务已开始", "dreamingwrt.logd", "", "", "", "notice", "packet_capture.started", 1),
    DW_EVENT("PACKET_CAPTURE_STOPPED", "SYSTEM", "Packet Capture Stopped", "抓包任务已停止", "dreamingwrt.logd", "", "", "", "notice", "packet_capture.stopped", 1),
    DW_EVENT("PACKET_CAPTURE_FINISHED", "SYSTEM", "Packet Capture Finished", "抓包任务已完成", "dreamingwrt.logd", "", "", "", "notice", "packet_capture.finished", 1),
    DW_EVENT("PACKET_CAPTURE_DELETED", "SYSTEM", "Packet Capture Deleted", "抓包记录已删除", "dreamingwrt.logd", "", "", "", "notice", "packet_capture.deleted", 1),
    DW_EVENT("WAN_EVENT", "INTERNET_AND_WAN", "WAN Event", "WAN 事件", "dreamingwrt.logd.collector.system_log", "", "", "", "notice", "wan.event", 1),
    DW_EVENT("PPPOE_EVENT", "INTERNET_AND_WAN", "PPPoE Event", "PPPoE 事件", "dreamingwrt.logd.collector.system_log", "", "", "", "notice", "pppoe.event", 1),
    DW_EVENT("PORT_LINK_DOWN", "INTERNET_AND_WAN", "Port Link Down", "端口链路断开", "dreamingwrt.logd.collector.port", "PORT_LINK_UP", "", "", "warning", "port.link_down", 1),
    DW_EVENT("PORT_LINK_UP", "INTERNET_AND_WAN", "Port Link Up", "端口链路恢复", "dreamingwrt.logd.collector.port", "PORT_LINK_DOWN", "PORT_LINK_DOWN", "", "notice", "port.link_up", 1),
    DW_EVENT("PORT_EVENT", "INTERNET_AND_WAN", "Port Event", "端口事件", "dreamingwrt.logd.collector.port", "", "", "", "notice", "port.event", 1),
    DW_EVENT("CLIENT_CONNECTED_WIRED", "CLIENT_DEVICES", "Wired Client Connected", "有线客户端已连接", "dreamingwrt-core", "CLIENT_DISCONNECTED", "", "", "notice", "client.connected_wired", 1),
    DW_EVENT("CLIENT_DISCONNECTED", "CLIENT_DEVICES", "Client Disconnected", "客户端已断开", "dreamingwrt-core", "CLIENT_CONNECTED_WIRED", "CLIENT_CONNECTED_WIRED", "", "notice", "client.disconnected", 1),
    DW_EVENT("CLIENT_AUTH_FAILED", "CLIENT_DEVICES", "Client Authentication Failed", "客户端认证失败", "dreamingwrt-core", "", "", "", "warning", "client.auth_failed", 1),
    DW_EVENT("DHCP_LEASE_ASSIGNED", "CLIENT_DEVICES", "DHCP Address Assigned", "已分配 DHCP 地址", "dreamingwrt.logd.collector.dhcp_lease", "", "", "", "notice", "dhcp.lease_assigned", 1),
    DW_EVENT("DHCP_LEASE_RELEASED", "CLIENT_DEVICES", "DHCP Address Released", "已释放 DHCP 地址", "dreamingwrt.logd.collector.dhcp_lease", "", "", "", "notice", "dhcp.lease_released", 1),
    DW_EVENT("DHCP_LEASE_CHANGED", "CLIENT_DEVICES", "DHCP Lease Changed", "DHCP 租约已变更", "dreamingwrt.logd.collector.dhcp_lease", "", "", "", "notice", "dhcp.lease_changed", 1),
    DW_EVENT("DHCP_LEASE_RENEWED", "CLIENT_DEVICES", "DHCP Lease Renewed", "DHCP 租约已续期", "dreamingwrt.logd.collector.dhcp_lease", "", "", "", "info", "dhcp.lease_renewed", 1),
    DW_EVENT("DHCP_EVENT", "CLIENT_DEVICES", "DHCP Event", "DHCP 事件", "dreamingwrt.logd.collector.dhcp_lease", "", "", "", "notice", "dhcp.event", 1),
    DW_EVENT("SECURITY_AUTH_EVENT", "SECURITY", "Device Authentication Event", "设备认证事件", "dreamingwrt.logd.collector.system_log", "", "", "", "warning", "security.authentication", 1),
    DW_EVENT("ADMIN_AUTH_EVENT", "ADMIN", "Admin Authentication Event", "管理员认证事件", "dreamingwrt.logd.collector.system_log", "", "", "", "warning", "admin.authentication", 1),
    DW_EVENT("WAN_DOWN", "INTERNET_AND_WAN", "Internet Down", "互联网连接中断", "dreamingwrt-core", "WAN_RESTORED", "", "", "warning", "wan.down", 1),
    DW_EVENT("WAN_RESTORED", "INTERNET_AND_WAN", "Internet Restored", "互联网连接已恢复", "dreamingwrt-core", "WAN_DOWN", "WAN_DOWN", "", "notice", "wan.restored", 1),
    DW_EVENT("WAN_FAILOVER_ACTIVE", "INTERNET_AND_WAN", "WAN Failover Active", "WAN 已切换到备用线路", "dreamingwrt.routed.health", "WAN_FAILBACK", "", "", "warning", "wan.failover_active", 1),
    DW_EVENT("WAN_FAILBACK", "INTERNET_AND_WAN", "WAN Failback", "WAN 已切回首选线路", "dreamingwrt.routed.health", "WAN_FAILOVER_ACTIVE", "WAN_FAILOVER_ACTIVE", "", "notice", "wan.failback", 1),
    DW_EVENT("WAN_QUALITY_DEGRADED", "INTERNET_AND_WAN", "WAN Quality Degraded", "WAN 质量下降", "dreamingwrt.routed.health", "WAN_QUALITY_RECOVERED", "", "", "warning", "wan.quality_degraded", 1),
    DW_EVENT("WAN_QUALITY_CRITICAL", "INTERNET_AND_WAN", "WAN Quality Critical", "WAN 质量严重下降", "dreamingwrt.routed.health", "WAN_QUALITY_RECOVERED", "", "", "critical", "wan.quality_critical", 1),
    DW_EVENT("WAN_PENALTY_RECOVERING", "INTERNET_AND_WAN", "WAN Penalty Recovering", "WAN 质量正在恢复观察", "dreamingwrt.routed.health", "WAN_QUALITY_RECOVERED", "", "", "notice", "wan.penalty_recovering", 1),
    DW_EVENT("WAN_QUALITY_RECOVERED", "INTERNET_AND_WAN", "WAN Quality Recovered", "WAN 质量已恢复", "dreamingwrt.routed.health", "WAN_QUALITY_DEGRADED", "WAN_QUALITY_DEGRADED", "", "notice", "wan.quality_recovered", 1),
    DW_EVENT("WAN_FLAPPING", "INTERNET_AND_WAN", "WAN Flapping", "WAN 连接频繁波动", "dreamingwrt-core", "", "", "", "warning", "wan.flapping", 1),
    DW_EVENT("ISP_PACKET_LOSS", "INTERNET_AND_WAN", "ISP Packet Loss", "ISP 丢包", "", "", "", "wan_sla_event_producer_pending", "warning", "isp.packet_loss", 0),
    DW_EVENT("ISP_HIGH_LATENCY", "INTERNET_AND_WAN", "ISP High Latency", "ISP 延迟过高", "", "", "", "wan_sla_event_producer_pending", "warning", "isp.high_latency", 0),
    DW_EVENT("DEVICE_OFFLINE", "DEVICES", "Infrastructure Device Offline", "基础设施设备离线", "dreamingwrt-core.topology_history", "DEVICE_RESTORED", "", "", "warning", "device.offline", 1),
    DW_EVENT("DEVICE_RESTORED", "DEVICES", "Infrastructure Device Restored", "基础设施设备已恢复", "dreamingwrt-core.topology_history", "DEVICE_OFFLINE", "DEVICE_OFFLINE", "", "notice", "device.restored", 1),
    DW_EVENT("AP_COMMIT_ERROR", "DEVICES", "AP Configuration Commit Failed", "AP 配置下发失败", "dreamingwrt-ac", "", "", "", "error", "ap.commit_error", 1),
    DW_EVENT("AP_UNPAIR_FAILED", "DEVICES", "AP Unpair Failed", "AP 解绑失败", "dreamingwrt-ac", "", "", "", "warning", "ap.unpair_failed", 1),
    DW_EVENT("AC_TRANSPORT_ERROR", "DEVICES", "AP Control Transport Error", "AP 控制传输故障", "dreamingwrt-ac", "", "", "", "error", "ac.transport_error", 1),
    DW_EVENT("AC_PKI_ERROR", "DEVICES", "AP Control PKI Error", "AP 控制 PKI 故障", "dreamingwrt-ac", "", "", "", "error", "ac.pki_error", 1),
    DW_EVENT("PORT_TX_RX_ERRORS", "INTERNET_AND_WAN", "Port TX/RX Errors", "端口收发错误增加", "dreamingwrt.logd.collector.port", "", "", "", "warning", "port.tx_rx_errors", 1),
    DW_EVENT("PORT_DROPPED_TRAFFIC", "INTERNET_AND_WAN", "Port Dropped Traffic", "端口出现丢弃流量", "dreamingwrt.logd.collector.port", "", "", "", "warning", "port.dropped_traffic", 1),
    DW_EVENT("DHCP_POOL_EXHAUSTED", "CLIENT_DEVICES", "DHCP Pool Exhausted", "DHCP 地址池已耗尽", "dreamingwrt-core", "", "", "", "critical", "dhcp.pool_exhausted", 1),
    DW_EVENT("CLIENT_IP_CONFLICT", "CLIENT_DEVICES", "Client IP Conflict", "客户端 IP 地址冲突", "dreamingwrt-core.ipam", "", "", "", "warning", "client.ip_conflict", 1),
    DW_EVENT("VPN_SITE_TO_SITE_DISCONNECTED", "VPN", "Site-to-Site VPN Disconnected", "站点到站点 VPN 已断开", "", "VPN_SITE_TO_SITE_RESTORED", "", "vpn_state_producer_pending", "warning", "vpn.site_to_site_disconnected", 0),
    DW_EVENT("VPN_SITE_TO_SITE_RESTORED", "VPN", "Site-to-Site VPN Restored", "站点到站点 VPN 已恢复", "", "VPN_SITE_TO_SITE_DISCONNECTED", "VPN_SITE_TO_SITE_DISCONNECTED", "vpn_state_producer_pending", "notice", "vpn.site_to_site_restored", 0),
    DW_EVENT("SECURITY_DETECTION", "SECURITY", "Security Detection", "检测到安全风险", "dreamingwrt.aegisxd.suricata", "", "", "", "warning", "security.detection", 1),
    DW_EVENT("WIFI_CONFIG_SAVE_FAILED", "ADMIN", "Wi-Fi Configuration Save Failed", "Wi-Fi 配置保存失败", "dreamingwrt-webd/dreamingwrt-ac", "", "", "", "error", "wifi.config_save_failed", 1),
    DW_EVENT("WIFI_CONFIG_APPLY_FAILED", "ADMIN", "Wi-Fi Configuration Apply Failed", "Wi-Fi 配置应用失败", "dreamingwrt-webd/dreamingwrt-ac", "", "", "", "error", "wifi.config_apply_failed", 1),
    DW_EVENT("WIFI_CONFIG_READBACK_MISMATCH", "ADMIN", "Wi-Fi Configuration Readback Mismatch", "Wi-Fi 配置回读不一致", "dreamingwrt-webd/dreamingwrt-ac", "", "", "", "error", "wifi.config_readback_mismatch", 1),
    DW_EVENT("CONFIG_COMMIT_FAILED", "ADMIN", "Configuration Commit Failed", "配置提交失败", "dreamingwrt-core", "", "", "", "error", "config.commit_failed", 1),
    DW_EVENT("APPLICATION_UPDATE_FAILED", "SYSTEM", "Application Update Failed", "应用更新失败", "dreamingwrt.otad", "", "", "", "error", "application.update_failed", 1),
    DW_EVENT("IMPROPER_SHUTDOWN", "SYSTEM", "Improper Shutdown", "系统未正常关机", "", "", "", "boot_marker_event_producer_pending", "warning", "system.improper_shutdown", 0),
    DW_EVENT("PROXY_NODE_MASS_FAILURE", "PROXY", "Proxy Nodes Mass Failure", "多个代理节点不可用", "dreamingproxy", "PROXY_NODE_MASS_RECOVERED", "", "", "warning", "proxy.node_mass_failure", 1),
    DW_EVENT("PROXY_NODE_MASS_RECOVERED", "PROXY", "Proxy Nodes Recovered", "代理节点已恢复", "dreamingproxy", "PROXY_NODE_MASS_FAILURE", "PROXY_NODE_MASS_FAILURE", "", "info", "proxy.node_mass_recovered", 1),
    DW_EVENT("PROXY_CAPABILITY_EMPTY", "PROXY", "Policy Group Candidates Empty", "策略组没有可用候选节点", "dreamingproxy", "PROXY_CAPABILITY_RECOVERED", "", "", "error", "proxy.capability_empty", 1),
    DW_EVENT("PROXY_CAPABILITY_RECOVERED", "PROXY", "Policy Group Candidates Recovered", "策略组候选节点已恢复", "dreamingproxy", "PROXY_CAPABILITY_EMPTY", "PROXY_CAPABILITY_EMPTY", "", "info", "proxy.capability_recovered", 1),
    DW_EVENT("PROXY_BINDING_OFFLINE", "PROXY", "Client Binding Offline", "客户端绑定已离线", "dreamingproxy", "PROXY_BINDING_RESTORED", "", "", "critical", "proxy.binding_offline", 1),
    DW_EVENT("PROXY_BINDING_RESTORED", "PROXY", "Client Binding Restored", "客户端绑定已恢复", "dreamingproxy", "PROXY_BINDING_OFFLINE", "PROXY_BINDING_OFFLINE", "", "info", "proxy.binding_restored", 1),
    DW_EVENT("PROXY_ALL_WANS_DEGRADED", "PROXY", "All WAN Paths Degraded", "所有代理 WAN 路径质量下降", "dreamingproxy", "PROXY_WAN_PATH_RECOVERED", "", "", "error", "proxy.all_wans_degraded", 1),
    DW_EVENT("PROXY_WAN_PATH_RECOVERED", "PROXY", "WAN Path Recovered", "代理 WAN 路径已恢复", "dreamingproxy", "PROXY_ALL_WANS_DEGRADED", "PROXY_ALL_WANS_DEGRADED", "", "info", "proxy.wan_path_recovered", 1),
    DW_EVENT("PROXY_WAN_PATH_FLAPPING", "PROXY", "WAN Path Flapping", "代理 WAN 路径频繁波动", "dreamingproxy", "", "", "", "warning", "proxy.wan_path_flapping", 1),
    DW_EVENT("PROXY_CONFIG_APPLY_FAILED", "PROXY", "Proxy Config Apply Failed", "代理配置应用失败", "dreamingproxy", "", "", "", "error", "proxy.config_apply_failed", 1),
    DW_EVENT("PROXY_CONFIG_ROLLED_BACK", "PROXY", "Proxy Config Rolled Back", "代理配置已回滚", "dreamingproxy", "", "", "", "warning", "proxy.config_rolled_back", 1),
    DW_EVENT("PROXY_SUBSCRIPTION_UPDATE_FAILED", "PROXY", "Subscription Update Failed", "代理订阅更新失败", "dreamingproxy", "PROXY_SUBSCRIPTION_UPDATE_RECOVERED", "", "", "warning", "proxy.subscription_update_failed", 1),
    DW_EVENT("PROXY_SUBSCRIPTION_UPDATE_RECOVERED", "PROXY", "Subscription Update Recovered", "代理订阅更新已恢复", "dreamingproxy", "PROXY_SUBSCRIPTION_UPDATE_FAILED", "PROXY_SUBSCRIPTION_UPDATE_FAILED", "", "info", "proxy.subscription_update_recovered", 1),
    DW_EVENT("PROXY_RULESET_UPDATE_FAILED", "PROXY", "Ruleset Update Failed", "代理规则集更新失败", "dreamingproxy", "PROXY_RULESET_UPDATE_RECOVERED", "", "", "warning", "proxy.ruleset_update_failed", 1),
    DW_EVENT("PROXY_RULESET_UPDATE_RECOVERED", "PROXY", "Ruleset Update Recovered", "代理规则集更新已恢复", "dreamingproxy", "PROXY_RULESET_UPDATE_FAILED", "PROXY_RULESET_UPDATE_FAILED", "", "info", "proxy.ruleset_update_recovered", 1),
    DW_EVENT("PROXY_CORE_UNAVAILABLE", "PROXY", "Proxy Core Unavailable", "代理核心不可用", "dreamingproxy", "PROXY_CORE_RECOVERED", "", "", "error", "proxy.core_unavailable", 1),
    DW_EVENT("PROXY_CORE_RECOVERED", "PROXY", "Proxy Core Recovered", "代理核心已恢复", "dreamingproxy", "PROXY_CORE_UNAVAILABLE", "PROXY_CORE_UNAVAILABLE", "", "info", "proxy.core_recovered", 1),
    DW_EVENT("PROXY_EGRESS_DRIFT", "PROXY", "Proxy Egress Address Drift", "代理出口地址发生变化", "dreamingproxy", "", "", "", "warning", "proxy.egress_drift", 1),
};

const size_t dw_event_definitions_count =
    sizeof(dw_event_definitions) / sizeof(dw_event_definitions[0]);

const struct dw_event_definition *dw_event_definition_find(const char *id)
{
    size_t i;

    if (!id || !id[0])
        return NULL;
    for (i = 0; i < dw_event_definitions_count; i++)
        if (!strcmp(dw_event_definitions[i].id, id))
            return &dw_event_definitions[i];
    return NULL;
}

const char *dw_event_locale_normalize(const char *locale)
{
    if (locale && (!strncasecmp(locale, "en", 2)))
        return "en";
    return "zh-CN";
}

static struct json_object *dw_event_detail(struct json_object *event)
{
    struct json_object *detail = NULL;
    struct json_object *parameters = NULL, *raw = NULL;

    if (event && json_object_object_get_ex(event, "detail_json", &detail) && detail &&
        json_object_is_type(detail, json_type_object))
        return detail;
    if (event && json_object_object_get_ex(event, "parameters", &parameters) &&
        parameters && json_object_object_get_ex(parameters, "RAW", &raw) && raw &&
        json_object_object_get_ex(raw, "detail_json", &detail) && detail &&
        json_object_is_type(detail, json_type_object))
        return detail;
    return NULL;
}

static const char *dw_event_string(struct json_object *event, struct json_object *detail,
                                   const char *key)
{
    struct json_object *value = NULL;

    if (event && json_object_object_get_ex(event, key, &value) && value &&
        json_object_is_type(value, json_type_string) && json_object_get_string(value) &&
        json_object_get_string(value)[0])
        return json_object_get_string(value);
    if (detail && json_object_object_get_ex(detail, key, &value) && value &&
        json_object_is_type(value, json_type_string) && json_object_get_string(value))
        return json_object_get_string(value);
    return "";
}

struct json_object *dw_event_message_args(struct json_object *event)
{
    static const char *keys[] = {
        "device_name", "node_id", "iface", "interface", "port_name", "wan_id",
        "target", "mac", "client_mac", "ip", "client_ip", "hostname", "username",
        "user", "auth_method", "auth_result", "program", "service", "worker_index",
        "worker_pid", "metric", "value", "threshold", "unit", "reason", "error_code",
        "error_message", "operation_id", "rule_name", "action", "source_ip",
        "destination_ip", "protocol", "old_ip", "old_hostname",
        "drop_delta", "error_delta", "rx_drop_delta", "tx_drop_delta",
        "rx_error_delta", "tx_error_delta", "sample_interval_seconds",
        "result", "retry_seconds", "task_id", "request_id", "object_id", "object_name",
        "app_id", "version", "previous_version", "disk_id", "mountpoint", "actor", "engine", "provider", "use",
        "path", "bytes", "duration_ms", "failure_stage", "failure_reason",
        "boot_id", "boot_time", "phase", "sector", "filesystem", "trigger", "checksum", "size_bytes", "model", "serial", "device_number",
        "smart_status", "previous_smart_status"
    };
    struct json_object *args = json_object_new_object();
    struct json_object *detail = dw_event_detail(event);
    size_t i;

    if (!args)
        return NULL;
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        struct json_object *value = NULL;

        if (event && json_object_object_get_ex(event, keys[i], &value) && value &&
            (!json_object_is_type(value, json_type_string) || json_object_get_string(value)[0]))
            json_object_object_add(args, keys[i], json_object_get(value));
        else if (detail && json_object_object_get_ex(detail, keys[i], &value) && value)
            json_object_object_add(args, keys[i], json_object_get(value));
    }
    return args;
}

static const char *dw_event_subject(struct json_object *event, struct json_object *detail)
{
    const char *value = dw_event_string(event, detail, "device_name");

    if (!value[0]) value = dw_event_string(event, detail, "hostname");
    if (!value[0]) value = dw_event_string(event, detail, "username");
    if (!value[0]) value = dw_event_string(event, detail, "mac");
    if (!value[0]) value = dw_event_string(event, detail, "iface");
    if (!value[0]) value = dw_event_string(event, detail, "wan_id");
    if (!value[0]) value = dw_event_string(event, detail, "object_name");
    if (!value[0]) value = dw_event_string(event, detail, "object_id");
    if (!value[0]) value = dw_event_string(event, detail, "target");
    if (!strcmp(value, "SYSTEM") || !strcmp(value, "DEVICE") ||
        !strcmp(value, "CLIENT") || !strcmp(value, "ADMIN"))
        value = "";
    return value;
}

const struct dw_event_domain_definition dw_event_domains[] = {
    { "SYSTEM", "系统运行", "System" },
    { "AUTH", "登录与连接", "Login and connections" },
    { "STORAGE", "磁盘与存储", "Disks and storage" },
    { "FILES", "文件与共享", "Files and shares" },
    { "APPLICATIONS", "应用与服务", "Applications and services" },
    { "VIRTUALIZATION", "容器与虚拟机", "Containers and virtual machines" },
    { "BACKUP", "备份与同步", "Backup and sync" },
    { "INTERNET_AND_WAN", "网络与 WAN", "Network and WAN" },
    { "CLIENT_DEVICES", "终端与 DHCP", "Clients and DHCP" },
    { "DEVICES", "AP 与基础设备", "AP and infrastructure" },
    { "SECURITY", "安全", "Security" },
    { "VPN", "VPN", "VPN" },
    { "PROXY", "代理", "Proxy" },
    { "ADMIN", "管理操作（历史未分域）", "Administration (legacy domain)" },
};
const size_t dw_event_domains_count = sizeof(dw_event_domains) / sizeof(dw_event_domains[0]);

const struct dw_event_domain_definition *dw_event_domain_find(const char *id)
{
    size_t i;
    if (!id) return NULL;
    for (i = 0; i < dw_event_domains_count; i++)
        if (!strcmp(id, dw_event_domains[i].id)) return &dw_event_domains[i];
    return NULL;
}

const char *dw_event_audit_action_label(const char *action)
{
    static const struct { const char *action, *label; } labels[] = {
        {"system.settings.save", "保存系统设置"},
        {"appstore.configure", "修改应用配置"},
        {"appstore.network-policy", "修改应用网络策略"},
        {"docker.config.set", "修改 Docker 配置"},
        {"docker.container.create", "创建 Docker 容器"},
        {"docker.container.pause", "暂停 Docker 容器"},
        {"docker.container.remove", "删除 Docker 容器"},
        {"docker.container.rename", "重命名 Docker 容器"},
        {"docker.container.restart", "重启 Docker 容器"},
        {"docker.container.restart_policy", "修改 Docker 重启策略"},
        {"docker.container.start", "启动 Docker 容器"},
        {"docker.container.stop", "停止 Docker 容器"},
        {"docker.container.unpause", "恢复 Docker 容器运行"},
        {"docker.image.prune", "清理 Docker 镜像"},
        {"docker.image.pull", "拉取 Docker 镜像"},
        {"docker.image.remove", "删除 Docker 镜像"},
        {"docker.job.cancel", "取消 Docker 任务"},
        {"docker.network.create", "创建 Docker 网络"},
        {"docker.network.prune", "清理 Docker 网络"},
        {"docker.network.remove", "删除 Docker 网络"},
        {"docker.service", "控制 Docker 服务"},
        {"docker.volume.create", "创建 Docker 卷"},
        {"docker.volume.prune", "清理 Docker 卷"},
        {"docker.volume.remove", "删除 Docker 卷"},
        {"ftp.settings", "修改 FTP 设置"},
        {"ftp.share", "修改 FTP 共享"},
        {"storage.migration.apply", "迁移存储"},
        {"storage.files.copy", "复制文件"},
        {"storage.files.create", "创建文件"},
        {"storage.files.delete", "删除文件"},
        {"storage.files.mkdir", "创建目录"},
        {"storage.files.move", "移动文件"},
        {"storage.files.mutate", "文件操作"},
        {"storage.files.rename", "重命名文件"},
        {"storage.files.upload.cancel", "取消文件上传"},
        {"storage.files.upload.complete", "完成文件上传"},
        {"storage.files.write", "写入文件"},
        {"system.admin.avatar", "修改管理员头像"},
        {"system.admin.password", "修改管理员密码"},
        {"system.admin.rename", "修改管理员名称"},
        {"system.cpu_interrupt.set", "修改 CPU 中断设置"},
        {"system.cpufreq.set", "修改 CPU 频率设置"},
        {"system.flash.firmware.apply", "安装固件"},
        {"system.flash.firmware.verify", "校验固件"},
        {"system.flash.preserve_config", "修改配置保留设置"},
        {"system.flash.signature.apply", "更新特征库"},
        {"system.flash.signature.validate", "校验特征库更新"},
        {"system.kernel.restore_defaults", "恢复内核默认设置"},
        {"system.net_tuning.set", "修改网络调优设置"},
        {"system.ota.apply", "安装系统更新"},
        {"system.ota.confirm_boot", "确认更新后启动"},
        {"system.ota.rollback", "回滚系统更新"},
        {"system.user_groups.create", "创建用户组"},
        {"system.user_groups.delete", "删除用户组"},
        {"system.user_groups.update", "修改用户组"},
        {"system.users.create", "创建用户"},
        {"system.users.delete", "删除用户"},
        {"system.users.import", "导入用户"},
        {"system.users.import.validate", "校验用户导入"},
        {"system.users.update", "修改用户"},
        {"storage.files.upload", "上传文件"},
        {"storage.files.action", "文件操作"},
        {"storage.migrate", "迁移存储"},
        {"webdav.share", "修改 WebDAV 共享"},
        {"file-share.operation", "修改远程共享"},
        {"file-share.account", "修改共享账号"},
        {"file-service.action", "控制文件服务"},
        {"nfs.defaults", "修改 NFS 默认设置"},
        {"samba.settings", "修改 SMB 设置"},
        {"system.startup.service-action", "控制启动服务"},
        {"system.startup.rc-local", "修改本地启动脚本"},
        {"system.crontab.apply", "修改计划任务"},
        {"system.flash.create_backup", "创建配置备份"},
        {"system.flash.backup.create", "创建配置备份"},
        {"system.flash.backup.delete", "删除配置备份"},
        {"system.flash.backup_policy.set", "修改备份策略"},
        {"system.flash.restore_backup", "准备配置恢复"},
        {"system.flash.restore.confirm", "确认配置恢复"},
        {"system.flash.restore.rollback", "回滚配置恢复"},
        {"auth.login.success", "Web 登录成功"},
        {"auth.login.failed", "Web 登录失败"},
        {"auth.logout", "退出登录"},
        {"vm.instance_create", "创建虚拟机"},
        {"vm.instance_delete", "删除虚拟机"},
        {"vm.instance_action", "控制虚拟机"},
        {"vm.task_cancel", "取消虚拟机任务"},
        {"lxc.container.create", "创建 LXC 容器"},
        {"lxc.container.destroy", "删除 LXC 容器"},
        {"lxc.container.start", "启动 LXC 容器"},
        {"lxc.container.stop", "停止 LXC 容器"},
        {"lxc.container.restart", "重启 LXC 容器"},
        {"lxc.container.clone", "克隆 LXC 容器"},
        {"lxc.container.snapshot", "创建快照 LXC 容器"},
        {"lxc.container.config.set", "修改配置 LXC 容器"},
        {"lxc.snapshot.restore", "恢复 LXC 快照"},
        {"appstore.install", "安装应用"},
        {"appstore.update", "更新应用"},
        {"appstore.uninstall", "卸载应用"},
        {"appstore.rollback", "回滚应用"},
    };
    if (!action) return "";
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++)
        if (!strcmp(action, labels[i].action)) return labels[i].label;
    return action;
}

const char *dw_event_audit_domain(const char *action)
{
    static const struct { const char *prefix; const char *domain; } map[] = {
        { "auth.", "AUTH" }, { "storage.files.", "FILES" }, { "storage.shares.", "FILES" },
        { "files.", "FILES" }, { "file_services.", "FILES" }, { "nas.", "FILES" },
        { "file-share.", "FILES" }, { "file-service.", "FILES" },
        { "webdav.", "FILES" }, { "nfs.", "FILES" }, { "samba.", "FILES" }, { "ftp.", "FILES" },
        { "storage.", "STORAGE" }, { "appstore.", "APPLICATIONS" }, { "application.", "APPLICATIONS" },
        { "vm.", "VIRTUALIZATION" }, { "docker.", "VIRTUALIZATION" }, { "lxc.", "VIRTUALIZATION" },
        { "backup.", "BACKUP" }, { "system.backup", "BACKUP" }, { "system.restore", "BACKUP" },
        { "system.flash.backup", "BACKUP" }, { "system.flash.create_backup", "BACKUP" }, { "system.flash.restore", "BACKUP" },
        { "network.dhcp.", "CLIENT_DEVICES" }, { "client.", "CLIENT_DEVICES" },
        { "ap.", "DEVICES" }, { "ac.", "DEVICES" }, { "proxy.", "PROXY" },
        { "vpn.", "VPN" }, { "security.", "SECURITY" }, { "firewall.", "SECURITY" },
        { "network.", "INTERNET_AND_WAN" }, { "system.", "SYSTEM" }
    };
    if (action) for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++)
        if (!strncmp(action, map[i].prefix, strlen(map[i].prefix))) return map[i].domain;
    return "ADMIN";
}

const char *dw_event_domain(const char *category, const char *id,
                            struct json_object *detail)
{
    const struct dw_event_definition *def = dw_event_definition_find(id);
    const char *explicit_domain = dw_event_string(NULL, detail, "domain");
    const char *metric = dw_event_string(NULL, detail, "metric");
    if (dw_event_domain_find(explicit_domain)) return explicit_domain;
    struct json_object *audit = NULL;
    if (detail && json_object_object_get_ex(detail, "web_audit", &audit) && json_object_get_boolean(audit))
        return dw_event_audit_domain(id);
    if (id && (!strcmp(id, "SECURITY_AUTH_EVENT") || !strcmp(id, "ADMIN_AUTH_EVENT")))
        return "AUTH";
    if (id && (!strcmp(id, "SYSTEM_RESOURCE_THRESHOLD") || !strcmp(id, "SYSTEM_RESOURCE_RECOVERED")) &&
        (!strcmp(metric, "disk") || !strcmp(metric, "inode"))) return "STORAGE";
    if (id && !strcmp(id, "APPLICATION_UPDATE_FAILED")) return "APPLICATIONS";
    if (def) return def->category;
    return dw_event_domain_find(category) ? category : "SYSTEM";
}

int dw_event_is_business(const char *id)
{
    return id && strcmp(id, "SYSTEM_LOG") && dw_event_definition_find(id) != NULL;
}

const char *dw_event_effective_severity(const char *id, struct json_object *detail,
                                        const char *stored)
{
    const char *result = dw_event_string(NULL, detail, "auth_result");
    if (id && !strcmp(id, "SECURITY_AUTH_EVENT")) {
        if (!strcmp(result, "success") || !strcmp(result, "disconnected")) return "info";
        if (!strcmp(result, "failure") && (!stored ||
            (strcmp(stored, "critical") && strcmp(stored, "error")))) return "warning";
    }
    if (id && (!strcmp(id, "APP_OPERATION_FINISHED") || !strcmp(id, "VM_OPERATION_FINISHED") || !strcmp(id, "STORAGE_MIGRATION_FINISHED") || !strcmp(id, "VM_ACTION_RESULT") || !strcmp(id, "CONFIG_BACKUP_FINISHED") || !strcmp(id, "SYSTEM_POWER_ACTION") || !strcmp(id, "CONFIG_RESTORE_STATE"))) {
        result = dw_event_string(NULL, detail, "result");
        return !strcmp(result, "failed") ? "error" : "info";
    }
    if (id && (!strcmp(id, "NFS_TARGET_UNREACHABLE") || !strcmp(id, "NFS_MOUNT_RETRYING"))) return "warning";
    if (id && (!strcmp(id, "FTP_CONNECTION") || !strcmp(id, "FTP_AUTH_RESULT") ||
               !strcmp(id, "FTP_TRANSFER_FINISHED") || !strcmp(id, "FTP_FILE_ACTION"))) {
        result = dw_event_string(NULL, detail, "result");
        if (!strcmp(result, "refused")) return "warning";
        if (!strcmp(result, "failed")) return !strcmp(id, "FTP_AUTH_RESULT") ? "warning" : "error";
        return "info";
    }
    if (id && !strcmp(id, "STORAGE_SMART_FAILED")) return "error";
    if (id && !strcmp(id, "STORAGE_SMART_RECOVERED")) return "info";
    return stored ? stored : "info";
}

static const char *dw_event_number(struct json_object *detail, const char *key)
{
    struct json_object *v = NULL;
    if (!detail || !json_object_object_get_ex(detail, key, &v) || !v ||
        (!json_object_is_type(v, json_type_int) && !json_object_is_type(v, json_type_double)))
        return "";
    return json_object_get_string(v);
}

static void dw_event_description(const struct dw_event_definition *def,
                                 struct json_object *event, const char *locale,
                                 char *out, size_t out_len, int *partial)
{
    struct json_object *detail = dw_event_detail(event);
    const char *subject = dw_event_subject(event, detail);
    const char *ip = dw_event_string(event, detail, "ip");
    const char *mac = dw_event_string(event, detail, "mac");
    const char *program = dw_event_string(event, detail, "program");
    const char *username = dw_event_string(event, detail, "username");
    const char *method = dw_event_string(event, detail, "auth_method");
    const char *result = dw_event_string(event, detail, "auth_result");
    const char *label = !strcmp(locale, "en") ? def->label_en : def->label_zh;

    if (!ip[0] && !strcmp(def->id, "SECURITY_AUTH_EVENT"))
        ip = dw_event_string(event, detail, "source_ip");

    if (!strcmp(def->id, "DHCP_LEASE_ASSIGNED") ||
        !strcmp(def->id, "DHCP_LEASE_RELEASED") ||
        !strcmp(def->id, "DHCP_LEASE_CHANGED") ||
        !strcmp(def->id, "DHCP_LEASE_RENEWED")) {
        const char *verb_en = !strcmp(def->id, "DHCP_LEASE_ASSIGNED") ? "Assigned" :
            (!strcmp(def->id, "DHCP_LEASE_RELEASED") ? "Released" :
             (!strcmp(def->id, "DHCP_LEASE_CHANGED") ? "Changed" : "Renewed"));
        const char *verb_zh = !strcmp(def->id, "DHCP_LEASE_ASSIGNED") ? "已分配" :
            (!strcmp(def->id, "DHCP_LEASE_RELEASED") ? "已释放" :
             (!strcmp(def->id, "DHCP_LEASE_CHANGED") ? "已变更" : "已续期"));

        if (!ip[0] || !mac[0])
            *partial = 1;
        if (!strcmp(locale, "en"))
            snprintf(out, out_len, "%s DHCP address%s%s%s%s.", verb_en,
                     ip[0] ? " " : "", ip, mac[0] ? " for " : "", mac);
        else
            snprintf(out, out_len, "%s DHCP 地址%s%s%s%s。", verb_zh,
                     ip[0] ? " " : "", ip, mac[0] ? "，设备 " : "", mac);
        return;
    }
    if (!strcmp(def->id, "SECURITY_AUTH_EVENT")) {
        const char *service = dw_event_string(event, detail, "service");
        const char *protocol = !strcmp(service, "ssh") ? "SSH " : "";
        const char *method_en = !strcmp(method, "publickey") ? "public key" :
            (!strcmp(method, "password") ? "password" :
             (!strcmp(method, "sudo") ? "sudo" : "device"));
        const char *method_zh = !strcmp(method, "publickey") ? "公钥" :
            (!strcmp(method, "password") ? "密码" :
             (!strcmp(method, "sudo") ? "sudo" : "设备"));

        if (!username[0] || !result[0])
            *partial = 1;
        if (!username[0]) {
            snprintf(out, out_len, !strcmp(locale, "en") ? "%s%s%s%s; user identity unavailable." :
                     "%s%s%s%s；未记录用户身份。", protocol,
                     !strcmp(result, "disconnected") ? (!strcmp(locale, "en") ? "session disconnected" : "会话已断开") :
                     !strcmp(result, "failure") ? (!strcmp(locale, "en") ? "authentication failed" : "认证失败") :
                     !strcmp(result, "success") ? (!strcmp(locale, "en") ? "authentication succeeded" : "认证成功") :
                     (!strcmp(locale, "en") ? "authentication event" : "认证事件"),
                     ip[0] ? (!strcmp(locale, "en") ? " from " : "，来源 IP：") : "", ip);
            return;
        }
        if ((!strcmp(result, "success") || !strcmp(result, "failure")) && !method[0])
            *partial = 1;
        if (!strcmp(locale, "en")) {
            if (!strcmp(result, "success"))
                snprintf(out, out_len, "User %s authenticated successfully using %s%s%s.",
                         username[0] ? username : "unknown", method_en,
                         ip[0] ? " from " : "", ip);
            else if (!strcmp(result, "failure"))
                snprintf(out, out_len, "Authentication failed for user %s using %s%s%s.",
                         username[0] ? username : "unknown", method_en,
                         ip[0] ? " from " : "", ip);
            else if (!strcmp(result, "disconnected"))
                snprintf(out, out_len, "Session for user %s disconnected%s%s.",
                         username[0] ? username : "unknown",
                         ip[0] ? " from " : "", ip);
            else
                snprintf(out, out_len, "User %s attempted %s authentication%s%s.",
                         username[0] ? username : "unknown", method_en,
                         ip[0] ? " from " : "", ip);
        } else {
            if (!strcmp(result, "success"))
                snprintf(out, out_len, "用户 %s 通过%s%s认证成功%s%s。",
                         username, protocol, method_zh,
                         ip[0] ? "，源 IP：" : "", ip);
            else if (!strcmp(result, "failure"))
                snprintf(out, out_len, "用户 %s 的%s认证失败%s%s。",
                         username[0] ? username : "未知用户", method_zh,
                         ip[0] ? "，源 IP：" : "", ip);
            else if (!strcmp(result, "disconnected"))
                snprintf(out, out_len, "用户 %s 的会话已断开%s%s。",
                         username[0] ? username : "未知用户",
                         ip[0] ? "，源 IP：" : "", ip);
            else
                snprintf(out, out_len, "用户 %s 发起了%s认证%s%s。",
                         username[0] ? username : "未知用户", method_zh,
                         ip[0] ? "，源 IP：" : "", ip);
        }
        return;
    }
    if (!strcmp(def->id, "STORAGE_SMART_FAILED") || !strcmp(def->id, "STORAGE_SMART_RECOVERED")) {
        const char *disk = dw_event_string(event, detail, "object_id");
        const char *model = dw_event_string(event, detail, "object_name");
        int failed = !strcmp(def->id, "STORAGE_SMART_FAILED");
        if (!disk[0] || !dw_event_string(event, detail, "smart_status")[0]) *partial = 1;
        snprintf(out, out_len, !strcmp(locale, "en") ? "Disk %s%s%s: SMART health check %s." :
                 "磁盘 %s%s%s：SMART 健康检查%s。", disk, model[0] ? " / " : "", model,
                 failed ? (!strcmp(locale, "en") ? "failed" : "失败") :
                          (!strcmp(locale, "en") ? "passed again" : "恢复通过"));
        return;
    }
    if (!strcmp(def->id, "STORAGE_DEVICE_OBSERVED") || !strcmp(def->id, "STORAGE_DEVICE_REMOVED")) {
        const char *disk = dw_event_string(event, detail, "disk_id"), *model = dw_event_string(event, detail, "model");
        int removed = !strcmp(def->id, "STORAGE_DEVICE_REMOVED");
        if (!disk[0] || !model[0]) *partial = 1;
        if (!strcmp(locale, "en")) snprintf(out, out_len, "%s disk %s%s%s.", removed ? "Removed" : "Observed", disk, model[0] ? ": " : "", model);
        else snprintf(out, out_len, "磁盘 %s：%s%s%s。", disk, removed ? "已移除" : "已发现", model[0] ? "，型号 " : "", model);
        return;
    }
    if (!strcmp(def->id, "STORAGE_IO_ERROR") || !strcmp(def->id, "STORAGE_READ_ONLY")) {
        const char *disk = dw_event_string(event, detail, "disk_id");
        const char *sector = dw_event_number(detail, "sector");
        int io = !strcmp(def->id, "STORAGE_IO_ERROR");
        if (!disk[0] || (io && !sector[0])) *partial = 1;
        if (!strcmp(locale, "en")) snprintf(out, out_len, io ? "Disk %s: I/O error at sector %s." : "Filesystem on %s remounted read-only.%s", disk[0] ? disk : "not recorded", io ? sector : "");
        else snprintf(out, out_len, io ? "磁盘 %s：扇区 %s 读写出错。" : "磁盘 %s 上的文件系统已转为只读。%s", disk[0] ? disk : "未记录", io ? sector : "");
        return;
    }
    if (!strcmp(def->id, "SYSTEM_BOOT_OBSERVED")) {
        const char *boot = dw_event_string(event, detail, "boot_id");
        const char *started = dw_event_number(detail, "boot_time");
        if (!boot[0] || !started[0]) *partial = 1;
        snprintf(out, out_len, !strcmp(locale, "en") ? "Observed system boot %s (kernel boot time: %s). Previous shutdown cause is unknown." : "已观察到本次系统启动 %s（内核启动时间：%s）；上一轮关机原因未记录。", boot, started);
        return;
    }
    if (!strcmp(def->id, "SYSTEM_RESOURCE_RECOVERED")) {
        const char *metric = dw_event_string(event, detail, "metric"), *value = dw_event_number(detail, "value"), *threshold = dw_event_number(detail, "threshold");
        if (!metric[0] || !value[0] || !threshold[0]) *partial = 1;
        snprintf(out, out_len, !strcmp(locale, "en") ? "%s usage recovered to %s, below warning threshold %s." : "%s 用量已恢复至 %s，低于警告阈值 %s。", metric, value, threshold);
        return;
    }
    if (!strcmp(def->id, "NFS_TARGET_UNREACHABLE")) {
        const char *host = dw_event_string(event, detail, "object_id");
        if (!host[0]) *partial = 1;
        snprintf(out, out_len, !strcmp(locale, "en") ? "NFS target %s is unreachable; the mount will still be attempted." : "NFS 目标 %s 暂不可达，仍将尝试挂载。", host[0] ? host : "未记录");
        return;
    }
    if (!strcmp(def->id, "FTP_CONNECTION") || !strcmp(def->id, "FTP_AUTH_RESULT") ||
        !strcmp(def->id, "FTP_TRANSFER_FINISHED") || !strcmp(def->id, "FTP_FILE_ACTION")) {
        int en = !strcmp(locale, "en");
        const char *ip = dw_event_string(event, detail, "source_ip");
        const char *user = dw_event_string(event, detail, "username");
        const char *result = dw_event_string(event, detail, "result");
        const char *reason = dw_event_string(event, detail, "failure_reason");
        const char *action = dw_event_string(event, detail, "action");
        const char *path = dw_event_string(event, detail, "path");
        const char *args = dw_event_string(event, detail, "operation_args");
        const char *bytes = dw_event_number(detail, "size_bytes");
        int failed = !strcmp(result, "failed"), refused = !strcmp(result, "refused");
        if (!ip[0] || !result[0]) *partial = 1;
        if (!strcmp(def->id, "FTP_CONNECTION")) {
            if (refused && !reason[0]) *partial = 1;
            snprintf(out, out_len, en ? "FTP connection from %s %s%s%s." : "来自 %s 的 FTP 连接%s%s%s。",
                     ip[0] ? ip : (en ? "unknown address" : "地址未记录"),
                     en ? (refused ? "was refused" : "was accepted; authentication has not completed") :
                          (refused ? "被拒绝" : "已接入，尚未完成认证"),
                     reason[0] ? (en ? ": " : "：") : "", reason);
            return;
        }
        if (!user[0] || (failed && !reason[0])) *partial = 1;
        const char *action_label = !strcmp(action, "login") ? "登录" :
            !strcmp(action, "upload") ? "上传" : !strcmp(action, "download") ? "下载" :
            !strcmp(action, "mkdir") ? "创建目录" : !strcmp(action, "delete") ? "删除文件" :
            !strcmp(action, "rename") ? "重命名" : !strcmp(action, "rmdir") ? "删除目录" :
            !strcmp(action, "chmod") ? "修改权限" : action;
        if (strcmp(def->id, "FTP_AUTH_RESULT") && !path[0]) *partial = 1;
        if (!strcmp(def->id, "FTP_TRANSFER_FINISHED") && !bytes[0]) *partial = 1;
        const char *object = path[0] ? path : args;
        snprintf(out, out_len, en ? "%s from %s: FTP %s %s%s%s%s%s%s%s%s." : "%s（%s）通过 FTP %s%s%s%s%s%s%s%s%s。",
                 user[0] ? user : (en ? "User not recorded" : "用户未记录"),
                 ip[0] ? ip : (en ? "address not recorded" : "地址未记录"),
                 en ? action : action_label, en ? (failed ? "failed" : "succeeded") : (failed ? "失败" : "成功"),
                 object[0] ? (args[0] ? (en ? "; original arguments: " : "，原始参数：") : (en ? ": " : "：")) : "", object,
                 bytes[0] ? (en ? "; transferred " : "，已传输 ") : "", bytes, bytes[0] ? (en ? " bytes" : " 字节") : "",
                 failed ? (en ? "; reason: " : "，原因：") : "",
                 failed ? (reason[0] ? reason : (en ? "not recorded" : "未记录")) : "");
        return;
    }
    if (!strcmp(def->id, "NFS_MOUNT_RETRYING")) {
        const char *retry = dw_event_number(detail, "retry_seconds"), *code = dw_event_number(detail, "error_code");
        *partial = 1; /* This producer line does not identify a mount/target. */
        snprintf(out, out_len, !strcmp(locale, "en") ? "NFS mount attempt failed (code %s); retry in %s seconds. Target not recorded." : "NFS 本次挂载失败（错误码 %s），%s 秒后重试；该记录未提供目标。", code[0] ? code : "—", retry[0] ? retry : "—");
        return;
    }
    if (!strcmp(def->id, "APP_OPERATION_FINISHED") || !strcmp(def->id, "VM_OPERATION_FINISHED") || !strcmp(def->id, "STORAGE_MIGRATION_FINISHED") || !strcmp(def->id, "VM_ACTION_RESULT") || !strcmp(def->id, "CONFIG_BACKUP_FINISHED") || !strcmp(def->id, "SYSTEM_POWER_ACTION") || !strcmp(def->id, "CONFIG_RESTORE_STATE")) {
        const char *object = dw_event_string(event, detail, "object_name");
        if (!object[0]) object = dw_event_string(event, detail, "object_id");
        const char *action = dw_event_string(event, detail, "action");
        const char *result = dw_event_string(event, detail, "result");
        const char *reason = dw_event_string(event, detail, "failure_reason");
        const char *task = dw_event_string(event, detail, "task_id");
        const char *result_zh = !strcmp(result, "success") ? "成功" : !strcmp(result, "failed") ? "失败" : !strcmp(result, "cancelled") ? "已取消" : !strcmp(result, "rolled_back") ? "已回滚" : !strcmp(result, "accepted") ? "已受理" : !strcmp(result, "dispatched") ? "已调度" : "结果未记录";
        const char *action_zh = !strcmp(action, "install") ? "安装" : !strcmp(action, "update") ? "更新" : !strcmp(action, "uninstall") ? "卸载" : !strcmp(action, "rollback") ? "回滚" : !strcmp(action, "instance_create") ? "创建" : !strcmp(action, "instance_delete") ? "删除" : !strcmp(action, "migrate") ? "迁移" : !strcmp(action, "restore") ? "恢复" : !strcmp(action, "backup") ? "备份" : !strcmp(action, "start") ? "启动" : !strcmp(action, "shutdown") ? "关机" : !strcmp(action, "reboot") ? "重启" : !strcmp(action, "pause") ? "暂停" : !strcmp(action, "resume") ? "恢复运行" : !strcmp(action, "force_stop") ? "强制停止" : !strcmp(action, "reset") ? "重置" : action;
        if (!object[0] || !action[0] || !result[0] || (!strcmp(result, "failed") && !reason[0])) *partial = 1;
        if (!strcmp(locale, "en")) snprintf(out, out_len, "%s: %s %s%s%s%s%s.", object[0] ? object : "Object not recorded", action, result, reason[0] ? "; reason: " : "", reason, task[0] ? "; task: " : "", task);
        else snprintf(out, out_len, "%s：%s%s%s%s%s%s。", object[0] ? object : "未记录对象", action_zh, result_zh, reason[0] ? "，原因：" : "", reason, task[0] ? "，任务：" : "", task);
        return;
    }
    if (!strcmp(def->id, "PORT_DROPPED_TRAFFIC") || !strcmp(def->id, "PORT_TX_RX_ERRORS")) {
        int drops = !strcmp(def->id, "PORT_DROPPED_TRAFFIC");
        const char *iface = dw_event_string(event, detail, "iface");
        const char *delta = dw_event_number(detail, drops ? "drop_delta" : "error_delta");
        const char *interval = dw_event_number(detail, "sample_interval_seconds");
        const char *threshold = dw_event_number(detail, "threshold");
        if (!iface[0] || !delta[0] || !interval[0] || !threshold[0]) *partial = 1;
        if (!strcmp(locale, "en"))
            snprintf(out, out_len, "%s: %s %s in %s seconds; threshold %s.", iface[0] ? iface : "Port",
                     delta[0] ? delta : "unknown", drops ? "dropped packets" : "TX/RX errors",
                     interval[0] ? interval : "unknown", threshold[0] ? threshold : "unknown");
        else
            snprintf(out, out_len, "%s 在 %s 秒内新增 %s 个%s，阈值 %s。", iface[0] ? iface : "端口",
                     interval[0] ? interval : "未记录", delta[0] ? delta : "未记录",
                     drops ? "丢包" : "收发错误", threshold[0] ? threshold : "未记录");
        return;
    }
    if (!strcmp(def->id, "SYSTEM_RESOURCE_THRESHOLD")) {
        const char *metric = dw_event_string(event, detail, "metric");
        const char *value = dw_event_number(detail, "value");
        const char *threshold = dw_event_number(detail, "threshold");
        const char *unit = dw_event_string(event, detail, "unit");
        if (!strcmp(unit, "percent")) unit = "%";
        else if (!strcmp(unit, "celsius")) unit = "°C";
        if (!metric[0] || !value[0] || !threshold[0] || !unit[0]) *partial = 1;
        snprintf(out, out_len, !strcmp(locale, "en") ? "%s: %s%s; threshold %s%s." : "%s：%s%s，阈值 %s%s。",
                 metric[0] ? metric : (!strcmp(locale, "en") ? "Resource" : "资源指标"),
                 value[0] ? value : "—", unit, threshold[0] ? threshold : "—", unit);
        return;
    }
    if (!strcmp(def->id, "SYSTEM_LOG")) {
        *partial = 1;
        snprintf(out, out_len, !strcmp(locale, "en") ?
                 "%s produced an unclassified log entry." : "%s 产生了一条未分类日志。",
                 program[0] ? program : "system");
        return;
    }
    if (subject[0])
        snprintf(out, out_len, !strcmp(locale, "en") ? "%s: %s." : "%s：%s。",
                 subject, label);
    else {
        *partial = 1;
        snprintf(out, out_len, "%s%s", label, !strcmp(locale, "en") ? "." : "。");
    }
}

static struct json_object *dw_event_actions(const struct dw_event_definition *def,
                                            struct json_object *event,
                                            const char *locale)
{
    struct json_object *actions = json_object_new_array();
    struct json_object *detail = dw_event_detail(event);
    const char *iface = dw_event_string(event, detail, "iface");
    const char *node = dw_event_string(event, detail, "node_id");

    if (!actions)
        return NULL;
    if ((!strcmp(def->id, "PORT_LINK_DOWN") || !strcmp(def->id, "PORT_LINK_UP")) &&
        iface[0]) {
        struct json_object *action = json_object_new_object();
        struct json_object *target = json_object_new_object();
        json_object_object_add(action, "id", json_object_new_string("view_port"));
        json_object_object_add(action, "label", json_object_new_string(
            !strcmp(locale, "en") ? "View port" : "查看端口"));
        json_object_object_add(target, "type", json_object_new_string("port"));
        json_object_object_add(target, "id", json_object_new_string(iface));
        json_object_object_add(action, "target", target);
        json_object_array_add(actions, action);
    } else if ((!strcmp(def->id, "DEVICE_OFFLINE") ||
                !strcmp(def->id, "DEVICE_RESTORED")) && node[0]) {
        struct json_object *action = json_object_new_object();
        struct json_object *target = json_object_new_object();
        json_object_object_add(action, "id", json_object_new_string("view_device"));
        json_object_object_add(action, "label", json_object_new_string(
            !strcmp(locale, "en") ? "View device" : "查看设备"));
        json_object_object_add(target, "type", json_object_new_string("device"));
        json_object_object_add(target, "id", json_object_new_string(node));
        json_object_object_add(action, "target", target);
        json_object_array_add(actions, action);
    }
    return actions;
}

struct json_object *dw_event_presentation_render(struct json_object *event,
                                                 const char *requested_locale)
{
    const char *id = NULL;
    struct json_object *id_obj = NULL;
    const struct dw_event_definition *def;
    const char *locale = dw_event_locale_normalize(requested_locale);
    struct json_object *presentation = json_object_new_object();
    struct json_object *detail = dw_event_detail(event);
    struct json_object *actions;
    const char *reason;
    char description[DW_RENDER_BODY_MAX];
    int partial = 0;

    if (!presentation)
        return NULL;
    if (event && json_object_object_get_ex(event, "event", &id_obj) && id_obj &&
        json_object_is_type(id_obj, json_type_string))
        id = json_object_get_string(id_obj);
    def = dw_event_definition_find(id);
    if (!def) {
        const char *source = dw_event_string(event, detail, "program");
        if (!source[0]) source = dw_event_string(event, detail, "source");
        if (!source[0]) source = "system";
        json_object_object_add(presentation, "locale", json_object_new_string(locale));
        json_object_object_add(presentation, "title", json_object_new_string(
            !strcmp(locale, "en") ? "Unclassified event" : "未分类事件"));
        snprintf(description, sizeof(description), !strcmp(locale, "en") ?
                 "%s produced an event that has not been classified." :
                 "%s 产生了一条尚未分类的事件。", source);
        json_object_object_add(presentation, "description", json_object_new_string(description));
        json_object_object_add(presentation, "reason_text", NULL);
        json_object_object_add(presentation, "recommended_actions", json_object_new_array());
        json_object_object_add(presentation, "render_status", json_object_new_string("unclassified"));
        return presentation;
    }
    dw_event_description(def, event, locale, description, sizeof(description), &partial);
    reason = dw_event_string(event, detail, "reason_text");
    if (!reason[0]) reason = dw_event_string(event, detail, "reason");
    actions = dw_event_actions(def, event, locale);
    json_object_object_add(presentation, "locale", json_object_new_string(locale));
    json_object_object_add(presentation, "title", json_object_new_string(
        !strcmp(locale, "en") ? def->label_en : def->label_zh));
    json_object_object_add(presentation, "description", json_object_new_string(description));
    if (reason[0])
        json_object_object_add(presentation, "reason_text", json_object_new_string(reason));
    else
        json_object_object_add(presentation, "reason_text", NULL);
    json_object_object_add(presentation, "recommended_actions",
                           actions ? actions : json_object_new_array());
    json_object_object_add(presentation, "render_status",
                           json_object_new_string(partial ? "partial" : "complete"));
    return presentation;
}

int dw_event_payload_present(struct json_object *event, const char *locale)
{
    struct json_object *presentation;
    struct json_object *args;
    struct json_object *value = NULL;
    const struct dw_event_definition *def;
    const char *id = "";
    const char *normalized = dw_event_locale_normalize(locale);

    if (!event || !json_object_is_type(event, json_type_object))
        return 0;
    if (json_object_object_get_ex(event, "event", &value) && value &&
        json_object_is_type(value, json_type_string))
        id = json_object_get_string(value);
    def = dw_event_definition_find(id);
    args = dw_event_message_args(event);
    presentation = dw_event_presentation_render(event, normalized);
    if (!args || !presentation) {
        if (args) json_object_put(args);
        if (presentation) json_object_put(presentation);
        return 0;
    }
    json_object_object_add(event, "message_key", json_object_new_string(
        def ? def->message_key : "event.unclassified"));
    json_object_object_add(event, "message_version", json_object_new_int(
        def ? (int)def->message_version : 1));
    json_object_object_add(event, "message_args", args);
    json_object_object_add(event, "presentation", presentation);
    json_object_object_add(event, "locale", json_object_new_string(normalized));
    json_object_object_add(event, "title", json_object_get(
        json_object_object_get(presentation, "title")));
    json_object_object_add(event, "message", json_object_get(
        json_object_object_get(presentation, "description")));
    return 1;
}
