// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * jmx_netconfig_db.h - DreamingWrt core configuration database accessors
 *
 * These legacy jmx_netconfig_* entry points now write durable router
 * configuration to /etc/dreamingwrt/config.db.  network.db is no longer a
 * configuration target; UCI/netifd is generated from config.db as runtime
 * apply output.
 *
 * Copyright(c) 2026 Lester(CJM) <www.lesterwrt.com>
 */
#ifndef __JMX_NETCONFIG_DB_H__
#define __JMX_NETCONFIG_DB_H__

#include <json-c/json.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

struct uci_context;
struct uci_package;

#define JMX_NETCONFIG_DB_PATH_DEFAULT "/etc/dreamingwrt/config.db"

#define JMX_NETCONFIG_DELETE_NOT_FOUND       -2
#define JMX_NETCONFIG_DELETE_PROTECTED       -3
#define JMX_NETCONFIG_DELETE_LAST_LAN        -4
#define JMX_NETCONFIG_DELETE_PORTS_ATTACHED  -5
#define JMX_NETCONFIG_DELETE_CHILD_LAN       -6
#define JMX_NETCONFIG_DELETE_IPAM_ATTACHED   -7
#define JMX_NETCONFIG_DELETE_SNAPSHOT_FAILED -8
#define JMX_NETCONFIG_DELETE_MANAGEMENT_PATH -9

/* lifecycle */
int  jmx_netconfig_db_init(void);
void jmx_netconfig_db_close(void);

typedef struct {
    char lan_ifname[32];
    int theme_mode;
    int record_enabled;
    int record_time;
    int app_valid_time;
    char history_data_size[64];
    char history_data_path[256];
    char monitor_device[64];
    int health_flush_sec;
    int health_prune_sec;
    int health_max_age_days;
} jmx_legacy_settings_t;

typedef int (*jmx_client_nickname_cb)(const char *mac, const char *nickname,
                                      void *arg);

/* Legacy jmxd settings now owned by config.db. UCI is a one-time migration source only. */
int jmx_legacy_settings_get(jmx_legacy_settings_t *settings);
int jmx_legacy_settings_set_system(const char *lan_ifname, int theme_mode);
int jmx_legacy_settings_set_record(int enabled, int record_time,
                                   int app_valid_time,
                                   const char *history_data_size,
                                   const char *history_data_path);
int jmx_legacy_settings_set_dashboard(const char *monitor_device);
int jmx_client_nickname_set(const char *mac, const char *nickname);
int jmx_client_nickname_foreach(jmx_client_nickname_cb callback, void *arg);
int jmx_network_control_appfilter_enabled(void);
int jmx_network_control_macfilter_enabled(void);
int jmx_network_control_set_filter_enabled(const char *filter, int enabled);
int jmx_identification_mode_get(char *mode, size_t mode_len,
                                int *traffic_record_enabled);
int jmx_identification_mode_set(const char *mode);

/* First-party work-mode authority. UCI is only a one-time migration source. */
int jmx_work_mode_config_get(int *mode, char *last_apply_id,
                             size_t last_apply_id_len,
                             char *apply_state, size_t apply_state_len);
int jmx_work_mode_config_set_legacy(int mode);
int jmx_work_mode_config_begin_apply(int target_mode, const char *rollback_id,
                                     int disable_dhcp, int disable_nat,
                                     int *previous_mode);
int jmx_work_mode_config_finish_apply(int success, const char *error);
int jmx_work_mode_config_begin_rollback(const char *rollback_id,
                                        int *target_mode);
int jmx_work_mode_config_finish_rollback(int success,
                                         const char *rollback_id,
                                         const char *error);

/* WAN CRUD */
struct json_object *jmx_netconfig_wan_list(void);
int jmx_netconfig_wan_configured(const char *id, const char *ifname);
struct json_object *jmx_netconfig_wan_get(const char *id);
int  jmx_netconfig_wan_set(struct json_object *wan_json);
int  jmx_netconfig_wan_set_enabled(const char *id, int enabled);
int  jmx_netconfig_wan_delete(const char *id);
struct json_object *jmx_netconfig_wan_save_apply_result(struct json_object *wan_json);
struct json_object *jmx_netconfig_wan_delete_result(const char *id);
struct json_object *jmx_netconfig_wan_batch_preview(struct json_object *payload,
                                                     const char *management_client_ip);
struct json_object *jmx_netconfig_wan_batch_apply(struct json_object *payload,
                                                   const char *management_client_ip);
/* Validate WAN config. Returns JSON array of field errors, or NULL if valid. */
struct json_object *jmx_netconfig_wan_validate(struct json_object *wan_json);

/* LAN CRUD */
struct json_object *jmx_netconfig_lan_list(void);
struct json_object *jmx_netconfig_lan_get(const char *id);
int  jmx_netconfig_lan_set(struct json_object *lan_json);
int  jmx_netconfig_lan_set_enabled(const char *id, int enabled);
int  jmx_netconfig_lan_delete(const char *id);
struct json_object *jmx_netconfig_lan_save_apply_result(struct json_object *lan_json);
struct json_object *jmx_netconfig_lan_delete_result(const char *id,
                                                     const char *management_client_ip);
struct json_object *jmx_netconfig_lan_batch_preview(struct json_object *payload,
                                                     const char *management_client_ip);
struct json_object *jmx_netconfig_lan_batch_apply(struct json_object *payload,
                                                   const char *management_client_ip);
int  jmx_netconfig_lan_set_ports(const char *id, struct json_object *ports_json);
/* Validate LAN config. Returns JSON array of field errors, or NULL if valid. */
struct json_object *jmx_netconfig_lan_validate(struct json_object *lan_json);

/* Global config */
struct json_object *jmx_netconfig_global_get(void);

/* Network overview — combines global + WAN summary + LAN summary */
struct json_object *jmx_netconfig_network_overview(void);
int  jmx_netconfig_global_set(struct json_object *global_json);
int  jmx_netconfig_global_apply(void);

/* Physical port cache */
struct json_object *jmx_netconfig_physical_port_list(void);
int  jmx_netconfig_physical_port_refresh(void);
struct json_object *jmx_netconfig_physical_port_config_get(const char *ifname);
struct json_object *jmx_netconfig_physical_port_config_apply(struct json_object *cfg);
int  jmx_netconfig_physical_port_apply_saved_all(void);
struct json_object *jmx_netconfig_physical_port_profile_list(void);
struct json_object *jmx_netconfig_physical_port_profile_get(const char *id);
struct json_object *jmx_netconfig_physical_port_profile_set(struct json_object *cfg);
struct json_object *jmx_netconfig_physical_port_profile_delete(const char *id);
struct json_object *jmx_netconfig_gateway_ports_get(void);
struct json_object *jmx_netconfig_gateway_ports_preview(struct json_object *payload);
struct json_object *jmx_netconfig_gateway_ports_apply(struct json_object *payload);

/* RADIUS servers */
struct json_object *jmx_netconfig_radius_list(void);
int  jmx_netconfig_radius_set(struct json_object *radius_json);
int  jmx_netconfig_radius_delete(const char *id);

/* Hybrid WAN sub-lines */
struct json_object *jmx_netconfig_hybrid_line_list(const char *parent_wan_id);
int  jmx_netconfig_hybrid_line_set(struct json_object *line_json);
int  jmx_netconfig_hybrid_line_delete(const char *id);
int  jmx_netconfig_hybrid_line_enable(const char *id, int enabled);
int  jmx_netconfig_apply_hybrid_line(const char *id);


/* DHCP Service */
struct json_object *jmx_dhcp_service_get(void);
int  jmx_dhcp_service_set(struct json_object *cfg);
int  jmx_dhcp_reservation_delete(const char *id);
int  jmx_dhcp_reservation_delete_resolve(const char *id, char *lan_id, size_t lan_id_len);
int  jmx_dhcp_service_apply(const char *lan_id);

/* UPnP IGD / miniupnpd */
struct json_object *jmx_upnp_service_get(void);
int  jmx_upnp_service_set(struct json_object *cfg);
int  jmx_upnp_acl_set(struct json_object *acl);
int  jmx_upnp_acl_delete(const char *id);
int  jmx_upnp_mapping_delete(const char *id);
int  jmx_upnp_service_apply(void);
/* Static mapping dataplane (independent nft table, see jmx_netconfig_db.c) */
struct json_object *jmx_upnp_static_status(void);
int  jmx_upnp_static_apply(void);
struct json_object *jmx_upnp_service_save_apply_result(struct json_object *cfg);
struct json_object *jmx_upnp_acl_save_apply_result(struct json_object *acl);
struct json_object *jmx_upnp_acl_delete_apply_result(const char *id);






/* Firewall service */
struct json_object *jmx_firewall_service_get(void);
int  jmx_firewall_service_set(struct json_object *cfg);
struct json_object *jmx_firewall_service_apply(struct json_object *cfg);

/* Geo-Block */
struct json_object *jmx_geo_block_get(void);
int jmx_geo_block_set(struct json_object *cfg);
struct json_object *jmx_geo_block_update(struct json_object *cfg);

/* Plugins */
struct json_object *jmx_plugins_list(void);
int jmx_plugin_action(const char *id, const char *action);

/* Flow control / policy routing / QoS */
struct json_object *jmx_flow_control_get(void);
int  jmx_flow_control_set(struct json_object *cfg);
struct json_object *jmx_flow_control_apply(struct json_object *cfg);
struct json_object *jmx_flow_control_rule_test(struct json_object *cfg);
int  jmx_flow_control_smart_set(struct json_object *cfg);
int  jmx_flow_control_priority_set(struct json_object *cfg);
int  jmx_flow_control_group_carrier_set(struct json_object *cfg);
char *jmx_netconfig_wan_csv(size_t *out_len);
char *jmx_netconfig_lan_csv(size_t *out_len);

/* AI history */
#define JMX_AI_HISTORY_DELETE_OK 0
#define JMX_AI_HISTORY_DELETE_NOT_FOUND 1
struct json_object *jmx_ai_history_list(int limit, int offset);
struct json_object *jmx_ai_history_get(const char *id);
struct json_object *jmx_ai_history_save(struct json_object *req);
int  jmx_ai_history_delete(const char *id);
int  jmx_ai_history_clear(void);

/* VPN config */
struct json_object *jmx_vpn_config_get(void);
int  jmx_vpn_config_set(struct json_object *cfg);
struct json_object *jmx_vpn_config_apply(struct json_object *cfg);
int  jmx_vpn_server_set(struct json_object *cfg);
int  jmx_vpn_client_set(struct json_object *cfg);
int  jmx_vpn_site_set(struct json_object *cfg);
int  jmx_vpn_account_set(struct json_object *cfg);
int  jmx_vpn_certificate_set(struct json_object *cfg);


/* Bulk IP / IPAM */
struct json_object *jmx_bulk_ip_get(void);
struct json_object *jmx_upnp_mappings_list(void);
int  jmx_upnp_mapping_set(struct json_object *cfg);
/* Same as jmx_upnp_mapping_set(), but reports the port's current listener so
 * the caller can name the blocker. Return codes documented at the definition. */
int  jmx_upnp_mapping_set_ex(struct json_object *cfg, char *owner, size_t owner_len);
struct json_object *jmx_routing_static_routes_list(void);
int  jmx_routing_static_route_set(struct json_object *cfg);
int  jmx_routing_static_route_delete(const char *id);
struct json_object *jmx_routing_policy_rules_list(void);
int  jmx_routing_policy_rule_set(struct json_object *cfg);
int  jmx_routing_policy_rule_delete(const char *id);
struct json_object *jmx_routing_tables_list(void);
int  jmx_routing_table_set(struct json_object *cfg);
int  jmx_routing_table_delete(const char *id);
int  jmx_bulk_ip_reserve(struct json_object *cfg);
int  jmx_bulk_ip_delete(const char *id);
struct json_object *jmx_flow_rules_list(void);
int  jmx_flow_rule_set(struct json_object *cfg);
int  jmx_flow_rule_delete(const char *id);
int  jmx_flow_client_limit_save(struct json_object *cfg);
struct json_object *jmx_multicast_service_get(void);
int  jmx_bulk_ip_set(struct json_object *cfg);
struct json_object *jmx_bulk_ip_import(struct json_object *cfg);
struct json_object *jmx_bulk_ip_export(struct json_object *cfg);
struct json_object *jmx_network_control_apply(struct json_object *cfg);
struct json_object *jmx_signature_db_status(struct json_object *cfg);
struct json_object *jmx_netconfig_wan_status(const char *id);
struct json_object *jmx_netconfig_bond_status(const char *wan_id);
struct json_object *jmx_netconfig_capabilities(void);
struct json_object *jmx_dns_service_get(void);
int jmx_dns_service_set(struct json_object *cfg);
int jmx_dns_upstream_set(struct json_object *u);
int jmx_dns_service_save_apply(struct json_object *payload, int apply);
struct json_object *jmx_dns_service_save_apply_result(struct json_object *payload, int apply);
int jmx_dns_rule_set(struct json_object *r);
int jmx_dns_rule_delete(const char *id);
int jmx_dns_service_apply(void);
struct json_object *jmx_wan_dns_policy_get(const char *wan_id);
int jmx_wan_dns_policy_set(const char *wan_id, struct json_object *cfg);
struct json_object *jmx_wan_dns_policy_save_apply_result(const char *wan_id,
                                                          struct json_object *cfg);
int jmx_wan_dns_split_save_from_array(struct json_object *wan_dns_arr);
int jmx_wan_dns_policy_delete(int policy_id);
struct json_object *jmx_wan_dns_policy_delete_apply_result(int policy_id);
int jmx_netconfig_apply_wan(const char *id);
int jmx_netconfig_apply_lan(const char *id);
int jmx_multicast_service_set(struct json_object *cfg);
int jmx_multicast_service_apply(int dry_run);
struct json_object *jmx_cellular_service_get(void);
int jmx_cellular_service_set(struct json_object *cfg);
int jmx_cellular_slot_set(struct json_object *cfg);
int jmx_cellular_slot_delete(const char *id);
int jmx_cellular_apn_profile_set(struct json_object *cfg);
int jmx_cellular_apn_profile_delete(const char *id);
int jmx_cellular_sms_delete(const char *id);
int jmx_cellular_service_apply(int dry_run);
struct json_object *jmx_wifi_config_get(void);
int jmx_wifi_config_save(struct json_object *cfg);
struct json_object *jmx_wifi_config_apply(struct json_object *cfg);
struct json_object *jmx_wifi_status_get(void);
struct json_object *jmx_wifi_scan(struct json_object *cfg);

/* First-run setup wizard */
struct json_object *jmx_setup_status(struct json_object *cfg);
struct json_object *jmx_setup_start(struct json_object *cfg);
struct json_object *jmx_setup_save_device(struct json_object *cfg);
struct json_object *jmx_setup_save_wan(struct json_object *cfg);
struct json_object *jmx_setup_test_wan(struct json_object *cfg);
struct json_object *jmx_setup_save_lan(struct json_object *cfg);
struct json_object *jmx_setup_save_wifi(struct json_object *cfg);
struct json_object *jmx_setup_apply(struct json_object *cfg);
struct json_object *jmx_setup_progress(struct json_object *cfg);
struct json_object *jmx_setup_finish(struct json_object *cfg);
struct json_object *jmx_setup_reset_wizard(struct json_object *cfg);
struct json_object *jmx_setup_support_bundle(struct json_object *cfg);
struct json_object *jmx_setup_detect_wan_start(struct json_object *cfg);
struct json_object *jmx_setup_detect_wan_status(struct json_object *cfg);
struct json_object *jmx_setup_assist_mode(struct json_object *cfg);
struct json_object *jmx_setup_security_ssh_set(struct json_object *cfg);

struct json_object *jmx_advanced_routing_get(void);
int jmx_advanced_routing_set(struct json_object *cfg);
struct json_object *jmx_advanced_routing_apply(struct json_object *cfg);
struct json_object *jmx_advanced_routing_status(void);
struct json_object *jmx_custom_config_get(void);
int jmx_custom_config_save(struct json_object *cfg);
struct json_object *jmx_custom_config_apply(struct json_object *cfg);
struct json_object *jmx_custom_config_status(void);
struct json_object *jmx_network_control_get(void);
int jmx_network_control_save(struct json_object *cfg);
struct json_object *jmx_rulesd_config_get(void);
struct json_object *jmx_rulesd_config_migrate(struct json_object *cfg);
struct json_object *jmx_aegis_app_blocks(struct json_object *cfg);
struct json_object *jmx_aegis_app_block_validate(struct json_object *cfg);
struct json_object *jmx_aegis_app_block_upsert(struct json_object *cfg);
struct json_object *jmx_aegis_app_block_delete(struct json_object *cfg);
int jmx_network_control_rules_bulk_delete(struct json_object *cfg);
struct json_object *jmx_network_control_status(void);
struct json_object *jmx_network_control_rule_test(struct json_object *cfg);

/* Client rate limit helpers */
int nc_client_rate_limit_set(const char *mac, const char *ip,
                              int upload_kbps, int download_kbps,
                              const char *remark);
int nc_client_rate_limit_set_ex(const char *mac, const char *ip,
                                 int upload_kbps, int download_kbps,
                                 const char *protocol, const char *remark);
int nc_client_rate_limit_delete(const char *mac);
int jmx_client_control_schedule_tick(void);
struct json_object *jmx_log_center_get(void);
struct json_object *jmx_log_center_query(struct json_object *cfg);
struct json_object *jmx_log_center_export(struct json_object *cfg);
struct json_object *jmx_log_center_clear(struct json_object *cfg);
struct json_object *jmx_log_center_mark_read(struct json_object *cfg);
int jmx_log_center_syslog_set(struct json_object *cfg);
int jmx_log_center_settings_set(struct json_object *cfg);
struct json_object *jmx_log_center_event_add(struct json_object *cfg);
int jmx_log_center_warning_rules_set(struct json_object *cfg);
struct json_object *jmx_log_center_warning_rules_get(void);
struct json_object *jmx_log_center_event_search(struct json_object *cfg);
struct json_object *jmx_log_center_alarm_get(struct json_object *cfg);
struct json_object *jmx_log_center_prune(struct json_object *cfg);
struct json_object *jmx_log_center_delivery_replay(struct json_object *cfg);
struct json_object *jmx_log_center_alarm_summary(struct json_object *cfg);
struct json_object *jmx_log_center_alarm_update(struct json_object *cfg);
struct json_object *jmx_log_center_delivery_get(struct json_object *cfg);
struct json_object *jmx_log_center_delivery_update(struct json_object *cfg);
int jmx_log_center_channels_set(struct json_object *cfg);
struct json_object *jmx_log_center_channels_get(void);
struct json_object *jmx_log_center_delivery_claim(struct json_object *cfg);
struct json_object *jmx_log_center_delivery_stats(void);
struct json_object *jmx_system_settings_get(void);
int jmx_system_settings_set(struct json_object *cfg);
int jmx_system_settings_apply(struct json_object *cfg);
struct json_object *jmx_system_settings_save_apply_result(struct json_object *cfg);
struct json_object *jmx_system_settings_apply_result(struct json_object *cfg);
struct json_object *jmx_system_settings_draft_apply(struct json_object *cfg);
struct json_object *jmx_flash_factory_reset(struct json_object *cfg);
struct json_object *jmx_flash_preserve_config_get(struct json_object *cfg);
struct json_object *jmx_flash_preserve_config_set(struct json_object *cfg);
int jmx_system_cron_set(struct json_object *cfg);
struct json_object *jmx_system_service_set(struct json_object *cfg);
struct json_object *jmx_system_disabled_functions_get(void);
struct json_object *jmx_system_disabled_functions_set(struct json_object *cfg);
struct json_object *jmx_system_services_status(struct json_object *cfg);
struct json_object *jmx_system_mounts_status(struct json_object *cfg);
struct json_object *jmx_system_cron_get(struct json_object *cfg);
struct json_object *jmx_wifi_capabilities_get(struct json_object *cfg);
struct json_object *jmx_cellular_runtime_status(struct json_object *cfg);
struct json_object *jmx_runtime_pending_matrix(struct json_object *cfg);
struct json_object *jmx_jmxd_phase_summary(struct json_object *cfg);
struct json_object *jmx_signature_db_apps(struct json_object *cfg);
struct json_object *jmx_signature_db_rules(struct json_object *cfg);
struct json_object *jmx_signature_db_carriers(struct json_object *cfg);
struct json_object *jmx_signature_db_carrier_prefixes(struct json_object *cfg);
struct json_object *jmx_signature_db_domain_groups(struct json_object *cfg);
struct json_object *jmx_signature_db_domains(struct json_object *cfg);
struct json_object *jmx_signature_db_device_vendors(struct json_object *cfg);
struct json_object *jmx_signature_db_device_types(struct json_object *cfg);
struct json_object *jmx_signature_db_fingerprint_rules(struct json_object *cfg);
int jmx_signature_db_fill_app_meta(struct json_object *obj, int app_id);
int jmx_signature_db_open(sqlite3 **db);
void jmx_signature_db_close(sqlite3 *db);
int jmx_signature_db_resolve_host_app_id_with_db(sqlite3 *db, const char *host,
                                                 const char *proto,
                                                 int dst_port, int *app_id);
int jmx_signature_db_resolve_host_app_id(const char *host, const char *proto,
                                         int dst_port, int *app_id);
struct json_object *jmx_signature_db_resolve_app(struct json_object *cfg);
struct json_object *jmx_ai_conversations_list(void);
struct json_object *jmx_ai_conversation_get(const char *id);
int jmx_ai_conversation_save(struct json_object *cfg);
int jmx_ai_conversation_delete(const char *id);

/* AI Config */
struct json_object *jmx_ai_config_get(void);
int jmx_ai_config_set(struct json_object *cfg);
struct json_object *jmx_ai_models_get(void);
struct json_object *jmx_ai_tools_get(void);
int jmx_ai_tool_authorize(int auth_id, int approve, const char *role);
struct json_object *jmx_ai_tool_authorization_resolve(int auth_id, int approve,
                                                      const char *actor,
                                                      const char *role);
struct json_object *jmx_ai_chat(struct json_object *req);
struct json_object *jmx_ai_tool_call(struct json_object *req);
struct json_object *jmx_ai_tool_authorizations_list(void);
struct json_object *jmx_ai_tool_authorizations_get(const char *conversation_id);
struct json_object *jmx_bulk_ip_get_v2(void);
int jmx_crontab_apply_text(const char *text, struct json_object *out);
int jmx_system_time_sync_browser(int64_t client_ts, struct json_object *out);
int jmx_system_time_sync_ntp(struct json_object *out);
struct json_object *jmx_system_startup_service_action(struct json_object *req);
int jmx_system_rc_local_apply(const char *content, int confirm_no_exit0, struct json_object *out);
int jmx_admin_password_set(struct json_object *req, struct json_object *out);
int jmx_admin_password_set_ex(struct json_object *req, struct json_object *out,
                              int create_if_missing);
int jmx_admin_rename(struct json_object *req, struct json_object *out);
int jmx_admin_avatar_set(struct json_object *req, struct json_object *out);
struct json_object *jmx_system_kernel_restore_defaults(struct json_object *cfg);
struct json_object *jmx_system_cpu_interrupt_get(void);
int jmx_system_cpu_interrupt_set(struct json_object *cfg, struct json_object *out);
int jmx_system_ssh_idle_timeout_set(struct json_object *cfg, struct json_object *out);

/* ═══ Container Service ═══ */
struct json_object *jmx_container_service_get(void);
struct json_object *jmx_container_docker_get(void);
struct json_object *jmx_container_lxc_get(void);

/* Docker operations */
int jmx_docker_container_start(const char *id, struct json_object *out);
int jmx_docker_container_stop(const char *id, struct json_object *cfg, struct json_object *out);
int jmx_docker_container_restart(const char *id, struct json_object *cfg, struct json_object *out);
int jmx_docker_container_pause(const char *id, struct json_object *out);
int jmx_docker_container_unpause(const char *id, struct json_object *out);
int jmx_docker_container_remove(const char *id, struct json_object *cfg, struct json_object *out);
int jmx_docker_container_rename(const char *id, struct json_object *cfg, struct json_object *out);
int jmx_docker_container_restart_policy(const char *id, struct json_object *cfg, struct json_object *out);
struct json_object *jmx_docker_container_logs(const char *id, struct json_object *cfg);
struct json_object *jmx_docker_container_stats(const char *id);
int jmx_docker_container_create(struct json_object *cfg, struct json_object *out);

/* Docker image operations */
int jmx_docker_image_pull(struct json_object *cfg, struct json_object *out);
int jmx_docker_image_remove(const char *id, struct json_object *cfg, struct json_object *out);
struct json_object *jmx_docker_image_prune(struct json_object *cfg);
struct json_object *jmx_docker_jobs_list(struct json_object *cfg);
struct json_object *jmx_docker_job_get(const char *id);
int jmx_docker_job_cancel(const char *id, struct json_object *cfg,
                          struct json_object *out);
int jmx_docker_job_worker(const char *id);
void jmx_docker_jobs_reap_workers(void);

/* Docker network operations */
int jmx_docker_network_create(struct json_object *cfg, struct json_object *out);
int jmx_docker_network_remove(const char *id, struct json_object *cfg, struct json_object *out);
struct json_object *jmx_docker_network_prune(struct json_object *cfg);

/* Docker volume operations */
int jmx_docker_volume_create(struct json_object *cfg, struct json_object *out);
int jmx_docker_volume_remove(const char *name, struct json_object *cfg, struct json_object *out);
struct json_object *jmx_docker_volume_prune(struct json_object *cfg);

/* Docker service operations */
struct json_object *jmx_docker_service_status(void);
int jmx_docker_service_action(const char *action, struct json_object *out);

/* Docker config */
struct json_object *jmx_docker_config_get(void);
int jmx_docker_config_set(struct json_object *cfg, struct json_object *out);

/* LXC operations */
int jmx_lxc_container_start(const char *name, struct json_object *out);
int jmx_lxc_container_stop(const char *name, struct json_object *cfg, struct json_object *out);
int jmx_lxc_container_restart(const char *name, struct json_object *cfg, struct json_object *out);
int jmx_lxc_container_destroy(const char *name, struct json_object *cfg, struct json_object *out);
int jmx_lxc_container_create(struct json_object *cfg, struct json_object *out);
int jmx_lxc_container_clone(const char *name, struct json_object *cfg, struct json_object *out);
int jmx_lxc_container_snapshot(const char *name, struct json_object *cfg, struct json_object *out);
int jmx_lxc_container_snapshot_restore(const char *name, const char *snap, struct json_object *cfg, struct json_object *out);
struct json_object *jmx_lxc_container_config_get(const char *name);
int jmx_lxc_container_config_set(const char *name, struct json_object *cfg, struct json_object *out);
struct json_object *jmx_lxc_config_get(void);
int jmx_lxc_config_set(struct json_object *cfg, struct json_object *out);
struct json_object *jmx_lxc_templates_get(void);
struct json_object *jmx_lxc_container_stats(const char *name);
struct json_object *jmx_lxc_container_processes(const char *name);
struct json_object *jmx_lxc_container_logs(const char *name, struct json_object *cfg);

/* JSON helpers */
const char *nc_json_str(struct json_object *o, const char *k, const char *def);
const char *nc_json_str_def(struct json_object *o, const char *k, const char *def);
int nc_json_int_def(struct json_object *o, const char *k, int def);
int nc_json_bool_def(struct json_object *o, const char *k, int def);
int nc_exec(const char *sql);
int nc_prepare(sqlite3_stmt **st, const char *sql);
int nc_step_done(sqlite3_stmt *st);
int nc_sqlite_changes(void);
sqlite3_int64 nc_sqlite_last_insert_rowid(void);
void nc_add_text(struct json_object *o, const char *key, sqlite3_stmt *st, int col);
const char *nc_sql_text(sqlite3_stmt *st, int col);
int64_t nc_now_s(void);

/* Shared helpers used by split netconfig source files. */
int nc_abs_path_ok(const char *s);
int nc_safe_id_ok(const char *s);
int nc_valid_name(const char *s);
int nc_iface_name_ok(const char *s);
int nc_file_exists(const char *path);
int nc_ipv4_ok(const char *ip);
int nc_cidr_ok(const char *cidr);
int nc_cmd_exists(const char *cmd);
int nc_run_quiet(const char *cmd);
void nc_dhcp_refresh_leases(void);
int nc_copy_file(const char *src, const char *dst);
int nc_safe_simple_command_ok(const char *s);
int nc_backup_config(const char *pkg, char *bak, size_t bak_len);
void nc_restore_config(const char *pkg, const char *bak);
void nc_cleanup_backup(const char *bak);
int nc_sig_open(sqlite3 **db);
int nc_vpn_count_table(const char *table, const char *where);
char *nc_cmd_output(const char *cmd, int max_len);
char *nc_cmd_output_status(const char *cmd, int max_len, int *status);
struct json_object *nc_json_array_from_text(const char *txt);
char *nc_json_array_to_string(struct json_object *o, const char *def);
char *nc_sys_read_file_text(const char *path, size_t max_bytes);
char *nc_sys_read_file_tail_text(const char *path, size_t max_bytes, int tail_lines);
void nc_write_uci_section(FILE *fp, const char *type, const char *name);
void nc_write_uci_anonymous_section(FILE *fp, const char *type);
void nc_write_uci_option(FILE *fp, const char *name, const char *value);
void nc_write_uci_list(FILE *fp, const char *name, const char *value);
int nc_uci_set_pkg(struct uci_context *ctx, const char *pkg_name,
                   const char *section, const char *option,
                   const char *value);
int nc_uci_delete_pkg(struct uci_context *ctx, const char *pkg_name,
                      const char *section, const char *option);
int nc_uci_add_list_pkg(struct uci_context *ctx, const char *pkg_name,
                        const char *section, const char *option,
                        const char *value);
int nc_uci_ensure_section(struct uci_context *ctx, struct uci_package *pkg,
                          const char *pkg_name, const char *section,
                          const char *type);
void nc_uci_delete_managed_sections(struct uci_context *ctx, struct uci_package *pkg,
                                    const char *pkg_name, const char *type,
                                    const char *prefix);
#endif
