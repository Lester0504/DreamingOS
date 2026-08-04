# ── dreamingwrt-core: DreamingWrt core control-plane daemon ───────────
#
# Object files (26):
#   main, user, common, config, ubus, netlink, utils, db, network, system
#   app_filter, mac_filter
#   dreamingwrt_api, netconfig_db, work_mode
#   rule, signature_db, proto_decode
#   nl_push, regex, regex_netlink, audit
#   domain, hosttype, route, events
#
# Required libraries (via LIBS from OpenWrt package Makefile):
#   libjmx_common      UCI helper wrappers (jmx_uci_*)
#   libubus             ubus IPC framework
#   libubox             blobmsg, uloop, list, utils
#   libblobmsg_json     blobmsg <-> JSON
#   libjson-c           JSON parsing/generation
#   libsqlite3          SQLite3 embedded database
#   libopenssl (crypto) EVP AES-256-CBC token encryption
#   zlib                compress/decompress (signature DB)
#   libnetfilter_queue  NFQUEUE packet interception
#   libnfnetlink        netfilter netlink
#   libmnl              minimalistic netlink
#   libpcre2-8          regex matching (domain rules)
#   libpthread          thread support
#   librt               clock_gettime (implicit on musl)
#
# System headers:
#   linux/netfilter/nfnetlink_queue.h
#   linux/netfilter.h
#   linux/netlink.h
#   linux/if_packet.h
#   openssl/aes.h, openssl/evp.h
#   pcre2.h
#   sqlite3.h
#   zlib.h
# ──────────────────────────────────────────────────────────────────────

OBJS := jmx_user.o jmx_netlink.o jmx_ubus.o jmx_config.o jmx_utils.o jmx_exec.o main.o
OBJS += jmx_app_filter.o jmx_mac_filter.o jmx_common.o jmx_db.o jmx_huginn.o jmx_dhcp_sniff.o
OBJS += jmx_system.o jmx_network.o
OBJS += jmx_dreamingwrt_api.o jmx_netconfig_db.o jmx_setup.o jmx_dreamingwrt_work_mode.o jmx_gateway_shadow.o
OBJS += jmx_gateway_shadow_pairing.o jmx_gateway_shadow_runtime.o
OBJS += jmx_rule.o jmx_signature_db.o jmx_signature_update.o
OBJS += jmx_proto_decode.o jmx_nl_push.o jmx_regex.o jmx_regex_netlink.o
OBJS += jmx_audit.o jmx_domain.o jmx_hosttype.o routed/jmx_route.o routed/jmx_route_db.o
OBJS += jmx_isp.o
OBJS += jmx_events.o
OBJS += jmx_flow_event.o
OBJS += jmx_topology_history.o
OBJS += client_protocol_history.o
OBJS += webd/webd_mmdb.o
OBJS += storage/storage_overview.o storage/storage_files.o storage/file_services.o storage/storage_blockdev.o
OBJS += system/power.o
OBJS += jmx_storage_guard.o jmx_core_watchdog.o
OBJS += jmx_path_provider.o jmx_system_data_path.o
OBJS += jmx_identification_runtime.o
OBJS += dw_async_query.o

WEBD_OBJS := webd/webd_main.o webd/apid_runtime.o webd/jmx_app_api.o webd/jmx_app_perms.o webd/jmx_app_cache.o webd/webd_http.o webd/webd_static.o webd/webd_mmdb.o webd/webd_upload_staging.o webd/webd_backup_store.o webd/webd_init_control.o webd/webd_wifi_aggregate.o webd/webd_vpn_aggregate.o webd/webd_api_keys.o webd/native_plugins.o webd/terminal_groups.o webd/system_ttyd.o webd/system_ttyd_proxy.o webd/webd_session_idle.o webd/webd_admin_transaction.o webd/ai_runtime.o webd/ai_oauth.o webd/ai_local_rpc.o jmx_path_provider.o jmx_system_data_path.o

HEALTHD_OBJS := healthd/healthd_main.o healthd/check_main.o
IDENTITYD_OBJS := identityd/identityd_main.o identityd/jmx_identity_collector.o identityd/jmx_huginn.o
METRICSD_OBJS := metricsd/metricsd_main.o
MAINTENANCED_OBJS := maintenanced/maintenanced_main.o
ROUTED_OBJS := routed/routed_main.o routed/routed_control.o routed/gateway_ports.o jmx_path_provider.o jmx_system_data_path.o
LOGD_OBJS := logd/logd_main.o logd/logd_common.o logd/logd_db.o logd/logd_event.o logd/logd_collectors.o logd/logd_ubus.o jmx_storage_guard.o
NOTIFYD_OBJS := notifyd/notifyd_main.o notifyd/notifyd_common.o notifyd/notifyd_db.o notifyd/notifyd_delivery.o notifyd/notifyd_ubus.o jmx_storage_guard.o
FLOWD_OBJS := flowd/flowd_main.o flowd/flowd_common.o flowd/flowd_db.o flowd/wan_sla_tx.o flowd/flowd_ubus.o jmx_path_provider.o jmx_system_data_path.o
AUTHD_OBJS := authd/authd_main.o authd/authd_common.o authd/authd_db.o authd/authd_write.o authd/authd_html.o authd/authd_ubus.o
OTAD_OBJS := otad/otad_main.o otad/otad_common.o otad/otad_db.o otad/otad_inventory.o otad/otad_inventory_transaction.o otad/otad_persist_source.o otad/otad_manifest.o otad/otad_trust.o otad/otad_topology.o otad/otad_firmware.o otad/otad_hot.o otad/otad_status.o otad/otad_ubus.o jmx_path_provider.o
AC_OBJS := ac/ac_main.o ac/ac_db.o ac/ac_enrollment.o ac/ac_pki.o ac/ac_secrets.o ac/ac_protocol.o ac/ac_transport.o ac/ac_ubus.o ap_control_wire.o
APD_OBJS := apd/apd_main.o apd/apd_db.o apd/apd_enrollment.o apd/apd_credentials.o apd/apd_protocol.o apd/apd_transport.o apd/apd_backend.o apd/apd_backend_openwrt.o apd/apd_vendor_chanlist.o apd/apd_readonly_command.o apd/apd_radio_job_journal.o apd/apd_config_job_journal.o apd/apd_config_executor.o apd/apd_config_recovery.o apd/apd_ubus.o ap_control_wire.o
AEGISXD_OBJS := aegisxd/aegisxd_main.o aegisxd/aegisxd_common.o aegisxd/aegisxd_db.o aegisxd/aegisxd_status.o aegisxd/aegisxd_feeds.o aegisxd/aegisxd_import.o aegisxd/aegisxd_dataplane.o aegisxd/aegisxd_hits.o aegisxd/aegisxd_honeypot.o aegisxd/aegisxd_content.o aegisxd/aegisxd_certificate.o aegisxd/aegisxd_pcdn.o aegisxd/aegisxd_pcdn_parser.o aegisxd/aegisxd_geo.o aegisxd/aegisxd_signature_policy.o geoip/mmdb_country_prefix.o aegisxd/aegisxd_ubus.o jmx_identification_runtime.o jmx_exec.o
HONEYPOTD_OBJS := honeypotd/main.o honeypotd/runtime.o honeypotd/protocols.o honeypotd/events.o honeypotd/sha256.o
TOOLKIT_OBJS := toolkit/toolkit_main.o toolkit/toolkit_common.o toolkit/toolkit_db.o toolkit/toolkit_ops.o
CLOUD_OBJS := cloud/cloud_main.o cloud/cloud_identity.o cloud/cloud_config.o cloud/cloud_devices.o cloud/cloud_envelope.o cloud/cloud_replay.o cloud/cloud_local.o cloud/cloud_tunnel.o cloud/cloud_enroll.o cloud/cloud_ubus.o
JMCTL_OBJS := ctl/jmctl.o
INIT_OBJS := init/dreamingwrt_init.o init/config_restore.o init/config_migrate.o init/system_db_sync.o jmx_path_provider.o

EXEC := dreamingwrt-core
WEBD_EXEC := dreamingwrt-webd
HEALTHD_EXEC := dreamingwrt-healthd
IDENTITYD_EXEC := dreamingwrt-identityd
METRICSD_EXEC := dreamingwrt-metricsd
MAINTENANCED_EXEC := dreamingwrt-maintenanced
ROUTED_EXEC := dreamingwrt-routed
LOGD_EXEC := dreamingwrt-logd
NOTIFYD_EXEC := dreamingwrt-notifyd
FLOWD_EXEC := dreamingwrt-flowd
AUTHD_EXEC := dreamingwrt-authd
OTAD_EXEC := dreamingwrt-otad
AC_EXEC := dreamingwrt-ac
APD_EXEC := dreamingwrt-apd
AEGISXD_EXEC := dreamingwrt-aegisxd
HONEYPOTD_EXEC := dreamingwrt-honeypotd
TOOLKIT_EXEC := dreamingwrt-toolkit
CLOUD_EXEC := dreamingos-cloud
JMCTL_EXEC := jmctl
INIT_EXEC := dreamingwrt-init

CFLAGS += -Wall -Wno-unused-parameter -I. -Irouted

WEBD_LIBS ?= $(LIBS)
HEALTHD_LIBS ?=
IDENTITYD_LIBS ?= -lubus -lubox -lblobmsg_json -ljson-c -lsqlite3 -lz
METRICSD_LIBS ?=
MAINTENANCED_LIBS ?=
ROUTED_LIBS ?= -lubus -lubox -lblobmsg_json -ljson-c -lsqlite3 -luci
LOGD_LIBS ?= -lssl -lcrypto
NOTIFYD_LIBS ?=
FLOWD_LIBS ?=
AUTHD_LIBS ?= -lubus -lubox -lblobmsg_json -ljson-c -lsqlite3 -lssl -lcrypto -lxml2 -liconv -lm
AUTHD_CFLAGS ?=
OTAD_LIBS ?= -lubus -lubox -lblobmsg_json -ljson-c -lsqlite3 -lblkid -lssl -lcrypto -lz -lm
AC_LIBS ?= -lubus -lubox -lblobmsg_json -ljson-c -lsqlite3 -lssl -lcrypto -lpthread
APD_LIBS ?= -lubus -lubox -lblobmsg_json -ljson-c -lsqlite3 -luci -lssl -lcrypto -lm -lpthread
AEGISXD_LIBS ?= -lssl -lcrypto -lmaxminddb
HONEYPOTD_LIBS ?= -lubus -lubox -lblobmsg_json -ljson-c
TOOLKIT_LIBS ?= -ljson-c -lsqlite3 -lcurl -lssl -lcrypto
CLOUD_LIBS ?= -lubus -lubox -lblobmsg_json -ljson-c -lsqlite3 -luci -lssl -lcrypto -lpthread
JMCTL_LIBS ?= -lubus -lubox -lblobmsg_json -ljson-c
INIT_LIBS ?= -lsqlite3 -lcrypto

all: $(EXEC) $(WEBD_EXEC) $(HEALTHD_EXEC) $(IDENTITYD_EXEC) $(METRICSD_EXEC) $(MAINTENANCED_EXEC) $(ROUTED_EXEC) $(LOGD_EXEC) $(NOTIFYD_EXEC) $(FLOWD_EXEC) $(AUTHD_EXEC) $(OTAD_EXEC) $(AC_EXEC) $(APD_EXEC) $(AEGISXD_EXEC) $(HONEYPOTD_EXEC) $(TOOLKIT_EXEC) $(CLOUD_EXEC) $(JMCTL_EXEC) $(INIT_EXEC)

$(EXEC): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

$(WEBD_EXEC): $(WEBD_OBJS)
	$(CC) -o $@ $(WEBD_OBJS) $(WEBD_LIBS)

$(HEALTHD_EXEC): $(HEALTHD_OBJS)
	$(CC) -o $@ $(HEALTHD_OBJS) $(HEALTHD_LIBS)

$(IDENTITYD_EXEC): $(IDENTITYD_OBJS)
	$(CC) -o $@ $(IDENTITYD_OBJS) $(IDENTITYD_LIBS)

$(METRICSD_EXEC): $(METRICSD_OBJS)
	$(CC) -o $@ $(METRICSD_OBJS) $(METRICSD_LIBS)

$(MAINTENANCED_EXEC): $(MAINTENANCED_OBJS)
	$(CC) -o $@ $(MAINTENANCED_OBJS) $(MAINTENANCED_LIBS)

$(ROUTED_EXEC): $(ROUTED_OBJS)
	$(CC) -o $@ $(ROUTED_OBJS) $(ROUTED_LIBS)

$(LOGD_EXEC): $(LOGD_OBJS)
	$(CC) -o $@ $(LOGD_OBJS) $(LOGD_LIBS)

$(NOTIFYD_EXEC): $(NOTIFYD_OBJS)
	$(CC) -o $@ $(NOTIFYD_OBJS) $(NOTIFYD_LIBS)

$(FLOWD_EXEC): $(FLOWD_OBJS)
	$(CC) -o $@ $(FLOWD_OBJS) $(FLOWD_LIBS)

$(AUTHD_EXEC): $(AUTHD_OBJS)
	$(CC) -o $@ $(AUTHD_OBJS) $(AUTHD_LIBS)

authd/authd_html.o: authd/authd_html.c
	$(CC) $(CFLAGS) $(AUTHD_CFLAGS) -c -o $@ $<

$(OTAD_EXEC): $(OTAD_OBJS)
	$(CC) -o $@ $(OTAD_OBJS) $(OTAD_LIBS)

$(AC_EXEC): $(AC_OBJS)
	$(CC) -o $@ $(AC_OBJS) $(AC_LIBS)

$(APD_EXEC): $(APD_OBJS)
	$(CC) -o $@ $(APD_OBJS) $(APD_LIBS)

$(AEGISXD_EXEC): $(AEGISXD_OBJS)
	$(CC) -o $@ $(AEGISXD_OBJS) $(AEGISXD_LIBS)

$(HONEYPOTD_EXEC): $(HONEYPOTD_OBJS)
	$(CC) -o $@ $(HONEYPOTD_OBJS) $(HONEYPOTD_LIBS)

$(TOOLKIT_EXEC): $(TOOLKIT_OBJS)
	$(CC) -o $@ $(TOOLKIT_OBJS) $(TOOLKIT_LIBS)

$(CLOUD_EXEC): $(CLOUD_OBJS)
	$(CC) -o $@ $(CLOUD_OBJS) $(CLOUD_LIBS)

$(JMCTL_EXEC): $(JMCTL_OBJS)
	$(CC) -o $@ $(JMCTL_OBJS) $(JMCTL_LIBS)

$(INIT_EXEC): $(INIT_OBJS)
	$(CC) -o $@ $(INIT_OBJS) $(INIT_LIBS)

clean:
	-rm -f $(EXEC) $(WEBD_EXEC) $(HEALTHD_EXEC) $(IDENTITYD_EXEC) $(METRICSD_EXEC) $(MAINTENANCED_EXEC) $(ROUTED_EXEC) $(LOGD_EXEC) $(NOTIFYD_EXEC) $(FLOWD_EXEC) $(AUTHD_EXEC) $(OTAD_EXEC) $(AC_EXEC) $(APD_EXEC) $(AEGISXD_EXEC) $(HONEYPOTD_EXEC) $(TOOLKIT_EXEC) $(CLOUD_EXEC) $(JMCTL_EXEC) $(INIT_EXEC) jmxd webd/dreamingwrt-webd *.o webd/*.o healthd/*.o identityd/*.o metricsd/*.o maintenanced/*.o routed/*.o logd/*.o notifyd/*.o flowd/*.o authd/*.o otad/*.o ac/*.o apd/*.o aegisxd/*.o geoip/*.o honeypotd/*.o toolkit/*.o cloud/*.o ctl/*.o init/*.o dreamingwrt-*.bak-* webd/dreamingwrt-*.bak-*
