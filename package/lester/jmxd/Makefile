include $(TOPDIR)/rules.mk

PKG_NAME:=dreamingwrt-core
PKG_VERSION:=12.05.17
PKG_RELEASE:=23
PKG_MAINTAINER:=DreamingOS contributors
PKG_LICENSE:=GPL-2.0-only

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
PKG_BUILD_DEPENDS:=libmaxminddb

include $(INCLUDE_DIR)/package.mk

# Release builds are the default on routers.  Set JMXD_DEBUG=1 explicitly
# when full symbols, frame pointers and disabled inlining are needed.
JMXD_DEBUG ?= 0
DREAMINGWRT_FLOWD_BUNDLE_GEOIP ?= 0
DREAMINGWRT_FLOWD_GEOIP_URL ?= https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb
DREAMINGWRT_FLOWD_GEOIP_FILE := $(DL_DIR)/dreamingwrt-geolite2-country.mmdb
DREAMINGWRT_FLOWD_BUNDLE_GEOIP_CITY ?= 0
DREAMINGWRT_FLOWD_GEOIP_CITY_URL ?= https://git.io/GeoLite2-City.mmdb
DREAMINGWRT_FLOWD_GEOIP_CITY_FILE := $(DL_DIR)/dreamingwrt-geolite2-city.mmdb
DREAMINGWRT_FLOWD_GEOIP_MARKER := abcdef4d61784d696e642e636f6d
DREAMINGWRT_AEGISXD_WITH_SURICATA ?= 0
ifneq ($(CONFIG_DREAMINGWRT_AEGISXD_WITH_SURICATA),)
DREAMINGWRT_AEGISXD_WITH_SURICATA:=$(if $(filter y 1,$(CONFIG_DREAMINGWRT_AEGISXD_WITH_SURICATA)),1,0)
endif
ifneq ($(CONFIG_DREAMINGWRT_FLOWD_BUNDLE_GEOIP),)
DREAMINGWRT_FLOWD_BUNDLE_GEOIP:=$(if $(filter y 1,$(CONFIG_DREAMINGWRT_FLOWD_BUNDLE_GEOIP)),1,0)
endif
ifneq ($(CONFIG_DREAMINGWRT_FLOWD_BUNDLE_GEOIP_CITY),)
DREAMINGWRT_FLOWD_BUNDLE_GEOIP_CITY:=$(if $(filter y 1,$(CONFIG_DREAMINGWRT_FLOWD_BUNDLE_GEOIP_CITY)),1,0)
endif

TARGET_CFLAGS += -Werror=implicit-function-declaration
TARGET_CFLAGS += -DJMX_CROND_SPECIAL_TIMES=$(if $(filter y,$(CONFIG_BUSYBOX_CONFIG_FEATURE_CROND_SPECIAL_TIMES)),1,0)

ifeq ($(JMXD_DEBUG),1)
RSTRIP:=:
TARGET_CFLAGS += -g3 -ggdb3 -Og -fno-omit-frame-pointer -fno-inline -fno-optimize-sibling-calls
TARGET_LDFLAGS += -Wl,--build-id
endif

# ── dreamingwrt-core daemon ───────────────────────────────────────────
#
# Dependency tree (transitive deps satisfied by OpenWrt automatically):
#
#   dreamingwrt-core
#   ├── libjmx_common        (UCI helper wrappers: jmx_uci_*)
#   │   ├── libuci            (UCI config framework)
#   │   └── libjson-c         (JSON parsing)
#   ├── libubus               (IPC: ubus_register_object / ubus_invoke)
#   │   └── libubox           (uloop, blobmsg, utils, list)
#   ├── libblobmsg_json       (blobmsg <-> JSON conversion)
#   │   ├── libubox
#   │   └── libjson-c
#   ├── libsqlite3            (embedded SQL database for all state)
#   ├── libopenssl            (EVP AES-256-CBC for token encryption)
#   │   └── zlib              (compression support)
#   ├── libnetfilter_queue    (NFQUEUE packet interception for flow mirror)
#   │   └── libnfnetlink
#   │       └── libmnl        (minimal netlink library)
#   ├── pcre2-libpcre2-8      (regex matching for domain rules)
#   ├── libpthread            (threads: identity collector, sniff)
#   └── librt                 (clock_gettime — implicit on musl)
#
# Header-only usage:
#   linux/netfilter/nfnetlink_queue.h
#   linux/netlink.h
#   linux/if_packet.h
#   openssl/aes.h openssl/evp.h
#   pcre2.h
#   sqlite3.h
#   zlib.h
# ──────────────────────────────────────────────────────────────────────

define Package/dreamingwrt-core
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt core control-plane daemon
  DEPENDS:=+libjmx_common \
           +libubox +libubus +libblobmsg-json \
           +libuci +libjson-c \
           +libsqlite3 \
           +libopenssl +zlib \
           +libnetfilter-queue +libnetfilter-conntrack +libnfnetlink +libmnl \
           +libpcre2 \
           +libnghttp2 \
           +libpthread \
           +libcurl \
           +DREAMINGWRT_GATEWAY_SHADOW:keepalived \
           +DREAMINGWRT_GATEWAY_SHADOW:conntrackd \
           +DREAMINGWRT_CORE_RECOMMEND_LLDPD:lldpd
endef

define Package/dreamingwrt-core/description
  DreamingWrt core control-plane daemon. This is the transitional core
  package for config, apply orchestration, ubus APIs, and compatibility
  services while heavier workers are split into separate dreamingwrt-* packages.
endef

define Package/dreamingwrt-core/config
config DREAMINGWRT_BUNDLE_SIGNATURE_DB
	bool "Bundle a private DreamingOS DPI/signature database"
	default n
	help
	  The public source tree does not contain the private signature database.
	  Enable this only after placing dreamingwrt_signatures.db under
	  package/lester/jmxd/files/signatures/. The build stops with an explicit
	  error when the option is enabled but the database is absent.

config DREAMINGWRT_BUNDLE_FINGERPRINT_DB
	bool "Bundle a private DreamingOS device fingerprint database"
	default n
	help
	  The public source tree does not contain fingerprint.db. Enable this only
	  after supplying the private database under package/lester/jmxd/files/.
	  Devices without it continue to run with fingerprint catalog features
	  reported as unavailable.

config DREAMINGWRT_GATEWAY_SHADOW
	bool "Enable Gateway Shadow VRRP high availability"
	default y
	select KEEPALIVED_VRRP
	help
	  Install Keepalived with VRRP support and conntrackd for the core-owned
	  Gateway Shadow control plane. Runtime activation still requires a valid
	  dedicated heartbeat interface and mutually authenticated peer pairing.

config DREAMINGWRT_CRON_SPECIAL_TIMES
	bool "Enable @reboot/@daily BusyBox cron schedules"
	default y
	select BUSYBOX_CONFIG_FEATURE_CROND_SPECIAL_TIMES
	help
	  Build BusyBox crond with special schedule support. The jmxd validation
	  contract rejects @-schedules unless this exact runtime capability was
	  compiled into both BusyBox and dreamingwrt-core.

config DREAMINGWRT_CORE_RECOMMEND_LLDPD
	bool "Recommend/install lldpd for topology neighbor discovery"
	default n
	help
	  Select this when you want UniFi-like infrastructure topology to use
	  real LLDP neighbors. It adds lldpd as a package dependency; when disabled,
	  DreamingWrt still exposes lldp_supported=false/lldpcli_unavailable and
	  does not guess switch/AP parent-child relationships.
endef

define Package/dreamingwrt-auditd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt audit worker
  DEPENDS:=+dreamingwrt-core +kmod-jmx +libubox +libubus +libsqlite3
endef

define Package/dreamingwrt-auditd/description
  Optional DreamingWrt audit worker. It is split from dreamingwrt-core so
  audit collection can be installed and started only on devices that need it.
endef

define Package/dreamingwrt-auditd/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	[ -x /usr/bin/dreamingwrt-init ] && /usr/bin/dreamingwrt-init enable auditd >/dev/null 2>&1 || true
	[ -x /usr/bin/dreamingwrt-init ] && /usr/bin/dreamingwrt-init start auditd >/dev/null 2>&1 || true
}
exit 0
endef

define Package/dreamingwrt-rulesd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt timed filter rule worker
  DEPENDS:=+dreamingwrt-core +lua +libubus-lua +libuci-lua
endef

define Package/dreamingwrt-rulesd/description
  Optional DreamingWrt worker for timed app-filter and mac-filter rule updates.
endef

define Package/dreamingwrt-webd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt Web Console BFF/API daemon
  DEPENDS:=+dreamingwrt-core +dreamingwrt-web +libubox +libubus +libblobmsg-json +libuci +libjson-c +libsqlite3 +libcurl +libopenssl +zlib +libnghttp2 +conntrack +qrencode
endef

define Package/dreamingwrt-webd/description
  Optional DreamingWrt Web Console BFF/API daemon. It owns HTTP session,
  permissions, menu/bootstrap aggregation, and /api/v1 routes outside
  dreamingwrt-core while core remains the facts and execution layer.
endef

define Package/dreamingwrt-healthd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt health and housekeeping worker
  DEPENDS:=+dreamingwrt-core
endef

define Package/dreamingwrt-healthd/description
  Optional DreamingWrt worker for internet reachability checks and lightweight
  housekeeping that used to run as a thread inside dreamingwrt-core.
endef

define Package/dreamingwrt-metricsd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt metrics scheduler worker
  DEPENDS:=+dreamingwrt-core +libubox +libubus
endef

define Package/dreamingwrt-metricsd/description
  Optional DreamingWrt worker that schedules lightweight dashboard metrics
  refreshes through the core ubus API instead of keeping those timers in core.
endef

define Package/dreamingwrt-metricsd/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	[ -x /usr/bin/dreamingwrt-init ] && /usr/bin/dreamingwrt-init enable metricsd >/dev/null 2>&1 || true
	[ -x /usr/bin/dreamingwrt-init ] && /usr/bin/dreamingwrt-init start metricsd >/dev/null 2>&1 || true
}
exit 0
endef

define Package/dreamingwrt-maintenanced
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt maintenance scheduler worker
  DEPENDS:=+dreamingwrt-core +libubox +libubus
endef

define Package/dreamingwrt-maintenanced/description
  Optional DreamingWrt worker that schedules client sync, history cleanup,
  daily archive, and database pruning through the core ubus API.
endef

define Package/dreamingwrt-routed
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt route scheduler worker
  DEPENDS:=+dreamingwrt-core +libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libuci
endef

define Package/dreamingwrt-routed/description
  Optional DreamingWrt worker that schedules multi-WAN route health checks
  through the core ubus API instead of keeping that timer in core.
endef

define Package/dreamingwrt-identityd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt client identity collector
  DEPENDS:=+dreamingwrt-core +libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libopenssl +zlib
endef

define Package/dreamingwrt-identityd/description
  Optional DreamingWrt worker for mDNS, SSDP, DHCP, ARP, and lease-based
  client identity signal collection.
endef

define Package/dreamingwrt-identityd/config
config DREAMINGWRT_FULL_CLIENT_IMAGES
	bool "Include full DreamingWrt client fingerprint image library"
	default n
	help
	  This private image library is not part of the public source tree. Enable
	  it only after supplying files/fingerprint/images. The build stops with an
	  explicit error if the selected asset directory is absent or empty.

config DREAMINGWRT_LOGOS
	bool "Include DreamingWrt application and brand logo library"
	default n
	help
	  This private logo catalog is not part of the public source tree. Enable it
	  only after supplying files/logo and files/logo/flags. The Web interface
	  uses its built-in generic fallbacks when this option is disabled.
endef

define Package/dreamingwrt-logd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt normalized event log daemon
  DEPENDS:=+dreamingwrt-core +libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libopenssl +zlib
endef

define Package/dreamingwrt-logd/description
  Optional DreamingWrt normalized event log daemon. It owns durable event
  ingestion, query, retention, and future collector integration outside webd.
endef

define Package/dreamingwrt-notifyd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt notification delivery daemon
  DEPENDS:=+dreamingwrt-core +libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libcurl
endef

define Package/dreamingwrt-notifyd/description
  Optional DreamingWrt notification delivery daemon. It owns notification
  routes, channel configuration, retry/outbox state, and future third-party
  push/mail/webhook providers outside logd and webd.
endef

define Package/dreamingwrt-flowd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt flow policy daemon
  DEPENDS:=+dreamingwrt-core +libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libcurl
endef

define Package/dreamingwrt-flowd/description
  Optional DreamingWrt flow policy daemon. It starts the split flow boundary
  with GeoIP/country routing policy control-plane ownership while the legacy
  flow-control APIs remain in dreamingwrt-core for compatibility.
endef

define Package/dreamingwrt-geoip-tools
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt offline GeoIP prefix maintenance tools
  DEPENDS:=+libmaxminddb +python3-light +python3-sqlite3
endef

define Package/dreamingwrt-geoip-tools/description
  Optional offline diagnostics which export selected GeoLite2 Country MMDB
  search-tree prefixes to deterministic CIDR CSV. The legacy SQLite importer
  is retained for diagnostics only and is not used by AegisXD at runtime.
endef

define Package/dreamingwrt-flowd/config
config DREAMINGWRT_FLOWD_BUNDLE_GEOIP
	bool "Bundle GeoLite2 country database into the image"
	default n
	help
	  Include the P3TERX GeoLite2-Country.mmdb data file in the firmware
	  image at /etc/dreamingwrt/geoip/GeoLite2-Country.mmdb.

	  Leave this disabled for smaller images. When disabled, flowd keeps the
	  same configured source and can install or refresh the database after
	  boot through its GeoIP import API.

config DREAMINGWRT_FLOWD_BUNDLE_GEOIP_CITY
	bool "Bundle GeoLite2 city database into the image"
	default n
	help
	  Include the P3TERX GeoLite2-City.mmdb data file in the firmware image
	  at /etc/dreamingwrt/geoip/GeoLite2-City.mmdb.

	  This enables city-level coordinates for Insights traffic maps. Leave it
	  disabled for smaller images or when the database is managed after boot.
endef

define Package/dreamingwrt-authd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt user authentication daemon
  DEPENDS:=+dreamingwrt-core +libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libopenssl +libxml2 +libiconv-full
endef

define Package/dreamingwrt-authd/description
  DreamingWrt authentication control-plane daemon. It owns the persistent
  user-authentication schema, safe read contracts, and future Portal,
  Voucher, RADIUS accounting, session revocation, and notification runtime.
endef

define Package/dreamingwrt-otad
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt OTA control-plane daemon
  DEPENDS:=+dreamingwrt-core +dreamingwrt-init +libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libopenssl +libblkid +zlib +mount-utils +resize2fs +tune2fs +grub2-editenv
endef

define Package/dreamingwrt-otad/description
  Optional DreamingWrt OTA control-plane daemon. The first stage provides
  manifest validation, inventory scanning, unknown-file reporting, and OTA
  status APIs without writing slots or changing boot state.
endef

define Package/dreamingwrt-ac
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=Optional DreamingWrt wireless access controller
  DEPENDS:=+dreamingwrt-init +libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libopenssl
endef

define Package/dreamingwrt-ac/description
  Optional DreamingWrt wireless access controller for managing remote AP
  nodes. Installation does not enable the component; dreamingwrt-init owns
  its lifecycle when explicitly enabled.
endef

define Package/dreamingwrt-apd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=Optional DreamingWrt managed AP node daemon
  DEPENDS:=+libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libuci +libopenssl
endef

define Package/dreamingwrt-apd/description
  Optional DreamingWrt AP node agent for local radio capability, readback,
  and controlled configuration transactions. Its dedicated procd service owns
  the AP-side process lifecycle independently of the controller platform.
endef

define Package/dreamingwrt-aegisxd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt security intelligence daemon
  DEPENDS:=+dreamingwrt-core +libubox +libubus +libblobmsg-json +libjson-c +libsqlite3 +libcurl +libopenssl +zlib +libmaxminddb +DREAMINGWRT_AEGISXD_WITH_SURICATA:suricata
endef

define Package/dreamingwrt-aegisxd/description
  Optional DreamingWrt security intelligence and policy control-plane daemon.
  It is the CyberSecure-like boundary for security feeds, IDS/IPS policy,
  content categories, reputation, and normalized security runtime contracts.
endef

define Package/dreamingwrt-honeypotd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt low-interaction honeypot data plane
  DEPENDS:=+libubox +libubus +libblobmsg-json +libjson-c
endef

define Package/dreamingwrt-honeypotd/description
  Optional low-interaction honeypot data plane for AegisX. It binds only the
  listeners rendered by the authenticated honeypot configuration workflow and
  emits structured security events to dreamingwrt-aegisxd over local ubus.
  Installation alone does not enable or start the daemon.
endef

define Package/dreamingwrt-toolkit
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt on-demand network toolkit
  DEPENDS:=+libjson-c +libsqlite3 +libcurl +libopenssl +tc-full +kmod-sched-core +iperf3
endef

define Package/dreamingwrt-toolkit/description
  Non-resident one-shot helper for router checks, Wake-on-LAN, tc port
  mirroring, encrypted DDNS updates, and asynchronous iperf3 tasks. webd
  starts it only when an authenticated toolkit API is called.
endef

define Package/dreamingwrt-aegisxd/config
config DREAMINGWRT_AEGISXD_WITH_SURICATA
	bool "Install Suricata runtime for Aegis IDS/IPS"
	default n
	help
	  Add the OpenWrt suricata package as a runtime dependency for
	  dreamingwrt-aegisxd. When enabled, aegisxd can render a guarded Suricata
	  config, run suricata -T, start the daemon, and ingest eve.json events into
	  aegis_events. When disabled, IDS/IPS status remains explicit with
	  ids_ips_runtime_available=false and reason=suricata_runtime_missing.

	  This option only declares the dependency; the selected OpenWrt feed must
	  actually provide a suricata package for the target.
endef

define Package/dreamingwrt-init
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt supervisor and service control CLI
  DEPENDS:=+dreamingwrt-core +libsqlite3 +libopenssl
endef

define Package/dreamingwrt-init/description
  DreamingWrt supervisor and service-control CLI. It starts and monitors the
  split dreamingwrt-* workers from one procd entry point and provides
  dreamingwrt-init status/start/stop/restart for console and recovery use.
endef

define Package/dreamingwrt-init/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	# Remove init entries from older images. dreamingwrt-init is the sole
	# procd-owned DreamingWrt service and directly supervises every worker.
	for s in jmx dreamingwrt-auditd dreamingwrt-rulesd dreamingwrt-webd \
		dreamingwrt-healthd dreamingwrt-metricsd dreamingwrt-maintenanced \
		dreamingwrt-routed dreamingwrt-identityd dreamingwrt-logd \
		dreamingwrt-notifyd dreamingwrt-flowd dreamingwrt-otad \
		dreamingwrt-authd dreamingwrt-aegisxd dreamingwrt-honeypotd \
		dreamingwrt-apid dreamingproxy; do
		[ -x /etc/init.d/$$s ] && /etc/init.d/$$s disable >/dev/null 2>&1 || true
		rm -f /etc/init.d/$$s
	done
	rm -f /usr/bin/jmxd /usr/bin/jmx_auditd /usr/bin/rule_manager /usr/bin/dreamingwrt-apid
	/etc/init.d/dreamingwrt-init enable >/dev/null 2>&1 || true
	/etc/init.d/dreamingwrt-init start >/dev/null 2>&1 || true
}
exit 0
endef

# ── Linker flags ──────────────────────────────────────────────────────
# Order matters: dependents before dependencies for static resolution.

JMXD_LIBS := \
	-ljmx_common \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-luci \
	-lsqlite3 \
	-lnetfilter_queue -lnetfilter_conntrack -lnfnetlink -lmnl \
	-lpcre2-8 \
	-lcurl -lnghttp2 -lssl -lcrypto -lz \
	-lpthread -lm

JMXD_AUDIT_LIBS := \
	-lubus -lubox \
	-lsqlite3 \
	-lz

JMXD_WEBD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-luci \
	-ljson-c \
	-lsqlite3 \
	-lcurl \
	-lnghttp2 -lssl -lcrypto \
	-lz -lm

JMXD_IDENTITYD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 \
	-lz

JMXD_METRICSD_LIBS := \
	-lubus -lubox

JMXD_MAINTENANCED_LIBS := \
	-lubus -lubox

JMXD_ROUTED_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 \
	-luci

JMXD_LOGD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 \
	-lssl -lcrypto \
	-lz

JMXD_NOTIFYD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 \
	-lcurl -lnghttp2 -lssl -lcrypto -lz

JMXD_FLOWD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 \
	-lcurl -lnghttp2 -lssl -lcrypto -lz

JMXD_AUTHD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 -lssl -lcrypto -lxml2 -liconv -lm

JMXD_OTAD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 -lblkid \
	-lssl -lcrypto \
	-lz -lm

JMXD_AC_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 \
	-lssl -lcrypto -lm -lpthread

JMXD_APD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 -luci \
	-lssl -lcrypto -lm -lpthread

JMXD_AEGISXD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c \
	-lsqlite3 \
	-lcurl -lnghttp2 -lssl -lcrypto -lz -lmaxminddb

JMXD_HONEYPOTD_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c

JMXD_TOOLKIT_LIBS := \
	-ljson-c -lsqlite3 \
	-lcurl -lnghttp2 -lssl -lcrypto -lz

JMXD_JMCTL_LIBS := \
	-lubus -lubox -lblobmsg_json \
	-ljson-c

JMXD_INIT_LIBS := \
	-lsqlite3 -lcrypto \
	-static-libgcc

define Build/Prepare
	$(call Build/Prepare/Default)
	@if [ "$(CONFIG_DREAMINGWRT_BUNDLE_SIGNATURE_DB)" = "y" ] && \
		[ ! -s ./files/signatures/dreamingwrt_signatures.db ]; then \
		echo "DREAMINGWRT_BUNDLE_SIGNATURE_DB=y but files/signatures/dreamingwrt_signatures.db is missing or empty"; \
		exit 1; \
	fi
	@if [ "$(CONFIG_DREAMINGWRT_BUNDLE_FINGERPRINT_DB)" = "y" ] && \
		[ ! -s ./files/fingerprint.db ]; then \
		echo "DREAMINGWRT_BUNDLE_FINGERPRINT_DB=y but files/fingerprint.db is missing or empty"; \
		exit 1; \
	fi
	@if [ "$(CONFIG_DREAMINGWRT_FULL_CLIENT_IMAGES)" = "y" ] && \
		! find ./files/fingerprint/images -type f -print -quit 2>/dev/null | grep -q .; then \
		echo "DREAMINGWRT_FULL_CLIENT_IMAGES=y but files/fingerprint/images is missing or empty"; \
		exit 1; \
	fi
	@if [ "$(CONFIG_DREAMINGWRT_LOGOS)" = "y" ] && { \
		! find ./files/logo -maxdepth 1 -type f -print -quit 2>/dev/null | grep -q . || \
		! find ./files/logo/flags -type f -print -quit 2>/dev/null | grep -q .; \
	}; then \
		echo "DREAMINGWRT_LOGOS=y but files/logo or files/logo/flags is missing or empty"; \
		exit 1; \
	fi
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	find $(PKG_BUILD_DIR) -type f \( -name '*.o' -o -name 'dreamingwrt-*' -o -name 'jmxd' -o -name '*.bak-*' \) -delete
endef

define Download/dreamingwrt-flowd-geoip
	FILE:=dreamingwrt-geolite2-country.mmdb
	URL_FILE:=GeoLite2-Country.mmdb
	URL:=$(dir $(DREAMINGWRT_FLOWD_GEOIP_URL))
	PROTO:=https
	HASH:=skip
endef

define Download/dreamingwrt-flowd-geoip-city
	FILE:=dreamingwrt-geolite2-city.mmdb
	URL_FILE:=GeoLite2-City.mmdb
	URL:=$(dir $(DREAMINGWRT_FLOWD_GEOIP_CITY_URL))
	PROTO:=https
	HASH:=skip
endef

ifeq ($(DREAMINGWRT_FLOWD_BUNDLE_GEOIP),1)
$(eval $(call Download,dreamingwrt-flowd-geoip))
endif
ifeq ($(DREAMINGWRT_FLOWD_BUNDLE_GEOIP_CITY),1)
$(eval $(call Download,dreamingwrt-flowd-geoip-city))
endif

define Build/Prepare/GeoIP
	@if [ "$(DREAMINGWRT_FLOWD_BUNDLE_GEOIP)" = "1" ]; then \
		if [ ! -s "$(DREAMINGWRT_FLOWD_GEOIP_FILE)" ]; then \
			echo "missing bundled GeoIP DB: $(DREAMINGWRT_FLOWD_GEOIP_FILE)"; \
			exit 1; \
		fi; \
		if ! od -An -tx1 -v "$(DREAMINGWRT_FLOWD_GEOIP_FILE)" | tr -d ' \n' | grep -q "$(DREAMINGWRT_FLOWD_GEOIP_MARKER)"; then \
			echo "invalid GeoIP DB: missing MaxMind MMDB marker"; \
			exit 1; \
		fi; \
	fi
	@if [ "$(DREAMINGWRT_FLOWD_BUNDLE_GEOIP_CITY)" = "1" ]; then \
		if [ ! -s "$(DREAMINGWRT_FLOWD_GEOIP_CITY_FILE)" ]; then \
			echo "missing bundled GeoIP City DB: $(DREAMINGWRT_FLOWD_GEOIP_CITY_FILE)"; \
			exit 1; \
		fi; \
		if ! od -An -tx1 -v "$(DREAMINGWRT_FLOWD_GEOIP_CITY_FILE)" | tr -d ' \n' | grep -q "$(DREAMINGWRT_FLOWD_GEOIP_MARKER)"; then \
			echo "invalid GeoIP City DB: missing MaxMind MMDB marker"; \
			exit 1; \
		fi; \
	fi
endef

define Build/Compile
	$(call Build/Prepare/GeoIP)
	$(TARGET_CC) $(TARGET_CFLAGS) -std=c11 -Wall -Wextra \
		-I$(STAGING_DIR)/usr/include \
		./tools/export-mmdb-country-prefix.c \
		./src/geoip/mmdb_country_prefix.c \
		-L$(STAGING_DIR)/usr/lib $(TARGET_LDFLAGS) -lmaxminddb \
		-o $(PKG_BUILD_DIR)/dreamingwrt-geoip-prefix-export
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
		CC="$(TARGET_CROSS)gcc" \
		CFLAGS="$(TARGET_CFLAGS) -I$(PKG_BUILD_DIR) -I$(PKG_BUILD_DIR)/routed" \
		LIBS="$(TARGET_LDFLAGS) $(JMXD_LIBS)" \
		WEBD_LIBS="$(TARGET_LDFLAGS) $(JMXD_WEBD_LIBS)" \
		HEALTHD_LIBS="$(TARGET_LDFLAGS)" \
		IDENTITYD_LIBS="$(TARGET_LDFLAGS) $(JMXD_IDENTITYD_LIBS)" \
		METRICSD_LIBS="$(TARGET_LDFLAGS) $(JMXD_METRICSD_LIBS)" \
		MAINTENANCED_LIBS="$(TARGET_LDFLAGS) $(JMXD_MAINTENANCED_LIBS)" \
		ROUTED_LIBS="$(TARGET_LDFLAGS) $(JMXD_ROUTED_LIBS)" \
		LOGD_LIBS="$(TARGET_LDFLAGS) $(JMXD_LOGD_LIBS)" \
		NOTIFYD_LIBS="$(TARGET_LDFLAGS) $(JMXD_NOTIFYD_LIBS)" \
		FLOWD_LIBS="$(TARGET_LDFLAGS) $(JMXD_FLOWD_LIBS)" \
		AUTHD_CFLAGS="-I$(STAGING_DIR)/usr/include/libxml2 -I$(STAGING_DIR)/usr/lib/libiconv-full/include" \
		AUTHD_LIBS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib/libiconv-full/lib -Wl,-rpath-link,$(STAGING_DIR)/usr/lib/libiconv-full/lib $(JMXD_AUTHD_LIBS)" \
		OTAD_LIBS="$(TARGET_LDFLAGS) $(JMXD_OTAD_LIBS)" \
		AC_LIBS="$(TARGET_LDFLAGS) $(JMXD_AC_LIBS)" \
		APD_LIBS="$(TARGET_LDFLAGS) $(JMXD_APD_LIBS)" \
		AEGISXD_LIBS="$(TARGET_LDFLAGS) $(JMXD_AEGISXD_LIBS)" \
		HONEYPOTD_LIBS="$(TARGET_LDFLAGS) $(JMXD_HONEYPOTD_LIBS)" \
		TOOLKIT_LIBS="$(TARGET_LDFLAGS) $(JMXD_TOOLKIT_LIBS)" \
		JMCTL_LIBS="$(TARGET_LDFLAGS) $(JMXD_JMCTL_LIBS)" \
		INIT_LIBS="$(TARGET_LDFLAGS) $(JMXD_INIT_LIBS)" \
		all
	$(MAKE) -C $(PKG_BUILD_DIR)/audit/ \
		CC="$(TARGET_CROSS)gcc" \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include" \
		LDFLAGS="$(TARGET_LDFLAGS) $(JMXD_AUDIT_LIBS)" \
		all
endef

define Build/Compile/Default
endef

define Package/dreamingwrt-core/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/usr/share/dreamingwrt/fingerprint
	$(INSTALL_DIR) $(1)/usr/share/dreamingwrt/system-db
ifeq ($(CONFIG_DREAMINGWRT_BUNDLE_SIGNATURE_DB),y)
	$(INSTALL_DATA) ./files/signatures/dreamingwrt_signatures.db $(1)/usr/share/dreamingwrt/system-db/dreamingwrt_signatures.db
endif
ifeq ($(CONFIG_DREAMINGWRT_BUNDLE_FINGERPRINT_DB),y)
	$(INSTALL_DATA) ./files/fingerprint.db $(1)/usr/share/dreamingwrt/system-db/fingerprint.db
endif
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-core $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/jmctl $(1)/usr/bin
	$(INSTALL_BIN) ./files/jmx-dump.sh $(1)/usr/bin/jmx-dump
	$(INSTALL_DATA) ./files/jmx.version $(1)/etc/jmx_version
endef

define Package/dreamingwrt-auditd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/audit/dreamingwrt-auditd $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/nginx/conf.d
	$(INSTALL_DATA) ./files/nginx/jmx_audit.locations $(1)/etc/nginx/conf.d/
endef

define Package/dreamingwrt-rulesd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/rule_manager.lua $(1)/usr/bin/dreamingwrt-rulesd
endef

define Package/dreamingwrt-webd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-webd $(1)/usr/bin
endef

define Package/dreamingwrt-healthd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-healthd $(1)/usr/bin
endef

define Package/dreamingwrt-metricsd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-metricsd $(1)/usr/bin
endef

define Package/dreamingwrt-maintenanced/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-maintenanced $(1)/usr/bin
endef

define Package/dreamingwrt-routed/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-routed $(1)/usr/bin
endef

define Package/dreamingwrt-identityd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-identityd $(1)/usr/bin
	$(INSTALL_DIR) $(1)/www/luci-static/dreamingwrt/fingerprint
ifeq ($(CONFIG_DREAMINGWRT_FULL_CLIENT_IMAGES),y)
	$(INSTALL_DIR) $(1)/usr/share/dreamingwrt/fingerprint/images
	$(CP) ./files/fingerprint/images/* $(1)/usr/share/dreamingwrt/fingerprint/images/
	ln -sf /usr/share/dreamingwrt/fingerprint/images $(1)/www/luci-static/dreamingwrt/fingerprint/images
endif
ifeq ($(CONFIG_DREAMINGWRT_LOGOS),y)
	$(INSTALL_DIR) $(1)/www/dreamingwrt/static/images/logo \
		$(1)/www/dreamingwrt/static/images/flags
	find ./files/logo -maxdepth 1 -type f -exec \
		$(CP) '{}' $(1)/www/dreamingwrt/static/images/logo/ \;
	$(CP) ./files/logo/flags/*.svg $(1)/www/dreamingwrt/static/images/flags/
endif
endef

define Package/dreamingwrt-logd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/dreamingwrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-logd $(1)/usr/bin
endef

define Package/dreamingwrt-notifyd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/dreamingwrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-notifyd $(1)/usr/bin
endef

define Package/dreamingwrt-flowd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/dreamingwrt/geoip
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-flowd $(1)/usr/bin
ifeq ($(DREAMINGWRT_FLOWD_BUNDLE_GEOIP),1)
	$(INSTALL_DATA) $(DREAMINGWRT_FLOWD_GEOIP_FILE) $(1)/etc/dreamingwrt/geoip/GeoLite2-Country.mmdb
endif
ifeq ($(DREAMINGWRT_FLOWD_BUNDLE_GEOIP_CITY),1)
	$(INSTALL_DATA) $(DREAMINGWRT_FLOWD_GEOIP_CITY_FILE) $(1)/etc/dreamingwrt/geoip/GeoLite2-City.mmdb
endif
endef

define Package/dreamingwrt-geoip-tools/install
	$(INSTALL_DIR) $(1)/usr/libexec/dreamingwrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-geoip-prefix-export \
		$(1)/usr/libexec/dreamingwrt/dreamingwrt-geoip-prefix-export
	$(INSTALL_BIN) ./tools/import-geoip-country-prefix.py \
		$(1)/usr/libexec/dreamingwrt/import-geoip-country-prefix.py
endef

define Package/dreamingwrt-authd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/dreamingwrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-authd $(1)/usr/bin
endef

define Package/dreamingwrt-otad/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/dreamingwrt/ota-trust/keys
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-otad $(1)/usr/bin
	$(INSTALL_CONF) ./files/ota-trust/policy.json $(1)/etc/dreamingwrt/ota-trust/policy.json
endef

define Package/dreamingwrt-ac/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-ac $(1)/usr/bin
endef

define Package/dreamingwrt-apd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-apd $(1)/usr/bin
	$(INSTALL_BIN) ./files/dreamingwrt-apd.init $(1)/etc/init.d/dreamingwrt-apd
endef

define Package/dreamingwrt-aegisxd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/dreamingwrt
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-aegisxd $(1)/usr/bin
endef

define Package/dreamingwrt-honeypotd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/acl.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-honeypotd $(1)/usr/bin
	$(INSTALL_DATA) ./files/acl.d/dreamingwrt-honeypotd.json $(1)/usr/share/acl.d/
endef

define Package/dreamingwrt-toolkit/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-toolkit $(1)/usr/bin
endef

define Package/dreamingwrt-init/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/dreamingwrt-init $(1)/usr/bin
	$(INSTALL_BIN) ./files/dreamingwrt-init.init $(1)/etc/init.d/dreamingwrt-init
endef

define Package/jmxd
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=DreamingWrt complete backend component set
  DEPENDS:=+dreamingwrt-init +dreamingwrt-core +dreamingwrt-rulesd +dreamingwrt-auditd +dreamingwrt-webd +dreamingwrt-healthd +dreamingwrt-metricsd +dreamingwrt-maintenanced +dreamingwrt-routed +dreamingwrt-identityd +dreamingwrt-logd +dreamingwrt-notifyd +dreamingwrt-flowd +dreamingwrt-authd +dreamingwrt-otad +dreamingwrt-aegisxd +dreamingwrt-honeypotd +dreamingwrt-toolkit
endef

define Package/jmxd/description
  DreamingWrt complete backend package set. It selects the core daemon,
  centralized supervisor, and all split dreamingwrt-* workers. Lean images may
  select dreamingwrt-core and only the workers they need directly.
endef

define Package/jmxd/install
	:
endef

$(eval $(call BuildPackage,dreamingwrt-core))
$(eval $(call BuildPackage,dreamingwrt-rulesd))
$(eval $(call BuildPackage,dreamingwrt-auditd))
$(eval $(call BuildPackage,dreamingwrt-webd))
$(eval $(call BuildPackage,dreamingwrt-healthd))
$(eval $(call BuildPackage,dreamingwrt-metricsd))
$(eval $(call BuildPackage,dreamingwrt-maintenanced))
$(eval $(call BuildPackage,dreamingwrt-routed))
$(eval $(call BuildPackage,dreamingwrt-identityd))
$(eval $(call BuildPackage,dreamingwrt-logd))
$(eval $(call BuildPackage,dreamingwrt-notifyd))
$(eval $(call BuildPackage,dreamingwrt-flowd))
$(eval $(call BuildPackage,dreamingwrt-geoip-tools))
$(eval $(call BuildPackage,dreamingwrt-authd))
$(eval $(call BuildPackage,dreamingwrt-otad))
$(eval $(call BuildPackage,dreamingwrt-ac))
$(eval $(call BuildPackage,dreamingwrt-apd))
$(eval $(call BuildPackage,dreamingwrt-aegisxd))
$(eval $(call BuildPackage,dreamingwrt-honeypotd))
$(eval $(call BuildPackage,dreamingwrt-toolkit))
$(eval $(call BuildPackage,dreamingwrt-init))
$(eval $(call BuildPackage,jmxd))
