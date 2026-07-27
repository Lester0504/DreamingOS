include $(TOPDIR)/rules.mk

PKG_NAME:=libjmx_common
PKG_VERSION:=12.05.17
PKG_RELEASE:=3
PKG_MAINTAINER:=DreamingOS contributors
PKG_LICENSE:=GPL-2.0-or-later

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

# ── libjmx_common ─────────────────────────────────────────────────────
#
# Thin shared library wrapping UCI operations used by jmxd.
# Exports 17 jmx_uci_* functions (get/set/add/del/commit for values,
# lists, arrays, and sections).
#
# Dependency: libuci (UCI context), libjson-c (included for future use)
# ──────────────────────────────────────────────────────────────────────

define Package/libjmx_common
  SECTION:=Base system
  CATEGORY:=Base system
  TITLE:=jmx UCI helper library
  DEPENDS:=+libubox +libuci +libjson-c
endef

define Package/libjmx_common/description
  Shared library providing UCI helper wrappers (jmx_uci_*) used by jmxd.
  Wraps uci_get/set/add_list/delete/commit with simplified APIs.
endef

# Force -fPIC for shared library (overrides any -fno-pic from global CFLAGS)
TARGET_CFLAGS += -fPIC

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -rf ./src/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/ \
		CC="$(TARGET_CROSS)gcc" \
		CFLAGS="$(TARGET_CFLAGS)" \
		LIBS="$(TARGET_LDFLAGS) -luci -ljson-c" \
		all
endef

define Build/Compile/Default
endef

define Package/libjmx_common/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libjmx_common.so $(1)/usr/lib
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/*.h $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libjmx_common.so $(1)/usr/lib/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
