include $(TOPDIR)/rules.mk

PKG_NAME:=jsonfilter
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL=$(PROJECT_GIT)/project/jsonpath.git
PKG_SOURCE_DATE:=2026-03-16
PKG_SOURCE_VERSION:=b9034210bd331749673416c6bf389cccd4e23610
PKG_MIRROR_HASH:=561647daddcc721226a0c15d8095d913673bbcefd4dd9774bebe57e04a4aeac4
CMAKE_INSTALL:=1

PKG_MAINTAINER:=Jo-Philipp Wich <jo@mein.io>
PKG_LICENSE:=ISC

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/jsonfilter
  SECTION:=base
  CATEGORY:=Base system
  DEPENDS:=+libubox +libjson-c
  TITLE:=OpenWrt JSON filter utility
  URL:=$(PKG_SOURCE_URL)
endef

define Package/jsonfilter/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/jsonpath $(1)/usr/bin/jsonfilter
endef

$(eval $(call BuildPackage,jsonfilter))
