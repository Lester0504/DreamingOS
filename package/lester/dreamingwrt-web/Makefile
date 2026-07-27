include $(TOPDIR)/rules.mk

PKG_NAME:=dreamingwrt-web
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=DreamingOS contributors
PKG_LICENSE:=GPL-2.0-or-later Apache-2.0 BSD-3-Clause MIT ISC
PKGARCH:=all
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/dreamingwrt-web
  SECTION:=web
  CATEGORY:=Web
  TITLE:=Dreaming OS standalone web interface
endef

define Package/dreamingwrt-web/description
  Static assets for the standalone Dreaming OS web interface served by
  dreamingwrt-webd/jmxd. This package intentionally does not depend on LuCI.
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/dreamingwrt-web/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./files/www/dreamingwrt $(1)/www/
	$(RM) -r $(1)/www/dreamingwrt/.playwright-cli $(1)/www/dreamingwrt/output
	$(INSTALL_DIR) $(1)/etc/nginx/conf.d
	$(INSTALL_DATA) ./files/etc/nginx/conf.d/dreamingwrt-webd.locations $(1)/etc/nginx/conf.d/dreamingwrt-webd.locations
endef

$(eval $(call BuildPackage,dreamingwrt-web))
