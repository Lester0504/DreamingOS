include $(TOPDIR)/rules.mk

PKG_NAME:=gnulib
PKG_CPE_ID:=cpe:/a:gnu:$(PKG_NAME)

PKG_SOURCE_URL=git://git.git.savannah.gnu.org/$(PKG_NAME).git
PKG_SOURCE_DATE:=2025-07-01
PKG_SOURCE_VERSION:=a3151d456d6919c9066b54dc6f680452168165cf# # stable-202501
PKG_MIRROR_HASH:=5004489477c414dde736d3b85bc8b20887880ada3e769b36677d6eb4a0f1d6ba

include $(INCLUDE_DIR)/host-build.mk

define Host/Configure
endef

# On installing the .m4 files, we add a gl_ prefix to prevent any conflict with
# automake. It was found that there is currently a conflict for the cond.m4 that
# is also shipped by automake, making the gnulib one having priority causing
# problem with finding AM_CONDITIONAL macro.
define Host/Install
	$(call Host/Uninstall)
	$(INSTALL_DIR) $(1)/share/aclocal
	for m4 in $(HOST_BUILD_DIR)/m4/*.m4; do \
		$(INSTALL_DATA) $(HOST_BUILD_DIR)/m4/$$$$(basename $$$$m4) \
				$(1)/share/aclocal/gl_$$$$(basename $$$$m4); \
	done
	$(CP) $(HOST_BUILD_DIR)/ $(1)/share/gnulib/
	ln -sf ../share/gnulib/gnulib-tool $(STAGING_DIR_HOST)/bin/gnulib-tool
endef

define Host/Uninstall
	rm -rf $(STAGING_DIR_HOST)/bin/gnulib-tool $(STAGING_DIR_HOST)/share/gnulib
endef

$(eval $(call HostBuild))
