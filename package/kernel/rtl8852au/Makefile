include $(TOPDIR)/rules.mk

PKG_NAME:=rtl8852au
PKG_VERSION:=1.15.0.1
PKG_RELEASE:=1

PKG_LICENSE:=GPLv2
PKG_LICENSE_FILES:=
PKG_MAINTAINER:=sbwml <admin@cooluc.com>

PKG_BUILD_PARALLEL:=1

STAMP_CONFIGURED_DEPENDS := $(STAGING_DIR)/usr/include/mac80211-backport/backport/autoconf.h

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/rtl8852au
  SUBMENU:=Wireless Drivers
  VERSION:=7.1.5
  TITLE:=Realtek RTL8852AU / RTL8832AU support (out-of-tree)
  DEPENDS:=+kmod-usb-core +kmod-cfg80211 +@DRIVER_11N_SUPPORT +@DRIVER_11AC_SUPPORT +@DRIVER_11AX_SUPPORT
  FILES:=\
	$(PKG_BUILD_DIR)/8852au.ko
  AUTOLOAD:=$(call AutoProbe,8852au)
endef

NOSTDINC_FLAGS := \
	$(KERNEL_NOSTDINC_FLAGS) \
	-I$(PKG_BUILD_DIR) \
	-I$(PKG_BUILD_DIR)/include \
	-I$(STAGING_DIR)/usr/include/mac80211-backport \
	-I$(STAGING_DIR)/usr/include/mac80211-backport/uapi \
	-I$(STAGING_DIR)/usr/include/mac80211 \
	-I$(STAGING_DIR)/usr/include/mac80211/uapi \
	-include backport/backport.h

NOSTDINC_FLAGS += -DCONFIG_IOCTL_CFG80211 -DRTW_USE_CFG80211_STA_EVENT \
	-D_LINUX_BYTEORDER_SWAB_H -DCONFIG_RADIO_WORK

ifeq ($(CONFIG_BIG_ENDIAN), y)
NOSTDINC_FLAGS += -DCONFIG_BIG_ENDIAN
endif
ifeq ($(CONFIG_LITTLE_ENDIAN), y)
NOSTDINC_FLAGS += -DCONFIG_LITTLE_ENDIAN
endif

define Build/Compile
	$(RM) $(PKG_BUILD_DIR)/include/linux/wireless.h
	+$(MAKE) $(PKG_JOBS) -C "$(LINUX_DIR)" \
		$(KERNEL_MAKE_FLAGS) \
		M="$(PKG_BUILD_DIR)" \
		NOSTDINC_FLAGS="$(NOSTDINC_FLAGS)" \
		CONFIG_RTL8852AU=m \
		modules
endef

$(eval $(call KernelPackage,rtl8852au))
