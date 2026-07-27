include $(TOPDIR)/rules.mk

PKG_NAME:=rtl8822cs
PKG_VERSION:=5.15.8.3
PKG_RELEASE:=17

PKG_LICENSE:=GPLv2
PKG_LICENSE_FILES:=
PKG_MAINTAINER:=sbwml <admin@cooluc.com>

PKG_BUILD_PARALLEL:=1

STAMP_CONFIGURED_DEPENDS := $(STAGING_DIR)/usr/include/mac80211-backport/backport/autoconf.h

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk

define KernelPackage/rtl8822cs
  SUBMENU:=Wireless Drivers
  VERSION:=7.1.5
  TITLE:=Realtek RTL8822CS SDIO WiFi support (High Performance)
  DEPENDS:=+kmod-mmc +kmod-cfg80211 +@DRIVER_11N_SUPPORT +@DRIVER_11AC_SUPPORT
  FILES:=\
	$(PKG_BUILD_DIR)/rtl8822cs.ko
  AUTOLOAD:=$(call AutoProbe,rtl8822cs)
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
	-D_LINUX_BYTEORDER_SWAB_H -DRTW_SINGLE_WIPHY

ifeq ($(CONFIG_BIG_ENDIAN), y)
NOSTDINC_FLAGS += -DCONFIG_BIG_ENDIAN
endif
ifeq ($(CONFIG_LITTLE_ENDIAN), y)
NOSTDINC_FLAGS += -DCONFIG_LITTLE_ENDIAN
endif

define Build/Compile
	+$(MAKE) $(PKG_JOBS) -C "$(LINUX_DIR)" \
		$(KERNEL_MAKE_FLAGS) \
		M="$(PKG_BUILD_DIR)" \
		NOSTDINC_FLAGS="$(NOSTDINC_FLAGS)" \
		CONFIG_RTL8822CS=m \
		USER_MODULE_NAME=rtl8822cs \
		modules
endef

$(eval $(call KernelPackage,rtl8822cs))
