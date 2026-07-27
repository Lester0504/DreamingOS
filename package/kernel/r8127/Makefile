#
# Download realtek r8127 linux driver from official site:
# https://www.realtek.com/Download/List?cate_id=584
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=r8127
PKG_VERSION:=11.015.00
PKG_RELEASE:=1

PKG_BUILD_PARALLEL:=1
PKG_LICENSE:=GPLv2

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define KernelPackage/r8127
  TITLE:=Realtek RTL8127 PCI 10 Gigabit Ethernet driver
  SUBMENU:=Network Devices
  VERSION:=7.1.5
  DEPENDS:=@PCI_SUPPORT +kmod-libphy
  FILES:= $(PKG_BUILD_DIR)/r8127.ko
  AUTOLOAD:=$(call AutoProbe,r8127)
  PROVIDES:=@kmod-r8169-any
endef

define Package/r8127/description
  This package contains a driver for Realtek r8127 chipsets.
endef

PKG_MAKE_FLAGS += \
	CONFIG_ASPM=n \
	ENABLE_RSS_SUPPORT=y \
	ENABLE_MULTIPLE_TX_QUEUE=y

define Build/Compile
	+$(KERNEL_MAKE) $(PKG_JOBS) \
		$(PKG_MAKE_FLAGS) \
		M=$(PKG_BUILD_DIR) \
		modules
endef

$(eval $(call KernelPackage,r8127))
