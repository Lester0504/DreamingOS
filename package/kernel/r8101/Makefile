#
# Download realtek r8101 linux driver from official site:
# [https://www.realtek.com/Download/List?cate_id=584]
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=r8101
PKG_VERSION:=1.039.00
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/r8101
  TITLE:=Driver for Realtek r8101 chipsets
  SUBMENU:=Network Devices
  VERSION:=7.1.5
  DEPENDS:=@PCI_SUPPORT
  FILES:= $(PKG_BUILD_DIR)/r8101.ko
  AUTOLOAD:=$(call AutoProbe,r8101)
  PROVIDES:=@kmod-r8169-any
endef

define Package/r8101/description
  This package contains a driver for Realtek r8101 chipsets.
endef

define Build/Compile
	+$(KERNEL_MAKE) M=$(PKG_BUILD_DIR) modules
endef

$(eval $(call KernelPackage,r8101))
