include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=jmx
PKG_MAINTAINER:=DreamingOS contributors
PKG_LICENSE:=GPL-2.0-or-later
include $(INCLUDE_DIR)/package.mk

PKG_RELEASE:=21
PKG_AUTOLOAD:=jmx
RSTRIP:=:

JMX_DEBUG ?= 1

EXTRA_CFLAGS:= \
	-Wno-declaration-after-statement \
	-Wno-strict-prototypes \
	-Wno-unused-variable \
	-Wno-implicit-fallthrough \
	-Wno-missing-braces \
	-Wno-parentheses \
	-Wno-format \
	-Wno-missing-prototypes \
	-Wno-missing-declarations \
	-Wno-misleading-indentation

ifeq ($(JMX_DEBUG),1)
EXTRA_CFLAGS += \
	-g3 \
	-Og \
	-fno-omit-frame-pointer \
	-fno-inline \
	-fno-optimize-sibling-calls
endif

MAKE_OPTS:= \
	$(KERNEL_MAKE_FLAGS) \
	M="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)

define KernelPackage/jmx
  SUBMENU:=Netfilter Extensions
  TITLE:=jmx netfilter module
  FILES:=$(PKG_BUILD_DIR)/jmx.ko
  DEPENDS:=+kmod-ipt-conntrack +kmod-nf-reject
  KCONFIG:=CONFIG_NF_CONNTRACK_EVENTS=y CONFIG_NF_CONNTRACK_CHAIN_EVENTS=y
endef

define KernelPackage/jmx/description
  jmx netfilter module
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,jmx))
