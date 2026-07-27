# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2006-2020 OpenWrt.org

ifdef CONFIG_STRIP_KERNEL_EXPORTS
  KERNEL_MAKEOPTS_IMAGE += \
	EXTRA_LDSFLAGS="-I$(KERNEL_BUILD_DIR) -include symtab.h"
endif

INITRAMFS_EXTRA_FILES ?= $(GENERIC_PLATFORM_DIR)/image/initramfs-base-files.txt

export HOST_EXTRACFLAGS=-I$(STAGING_DIR_HOST)/include

# defined in quilt.mk
Kernel/Patch:=$(Kernel/Patch/Default)

ifneq (,$(findstring .xz,$(LINUX_SOURCE)))
  LINUX_CAT:=xzcat
else
  LINUX_CAT:=$(STAGING_DIR_HOST)/bin/libdeflate-gzip -dc
endif

ifeq ($(strip $(CONFIG_EXTERNAL_KERNEL_TREE)),"")
  ifeq ($(strip $(CONFIG_KERNEL_GIT_CLONE_URI)),"")
    define Kernel/Prepare/Default
	$(LINUX_CAT) $(DL_DIR)/$(LINUX_SOURCE) | $(TAR) -C $(KERNEL_BUILD_DIR) $(TAR_OPTIONS)
	$(Kernel/Patch)
    endef
  else
    define Kernel/Prepare/Default
	$(LINUX_CAT) $(DL_DIR)/$(LINUX_SOURCE) | $(TAR) -C $(KERNEL_BUILD_DIR) $(TAR_OPTIONS)
    endef
  endif
else
  define Kernel/Prepare/Default
	mkdir -p $(KERNEL_BUILD_DIR)
	if [ -d $(LINUX_DIR) ]; then \
		rmdir $(LINUX_DIR); \
	fi
	ln -s $(CONFIG_EXTERNAL_KERNEL_TREE) $(LINUX_DIR)
	if [ -d $(LINUX_DIR)/user_headers ]; then \
		rm -rf $(LINUX_DIR)/user_headers; \
	fi
  endef
endif

ifeq ($(CONFIG_TARGET_ROOTFS_INITRAMFS),y)
  ifeq ($(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE),y)
    define Kernel/SetInitramfs/PreConfigure
	{ \
		grep -v -e CONFIG_BLK_DEV_INITRD $(2)/.config.old > $(2)/.config; \
		echo 'CONFIG_BLK_DEV_INITRD=y' >> $(2)/.config; \
		echo 'CONFIG_INITRAMFS_SOURCE=""' >> $(2)/.config; \
	}
    endef
  else
    ifeq ($(strip $(CONFIG_EXTERNAL_CPIO)),"")
      define Kernel/SetInitramfs/PreConfigure
	{ \
		grep -v -e INITRAMFS -e CONFIG_RD_ -e CONFIG_BLK_DEV_INITRD $(2)/.config.old > $(2)/.config; \
		echo 'CONFIG_BLK_DEV_INITRD=y' >> $(2)/.config; \
		echo 'CONFIG_INITRAMFS_SOURCE="$(strip $(1) $(INITRAMFS_EXTRA_FILES))"' >> $(2)/.config; \
	}
      endef
    else
      define Kernel/SetInitramfs/PreConfigure
	{ \
		grep -v INITRAMFS $(2)/.config.old > $(2)/.config; \
		echo 'CONFIG_INITRAMFS_SOURCE="$(call qstrip,$(CONFIG_EXTERNAL_CPIO))"' >> $(2)/.config; \
	}
      endef
    endif
  endif

  define Kernel/SetInitramfs
	{ \
		rm -f $(2)/.config.prev; \
		mv $(2)/.config $(2)/.config.old; \
		$(call Kernel/SetInitramfs/PreConfigure,$(1),$(2)); \
		echo "# CONFIG_INITRAMFS_PRESERVE_MTIME is not set" >> $(2)/.config; \
		$(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE),,echo "CONFIG_INITRAMFS_ROOT_UID=$(shell id -u)" >> $(2)/.config;) \
		$(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE),,echo "CONFIG_INITRAMFS_ROOT_GID=$(shell id -g)" >> $(2)/.config;) \
		$(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE), \
			echo "# CONFIG_INITRAMFS_FORCE is not set" >> $(2)/.config;, \
			$(if $(CONFIG_TARGET_INITRAMFS_FORCE), \
				echo "CONFIG_INITRAMFS_FORCE=y" >> $(2)/.config;, \
				echo "# CONFIG_INITRAMFS_FORCE is not set" >> $(2)/.config;)) \
		$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_NONE), \
			echo "CONFIG_INITRAMFS_COMPRESSION_NONE=y" >> $(2)/.config;, \
			echo "# CONFIG_INITRAMFS_COMPRESSION_NONE is not set" >> $(2)/.config; ) \
		$(foreach ALGO,GZIP BZIP2 LZMA LZO XZ LZ4 ZSTD, \
			$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_$(ALGO)), \
				echo "CONFIG_INITRAMFS_COMPRESSION_$(ALGO)=y" >> $(2)/.config; $\, \
				echo "# CONFIG_INITRAMFS_COMPRESSION_$(ALGO) is not set" >> $(2)/.config; $\) \
			$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_$(ALGO)), \
				echo "CONFIG_RD_$(ALGO)=y" >> $(2)/.config; $\, \
				echo "# CONFIG_RD_$(ALGO) is not set" >> $(2)/.config; $\) \
		) \
	}
  endef
else
endif

define Kernel/SetNoInitramfs
	mv $(LINUX_DIR)/.config.set $(LINUX_DIR)/.config.old
	grep -v INITRAMFS $(LINUX_DIR)/.config.old > $(LINUX_DIR)/.config.set
	echo 'CONFIG_INITRAMFS_SOURCE=""' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_INITRAMFS_FORCE is not set' >> $(LINUX_DIR)/.config.set
	echo "# CONFIG_INITRAMFS_PRESERVE_MTIME is not set" >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_FSCACHE is not set' >> $(LINUX_DIR)/.config.set
# CLANG
	mv $(LINUX_DIR)/.config.set $(LINUX_DIR)/.config.old
	grep -v CONFIG_LTO $(LINUX_DIR)/.config.old > $(LINUX_DIR)/.config.set
ifneq (,$(findstring clang,$(KERNEL_CC)))
	echo 'CONFIG_LTO=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LTO_CLANG=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LTO_CLANG_THIN=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_HAS_LTO_CLANG=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_RANDSTRUCT_NONE=y' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_CFI_CLANG is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LTO_CLANG_FULL is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LTO_NONE is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_RANDSTRUCT_FULL is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_RELR is not set' >> $(LINUX_DIR)/.config.set
else
	echo '# CONFIG_LTO is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LTO_CLANG is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LTO_CLANG_THIN is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LTO_CLANG_FULL is not set' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LTO_NONE=y' >> $(LINUX_DIR)/.config.set
endif
# BTF
ifeq ($(call qstrip,$(CONFIG_KERNEL_BPF_EVENTS)),y)
	echo 'CONFIG_DEBUG_INFO_BTF_MODULES=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_PROBE_EVENTS_BTF_ARGS=y' >> $(LINUX_DIR)/.config.set
endif
# LRNG
ifeq ($(call qstrip,$(CONFIG_KERNEL_LRNG)),y)
	echo 'CONFIG_LRNG=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_AUTO_SELECTED=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_COLLECTION_SIZE_1024=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_CONTINUOUS_COMPRESSION_ENABLED=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_CPU=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_CPU_ENTROPY_RATE=8' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_DEV_IF=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_DFLT_DRNG_CHACHA20=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_IRQ=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_IRQ_DFLT_TIMER_ES=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_IRQ_ENTROPY_RATE=256' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_JENT=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_JENT_ENTROPY_BLOCKS=128' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_JENT_ENTROPY_BLOCKS_NO_128=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_JENT_ENTROPY_RATE=16' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_KCAPI_IF=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_RUNTIME_ES_CONFIG=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_SCHED=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_SCHED_ENTROPY_RATE=4294967295' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_SWITCH_DRNG=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_SWITCH_HASH=y' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_LRNG_SWITCHABLE_CONTINUOUS_COMPRESSION=y' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_AIS2031_NTG1_SEEDING_STRATEGY is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_COLLECTION_SIZE_2048 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_COLLECTION_SIZE_256 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_COLLECTION_SIZE_4096 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_COLLECTION_SIZE_512 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_COLLECTION_SIZE_8192 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_CONTINUOUS_COMPRESSION_DISABLED is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_DFLT_DRNG_DRBG is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_DFLT_DRNG_KCAPI is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_HASH_KCAPI is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_HEALTH_TESTS is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_HWRAND_IF is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_JENT_ENTROPY_BLOCKS_DISABLED is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_JENT_ENTROPY_BLOCKS_NO_1024 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_JENT_ENTROPY_BLOCKS_NO_256 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_JENT_ENTROPY_BLOCKS_NO_32 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_JENT_ENTROPY_BLOCKS_NO_512 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_JENT_ENTROPY_BLOCKS_NO_64 is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_SCHED_DFLT_TIMER_ES is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_SELFTEST is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_SWITCH_DRBG is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_SWITCH_DRNG_KCAPI is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_LRNG_TESTING_MENU is not set' >> $(LINUX_DIR)/.config.set
	echo '# CONFIG_RANDOM_DEFAULT_IMPL is not set' >> $(LINUX_DIR)/.config.set
else
	echo '# CONFIG_LRNG is not set' >> $(LINUX_DIR)/.config.set
	echo 'CONFIG_RANDOM_DEFAULT_IMPL=y' >> $(LINUX_DIR)/.config.set
endif
endef

define Kernel/Configure/Default
	rm -f $(LINUX_DIR)/localversion
	$(LINUX_CONF_CMD) > $(LINUX_DIR)/.config.target
# copy CONFIG_KERNEL_* settings over to .config.target
	awk '/^(#[[:space:]]+)?CONFIG_KERNEL/{sub("CONFIG_KERNEL_","CONFIG_");print}' $(TOPDIR)/.config >> $(LINUX_DIR)/.config.target
	echo "# CONFIG_KALLSYMS_EXTRA_PASS is not set" >> $(LINUX_DIR)/.config.target
	echo "# CONFIG_KALLSYMS_ALL is not set" >> $(LINUX_DIR)/.config.target
	echo "CONFIG_KALLSYMS_UNCOMPRESSED=y" >> $(LINUX_DIR)/.config.target
	$(SCRIPT_DIR)/package-metadata.pl kconfig $(TMP_DIR)/.packageinfo $(TOPDIR)/.config $(KERNEL_PATCHVER) > $(LINUX_DIR)/.config.override
	$(SCRIPT_DIR)/kconfig.pl 'm+' '+' $(LINUX_DIR)/.config.target /dev/null $(LINUX_DIR)/.config.override > $(LINUX_DIR)/.config.set
	$(call Kernel/SetNoInitramfs)
	rm -rf $(KERNEL_BUILD_DIR)/modules
	cmp -s $(LINUX_DIR)/.config.set $(LINUX_DIR)/.config.prev || { \
		cp $(LINUX_DIR)/.config.set $(LINUX_DIR)/.config; \
		cp $(LINUX_DIR)/.config.set $(LINUX_DIR)/.config.prev; \
	}
	$(_SINGLE) [ -d $(LINUX_DIR)/user_headers ] || $(KERNEL_MAKE) $(if $(findstring uml,$(BOARD)),ARCH=$(ARCH)) INSTALL_HDR_PATH=$(LINUX_DIR)/user_headers headers_install
	cp $(TOPDIR)/.vermagic $(LINUX_DIR)/.vermagic
endef

define Kernel/Configure/Initramfs
	$(call Kernel/SetInitramfs,$(1),$(2))
endef

define Kernel/CompileModules/Default
	rm -f $(LINUX_DIR)/vmlinux $(LINUX_DIR)/System.map
	+$(KERNEL_MAKE) $(if $(KERNELNAME),$(KERNELNAME),all) modules
	# If .config did not change, use the previous timestamp to avoid package rebuilds
	cmp -s $(LINUX_DIR)/.config $(LINUX_DIR)/.config.modules.save && \
		mv $(LINUX_DIR)/.config.modules.save $(LINUX_DIR)/.config; \
	$(CP) $(LINUX_DIR)/.config $(LINUX_DIR)/.config.modules.save
endef

OBJCOPY_STRIP = -R .reginfo -R .notes -R .note -R .comment -R .mdebug -R .note.gnu.build-id

# AMD64 shares the location with x86
ifeq ($(LINUX_KARCH),x86_64)
IMAGES_DIR:=../../x86/boot
endif

# $1: image suffix
# $2: Per Device Rootfs ID
define Kernel/CopyImage
	cmp -s $(LINUX_DIR)$(2)/vmlinux $(KERNEL_BUILD_DIR)/vmlinux$(1).debug$(2) || { \
		$(KERNEL_CROSS)objcopy -O binary $(OBJCOPY_STRIP) -S $(LINUX_DIR)$(2)/vmlinux $(LINUX_KERNEL)$(1)$(2); \
		$(KERNEL_CROSS)objcopy $(OBJCOPY_STRIP) -S $(LINUX_DIR)$(2)/vmlinux $(KERNEL_BUILD_DIR)/vmlinux$(1).elf$(2); \
		$(CP) $(LINUX_DIR)$(2)/vmlinux $(KERNEL_BUILD_DIR)/vmlinux$(1).debug$(2); \
		$(foreach k, \
			$(if $(KERNEL_IMAGES),$(KERNEL_IMAGES),$(filter-out vmlinux dtbs,$(KERNELNAME))), \
			$(CP) $(LINUX_DIR)$(2)/arch/$(LINUX_KARCH)/boot/$(IMAGES_DIR)/$(k) $(KERNEL_BUILD_DIR)/$(k)$(1)$(2); \
		) \
	}
endef

define Kernel/CompileImage/Default
	rm -f $(TARGET_DIR)/init
	+$(KERNEL_MAKE) $(KERNEL_MAKEOPTS_IMAGE) $(if $(KERNELNAME),$(KERNELNAME),all)
	$(call Kernel/CopyImage)
endef

define Kernel/PrepareConfigPerRootfs
	{ \
		[ ! -d "$(1)" ] || rm -rf $(1); \
		mkdir $(1) && $(CP) -T $(LINUX_DIR) $(1); \
		touch $(1)/.config; \
	}
endef

ifneq ($(CONFIG_TARGET_ROOTFS_INITRAMFS),)
# $1: Custom TARGET_DIR. If omitted TARGET_DIR is used.
# $2: If defined Generate Per Rootfs Kernel Directory and use it
# For Separate Initramf with $2 declared, skip kernel compile, it has
# already been done previously on generic image build
define Kernel/CompileImage/Initramfs
	$(call locked,{ \
		$(if $(2),$(call Kernel/PrepareConfigPerRootfs,$(LINUX_DIR)$(2));) \
		$(call Kernel/Configure/Initramfs,$(if $(1),$(1),$(TARGET_DIR)),$(LINUX_DIR)$(2)); \
		$(CP) $(GENERIC_PLATFORM_DIR)/other-files/init $(if $(1),$(1),$(TARGET_DIR))/init; \
		$(if $(SOURCE_DATE_EPOCH),touch -hcd "@$(SOURCE_DATE_EPOCH)" $(if $(1),$(1),$(TARGET_DIR)) $(if $(1),$(1),$(TARGET_DIR))/init;) \
		rm -rf $(LINUX_DIR)$(2)/usr/initramfs_data.cpio*; \
		$(if $(CONFIG_TARGET_ROOTFS_INITRAMFS_SEPARATE), \
			$(call locked,{ \
				$(if $(call qstrip,$(CONFIG_EXTERNAL_CPIO)), \
					$(CP) $(CONFIG_EXTERNAL_CPIO) $(KERNEL_BUILD_DIR)/initrd$(2).cpio;,\
					( cd $(if $(1),$(1),$(TARGET_DIR)); find . | LC_ALL=C sort | $(STAGING_DIR_HOST)/bin/cpio --reproducible -o -H newc -R 0:0 > $(KERNEL_BUILD_DIR)/initrd$(2).cpio );) \
				$(if $(SOURCE_DATE_EPOCH), \
					touch -hcd "@$(SOURCE_DATE_EPOCH)" $(KERNEL_BUILD_DIR)/initrd$(2).cpio;) \
				$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_BZIP2), \
					$(STAGING_DIR_HOST)/bin/bzip2 -9 -c < $(KERNEL_BUILD_DIR)/initrd$(2).cpio > $(KERNEL_BUILD_DIR)/initrd$(2).cpio.bzip2;) \
				$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_GZIP), \
					$(STAGING_DIR_HOST)/bin/libdeflate-gzip -n -f -S .gzip -12 $(KERNEL_BUILD_DIR)/initrd$(2).cpio;) \
				$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_LZ4), \
					$(STAGING_DIR_HOST)/bin/lz4c -l -c1 -fz --favor-decSpeed $(KERNEL_BUILD_DIR)/initrd$(2).cpio $(KERNEL_BUILD_DIR)/initrd$(2).cpio.lz4;) \
				$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_LZMA), \
					$(STAGING_DIR_HOST)/bin/lzma e -lc1 -lp2 -pb2 $(KERNEL_BUILD_DIR)/initrd$(2).cpio $(KERNEL_BUILD_DIR)/initrd$(2).cpio.lzma;) \
				$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_LZO), \
					$(STAGING_DIR_HOST)/bin/lzop -9 -f $(KERNEL_BUILD_DIR)/initrd$(2).cpio;) \
				$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_XZ), \
					$(STAGING_DIR_HOST)/bin/xz -T$(if $(filter 1,$(NPROC)),2,0) -9 -fz --check=crc32 $(KERNEL_BUILD_DIR)/initrd$(2).cpio;) \
				$(if $(CONFIG_TARGET_INITRAMFS_COMPRESSION_ZSTD), \
					$(STAGING_DIR_HOST)/bin/zstd -T0 -f -o $(KERNEL_BUILD_DIR)/initrd$(2).cpio.zstd $(KERNEL_BUILD_DIR)/initrd$(2).cpio;) \
			}, gen-cpio$(2)); \
			$(if $(2),,$(KERNEL_MAKE) $(KERNEL_MAKEOPTS_IMAGE) $(if $(KERNELNAME),$(KERNELNAME),all);),\
			$(KERNEL_MAKE) $(if $(2),-C $(LINUX_DIR)$(2)) $(KERNEL_MAKEOPTS_IMAGE) $(if $(KERNELNAME),$(KERNELNAME),all);) \
		$(call Kernel/CopyImage,-initramfs,$(2)); \
		$(if $(2),rm -rf $(LINUX_DIR)$(2);) \
	}, gen-initramfs$(2));
endef
else
define Kernel/CompileImage/Initramfs
endef
endif

define Kernel/Clean/Default
	rm -f $(KERNEL_BUILD_DIR)/linux-$(LINUX_VERSION)/.configured
	rm -f $(LINUX_KERNEL)
	$(_SINGLE)$(MAKE) -C $(KERNEL_BUILD_DIR)/linux-$(LINUX_VERSION) clean
endef
