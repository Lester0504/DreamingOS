# DreamingWrt x86 installer/OTA image integration.
# This fragment is included by target/linux/x86/image/Makefile.

DREAMINGWRT_FW_BUILDER:=$(firstword $(wildcard \
	$(TOPDIR)/package/lester/dreamingwrt-fw-builder/files/dreamingwrt-fw-builder \
	$(TOPDIR)/package/lester/dreamingwrt-packages/dreamingwrt-fw-builder/files/dreamingwrt-fw-builder))
DREAMINGWRT_VERSION:=$(call qstrip,$(CONFIG_DREAMINGWRT_VERSION))
DREAMINGWRT_VERSION:=$(if $(DREAMINGWRT_VERSION),$(DREAMINGWRT_VERSION),0.1.0-dev)
DREAMINGWRT_BUILD_ID:=Build$(shell TZ=Asia/Shanghai date +%Y%m%d%H%M)
DREAMINGWRT_MIN_SLOT_MIB:=$(if $(CONFIG_DREAMINGWRT_AB_MIN_SLOT_SIZE),$(CONFIG_DREAMINGWRT_AB_MIN_SLOT_SIZE),5120)
DREAMINGWRT_DEFAULT_SLOT_MIB:=$(if $(CONFIG_DREAMINGWRT_AB_DEFAULT_SLOT_SIZE),$(CONFIG_DREAMINGWRT_AB_DEFAULT_SLOT_SIZE),6144)
DREAMINGWRT_MIN_DATA_MIB:=$(if $(CONFIG_DREAMINGWRT_AB_MIN_DATA_SIZE),$(CONFIG_DREAMINGWRT_AB_MIN_DATA_SIZE),4096)
DREAMINGWRT_ISO_LABEL:=DWRT_INSTALL
DREAMINGWRT_INSTALLER_INITRAMFS_BUILDER:=./build-dreamingwrt-installer-initramfs.sh
DREAMINGWRT_GRUB_THEME:=./dreamingwrt-grub-theme
# IMAGE_ROOTFS is an image-pipeline argument in x86 artifact recipes and can
# expand to the literal device image list (for example "generic-images").
# The ext4 slot payload itself is always materialized at this KDIR path.
DREAMINGWRT_SLOT_ROOTFS:=$(KDIR)/root.ext4

# Standalone rootfs pipelines use append-rootfs, so an interrupted incremental
# image build must remove the previous output before appending a fresh slot.
define Build/dreamingwrt-reset-output
	rm -f $@
endef

define Build/dreamingwrt-check-initrd-gzip
	grep -q '^CONFIG_BLK_DEV_INITRD=y' $(LINUX_DIR)/.config || \
		{ echo "DreamingWrt installer ISO requires CONFIG_BLK_DEV_INITRD=y" >&2; exit 1; }
	grep -q '^CONFIG_RD_GZIP=y' $(LINUX_DIR)/.config || \
		{ echo "DreamingWrt installer ISO requires CONFIG_RD_GZIP=y" >&2; exit 1; }
endef

define Build/dreamingwrt-iso-payload
	$(call Build/dreamingwrt-check-initrd-gzip)
	$(INSTALL_DIR) $@.boot/boot $@.boot/boot/grub/themes/dreamingwrt \
		$@.boot/firmware/grub/theme
	test -s $(DREAMINGWRT_GRUB_THEME)/theme.txt && \
		test -s $(DREAMINGWRT_GRUB_THEME)/background.jpg && \
		test -s $(DREAMINGWRT_GRUB_THEME)/terminus-14.pf2
	$(CP) $(DREAMINGWRT_GRUB_THEME)/. $@.boot/boot/grub/themes/dreamingwrt/
	$(CP) $(DREAMINGWRT_GRUB_THEME)/. $@.boot/firmware/grub/theme/
	gzip -9n < $(DREAMINGWRT_SLOT_ROOTFS) > $@.boot/firmware/rootfs.img.gz
	sh $(DREAMINGWRT_INSTALLER_INITRAMFS_BUILDER) \
		$(TARGET_DIR) $@.boot/boot/installer-initramfs.cpio.gz $(DREAMINGWRT_ISO_LABEL)
	$(CP) $(STAGING_DIR_IMAGE)/grub2/boot.img $@.boot/firmware/grub/
	$(CP) $(STAGING_DIR_IMAGE)/grub2/dreamingwrt-core.img \
		$@.boot/firmware/grub/core.img
	$(if $(CONFIG_GRUB_EFI_IMAGES), \
		$(CP) $(STAGING_DIR_IMAGE)/grub2/dreamingwrt-boot$(if $(CONFIG_x86_64),x64,ia32).efi \
			$@.boot/firmware/grub/bootx64.efi)
endef

define Build/dreamingwrt-iso-info
	size=0; stable=0; \
	for pass in 1 2 3; do \
		SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) python3 $(DREAMINGWRT_FW_BUILDER) iso-info \
			--rootfs $@.boot/firmware/rootfs.img.gz \
			--vmlinuz $@.boot/boot/vmlinuz \
			--output $@.boot/firmware/firmware_info.json \
			--version '$(DREAMINGWRT_VERSION)' \
			--linux-version '$(LINUX_VERSION)' \
			--build-id '$(DREAMINGWRT_BUILD_ID)' \
			--artifact-size $$size \
			--min-slot-mib $(DREAMINGWRT_MIN_SLOT_MIB) \
			--default-slot-mib $(DREAMINGWRT_DEFAULT_SLOT_MIB) \
			--min-data-mib $(DREAMINGWRT_MIN_DATA_MIB) >/dev/null || exit 1; \
			$(CP) $@.boot/firmware/firmware_info.json $@.boot/firmware_info.json; \
			rm -f $@; \
		mkisofs -iso-level 3 -R -V $(DREAMINGWRT_ISO_LABEL) -b boot/grub/eltorito.img -no-emul-boot -boot-info-table \
			$(if $(filter $(1),efi),-boot-load-size 4 -c boot.cat -eltorito-alt-boot -eltorito-platform efi -b boot/grub/isoboot.img -no-emul-boot) \
			-o $@ $@.boot || exit 1; \
		next=$$(wc -c < $@ | tr -d ' '); \
		if [ "$$next" = "$$size" ]; then stable=1; break; fi; \
		size=$$next; \
	done; \
	[ "$$stable" = 1 ] || { echo "DreamingWrt installer ISO size did not converge" >&2; exit 1; }
endef

define Build/dreamingwrt-ota-bin
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) python3 $(DREAMINGWRT_FW_BUILDER) build-slot \
		--rootfs $(DREAMINGWRT_SLOT_ROOTFS) \
		--vmlinuz $(KDIR)/$(KERNEL_NAME) \
		--output $@ \
		--version '$(DREAMINGWRT_VERSION)' \
		--linux-version '$(LINUX_VERSION)' \
		--build-id '$(DREAMINGWRT_BUILD_ID)' \
		--min-slot-mib $(DREAMINGWRT_MIN_SLOT_MIB) \
		--default-slot-mib $(DREAMINGWRT_DEFAULT_SLOT_MIB) \
		--min-data-mib $(DREAMINGWRT_MIN_DATA_MIB)
	$(INSTALL_DIR) $(BIN_DIR)
	$(CP) $@.firmware_info.json $(BIN_DIR)/$(notdir $@).firmware_info.json
endef
