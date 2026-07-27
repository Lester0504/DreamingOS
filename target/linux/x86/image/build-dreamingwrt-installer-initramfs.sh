#!/bin/sh
set -eu

usage() {
	cat >&2 <<'EOUSAGE'
usage: build-installer-initramfs.sh TARGET_DIR OUT_CPIO_GZ [ISO_LABEL]
EOUSAGE
	exit 1
}

TARGET_DIR="${1:-}"
OUT="${2:-}"
ISO_LABEL="${3:-DWRT_INSTALL}"
[ -n "$TARGET_DIR" ] && [ -d "$TARGET_DIR" ] || usage
[ -n "$OUT" ] || usage

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dwrt-installer-initramfs.XXXXXX")"
ROOT="$WORK/root"
ELF_QUEUE="$WORK/elf.queue"
ELF_DONE="$WORK/elf.done"
LIB_DONE="$WORK/lib.done"
mkdir -p "$ROOT" "$(dirname "$OUT")"
: >"$ELF_QUEUE"
: >"$ELF_DONE"
: >"$LIB_DONE"

cleanup() {
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

fail() {
	echo "build-installer-initramfs: $*" >&2
	exit 1
}

need_host() {
	command -v "$1" >/dev/null 2>&1 || fail "missing host command: $1"
}

need_host cpio
need_host file
need_host gzip
need_host readelf

mkdir -p "$ROOT"/bin "$ROOT"/sbin "$ROOT"/usr/bin "$ROOT"/usr/sbin \
	"$ROOT"/lib "$ROOT"/usr/lib "$ROOT"/etc "$ROOT"/dev "$ROOT"/proc \
	"$ROOT"/sys "$ROOT"/tmp "$ROOT"/run "$ROOT"/mnt "$ROOT"/rom \
	"$ROOT"/iso "$ROOT"/firmware "$ROOT"/boot
chmod 0755 "$ROOT"/tmp "$ROOT"/run

copy_entry() {
	_src="$1"
	_dst="$2"
	# Absolute links in TARGET_DIR are rooted inside the firmware image, not on
	# the build host.  Such links can look dangling to test -e on the host.
	[ -e "$_src" ] || [ -L "$_src" ] || return 1
	mkdir -p "$(dirname "$_dst")"
	if [ -L "$_src" ]; then
		_link="$(readlink "$_src")"
		ln -snf "$_link" "$_dst"
		case "$_link" in
			/*)
				_target_src="$TARGET_DIR$_link"
				_target_dst="$ROOT$_link"
				;;
			*)
				_target_src="$(readlink -m "$(dirname "$_src")/$_link")"
				_target_dst="$(readlink -m "$(dirname "$_dst")/$_link")"
				;;
		esac
		case "$_target_src:$_target_dst" in
			"$TARGET_DIR"/*:"$ROOT"/*) copy_entry "$_target_src" "$_target_dst" || true ;;
		esac
	elif [ -d "$_src" ]; then
		mkdir -p "$_dst"
	else
		cp -p "$_src" "$_dst"
		queue_elf "$_dst"
	fi
}

queue_elf() {
	_path="$1"
	case "$_path" in "$ROOT"/*) ;; *) return 0 ;; esac
	file "$_path" 2>/dev/null | grep -q 'ELF' || return 0
	_rel="/${_path#$ROOT/}"
	grep -Fxq "$_rel" "$ELF_QUEUE" 2>/dev/null && return 0
	grep -Fxq "$_rel" "$ELF_DONE" 2>/dev/null && return 0
	printf '%s\n' "$_rel" >>"$ELF_QUEUE"
}

copy_target_path() {
	_rel="$1"
	case "$_rel" in /*) ;; *) _rel="/$_rel" ;; esac
	_src="$TARGET_DIR$_rel"
	_dst="$ROOT$_rel"
	[ -e "$_src" ] || [ -L "$_src" ] || return 1
	copy_entry "$_src" "$_dst"
	return 0
}

find_command() {
	_cmd="$1"
	for _dir in /usr/sbin /usr/bin /sbin /bin; do
		if [ -e "$TARGET_DIR$_dir/$_cmd" ] || [ -L "$TARGET_DIR$_dir/$_cmd" ]; then
			printf '%s\n' "$_dir/$_cmd"
			return 0
		fi
	done
	return 1
}

copy_command() {
	_cmd="$1"
	_rel="$(find_command "$_cmd" 2>/dev/null || true)"
	[ -n "$_rel" ] || fail "target command is missing from rootfs: $_cmd"
	copy_target_path "$_rel"
}

copy_optional_command() {
	_cmd="$1"
	_rel="$(find_command "$_cmd" 2>/dev/null || true)"
	[ -n "$_rel" ] || return 0
	copy_target_path "$_rel"
}

copy_lib_name() {
	_name="$1"
	case "$_name" in */*) _candidates="$_name" ;; *) _candidates="/lib/$_name /usr/lib/$_name" ;; esac
	for _rel in $_candidates; do
		if [ -e "$TARGET_DIR$_rel" ]; then
			copy_target_path "$_rel"
			return 0
		fi
	done
	_found="$(find "$TARGET_DIR/lib" "$TARGET_DIR/usr/lib" -name "$_name" -print -quit 2>/dev/null || true)"
	[ -n "$_found" ] || return 0
	copy_target_path "/${_found#$TARGET_DIR/}"
}

copy_elf_deps() {
	_elf="$1"
	_rel="/${_elf#$ROOT/}"
	grep -Fxq "$_rel" "$ELF_DONE" 2>/dev/null && return 0
	printf '%s\n' "$_rel" >>"$ELF_DONE"
	readelf -l "$_elf" 2>/dev/null | sed -n 's#.*Requesting program interpreter: \([^]]*\).*#\1#p' |
	while IFS= read -r _interp; do
		[ -n "$_interp" ] && copy_lib_name "$_interp"
	done
	readelf -d "$_elf" 2>/dev/null | sed -n 's#.*Shared library: \[\([^]]*\)\].*#\1#p' |
	while IFS= read -r _lib; do
		[ -n "$_lib" ] && copy_lib_name "$_lib"
	done
}

# BusyBox applets and standalone tools required by the installer and init.
for cmd in sh mount umount mkdir rmdir rm cp mv cat echo printf sleep grep sed awk tr \
	readlink basename dirname cut sort uniq find xargs ps dmesg sync dd stat md5sum \
	sha256sum gzip gunzip jsonfilter lsblk blockdev findmnt sfdisk partx mkfs.fat mkfs.ext4 \
	e2fsck resize2fs tune2fs blkid grub-editenv grub-bios-setup swapoff wipefs mkfifo mknod; do
	copy_command "$cmd"
done
for cmd in kmod modprobe insmod kmodloader mdev switch_root setsid cttyhack reboot poweroff; do
	copy_optional_command "$cmd"
done

# Installer entry point and minimal OpenWrt identity/config files.
copy_target_path /usr/sbin/dreamingwrt-installer
for rel in /etc/passwd /etc/group /etc/shadow /etc/profile /etc/shells /etc/protocols /etc/services /etc/mke2fs.conf; do
	copy_target_path "$rel" || true
done

# Some installer kernels expose disks in sysfs but do not provide devtmpfs,
# and this image's BusyBox may have mdev disabled.  Populate block nodes from
# the kernel's authoritative major:minor values without depending on either.
cat >"$ROOT/sbin/dreamingwrt-populate-block-devices" <<'EOF_BLOCK_NODES'
#!/bin/sh
for sysdev in /sys/class/block/*; do
	[ -r "$sysdev/dev" ] || continue
	name="${sysdev##*/}"
	devno="$(cat "$sysdev/dev" 2>/dev/null || true)"
	major="${devno%%:*}"
	minor="${devno#*:}"
	case "$major:$minor" in
		*[!0-9:]*|:|*:|:*:) continue ;;
	esac
	node="/dev/$name"
	[ -b "$node" ] && continue
	rm -f "$node"
	mknod "$node" b "$major" "$minor" 2>/dev/null || true
done
EOF_BLOCK_NODES
chmod 0755 "$ROOT/sbin/dreamingwrt-populate-block-devices"

# Include only kernel modules/config needed by the installer runtime, not the
# full rootfs. Built-in modules are harmlessly skipped at boot.
if [ -d "$TARGET_DIR/lib/modules" ]; then
	mkdir -p "$ROOT/lib/modules"
	find "$TARGET_DIR/lib/modules" -type f \( \
		-name 'modules.*' -o -name 'isofs.ko*' -o -name 'iso9660.ko*' -o \
		-name 'sr_mod.ko*' -o -name 'cdrom.ko*' -o -name 'scsi_mod.ko*' -o \
		-name 'sd_mod.ko*' -o -name 'usb-storage.ko*' -o -name 'uas.ko*' -o \
		-name 'ext4.ko*' -o -name 'jbd2.ko*' -o -name 'mbcache.ko*' -o \
		-name 'fat.ko*' -o -name 'vfat.ko*' -o -name 'nls_cp437.ko*' -o \
		-name 'nls_iso8859-1.ko*' \
	\) | while IFS= read -r mod; do
		copy_entry "$mod" "$ROOT/${mod#$TARGET_DIR/}"
	done
fi

# Resolve dynamic library closure.
while :; do
	_next="$(awk 'NR == 1 { print; exit }' "$ELF_QUEUE")"
	[ -n "$_next" ] || break
	sed '1d' "$ELF_QUEUE" >"$ELF_QUEUE.tmp" && mv "$ELF_QUEUE.tmp" "$ELF_QUEUE"
	[ -f "$ROOT$_next" ] && copy_elf_deps "$ROOT$_next"
done

case "$ISO_LABEL" in
	''|*[!A-Za-z0-9_.-]*) fail "invalid ISO label: $ISO_LABEL" ;;
esac
{
	printf '%s\n' '#!/bin/sh' 'export PATH=/usr/sbin:/usr/bin:/sbin:/bin' "ISO_LABEL='$ISO_LABEL'"
	cat <<'EOF_INIT'

mountpoint_is_mounted() { grep -qs " $1 " /proc/mounts; }

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
[ -e /dev/console ] || mknod /dev/console c 5 1 2>/dev/null || true
[ -e /dev/null ] || mknod /dev/null c 1 3 2>/dev/null || true
mkdir -p /dev/pts /tmp /run /rom /iso /firmware /boot
mount -t devpts devpts /dev/pts 2>/dev/null || true
exec </dev/console >/dev/console 2>&1

for mod in scsi_mod sd_mod sr_mod cdrom isofs iso9660 ext4 jbd2 mbcache fat vfat nls_cp437 nls_iso8859-1; do
	modprobe "$mod" >/dev/null 2>&1 || true
done
[ -x /sbin/kmodloader ] && /sbin/kmodloader >/dev/null 2>&1 || true
[ -x /sbin/mdev ] && { echo /sbin/mdev >/proc/sys/kernel/hotplug 2>/dev/null || true; /sbin/mdev -s 2>/dev/null || true; }
/sbin/dreamingwrt-populate-block-devices

cmdline="$(cat /proc/cmdline 2>/dev/null || true)"
for token in $cmdline; do
	case "$token" in
		dreamingwrt.iso_label=*) ISO_LABEL="${token#dreamingwrt.iso_label=}" ;;
	esac
done

try_mount_iso() {
	dev="$1"
	[ -b "$dev" ] || return 1
	mount -t iso9660 -o ro "$dev" /rom 2>/dev/null || return 1
	[ -f /rom/firmware/firmware_info.json ] && [ -f /rom/firmware/rootfs.img.gz ] && return 0
	umount /rom 2>/dev/null || true
	return 1
}

find_iso_device() {
	if command -v blkid >/dev/null 2>&1; then
		dev="$(blkid -L "$ISO_LABEL" 2>/dev/null || true)"
		[ -n "$dev" ] && { echo "$dev"; return 0; }
	fi
	for dev in /dev/disk/by-label/"$ISO_LABEL" /dev/sr* /dev/cdrom /dev/sd* /dev/vd* /dev/nvme*n*p*; do
		[ -e "$dev" ] || continue
		dev="$(readlink -f "$dev" 2>/dev/null || echo "$dev")"
		if try_mount_iso "$dev"; then
			umount /rom 2>/dev/null || true
			echo "$dev"
			return 0
		fi
	done
	return 1
}

echo "DreamingWrt installer runtime: locating ISO payload (label=$ISO_LABEL)"
ISO_DEV=""
for i in 1 2 3 4 5 6 7 8 9 10; do
	ISO_DEV="$(find_iso_device 2>/dev/null || true)"
	[ -n "$ISO_DEV" ] && break
	sleep 1
done
[ -n "$ISO_DEV" ] && try_mount_iso "$ISO_DEV" || {
	echo "DreamingWrt installer runtime: unable to mount ISO payload"
	exec sh
}

mountpoint_is_mounted /iso || mount --bind /rom /iso 2>/dev/null || true
mountpoint_is_mounted /firmware || mount --bind /rom/firmware /firmware 2>/dev/null || true
mountpoint_is_mounted /boot || mount --bind /rom/boot /boot 2>/dev/null || true
export DREAMINGWRT_FIRMWARE_DIR=/rom/firmware
export DREAMINGWRT_INFO=/rom/firmware/firmware_info.json
export DREAMINGWRT_ROOT_INFO=/rom/firmware_info.json
export DREAMINGWRT_ROOTFS=/rom/firmware/rootfs.img.gz
export DREAMINGWRT_ROOTFS_COMPRESSION=gzip
export DREAMINGWRT_VMLINUX=/rom/boot/vmlinuz
export DREAMINGWRT_INSTALL_SOURCE="$ISO_DEV"

while :; do
	echo "DreamingWrt installer runtime: starting installer from $ISO_DEV"
	/usr/sbin/dreamingwrt-installer
	rc=$?
	echo "DreamingWrt installer exited with rc=$rc"
	echo "Select: [r] retry installer, [s] recovery shell, [b] reboot"
	read -r choice </dev/console || choice=s
	case "$choice" in
		r|R) continue ;;
		b|B) reboot -f 2>/dev/null || reboot ;;
		*) echo "Starting recovery shell. Exit shell to return to installer menu."; sh </dev/console >/dev/console 2>&1 ;;
	esac
done
EOF_INIT
} >"$ROOT/init"
chmod 0755 "$ROOT/init"

# Ensure busybox applet symlinks that may not exist in TARGET_DIR but are used
# by init fallback paths are present when /bin/busybox is available.
if [ -x "$ROOT/bin/busybox" ]; then
	for app in sh mount umount mkdir cat echo sleep grep awk readlink blkid modprobe mdev; do
		for dir in /bin /sbin /usr/bin /usr/sbin; do
			{ [ -e "$ROOT$dir/$app" ] || [ -L "$ROOT$dir/$app" ]; } && continue 2
		done
		ln -s /bin/busybox "$ROOT/bin/$app"
	done
fi

(
	cd "$ROOT"
	find . -print | LC_ALL=C sort | cpio -o -H newc 2>/dev/null | gzip -9n >"$OUT.tmp"
)
mv "$OUT.tmp" "$OUT"
