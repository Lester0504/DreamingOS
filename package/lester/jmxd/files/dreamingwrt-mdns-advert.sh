#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# DreamingWrt mDNS service advertisement generator.
#
# Writes /etc/avahi/services/dreamingwrt.service so a phone on the LAN can
# discover this router with standard Bonjour browsing (_dreamingwrt._tcp)
# before it holds any credential. avahi-daemon watches its services directory
# and republishes on its own, so rewriting the file is all that is needed.
#
# TXT records published here, and why each one is safe to broadcast:
#
#   mac    LAN bridge MAC. Stable device identity; the App needs it because the
#          IP changes and it must not re-prompt for a device already in its
#          list. Any host on the same L2 segment can already read it via ARP,
#          so publishing it discloses nothing new.
#   model  Board model string, the same value the setup wizard shows.
#   ver    DreamingOS display identity from the canonical release JSON.
#   paired Whether a usable App binding already exists (0/1), so the App does
#          not prompt for a router somebody else already owns.
#
# Deliberately NOT published:
#
#   initialized  Would tell the whole broadcast domain whether the router is
#                still unconfigured, which is a targeting hint. The value is
#                also currently wrong: setup_finish has never run, so a
#                configured router reports initialized=false. Both the value
#                and the exposure must be settled before this is broadcast.
#                See todo/2026-08-05/Handoff/
#                Front-to-Backend-SECURITY-unauthenticated-setup-write-open-on-configured-router.md
#   serial numbers, usernames, tokens, client lists, topology, WAN addressing.

# Overridable so the generator can be exercised against a scratch directory
# without publishing anything. Production callers pass nothing and get the real
# avahi services directory.
SERVICE_DIR="${DWRT_MDNS_SERVICE_DIR:-/etc/avahi/services}"
SERVICE_FILE="$SERVICE_DIR/dreamingwrt.service"
SERVICE_TYPE="_dreamingwrt._tcp"
DEFAULT_PORT=12518
# Refresh cadence for the supervised `run` mode. paired flips when a phone
# pairs or is unpaired, and the LAN MAC/port can change on a reconfigure, so
# the file is regenerated periodically. Writes are content-compared, so a
# steady state costs one stat and no republish.
DEFAULT_INTERVAL=300

log() {
	logger -t dreamingwrt-mdns -p daemon.info "$1" 2>/dev/null || true
}

# XML text escape. TXT values land inside element content, so the five
# predefined entities are the whole surface; a model string containing '&'
# would otherwise make avahi reject the file and drop the advert entirely.
xml_escape() {
	printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
		-e "s/'/\&apos;/g" -e 's/"/\&quot;/g'
}

# Strip control characters and cap length: a newline would corrupt the file and
# a single TXT string cannot exceed 255 bytes.
sanitize() {
	printf '%s' "$1" | tr -d '\000-\037' | cut -c1-200
}

lan_mac() {
	local mac=""
	local iface

	for iface in br-lan br0; do
		if [ -r "/sys/class/net/$iface/address" ]; then
			read -r mac < "/sys/class/net/$iface/address"
			[ -n "$mac" ] && { printf '%s' "$mac"; return 0; }
		fi
	done

	# No bridge (single-port or unusual layout): fall back to whatever UCI
	# calls the LAN device.
	iface="$(uci -q get network.lan.device || uci -q get network.lan.ifname)"
	if [ -n "$iface" ] && [ -r "/sys/class/net/$iface/address" ]; then
		read -r mac < "/sys/class/net/$iface/address"
		printf '%s' "$mac"
		return 0
	fi

	return 1
}

device_model() {
	local model=""

	[ -r /tmp/sysinfo/model ] && read -r model < /tmp/sysinfo/model
	if [ -z "$model" ] && [ -r /proc/device-tree/model ]; then
		model="$(tr -d '\000' < /proc/device-tree/model)"
	fi
	[ -z "$model" ] && [ -r /tmp/sysinfo/board_name ] && read -r model < /tmp/sysinfo/board_name
	printf '%s' "$model"
}

device_version() {
	local ver=""

    local release=/etc/dreamingos-release.json
    [ -r "$release" ] || release=/etc/dreamingwrt-release.json
    if [ -r "$release" ]; then
        ver="$(jsonfilter -i "$release" -e '@.display_version' 2>/dev/null)"
        [ -n "$ver" ] || ver="$(jsonfilter -i "$release" -e '@.version' 2>/dev/null)"
        [ -n "$ver" ] || ver="$(jsonfilter -i "$release" -e '@.dreamingwrt_version' 2>/dev/null)"
    fi
	printf '%s' "$ver"
}

# Resolve the port webd actually listens on rather than assuming the default:
# it is started as `dreamingwrt-webd <port> <bind>` and this box may have been
# moved off 12517.
web_port() {
	local port=""
	local cmdline
	local p

	for p in /proc/[0-9]*; do
		cmdline="$(tr '\000' ' ' < "$p/cmdline" 2>/dev/null)" || continue
		case "$cmdline" in
		*dreamingwrt-webd*)
			port="$(printf '%s' "$cmdline" | awk '{print $2}')"
			break
			;;
		esac
	done

	case "$port" in
	''|*[!0-9]*) port="$DEFAULT_PORT" ;;
	esac
	{ [ "$port" -gt 0 ] && [ "$port" -le 65535 ]; } 2>/dev/null || port="$DEFAULT_PORT"
	printf '%s' "$port"
}

# paired reflects a *usable* App binding, reusing the definition the setup
# status API already uses (nc_setup_app_pairing_json, src/jmx_setup.c): an
# enabled app_devices row with a live, unrevoked token. Read it through ubus
# rather than opening apid.db -- the router has no sqlite3 CLI, and webd stays
# the only component touching that database.
#
# When the state cannot be determined, omit the record instead of guessing. A
# wrong paired=0 makes the App prompt for a router that is already bound; a
# missing record makes it fall back to prompting and letting the backend
# refuse, which is the degraded path the App already handles.
paired_state() {
	local json
	local val

	json="$(ubus call dreamingwrt setup_status 2>/dev/null)" || return 1
	[ -n "$json" ] || return 1

	val="$(printf '%s' "$json" | jsonfilter -e '@.data.app_pairing.status_available' 2>/dev/null)"
	[ "$val" = "true" ] || return 1

	val="$(printf '%s' "$json" | jsonfilter -e '@.data.app_pairing.paired' 2>/dev/null)"
	case "$val" in
	true)  printf '1' ;;
	false) printf '0' ;;
	*)     return 1 ;;
	esac
}

generate() {
	local mac model ver port paired
	local tmp

	mac="$(lan_mac)"
	if [ -z "$mac" ]; then
		# Without a stable identity the advert is not useful, and a
		# half-populated record is worse than none: it would be discovered and
		# then fail to correlate across an IP change.
		log "no LAN MAC available, skipping mDNS advert"
		return 1
	fi

	[ -d "$SERVICE_DIR" ] || mkdir -p "$SERVICE_DIR" || {
		log "cannot create $SERVICE_DIR"
		return 1
	}

	model="$(sanitize "$(device_model)")"
	ver="$(sanitize "$(device_version)")"
	port="$(web_port)"
	paired="$(paired_state)"

	tmp="$SERVICE_FILE.tmp.$$"
	{
		printf '%s\n' '<?xml version="1.0" standalone="no"?><!--*-nxml-*-->'
		printf '%s\n' '<!DOCTYPE service-group SYSTEM "avahi-service.dtd">'
		printf '%s\n' '<!-- Generated by dreamingwrt-mdns-advert; edits are overwritten. -->'
		printf '%s\n' '<service-group>'
		printf '%s\n' '  <name replace-wildcards="yes">DreamingWrt on %h</name>'
		printf '%s\n' '  <service>'
		printf '    <type>%s</type>\n' "$SERVICE_TYPE"
		printf '    <port>%s</port>\n' "$port"
		printf '    <txt-record>mac=%s</txt-record>\n' "$(xml_escape "$mac")"
		[ -n "$model" ] && printf '    <txt-record>model=%s</txt-record>\n' "$(xml_escape "$model")"
		[ -n "$ver" ] && printf '    <txt-record>ver=%s</txt-record>\n' "$(xml_escape "$ver")"
		[ -n "$paired" ] && printf '    <txt-record>paired=%s</txt-record>\n' "$paired"
		printf '%s\n' '  </service>'
		printf '%s\n' '</service-group>'
	} > "$tmp" || {
		rm -f "$tmp"
		log "failed writing $tmp"
		return 1
	}

	# Replace atomically: avahi-daemon reacts to directory events, so a
	# partially written file would be read and rejected as malformed.
	if [ -f "$SERVICE_FILE" ] && cmp -s "$tmp" "$SERVICE_FILE"; then
		rm -f "$tmp"
		return 0
	fi

	mv "$tmp" "$SERVICE_FILE" || {
		rm -f "$tmp"
		log "failed installing $SERVICE_FILE"
		return 1
	}
	chmod 0644 "$SERVICE_FILE"
	log "published $SERVICE_TYPE port=$port paired=${paired:-unknown}"
	return 0
}

remove() {
	rm -f "$SERVICE_FILE"
	log "withdrew $SERVICE_TYPE advert"
}

# Supervised mode: publish now, then keep the record honest. Without this a
# device that pairs after boot keeps advertising paired=0 until the next
# restart, and the App would go on prompting for a router that is already
# bound -- the exact repeat-prompt problem the record exists to prevent.
run() {
	local interval="${1:-$DEFAULT_INTERVAL}"

	case "$interval" in
	''|*[!0-9]*) interval="$DEFAULT_INTERVAL" ;;
	esac
	[ "$interval" -ge 30 ] 2>/dev/null || interval="$DEFAULT_INTERVAL"

	while :; do
		generate
		sleep "$interval"
	done
}

case "${1:-generate}" in
generate|update)
	generate
	;;
run)
	run "$2"
	;;
remove)
	remove
	;;
*)
	printf 'usage: %s {generate|run [interval]|remove}\n' "$0" >&2
	exit 2
	;;
esac
