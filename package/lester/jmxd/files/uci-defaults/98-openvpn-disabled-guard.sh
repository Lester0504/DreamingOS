#!/bin/sh
#
# Workaround for an upstream openvpn regression.
#
# Upstream commit 2607b7615 ("openvpn: introduce proto handler") moved OpenVPN
# from the init.d service model to a netifd proto handler and dropped
# init.d/openvpn, which used to be the only consumer of "option enabled".
# The companion migration script (60_openvpn_migrate.sh) copies
# /etc/config/openvpn into /etc/config/network verbatim, renaming only
# "option proto" to "option ovpnproto". "option enabled '0'" is carried over
# as-is, but the new proto handler never reads it: proto_openvpn_setup() has no
# enabled check and proto_openvpn_init_config() hardcodes available=1.
#
# The result is that an instance the operator believes is disabled gets spawned
# unconditionally. When the instance cannot start (for example a client whose
# referenced .conf file is absent, so no --dev is emitted), openvpn exits
# immediately, netifd retries, and the box ends up in a restart storm that
# floods syslog and pins the load average.
#
# netifd itself honours "option disabled" on an interface, so mirror the stale
# "enabled '0'" onto "disabled '1'" for openvpn interfaces only.
#
# Deliberately conservative:
#   - only touches interfaces whose proto is exactly "openvpn"
#   - never clears an existing "disabled" value, in either direction
#   - leaves "enabled" in place so the mapping stays auditable and so a future
#     upstream fix that starts honouring it is not silently undermined
#   - takes no action when "enabled" is absent or non-zero
#
# Remove this once the upstream proto handler consumes "enabled" itself.
#

. /lib/functions.sh

changed=0

guard_openvpn_interface() {
	local section="$1"
	local proto enabled disabled

	config_get proto "$section" proto
	[ "$proto" = "openvpn" ] || return 0

	# Respect an explicit decision that is already recorded.
	config_get disabled "$section" disabled
	[ -n "$disabled" ] && return 0

	# Only act on the stale "disabled" intent the migration left behind.
	config_get enabled "$section" enabled
	[ -n "$enabled" ] || return 0
	[ "$enabled" = "0" ] || return 0

	uci -q set "network.$section.disabled=1"
	changed=1
	logger -t openvpn-disabled-guard -p daemon.notice \
		"network.$section: mirrored stale enabled='0' onto disabled='1' (upstream proto handler ignores 'enabled')"
}

config_load network
config_foreach guard_openvpn_interface interface

[ "$changed" = "1" ] && uci -q commit network

exit 0
