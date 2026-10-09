#!/bin/sh

# OpenWrt's stock UTC default is only a placeholder. Apply DreamingWrt's
# product default once, while preserving any timezone the operator selected.
zone="$(uci -q get system.@system[0].zonename)"
tz="$(uci -q get system.@system[0].timezone)"

case "$zone:$tz" in
	""|UTC:GMT0|UTC:UTC|GMT:GMT0)
		uci set system.@system[0].zonename='Asia/Shanghai'
		uci set system.@system[0].timezone='CST-8'
		uci commit system
		echo 'CST-8' > /tmp/TZ
		;;
esac

exit 0
