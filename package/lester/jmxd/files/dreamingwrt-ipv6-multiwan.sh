#!/bin/sh

# Own IPv6 source selection at the router. LAN clients and downstream routers
# receive subnets from one stable ULA delegation; each new flow is routed by
# its WAN mark and SNAT66 translates it to that WAN's current delegated prefix.
# The implementation is provider-neutral and discovers active wan/wanN
# interfaces from netifd at every apply.

TABLE_NAME=${DREAMINGWRT_IPV6_MW_TABLE_NAME:-dreamingwrt_npt}
LAN_LOGICAL=${DREAMINGWRT_IPV6_MW_LAN_LOGICAL:-lan}
STATE_FILE=${DREAMINGWRT_IPV6_MW_STATE_FILE:-/var/run/dreamingwrt-ipv6-mw.state}
LOCK_FILE=${DREAMINGWRT_IPV6_MW_LOCK_FILE:-/var/run/dreamingwrt-ipv6-mw.lock}
NFT_FILE=${DREAMINGWRT_IPV6_MW_NFT_FILE:-/tmp/dreamingwrt-ipv6-mw.nft}
LOG_TAG=dreamingwrt-ipv6-mw

umask 077

log() {
    logger -t "$LOG_TAG" "$*"
}

json_value() {
    jsonfilter -e "$2" 2>/dev/null <<EOF
$1
EOF
}

ula_prefixes() {
    ula_route=$(uci -q get network.globals.ula_prefix)
    [ -n "$ula_route" ] || return 1
    ula_base=${ula_route%/*}
    case "$ula_base" in
        *::) ula_lan="${ula_base%::}::/64" ;;
        *) return 1 ;;
    esac
    return 0
}

lan_device() {
    status=$(ubus call "network.interface.$LAN_LOGICAL" status 2>/dev/null)
    device=$(json_value "$status" '@.l3_device')
    printf '%s\n' "${device:-br-lan}"
}

discover_paths() {
    output=$1
    raw="${output}.raw.$$"
    : > "$raw" || return 1

    ubus list 'network.interface.wan*' 2>/dev/null |
        sed -n 's/^network\.interface\.//p' |
        while IFS= read -r logical; do
            case "$logical" in
                wan) id=1 ;;
                wan[2-9]|wan[1-9][0-9]*) id=${logical#wan} ;;
                *) continue ;;
            esac

            ipv6_logical="${logical}_6"
            ubus list "network.interface.$ipv6_logical" 2>/dev/null |
                grep -qx "network.interface.$ipv6_logical" || continue

            status=$(ubus call "network.interface.$logical" status 2>/dev/null)
            ipv6_status=$(ubus call "network.interface.$ipv6_logical" status 2>/dev/null)
            [ "$(json_value "$status" '@.up')" = true ] || continue
            [ "$(json_value "$ipv6_status" '@.up')" = true ] || continue

            device=$(json_value "$status" '@.l3_device')
            pd=$(json_value "$ipv6_status" '@["ipv6-prefix"][0].address')
            pd_mask=$(json_value "$ipv6_status" '@["ipv6-prefix"][0].mask')
            [ -n "$device" ] && [ -n "$pd" ] && [ -n "$pd_mask" ] || continue
            case "$pd:$pd_mask" in
                *:::6[0-4]|*:::5[0-9]|*:::4[0-9]) ;;
                *)
                    log "skip $logical: unsupported delegated prefix $pd/$pd_mask"
                    continue
                    ;;
            esac

            table=$((100 + id))
            mark=$(printf '0x%x' $((0x10000 + id)))
            snat="${pd}1"
            printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
                "$id" "$logical" "$ipv6_logical" "$device" "$table" \
                "$mark" "$pd" "$pd_mask" "$snat" >> "$raw"
        done

    sort -t '|' -k 1,1n "$raw" > "$output"
    rm -f "$raw"
    [ -s "$output" ]
}

state_has_field() {
    file=$1
    field=$2
    value=$3
    [ -f "$file" ] || return 1
    awk -F '|' -v field="$field" -v value="$value" '
        $1 == "path" && $field == value { found=1 }
        END { exit found ? 0 : 1 }
    ' "$file"
}

delete_mark_rule() {
    priority=$1
    while ip -6 rule del priority "$priority" 2>/dev/null; do :; done
}

delete_reject_rule() {
    prefix=$1
    device=$2
    while ip -6 rule del from "$prefix" iif "$device" unreachable 2>/dev/null; do :; done
}

write_state() {
    paths=$1
    output=$2
    printf 'meta|%s|%s|%s\n' "$lan_dev" "$ula_lan" "$ula_route" > "$output"
    while IFS='|' read -r id logical ipv6_logical device table mark pd pd_mask snat; do
        printf 'path|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
            "$id" "$logical" "$ipv6_logical" "$device" "$table" \
            "$mark" "$pd" "$pd_mask" "$snat" >> "$output"
    done < "$paths"
}

build_nft() {
    paths=$1
    output=$2
    if nft list table ip6 "$TABLE_NAME" >/dev/null 2>&1; then
        printf 'delete table ip6 %s\n' "$TABLE_NAME" > "$output"
    else
        : > "$output"
    fi
    {
        printf 'table ip6 %s {\n' "$TABLE_NAME"
        printf '  comment "owned-by=dreamingwrt-ipv6-mw"\n'
        printf '  chain postrouting {\n'
        printf '    type nat hook postrouting priority srcnat; policy accept;\n'
        while IFS='|' read -r id logical ipv6_logical device table mark pd pd_mask snat; do
            printf '    oifname "%s" ip6 saddr %s counter snat to %s\n' \
                "$device" "$ula_route" "$snat"
        done < "$paths"
        printf '  }\n}\n'
    } >> "$output"
}

prepare_paths() {
    paths=$1
    fallback_table=

    while IFS='|' read -r id logical ipv6_logical device table mark pd pd_mask snat; do
        fallback_table=$table
        ip -6 addr replace "$snat/128" dev lo || return 1

        gateway=$(ip -6 route show default dev "$device" 2>/dev/null |
            sed -n 's/.*via \([0-9a-fA-F:]*\).*/\1/p' | head -1)
        if [ -n "$gateway" ]; then
            ip -6 route replace default via "$gateway" dev "$device" table "$table" || return 1
        else
            ip -6 route replace default dev "$device" table "$table" || return 1
        fi

        # Conntrack restores the mark on replies too. A broad from-all rule
        # loops SYN-ACK packets back to WAN, so only LAN-originated ULA traffic
        # may enter a marked WAN table. Match the full delegated ULA route,
        # not only the root LAN /64: downstream routers receive sibling /64s.
        priority=$((1000 + id))
        delete_mark_rule "$priority"
        ip -6 rule add iif "$lan_dev" from "$ula_route" fwmark "$mark" \
            table "$table" priority "$priority" || return 1

        stale_lan="${pd}/64"
        delete_reject_rule "$stale_lan" "$lan_dev"
        ip -6 rule add from "$stale_lan" iif "$lan_dev" unreachable \
            priority 900 || return 1
    done < "$paths"

    [ -n "$fallback_table" ] || return 1
    while ip -6 rule del priority 2000 2>/dev/null; do :; done
    ip -6 rule add from "$ula_route" table "$fallback_table" priority 2000
}

cleanup_previous_state() {
    new_state=$1
    [ -f "$STATE_FILE" ] || return 0

    old_lan_dev=$(awk -F '|' '$1 == "meta" { print $2; exit }' "$STATE_FILE")
    [ -n "$old_lan_dev" ] || old_lan_dev=$lan_dev
    while IFS='|' read -r kind id logical ipv6_logical device table mark pd pd_mask snat; do
        [ "$kind" = path ] || continue
        if ! state_has_field "$new_state" 2 "$id"; then
            delete_mark_rule $((1000 + id))
            ip -6 route flush table "$table" 2>/dev/null
        fi
        if ! state_has_field "$new_state" 10 "$snat"; then
            ip -6 addr del "$snat/128" dev lo 2>/dev/null
        fi
        if ! state_has_field "$new_state" 8 "$pd"; then
            delete_reject_rule "${pd}/64" "$old_lan_dev"
        fi
    done < "$STATE_FILE"
}

apply_config() {
    work_dir=$(mktemp -d /tmp/dreamingwrt-ipv6-mw.XXXXXX) || return 1
    paths="$work_dir/paths"
    nft_plan="$work_dir/rules.nft"
    new_state="$work_dir/state"

    if ! ula_prefixes; then
        log "ERROR: network.globals.ula_prefix is missing or unsupported"
        rm -rf "$work_dir"
        return 1
    fi
    lan_dev=$(lan_device)
    if ! discover_paths "$paths"; then
        log "ERROR: no active WAN with an IPv6 delegated prefix; keeping current dataplane"
        rm -rf "$work_dir"
        return 1
    fi

    build_nft "$paths" "$nft_plan"
    if ! nft -c -f "$nft_plan"; then
        log "ERROR: generated nft transaction did not validate"
        rm -rf "$work_dir"
        return 1
    fi
    if ! prepare_paths "$paths"; then
        log "ERROR: failed to prepare IPv6 routes or policy rules"
        rm -rf "$work_dir"
        return 1
    fi
    if ! nft -f "$nft_plan"; then
        log "ERROR: nft transaction failed; existing table was left unchanged"
        rm -rf "$work_dir"
        return 1
    fi

    write_state "$paths" "$new_state"
    cleanup_previous_state "$new_state"
    mv "$new_state" "$STATE_FILE"
    mv "$nft_plan" "$NFT_FILE"
    rm -rf "$work_dir"
    log "applied $(awk -F '|' '$1 == "path" { count++ } END { print count+0 }' "$STATE_FILE") IPv6 WAN paths"
}

plan_config() {
    work_dir=$(mktemp -d /tmp/dreamingwrt-ipv6-mw-plan.XXXXXX) || return 1
    paths="$work_dir/paths"
    nft_plan="$work_dir/rules.nft"

    if ! ula_prefixes; then
        echo "network.globals.ula_prefix is missing or unsupported" >&2
        rm -rf "$work_dir"
        return 1
    fi
    lan_dev=$(lan_device)
    if ! discover_paths "$paths"; then
        echo "no active WAN with an IPv6 delegated prefix" >&2
        rm -rf "$work_dir"
        return 1
    fi
    build_nft "$paths" "$nft_plan"
    nft -c -f "$nft_plan" || {
        rm -rf "$work_dir"
        return 1
    }
    echo "--- paths ---"
    cat "$paths"
    echo "--- nft transaction ---"
    cat "$nft_plan"
    rm -rf "$work_dir"
}

stop_config() {
    nft delete table ip6 "$TABLE_NAME" 2>/dev/null
    while ip -6 rule del priority 2000 2>/dev/null; do :; done
    if [ -f "$STATE_FILE" ]; then
        old_lan_dev=$(awk -F '|' '$1 == "meta" { print $2; exit }' "$STATE_FILE")
        while IFS='|' read -r kind id logical ipv6_logical device table mark pd pd_mask snat; do
            [ "$kind" = path ] || continue
            delete_mark_rule $((1000 + id))
            delete_reject_rule "${pd}/64" "${old_lan_dev:-br-lan}"
            ip -6 route flush table "$table" 2>/dev/null
            ip -6 addr del "$snat/128" dev lo 2>/dev/null
        done < "$STATE_FILE"
    fi
    rm -f "$STATE_FILE" "$NFT_FILE"
    log "stopped"
}

status_config() {
    echo "--- runtime state ---"
    cat "$STATE_FILE" 2>/dev/null || true
    echo "--- snat66 ---"
    nft list table ip6 "$TABLE_NAME" 2>/dev/null || true
    echo "--- policy rules ---"
    ip -6 rule show
}

mkdir -p /var/run
exec 9>"$LOCK_FILE" || exit 1
if ! flock -w 30 9; then
    log "ERROR: timed out waiting for the apply lock"
    exit 1
fi

case "${1:-start}" in
    start|apply) apply_config ;;
    plan) plan_config ;;
    stop) stop_config ;;
    restart) stop_config && apply_config ;;
    status) status_config ;;
    *) echo "usage: $0 {start|apply|plan|stop|restart|status}" >&2; exit 2 ;;
esac
