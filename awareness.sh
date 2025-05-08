#!/bin/bash

############### 1. defaults ###################################################
INTERFACE="eth0"
STATE_INTERFACE=0
STATE_COUNTER=0
THRESHOLD_UP=3                 # 3 × 5 s = 15 s stable carrier-up
THRESHOLD_DOWN=5               # 5 × 5 s = 25 s stable carrier-down
TIMER="5s"

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
COMMON_OPTS=()                 # options forwarded to nac_bypass_setup.sh

############### 2. purge previous logs ########################################
rm -f "$(pwd)"/nac_bypass_setup.log 2>/dev/null || true

############### 3. usage / arg-parsing ########################################
Usage() {
  cat <<EOF
Usage: $0 [-I iface] [OTHER-OPTIONS]

  -I iface        Interface to monitor for link state (default: eth0)
  Any other flag  Is passed straight through to nac_bypass_setup.sh:
                   -1 <eth>     network interface plugged into switch (default: eth0)
                   -2 <eth>     network interface plugged into victim machine (default: eth1)
                   -g <MAC>     set swutch MAC address (GWMAC) manually (optional)
                   -R           enable port redirection for Responder.py (optional)
                   -S           enable port redirection for OpenSSH and start the service (optional)

Example:
  $0 -I eth0 -R -S -g aa:bb:cc:dd:ee:ff
EOF
  exit 0
}

# Parse options
while getopts ":I:h1:2:acg:rRS" opt; do
  case "$opt" in
    I)  INTERFACE="$OPTARG" ;;
    h)  Usage ;;
    *)  # Forward all other options and their arguments
        COMMON_OPTS+=("-$opt")
        if [[ "$OPTARG" && "$OPTARG" != -* ]]; then
          COMMON_OPTS+=("$OPTARG")
        fi
        ;;
  esac
done
shift $((OPTIND-1))
COMMON_OPTS+=("$@")

echo "[*] Monitoring link on $INTERFACE ; forwarding opts: ${COMMON_OPTS[*]}"

############### 4. helper to call setup script ################################
call_setup() {
  case "$1" in
    init)  bash "$SCRIPT_DIR/nac_bypass_setup.sh" -a -i "${COMMON_OPTS[@]}" ;;
    conn)  bash "$SCRIPT_DIR/nac_bypass_setup.sh" -a -c "${COMMON_OPTS[@]}" ;;
    reset) bash "$SCRIPT_DIR/nac_bypass_setup.sh" -a -r;;
  esac
}

############### 5. first initialisation #######################################
echo "[*] Resetting previous configuration and initialising..."
call_setup reset
sleep 1s
call_setup init

############### 6. main loop ##################################################
while true; do
  NETWORK_STATE_INTERFACE=$(cat "/sys/class/net/$INTERFACE/carrier" 2>/dev/null || echo 0)

  if (( NETWORK_STATE_INTERFACE != STATE_INTERFACE )); then
    STATE_COUNTER=0
    if (( NETWORK_STATE_INTERFACE == 1 )); then
      echo "[!] $INTERFACE is now UP"
    else
      echo "[!] $INTERFACE is now DOWN"
    fi
  else
    if (( STATE_COUNTER == THRESHOLD_UP && NETWORK_STATE_INTERFACE == 1 )); then
      echo "[!!] Stable UP – running ConnectionSetup"
      call_setup conn
    elif (( STATE_COUNTER == THRESHOLD_DOWN && NETWORK_STATE_INTERFACE == 0 )); then
      echo "[!!] Stable DOWN – resetting"
      call_setup reset
      sleep 1s
      echo "Resetting settings and re-initialising..."
      call_setup init
    fi
    ((STATE_COUNTER++))
  fi

  STATE_INTERFACE=$NETWORK_STATE_INTERFACE
  sleep $TIMER
done
