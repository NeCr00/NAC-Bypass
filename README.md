# NAC Bypass Toolkit

## Overview

This toolkit provides a robust method to bypass **Network Access Control (NAC)** in real-time environments by transparently intercepting and relaying traffic between a victim device and a switch using a bridging setup. It leverages two scripts:

- `nac_bypass_setup.sh`: Creates a transparent bridge, learns MAC/IP information, and configures ARP, ebtables, and iptables to impersonate the victim.
- `awareness.sh`: Monitors the physical link state of an interface and automatically resets or re-establishes the bridge when devices connect/disconnect.



## What Does It Do?

- Creates a **transparent Layer 2 bridge** between a switch and a victim machine.
- **Learns and impersonates** the victim’s IP/MAC address via passive packet capture (e.g. DHCP/SYN).
- **Redirects ports** to tools like `Responder` or `sshd` for attacks or access.
- Automatically **handles reconnections** if the link state changes.
- Supports **autonomous mode** for full automation and stealth.


## Deployment Architecture

```
[ Switch ] ←→ [ eth0 (Attacker) ] ←→ [ br0 (Transparent Bridge) ] ←→ [ eth1 (Victim) ]
```

- `eth0`: Connects to the switch (SWINT).
- `eth1`: Connects to the victim device (COMPINT).
- `br0`: Software bridge used to transparently pass traffic.
- The attacker can forward packets as if they are the victim.



## Setup

### Requirements

- Linux with `brctl`, `arptables`, `ebtables`, `iptables`, `tcpdump`, `macchanger`
- Root privileges
- Two physical NICs (eth0, eth1)
- Internet-disabled NAC environment (ideal)


## Usage

### Step 1: Make scripts executable

```bash
chmod +x nac_bypass_setup.sh awareness.sh
```

### Step 2: Run the `awareness.sh` script

```bash
# Executing NAC Bypass with default values
./awareness.sh

# Monitor a Specific Interface for Link Status
/awareness.sh -I <monitor_interface>

# Executing with specific parameters (optional parameters)
./awareness.sh -i <monitor_interface> -1 <switch_interface> -2 <victim_interface> [-R] [-S] [-g <switch_mac>]

```

### Arguments

| Flag | Description |
|------|-------------|
| `-I <iface>` | Interface to monitor for link state (e.g. eth0) |
| `-1 <iface>` | Interface connected to the switch |
| `-2 <iface>` | Interface connected to the victim |
| `-g <MAC>` | Manually specify gateway MAC address |
| `-R` | Enable Responder port redirection |
| `-S` | Enable OpenSSH port redirection and start the service |

## Resetting Configuration
In case of any issue which sets the trasparent bridge to unstable state, try to reset the configuration and try again

```bash
./nac_bypass_setup.sh -r
```

