<div align="center">

# NAC Bypass

### Transparent-bridge Network Access Control Bypass

<br>

[![Version](https://img.shields.io/badge/version-3.1-blue.svg?style=for-the-badge)](./nac_bypass.sh)
[![Bash](https://img.shields.io/badge/bash-5.x-1f425f.svg?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-linux-FCC624.svg?style=for-the-badge&logo=linux&logoColor=black)](https://www.kernel.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](#license)
[![Status](https://img.shields.io/badge/status-production-brightgreen.svg?style=for-the-badge)](#)

<br>

<img width="1024" height="559" alt="83139aef-6216-4873-bac2-f4ee23a92eba" src="https://github.com/user-attachments/assets/dc84b336-59e5-4b1c-baad-2ced186cfd15" />


<sub><i>One Linux box. Two NICs. Inherit the workstation's NAC session.</i></sub>

</div>

## Overview

`nac_bypass.sh` turns a Linux laptop with two Ethernet NICs into a **transparent
Layer-2 bridge** between an authorized workstation and its switch port. The
workstation's 802.1X / MAC-auth session stays alive through the bridge, while
the attacking host masquerades its own outbound traffic as the workstation —
egressing the wire with the workstation's MAC and IP.

Tools running on the attacking host (`nmap`, `NetExec`, `Impacket`, `smbclient`,
`responder`, `evil-winrm`, …) reach internal hosts as the workstation; replies
are reverse-NAT'd by conntrack and delivered to the local stack instead of being
forwarded on to the workstation.

## Architecture

```text

   ┌──────────────┐     ┌─────────────────────────────────┐     ┌────────────┐
   │              │     │   Attacker host (this machine)  │     │            │
   │              │     │                                 │     │            │
   │   Switch     │◄───►│  eth0 ─┐                ┌─ eth1 │◄───►│ Workstation│
   │  (802.1X /   │     │        │   nacbr0       │       │     │            │
   │   MAC-auth)  │     │        ├──[ bridge ]────┤       │     │            │
   │              │     │        │   STP off      │       │     │            │
   └──────────────┘     │        │   EAPOL fwd    │       │     └────────────┘
                        │        │                │       │
                        │      [ebtables nat]     │       │
                        │      [iptables nat]     │       │
                        │      [conntrack]        │       │
                        │                                 │
                        │  Local stack ──► br0 ──► SNAT ──┼──► out as workstation
                        │  Local stack ◄── DNAT ◄── br0 ◄─┼──── replies (conntrack)
                        │                                 │
                        └─────────────────────────────────┘

```

The workstation's frames pass through unchanged (preserving its NAC session).
The host's own packets get SNAT'd at L2 and L3 so they appear on the wire as
the workstation; their replies are reverse-NAT'd back to the host's stack
instead of being bridged on to the workstation.



## Requirements

| Component | Why |
|---|---|
| Linux kernel ≥ 4.x | `br_netfilter`, `nf_conntrack`, modern bridge |
| `iproute2` (`ip`) | Bridge + neighbor + route management |
| `iptables`, `ebtables` | NAT layers (legacy or `-nft` compat shim both fine) |
| `tcpdump` | Passive learning |
| `macchanger` | Bridge MAC alignment |
| Two physical Ethernet NICs | `eth0` to switch, `eth1` to workstation |
| Root | Bridge + netfilter + sysctl require it |

Optional: `nmcli` (NM unmanage), `arptables`, `Responder`, `openssh-server`.

```bash
sudo apt-get install iproute2 tcpdump macchanger ebtables iptables
```



## Installation

```bash
git clone https://github.com/yourname/nac-bypass.git
cd nac-bypass
chmod +x nac_bypass.sh
```

No build step. Single self-contained Bash script.



## Usage

```text
nac_bypass.sh [options]
```

### Common workflows

```bash
# Full pipeline: bridge + masquerade + monitor loop. Ctrl+C to stop and clean up.
sudo ./nac_bypass.sh -R -S

# Custom NIC names
sudo ./nac_bypass.sh -1 enp1s0 -2 enp2s0

# Pin the gateway MAC if passive learning can't see it
sudo ./nac_bypass.sh -g aa:bb:cc:dd:ee:ff

# Cleanup a prior run (also recovers from SIGKILL / power loss)
sudo ./nac_bypass.sh -r
```

### Options

| Flag | Argument | Description |
|------|----------|-------------|
| `-1` | `<iface>` | NIC plugged into the switch (default: `eth0`) |
| `-2` | `<iface>` | NIC plugged into the workstation (default: `eth1`) |
| `-b` | `<name>` | Bridge name (default: `nacbr0`) |
| `-I` | `<iface>` | Link-state monitor interface (default: same as `-2`) |
| `-g` | `<mac>` | Pin gateway MAC manually |
| `-d` | `<ip>` | Primary DNS (default: `1.1.1.1`) |
| `-D` | `<ip>` | Secondary DNS (default: `8.8.8.8`; `''` to disable) |
| `-m` | `<num>` | Default-route metric for our bridge route (default: `0`) |
| `-t` | `<secs>` | Passive-learning timeout (default: `45`) |
| `-R` |  | Enable Responder port redirection (NetBIOS / LLMNR / SMB / HTTP / …) |
| `-S` |  | Enable sshd redirection and start the service |
| `-r` |  | Reset / cleanup any prior run and exit |
| `-v` |  | Verbose (DEBUG logs) |
| `-a` |  | Autonomous mode (no interactive prompts) |
| `-h` |  | Help |

### Running offensive tools

The script prints a banner once the bridge is armed; run your tools in a
**second terminal**. The default route via the bridge has metric 0, so most
kernel-socket tools just work. For raw-socket tools, pin the source explicitly:

```bash
nmap   -e nacbr0 -S 169.254.66.66 -sT -p- 10.0.0.0/24
nmap   -e nacbr0 -S 169.254.66.66 -Pn -sS 10.0.0.0/24
ping   -I nacbr0 10.0.0.1
curl   --interface nacbr0 http://10.0.0.50/
netexec smb 10.0.0.0/24 -u alice -p 'Hunter2!'
impacket-secretsdump alice@10.0.0.5
responder -I nacbr0      # if -R was supplied
```


## How it works

| Step | What the script does |
|------|----------------------|
| 1. Preflight | Root, binaries, `br_netfilter`, `nf_conntrack`, NIC availability, no bridge collision, NM conflicts. Aborts cleanly on failure. |
| 2. Host lockdown | Stops NM/networkd/wpa_supplicant, marks NICs unmanaged, disables NTP/IPv6, snapshots sysctls + resolv.conf + default routes. |
| 3. Bridge build | Creates `nacbr0` (STP off), enables EAPOL forwarding, installs egress lock on `-o nacbr0`, then enslaves both NICs in promiscuous mode. |
| 4. Passive learning | Captures ARP / DHCP / SYN traffic in parallel; the first reliable channel wins. Refuses to proceed without both victim and gateway info. |
| 5. Masquerade | Ebtables L2 SNAT (`SWMAC → COMPMAC`), iptables L3 SNAT (`BRIP → COMIP:high-port`), static neighbor entry for the fictional bridge gateway, additive default route. |
| 6. Monitor | Polls the link every 5s; tears down NAT on stable down, re-arms on stable up. |
| 7. Cleanup | Reverses every change keyed off state-dir markers. Restores NICs, sysctls, services, default routes, NM-managed state. |

All bypass NAT rules live in dedicated `NACBYPASS_OUT` / `NACBYPASS_IN` /
`NACBYPASS` chains — cleanup deletes only those, leaving any operator-installed
firewall, container, or VPN rules untouched.



## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `br_netfilter is not available` | Kernel module missing or disabled | `modprobe br_netfilter`; check `CONFIG_BRIDGE_NETFILTER=y` |
| `Could not learn ... in 45s` | Workstation idle | Increase timeout: `-t 120`, or wait for it to send traffic |
| `... but not gateway info` | No ARP/DHCP traffic seen for the gateway | Pin manually: `-g aa:bb:cc:dd:ee:ff` |
| Tools work but get no replies | `bridge-nf-call-iptables=0` or `nf_conntrack` not loaded | Both are mandatory; preflight enforces them |
| Replies go to wrong NIC | Operator has a lower-metric default route | Use `-m 0` (default) and/or pin tools with `-e nacbr0 -S 169.254.66.66` |
| Workstation drops auth briefly | Hundreds-of-ms gap during bridge enslavement | Acceptable; most NACs tolerate it |



## Disclaimer

This software is provided for **authorized security testing and educational
purposes only**. Use it only on networks and systems for which you have
explicit, written permission to test. The authors and contributors assume no
liability and are not responsible for any misuse or damage caused by this
program. Unauthorized use against systems you do not own may violate local,
state, or federal law.


