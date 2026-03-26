# PENSTATION — Simple LAN Scanner

Minimal network scanner for Raspberry Pi 3B+ running Kali Linux.
Discovers devices on the local network using ARP scan (fast) with nmap fallback.

## Install

```bash
sudo apt update && sudo apt install -y arp-scan nmap
git clone <repo-url> && cd penstation
```

## Usage

```bash
# basic scan
sudo python3 scanner.py

# save results to scan_results.json
sudo python3 scanner.py --save

# continuous scanning every 30 seconds
sudo python3 scanner.py --loop

# continuous scanning every 10 seconds
sudo python3 scanner.py --loop 10
```

`sudo` is required for ARP scanning.

## Output example

```
 Found 5 device(s) on the local network
======================================================================
 IP Address        MAC Address         Vendor/Hostname
 ----------------  -----------------   ------------------------------
 192.168.1.1       AA:BB:CC:DD:EE:FF   TP-Link router
 192.168.1.42      11:22:33:44:55:66   raspberrypi
======================================================================
```
