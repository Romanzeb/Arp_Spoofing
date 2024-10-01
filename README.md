# ARP Spoofing Detection Script

This Python script monitors ARP (Address Resolution Protocol) traffic to detect potential ARP spoofing attacks. It uses the `scapy` library to sniff ARP packets and track IP-MAC pairs. If a mismatch is detected in an IP's associated MAC address, it raises an alert indicating possible ARP spoofing.

## Features
- Monitors ARP packets on the network.
- Tracks known IP-MAC mappings.
- Detects changes in IP-MAC pairs.
- Alerts in real-time when possible ARP spoofing is detected.

## Requirements
- Python 3.x
- `scapy` library

## Installation
1. Clone this repository:
    ```bash
    git clone https://github.com/Romanzeb/Arp_Spoofing.git
    ```
2. Install the required dependencies:
    ```bash
    pip install scapy
    ```

## Usage
Run the script with administrator/root privileges to sniff network traffic:
```bash
sudo python3 arp_spoof_detection.py
