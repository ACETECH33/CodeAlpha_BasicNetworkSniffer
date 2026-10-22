# BasicNetworkSniffer

CodeAlpha Cyber Security, by Ayorinde Ashogbon: a basic network sniffer in Python using `scapy`.

## Features
- Live packet capture (TCP, UDP, ICMP, ARP, IPv4/IPv6)
- Shows source/destination IPs, protocol, ports, TCP flags, length
- Optional payload preview and DNS query names
- BPF filters, packet count limit, save to `.pcap` (open in Wireshark)

## Setup
```
pip install scapy
```
Windows also needs [Npcap](https://npcap.com). Run with admin/root privileges.

## Usage
```
sudo python3 sniffer.py                      # sniff everything
sudo python3 sniffer.py -i eth0 -c 50        # 50 packets on eth0
sudo python3 sniffer.py -f "tcp port 80" --payload
sudo python3 sniffer.py -o capture.pcap
```

## How it works
`scapy.sniff()` reads raw frames from the interface. Each frame is layered
(Ethernet > IP > TCP/UDP/ICMP > payload). The program inspects each layer
with `haslayer()`, extracts fields, and prints a summary. Seeing the layers
separately shows how data is encapsulated as it moves through the network.

## Ethical use
Capture only on networks you own or have written permission to monitor.
