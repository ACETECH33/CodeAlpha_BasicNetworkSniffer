#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer
Author: Ayorinde Ashogbon

Captures live packets with scapy and prints source/destination IPs,
protocol, ports, and a payload preview.

Run only on networks you own or have permission to monitor.
Requires administrator/root privileges (and Npcap on Windows).

Usage examples:
    sudo python3 sniffer.py
    sudo python3 sniffer.py -i eth0 -c 50
    sudo python3 sniffer.py -f "tcp port 80" --payload
    sudo python3 sniffer.py -o capture.pcap
"""

import argparse
import sys
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
captured = []
counter = {"total": 0}
args = None


def payload_preview(packet, limit=64):
    """Return a printable preview of the packet payload."""
    if not packet.haslayer(Raw):
        return ""
    data = bytes(packet[Raw].load)[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def describe(packet):
    """Build a one-packet summary string, or None if not handled."""
    ts = datetime.now().strftime("%H:%M:%S")
    lines = []

    if packet.haslayer(ARP):
        arp = packet[ARP]
        op = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
        lines.append(f"[{ts}] ARP {op}: {arp.psrc} ({arp.hwsrc}) -> {arp.pdst}")
        return "\n".join(lines)

    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.proto, f"OTHER({ip.proto})")
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        src, dst = ip6.src, ip6.dst
        proto = PROTO_NAMES.get(ip6.nh, f"OTHER({ip6.nh})")
    else:
        return None

    header = f"[{ts}] {proto} {src} -> {dst}"

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        header += f" | ports {tcp.sport} -> {tcp.dport} | flags {tcp.flags}"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        header += f" | ports {udp.sport} -> {udp.dport}"
    elif packet.haslayer(ICMP):
        header += f" | type {packet[ICMP].type} code {packet[ICMP].code}"

    header += f" | len {len(packet)}"
    lines.append(header)

    if packet.haslayer(DNS) and packet[DNS].qd is not None:
        qname = packet[DNS].qd.qname
        qname = qname.decode(errors="replace") if isinstance(qname, bytes) else str(qname)
        lines.append(f"    DNS query: {qname}")

    if args.payload:
        preview = payload_preview(packet)
        if preview:
            lines.append(f"    Payload: {preview}")

    return "\n".join(lines)


def handle(packet):
    counter["total"] += 1
    summary = describe(packet)
    if summary:
        print(summary)
    if args.output:
        captured.append(packet)


def main():
    global args
    parser = argparse.ArgumentParser(description="Basic network sniffer (scapy)")
    parser.add_argument("-i", "--iface", help="interface to sniff on (default: scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0, help="stop after N packets (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="", help='BPF filter, e.g. "tcp port 80"')
    parser.add_argument("--payload", action="store_true", help="show a payload preview")
    parser.add_argument("-o", "--output", help="save capture to a .pcap file")
    args = parser.parse_args()

    print("Sniffing started. Press Ctrl+C to stop.")
    try:
        sniff(
            iface=args.iface,
            filter=args.filter or None,
            prn=handle,
            count=args.count,
            store=False,
        )
    except PermissionError:
        sys.exit("Permission denied. Run as administrator/root.")
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\nCaptured {counter['total']} packets.")
        if args.output and captured:
            wrpcap(args.output, captured)
            print(f"Saved to {args.output}")


if __name__ == "__main__":
    main()
