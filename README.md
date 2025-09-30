# Network Packet Analysis Tool

A Python-based packet capture and analysis tool that manually parses network protocol headers from raw hexadecimal data using Scapy.

## Overview

This tool captures live network traffic and performs manual protocol parsing without relying on Scapy's built-in packet dissection. It supports multiple network protocols across all OSI layers, providing detailed field-level analysis.

## Supported Protocols

- **Layer 2:** Ethernet
- **Layer 3:** IPv4, IPv6, ARP
- **Layer 4:** ICMP, ICMPv6, TCP, UDP
- **Application:** DNS

## Features

- Manual hex parsing of protocol headers
- Multi-protocol support with automatic routing
- Berkeley Packet Filter (BPF) support for targeted capture
- Multi-interface capture capability
- IPv4 fragmentation handling
- TCP flag parsing
- DNS header analysis

## Requirements

- Python 3.10+
- Scapy
- psutil
- Root/Administrator privileges

## Installation

```bash
git clone https://github.com/ParthCv/Hex-Code-Dump-Packet-Analysis-.git
cd Hex-Code-Dump-Packet-Analysis-
pip install scapy psutil
```

## Usage

```bash
sudo python3 main.py -i <interface> -c <count> [-f <filter>]
```

### Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `-i, --interface` | Network interface (e.g., eth0, wlan0, any) | Yes |
| `-c, --count` | Number of packets to capture | Yes |
| `-f, --filter` | BPF filter expression | No |

### Examples

```bash
# Capture ARP packets
sudo python3 main.py -i any -c 1 -f arp

# Capture ICMP packets
sudo python3 main.py -i any -c 1 -f icmp

# Capture DNS traffic
sudo python3 main.py -i any -c 1 -f "udp and port 53"

# Capture TCP packets on specific interface
sudo python3 main.py -i eth0 -c 5 -f tcp

# Capture all traffic
sudo python3 main.py -i any -c 10
```

## Sample Output

```
Ethernet Header:
  Destination MAC:      a483e75dc46c         | a4:83:e7:5d:c4:6c
  Source MAC:           8c19b53ae74e         | 8c:19:b5:3a:e7:4e
  EtherType:            0800                 | 2048
IPv4 Header:
  Version:              4                    | 4
  Protocol:             11                   | 17
  Source IP:            c0a80152             | 192.168.1.82
  Destination IP:       08080808             | 8.8.8.8
UDP Header:
  Source Port:          ddef                 | 56815
  Destination Port:     0035                 | 53
DNS Header:
  Transaction ID:       9df9                 | 40441
  Flags:                0100                 | 256
```

## Project Structure

```
├── source/
│   ├── main.py              # Main capture logic
│   └── packet_parsers.py    # Protocol parsing functions
├── report/                  # Documentation (PDF)
├── pcap/                    # Sample captures
├── video/                   # Demonstration video
└── README.md
```

## Testing

Generate traffic for testing different protocols:

```bash
# ARP
sudo arping -c 1 192.168.1.1

# ICMP
ping -c 1 8.8.8.8

# UDP/DNS
nslookup google.com

# TCP
curl http://example.com
```

## Platform Support

- Linux (tested on Manjaro/Arch)
- macOS (limited IPv6 support)
- Windows (requires Npcap)

## Limitations

- Requires root/administrator privileges
- Does not reassemble fragmented packets
- Does not parse TCP options beyond basic header
- DNS question/answer sections not fully decoded

## Documentation

Complete documentation is available in the `report/` directory including:
- Design document with architecture and state diagrams
- User guide with detailed usage instructions
- Testing document with comprehensive test cases
