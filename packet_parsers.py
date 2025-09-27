def parse_ethernet_header(hex_data):
    """
    Parse Ethernet frame header from hex data.

    Args:
        hex_data (str): Complete packet hex dump starting with Ethernet header

    Returns:
        tuple: (ether_type, payload) ether_type is the EtherType field and payload is the remaining hex dump
    """

    # Extract the MAC addresses and the ether type
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    # print("hex dump")
    # print(hex_data)
    # print()

    # Display the Ethernet Header fields
    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        parse_arp_header(payload)
    elif ether_type == "0800": # IPv4
        parse_ipv4_header(payload)
    elif ether_type == "86dd": # IPv6
        parse_ipv6_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


def parse_arp_header(hex_data):
    """
        Parse ARP (Address Resolution Protocol) header from hex dump.

        Args:
            hex_data (str): Hex dump containing ARP header (28+ bytes)
    """

    hardware_type = int(hex_data[:4], 16)  # Hardware type (bytes 0-1): 1 = Ethernet
    protocol_type = int(hex_data[4:8], 16)  # Protocol type (bytes 2-3): 0x0800 = IPv4
    hardware_size = int(hex_data[8:10], 16)  # Hardware address size (byte 4): 6 for MAC
    protocol_size = int(hex_data[10:12], 16)  # Protocol address size (byte 5): 4 for IPv4
    opcode = int(hex_data[12:16], 16)  # Operation code (bytes 6-7): 1=request, 2=reply

    # Extract MAC and IP addresses
    sender_mac_hex = hex_data[16:28]  # Sender MAC (bytes 8-13)
    sender_mac = ':'.join(sender_mac_hex[i:i + 2] for i in range(0, 12, 2)) # Format MAC address

    sender_ip_hex = hex_data[28:36]  # Sender IP address (bytes 14-17)
    sender_ip_ints_list = [str(int(sender_ip_hex[i:i + 2], 16)) for i in range(0, 8, 2)] # Format MAC address in ints
    sender_ip = '.'.join(sender_ip_ints_list)

    target_mac_hex = hex_data[36:48]  # Target MAC address (bytes 18-23)
    target_mac = ':'.join(target_mac_hex[i:i + 2] for i in range(0, 12, 2)) # Format MAC address

    target_ip_hex = hex_data[48:56]  # Target IP address (bytes 24-27)
    target_ip_ints_list = [str(int(target_ip_hex[i:i + 2], 16)) for i in range(0, 8, 2)] # Format MAC address in ints
    target_ip = '.'.join(target_ip_ints_list)

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {opcode}")
    print(f"  {'Sender MAC:':<25} {sender_mac_hex:<20} | {sender_mac}")
    print(f"  {'Sender IP:':<25} {sender_ip_hex:<20} | {sender_ip}")
    print(f"  {'Target MAC:':<25} {target_mac_hex:<20} | {target_mac}")
    print(f"  {'Target IP:':<25} {target_ip_hex:<20} | {target_ip}")
    print(f"")


def parse_ipv4_header(hex_data):
    """
    Parse IPv4 header from hex dump and route to next protocol layer (ICMP, TCP, UDP).

    Args:
        hex_data (str): Hex dump containing IPv4 header (20+ bytes)
    """
    # Parse IPv4 header fields (minimum 20 bytes)
    version = int(hex_data[0], 16)  # Version field (first 4 bits): should be 4
    header_length = int(hex_data[1], 16) * 4  # Header length (next 4 bits) * 4 = bytes
    total_length = int(hex_data[4:8], 16)  # Total packet length (bytes 2-3)
    identification = int(hex_data[8:12], 16)  # Fragment identification (bytes 4-5)

    # Parse fragmentation flags and offset (bytes 6-7)
    flags_and_fragment = int(hex_data[12:16], 16)
    reserved_flag = (flags_and_fragment >> 15) & 1  # Reserved bit (must be 0)
    df_flag = (flags_and_fragment >> 14) & 1  # Don't Fragment flag
    mf_flag = (flags_and_fragment >> 13) & 1  # More Fragments flag
    fragment_offset = flags_and_fragment & 0x1FFF  # Fragment offset (13 bits)

    protocol = int(hex_data[18:20], 16)  # Next protocol (byte 9): 1=ICMP, 6=TCP, 17=UDP

    source_ip_hex = hex_data[24:32]  # Source IP (bytes 12-15)
    source_ip_ints_list = [str(int(source_ip_hex[i:i + 2], 16)) for i in range(0, 8, 2)] # Format IP address to ints
    source_ip = '.'.join(source_ip_ints_list)

    destination_ip_hex = hex_data[32:40]  # Destination IP (bytes 16-19)
    destination_ip_ints_list = [str(int(destination_ip_hex[i:i + 2], 16)) for i in range(0, 8, 2)] # Format IP address to ints
    destination_ip = '.'.join(destination_ip_ints_list)

    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {hex_data[0]:<20} | {version}")
    print(f"  {'Header Length:':<25} {hex_data[1]:<20} | {header_length}")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Flags & Frag Offset:':<25} {hex_data[12:16]:<20} | {flags_and_fragment}")
    print(f"    {'Reserved:':<10} {reserved_flag:<20}")
    print(f"    {'DF (Do not Fragment):':<10} {df_flag:<20}")
    print(f"    {'MF (More Fragments):':<10} {mf_flag:<20}")
    print(f"    {'Fragment Offset:':<10} {hex(fragment_offset):<1} | {fragment_offset}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Source IP:':<25} {hex_data[24:32]:<20} | {source_ip}")
    print(f"  {'Destination IP:':<25} {hex_data[32:40]:<20} | {destination_ip}")

    payload = hex_data[header_length * 2:] # length in bytes * 2 hex chars per byte

    # Route to next protocol layer based on protocol field
    if protocol == 1: # ICMP
        parse_icmp_header(payload)
    elif protocol == 6: # TCP
        parse_tcp_header(payload)
    elif protocol == 17: # UDP
        parse_udp_header(payload)
    else:
        print(f"  {'Unknown Protocol:':<25} {protocol:<20}")
        print("  No parser available for this Protocol.")


def parse_icmp_header(hex_data):
    """
        Parse ICMP (Internet Control Message Protocol) header from hex dump.

        Args:
            hex_data (str): Hex dump containing ICMP header (8+ bytes)
    """

    icmp_type = int(hex_data[0:2], 16)  # ICMP message type (byte 0): 0=reply, 8=request
    icmp_code = int(hex_data[2:4], 16)  # ICMP message code (byte 1): provides additional context
    checksum = int(hex_data[4:8], 16)  # Checksum (bytes 2-3): error detector

    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {hex_data[0:2]:<20} | {icmp_type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {icmp_code}")
    print(f"  {'Checksum:':<25} {hex_data[4:8]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {hex_data[8:]:<20}")


def parse_tcp_header(hex_data):
    """
    Parse TCP (Transmission Control Protocol) header from hex dump.

    Args:
        hex_data (str): Hex dump containing TCP header (20+ bytes)
    """

    source_port = int(hex_data[0:4], 16)  # Source port (bytes 0-1)
    destination_port = int(hex_data[4:8], 16)  # Destination port (bytes 2-3)
    sequence_number = int(hex_data[8:16], 16)  # Sequence number (bytes 4-7)
    acknowledgement_number = int(hex_data[16:24], 16)  # Acknowledgment number (bytes 8-11)

    data_offset = int(hex_data[24], 16) * 4  # Data offset (upper 4 bits) * 4 = header length
    reserved = int(hex_data[25], 16)  # Reserved field (lower 4 bits): should be 0

    ns_flag = (flags >> 0) & 1  # NS flag (bit 8 of flags field)
    cwr_flag = (flags >> 7) & 1  # CWR flag
    ece_flag = (flags >> 6) & 1  # ECE flag
    urg_flag = (flags >> 5) & 1  # URG flag
    ack_flag = (flags >> 4) & 1  # ACK flag
    psh_flag = (flags >> 3) & 1  # PSH flag
    rst_flag = (flags >> 2) & 1  # RST flag
    syn_flag = (flags >> 1) & 1  # SYN flag
    fin_flag = flags & 1  # FIN flag

    window_size = int(hex_data[28:32], 16)  # Window size (bytes 14-15): flow control
    checksum = int(hex_data[32:36], 16)  # Checksum (bytes 16-17): error detector
    urgent_pointer = int(hex_data[36:40], 16)  # Urgent pointer (bytes 18-19): points to urgent data

    print(f"TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[0:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Sequence Number:':<25} {hex_data[8:16]:<20} | {sequence_number}")
    print(f"  {'Acknowledgement Number:':<25} {hex_data[16:24]:<20} | {acknowledgement_number}")
    print(f"  {'Data Offset:':<25} {hex_data[24]:<20} | {data_offset} bytes")
    print(f"  {'Reserved:':<25} {hex_data[25]:<20} | {reserved}")
    print(f"  {'Flags:':<25} {hex_data[26:28]:<20} | {flags}")
    print(f"    {'NS:':<10} {ns_flag:<20}")
    print(f"    {'CRW:':<10} {cwr_flag:<20}")
    print(f"    {'ECE:':<10} {ece_flag:<20}")
    print(f"    {'URG:':<10} {urg_flag:<20}")
    print(f"    {'ACK:':<10} {ack_flag:<20}")
    print(f"    {'PSH:':<10} {psh_flag:<20}")
    print(f"    {'RST:':<10} {rst_flag:<20}")
    print(f"    {'SYN:':<10} {syn_flag:<20}")
    print(f"    {'FIN:':<10} {fin_flag:<20}")
    print(f"  {'Windows Size:':<25} {hex_data[28:32]:<20} | {window_size}")
    print(f"  {'Checksum:':<25} {hex_data[32:36]:<20} | {checksum}")
    print(f"  {'Urgent Pointer:':<25} {hex_data[36:40]:<20} | {urgent_pointer}")
    print(f"  {'Payload (hex):':<25} {hex_data[40:]:<20}")


def parse_udp_header(hex_data):
    """
        Parse UDP (User Datagram Protocol) header from hex dump.

        Args:
            hex_data (str): Hex dump containing UDP header (8+ bytes)
    """

    source_port = int(hex_data[0:4], 16)       # Source port (bytes 0-1)
    destination_port = int(hex_data[4:8], 16)  # Destination port (bytes 2-3)
    length = int(hex_data[8:12], 16)           # UDP length (bytes 4-5): header + data
    checksum = int(hex_data[12:16], 16)        # Checksum (bytes 6-7): error detection

    print(f"UDP Header:")
    print(f"  {'Source Port:':<25} {hex_data[0:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Length:':<25} {hex_data[8:12]:<20} | {length}")
    print(f"  {'Checksum:':<25} {hex_data[12:16]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {hex_data[16:]:<20}")

    # if either the source or destination port is 53 then this is DNS traffic
    if source_port == 53 or destination_port == 53:
        parse_dns_header(hex_data[16:])


def parse_dns_header(hex_data):
    """
    Parse DNS (Domain Name System) header from hex dump.

    Args:
        hex_data (str): Hex dump containing DNS (12+ bytes)
    """
    transaction_id = int(hex_data[0:4], 16)  # Transaction ID (bytes 0-1): matches query/response
    flags = int(hex_data[4:8], 16)  # Flags field (bytes 2-3): various control bits

    qr = (flags >> 15) & 1  # QR bit: 0=query, 1=response
    opcode = (flags >> 11) & 0xF # Opcode (4 bits): operation type
    aa = (flags >> 10) & 1 # AA bit: authoritative answer
    tc = (flags >> 9) & 1 # TC bit: truncated message
    rd = (flags >> 8) & 1 # RD bit: recursion desired
    ra = (flags >> 7) & 1 # RA bit: recursion available
    rcode = flags & 0xF # RCODE (4 bits): response code

    question = int(hex_data[8:12], 16) # Questions count (bytes 4-5)
    answer_rrs = int(hex_data[12:16], 16) # Answer RRs count (bytes 6-7)
    authority_rrs = int(hex_data[16:20], 16) # Authority RRs count (bytes 8-9)
    additional_rrs = int(hex_data[20:24], 16) # Additional RRs count (bytes 10-11)

    print("DNS Header:")
    print(f"  {'Transaction ID:':<25} {hex_data[0:4]:<20} | {transaction_id}")
    print(f"  {'Flags:':<25} {hex_data[4:8]:<20} | {flags}")
    print(f"    {'QR (Query/Response):':<10} {qr:<20}")
    print(f"    {'Opcode:':<10} {opcode:<20}")
    print(f"    {'AA (Auth Answer):':<10} {aa:<20}")
    print(f"    {'TC (Truncated):':<10} {tc:<20}")
    print(f"    {'RD (Recursion Des):':<10} {rd:<20}")
    print(f"    {'RA (Recursion Avail):':<10} {ra:<20}")
    print(f"    {'Response Code:':<10} {rcode:<20}")
    print(f"  {'Questions:':<25} {hex_data[8:12]:<20} | {question}")
    print(f"  {'Answer RRs:':<25} {hex_data[12:16]:<20} | {answer_rrs}")
    print(f"  {'Authority RRs:':<25} {hex_data[16:20]:<20} | {authority_rrs}")
    print(f"  {'Additional RRs:':<25} {hex_data[20:24]:<20} | {additional_rrs}")
    print(f"  {'Payload (hex):':<25} {hex_data[24:]:<20}")


def parse_icmpv6_header(hex_data):
    """
        Parse ICMPv6 (Internet Control Message Protocol version 6) header from hex dump.

        Args:
            hex_data (str): Hex dump containing ICMPv6 header (8+ bytes)
    """

    icmp6_type = int(hex_data[0:2], 16)  # ICMP message type (byte 0): 0=reply, 8=request
    icmp6_code = int(hex_data[2:4], 16)  # ICMP message code (byte 1): provides additional context
    checksum = int(hex_data[4:8], 16)  # Checksum (bytes 2-3): error detector

    print(f"ICMP6 Header:")
    print(f"  {'Type:':<25} {hex_data[0:2]:<20} | {icmp6_type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {icmp6_code}")
    print(f"  {'Checksum:':<25} {hex_data[4:8]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {hex_data[8:]:<20}")

def parse_ipv6_header(hex_data):
    """
        Parse IPv6 header from hex dump and route to next protocol layer.

        Args:
            hex_data (str): Hex dump containing IPv6 header (40 bytes fixed)
    """
    version = int(hex_data[0], 16)  # Version (first 4 bits): should be 6
    payload_length = int(hex_data[8:12], 16) # Payload length (bytes 4-5): without IPv6 header
    next_header = int(hex_data[12:14], 16)  # Next header (byte 6): 6=TCP, 17=UDP, 58=ICMPv6
    hop_limit = int(hex_data[14:16], 16)  # Hop limit (byte 7): TTL

    source_ipv6_hex = hex_data[16:48]  # Source IPv6 address (bytes 8-23)
    source_ipv6 = ":".join(source_ipv6_hex[i:i + 4] for i in range(0, 32, 4))  # Format

    destination_ipv6_hex = hex_data[48:80]  # Destination IPv6 address (bytes 24-39)
    destination_ipv6 = ":".join(destination_ipv6_hex[i:i + 4] for i in range(0, 32, 4)) # Format

    print(f"IPv6 Header:")
    print(f"  {'Version:':<25} {hex_data[0]:<20} | {version}")
    print(f"  {'Payload Length:':<25} {hex_data[8:12]:<20} | {payload_length}")
    print(f"  {'Next Header:':<25} {hex_data[12:14]:<20} | {next_header}")
    print(f"  {'Hop Limit:':<25} {hex_data[14:16]:<20} | {hop_limit}")
    print(f"  {'Source IP':<25} {hex_data[16:48]:<20} | {source_ipv6}")
    print(f"  {'Destination IP:':<25} {hex_data[48:80]:<20} | {destination_ipv6}")

    payload = hex_data[80:]

    if next_header == 58:  # ICMPv6
        parse_icmpv6_header(payload)
    elif next_header == 6:  # TCP
        parse_tcp_header(payload)
    elif next_header == 17:  # UDP
        parse_udp_header(payload)
    else:
        print(f"  {'Unknown Next Header:':<25} {next_header:<20}")
