# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

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
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)
    protocol_type = int(hex_data[4:8], 16)
    hardware_size = int(hex_data[8:10], 16)
    protocol_size = int(hex_data[10:12], 16)
    opcode = int(hex_data[12:16], 16)
    sender_mac_hex = hex_data[16:28]
    sender_mac = ':'.join(sender_mac_hex[i:i+2] for i in range(0, 12, 2))
    sender_ip_hex = hex_data[28:36]
    sender_ip_ints_list = [str(int(sender_ip_hex[i:i+2],16)) for i in range(0, 8, 2)]
    sender_ip = '.'.join(sender_ip_ints_list)
    target_mac_hex = hex_data[36:48]
    target_mac = ':'.join(target_mac_hex[i:i+2] for i in range(0, 12, 2))
    target_ip_hex = hex_data[48:56]
    target_ip_ints_list = [str(int(target_ip_hex[i:i+2],16)) for i in range(0, 8, 2)]
    target_ip = '.'.join(target_ip_ints_list)


    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Opcode:':<25} {hex_data[12:16]:<20} | {opcode}")
    print(f"  {'Sender Mac address:':<25} {sender_mac_hex:<20} | {sender_mac}")
    print(f"  {'Sender IP address:':<25} {sender_ip_hex:<20} | {sender_ip}")
    print(f"  {'Target Mac address:':<25} {target_mac_hex:<20} | {target_mac}")
    print(f"  {'Target IP address:':<25} {target_ip_hex:<20} | {target_ip}")
    print(f"")

def parse_ipv4_header(hex_data):
    version = int(hex_data[0], 16)
    header_length = int(hex_data[1], 16) * 4
    total_length = int(hex_data[4:8], 16)
    identification =  int(hex_data[8:12], 16)
    flags_and_fragment = int(hex_data[12:16], 16)
    # add the reserved, df, mf and fragment offset flags
    reserved_flag = (flags_and_fragment >> 15) & 1
    df_flag = (flags_and_fragment >> 14) & 1
    mf_flag = (flags_and_fragment >> 13) & 1
    fragment_offset = flags_and_fragment & 0x1FFF

    protocol = int(hex_data[18:20], 16)

    source_ip_hex = hex_data[24:32]
    source_ip_ints_list = [str(int(source_ip_hex[i:i+2], 16)) for i in range(0, 8, 2)]
    source_ip = '.'.join(source_ip_ints_list)

    destination_ip_hex = hex_data[32:40]
    destination_ip_ints_list = [str(int(destination_ip_hex[i:i+2], 16)) for i in range(0, 8, 2)]
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

    payload = hex_data[header_length * 2:]

    if protocol == 1:
        parse_icmp_header(payload)
    elif protocol == 6:
        parse_tcp_header(payload)
    elif protocol == 17:
        parse_udp_header(payload)
    else:
        print(f"  {'Unknown Protocol:':<25} {protocol:<20}")
        print("  No parser available for this Protocol.")

def parse_icmp_header(hex_data):
    icmp_type = int(hex_data[0:2], 16)
    icmp_code = int(hex_data[2:4], 16)
    checksum = int(hex_data[4:8], 16)

    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {hex_data[0:2]:<20} | {icmp_type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {icmp_code}")
    print(f"  {'Checksum:':<25} {hex_data[4:8]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {hex_data[8:]:<20}")

def parse_tcp_header(hex_data):
    source_port = int(hex_data[0:4], 16)
    destination_port = int(hex_data[4:8], 16)
    sequence_number = int(hex_data[8:16], 16)
    acknowledgement_number = int(hex_data[16:24], 16)

    data_offset_flags = int(hex_data[24:26], 16) * 4

    flags = int(hex_data[26:28], 16)

    ns_flag = (flags >> 8) & 1  # NS flag (bit 8 of flags field)
    cwr_flag = (flags >> 7) & 1  # CWR flag
    ece_flag = (flags >> 6) & 1  # ECE flag
    urg_flag = (flags >> 5) & 1  # URG flag
    ack_flag = (flags >> 4) & 1  # ACK flag
    psh_flag = (flags >> 3) & 1  # PSH flag
    rst_flag = (flags >> 2) & 1  # RST flag
    syn_flag = (flags >> 1) & 1  # SYN flag
    fin_flag = flags & 1  # FIN flag

    window_size = int(hex_data[28:32], 16)
    checksum = int(hex_data[32:36], 16)

    urgent_pointer = int(hex_data[36:40], 16)

    print(f"TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[0:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Sequence Number:':<25} {hex_data[8:16]:<20} | {sequence_number}")
    print(f"  {'Acknowledgement Number:':<25} {hex_data[16:24]:<20} | {acknowledgement_number}")
    print(f"  {'Data Offset:':<25} {hex_data[24:26]:<20} | {data_offset_flags}")
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
    source_port = int(hex_data[0:4], 16)
    destination_port = int(hex_data[4:8], 16)
    length = int(hex_data[8:12], 16)
    checksum = int(hex_data[12:16], 16)

    print(f"UDP Header:")
    print(f"  {'Source Port:':<25} {hex_data[0:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Length:':<25} {hex_data[8:12]:<20} | {length}")
    print(f"  {'Checksum:':<25} {hex_data[12:16]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {hex_data[16:]:<20}")
