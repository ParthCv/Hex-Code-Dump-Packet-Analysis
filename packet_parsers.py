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
