import logging
from scapy.all import sniff, IP
from network_sniffer.network_packet import NetworkPacket  # Import the NetworkPacket class

# Disable scapy's verbose logging to keep the output clean
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def ip_in_range(ip, start_ip, end_ip):
    """Check if an IP is within a given range."""
    ip_parts = list(map(int, ip.split('.')))
    start_parts = list(map(int, start_ip.split('.')))
    end_parts = list(map(int, end_ip.split('.')))
    return start_parts <= ip_parts <= end_parts

def packet_handler(packet, start_ip, end_ip):
    """
    Processes each captured packet.
    Only processes packets where the source or destination IP is in the given range.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if ip_in_range(src_ip, start_ip, end_ip) or ip_in_range(dst_ip, start_ip, end_ip):
            # Create a NetworkPacket object to represent the captured packet
            network_packet = NetworkPacket(data=bytes(packet))
            print(f"Captured Packet: {network_packet}")

def capture_packets(start_ip, end_ip, interface=None, packet_count=0):
    """
    Sniffs packets on a specific network interface and filters by a range of IP addresses.
    """
    print(f"Starting packet capture on interface: {interface or 'default'}")
    print(f"Capturing packets from IP range: {start_ip} to {end_ip}")

    # Capture packets and process only those within the IP range
    sniff(
        iface=interface,         # Interface to sniff on (None means default)
        prn=lambda pkt: packet_handler(pkt, start_ip, end_ip),  # Pass the packet to the handler
        count=packet_count,      # Number of packets to capture (0 = infinite)
        store=False              # Don't store packets in memory (saves RAM)
    )
 