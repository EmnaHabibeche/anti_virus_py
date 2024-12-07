import logging
from scapy.all import sniff, IP

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
            print(f"Captured Packet: {packet.summary()}")

def capture_packets(start_ip, end_ip, interface=None, packet_count=0):
    """
    Sniffs packets on a specific network interface and filters by a range of IP addresses.

    Args:
    - start_ip (str): The starting IP address of the range.
    - end_ip (str): The ending IP address of the range.
    - interface (str): The network interface to sniff on (e.g., 'eth0', 'wlan0'). 
                       If None, it will use the default interface.
    - packet_count (int): Number of packets to capture. If 0, it captures indefinitely.

    Returns:
    - None
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

if __name__ == "__main__":
    # Get user input for IP range
    start_ip = input("Enter the starting IP address (e.g., 192.168.1.1): ")
    end_ip = input("Enter the ending IP address (e.g., 192.168.1.255): ")
    
    # Start capturing packets
    capture_packets(start_ip=start_ip, end_ip=end_ip, interface=None, packet_count=0)  # Infinite capture

