from scapy.all import sniff
from database import save_packet  # Import save_packet to store captured packets
from datetime import datetime

def packet_callback(packet):
    """
    Callback function to handle each captured packet.
    """
    data = str(packet)  # Convert the packet to a string representation
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Current timestamp

    print(f"Captured packet: {data} at {timestamp}")

    # Save the captured packet to the database
    save_packet(data, timestamp)

def capture_packets(start_ip, end_ip, interface=None, packet_count=0):
    """
    Capture network packets and save them to the database.
    """
    print(f"Starting packet capture on interface: {interface or 'default'}")
    print(f"Capturing packets from IP range: {start_ip} to {end_ip}...")

    # Start sniffing packets
    sniff(
        iface=interface,  # Network interface to listen on
        prn=packet_callback,  # Callback function for each packet
        count=packet_count if packet_count > 0 else 10  # Limit or infinite packets
    )

    print("Finished capturing packets.")
