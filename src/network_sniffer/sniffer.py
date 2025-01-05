from scapy.all import sniff
from database import save_packet  # Import save_packet to store captured packets
from datetime import datetime
from scapy.layers.inet import IP

def packet_callback(packet):
    """
    Callback function to handle each captured packet.
    """
    data = str(packet)  # Convert the packet to a string representation
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Current timestamp

    # Extract IP details from the packet
    source_ip = packet[IP].src if IP in packet else "Unknown"
    destination_ip = packet[IP].dst if IP in packet else "Unknown"

    print(f"Captured packet: {data} at {timestamp}")

    # Save the captured packet to the database
    save_packet(data, source_ip, destination_ip, timestamp)


def analyze_packet(packet):
    """
    Analyze a captured packet for potential viruses using the EICAR test signature.
    """
    EICAR_SIGNATURE = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    # Example: Extract payload from the packet (update based on actual packet structure)
    payload = bytes(packet.payload)

    # Check if the EICAR signature exists in the payload
    if EICAR_SIGNATURE.encode() in payload:
        return True
    return False


def capture_packets(start_ip, end_ip, interface=None, packet_count=0):
    """
    Capture packets in a specified IP range and analyze them.
    """
    def packet_callback(packet):
        try:
            # Extract IP details from the packet
            source_ip = packet[IP].src if IP in packet else "Unknown"
            destination_ip = packet[IP].dst if IP in packet else "Unknown"
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            data = str(packet)

            # Analyze the packet for EICAR signature
            is_malicious = analyze_packet(packet)

            # Save the packet to the database
            save_packet(data, source_ip, destination_ip, timestamp, is_malicious)
            print(f"Captured packet: {packet.summary()} at {timestamp}")
        except Exception as e:
            print(f"Error processing packet: {e}")

    print(f"Starting packet capture on interface: {interface}")
    sniff(prn=packet_callback, iface=interface, count=packet_count, store=False)
    print("Finished capturing packets.")
