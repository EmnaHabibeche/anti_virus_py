from network_sniffer.sniffer import capture_packets  # Import the capture function
from database import init_db, get_all_packets  # Import database functions

def main():
    """
    Main entry point for the packet sniffing application.
    """
    # Step 1: Initialize the database
    init_db()

    print("Starting packet capture...")

    # Step 2: Get user input for IP range
    start_ip = input("Enter the starting IP address (e.g., 192.168.1.1): ")
    end_ip = input("Enter the ending IP address (e.g., 192.168.1.255): ")

    # Step 3: Start capturing packets
    capture_packets(start_ip=start_ip, end_ip=end_ip, interface=None, packet_count=0)

    # Step 4: Display stored packets
    packets = get_all_packets()
    print("Packets stored in the database:")
    for packet in packets:
        print(packet)

if __name__ == "__main__":
    main()
