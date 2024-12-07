from network_sniffer.sniffer import capture_packets  # Import the capture function from sniffer.py

def main():
    """
    Main entry point for the packet sniffing application.
    """
    print("Starting packet capture...")

    # Get user input for IP range
    start_ip = input("Enter the starting IP address (e.g., 192.168.1.1): ")
    end_ip = input("Enter the ending IP address (e.g., 192.168.1.255): ")
    
    # Start capturing packets (default interface and infinite capture)
    capture_packets(start_ip=start_ip, end_ip=end_ip, interface=None, packet_count=0)

if __name__ == "__main__":
    main()  # Run the main function when the script is executed
