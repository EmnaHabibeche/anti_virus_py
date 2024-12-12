import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt5.uic import loadUi

# Step 1: Add the project root (anti folder) to Python's path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    # Import necessary modules from src
    from src.network_sniffer.sniffer import capture_packets  # Import the capture function
    from src.database import init_db, get_all_packets  # Import database functions

    """
    Main entry point for the packet sniffing application with a graphical interface.
    """

    # Step 2: Initialize the database
    init_db()

    # Step 3: Create the application and main window
    app = QApplication(sys.argv)
    main_window = QMainWindow()

    # Step 4: Load the UI file
    ui_path = os.path.join(os.path.dirname(__file__), "ui", "mainwindow.ui")
    if not os.path.exists(ui_path):
        QMessageBox.critical(
            None, "Error", f"UI file not found: {ui_path}"
        )
        sys.exit(1)

    try:
        loadUi(ui_path, main_window)
    except Exception as e:
        QMessageBox.critical(
            None, "Error", f"Failed to load UI file: {e}"
        )
        sys.exit(1)

    # Step 5: Show the main window
    main_window.show()

    # Optional: Connect signals and slots for UI interactions

    # Step 6: Run backend logic in parallel
    print("Starting packet capture...")

    # Step 6.1: Get user input for IP range
    start_ip = input("Enter the starting IP address (e.g., 192.168.1.1): ")
    end_ip = input("Enter the ending IP address (e.g., 192.168.1.255): ")

    # Step 6.2: Start capturing packets
    capture_packets(start_ip=start_ip, end_ip=end_ip, interface=None, packet_count=0)

    # Step 6.3: Display stored packets
    packets = get_all_packets()
    print("Packets stored in the database:")
    for packet in packets:
        print(packet)

    # Step 7: Run the application event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
