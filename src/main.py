import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QLineEdit, QPushButton
from PyQt5.uic import loadUi
from PyQt5.QtCore import pyqtSlot

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
    ui_path = os.path.join(os.path.dirname(__file__), "ui", "ui_main.ui")
    if not os.path.exists(ui_path):
        QMessageBox.critical(None, "Error", f"UI file not found: {ui_path}")
        sys.exit(1)

    try:
        loadUi(ui_path, main_window)
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to load UI file: {e}")
        sys.exit(1)

    # Step 5: Show the main window
    main_window.show()

    # Step 6: Get references to the widgets in the UI
    start_ip_input = main_window.findChild(QLineEdit, "start_ip_input")  # Input for starting IP
    end_ip_input = main_window.findChild(QLineEdit, "end_ip_input")  # Input for ending IP
    scan_button = main_window.findChild(QPushButton, "scan_button")  # Scan button

    # Step 7: Connect the scan button to the start_scan function
    scan_button.clicked.connect(lambda: start_scan(start_ip_input, end_ip_input, capture_packets, get_all_packets))

    # Step 8: Run the application event loop
    sys.exit(app.exec_())

@pyqtSlot()
def start_scan(start_ip_input, end_ip_input, capture_packets, get_all_packets):
    """
    This function is triggered when the 'Scan' button is clicked. It retrieves the IP addresses
    from the input fields and starts the packet sniffing process.
    """
    # Get the IP addresses from the input fields
    start_ip = start_ip_input.text()
    end_ip = end_ip_input.text()

    # Validate IP addresses (simple check)
    if not start_ip or not end_ip:
        QMessageBox.warning(None, "Input Error", "Please enter both start and end IP addresses.")
        return

    # Start the packet capture
    print(f"Starting packet capture from {start_ip} to {end_ip}...")
    capture_packets(start_ip=start_ip, end_ip=end_ip, interface=None, packet_count=0)

    # Display the results (optional)
    packets = get_all_packets()
    print("Packets stored in the database:")
    for packet in packets:
        print(packet)

if __name__ == "__main__":
    main()
