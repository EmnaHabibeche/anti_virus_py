import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QLineEdit, QPushButton, QTableView
from PyQt5.uic import loadUi
from PyQt5.QtCore import pyqtSlot, QTimer
from PyQt5.QtSql import QSqlDatabase, QSqlTableModel
import sqlite3

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    from src.network_sniffer.sniffer import capture_packets  # Import the capture function
    from src.database import init_db, get_all_packets  # Import database functions

    init_db()

    app = QApplication(sys.argv)
    main_window = QMainWindow()

    ui_path = os.path.join(os.path.dirname(__file__), "ui", "ui_main.ui")
    if not os.path.exists(ui_path):
        QMessageBox.critical(None, "Error", f"UI file not found: {ui_path}")
        sys.exit(1)

    try:
        loadUi(ui_path, main_window)
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Failed to load UI file: {e}")
        sys.exit(1)

    main_window.show()

    start_ip_input = main_window.findChild(QLineEdit, "start_ip_input")  # Input for starting IP
    end_ip_input = main_window.findChild(QLineEdit, "end_ip_input")  # Input for ending IP
    scan_button = main_window.findChild(QPushButton, "scan_button")  # Scan button
    table_view = main_window.findChild(QTableView, "table_view")  # Table view for displaying packets

    # Set up the table view and get the model
    model = setup_table_view(table_view)

    # Connect the scan button to start_scan
    scan_button.clicked.connect(lambda: start_scan(start_ip_input, end_ip_input, capture_packets, model))

    sys.exit(app.exec_())

def setup_table_view(table_view):
    """
    This function sets up the QSqlTableModel and connects it to the QTableView.
    """
    # Create a connection to the SQLite database
    db = QSqlDatabase.addDatabase('QSQLITE')
    db.setDatabaseName('antivirus.db')

    if not db.open():
        QMessageBox.critical(None, "Database Error", "Failed to open the database.")
        return None

    # Clear the packets table at the start
    conn = sqlite3.connect('antivirus.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM packets")
    conn.commit()
    conn.close()

    # Create the table model and set the table name
    model = QSqlTableModel()
    model.setTable('packets')
    model.setEditStrategy(QSqlTableModel.OnFieldChange)  # Allows editing in the table
    model.select()  # Initialize with no data

    # Set the model on the QTableView
    table_view.setModel(model)

    return model

@pyqtSlot()
def start_scan(start_ip_input, end_ip_input, capture_packets, model):
    """
    Triggered when the 'Scan' button is clicked.
    Starts packet sniffing and refreshes the table view periodically.
    """
    start_ip = start_ip_input.text()
    end_ip = end_ip_input.text()

    if not start_ip or not end_ip:
        QMessageBox.warning(None, "Input Error", "Please enter both start and end IP addresses.")
        return

    # Clear the table before starting the scan
    conn = sqlite3.connect('antivirus.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM packets")
    conn.commit()
    conn.close()
    model.select()

    # Start packet capture in a separate thread (non-blocking)
    from threading import Thread
    def run_sniffer():
        capture_packets(start_ip=start_ip, end_ip=end_ip, interface=None, packet_count=0)
    sniffer_thread = Thread(target=run_sniffer, daemon=True)
    sniffer_thread.start()

    # Refresh the table model periodically
    timer = QTimer()
    timer.timeout.connect(model.select)
    timer.start(1000)

    QMessageBox.information(None, "Scan Started", "Packet capture started successfully.")
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

if __name__ == "__main__":
    main()


