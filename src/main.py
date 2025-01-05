import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QLineEdit, QPushButton, QTableView
from PyQt5.uic import loadUi
from PyQt5.QtCore import pyqtSlot, QTimer
from PyQt5.QtSql import QSqlDatabase, QSqlTableModel
import sqlite3
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os
import platform

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
    generate_report_button = main_window.findChild(QPushButton, "generate_report_button")  # Generate report button
    table_view = main_window.findChild(QTableView, "table_view")  # Table view for displaying packets

    # Set up the table view and get the model
    model = setup_table_view(table_view)

    # Connect the scan button to start_scan
    scan_button.clicked.connect(lambda: start_scan(start_ip_input, end_ip_input, capture_packets, model))

    # Connect the generate report button to the generate_report function
    generate_report_button.clicked.connect(lambda: generate_report_action(model))

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

def generate_report_action(model):
    """
    Generate the report when the 'Generate Report' button is clicked.
    """
    # Example: Get the data from the table model for the report
    detection_results = []
    for row in range(model.rowCount()):
        packet = model.record(row)
        detection_results.append(f"Packet {packet.value('id')}: {packet.value('source_ip')} -> {packet.value('destination_ip')}")

    analysis_summary = "This is a summary of the virus detection analysis."

    # Specify the file path where the report will be saved
    file_path = "antivirus_report.pdf"

    # Generate the report PDF
    generate_report(file_path, analysis_summary, detection_results)

    QMessageBox.information(None, "Report Generated", f"The report has been generated and saved as {file_path}.")

    # Open the PDF automatically
    if platform.system() == "Windows":
        os.startfile(file_path)
    elif platform.system() == "Darwin":  # macOS
        os.system(f"open {file_path}")
    else:  # Linux
        os.system(f"xdg-open {file_path}")

def generate_report(file_path, analysis_summary, detection_results):
    """
    Generate a PDF report summarizing the analysis and detection results.
    """
    c = canvas.Canvas(file_path, pagesize=letter)
    c.setFont("Helvetica", 12)

    # Title
    c.drawString(200, 750, "Rapport d'Analyse Antivirus")

    # Analysis Summary
    c.drawString(50, 700, f"Résumé de l'analyse: {analysis_summary}")

    # Detection Results
    y_position = 650
    c.drawString(50, y_position, "Résultats de détection :")
    for result in detection_results:
        y_position -= 20
        c.drawString(50, y_position, f"- {result}")

    # Save PDF
    c.save()

if __name__ == "__main__":
    main()


