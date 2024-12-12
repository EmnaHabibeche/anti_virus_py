import sqlite3

def init_db():
    """
    Initialize the SQLite database and create the packets table.
    """
    connection = sqlite3.connect("antivirus.db")
    cursor = connection.cursor()

    # Create the packets table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT,
            timestamp TEXT
        )
    ''')
    connection.commit()
    connection.close()
    print("Database initialized successfully.")

def save_packet(data, timestamp):
    """
    Save a network packet to the database.
    :param data: The raw data of the packet.
    :param timestamp: The timestamp when the packet was captured.
    """
    connection = sqlite3.connect("antivirus.db")
    cursor = connection.cursor()

    cursor.execute('''
        INSERT INTO packets (data, timestamp)
        VALUES (?, ?)
    ''', (data, timestamp))
    connection.commit()
    connection.close()
    print("Packet saved successfully.")

def get_all_packets():
    """
    Retrieve all packets from the database.
    :return: A list of tuples representing packets.
    """
    connection = sqlite3.connect("antivirus.db")
    cursor = connection.cursor()

    cursor.execute('SELECT * FROM packets')
    packets = cursor.fetchall()
    connection.close()
    return packets
