import sqlite3

def init_db():
    """
    Initialize the SQLite database and ensure the packets table is correctly structured.
    """
    connection = sqlite3.connect("antivirus.db")
    cursor = connection.cursor()

    # Create the packets table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            data TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            timestamp TEXT,
            is_malicious BOOLEAN DEFAULT 0
        )
    ''')

    # Ensure the 'is_malicious' column exists (if not, add it)
    try:
        cursor.execute('SELECT is_malicious FROM packets LIMIT 1')
    except sqlite3.OperationalError:
        cursor.execute('ALTER TABLE packets ADD COLUMN is_malicious BOOLEAN DEFAULT 0')

    # Ensure the necessary columns exist (source_ip, destination_ip, and timestamp)
    cursor.execute('PRAGMA table_info(packets)')
    columns = [column[1] for column in cursor.fetchall()]
    
    # Add columns if they are missing
    if 'source_ip' not in columns:
        cursor.execute('ALTER TABLE packets ADD COLUMN source_ip TEXT')
    if 'destination_ip' not in columns:
        cursor.execute('ALTER TABLE packets ADD COLUMN destination_ip TEXT')
    if 'timestamp' not in columns:
        cursor.execute('ALTER TABLE packets ADD COLUMN timestamp TEXT')

    connection.commit()
    connection.close()
    print("Database initialized successfully.")


def save_packet(data, source_ip, destination_ip, timestamp, is_malicious=False):
    """
    Save a network packet to the database.
    """
    try:
        connection = sqlite3.connect("antivirus.db")
        cursor = connection.cursor()

        cursor.execute('''
            INSERT INTO packets (data, source_ip, destination_ip, timestamp, is_malicious)
            VALUES (?, ?, ?, ?, ?)
        ''', (data, source_ip, destination_ip, timestamp, is_malicious))
        connection.commit()
        connection.close()
        print(f"Packet saved successfully. Malicious: {is_malicious}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def get_all_packets():
    """
    Retrieve all packets from the database.
    :return: A list of tuples representing packets.
    """
    try:
        connection = sqlite3.connect("antivirus.db")
        cursor = connection.cursor()

        cursor.execute('SELECT data, source_ip, destination_ip, timestamp, is_malicious FROM packets')
        packets = cursor.fetchall()
        connection.close()
        return packets
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def get_malicious_packets():
    """
    Retrieve all packets flagged as malicious from the database.
    """
    try:
        connection = sqlite3.connect("antivirus.db")
        cursor = connection.cursor()

        cursor.execute('SELECT data, source_ip, destination_ip, timestamp FROM packets WHERE is_malicious = 1')
        malicious_packets = cursor.fetchall()
        connection.close()
        return malicious_packets
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def clear_packets():
    """
    Clear all entries in the packets table.
    """
    try:
        connection = sqlite3.connect("antivirus.db")
        cursor = connection.cursor()

        cursor.execute('DELETE FROM packets')
        connection.commit()
        connection.close()
        print("All packets cleared successfully.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

