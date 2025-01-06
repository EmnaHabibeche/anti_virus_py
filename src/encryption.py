from cryptography.fernet import Fernet

def generate_key():
    """
    Generate a key and save it into a file for later use.
    """
    key = Fernet.generate_key()
    with open("encryption.key", "wb") as key_file:
        key_file.write(key)
    print("Encryption key generated and saved.")

def load_key():
    """
    Load the previously generated key.
    """
    with open("encryption.key", "rb") as key_file:
        return key_file.read()

def encrypt_file(file_path):
    """
    Encrypt a file using the loaded encryption key.
    """
    key = load_key()
    cipher_suite = Fernet(key)

    # Read the file's contents
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Encrypt the data
    encrypted_data = cipher_suite.encrypt(file_data)

    # Overwrite the file with encrypted data
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

    print(f"File encrypted: {file_path}")

def decrypt_file(file_path):
    """
    Decrypt a file using the loaded encryption key.
    """
    key = load_key()
    cipher_suite = Fernet(key)

    # Read the encrypted file's contents
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    # Decrypt the data
    decrypted_data = cipher_suite.decrypt(encrypted_data)

    # Overwrite the file with decrypted data
    with open(file_path, "wb") as file:
        file.write(decrypted_data)

    print(f"File decrypted: {file_path}")

