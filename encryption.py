import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
import base64
from tkinter import messagebox

def generate_key(password, salt):
    """
    Generates a secure encryption key using PBKDF2 with a given password and salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_folder(folder_path, password):
    """
    Encrypts all files within the specified folder using AES encryption in CFB mode.
    Displays a popup confirmation message upon successful encryption.
    """
    if not os.path.isdir(folder_path):
        messagebox.showerror("Error", "Invalid folder path!")
        return

    # Generate a random salt for key derivation
    salt = urandom(16)

    # Derive the key from the password
    key = generate_key(password, salt)

    # Generate a random IV for the AES cipher
    iv = urandom(16)

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                data = f.read()

            # Encrypt the file data
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()

            # Save the encrypted data along with the salt and IV
            with open(file_path, 'wb') as f:
                f.write(salt + iv + encrypted_data)

    # Show a popup confirmation message
    messagebox.showinfo("Success", f"Folder '{folder_path}' has been successfully encrypted.")

def decrypt_folder(folder_path, password):
    """
    Decrypts all files within the specified folder using AES decryption in CFB mode.
    Displays a popup confirmation message upon successful decryption.
    """
    if not os.path.isdir(folder_path):
        messagebox.showerror("Error", "Invalid folder path!")
        return

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                # Read the salt, IV, and encrypted data
                file_data = f.read()
                salt = file_data[:16]
                iv = file_data[16:32]
                encrypted_data = file_data[32:]

            # Derive the key from the password and extracted salt
            key = generate_key(password, salt)

            # Decrypt the file data
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Save the decrypted data
            with open(file_path, 'wb') as f:
                f.write(data)

    # Show a popup confirmation message
    messagebox.showinfo("Success", f"Folder '{folder_path}' has been successfully decrypted.")