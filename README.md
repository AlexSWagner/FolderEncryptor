# Secure Folder Encryptor

A desktop application that provides secure folder encryption using AES encryption with PBKDF2 key derivation and unique salt generation.

## Features
- Folder encryption/decryption using password-based security
- User-friendly GUI interface
- Real-time progress tracking
- Secure cryptographic implementation
- Password confirmation and validation

## Requirements
- Python 3.x
- tkinter (included with Python)
- cryptography >= 41.0.1

To install required package:
pip install cryptography

## Usage
1. Run the application
2. Select a folder to encrypt/decrypt
3. Enter a secure password
4. Choose to either encrypt or decrypt the folder

## Security Features
- AES encryption
- PBKDF2 key derivation (100,000 iterations)
- Unique salt generation for each operation
- No stored keys - everything derived from password
