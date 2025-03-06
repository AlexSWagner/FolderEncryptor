# Folder Encryption Suite

A secure application for encrypting and protecting folders with password-based encryption and 7z archive protection.

## Features

- Encrypt folders with strong AES-256 encryption
- Password-based key derivation for secure encryption
- Progress tracking during encryption and decryption operations
- 7z archive protection for additional security
- Modern graphical user interface

## Running the Application

### Option 1: Using the Batch File (Recommended for Windows Users)

1. Make sure you have Python 3.6+ installed on your system
2. Install the required dependencies:
   ```
   pip install cryptography py7zr tkinter
   ```
3. Double-click the `run_folder_encryption.bat` file to start the application

### Option 2: Running Directly with Python

1. Make sure you have Python 3.6+ installed on your system
2. Install the required dependencies:
   ```
   pip install cryptography py7zr tkinter
   ```
3. Run the application:
   ```
   python main.py
   ```

## Antivirus False Positives

If you create an executable using PyInstaller, you may encounter antivirus warnings (such as "Trojan:Win32/Wacatac.B!ml"). This is a common false positive with PyInstaller-generated executables and not an actual virus.

For most users, I recommend using the batch file method described above, which avoids these issues entirely.

## Usage Instructions

1. **Encryption Tab**:
   - Select a folder to encrypt
   - Enter a strong password
   - Choose whether to delete the original folder after encryption
   - Click "Encrypt Folder"

2. **7z Protection Tab**:
   - Select a folder to protect
   - Enter a password for the 7z archive
   - Choose compression level
   - Click "Create Protected Archive"

## Security Notes

- Always use strong, unique passwords
- Keep your encryption passwords safe - if lost, encrypted data cannot be recovered
- The application does not store your passwords anywhere 
