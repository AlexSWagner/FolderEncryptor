import os
import sys
import logging
from core.key_manager import KeyManager
from core.encryptor import FileEncryptor
from core.folder_handler import FolderEncryptor
from core.protector import FolderProtector

class CLI:
    def __init__(self):
        self.key_manager = KeyManager()
        self.file_encryptor = FileEncryptor(self.key_manager)
        self.folder_encryptor = FolderEncryptor(self.file_encryptor)
        self.protector = FolderProtector()
        self.logger = logging.getLogger(__name__)
    
    def print_progress_bar(self, percent, current_file=None):
        """Print a progress bar to the console"""
        bar_length = 50
        filled_length = int(bar_length * percent // 100)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        
        # Truncate filename if too long
        if current_file:
            max_len = 40
            if len(current_file) > max_len:
                current_file = '...' + current_file[-(max_len-3):]
        
        sys.stdout.write(f'\r[{bar}] {percent}% {current_file or ""}')
        sys.stdout.flush()
        
        if percent == 100:
            print()  # New line after completion
    
    def run(self):
        """Run the command-line interface"""
        while True:
            print("\nFolder Security Suite")
            print("=== Encryption ===")
            print("1. Generate new key")
            print("2. Generate password-based key")
            print("3. Load existing key")
            print("4. Encrypt a folder")
            print("5. Decrypt a folder")
            print("6. Encrypt a single file")
            print("7. Decrypt a single file")
            print("=== 7z Protection ===")
            print("8. Set protection password")
            print("9. Protect a folder")
            print("10. Unprotect an archive")
            print("=== Other ===")
            print("11. Exit")
            
            choice = input("Enter your choice (1-11): ")
            
            # Encryption options
            if choice == '1':
                self.key_manager.generate_key()
                print("New random key generated successfully.")
                
            elif choice == '2':
                password = input("Enter a strong password: ")
                confirm = input("Confirm password: ")
                if password != confirm:
                    print("Passwords don't match!")
                    continue
                self.key_manager.generate_key(password)
                print("New password-based key generated successfully.")
                
            elif choice == '3':
                try:
                    use_password = input("Is this a password-based key? (y/n): ").lower() == 'y'
                    if use_password:
                        password = input("Enter your password: ")
                        self.key_manager.load_key(password)
                    else:
                        self.key_manager.load_key()
                    print("Key loaded successfully.")
                except Exception as e:
                    print(f"Error loading key: {str(e)}")
                    
            elif choice == '4':
                if self.key_manager.key is None:
                    print("Please load or generate a key first.")
                    continue
                    
                folder_path = input("Enter the folder path to encrypt: ")
                if not os.path.exists(folder_path):
                    print(f"Folder not found: {folder_path}")
                    continue
                    
                extensions = input("Enter file extensions to encrypt (comma-separated, leave empty for all): ")
                ext_list = [ext.strip() for ext in extensions.split(',')] if extensions else None
                
                exclude = input("Enter directories to exclude (comma-separated, leave empty for none): ")
                exclude_list = [dir.strip() for dir in exclude.split(',')] if exclude else None
                
                backup = input("Create backups of files before encryption? (y/n): ").lower() == 'y'
                
                print(f"Starting encryption of {folder_path}...")
                count = self.folder_encryptor.encrypt_folder(
                    folder_path, ext_list, exclude_list, backup, self.print_progress_bar
                )
                print(f"Encryption complete. Successfully processed {count} files.")
                
            elif choice == '5':
                if self.key_manager.key is None:
                    print("Please load or generate a key first.")
                    continue
                    
                folder_path = input("Enter the folder path to decrypt: ")
                if not os.path.exists(folder_path):
                    print(f"Folder not found: {folder_path}")
                    continue
                    
                extensions = input("Enter file extensions to decrypt (comma-separated, leave empty for all): ")
                ext_list = [ext.strip() for ext in extensions.split(',')] if extensions else None
                
                exclude = input("Enter directories to exclude (comma-separated, leave empty for none): ")
                exclude_list = [dir.strip() for dir in exclude.split(',')] if exclude else None
                
                print(f"Starting decryption of {folder_path}...")
                count = self.folder_encryptor.decrypt_folder(
                    folder_path, ext_list, exclude_list, self.print_progress_bar
                )
                print(f"Decryption complete. Successfully processed {count} files.")
                
            elif choice == '6':
                if self.key_manager.key is None:
                    print("Please load or generate a key first.")
                    continue
                    
                file_path = input("Enter the file path to encrypt: ")
                if not os.path.isfile(file_path):
                    print(f"File not found: {file_path}")
                    continue
                    
                backup = input("Create backup before encryption? (y/n): ").lower() == 'y'
                
                success = self.file_encryptor.encrypt_file(file_path, backup)
                if success:
                    print(f"File encrypted successfully: {file_path}")
                else:
                    print(f"Failed to encrypt file: {file_path}")
                    
            elif choice == '7':
                if self.key_manager.key is None:
                    print("Please load or generate a key first.")
                    continue
                    
                file_path = input("Enter the file path to decrypt: ")
                if not os.path.isfile(file_path):
                    print(f"File not found: {file_path}")
                    continue
                    
                success = self.file_encryptor.decrypt_file(file_path)
                if success:
                    print(f"File decrypted successfully: {file_path}")
                else:
                    print(f"Failed to decrypt file: {file_path}")
            
            # 7z Protection options
            elif choice == '8':
                password = input("Enter protection password: ")
                confirm = input("Confirm password: ")
                if password != confirm:
                    print("Passwords don't match!")
                    continue
                self.protector.set_password(password)
                print("Protection password set successfully.")
                
            elif choice == '9':
                if not self.protector.password:
                    print("Please set a protection password first.")
                    continue
                    
                folder_path = input("Enter the folder path to protect: ")
                if not os.path.exists(folder_path):
                    print(f"Folder not found: {folder_path}")
                    continue
                    
                delete_original = input("Delete original folder after protection? (y/n): ").lower() == 'y'
                
                compression_level = 3  # Default
                try:
                    level_input = input("Enter compression level (0-9, default is 3): ")
                    if level_input:
                        compression_level = int(level_input)
                        if compression_level < 0 or compression_level > 9:
                            print("Invalid compression level. Using default (3).")
                            compression_level = 3
                except ValueError:
                    print("Invalid compression level. Using default (3).")
                
                if self.protector.protect_folder(folder_path, delete_original, compression_level):
                    print(f"Folder protected: {folder_path}.7z")
                else:
                    print("Failed to protect folder")
                    
            elif choice == '10':
                if not self.protector.password:
                    print("Please set a protection password first.")
                    continue
                    
                archive_path = input("Enter the path of the protected archive: ")
                if not os.path.exists(archive_path) and not os.path.exists(archive_path + '.7z'):
                    print(f"Archive not found: {archive_path}")
                    continue
                    
                extract_path = input("Enter extraction path (leave empty for default): ")
                extract_path = extract_path if extract_path else None
                
                if self.protector.unprotect_folder(archive_path, extract_path):
                    if extract_path:
                        print(f"Folder unprotected: {extract_path}")
                    else:
                        print(f"Folder unprotected: {os.path.splitext(archive_path)[0]}_decrypted")
                else:
                    print("Failed to unprotect folder")
                    
            elif choice == '11':
                print("Exiting the application")
                break
                
            else:
                print("Invalid choice. Please try again.")
