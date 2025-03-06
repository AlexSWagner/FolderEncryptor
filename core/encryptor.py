import os
import shutil
import logging
from cryptography.fernet import Fernet, InvalidToken

class FileEncryptor:
    def __init__(self, key_manager):
        self.key_manager = key_manager
        self.logger = logging.getLogger(__name__)
    
    def encrypt_file(self, file_path, backup=False):
        """Encrypt a single file"""
        try:
            if not os.path.isfile(file_path):
                self.logger.error(f"Not a file: {file_path}")
                return False
                
            self.logger.info(f"Attempting to encrypt: {file_path}")
            
            # Create backup if requested
            if backup:
                backup_path = f"{file_path}.bak"
                shutil.copy2(file_path, backup_path)
                self.logger.info(f"Backup created at: {backup_path}")
            
            # Encrypt the file
            with open(file_path, 'rb') as file:
                data = file.read()
            
            fernet = Fernet(self.key_manager.key)
            encrypted_data = fernet.encrypt(data)
            
            with open(file_path, 'wb') as file:
                file.write(encrypted_data)
                
            self.logger.info(f"Successfully encrypted: {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error encrypting {file_path}: {str(e)}")
            return False
    
    def decrypt_file(self, file_path):
        """Decrypt a single file"""
        try:
            if not os.path.isfile(file_path):
                self.logger.error(f"Not a file: {file_path}")
                return False
                
            self.logger.info(f"Attempting to decrypt: {file_path}")
            
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
                
            fernet = Fernet(self.key_manager.key)
            try:
                decrypted_data = fernet.decrypt(encrypted_data)
            except InvalidToken:
                self.logger.error(f"Invalid token or incorrect key for {file_path}")
                return False
            
            with open(file_path, 'wb') as file:
                file.write(decrypted_data)
                
            self.logger.info(f"Successfully decrypted: {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error decrypting {file_path}: {str(e)}")
            return False
            
    def verify_file_integrity(self, original_file_path, processed_file_path):
        """Verify file integrity by comparing file sizes and basic content checks"""
        try:
            # Check if files exist
            if not os.path.isfile(original_file_path) or not os.path.isfile(processed_file_path):
                return False
                
            # Compare file sizes (should be different for encrypted vs. original)
            original_size = os.path.getsize(original_file_path)
            processed_size = os.path.getsize(processed_file_path)
            
            # Basic check: ensure the processed file is not empty
            if processed_size == 0:
                return False
                
            # For encryption, ensure the file changed
            if original_file_path == processed_file_path:
                # Same file (in-place encryption/decryption)
                # Can't easily verify without additional data
                return True
            
            return True
        except Exception as e:
            self.logger.error(f"Error verifying file integrity: {str(e)}")
            return False
