import os
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import logging

class KeyManager:
    def __init__(self, key_file_path='encryption_key.key'):
        self.key_file_path = key_file_path
        self.key = None
        self.logger = logging.getLogger(__name__)
        self.salt = None
    
    def generate_key(self):
        """Generate a random key"""
        key = Fernet.generate_key()
        
        # Store key info
        key_data = {
            'key': key.decode('utf-8'),
            'password_based': False
        }
        
        with open(self.key_file_path, 'w') as key_file:
            json.dump(key_data, key_file)
            
        self.key = key
        self.logger.info(f"New random key generated and saved as '{self.key_file_path}'")
        return True
    
    def generate_key_from_password(self, password):
        """Generate a key from a password"""
        if not password:
            self.logger.error("Password cannot be empty")
            return False
            
        # Derive key from password with salt
        self.salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Store salt and key info
        key_data = {
            'salt': base64.b64encode(self.salt).decode('utf-8'),
            'key': key.decode('utf-8'),
            'password_based': True
        }
        
        with open(self.key_file_path, 'w') as key_file:
            json.dump(key_data, key_file)
            
        self.key = key
        self.logger.info(f"New password-derived key generated and saved as '{self.key_file_path}'")
        return True
    
    def load_key(self, key_file_path=None):
        """Load a key from a file"""
        if key_file_path:
            self.key_file_path = key_file_path
            
        if not os.path.exists(self.key_file_path):
            self.logger.error(f"Key file not found: {self.key_file_path}")
            return False
            
        try:
            with open(self.key_file_path, 'r') as key_file:
                key_data = json.load(key_file)
                
            self.key = key_data['key'].encode('utf-8')
            
            # Load salt if password-based
            if key_data.get('password_based', False):
                self.salt = base64.b64decode(key_data['salt'])
                
            self.logger.info(f"Key loaded from '{self.key_file_path}'")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load key: {str(e)}")
            return False
