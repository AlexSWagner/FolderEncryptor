import os
import logging

class FolderEncryptor:
    def __init__(self, file_encryptor):
        self.file_encryptor = file_encryptor
        self.logger = logging.getLogger(__name__)
    
    def count_files(self, folder_path, file_extensions=None, exclude_dirs=None):
        """Count files in a folder that match the criteria"""
        if not os.path.exists(folder_path):
            return 0
            
        if exclude_dirs is None:
            exclude_dirs = []
            
        # Normalize file extensions (add dot if missing)
        if file_extensions:
            file_extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in file_extensions]
        
        count = 0
        for root, dirs, files in os.walk(folder_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                # Skip files with non-matching extensions if specified
                if file_extensions:
                    file_ext = os.path.splitext(file)[1].lower()
                    if file_ext not in file_extensions:
                        continue
                count += 1
        
        return count
    
    def process_folder(self, folder_path, operation, file_extensions=None, exclude_dirs=None, backup=False, progress_callback=None):
        """Process all files in a folder with the given operation
        
        Args:
            folder_path: Path to the folder to process
            operation: 'encrypt' or 'decrypt'
            file_extensions: List of file extensions to process (None for all)
            exclude_dirs: List of directory names to exclude
            backup: Whether to create backups of files before encryption
            progress_callback: Function to call with progress updates (receives percentage and current file)
        """
        if not os.path.exists(folder_path):
            self.logger.error(f"Folder not found: {folder_path}")
            return 0
            
        if exclude_dirs is None:
            exclude_dirs = []
            
        # Count total files for progress reporting
        total_files = self.count_files(folder_path, file_extensions, exclude_dirs)
        if total_files == 0:
            self.logger.warning(f"No matching files found in {folder_path}")
            return 0
            
        file_count = 0
        success_count = 0
        
        # Normalize file extensions (add dot if missing)
        if file_extensions:
            file_extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in file_extensions]
        
        for root, dirs, files in os.walk(folder_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                # Skip files with non-matching extensions if specified
                if file_extensions:
                    file_ext = os.path.splitext(file)[1].lower()
                    if file_ext not in file_extensions:
                        continue
                    
                file_path = os.path.join(root, file)
                
                if operation == 'encrypt':
                    success = self.file_encryptor.encrypt_file(file_path, backup)
                else:  # decrypt
                    success = self.file_encryptor.decrypt_file(file_path)
                    
                file_count += 1
                if success:
                    success_count += 1
                    
                # Report progress if callback provided
                if progress_callback:
                    percent = int((file_count / total_files) * 100)
                    progress_callback(percent, file_path)
        
        operation_name = "Encryption" if operation == 'encrypt' else "Decryption"
        self.logger.info(f"{operation_name} complete. Successfully processed {success_count}/{file_count} files.")
        return success_count
        
    def encrypt_folder(self, folder_path, file_extensions=None, exclude_dirs=None, backup=False, progress_callback=None):
        """Encrypt all files in a folder"""
        return self.process_folder(folder_path, 'encrypt', file_extensions, exclude_dirs, backup, progress_callback)
        
    def decrypt_folder(self, folder_path, file_extensions=None, exclude_dirs=None, progress_callback=None):
        """Decrypt all files in a folder"""
        return self.process_folder(folder_path, 'decrypt', file_extensions, exclude_dirs, False, progress_callback)
