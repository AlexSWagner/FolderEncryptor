import os
import py7zr
import shutil
import logging

class FolderProtector:
    def __init__(self):
        self.password = None
        self.logger = logging.getLogger(__name__)

    def set_password(self, password):
        self.password = password
        self.logger.info("Password set successfully")
        return True

    def protect_folder(self, folder_path, output_file=None, delete_original=False, compression_level=3, progress_callback=None):
        """
        Protect a folder with 7z compression and password
        
        Args:
            folder_path: Path to the folder to protect
            output_file: Path to the output archive file (default: folder_path + '.7z')
            delete_original: Whether to delete the original folder after protection
            compression_level: Compression level (0-9)
            progress_callback: Function to call with progress updates (receives percentage)
        """
        if not os.path.exists(folder_path):
            self.logger.error(f"Folder not found: {folder_path}")
            return False
            
        if not self.password:
            self.logger.error("No password set")
            return False

        if output_file is None:
            output_file = folder_path + '.7z'
            
        try:
            # Configure compression
            filters = [{"id": py7zr.FILTER_LZMA2, "preset": compression_level}]
            
            # Simple progress callback wrapper
            if progress_callback:
                progress_callback(0)
                
            with py7zr.SevenZipFile(output_file, 'w', password=self.password, filters=filters) as archive:
                archive.writeall(folder_path, os.path.basename(folder_path))
                
            # Report completion
            if progress_callback:
                progress_callback(100)
                
            self.logger.info(f"Folder protected: {output_file}")
            
            # Delete original if requested
            if delete_original:
                shutil.rmtree(folder_path)
                
            return True
        except Exception as e:
            self.logger.error(f"Failed to protect folder: {str(e)}")
            return False

    def unprotect_archive(self, archive_path, output_dir=None, delete_original=False, progress_callback=None):
        """
        Unprotect a 7z archive
        
        Args:
            archive_path: Path to the 7z archive
            output_dir: Directory to extract to (default: current directory)
            delete_original: Whether to delete the original archive after extraction
            progress_callback: Function to call with progress updates (receives percentage)
        """
        if not os.path.exists(archive_path):
            self.logger.error(f"Archive not found: {archive_path}")
            return False
            
        if not self.password:
            self.logger.error("No password set")
            return False
            
        if output_dir is None:
            output_dir = os.path.dirname(archive_path)
            
        try:
            # Simple progress callback wrapper
            if progress_callback:
                progress_callback(0)
                
            with py7zr.SevenZipFile(archive_path, 'r', password=self.password) as archive:
                archive.extractall(path=output_dir)
                
            # Report completion
            if progress_callback:
                progress_callback(100)
                
            self.logger.info(f"Archive unprotected: {archive_path}")
            
            # Delete original if requested
            if delete_original:
                os.remove(archive_path)
                self.logger.info(f"Original archive removed: {archive_path}")
                
            return True
        except Exception as e:
            self.logger.error(f"Failed to unprotect archive: {str(e)}")
            return False
