@echo off
echo Installing dependencies for Folder Encryption Suite...
pip install cryptography py7zr
echo Dependencies installed successfully!
echo.
echo You can now run the application using run_folder_encryption.bat
echo.
echo NOTE: If you try to create an executable with PyInstaller, you may encounter
echo antivirus warnings. This is a common false positive. We recommend using
echo the batch file method instead of creating an executable.
pause 