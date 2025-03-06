import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinter.simpledialog as simpledialog
import threading
import logging
from core.key_manager import KeyManager
from core.encryptor import FileEncryptor
from core.folder_handler import FolderEncryptor
from core.protector import FolderProtector

class EncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # Initialize core components
        self.key_manager = KeyManager()
        self.file_encryptor = FileEncryptor(self.key_manager)
        self.folder_encryptor = FolderEncryptor(self.file_encryptor)
        self.protector = FolderProtector()
        self.logger = logging.getLogger(__name__)
        
        # Configure the window
        self.title("Folder Security Suite")
        self.geometry("500x550")
        
        # Create style
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", font=("Segoe UI", 9))
        self.style.configure("TLabel", font=("Segoe UI", 9))
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"))
        self.style.configure("TLabelframe", padding=8)
        self.style.configure("TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        
        # Create the main frame with padding
        self.main_frame = ttk.Frame(self, padding="10 10 10 10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create the header
        self.header_label = ttk.Label(
            self.main_frame, 
            text="Folder Security Suite",
            style="Header.TLabel"
        )
        self.header_label.pack(pady=(0, 15))
        
        # Create the notebook (tabs)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create the encryption tab
        self.encryption_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.encryption_tab, text="Encryption")
        
        # Create the protection tab
        self.protection_tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.protection_tab, text="7z Protection")
        
        # Setup the encryption tab
        self.setup_encryption_tab()
        
        # Setup the protection tab
        self.setup_protection_tab()
        
        # Create the status bar
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        
        # Create the progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            status_frame, 
            variable=self.progress_var, 
            maximum=100
        )
        self.progress_bar.pack(side=tk.TOP, fill=tk.X)
        
        # Status text
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(
            status_frame, 
            textvariable=self.status_var,
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.TOP, fill=tk.X, pady=(5, 0))
        
    def setup_encryption_tab(self):
        # Use grid layout for better organization
        self.encryption_tab.columnconfigure(0, weight=1)
        self.encryption_tab.columnconfigure(1, weight=1)
        
        # Key Management Section
        key_frame = ttk.LabelFrame(self.encryption_tab, text="Key Management")
        key_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        # Configure grid for key frame
        key_frame.columnconfigure(0, weight=1)
        key_frame.columnconfigure(1, weight=1)
        
        # Key Management Buttons
        ttk.Button(
            key_frame, 
            text="Generate New Key", 
            command=self.generate_new_key
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        ttk.Button(
            key_frame, 
            text="Password-Based Key", 
            command=self.generate_password_key
        ).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Button(
            key_frame, 
            text="Load Existing Key", 
            command=self.load_existing_key
        ).grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        
        # File Operations Section
        file_frame = ttk.LabelFrame(self.encryption_tab, text="File Operations")
        file_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        
        # Configure grid for file frame
        file_frame.columnconfigure(0, weight=1)
        
        ttk.Button(
            file_frame, 
            text="Encrypt File", 
            command=self.encrypt_file
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        ttk.Button(
            file_frame, 
            text="Decrypt File", 
            command=self.decrypt_file
        ).grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        
        # Folder Operations Section
        folder_frame = ttk.LabelFrame(self.encryption_tab, text="Folder Operations")
        folder_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        
        # Configure grid for folder frame
        folder_frame.columnconfigure(0, weight=1)
        
        ttk.Button(
            folder_frame, 
            text="Encrypt Folder", 
            command=self.encrypt_folder
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        ttk.Button(
            folder_frame, 
            text="Decrypt Folder", 
            command=self.decrypt_folder
        ).grid(row=1, column=0, padx=5, pady=5, sticky="ew")
    
    def setup_protection_tab(self):
        # Use grid layout for better organization
        self.protection_tab.columnconfigure(0, weight=1)
        
        # Password Management Section
        password_frame = ttk.LabelFrame(self.protection_tab, text="Password Management")
        password_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        # Configure grid for password frame
        password_frame.columnconfigure(0, weight=1)
        
        ttk.Button(
            password_frame, 
            text="Set Protection Password", 
            command=self.set_protection_password
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        # Protection Operations Section
        operation_frame = ttk.LabelFrame(self.protection_tab, text="Protection Operations")
        operation_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        
        # Configure grid for operation frame
        operation_frame.columnconfigure(0, weight=1)
        operation_frame.columnconfigure(1, weight=1)
        
        ttk.Button(
            operation_frame, 
            text="Protect Folder", 
            command=self.protect_folder
        ).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        ttk.Button(
            operation_frame, 
            text="Unprotect Archive", 
            command=self.unprotect_archive
        ).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Information Section
        info_frame = ttk.LabelFrame(self.protection_tab, text="Information")
        info_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        
        info_text = "7z Protection allows you to create password-protected archives\n" + \
                   "of your folders for secure storage and transfer."
        ttk.Label(
            info_frame, 
            text=info_text,
            justify=tk.LEFT,
            wraplength=450
        ).grid(row=0, column=0, padx=5, pady=5, sticky="w")
    
    def update_progress(self, percent, current_file=None):
        """Update the progress bar and status"""
        self.progress_var.set(percent)
        if current_file:
            self.status_var.set(f"Processing: {current_file}")
        else:
            self.status_var.set(f"Progress: {percent:.1f}%")
        self.update_idletasks()
    
    def run_in_thread(self, func, *args, **kwargs):
        """Run a function in a separate thread to keep the UI responsive"""
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        thread.daemon = True
        thread.start()
    
    # Key Management Functions
    def generate_new_key(self):
        try:
            self.key_manager.generate_key()
            messagebox.showinfo("Success", "New random key generated successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {str(e)}")
    
    def generate_password_key(self):
        password = simpledialog.askstring("Password", "Enter password for key generation:", show='*')
        if password:
            try:
                self.key_manager.generate_key_from_password(password)
                messagebox.showinfo("Success", "Password-based key generated successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate key: {str(e)}")
    
    def load_existing_key(self):
        key_file = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")]
        )
        if key_file:
            try:
                self.key_manager.load_key(key_file)
                messagebox.showinfo("Success", "Key loaded successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {str(e)}")
    
    # Folder Operations
    def encrypt_folder(self):
        if not self.key_manager.key:
            messagebox.showwarning("Warning", "No encryption key loaded. Please generate or load a key first.")
            return
        
        folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
        if not folder_path:
            return
        
        self.status_var.set("Starting folder encryption...")
        
        def encrypt_task():
            try:
                self.folder_encryptor.encrypt_folder(
                    folder_path, 
                    progress_callback=self.update_progress
                )
                self.status_var.set("Folder encrypted successfully.")
                messagebox.showinfo("Success", "Folder encrypted successfully.")
            except Exception as e:
                self.status_var.set("Encryption failed.")
                messagebox.showerror("Error", f"Failed to encrypt folder: {str(e)}")
        
        self.run_in_thread(encrypt_task)
    
    def decrypt_folder(self):
        if not self.key_manager.key:
            messagebox.showwarning("Warning", "No encryption key loaded. Please generate or load a key first.")
            return
        
        folder_path = filedialog.askdirectory(title="Select Folder to Decrypt")
        if not folder_path:
            return
        
        self.status_var.set("Starting folder decryption...")
        
        def decrypt_task():
            try:
                self.folder_encryptor.decrypt_folder(
                    folder_path, 
                    progress_callback=self.update_progress
                )
                self.status_var.set("Folder decrypted successfully.")
                messagebox.showinfo("Success", "Folder decrypted successfully.")
            except Exception as e:
                self.status_var.set("Decryption failed.")
                messagebox.showerror("Error", f"Failed to decrypt folder: {str(e)}")
        
        self.run_in_thread(decrypt_task)
    
    # File Operations
    def encrypt_file(self):
        if not self.key_manager.key:
            messagebox.showwarning("Warning", "No encryption key loaded. Please generate or load a key first.")
            return
        
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return
        
        self.status_var.set("Encrypting file...")
        
        def encrypt_task():
            try:
                self.file_encryptor.encrypt_file(file_path)
                self.status_var.set("File encrypted successfully.")
                messagebox.showinfo("Success", "File encrypted successfully.")
            except Exception as e:
                self.status_var.set("Encryption failed.")
                messagebox.showerror("Error", f"Failed to encrypt file: {str(e)}")
        
        self.run_in_thread(encrypt_task)
    
    def decrypt_file(self):
        if not self.key_manager.key:
            messagebox.showwarning("Warning", "No encryption key loaded. Please generate or load a key first.")
            return
        
        file_path = filedialog.askopenfilename(
            title="Select File to Decrypt",
            filetypes=[("Encrypted Files", "*.encrypted"), ("All Files", "*.*")]
        )
        if not file_path:
            return
        
        self.status_var.set("Decrypting file...")
        
        def decrypt_task():
            try:
                self.file_encryptor.decrypt_file(file_path)
                self.status_var.set("File decrypted successfully.")
                messagebox.showinfo("Success", "File decrypted successfully.")
            except Exception as e:
                self.status_var.set("Decryption failed.")
                messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")
        
        self.run_in_thread(decrypt_task)
    
    # Protection Functions
    def set_protection_password(self):
        password = simpledialog.askstring("Password", "Enter protection password:", show='*')
        if password:
            try:
                self.protector.set_password(password)
                messagebox.showinfo("Success", "Protection password set successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to set password: {str(e)}")
    
    def protect_folder(self):
        if not self.protector.password:
            messagebox.showwarning("Warning", "No protection password set. Please set a password first.")
            return
        
        folder_path = filedialog.askdirectory(title="Select Folder to Protect")
        if not folder_path:
            return
        
        output_file = filedialog.asksaveasfilename(
            title="Save Protected Archive As",
            defaultextension=".7z",
            filetypes=[("7z Archives", "*.7z"), ("All Files", "*.*")]
        )
        if not output_file:
            return
        
        # Ask if the user wants to delete the original folder
        delete_original = messagebox.askyesno(
            "Delete Original", 
            "Do you want to delete the original folder after protection?"
        )
        
        self.status_var.set("Protecting folder...")
        
        def protect_task():
            try:
                self.protector.protect_folder(
                    folder_path, 
                    output_file, 
                    delete_original=delete_original,
                    progress_callback=self.update_progress
                )
                self.status_var.set("Folder protected successfully.")
                messagebox.showinfo("Success", "Folder protected successfully.")
            except Exception as e:
                self.status_var.set("Protection failed.")
                messagebox.showerror("Error", f"Failed to protect folder: {str(e)}")
        
        self.run_in_thread(protect_task)
    
    def unprotect_archive(self):
        if not self.protector.password:
            messagebox.showwarning("Warning", "No protection password set. Please set a password first.")
            return
        
        archive_path = filedialog.askopenfilename(
            title="Select Archive to Unprotect",
            filetypes=[("7z Archives", "*.7z"), ("All Files", "*.*")]
        )
        if not archive_path:
            return
        
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            return
        
        # Ask if the user wants to delete the original archive
        delete_original = messagebox.askyesno(
            "Delete Original", 
            "Do you want to delete the original archive after extraction?"
        )
        
        self.status_var.set("Unprotecting archive...")
        
        def unprotect_task():
            try:
                self.protector.unprotect_archive(
                    archive_path, 
                    output_dir, 
                    delete_original=delete_original,
                    progress_callback=self.update_progress
                )
                self.status_var.set("Archive unprotected successfully.")
                messagebox.showinfo("Success", "Archive unprotected successfully.")
            except Exception as e:
                self.status_var.set("Unprotection failed.")
                messagebox.showerror("Error", f"Failed to unprotect archive: {str(e)}")
        
        self.run_in_thread(unprotect_task)

class GUI:
    def __init__(self):
        self.app = EncryptionApp()
    
    def run(self):
        self.app.mainloop() 