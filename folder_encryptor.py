import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import threading

class FolderEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Folder Encryptor")
        self.root.geometry("600x500")
        self.root.configure(bg="#f0f0f0")  # Light gray background
        
        # Add status variables
        self.current_folder = tk.StringVar(value="No folder selected")
        self.status = tk.StringVar(value="Ready")
        self.is_processing = False
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main container with padding
        main_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(
            main_frame,
            text="Secure Folder Encryptor",
            font=("Helvetica", 16, "bold"),
            bg="#f0f0f0"
        )
        title_label.pack(pady=(0, 20))
        
        # Folder selection frame
        folder_frame = tk.LabelFrame(
            main_frame,
            text="Folder Selection",
            bg="#f0f0f0",
            padx=10,
            pady=10
        )
        folder_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.folder_label = tk.Label(
            folder_frame,
            textvariable=self.current_folder,
            wraplength=500,
            bg="#f0f0f0"
        )
        self.folder_label.pack(pady=5)
        
        self.select_btn = tk.Button(
            folder_frame,
            text="Select Folder",
            command=self.select_folder,
            width=20,
            bg="#007bff",
            fg="white",
            font=("Helvetica", 10)
        )
        self.select_btn.pack(pady=5)
        
        # Password frame
        password_frame = tk.LabelFrame(
            main_frame,
            text="Password",
            bg="#f0f0f0",
            padx=10,
            pady=10
        )
        password_frame.pack(fill=tk.X, pady=(0, 15))
        
        # First password entry
        self.password_entry = tk.Entry(password_frame, show="", width=30)
        self.password_entry.insert(0, "Enter Password")
        self.password_entry.bind('<FocusIn>', self.on_password_entry_click)
        self.password_entry.bind('<FocusOut>', self.on_password_focus_out)
        self.password_entry.pack(pady=5)
        
        # Confirm password entry
        self.confirm_password_entry = tk.Entry(password_frame, show="", width=30)
        self.confirm_password_entry.insert(0, "Confirm Password")
        self.confirm_password_entry.bind('<FocusIn>', self.on_confirm_entry_click)
        self.confirm_password_entry.bind('<FocusOut>', self.on_confirm_focus_out)
        self.confirm_password_entry.pack(pady=5)
        
        # Show/Hide password checkbox
        self.show_password = tk.BooleanVar()
        self.show_password_cb = tk.Checkbutton(
            password_frame,
            text="Show Password",
            variable=self.show_password,
            command=self.toggle_password_visibility,
            bg="#f0f0f0"
        )
        self.show_password_cb.pack()
        
        # Action buttons frame
        button_frame = tk.Frame(main_frame, bg="#f0f0f0")
        button_frame.pack(pady=15)
        
        self.encrypt_btn = tk.Button(
            button_frame,
            text="Encrypt Folder",
            command=self.encrypt_with_confirmation,
            width=15,
            bg="#28a745",
            fg="white",
            font=("Helvetica", 10)
        )
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.decrypt_btn = tk.Button(
            button_frame,
            text="Decrypt Folder",
            command=self.decrypt_folder,
            width=15,
            bg="#dc3545",
            fg="white",
            font=("Helvetica", 10)
        )
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            main_frame,
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X, pady=15)
        
        # Status label
        self.status_label = tk.Label(
            main_frame,
            textvariable=self.status,
            bg="#f0f0f0",
            font=("Helvetica", 9)
        )
        self.status_label.pack()

    def on_password_entry_click(self, event):
        if self.password_entry.get() == "Enter Password":
            self.password_entry.delete(0, tk.END)
            self.password_entry.config(show="*")

    def on_password_focus_out(self, event):
        if self.password_entry.get() == "":
            self.password_entry.insert(0, "Enter Password")
            self.password_entry.config(show="")

    def on_confirm_entry_click(self, event):
        if self.confirm_password_entry.get() == "Confirm Password":
            self.confirm_password_entry.delete(0, tk.END)
            self.confirm_password_entry.config(show="*")

    def on_confirm_focus_out(self, event):
        if self.confirm_password_entry.get() == "":
            self.confirm_password_entry.insert(0, "Confirm Password")
            self.confirm_password_entry.config(show="")

    def toggle_password_visibility(self):
        show = self.show_password.get()
        self.password_entry.config(show="" if show else "*")
        if self.confirm_password_entry.get() != "Confirm Password":
            self.confirm_password_entry.config(show="" if show else "*")

    def encrypt_with_confirmation(self):
        if not self.validate_passwords():
            return
        if messagebox.askyesno("Confirm Encryption", 
            "Are you sure you want to encrypt this folder? Make sure you remember the password!"):
            self.encrypt_folder()

    def validate_passwords(self):
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password!")
            return False
        
        if confirm_password == "Confirm Password" or confirm_password != password:
            messagebox.showerror("Error", "Passwords do not match!")
            return False
            
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long!")
            return False
            
        return True

    def update_progress(self, current, total):
        progress = (current / total) * 100
        self.progress_var.set(progress)
        self.status.set(f"Processing file {current} of {total}")
        self.root.update_idletasks()

    def load_or_generate_key(self):
        key_file = "encryption_key.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
            return key
    
    def setup_password_entry(self):
        # Password frame
        password_frame = tk.Frame(self.root)
        password_frame.pack(pady=10)
        
        tk.Label(password_frame, text="Password:").pack(side=tk.LEFT)
        self.password_entry = tk.Entry(password_frame, show="*")
        self.password_entry.pack(side=tk.LEFT, padx=5)

    def derive_key(self, password):
        # Generate a secure key from password using PBKDF2
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())
        return key, salt

    def encrypt_file(self, file_data):
        # Generate IV (Initialization Vector)
        iv = os.urandom(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv)
        )
        encryptor = cipher.encryptor()
        
        # Add padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + encrypted data
        return iv + encrypted_data
    
    def select_folder(self):
        self.folder_path = filedialog.askdirectory()
        if self.folder_path:
            # Get just the folder name from the full path
            folder_name = os.path.basename(self.folder_path)
            # Update the StringVar with the new message
            self.current_folder.set(f"Selected folder: {folder_name}")
            # Or if you prefer just the folder name:
            # self.current_folder.set(folder_name)
    
    def encrypt_folder(self):
        if self.is_processing:
            return
        
        self.is_processing = True
        self.status.set("Counting files...")
        self.progress_var.set(0)
        
        try:
            # Count total files first
            total_files = sum(len(files) for _, _, files in os.walk(self.folder_path))
            current_file = 0
            
            # Generate encryption key from password
            password = self.password_entry.get()
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            cipher_suite = Fernet(key)

            files_encrypted = 0
            
            for root, _, files in os.walk(self.folder_path):
                for file in files:
                    current_file += 1
                    self.update_progress(current_file, total_files)
                    
                    file_path = os.path.join(root, file)
                    try:
                        if file.startswith('.') or file.endswith('.encrypted'):
                            continue
                        
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        
                        encrypted_data = salt + cipher_suite.encrypt(file_data)
                        
                        encrypted_path = file_path + '.encrypted'
                        with open(encrypted_path, 'wb') as f:
                            f.write(encrypted_data)
                        
                        os.remove(file_path)
                        files_encrypted += 1
                        
                    except Exception as e:
                        print(f"Error encrypting {file_path}: {str(e)}")
                        continue
                
            self.status.set(f"Encryption completed! {files_encrypted} files encrypted.")
            
        except Exception as e:
            self.status.set("Encryption failed!")
            messagebox.showerror("Error", str(e))
        finally:
            self.is_processing = False
            self.progress_var.set(0)

    def decrypt_folder(self):
        if self.is_processing:
            return
        
        self.is_processing = True
        self.status.set("Counting files...")
        self.progress_var.set(0)
        
        try:
            # Count total files first
            total_files = sum(len(files) for _, _, files in os.walk(self.folder_path))
            current_file = 0
            
            password = self.password_entry.get()
            if not password:
                messagebox.showerror("Error", "Please enter a password!")
                return

            files_decrypted = 0
            
            for root, _, files in os.walk(self.folder_path):
                for file in files:
                    current_file += 1
                    self.update_progress(current_file, total_files)
                    
                    if not file.endswith('.encrypted'):
                        continue
                    
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        
                        salt = file_data[:16]
                        encrypted_data = file_data[16:]
                        
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                        )
                        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                        cipher_suite = Fernet(key)
                        
                        decrypted_data = cipher_suite.decrypt(encrypted_data)
                        
                        decrypted_path = file_path[:-10]  # Remove '.encrypted'
                        with open(decrypted_path, 'wb') as f:
                            f.write(decrypted_data)
                        
                        os.remove(file_path)
                        files_decrypted += 1
                        
                    except Exception as e:
                        print(f"Error decrypting {file_path}: {str(e)}")
                        continue
            
            if files_decrypted > 0:
                self.status.set(f"Decryption completed! {files_decrypted} files decrypted.")
            else:
                self.status.set("No encrypted files found!")
                
        except Exception as e:
            self.status.set("Decryption failed!")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        finally:
            self.is_processing = False
            self.progress_var.set(0)

if __name__ == "__main__":
    root = tk.Tk()
    app = FolderEncryptorApp(root)
    root.mainloop()
