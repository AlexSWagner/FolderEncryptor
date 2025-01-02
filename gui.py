import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from encryption import encrypt_folder, decrypt_folder
from utils import validate_passwords

class FolderEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Folder Encryptor")
        self.root.geometry("600x500")
        self.root.configure(bg="#f0f0f0")

        self.current_folder = tk.StringVar(value="No folder selected")
        self.status = tk.StringVar(value="Ready")
        self.create_widgets()

    def create_widgets(self):
        main_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = tk.Label(main_frame, text="Secure Folder Encryptor",
                               font=("Helvetica", 16, "bold"), bg="#f0f0f0")
        title_label.pack(pady=(0, 20))

        folder_frame = tk.LabelFrame(main_frame, text="Folder Selection", bg="#f0f0f0", padx=10, pady=10)
        folder_frame.pack(fill=tk.X, pady=(0, 15))

        self.folder_label = tk.Label(folder_frame, textvariable=self.current_folder,
                                     wraplength=500, bg="#f0f0f0")
        self.folder_label.pack(pady=5)

        self.select_btn = tk.Button(folder_frame, text="Select Folder", command=self.select_folder,
                                    width=20, bg="#007bff", fg="white", font=("Helvetica", 10))
        self.select_btn.pack(pady=5)

        password_frame = tk.LabelFrame(main_frame, text="Password", bg="#f0f0f0", padx=10, pady=10)
        password_frame.pack(fill=tk.X, pady=(0, 15))

        self.password_entry = tk.Entry(password_frame, show="*", width=30)
        self.password_entry.pack(pady=5)

        self.confirm_password_entry = tk.Entry(password_frame, show="*", width=30)
        self.confirm_password_entry.pack(pady=5)

        button_frame = tk.Frame(main_frame, bg="#f0f0f0")
        button_frame.pack(pady=15)

        self.encrypt_btn = tk.Button(button_frame, text="Encrypt Folder",
                                     command=self.encrypt_with_confirmation,
                                     width=15, bg="#28a745", fg="white", font=("Helvetica", 10))
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)

        self.decrypt_btn = tk.Button(button_frame, text="Decrypt Folder",
                                     command=self.decrypt_folder,
                                     width=15, bg="#dc3545", fg="white", font=("Helvetica", 10))
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.current_folder.set(folder)

    def encrypt_with_confirmation(self):
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        is_valid, error_message = validate_passwords(password, confirm_password)
        if not is_valid:
            messagebox.showerror("Error", error_message)
            return

        if messagebox.askyesno("Confirm Encryption", "Are you sure you want to encrypt this folder?"):
            encrypt_folder(self.current_folder.get(), password)

    def decrypt_folder(self):
        password = self.password_entry.get()
        decrypt_folder(self.current_folder.get(), password)