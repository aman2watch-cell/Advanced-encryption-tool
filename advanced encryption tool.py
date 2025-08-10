import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets
# Generate AES key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt file
def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Enter a password!")
        return

    with open(file_path, 'rb') as f:
        data = f.read()

    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

    messagebox.showinfo("Success", f"File encrypted:\n{encrypted_file_path}")

# Decrypt file
def decrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if not file_path:
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Enter a password!")
        return

    with open(file_path, 'rb') as f:
        raw_data = f.read()

    salt = raw_data[:16]
    iv = raw_data[16:32]
    encrypted_data = raw_data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    try:
        data = unpadder.update(padded_data) + unpadder.finalize()
    except ValueError:
        messagebox.showerror("Error", "Incorrect password or corrupted file.")
        return

    decrypted_file_path = file_path.replace(".enc", "_decrypted")
    with open(decrypted_file_path, 'wb') as f:
        f.write(data)

    messagebox.showinfo("Success", f"File decrypted:\n{decrypted_file_path}")

# GUI Setup
root = tk.Tk()
root.title("AES-256 File Encryption Tool")
root.geometry("400x250")
root.resizable(False, False)

tk.Label(root, text="AES-256 Encryption Tool", font=("Arial", 14, "bold")).pack(pady=10)

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack()
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=5)

tk.Button(root, text="Encrypt File", command=encrypt_file, bg="green", fg="white", width=20).pack(pady=10)
tk.Button(root, text="Decrypt File", command=decrypt_file, bg="blue", fg="white", width=20).pack(pady=5)
tk.Button(root, text="Exit", command=root.quit, bg="red", fg="white", width=20).pack(pady=10)

root.mainloop()