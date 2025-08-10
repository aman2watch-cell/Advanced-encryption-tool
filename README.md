# 🔐 AES-256 File Encryption Tool (Python + Tkinter)

A simple **GUI-based AES-256 encryption and decryption tool** built with **Python** and **Tkinter**.  
It allows you to securely encrypt and decrypt files using a password, with **PBKDF2 key derivation** for enhanced security.

---

## ⚠️ Disclaimer
This tool is intended for **personal and educational purposes only**.  
The author is **not responsible** for any misuse or data loss.

---

## 📌 Features
- 🔑 **AES-256** encryption (CBC mode)
- 🧂 Random **16-byte salt** for each encryption
- 🌀 **PBKDF2-HMAC-SHA256** key derivation
- 📁 File selection via GUI
- 🖥️ User-friendly **Tkinter interface**
- ✅ Works on Windows, macOS, and Linux

---

## 🛠 Requirements

Install dependencies:
```bash
pip install cryptography
