# 🔑 CLI Password Manager (C++)

A secure, high-performance Password Manager built in C++ with AES-256 encryption, session protection, and full credential management.  
All data is stored **locally**, encrypted, and never leaves the user’s machine.

---

## 🛡️ Core Security Features

The core principle of this tool is that no sensitive data is readable without the Master Password.

### ✔ Secure Memory Erase  
All sensitive session data — especially the active AES decryption key — is explicitly wiped (overwritten) in memory upon logout or auto-lock. This provides strong protection against memory scraping and cold-boot attacks.

### ✔ AES-256 GCM Encryption  
All passwords are encrypted using **AES-256-GCM**, providing:

- Confidentiality  
- Integrity (tampering detection)  
- A unique IV for every encrypted entry  
- An authentication tag used during decryption  

### ✔ Key Derivation Function (KDF)  
The Master Password is processed through a slow, secure KDF (e.g., PBKDF2) to derive a strong 256-bit key.  
The password itself is **never** used directly for encryption.

### ✔ SQLite Local Storage  
All credential metadata (service, username, encrypted password, IV, tag) is stored in a **local SQLite database file**.

---

## ✨ Feature Set 

### 🔐 Security & Session Management

#### **Auto-Lock System 
If the user is inactive for a configurable timeout period (default: 60 seconds), the application:

1. Wipes the active AES session key from memory  
2. Terminates the session  
3. Requires Master Password re-authentication  

#### **Activity Logger 
All critical actions are logged with timestamps:

- Login success/failure  
- Export  
- Import  
- Credential deletion  
- Auto-lock triggers  

#### **Encrypted Export / Import (CSV)**  
The manager supports full backup & restore through a structured **encrypted CSV file**, containing:

```
id | service | username | ciphertext | iv | tag
```

- ✔ **Export** writes all encrypted entries to a CSV file (Base64 encoded)
- ✔ **Import** loads a CSV file, validates each entry, and inserts it into SQLite

This ensures portability across devices while maintaining encryption end-to-end.

---

## 👤 User Operations

### ➕ Add Credential  
Stores:  
- Service name  
- Username  
- Plaintext password (immediately encrypted)

### 🔐 View All Credentials  
All entries are decrypted **on-demand** and displayed only during the active session.

### 🔍 Search  
Fast search for entries matching the service or username.

### 🗑 Delete  
Removes an entry using its database ID.

### 🔧 Generate Secure Password  
Creates high-entropy passwords based on:

- Length  
- Inclusion of digits  
- Uppercase letters  
- Lowercase letters  
- Symbols  

Passwords are **automatically stored**.

---

## 🖥 CLI Interface

- Color-coded output using ANSI escape codes  
- Clean ASCII header on startup  
- Simple numeric menu control  

---

## 🛠 Technical Overview

| Component | Purpose |
|----------|---------|
| **AppController** | Main application loop, user input, session control |
| **CredentialService** | Data access, business logic, encryption operations |
| **AES/KDF Modules** | Key derivation and AES-GCM encryption/decryption |
| **SecureMemory** | Memory wipe utilities and key erasure |
| **ActivityLogger** | Timestamped logging |
| **PasswordGenerator** | High-entropy random password generation |
| **Database (SQLite)** | Query execution and storage backend |

---

## 🚀 Build & Run Instructions

### 📥 1. Clone the Repository

```bash
git clone https://github.com/luksha14/PasswordManager
cd YOUR_REPO_NAME
```

---

### 🔨 2. Create Build Folder

```bash
mkdir build
cd build
```

---

### ⚙️ 3. Configure CMake

```bash
cmake ..
```

---

### 🏗️ 4. Build the Application

```bash
cmake --build .
```

---

### ▶️ 5. Run

```bash
./PasswordManager
```

(Windows: `PasswordManager.exe`)

---

## 📦 Dependencies

- CMake 3.10+
- C++17 compatible compiler
- SQLite3
- OpenSSL (AES-256 GCM + PBKDF2)
- ANSI-compatible terminal

---

## 🚀 Future Improvements / Upgrade Ideas

### 📌 1. JSON Import & Export (planned)
In addition to CSV, future versions could support JSON backups:

```json
[
  {
    "service": "gmail",
    "username": "user123",
    "ciphertext": "...",
    "iv": "...",
    "tag": "..."
  }
]
``` 

### 📌  Multi-User Support  
Each user has their own Master Password and isolated SQLite table.

### 📌  GUI Version (Qt or ImGui)  
A cross-platform GUI application using the same backend logic.

---

## 👨‍💻 Author

**Luka Mikulić**  
Developer & author of the CLI Password Manager project.  
Focused on security, cryptography, and modern C++ development.

---