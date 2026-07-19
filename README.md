# 🛡️ CyberGuard

A Python-based cybersecurity toolkit that combines multiple security utilities into a single command-line application. CyberGuard helps users perform network analysis, URL reputation checks, encryption, and system information gathering using industry-standard libraries and APIs.

---

## 📖 Overview

CyberGuard is designed as an all-in-one cybersecurity utility that demonstrates practical security concepts such as:

- Network Scanning
- URL Reputation Analysis
- IP Address Information Lookup
- AES File Encryption & Decryption
- VirusTotal Integration
- Basic Security Automation

The project showcases practical applications of Python in cybersecurity and secure software development.

---

## 🚀 Features

### 🌐 IP Address Information
- Retrieve public IP address details
- Display ISP, country, city, timezone, and location
- Uses public IP information APIs

### 🔍 URL Reputation Scanner
- Checks URLs for potential security threats
- Integrates with VirusTotal API
- Displays scan results and reputation

### 🔒 File Encryption & Decryption
- AES-256 Encryption
- Password-based key derivation (PBKDF2)
- Secure file encryption
- Secure file decryption

### 📡 Network Scanner
- Scan hosts using Nmap
- Detect open ports
- Identify running services
- Gather network information

### 🛠 Security Utilities
- System Information
- Network Information
- Basic Security Automation

---

# 🏗 Architecture

```
User
   │
   ▼
CyberGuard CLI
   │
   ├──────────────► IP Lookup Module
   │
   ├──────────────► URL Scanner
   │                  │
   │                  ▼
   │             VirusTotal API
   │
   ├──────────────► Encryption Module
   │                  │
   │                  ▼
   │             AES-256 + PBKDF2
   │
   └──────────────► Network Scanner
                      │
                      ▼
                     Nmap
```

---

# ⚙ Technologies Used

## Programming Language

- Python

## Libraries

- requests
- python-nmap
- PyCryptodome
- socket
- os
- hashlib

## APIs

- VirusTotal API
- IP Geolocation API

## Security Tools

- Nmap
- AES Encryption
- PBKDF2

---

# 📂 Project Structure

```
CyberGuard/

├── modules/
├── assets/
├── screenshots/
├── requirements.txt
├── main.py
├── README.md
└── LICENSE
```

---

# 🔄 Workflow

1. User launches CyberGuard.
2. Selects a security utility.
3. The selected module performs the requested task.
4. Results are displayed securely to the user.

---

# ✨ Key Features

- Modular architecture
- Multiple cybersecurity tools in one application
- VirusTotal API integration
- AES-256 file encryption
- URL reputation analysis
- Network reconnaissance
- Public IP intelligence
- Easy-to-use command-line interface

---

# 📚 Learning Outcomes

This project helped me gain practical experience with:

- Python Programming
- Cybersecurity Fundamentals
- API Integration
- Network Scanning
- Cryptography
- Secure File Handling
- REST APIs
- CLI Application Development
- Python Package Management

---

# 🚀 Future Improvements

- Graphical User Interface (GUI)
- Multi-threaded Network Scanning
- Malware Hash Scanner
- WHOIS Lookup
- DNS Enumeration
- SSL Certificate Analysis
- Shodan API Integration
- Report Generation (PDF/HTML)

---

# 📸 Screenshots

Add screenshots of:

- Main Menu
- URL Scanner
- VirusTotal Results
- Encryption Module
- Network Scanner
- IP Lookup

---

# 💻 Installation

```bash
git clone https://github.com/Abdullah0617/CyberGuard.git

cd CyberGuard

pip install -r requirements.txt

python main.py
```

---

# 👨‍💻 Author

**Abdullah Zahid**

B.Tech Computer Science

GitHub: https://github.com/Abdullah0617

LinkedIn: https://www.linkedin.com/in/abdullah-zahid-279420336/

---

## ⭐ If you found this project useful, consider giving it a Star!
