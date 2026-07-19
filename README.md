# 🛡️ CyberGuard - Network Security & Cryptography Toolkit

CyberGuard is a Python-based cybersecurity toolkit that combines multiple security utilities into a single command-line application. It demonstrates practical cybersecurity concepts such as **network reconnaissance, cryptography, and URL reputation analysis** using industry-standard libraries and APIs.

---

## 📖 Project Overview

CyberGuard is designed to provide essential cybersecurity functionalities for learning and basic security assessment. The toolkit integrates network scanning, cryptographic utilities, and threat intelligence into a simple, modular CLI application.

The application allows users to:

- Discover live hosts on a network
- Scan TCP ports
- Detect the operating system of a target host
- Perform network traceroute
- Encrypt and decrypt sensitive text using AES-256
- Check URL reputation using the VirusTotal API

---

# 🏗️ Architecture

```
                    +----------------+
                    |     User       |
                    +-------+--------+
                            |
                            v
                 +---------------------+
                 |   CyberGuard CLI    |
                 +----------+----------+
                            |
     -----------------------------------------------------
     |             |             |              |         |
     v             v             v              v         v
+---------+  +-----------+  +----------+  +-----------+ +-------------+
| Host    |  | Port      |  | OS       |  | Traceroute| | Encryption  |
| Scanner |  | Scanner   |  | Detection|  |           | | (AES-256)   |
+---------+  +-----------+  +----------+  +-----------+ +-------------+
                                                          |
                                                          v
                                                  +---------------+
                                                  |  PyCryptodome |
                                                  +---------------+

                            |
                            v

                    +-------------------+
                    | URL Reputation    |
                    | VirusTotal API    |
                    +-------------------+
```

---

# ⚙️ Tech Stack

## Programming Language

- Python

## Libraries

- python-nmap
- requests
- PyCryptodome

## APIs

- VirusTotal API

## Security Concepts

- Network Reconnaissance
- Host Discovery
- Port Scanning
- OS Fingerprinting
- Network Traceroute
- AES-256 Encryption
- PBKDF2 Key Derivation
- REST API Integration

---

# ✨ Features

### 🌐 Network Security

- Live Host Discovery
- TCP Port Scanning
- Operating System Detection
- Network Traceroute

### 🔒 Cryptography

- AES-256 Encryption
- AES-256 Decryption
- PBKDF2 Password-Based Key Derivation
- Random Salt Generation
- Random IV Generation

### 🛡️ Threat Intelligence

- URL Reputation Analysis
- VirusTotal API Integration

---

# 🔄 Workflow

### Network Reconnaissance

1. Enter the target IP address.
2. Choose the desired scanning module.
3. CyberGuard performs the requested scan using Nmap.
4. Results are displayed in the terminal.

### Encryption

1. Enter the plaintext.
2. Provide a password.
3. PBKDF2 derives a secure encryption key.
4. AES-256 encrypts the data.
5. Encrypted output is saved as a binary file.

### Decryption

1. Select the encrypted file.
2. Enter the password.
3. The key is regenerated using PBKDF2.
4. The encrypted data is decrypted.

### URL Reputation

1. Enter a URL.
2. CyberGuard queries the VirusTotal API.
3. The URL reputation is displayed.

---

# 📂 Repository Structure

```
CyberGuard/

├── main.py
├── README.md
└── requirements.txt
```

---

# 📌 Key Functionalities

| Module | Description |
|---------|-------------|
| Host Discovery | Detects active hosts on a network |
| Port Scanner | Scans TCP ports (1–1024) |
| OS Detection | Identifies the operating system using Nmap |
| Traceroute | Displays the network path to a target |
| Encryption | Encrypts text using AES-256 |
| Decryption | Decrypts encrypted files |
| URL Scanner | Checks URL reputation using VirusTotal |

---

# 🚀 Installation

## Clone the repository

```bash
git clone https://github.com/Abdullah0617/CyberGuard.git
```

```bash
cd CyberGuard
```

## Install dependencies

```bash
pip install -r requirements.txt
```

## Install Nmap

### Ubuntu

```bash
sudo apt install nmap
```

### Windows

Download and install from:

https://nmap.org/download.html

---

# ▶️ Usage

Run the application:

```bash
python main.py
```

Choose one of the available services:

```
1. IP Details
2. Encryption & Decryption
3. URL Reputation Check
```

---

# 📚 Learning Outcomes

Through this project, I gained practical experience in:

- Python Programming
- Network Reconnaissance
- Cybersecurity Fundamentals
- Cryptography
- AES-256 Encryption
- PBKDF2 Key Derivation
- API Integration
- REST APIs
- Python Automation
- Secure File Handling

---

# 🚧 Future Improvements

- GUI using Tkinter or PyQt
- Multi-threaded port scanning
- WHOIS Lookup
- DNS Enumeration
- SSL Certificate Analysis
- CVE Vulnerability Lookup
- IP Geolocation
- Malware Hash Scanning
- Shodan API Integration
- PDF Report Generation

---

# 📸 Screenshots

Add screenshots of:

- Main Menu
- Host Discovery
- Port Scanner
- OS Detection
- Traceroute
- Encryption Module
- URL Reputation Scanner

---

# 👨‍💻 Author

**Abdullah Zahid**

B.Tech Computer Science

GitHub: https://github.com/Abdullah0617

LinkedIn: https://www.linkedin.com/in/abdullah-zahid-279420336/

---

## ⭐ Star this repository if you found it useful!

If you like this project, consider giving it a ⭐ on GitHub.
