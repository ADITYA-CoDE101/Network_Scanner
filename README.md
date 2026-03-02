# Network_Scanner [ZONIX]. 


[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![MIT License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Networking](https://img.shields.io/badge/Networking-TCP%2FIP-orange?style=flat-square&logo=signal)](https://en.wikipedia.org/wiki/Internet_protocol_suite)
[![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Vulnerability%20Scanning-red?style=flat-square&logo=security)](https://en.wikipedia.org/wiki/Vulnerability_assessment)

> ⚠️ **Educational Purpose Only** - This tool is designed for learning and demonstration purposes in a controlled, authorized environment.

---

## 📖 Table of Contents

- [Introduction](#-introduction)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Command Reference](#-command-reference)
- [Disclaimer](#-disclaimer)
- [Acknowledgments](#-acknowledgments)
- [License](#license)
- [Author](#-author)

---

## 📌 Introduction

**ZONIX** is a comprehensive network scanning tool developed as a college mini-project. It illustrates the dual nature of network security by demonstrating both offensive capabilities and their corresponding defensive countermeasures.

This tool serves as an educational platform for understanding:
- Network protocols and their behavior
- Packet construction and analysis
- System and network traffic monitoring
- Security vulnerabilities and mitigation strategies

---

## 🔧 Features

### 🔴 Offensive Module

| Feature | Description |
|---------|-------------|
| **Port Scan** | Scans target systems for open ports and services |
| **DNS Services Scanning** | Enumerates DNS records and services |
| **DNS Explorer** | Explores DNS configurations and zone information |

### 🟢 Defensive Module

| Feature | Description |
|---------|-------------|
| **Port Scan Detection** | Identifies and alerts on port scanning attempts |
| **DNS Scan Detection** | Detects DNS enumeration activities |
| **Deception** | Implements honeypot and decoy techniques |
| **Monitoring** | Real-time network traffic and device process monitoring |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Scanner ZONIX                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────┐    ┌─────────────────────┐         │
│  │    OFFENSIVE        │    │     DEFENSIVE       │         │
│  ├─────────────────────┤    ├─────────────────────┤         │
│  │ • Port Scan         │    │ • Port Scan Detect  │         │ 
│  │ • DNS Services Scan │    │ • DNS Scan Detect   │         │
│  │ • DNS Explorer      │    │ • Deception         │         │
│  │                     │    │ • Monitoring        │         │
│  └─────────────────────┘    └─────────────────────┘         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                      Core Modules                           │
│  • Network Protocols  • Packet Handling  • Traffic Monitor  │
└─────────────────────────────────────────────────────────────┘
```

---

## 💻 Installation

### Prerequisites

- **Python 3.x** installed on your system
- **Administrator/root privileges** for network operations
- Required Python packages (see below)

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/Network_Scanner_ZONIX.git

# Navigate to project directory
cd Network_Scanner_ZONIX

# Install dependencies
pip install -r requirements.txt

# Run the tool
python ZoniX.py
```

### Requirements

```
scapy
colorama
pyfiglet
dnspython
```

---

## 🚀 Usage

### Interactive Mode

```bash
python Zonix.py
```


---

## 📋 Command Reference

| Command | Description |
|---------|-------------|
| `-h` | Display help section |
| `-pS` | Perform port scanning on target |
| `-dS` | Scan DNS services |
| `-dexp` | Explore DNS records and configurations |
| `-psD` | Detect port scanning activities |
| `-dsD` | Detect DNS scanning/enumeration |
| `-pd` / `--deception` | Activate deception/honeypot mechanisms |
| `-mo` | Monitor network traffic and system processes |
| `-q` / `--exit` | Quit the application |

### Example Output

```
┌──(workspace㉿command)-[Current Time]
└─# Command: -pS 192.168.1.1
```

---

## ⚠️ Disclaimer

> **IMPORTANT: Educational Use Only**
> 
> This tool is created for **educational and learning purposes** only. It demonstrates fundamental networking concepts and security principles in a controlled environment.
> 
> - ⚡ Use this tool only on networks/systems you own or have explicit written permission to test
> - ⚡ Unauthorized scanning or testing of systems is illegal and unethical
> - ⚡ The developers assume no liability for any misuse or damage caused by this tool
> - ⚡ Always comply with applicable laws and regulations
>
> **By using this tool, you agree to use it responsibly and ethically.**

---


## 👏 Acknowledgments

- **Educational Institution** - For providing the opportunity to build this project
- **Open Source Community** - For the libraries and tools that made this possible


---

<p align="center">
  <sub>Built with 🖥️ for educational purposes | Network Scanner ZONIX v1.0</sub>
</p>

---

## License
```
# MIT License

Copyright (c) 2025 Aditya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👤 Author

- **Aditya**
- 📧 Email: adi8708470492@gmail.com / darkcode01882@gmail.com
- 🔗 LinkedIn: [My LinkedIn](www.linkedin.com/in/aditya-kumar-36454a310)

> 📝 **Note:** Learning is something that enables you to reach greater heights .
