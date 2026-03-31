# 🎯 zeroHack v2.0 - Comprehensive Vulnerability Assessment Tool

```
███████╗███████╗██████╗  ██████╗ ██╗  ██╗ █████╗  ██████╗██╗  ██╗
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██║  ██║██╔══██╗██╔════╝██║ ██╔╝
  ███╔╝ █████╗  ██████╔╝██║   ██║███████║███████║██║     █████╔╝ 
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██╔══██║██╔══██║██║     ██╔═██╗ 
███████╗███████╗██║  ██║╚██████╔╝██║  ██║██║  ██║╚██████╗██║  ██╗
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Tool](https://img.shields.io/badge/Security-Tool-red.svg)]()

> **Professional-grade vulnerability scanner** for web applications, APIs, smart contracts, cloud infrastructure, mobile apps, and IoT devices.

⚠️ **AUTHORIZED USE ONLY** - Only test systems you own or have explicit permission to test.

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Command Options](#-command-options)
- [Attack Levels](#-attack-levels)
- [Security Modules](#-security-modules)
- [Project Structure](#-project-structure)
- [Output Format](#-output-format)
- [Examples](#-examples)
- [Legal Disclaimer](#-legal-disclaimer)
- [License](#-license)

---

## 🛡️ Features

| Category | Capabilities |
|----------|-------------|
| **Web Security** | SQL Injection (320+ payloads), XSS, SSRF, RCE, IDOR, Cache Poisoning |
| **API Security** | GraphQL, JWT, Mass Assignment, Rate Limiting |
| **Smart Contracts** | Reentrancy, Proxy Bugs, NFT Bridge, DeFi Exploits (7 Immunefi Cases - $14M+) |
| **Cloud Security** | AWS, Azure, GCP Misconfigurations, Container Security |
| **Mobile Security** | Android/iOS Vulnerabilities, WebView Exploits |
| **IoT Security** | MQTT, CoAP, Default Credentials, Industrial Protocols |
| **Network** | Subdomain Enumeration, Port Scanning |
| **Notifications** | Desktop, Audio, Email Alerts |

---

## 🚀 Installation

### Prerequisites
- **Python 3.8+** (Ensure Python is added to your system PATH)
- **Git** (To clone the repository)
- **pip** (Python package installer)

### Step 1: Clone the Repository
Download the latest version of zeroHack v2.0 directly from GitHub:
```bash
git clone https://github.com/ankan288/zeroHack-v2.0.git
cd "zeroHack  v2.0"
```

### Step 2: Set Up a Virtual Environment (Recommended)
Creating a virtual environment ensures that zeroHack's dependencies don't conflict with other Python packages on your system.

**For Windows:**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

**For Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Required Dependencies
Install the required packages using `pip`.

**For Windows:**
```powershell
pip install -r requirements.txt
```

**For Linux/macOS:**
```bash
pip3 install -r requirements.txt
```

### Step 4: Verify Installation
Run the tool's help command to make sure everything is installed correctly:
```bash
python vulnscanner.py --help
```

### 🐧 Kali Linux (Quick Install)
If you are using Kali Linux, we have provided an automated installation script:
```bash
chmod +x install-kali.sh
sudo ./install-kali.sh
```

---

## 🔧 Usage

### Basic Syntax
```bash
python vulnscanner.py -t <target> [options]
```

### Quick Examples
```bash
# Basic scan
python vulnscanner.py -t example.com

# Moderate intensity
python vulnscanner.py -t example.com -l moderate

# Extreme with JSON output
python vulnscanner.py -t example.com -l extreme -o report.json

# Web-only (skip network scanning)
python vulnscanner.py -t example.com --no-subdomain --no-port-scan
```

---

## 📋 Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target` | **Required.** Target domain to scan | - |
| `-l, --level` | Attack intensity: `normal`, `moderate`, `extreme` | `normal` |
| `-o, --output` | Output file path (JSON format) | Console |
| `--no-subdomain` | Skip subdomain enumeration | Enabled |
| `--no-port-scan` | Skip port scanning | Enabled |
| `--ports` | Port range to scan | `1-1000` |
| `--threads` | Number of concurrent threads | Level default |
| `--no-notifications` | Disable all notifications | Enabled |
| `--no-desktop` | Disable desktop alerts | Enabled |
| `--no-audio` | Disable audio alerts | Enabled |
| `--email-alerts` | Email for alerts | Disabled |
| `--cache-poisoning` | Enable cache poisoning detection | Disabled |
| `--cache-deception` | Enable cache deception testing | Disabled |

---

## ⚔️ Attack Levels

| Level | Threads | Timeout | Delay | Use Case |
|-------|---------|---------|-------|----------|
| 🟢 **Normal** | 10 | 5s | 1s | Initial recon, stealth |
| 🟡 **Moderate** | 25 | 10s | 0.5s | Comprehensive assessment |
| 🔴 **Extreme** | 50 | 15s | 0.1s | Maximum coverage, pentesting |

---

## 🛡️ Security Modules

### 16 Specialized Modules:

| Module | Description |
|--------|-------------|
| `sql_injection.py` | SQL Injection testing with 320+ payloads, WAF bypass |
| `xss_tester.py` | Reflected, Stored, DOM-based XSS detection |
| `ssrf_tester.py` | Server-Side Request Forgery with bypass techniques |
| `rce_tester.py` | Remote Code Execution, Command Injection |
| `idor_tester.py` | Insecure Direct Object Reference testing |
| `smart_contract_tester.py` | Smart contract security (7 Immunefi cases - $14M+) |
| `api_security_tester.py` | GraphQL, JWT, Mass Assignment |
| `cloud_security_tester.py` | AWS, Azure, GCP misconfigurations |
| `mobile_security_tester.py` | Android/iOS vulnerability testing |
| `iot_security_tester.py` | MQTT, CoAP, Industrial protocols |
| `web_cache_tester.py` | Cache poisoning, Cache deception |
| `port_scanner.py` | TCP/UDP port scanning |
| `subdomain_enum.py` | Subdomain enumeration |
| `web3_tester.py` | Web3/Blockchain security |
| `additional_vulns.py` | Additional vulnerability tests |
| `notification_system.py` | Real-time alerts (Desktop, Audio, Email) |

---

## 📁 Project Structure

```
zeroHack-v2.0/
├── vulnscanner.py           # Main application
├── requirements.txt         # Python dependencies
├── setup.py                 # Package setup
├── LICENSE                  # MIT License
├── README.md                # This file
├── install-kali.sh          # Kali Linux installer
├── .gitignore               # Git ignore rules
├── __init__.py              # Package init
└── modules/                 # Security modules (17 files)
    ├── __init__.py
    ├── sql_injection.py
    ├── xss_tester.py
    ├── ssrf_tester.py
    ├── rce_tester.py
    ├── idor_tester.py
    ├── smart_contract_tester.py
    ├── api_security_tester.py
    ├── cloud_security_tester.py
    ├── mobile_security_tester.py
    ├── iot_security_tester.py
    ├── web_cache_tester.py
    ├── port_scanner.py
    ├── subdomain_enum.py
    ├── web3_tester.py
    ├── additional_vulns.py
    └── notification_system.py
```

---

## 📊 Output Format

### JSON Report Structure
```json
{
  "target": "example.com",
  "level": "extreme",
  "scan_time": {
    "start": "2025-12-30T10:00:00",
    "end": "2025-12-30T10:30:00"
  },
  "subdomains": [],
  "open_ports": [],
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "Critical",
      "url": "https://example.com/api/user",
      "parameter": "id",
      "payload": "' OR 1=1--",
      "evidence": "Database error in response",
      "remediation": "Use parameterized queries"
    }
  ],
  "summary": {
    "total_vulnerabilities": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2
  }
}
```

### Severity Levels
- 🔴 **Critical** - Immediate action required
- 🟠 **High** - Serious vulnerability
- 🟡 **Medium** - Moderate risk
- 🟢 **Low** - Minor issue

---

## 💡 Examples

### 1. Basic Scan
```bash
python vulnscanner.py -t testsite.com
```

### 2. Full Scan with Report
```bash
python vulnscanner.py -t testsite.com -l extreme -o report.json
```

### 3. Web-Only Scan (Faster)
```bash
python vulnscanner.py -t testsite.com --no-subdomain --no-port-scan
```

### 4. Extended Port Range
```bash
python vulnscanner.py -t testsite.com --ports 1-65535 --threads 100
```

### 5. Silent Mode with Output
```bash
python vulnscanner.py -t testsite.com -l extreme --no-notifications -o results.json
```

### 6. With Email Alerts
```bash
python vulnscanner.py -t testsite.com --email-alerts security@company.com
```

### 7. Cache Vulnerability Testing
```bash
python vulnscanner.py -t testsite.com --cache-poisoning --cache-deception
```

---

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| Module not found | `pip install -r requirements.txt --force-reinstall` |
| Permission denied | Run as admin (Windows) or use `sudo` (Linux) |
| Connection timeout | Use `-l moderate` for longer timeouts |
| Too many false positives | Use `-l normal` for cleaner results |

---

## ⚖️ Legal Disclaimer

```
⚠️ IMPORTANT: AUTHORIZED USE ONLY

This tool is for AUTHORIZED security testing only.

✅ ALLOWED:
- Testing systems you own
- Authorized penetration testing
- Bug bounty programs (within scope)
- Educational purposes

❌ PROHIBITED:
- Unauthorized scanning
- Malicious attacks
- Violation of laws

The developers are NOT responsible for misuse.
Unauthorized access to computer systems is ILLEGAL.
```

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

```
Copyright (c) 2025 ZeroHack Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-module`)
3. Commit changes (`git commit -m 'Add new module'`)
4. Push to branch (`git push origin feature/new-module`)
5. Open Pull Request

---

## 📞 Contact

- **GitHub Issues**: Bug reports and feature requests
- **Email**: security@zerohack.dev

---

<div align="center">

**Made with ❤️ by ZeroHack Team**

⭐ **Star this repo if you find it useful!**

*Version 2.0 | December 2025*

</div>
