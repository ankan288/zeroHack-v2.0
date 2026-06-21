# ⚡ ZeroHack v2.0

> **Advanced Vulnerability Assessment Tool** — Multi-module, CLI + TUI, async + sync, with built-in benchmark evaluation.

```
 ______              _   _            _    
|___  /             | | | |          | |   
   / /  ___ _ __ ___| |_| | __ _  ___| | __
  / /  / _ \ '__/ _ \ __| |/ _` |/ __| |/ /
 / /__| (_) | | | (_) | |_| | (_| | (__|   < 
/_____|\___/|_|  \___/ \__|_|\__,_|\___|_|\_\
                                    v2.0
```

---

## ⚠️ Legal Disclaimer

> This tool is intended for **authorized security testing only**.  
> Running it against systems you do not own or have explicit written permission to test is **illegal**.  
> The developers assume no liability for misuse.

---

## 🚀 Features

| Category | Modules |
|----------|---------|
| **Web App** | SQL Injection, XSS, SSRF, RCE/SSTI, IDOR, Web Cache Poisoning, Business Logic, CORS/Headers/LFI/XXE |
| **Network** | Port Scanner (with Nmap comparison), Subdomain Enumeration |
| **API/REST** | JWT attacks, GraphQL introspection, Rate limiting, Mass assignment, BOLA |
| **Cloud** | AWS IMDS / S3, GCP Metadata, Azure IMDS, Env variable exposure |
| **IoT** | Default credentials, MQTT open access, UPnP, Telnet |
| **Mobile** | APK static analysis, Hardcoded secrets, SSL bypass, Mobile API |
| **Blockchain** | Smart contract reentrancy/overflow/tx.origin, Web3 RPC, Flash loan surface |

**Interface**: Both CLI and interactive Rich TUI  
**Scanning**: Both async (concurrent) and sync modes  
**Reports**: Both JSON + styled HTML (with Chart.js)  
**Benchmarking**: Full evaluation framework with 0-100 capability score

---

## 🛠 Installation

### Requirements
- Python 3.9+
- pip

### Install Dependencies

```bash
cd "e:\cyber tool\zeroHack-v2.0"
pip install -r requirements.txt
```

### Install as Package (adds `zerohack` command)

```bash
pip install -e .
```

---

## 🎯 Usage

### Interactive TUI (no arguments)

```bash
python vulnscanner.py
```

Launches a Rich-based interactive menu where you select target, modules, and options.

### CLI Mode

```bash
# Scan with specific modules
python vulnscanner.py --target http://testphp.vulnweb.com --modules sql,xss,headers

# Full scan with all modules
python vulnscanner.py --target http://localhost/dvwa --all

# Async mode (concurrent requests)
python vulnscanner.py --target https://example.com --all --async-mode

# With proxy (Burp Suite)
python vulnscanner.py --target http://localhost/dvwa --modules sql,xss --proxy http://127.0.0.1:8080

# With session cookies
python vulnscanner.py --target http://localhost/dvwa --cookies "PHPSESSID=abc123;security=low"

# With APK analysis
python vulnscanner.py --target http://api.myapp.com --modules mobile --apk myapp.apk

# Custom port range
python vulnscanner.py --target http://localhost --modules ports --port-range 1-1024

# List all modules
python vulnscanner.py --list-modules
```

### Module Keys Reference

| Key | Module | Category |
|-----|--------|----------|
| `sql` | SQL Injection | Web |
| `xss` | XSS (Reflected/Stored/DOM) | Web |
| `ssrf` | Server-Side Request Forgery | Web |
| `rce` | RCE / Command Injection / SSTI | Web |
| `idor` | Insecure Direct Object Reference | Web |
| `headers` | Security Headers / CORS / LFI / XXE | Web |
| `cache` | Web Cache Poisoning | Web |
| `logic` | Business Logic | Web |
| `ports` | Port Scanner + Nmap comparison | Network |
| `subdomain` | Subdomain Enumeration | Network |
| `api` | API Security (JWT, GraphQL, Rate limiting) | API |
| `cloud` | Cloud Security (AWS/GCP/Azure) | Cloud |
| `iot` | IoT Security | IoT |
| `mobile` | Mobile Security + APK Analysis | Mobile |
| `contract` | Smart Contract Security | Blockchain |
| `web3` | Web3 / DeFi Security | Blockchain |

---

## 📊 Benchmark Evaluation

Objectively measure your tool's capabilities against known-vulnerable targets.

### Quick Benchmark (no Docker needed)

```bash
# Against Acunetix test site (publicly available, deliberately vulnerable)
python benchmark_eval.py --target http://testphp.vulnweb.com

# Quick mode (4 core modules only)
python benchmark_eval.py --target http://testphp.vulnweb.com --quick
```

### Full Benchmark with Nmap Comparison

```bash
python benchmark_eval.py --target http://localhost --all --compare-nmap
```

### Against DVWA (requires local setup)

```bash
# Start DVWA with Docker
docker run -d -p 80:80 vulnerables/web-dvwa

# Run benchmark
python benchmark_eval.py --target http://localhost/dvwa
```

### Against OWASP Juice Shop (requires local setup)

```bash
# Start Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Run benchmark
python benchmark_eval.py --target http://localhost:3000
```

### Benchmark Metrics

| Metric | Description | Weight |
|--------|-------------|--------|
| **Detection Rate** | % of known vulns identified | 40 pts |
| **Coverage Score** | % of vuln categories tested | 30 pts |
| **Speed Score** | Avg module response time | 20 pts |
| **False Positive Penalty** | Deduct per estimated FP | 10 pts |

**Score Range**: 0–100 (`≥70` = capable, `≥40` = moderate, `<40` = needs improvement)

---

## 📁 Output Files

| File | Description |
|------|-------------|
| `zerohack_report.json` | Machine-readable findings with full metadata |
| `zerohack_report.html` | Interactive HTML report with charts, filtering, severity badges |
| `benchmark_report.json` | Benchmark metrics in JSON |
| `benchmark_report.html` | Visual benchmark dashboard with score, charts, module perf |

---

## 🔬 Testing Against Controlled Environments

### Recommended Test Targets

| Target | Vulnerabilities | Setup |
|--------|----------------|-------|
| [testphp.vulnweb.com](http://testphp.vulnweb.com) | SQLi, XSS, LFI | None (public) |
| [DVWA](https://github.com/digininja/DVWA) | SQLi, XSS, RCE, LFI, CSRF, File Upload | Docker |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | Full OWASP Top 10 | Docker |
| [WebGoat](https://github.com/WebGoat/WebGoat) | Multi-category | Docker |

### Side-by-Side Comparison (Nmap)

The port scanner module automatically runs Nmap when available and displays:
- Ports found by ZeroHack only
- Ports found by Nmap only  
- Agreement percentage

---

## 🏗 Architecture

```
zerohack-v2.0/
├── vulnscanner.py          # Main CLI + TUI entry point
├── benchmark_eval.py       # Benchmark evaluation framework
├── requirements.txt
├── setup.py
└── modules/
    ├── notification_system.py   # Rich console + JSON/HTML reports
    ├── enhanced_scanner.py      # Base scanner + HTTP session + async engine
    ├── sql_injection.py         # Error/time/boolean SQLi
    ├── xss_tester.py            # Reflected/Stored/DOM XSS
    ├── ssrf_tester.py           # SSRF + cloud metadata
    ├── rce_tester.py            # CMD injection + SSTI
    ├── idor_tester.py           # IDOR + UUID testing
    ├── additional_vulns.py      # Headers, CORS, LFI, XXE
    ├── web_cache_tester.py      # Cache poisoning
    ├── business_logic_tester.py # Logic flaws + race conditions
    ├── port_scanner.py          # Port scan + Nmap comparison
    ├── subdomain_enum.py        # DNS + crt.sh CT logs
    ├── api_security_tester.py   # JWT, GraphQL, BOLA
    ├── cloud_security_tester.py # AWS/GCP/Azure
    ├── iot_security_tester.py   # Default creds, MQTT, UPnP
    ├── mobile_security_tester.py # APK analysis, TLS
    ├── smart_contract_tester.py  # Solidity static analysis
    └── web3_tester.py           # Web3 RPC + DeFi
```

---

## 📈 Severity Classification

| Level | CVSS Range | Description |
|-------|-----------|-------------|
| 🔴 **CRITICAL** | 9.0–10.0 | Immediate exploitation possible (SQLi, RCE, Stored XSS) |
| 🟠 **HIGH** | 7.0–8.9 | Significant impact, requires some conditions |
| 🟡 **MEDIUM** | 4.0–6.9 | Moderate risk, defense-in-depth weakness |
| 🔵 **LOW** | 1.0–3.9 | Minor issue, informational value |
| ⬜ **INFO** | 0.0 | Informational only, no direct security impact |

---

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

---

*ZeroHack v2.0 — For authorized security research only.*
