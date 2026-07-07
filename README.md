# SENTINEL

> Analyze. Detect. Secure.

SENTINEL is a cybersecurity intelligence CLI tool for ethical security assessment of domains and websites. Built for developers, DevOps engineers, security students, and sysadmins.

---

Warning: **Ethical Use Only** - Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.

---

## Features

- Website scanner with security scoring
- SSL certificate checker with expiry warnings
- DNS lookup (A, MX, TXT, NS, AAAA)
- WHOIS domain information
- Security headers analysis
- Port scanner (common ports)
- IP geolocation intelligence
- Cryptographic password generator
- Hash generator (SHA-256, SHA-512, MD5)
- Security report generator (Markdown + PDF)

---

## Installation

```bash
pip install sentinel-cli
```

---

## Usage

```bash
sentinel --help
sentinel scan example.com
sentinel ssl example.com
sentinel dns google.com
sentinel whois openai.com
sentinel headers github.com
sentinel ports example.com
sentinel ip 8.8.8.8
sentinel password --length 24
sentinel hash "Hello World" --algo sha256
sentinel report example.com
```

---

## Tech Stack

- Python 3.10+
- Typer - CLI framework
- Rich - terminal UI
- Requests - HTTP
- dnspython - DNS queries
- python-whois - WHOIS data
- ReportLab - PDF generation

---

## License

MIT (c) Khizar Arain
