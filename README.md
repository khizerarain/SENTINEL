# SENTINEL

**SENTINEL — Cybersecurity Intelligence CLI**

Analyze. Detect. Secure.

⚠️ SENTINEL is intended for use on systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction. Use responsibly.

## Overview

SENTINEL is a Python-based cybersecurity intelligence CLI for ethical security assessment, designed for developers, DevOps engineers, security students, and sysadmins. It helps inspect domains and websites with network, SSL, DNS, WHOIS, header, port, and report capabilities.

The port scanner checks common TCP services and highlights open ports while reminding users to only scan authorized systems.

The SSL checker verifies certificate validity, issuer details, and expiry warnings for soon-to-expire certificates.

The DNS lookup module resolves A, AAAA, MX, TXT, and NS records and displays them in a Rich table for quick inspection.

The password generator uses the secure `secrets` module and can produce high-entropy credentials with optional symbol exclusion.

The hashing command supports SHA-256, SHA-512, and MD5, with a warning flag for MD5 usage.

This tool is intended for authorized security testing only and includes a prominent ethical use disclaimer in both the README and startup UI.

## Tech Stack

- Python 3.10+
- Typer
- Rich
- Requests
- dnspython
- python-whois
- reportlab
- ssl / socket
- hashlib

## Installation

```bash
pip install -r requirements.txt
```

## Testing

Run the included CLI validation suite with:

```bash
python -m unittest discover tests
```

```

## Usage

```bash
python main.py
```

### Commands

- `sentinel scan <domain>` — Run a full site security scan
- `sentinel ssl <domain>` — Inspect SSL/TLS certificate details
- `sentinel dns <domain>` — Query DNS records
- `sentinel whois <domain>` — Fetch WHOIS registration details
- `sentinel headers <domain>` — Validate security headers
- `sentinel ports <domain>` — Scan common TCP ports
- `sentinel ip [ip-address]` — Look up IP geolocation
- `sentinel password [--length INT] [--no-symbols]` — Generate a secure password
- `sentinel hash [--algo sha256|sha512|md5] <text>` — Compute a hash digest
- `sentinel report <domain>` — Generate Markdown and PDF security reports

### Examples

```bash
python main.py scan example.com
python main.py ssl example.com
python main.py dns example.com
python main.py whois example.com
python main.py headers example.com
python main.py ports example.com
python main.py ip 8.8.8.8
python main.py password --length 20
python main.py password --no-symbols
python main.py hash --algo sha256 "important text"
python main.py report example.com
```

## Report Generation

SENTINEL can create both Markdown and PDF security reports for audited domains. The PDF report uses ReportLab for a clean layout with headings, technical details, and a security score summary.

## Ethical Use Disclaimer

> ⚠️ SENTINEL is intended for use on systems you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction. Use responsibly.

## Screenshot

![SENTINEL Screenshot](screenshot.png)
