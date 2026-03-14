# URL Security Scanner CLI

Cloudflare + VirusTotal + Multi-API Security Analysis Tool

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> 교육 및 보안 연구 목적의 URL 보안 분석 도구

## Features

### 1. URL Structure Analysis
- HTTPS usage verification
- Suspicious character detection
- Direct IP address usage check
- Suspicious TLD detection (.tk, .ml, .ga, etc.)
- URL length and subdomain count analysis

### 2. DNS Records Check
- A record lookup
- MX record verification
- DNS record existence validation

### 3. SSL/TLS Certificate Check
- Certificate validity verification
- Issuer information lookup
- Expiration date check
- Certificate version inspection

### 4. Malicious Pattern Detection
- Phishing keyword detection (login, verify, banking, etc.)
- Suspicious pattern inspection
- Random string detection

### 5. Cloudflare DNS Filtering
- Uses Cloudflare 1.1.1.2 (Malware Blocking DNS)
- Automatic blocked site detection
- Real-time filtering verification

## Installation

### Automatic Installation
```bash
install.bat
```

### Manual Installation
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python scanner_cli.py https://example.com
```

### Using Batch File
```bash
run.bat https://example.com
```

### Without Protocol
```bash
python scanner_cli.py example.com
```

### Verbose Mode
```bash
python scanner_cli.py https://example.com -v
```

## Examples

### Safe Site
```bash
python scanner_cli.py https://google.com
```

### Suspicious Site
```bash
python scanner_cli.py http://suspicious-site.tk
```

### Dangerous Site
```bash
python scanner_cli.py http://192.168.1.1/phishing
```

## Risk Levels

- **SAFE (0-19)**: Safe site
- **LOW (20-39)**: Low risk
- **MEDIUM (40-59)**: Medium risk
- **HIGH (60-100)**: High risk

## Detailed Checks

### URL Structure Analysis
```
- No HTTPS: +30 points
- Suspicious characters: +20 points
- IP address usage: +25 points
- Suspicious TLD: +20 points
- Long URL (100+ chars): +15 points
- Many subdomains (3+): +10 points
```

### Cloudflare DNS Filtering
```
- Cloudflare 1.1.1.2 DNS usage
- Blocked site: +80 points
- NXDOMAIN: +70 points
```

### Malicious Patterns
```
- Phishing keyword found: +10 points per keyword
- Suspicious pattern: +15 points per pattern
```

## Cloudflare Integration

### Cloudflare DNS Servers
- **1.1.1.2**: Malware blocking
- **1.0.0.2**: Backup DNS

### How It Works
1. Extract domain from input URL
2. Query A record via Cloudflare DNS
3. If blocked, returns 0.0.0.0 or 127.0.0.1
4. Reflect blocking status in results

## Requirements

- Python 3.6+
- dnspython
- requests
- colorama

## Output Example

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           URL Security Scanner v1.0                       ║
║        Cloudflare + Multi-API Analysis Tool               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

Target URL: https://example.com

============================================================
[*] URL Structure Analysis
============================================================
  Protocol: HTTPS
  Domain: example.com
  Path: /
  URL Length: 20
  Subdomain Count: 1

  Risk Score: 0/100

============================================================
[*] DNS Records Check
============================================================
  A Records: 93.184.216.34
  MX Records: 0 found

  Risk Score: 0/100

============================================================
[*] SSL/TLS Certificate Check
============================================================
  Issuer: DigiCert Inc
  Subject: example.com
  Expires: Dec 31 23:59:59 2024 GMT
  Days Until Expiry: 250

  Risk Score: 0/100

============================================================
[*] Malicious Pattern Detection
============================================================
  Suspicious Keywords: None detected

  Risk Score: 0/100

============================================================
[*] Cloudflare DNS Filtering Check
============================================================
  Cloudflare Status: Passed - Not blocked

  Risk Score: 0/100

============================================================
[*] FINAL ANALYSIS RESULTS
============================================================

██████████████████████████████████████████████████

  Risk Level: SAFE
  Risk Score: 0/100

============================================================
[*] RECOMMENDATIONS
============================================================

  ✓ This site appears to be safe.

Scan completed at: 2024-01-15 10:30:45
```

## Troubleshooting

### DNS Resolution Error
- Check internet connection
- Verify DNS server accessibility
- Try different DNS server

### SSL Certificate Error
- Site may not support HTTPS
- Certificate may be expired
- Firewall may be blocking connection

### Timeout Error
- Site may be down
- Network connection may be slow
- Increase timeout value

## Notes

- Analysis results are for reference only and may not be 100% accurate
- Always exercise caution when visiting unknown sites
- Do not enter personal information on suspicious sites

## License

Free to use and modify

---

**Warning**: Use this tool responsibly. Do not use it for illegal purposes.
