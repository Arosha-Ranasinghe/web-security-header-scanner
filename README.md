# Web Security Header Scanner

A pentest-style Python tool that scans a target website for common HTTP security headers and reports:

- Whether each header is **PRESENT**, **MISSING**, or **WEAK**
- What each header helps protect against
- A simple score and overall risk rating
- Optional JSON report output for evidence/reporting

## Headers checked
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Features
- Professional colored terminal output (`--no-color` to disable)
- Scans multiple endpoints (`--paths /,/login,/admin`)
- Detects basic misconfigurations (e.g., weak HSTS max-age, CSP `unsafe-inline`)
- Exports JSON reports (`--json report.json`)
- Beginner-friendly, well-commented code

## Installation
```bash
pip install -r requirements.txt
```

## Usage

Scan a single endpoint:
```bash
python web_security_header_scanner.py --url https://example.com
```

Scan multiple endpoints (recommended):
```bash
python web_security_header_scanner.py --url https://example.com --paths /,/login,/admin
```

Export JSON report:
```bash
python web_security_header_scanner.py --url https://example.com --paths /,/login --json report.json
```

Disable colors / hide header values:
```bash
python web_security_header_scanner.py --url https://example.com --no-color --no-values
```

## Disclaimer
Use only on systems you own or where you have explicit permission to test.

## License
MIT
