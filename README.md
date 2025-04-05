# Security Scanner Tool

A comprehensive security scanning tool that combines active and passive scanning methods with email reporting capabilities.

## Features

- DNS Record Scanning (A, AAAA, MX, NS, TXT, SOA, CNAME)
- Network Port Scanning
- Email Report Delivery
- Configurable Scan Options

## Requirements

- Python 3.x
- Required Python packages:
  - dnspython
  - python-nmap
  - sendgrid

## Installation

1. Clone the repository
2. Install required packages:
```bash
pip install dnspython python-nmap sendgrid
```

3. Set up environment variables:
- `SENDGRID_API_KEY`: Your SendGrid API key for email delivery

## Usage

Basic usage:
```bash
python scanner.py example.com
```

With email reporting:
```bash
python scanner.py example.com --email recipient@example.com
```

Selective scanning:
```bash
python scanner.py example.com --dns-only    # Only DNS scanning
python scanner.py example.com --network-only # Only network scanning
```

## Components

1. `scanner.py` - Main entry point and orchestration
2. `dns_tools.py` - DNS scanning functionality
3. `network_tools.py` - Network port scanning
4. `report_generator.py` - Report generation
5. `email_sender.py` - Email delivery using SendGrid
6. `utils.py` - Utility functions
7. `config.py` - Configuration settings

## File Structure

```
.
├── scanner.py
├── dns_tools.py
├── network_tools.py
├── report_generator.py
├── email_sender.py
├── utils.py
└── config.py
```
