# Port Scanner (Nmap) - Python

A Python-based port scanner using Nmap.

## Features
- Automatic scan: service detection + default scripts + `ssl-enum-ciphers` and `dns-recursion`
- Manual scan: checks a single port and runs `ssl-enum-ciphers` and `dns-recursion` scripts if the port is open
- Detects potentially insecure services (e.g., FTP, Telnet)
- Warns if services look outdated/vulnerable (based on Nmap output)

## Requirements
- Python 3.10+
- Nmap installed on your system
- Python package: `python-nmap`

## Install
```bash
pip install -r requirements.txt
