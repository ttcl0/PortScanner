# IP Port Scanner

A fast and flexible IP port scanner for IPv4 and IPv6 featuring Light, Deep and Targeted scan modes with support for custom port lists.

## Features

- Supports both IPv4 and IPv6  
- Simple step by step input in the terminal  
- Multiple scan modes for different use cases  
- Custom port scanning via file input  

## How It Works

When you run the script, it will guide you through the process:

1. Enter a target IP address (IPv4 or IPv6)  
2. Select a scan mode  
   - `1` for Light scan  
   - `2` for Deep scan  
   - `3` for Targeted scan  

## Scan Modes

**Light Scan**  
Scans a small set of common ports for quick results.

**Deep Scan**  
Scans a wider range of ports for a more thorough check.

**Targeted Scan**  
Scans only the ports listed in `targeted_ports.txt`.

## Usage

You can run the script in two ways:

**Option 1: Double click**
- Simply double click `portscanner.py`

**Option 2: Run in terminal**
```bash
python portscanner.py
