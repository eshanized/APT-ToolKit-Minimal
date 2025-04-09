# 🔐 Automated Penetration Testing Toolkit

![CI](https://github.com/eshanized/APT-ToolKit-Minimal/actions/workflows/test.yml/badge.svg)


A modular, Python-based penetration testing toolkit with GUI and CLI support.

## Modules:
- Reconnaissance
- Vulnerability Scanning
- Brute Force Attacks
- Payload Generation
- Exploit Execution
- Reporting

## Requirements

### System Dependencies

- Python 3.8+
- Qt6 libraries
- Nmap (for network scanning functionality)

### Python Dependencies

All Python dependencies are listed in the `requirements.txt` file and can be installed using pip:

```
pip install -r requirements.txt
```

## Installation

1. Install system dependencies:

   **For Debian/Ubuntu:**
   ```
   sudo apt-get update
   sudo apt-get install python3 python3-pip python3-venv nmap
   ```

   **For Fedora/RHEL:**
   ```
   sudo dnf install python3 python3-pip python3-venv nmap
   ```

   **For Arch Linux:**
   ```
   sudo pacman -S python python-pip python-virtualenv nmap
   ```

2. Clone the repository:
   ```
   git clone https://github.com/your-username/Project-N.git
   cd Project-N
   ```

3. Create and activate a virtual environment:
   ```
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the GUI application:

```
python src/main.py
```

Or use the provided script:

```
./scripts/run_gui.sh
```

## Features

- **Network Reconnaissance**: Discover hosts and services on a network
- **Vulnerability Scanning**: Identify security vulnerabilities in systems
- **Network Mapping**: Map out network topology with Nmap integration
- **Exploitation Tools**: Tools for testing security measures
- **Reporting**: Generate comprehensive security reports

## License

This project is licensed under the MIT License - see the LICENSE file for details.
