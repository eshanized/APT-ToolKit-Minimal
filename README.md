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

## New Feature: Data Visualization

The latest update includes a powerful data visualization feature for reconnaissance results. This allows you to:

- View a network graph of hosts and their open ports
- Analyze port distribution with interactive bar charts
- Explore subdomains with a hierarchical visualization
- Get a comprehensive summary dashboard

### Using the Visualization Feature

1. Run a reconnaissance scan
2. After the scan completes, the results will automatically be displayed in the Visualization tab
3. You can switch between different visualization types using the controls at the bottom
4. Export visualizations to PNG, JPEG, PDF, or SVG formats using the Export button

### Installing Visualization Dependencies

To use the visualization features, you need to install the required dependencies:

```bash
# Using the provided script
./install_viz_deps.sh

# Or manually with pip
pip install matplotlib>=3.5.0 networkx>=2.7.0 numpy>=1.22.0 pyqtgraph>=0.12.0
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
