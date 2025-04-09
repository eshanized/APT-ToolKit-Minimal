#!/bin/bash

set -e  # Exit on error

echo "[+] Initializing Automated Penetration Testing Toolkit setup..."

# Check for dependencies
command -v python3 >/dev/null 2>&1 || { echo >&2 "[-] Python3 is not installed. Aborting."; exit 1; }
command -v pip >/dev/null 2>&1 || { echo >&2 "[-] pip is not installed. Aborting."; exit 1; }

# Create virtual environment
echo "[+] Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# Create requirements.txt if it doesn't exist
if [ ! -f requirements.txt ]; then
    echo "[*] Creating default requirements.txt..."
    echo "PyQt6" > requirements.txt
fi

# Upgrade pip and install basic dependencies
echo "[+] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create project structure
echo "[+] Creating directory structure..."
mkdir -p \
    src/modules \
    src/ui \
    src/utils \
    src/templates \
    src/wordlists \
    src/core \
    src/data \
    tests \
    scripts

# Create UI files
echo "[+] Creating .ui files..."
touch src/ui/{main_window,recon,vuln_scanner,brute_force,payload_gen,exploit_exec,report,settings,logs,scan_result,terminal}.ui

# Create main entry point
echo "[+] Creating main script..."
cat <<EOF > src/main.py
from PyQt6 import QtWidgets
import sys

def main():
    app = QtWidgets.QApplication(sys.argv)
    # Load UI here
    print("[*] APT Toolkit UI started.")
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
EOF

# Create Python module files
echo "[+] Creating module files..."
touch src/modules/{recon,vuln_scanner,brute_force,payload_gen,exploit_exec,report_gen,auth_bypass,web_scanner,network_mapper,service_enum,scan_engine}.py

# Create utility files
touch src/utils/{logger.py,helpers.py,validators.py,config.py,network.py}

# Create core engine files
touch src/core/{engine.py,dispatcher.py,thread_pool.py,scheduler.py,plugin_loader.py}

# Create template and wordlist placeholders
echo "[+] Creating HTML template and wordlists..."
touch src/templates/report_template.html
touch src/wordlists/{common_passwords.txt,subdomains.txt,usernames.txt}

# Create test files
echo "[+] Creating test cases..."
touch tests/{test_recon.py,test_brute_force.py,test_vuln_scanner.py}

# Create helper scripts
echo "[+] Creating utility scripts..."
cat <<EOF > scripts/run_gui.sh
#!/bin/bash
source ../.venv/bin/activate
python ../src/main.py
EOF

chmod +x scripts/run_gui.sh

# Create README
echo "[+] Creating README..."
cat <<EOF > README.md
# 🔐 Automated Penetration Testing Toolkit

A modular, Python-based penetration testing toolkit with GUI and CLI support.

## Modules:
- Reconnaissance
- Vulnerability Scanning
- Brute Force Attacks
- Payload Generation
- Exploit Execution
- Reporting
EOF

# Create .gitignore
echo "[+] Creating .gitignore..."
cat <<EOF > .gitignore
.venv/
__pycache__/
*.pyc
*.log
EOF

# Qt Designer reminder
echo "[*] Reminder: For UI development, make sure you have Qt Designer installed (often part of qttools)."

echo "[+] Project setup complete. Activate with 'source .venv/bin/activate' and run with './scripts/run_gui.sh'"

