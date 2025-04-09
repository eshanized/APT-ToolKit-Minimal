#!/usr/bin/env python3
"""
Utility script to check if required system dependencies are installed.
"""

import os
import platform
import shutil
import sys
import importlib.util

def check_nmap_installed():
    """Check if nmap is installed on the system."""
    return shutil.which('nmap') is not None

def get_nmap_installation_instructions():
    """
    Get platform-specific instructions for installing nmap
    Returns a string with installation instructions
    """
    platform = sys.platform
    
    if platform == "linux" or platform == "linux2":
        # Linux
        return "sudo apt-get install nmap\nor\nsudo yum install nmap"
    elif platform == "darwin":
        # macOS
        return "brew install nmap\nor\nport install nmap"
    elif platform == "win32":
        # Windows
        return "Download and install from https://nmap.org/download.html"
    else:
        # Unknown platform
        return "Install nmap from https://nmap.org/download.html"

def check_dependencies():
    """
    Check if all required dependencies are installed.
    Returns a list of tuples (dependency_name, installation_instructions) for missing dependencies.
    """
    missing_deps = []
    
    # PyQt6 dependencies
    pyqt_deps = [
        ("PyQt6", "pip install PyQt6"),
        ("PyQt6.QtCore", "pip install PyQt6"),
        ("PyQt6.QtWidgets", "pip install PyQt6"),
        ("PyQt6.QtGui", "pip install PyQt6")
    ]
    
    for name, install_cmd in pyqt_deps:
        if not _is_module_installed(name):
            missing_deps.append((name, install_cmd))
    
    # Network-related dependencies
    network_deps = [
        ("requests", "pip install requests"),
        ("python-nmap", "pip install python-nmap")
    ]
    
    for name, install_cmd in network_deps:
        if not _is_module_installed(name):
            missing_deps.append((name, install_cmd))
    
    # Other dependencies
    other_deps = [
        ("whois", "pip install python-whois"),
        ("paramiko", "pip install paramiko"),
        ("cryptography", "pip install cryptography")
    ]
    
    for name, install_cmd in other_deps:
        if not _is_module_installed(name):
            missing_deps.append((name, install_cmd))
    
    return missing_deps

def _is_module_installed(module_name):
    """
    Check if a module is installed
    """
    try:
        # Try to find the spec
        spec = importlib.util.find_spec(module_name)
        if spec is None:
            return False
        return True
    except (ImportError, ValueError):
        return False

def check_nmap_installation():
    """
    Check if nmap is installed and the python-nmap library is available.
    Returns a tuple of (system_nmap_installed, python_nmap_installed, error_message)
    """
    system_nmap_installed = False
    python_nmap_installed = False
    error_message = ""
    
    # Check if system nmap is installed
    try:
        import subprocess
        result = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
        if result.returncode == 0:
            system_nmap_installed = True
        else:
            error_message = "Nmap is not installed on the system."
    except Exception as e:
        error_message = f"Error checking for nmap: {str(e)}"
    
    # Check if python-nmap is installed
    try:
        import nmap
        python_nmap_installed = True
    except ImportError:
        if error_message:
            error_message += " Python-nmap library is not installed."
        else:
            error_message = "Python-nmap library is not installed."
    
    return system_nmap_installed, python_nmap_installed, error_message

if __name__ == "__main__":
    missing = check_dependencies()
    if missing:
        print("Missing dependencies:")
        for dep, cmd in missing:
            print(f"  - {dep}: {cmd}")
    else:
        print("All dependencies are installed.") 