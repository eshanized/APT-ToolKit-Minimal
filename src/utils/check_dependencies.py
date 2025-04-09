#!/usr/bin/env python3
"""
Utility script to check if required system dependencies are installed.
"""

import os
import platform
import shutil
import sys

def check_nmap_installed():
    """Check if nmap is installed on the system."""
    return shutil.which('nmap') is not None

def get_nmap_installation_instructions():
    """Get platform-specific instructions for installing nmap."""
    system = platform.system().lower()
    
    if system == 'linux':
        # Check for specific distributions
        try:
            with open('/etc/os-release', 'r') as f:
                os_info = f.read().lower()
                
            if 'ubuntu' in os_info or 'debian' in os_info:
                return "sudo apt-get update && sudo apt-get install -y nmap"
            elif 'fedora' in os_info or 'rhel' in os_info or 'centos' in os_info:
                return "sudo dnf install -y nmap"
            elif 'arch' in os_info:
                return "sudo pacman -S nmap"
            else:
                return "Please install nmap using your distribution's package manager."
        except:
            return "Please install nmap using your distribution's package manager."
    
    elif system == 'darwin':  # macOS
        return "brew install nmap"
    
    elif system == 'windows':
        return "Please download and install nmap from https://nmap.org/download.html"
    
    return "Please install nmap from https://nmap.org/download.html"

def check_dependencies():
    """Check all required dependencies and return a list of missing ones."""
    missing_deps = []
    
    if not check_nmap_installed():
        missing_deps.append(("nmap", get_nmap_installation_instructions()))
    
    return missing_deps

if __name__ == "__main__":
    missing = check_dependencies()
    
    if missing:
        print("The following dependencies are missing:")
        for dep, instructions in missing:
            print(f"- {dep}: {instructions}")
        sys.exit(1)
    else:
        print("All dependencies are installed.")
        sys.exit(0) 