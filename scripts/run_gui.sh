#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Define colors for terminal output
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
RESET="\033[0m"

echo -e "${GREEN}Starting APT Toolkit...${RESET}"
echo -e "Project directory: ${PROJECT_ROOT}"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed. Please install Python 3 to run this application.${RESET}"
    exit 1
fi

# Activate the virtual environment
if [ -d "$PROJECT_ROOT/.venv" ]; then
    echo -e "${GREEN}Activating virtual environment...${RESET}"
    source "$PROJECT_ROOT/.venv/bin/activate"
else
    echo -e "${YELLOW}Virtual environment not found. Creating a new one...${RESET}"
    
    # Check if python3-venv is installed
    if ! python3 -m venv --help &> /dev/null; then
        echo -e "${RED}Error: python3-venv is not installed.${RESET}"
        echo -e "Please install it using:"
        echo -e "  sudo apt-get install python3-venv  # Debian/Ubuntu"
        echo -e "  sudo dnf install python3-venv      # Fedora"
        echo -e "  sudo pacman -S python-virtualenv   # Arch Linux"
        exit 1
    fi
    
    # Create virtual environment
    python3 -m venv "$PROJECT_ROOT/.venv"
    source "$PROJECT_ROOT/.venv/bin/activate"
    
    echo -e "${GREEN}Installing required packages...${RESET}"
    pip install -r "$PROJECT_ROOT/requirements.txt"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install required packages. Please check your internet connection and try again.${RESET}"
        exit 1
    fi
fi

# Check if PyQt6 is installed (required for GUI)
if ! pip list | grep -q "PyQt6"; then
    echo -e "${YELLOW}PyQt6 not found. Installing required packages...${RESET}"
    pip install -r "$PROJECT_ROOT/requirements.txt"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to install PyQt6. Please install it manually:${RESET}"
        echo -e "  pip install PyQt6"
        deactivate
        exit 1
    fi
fi

# Run the main application
echo -e "${GREEN}Starting APT Toolkit GUI...${RESET}"
cd "$PROJECT_ROOT"
python src/main.py

# Capture exit code
EXIT_CODE=$?

# Deactivate the virtual environment when the application exits
deactivate

# Check if application exited with an error
if [ $EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Application exited with an error (code: $EXIT_CODE).${RESET}"
    echo -e "Check the logs for more information."
    exit $EXIT_CODE
else
    echo -e "${GREEN}APT Toolkit closed successfully.${RESET}"
fi
