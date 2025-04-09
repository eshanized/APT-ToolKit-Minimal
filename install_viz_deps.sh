#!/bin/bash

echo "Installing visualization dependencies for Project-N..."

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo "pip3 not found. Please install Python3 and pip3 first."
    exit 1
fi

# Install the visualization dependencies
pip3 install matplotlib>=3.5.0 networkx>=2.7.0 numpy>=1.22.0 pyqtgraph>=0.12.0

echo "Visualization dependencies installed successfully!"
echo "You can now run the application with visualization support." 