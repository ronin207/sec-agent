#!/bin/bash
set -e

echo "Installing Slither Analyzer and dependencies..."

# Check if running in a virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
  echo "Warning: Not running in a virtual environment. It's recommended to use a dedicated environment for Slither."
  echo "Would you like to create a new virtual environment? (y/n)"
  read -r choice
  if [[ "$choice" =~ ^[Yy]$ ]]; then
    # Create a virtual environment
    python -m venv slither-env
    source slither-env/bin/activate
    echo "Created and activated slither-env virtual environment"
  fi
fi

# Uninstall potentially conflicting packages first
echo "Removing any conflicting packages..."
pip uninstall -y web3 eth-abi eth-hash eth-account eth-typing 2>/dev/null || true

# Install slither with compatible web3 version
echo "Installing slither-analyzer with compatible dependencies..."
pip install slither-analyzer==0.9.5 web3==6.0.0

echo "Slither installation complete!"
echo "To verify installation, run: slither --version" 