#!/bin/bash
set -e

echo "Setting up security agent environment..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
  echo "Creating virtual environment..."
  python -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Uninstall potentially conflicting packages
echo "Removing any conflicting packages..."
pip uninstall -y web3 eth-abi eth-account eth-hash eth-typing eth-utils hexbytes rlp slither-analyzer mythril manticore 2>/dev/null || true

# Install core requirements first
echo "Installing core requirements..."
pip install -r requirements.txt

# Install AI/LLM requirements
echo "Installing AI/LLM requirements..."
pip install -r requirements-ai.txt

# Install web3 basic requirements
echo "Installing Web3 basic requirements..."
pip install -r requirements-web3.txt

echo "Installation complete!"
echo ""
echo "To install security analysis tools, run the following commands separately:"
echo "  pip install -r requirements-slither.txt"
echo "  pip install -r requirements-mythril.txt"
echo "  pip install -r requirements-manticore.txt"
echo ""
echo "These are kept separate to avoid dependency conflicts." 