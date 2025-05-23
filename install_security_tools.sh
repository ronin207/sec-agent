#!/bin/bash
# Security Tools Installation Script
# This script installs the security analysis tools with conflicting dependencies

echo "=== Installing Security Tools for Smart Contract Analysis ==="
echo ""

# Create a directory for the tool-specific virtual environments
mkdir -p .venv

# Check if npm is installed for solhint
if ! command -v npm &> /dev/null; then
    echo "ERROR: npm is not installed. Please install Node.js and npm first."
    echo "Visit https://nodejs.org/ for installation instructions."
    exit 1
fi

# Install solhint using npm
echo "1. Installing Solhint (requires npm)..."
npm install -g solhint
echo "✅ Solhint installed successfully"
echo ""

# Install Slither in the main environment
echo "2. Installing Slither Analysis Tool (requires eth-abi>=4.0.0)..."
pip install slither-analyzer==0.9.5
echo "✅ Slither installed successfully"
echo ""

# Create and activate a virtual environment for Mythril
echo "3. Creating a separate virtual environment for Mythril (requires eth-abi<3.0.0)..."
python -m venv .venv/mythril-env

# Activate the environment and install Mythril
echo "Installing Mythril in isolated environment..."
if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux-gnu"* ]]; then
    source .venv/mythril-env/bin/activate
    pip install mythril==0.23.15
    # Create a wrapper script
    echo '#!/bin/bash' > myth
    echo 'source "'$(pwd)'/.venv/mythril-env/bin/activate"' >> myth
    echo '"'$(pwd)'/.venv/mythril-env/bin/myth" "$@"' >> myth
    chmod +x myth
    echo "Created wrapper script: $(pwd)/myth"
    deactivate
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
    .venv/mythril-env/Scripts/activate
    pip install mythril==0.23.15
    # Create a wrapper script for Windows
    echo '@echo off' > myth.bat
    echo 'call "'$(pwd)'\\.venv\\mythril-env\\Scripts\\activate.bat"' >> myth.bat
    echo '"'$(pwd)'\\.venv\\mythril-env\\Scripts\\myth.exe" %*' >> myth.bat
    echo "Created wrapper script: $(pwd)/myth.bat"
    deactivate
else
    echo "Unsupported OS. Please manually activate the virtual environment and install Mythril."
fi

echo "✅ Mythril installed successfully in isolated environment"
echo ""

# Create and activate a virtual environment for Manticore
echo "4. Creating a separate virtual environment for Manticore..."
python -m venv .venv/manticore-env

# Activate the environment and install Manticore
echo "Installing Manticore in isolated environment..."
if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux-gnu"* ]]; then
    source .venv/manticore-env/bin/activate
    pip install manticore==0.3.7 crytic-compile==0.2.2
    # Create a wrapper script
    echo '#!/bin/bash' > manticore
    echo 'source "'$(pwd)'/.venv/manticore-env/bin/activate"' >> manticore
    echo '"'$(pwd)'/.venv/manticore-env/bin/manticore" "$@"' >> manticore
    chmod +x manticore
    echo "Created wrapper script: $(pwd)/manticore"
    deactivate
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
    .venv/manticore-env/Scripts/activate
    pip install manticore==0.3.7 crytic-compile==0.2.2
    # Create a wrapper script for Windows
    echo '@echo off' > manticore.bat
    echo 'call "'$(pwd)'\\.venv\\manticore-env\\Scripts\\activate.bat"' >> manticore.bat
    echo '"'$(pwd)'\\.venv\\manticore-env\\Scripts\\manticore.exe" %*' >> manticore.bat
    echo "Created wrapper script: $(pwd)/manticore.bat"
    deactivate
else
    echo "Unsupported OS. Please manually activate the virtual environment and install Manticore."
fi

echo "✅ Manticore installed successfully in isolated environment"
echo ""

# Install solc-select in main environment
echo "5. Installing solc-select..."
pip install solc-select==1.0.3 echidna-parade==0.2
echo "✅ solc-select installed successfully"
echo ""

echo "=== Installation Complete ==="
echo ""
echo "Usage instructions:"
echo "- Slither: Use 'slither <contract.sol>' directly"
echo "- Mythril: Use './myth analyze <contract.sol>' to run from the wrapper script"
echo "- Solhint: Use 'solhint <contract.sol>' directly"
echo "- Manticore: Use './manticore <contract.sol>' to run from the wrapper script"
echo ""
echo "Note: The wrapper scripts automatically activate the correct virtual environment" 