#!/bin/bash
# UV Commands for Security Agent Project

echo "🚀 Security Agent - UV Commands"
echo "================================"

# Function to print colored output
print_step() {
    echo -e "\n\033[1;34m$1\033[0m"
}

print_step "1. Setup Virtual Environment"
echo "uv venv                    # Create virtual environment"
echo "source .venv/bin/activate  # Activate virtual environment"

print_step "2. Install Dependencies"
echo "uv sync                    # Install core dependencies"
echo "uv sync --extra ai         # Install with AI features"
echo "uv sync --extra security   # Install with security tools"
echo "uv sync --extra dev        # Install with dev tools"
echo "uv sync --extra full       # Install everything"

print_step "3. Run Commands"
echo "uv run python -m backend.main           # Run main application"
echo "uv run slither contract.sol             # Run Slither analysis"
echo "uv run python -c 'import openai'       # Test AI imports"

print_step "4. Add New Dependencies"
echo "uv add requests                         # Add core dependency"
echo "uv add --dev pytest                    # Add dev dependency"
echo "uv add --optional-group security mythril # Add to security group"

print_step "5. Update Dependencies"
echo "uv lock --upgrade          # Update lock file"
echo "uv sync                    # Sync updated dependencies"

print_step "6. Environment Management"
echo "uv venv --python 3.11      # Create with specific Python version"
echo "uv python list             # List available Python versions"
echo "uv pip list                # List installed packages"

print_step "7. Useful Commands"
echo "uv tree                    # Show dependency tree"
echo "uv pip freeze              # Show installed packages (pip format)"
echo "uv cache clean             # Clean package cache"

print_step "8. Project Information"
echo "uv show openai             # Show package information"
echo "uv pip check               # Check for dependency conflicts"

echo -e "\n\033[1;32m✅ For more information, see README-uv.md\033[0m" 