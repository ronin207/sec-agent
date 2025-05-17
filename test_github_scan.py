#!/usr/bin/env python
"""
Test script for GitHub repo scanning
"""
import os
import sys
import json
import argparse
import tempfile
import shutil
from backend.core.security_agent import SecurityAgent

def test_with_local_files():
    """Test with local Solidity files instead of GitHub"""
    print("No valid GitHub token available. Testing with local files instead.")
    
    # Create a temporary Solidity file
    temp_dir = tempfile.mkdtemp()
    try:
        # Create a simple vulnerable Solidity contract
        contract_content = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Vulnerable to reentrancy
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        
        // Vulnerability: State change after external call
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= _amount;
    }
}
        """
        
        sol_file = os.path.join(temp_dir, "vulnerable.sol")
        with open(sol_file, "w") as f:
            f.write(contract_content)
        
        print(f"Created test file: {sol_file}")
        
        # Test with the SecurityAgent
        agent = SecurityAgent()
        results = agent.run(sol_file)
        
        # Print results
        print(json.dumps(results, indent=2))
        
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Test GitHub repository scanning')
    parser.add_argument('--token', '-t', help='GitHub API token')
    parser.add_argument('--repo', '-r', default="https://github.com/haruto0kitune/vulnerable-solidity-examples",
                        help='GitHub repository URL to scan')
    parser.add_argument('--local', '-l', action='store_true', help='Use local testing mode instead of GitHub')
    args = parser.parse_args()
    
    # Set environment variables
    os.environ["LOG_LEVEL"] = "DEBUG"
    
    # If local testing is requested, skip GitHub and test with local files
    if args.local:
        test_with_local_files()
        return
    
    # Set GitHub token from args or environment
    github_token = args.token or os.environ.get("GITHUB_TOKEN")
    if github_token:
        os.environ["GITHUB_TOKEN"] = github_token
        print(f"Using GitHub token: {github_token[:4]}...{github_token[-4:] if len(github_token) > 8 else '****'}")
    else:
        print("WARNING: No GitHub token provided. API rate limits may apply.")
        print("You may want to run with --local to test with local files instead.")
    
    # Create security agent
    agent = SecurityAgent()
    
    repo_url = args.repo
    print(f"Scanning GitHub repository: {repo_url}")
    
    # Call scan_github_repo method
    results = agent.scan_github_repo(
        repo_url=repo_url,
        output_format="json",
        token=github_token
    )
    
    # Print results
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 