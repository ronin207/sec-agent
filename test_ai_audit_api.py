#!/usr/bin/env python3
"""
Test script for AI audit API endpoints
"""

import requests
import json
import time

# API base URL - adjust if running on different host/port
API_BASE = "http://127.0.0.1:8080"

def test_ai_audit_single():
    """Test the single contract AI audit endpoint"""
    print("Testing AI Audit Single Contract Endpoint")
    print("=" * 50)
    
    # Sample vulnerable contract code
    contract_code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerable to reentrancy - external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State updated after external call
        balances[msg.sender] -= amount;
    }
    
    function transfer(address payable recipient, uint256 amount) public {
        // Unchecked return value from low-level call
        recipient.send(amount);
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
"""
    
    # Prepare request data
    data = {
        "code": contract_code,
        "contract_name": "VulnerableToken.sol"
    }
    
    try:
        # Make API request
        response = requests.post(f"{API_BASE}/api/ai-audit", json=data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ AI Audit Status: {result['status']}")
            print(f"📝 Contract: {result['contract_name']}")
            print(f"🔍 Total Findings: {result['ai_audit_findings']['total_findings']}")
            print(f"🤖 Analyzer: {result['ai_audit_findings']['analyzer']}")
            
            # Display severity breakdown
            severity_breakdown = result['ai_audit_findings']['severity_breakdown']
            print("\n📊 Severity Breakdown:")
            for severity, count in severity_breakdown.items():
                if count > 0:
                    print(f"   {severity}: {count}")
            
            # Show first few findings
            findings = result['ai_audit_findings']['findings']
            if findings:
                print(f"\n🔍 Sample Findings (showing first 3):")
                for i, finding in enumerate(findings[:3], 1):
                    print(f"\n{i}. {finding.get('type', 'Unknown Type')}")
                    print(f"   Severity: {finding.get('severity', 'Unknown')}")
                    print(f"   Location: {finding.get('location', 'Unknown')}")
                    print(f"   Description: {finding.get('description', 'No description')[:100]}...")
            
            return True
        else:
            print(f"❌ API Error: {response.status_code}")
            print(response.text)
            return False
            
    except Exception as e:
        print(f"❌ Request Error: {str(e)}")
        return False

def test_ai_audit_batch():
    """Test the batch AI audit endpoint"""
    print("\n\nTesting AI Audit Batch Endpoint")
    print("=" * 50)
    
    # Sample contracts for batch analysis
    contracts = [
        {
            "name": "SimpleVulnerable.sol",
            "code": """
pragma solidity ^0.6.0;
contract Simple {
    mapping(address => uint) balances;
    function withdraw() public {
        msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;
    }
}
"""
        },
        {
            "name": "UncheckedSend.sol", 
            "code": """
pragma solidity ^0.6.0;
contract UncheckedSend {
    function transfer(address payable recipient, uint amount) public {
        recipient.send(amount);  // Unchecked return value
    }
}
"""
        }
    ]
    
    # Prepare request data
    data = {
        "contracts": contracts
    }
    
    try:
        # Make API request
        response = requests.post(f"{API_BASE}/api/ai-audit/batch", json=data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Batch AI Audit Status: {result['status']}")
            
            # Batch summary
            summary = result['batch_summary']
            print(f"📊 Batch Summary:")
            print(f"   Total Contracts: {summary['total_contracts']}")
            print(f"   Successfully Analyzed: {summary['contracts_analyzed']}")
            print(f"   Failed: {summary['contracts_failed']}")
            print(f"   Total Findings: {summary['total_findings']}")
            
            # Overall severity breakdown
            severity_breakdown = result['ai_audit_findings']['severity_breakdown']
            print(f"\n📊 Overall Severity Breakdown:")
            for severity, count in severity_breakdown.items():
                if count > 0:
                    print(f"   {severity}: {count}")
            
            # Individual contract results
            print(f"\n📝 Individual Contract Results:")
            for contract_result in result['contract_results']:
                status_icon = "✅" if contract_result['status'] == 'completed' else "❌"
                print(f"   {status_icon} {contract_result['contract_name']}: {contract_result.get('findings_count', 0)} findings")
                if contract_result.get('has_critical'):
                    print(f"      ⚠️  Contains Critical Issues")
                if contract_result.get('has_high'):
                    print(f"      🔴 Contains High Severity Issues")
            
            return True
        else:
            print(f"❌ API Error: {response.status_code}")
            print(response.text)
            return False
            
    except Exception as e:
        print(f"❌ Request Error: {str(e)}")
        return False

def test_api_status():
    """Test the API status endpoint to check AI audit capabilities"""
    print("\n\nTesting API Status Endpoint")
    print("=" * 50)
    
    try:
        response = requests.get(f"{API_BASE}/")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ API Status: {result['status']}")
            print(f"🤖 AI Audit Model: {result['ai_audit_model']}")
            print(f"📡 LLM Model: {result['llm_model']}")
            
            print(f"\n🔧 Available Features:")
            for feature, enabled in result['features'].items():
                status_icon = "✅" if enabled else "❌"
                print(f"   {status_icon} {feature.replace('_', ' ').title()}")
            
            print(f"\n🌐 Available Endpoints:")
            for endpoint, description in result['endpoints'].items():
                print(f"   {endpoint}: {description}")
            
            return True
        else:
            print(f"❌ API Error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Request Error: {str(e)}")
        return False

def main():
    """Run all AI audit API tests"""
    print("🚀 AI Audit API Testing Suite")
    print("=" * 60)
    
    # Test API status first
    if not test_api_status():
        print("❌ API status check failed. Make sure the server is running.")
        return
    
    # Wait a moment
    time.sleep(1)
    
    # Test single contract analysis
    if not test_ai_audit_single():
        print("❌ Single contract AI audit test failed.")
        return
    
    # Wait a moment
    time.sleep(1)
    
    # Test batch analysis
    if not test_ai_audit_batch():
        print("❌ Batch AI audit test failed.")
        return
    
    print("\n🎉 All AI Audit API tests completed successfully!")
    print("\n💡 You can now use these endpoints:")
    print("   • POST /api/ai-audit - Single contract analysis")
    print("   • POST /api/ai-audit/batch - Multiple contract analysis")
    print("   • GET / - API status and capabilities")

if __name__ == "__main__":
    main() 