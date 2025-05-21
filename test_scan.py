#!/usr/bin/env python3
"""
Test script for the Security AI Agent.
"""
import os
import sys
import json
from backend.core.security_agent import SecurityAgent

def main():
    """Run a test security scan on the test contract."""
    print("Security AI Agent Test Scanner")
    print("------------------------------")
    
    # Get the path to the test contract
    script_dir = os.path.dirname(os.path.abspath(__file__))
    test_contract = os.path.join(script_dir, "test_contract.sol")
    
    if not os.path.exists(test_contract):
        print(f"Error: Test contract not found at {test_contract}")
        return 1
    
    print(f"Found test contract: {test_contract}")
    
    # Initialize the security agent
    agent = SecurityAgent()
    
    # Run the scan
    print("Running security scan...")
    result = agent.run(test_contract)
    
    if result.get('status') == 'error':
        print(f"Error: {result.get('error')}")
        return 1
    
    # Print summary
    print("\nScan Results Summary")
    print("-------------------")
    print(f"Input Type: {result.get('input_type')}")
    print(f"Status: {result.get('status')}")
    print(f"Execution Time: {result.get('execution_time'):.2f} seconds")
    
    # Print findings by severity
    findings_by_severity = result.get('aggregated_results', {}).get('findings_by_severity', {})
    
    print("\nFindings by Severity")
    print("-------------------")
    for severity, count in findings_by_severity.items():
        print(f"{severity}: {count}")
    
    # Print detailed findings
    findings = result.get('aggregated_results', {}).get('findings', [])
    
    print("\nDetailed Findings")
    print("----------------")
    for i, finding in enumerate(findings, 1):
        print(f"\n{i}. {finding.get('name')} ({finding.get('severity')})")
        print(f"   Description: {finding.get('description')}")
        print(f"   Location: {finding.get('location')}")
        
        # Check if we have the vulnerable code snippet
        if 'vulnerable_code' in finding and finding['vulnerable_code'] != "// Unable to extract vulnerable code":
            print(f"   Vulnerable Code: \n{finding.get('vulnerable_code')}")
        
        # Check if we have a suggested fix
        if 'suggested_fix' in finding and finding['suggested_fix'] != "// Suggested fix not available":
            print(f"   Suggested Fix: \n{finding.get('suggested_fix')}")
    
    # Save detailed results to a file
    with open('scan_results.json', 'w') as f:
        json.dump(result, f, indent=2)
    
    print("\nFull results saved to scan_results.json")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 