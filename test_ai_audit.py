#!/usr/bin/env python3
"""
Test script to verify AI audit analysis integration
"""

import json
import os
from backend.core.security_agent import SecurityAgent

def test_ai_audit():
    """Test AI audit analysis on the test contract"""
    
    # Initialize the security agent
    agent = SecurityAgent()
    
    # Test with the vulnerable contract
    contract_file = "test_contract.sol"
    
    print("Testing AI Audit Analysis...")
    print("=" * 50)
    
    # Run the scan
    results = agent.run(contract_file, output_format="json")
    
    print(f"Scan Status: {results.get('status')}")
    print(f"Execution Time: {results.get('execution_time', 0):.2f} seconds")
    
    # Check for AI audit findings
    if 'aggregated_results' in results and 'ai_audit_findings' in results['aggregated_results']:
        ai_findings = results['aggregated_results']['ai_audit_findings']
        print(f"\nAI Audit Analysis Found: {ai_findings.get('total_findings', 0)} findings")
        print(f"Analyzer: {ai_findings.get('analyzer', 'Unknown')}")
        print(f"Knowledge Base: {ai_findings.get('knowledge_base', 'Unknown')}")
        
        if ai_findings.get('findings'):
            print("\nAI Audit Findings:")
            for i, finding in enumerate(ai_findings['findings'][:3], 1):  # Show first 3
                print(f"\n{i}. {finding.get('type', 'Unknown Type')}")
                print(f"   Severity: {finding.get('severity', 'Unknown')}")
                print(f"   Description: {finding.get('description', 'No description')[:100]}...")
                if finding.get('recommendation'):
                    print(f"   Recommendation: {finding.get('recommendation', '')[:100]}...")
        else:
            print("No AI audit findings returned")
    else:
        print("No AI audit results found in aggregated_results")
        
    # Check for traditional security tool findings
    if 'aggregated_results' in results and 'findings' in results['aggregated_results']:
        traditional_findings = results['aggregated_results']['findings']
        print(f"\nTraditional Security Tools Found: {len(traditional_findings)} findings")
    else:
        print("No traditional security tool findings found")
        
    # Save detailed results
    with open('ai_audit_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed results saved to ai_audit_test_results.json")
    
    return results

if __name__ == "__main__":
    test_ai_audit() 