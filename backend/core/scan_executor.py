"""
Scan Executor module for the Security Agent.
Handles execution of security scans using the selected tools.
"""
import time
import random
import json
import uuid
from typing import Dict, List, Optional, Any
import subprocess
from datetime import datetime

# Import helpers
from backend.utils.helpers import get_logger

# Get logger
logger = get_logger('security_agent')

class ScanExecutor:
    """
    Executes security scans using the selected tools.
    For demo purposes, this provides mocked implementations of the tools.
    In a real implementation, this would execute real security tools.
    """
    
    def __init__(self):
        pass
    
    def execute_scans(self, input_data: Dict, selected_tools: Dict) -> Dict:
        """
        Execute security scans using the selected tools.
        
        Args:
            input_data: Dictionary containing input type and value
            selected_tools: Dictionary containing selected tools and their configuration
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Executing security scans for input type: {input_data.get('type')}")
        
        # Get the input type and value
        input_type = input_data.get('type')
        input_value = input_data.get('input')
        
        # Initialize results
        scan_results = {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "target": input_value,
            "input_type": input_type,
            "tool_results": [],
            "execution_time": 0
        }
        
        # Track execution time
        start_time = time.time()
        
        # Execute the selected tools
        for tool in selected_tools.get('selected_tools', []):
            try:
                logger.info(f"Executing tool: {tool.get('name')}")
                
                # In a real implementation, this would execute the actual tool
                # For demo purposes, we'll simulate tool execution
                tool_result = self._simulate_tool_execution(tool, input_type, input_value)
                
                # Log detailed tool execution results
                logger.debug(f"Tool execution details for {tool.get('name')}:")
                logger.debug(f"Command executed: {tool.get('command').format(target=input_value)}")
                logger.debug(f"Execution time: {tool_result.get('execution_time'):.2f} seconds")
                logger.debug(f"Status: {tool_result.get('status')}")
                logger.debug(f"Number of findings: {len(tool_result.get('findings', []))}")
                logger.debug(f"Raw output sample: {tool_result.get('raw_output')[:200]}...")
                
                # Log each finding in detail
                for i, finding in enumerate(tool_result.get('findings', []), 1):
                    logger.debug(f"Finding {i} from {tool.get('name')}:")
                    logger.debug(f"  ID: {finding.get('id')}")
                    logger.debug(f"  Name: {finding.get('name')}")
                    logger.debug(f"  Severity: {finding.get('severity')}")
                    logger.debug(f"  Description: {finding.get('description')}")
                    logger.debug(f"  Location: {finding.get('location')}")
                
                scan_results['tool_results'].append({
                    "tool_id": tool.get('id'),
                    "tool_name": tool.get('name'),
                    "command_executed": tool.get('command').format(target=input_value),
                    "execution_time": tool_result.get("execution_time"),
                    "status": tool_result.get("status"),
                    "findings": tool_result.get("findings"),
                    "raw_output": tool_result.get("raw_output")
                })
                
                # Add a delay to simulate processing time
                time.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error executing tool {tool.get('name')}: {str(e)}")
                scan_results['tool_results'].append({
                    "tool_id": tool.get('id'),
                    "tool_name": tool.get('name'),
                    "status": "error",
                    "error_message": str(e)
                })
        
        # Calculate total execution time
        scan_results['execution_time'] = time.time() - start_time
        
        return scan_results
    
    def execute_real_tool(self, command: str, timeout: int = 300) -> Dict:
        """
        Execute a real security tool using subprocess.
        Note: This is included for future implementation but is not used in the demo.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            
        Returns:
            Dictionary containing execution results
        """
        try:
            start_time = time.time()
            # Execute the command and capture output
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            # Wait for the process to complete with timeout
            stdout, stderr = process.communicate(timeout=timeout)
            
            execution_time = time.time() - start_time
            
            # Process the output
            return {
                "status": "success" if process.returncode == 0 else "error",
                "return_code": process.returncode,
                "execution_time": execution_time,
                "stdout": stdout,
                "stderr": stderr
            }
        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            stdout, stderr = process.communicate()
            return {
                "status": "timeout",
                "execution_time": timeout,
                "stdout": stdout,
                "stderr": stderr,
                "error_message": f"Command execution timed out after {timeout} seconds"
            }
        except Exception as e:
            return {
                "status": "error",
                "execution_time": 0,
                "stdout": "",
                "stderr": "",
                "error_message": str(e)
            }
    
    def _simulate_tool_execution(self, tool: Dict, input_type: str, target: str) -> Dict:
        """
        Simulate execution of a security tool.
        
        Args:
            tool: Tool configuration
            input_type: Type of input ('website' or 'solidity_contract')
            target: Target to scan
            
        Returns:
            Dictionary containing simulated scan results
        """
        tool_id = tool.get('id')
        
        # Simulate execution time (random between 2-5 seconds)
        execution_time = random.uniform(2.0, 5.0)
        
        # Get mocked results based on tool type
        if input_type == 'website':
            if tool_id == 'owasp_zap':
                return self._mock_zap_results(target, execution_time)
            elif tool_id == 'nikto':
                return self._mock_nikto_results(target, execution_time)
            elif tool_id == 'wappalyzer':
                return self._mock_wappalyzer_results(target, execution_time)
            elif tool_id == 'nuclei':
                return self._mock_nuclei_results(target, execution_time)
        elif input_type == 'solidity_contract':
            if tool_id == 'slither':
                return self._mock_slither_results(target, execution_time)
            elif tool_id == 'solhint':
                return self._mock_solhint_results(target, execution_time)
            elif tool_id == 'mythril':
                return self._mock_mythril_results(target, execution_time)
            elif tool_id == 'manticore':
                return self._mock_manticore_results(target, execution_time)
        
        # Default mock response for unknown tools
        return {
            "status": "unknown_tool",
            "execution_time": execution_time,
            "findings": [],
            "raw_output": f"Unknown tool: {tool_id}"
        }
    
    def _mock_zap_results(self, target: str, execution_time: float) -> Dict:
        """Mock OWASP ZAP scanning results"""
        findings = [
            {
                "id": "zap-xss-1",
                "name": "Cross-Site Scripting (XSS)",
                "severity": "High",
                "description": "A reflected XSS vulnerability was detected in the search parameter",
                "location": f"{target}/search?q=test",
                "evidence": "<script>alert(1)</script>"
            },
            {
                "id": "zap-csrf-1",
                "name": "Cross-Site Request Forgery (CSRF)",
                "severity": "Medium",
                "description": "Form submission without anti-CSRF token",
                "location": f"{target}/login",
                "evidence": "No CSRF token found in form"
            },
            {
                "id": "zap-headers-1",
                "name": "Missing Security Headers",
                "severity": "Low",
                "description": "Several security headers are missing from the HTTP response",
                "location": target,
                "evidence": "Missing: X-XSS-Protection, Content-Security-Policy"
            }
        ]
        
        raw_output = """
OWASP ZAP Report for {target}
=========================
Scan completed at: {timestamp}
Scan duration: {execution_time:.2f} seconds
Target: {target}

Issues Found:
* High: 1
* Medium: 1
* Low: 1

Details:
1. Cross-Site Scripting (XSS)
   URL: {target}/search?q=test
   Severity: High
   Description: Reflected XSS detected in the search parameter

2. CSRF Vulnerability
   URL: {target}/login
   Severity: Medium
   Description: No CSRF token found in form submission

3. Missing Security Headers
   URL: {target}
   Severity: Low
   Description: Security headers missing: X-XSS-Protection, Content-Security-Policy
""".format(
            target=target,
            timestamp=datetime.now().isoformat(),
            execution_time=execution_time
        )
        
        return {
            "status": "success",
            "execution_time": execution_time,
            "findings": findings,
            "raw_output": raw_output
        }
    
    def _mock_nikto_results(self, target: str, execution_time: float) -> Dict:
        """Mock Nikto scanning results"""
        findings = [
            {
                "id": "nikto-server-info-1",
                "name": "Server Information Disclosure",
                "severity": "Medium",
                "description": "Server header reveals version information",
                "location": target,
                "evidence": "Server: Apache/2.4.29 (Ubuntu)"
            },
            {
                "id": "nikto-directory-listing-1",
                "name": "Directory Listing Enabled",
                "severity": "Medium",
                "description": "Directory listing is enabled on the server",
                "location": f"{target}/images/",
                "evidence": "Directory listing enabled at /images/"
            }
        ]
        
        raw_output = """
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          {ip}
+ Target Hostname:    {hostname}
+ Target Port:        80
---------------------------------------------------------------------------
+ Server: Apache/2.4.29 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Directory listing enabled at /images/
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3233: /icons/README: Apache default file found.
""".format(
            ip="192.168.1.1",
            hostname=target.replace("https://", "").replace("http://", "")
        )
        
        return {
            "status": "success",
            "execution_time": execution_time,
            "findings": findings,
            "raw_output": raw_output
        }
    
    def _mock_wappalyzer_results(self, target: str, execution_time: float) -> Dict:
        """Mock Wappalyzer scanning results"""
        findings = [
            {
                "id": "wappalyzer-tech-1",
                "name": "Web Server Identified",
                "severity": "Info",
                "description": "Web server technology identified",
                "location": target,
                "evidence": "Apache 2.4.29"
            },
            {
                "id": "wappalyzer-tech-2",
                "name": "Programming Language Identified",
                "severity": "Info",
                "description": "Server-side programming language identified",
                "location": target,
                "evidence": "PHP 7.4"
            },
            {
                "id": "wappalyzer-tech-3",
                "name": "JavaScript Framework Identified",
                "severity": "Info",
                "description": "JavaScript framework identified",
                "location": target,
                "evidence": "React 17.0.2"
            }
        ]
        
        raw_output = json.dumps({
            "urls": {
                target: {
                    "status": 200
                }
            },
            "technologies": [
                {
                    "name": "Apache",
                    "version": "2.4.29",
                    "categories": [
                        {
                            "id": 22,
                            "name": "Web servers"
                        }
                    ]
                },
                {
                    "name": "PHP",
                    "version": "7.4",
                    "categories": [
                        {
                            "id": 27,
                            "name": "Programming languages"
                        }
                    ]
                },
                {
                    "name": "React",
                    "version": "17.0.2",
                    "categories": [
                        {
                            "id": 12,
                            "name": "JavaScript frameworks"
                        }
                    ]
                }
            ]
        }, indent=2)
        
        return {
            "status": "success",
            "execution_time": execution_time,
            "findings": findings,
            "raw_output": raw_output
        }
    
    def _mock_nuclei_results(self, target: str, execution_time: float) -> Dict:
        """Mock Nuclei scanning results"""
        findings = [
            {
                "id": "nuclei-cve-2021-44228",
                "name": "Apache Log4j RCE (CVE-2021-44228)",
                "severity": "Critical",
                "description": "Remote code execution vulnerability in Log4j",
                "location": f"{target}/api/login",
                "evidence": "Vulnerable Log4j version detected"
            },
            {
                "id": "nuclei-cve-2023-23506",
                "name": "Prototype Pollution in Next.js (CVE-2023-23506)",
                "severity": "High",
                "description": "Prototype pollution in Next.js leading to authentication bypass",
                "location": target,
                "evidence": "Next.js version < 13.5.6"
            }
        ]
        
        raw_output = """
[2023-07-10 15:23:45] [info] Nuclei Engine v2.9.1
[2023-07-10 15:23:46] [info] Targets loaded for scan: 1
[2023-07-10 15:23:48] [critical] [CVE-2021-44228] Apache Log4j RCE via JNDI injection detected at {target}/api/login
[2023-07-10 15:23:50] [high] [CVE-2023-23506] Next.js Prototype Pollution vulnerability detected 
[2023-07-10 15:23:52] [info] Scan completed in {execution_time:.2f} seconds
""".format(
            target=target,
            execution_time=execution_time
        )
        
        return {
            "status": "success",
            "execution_time": execution_time,
            "findings": findings,
            "raw_output": raw_output
        }
    
    def _mock_slither_results(self, target: str, execution_time: float) -> Dict:
        """Mock Slither scanning results"""
        findings = [
            {
                "id": "slither-reentrancy-1",
                "name": "Reentrancy",
                "severity": "High",
                "description": "Reentrancy vulnerability in withdraw function",
                "location": "TokenContract.sol:56-78",
                "evidence": "External calls inside a loop"
            },
            {
                "id": "slither-unchecked-return-1",
                "name": "Unchecked Return Value",
                "severity": "Medium",
                "description": "Return value of external call not checked",
                "location": "TokenContract.sol:112",
                "evidence": "External call return value not checked"
            },
            {
                "id": "slither-pragma-1",
                "name": "Outdated Compiler Version",
                "severity": "Low",
                "description": "Outdated Solidity compiler version",
                "location": "TokenContract.sol:1",
                "evidence": "pragma solidity ^0.6.0;"
            }
        ]
        
        raw_output = json.dumps({
            "success": True,
            "error": None,
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Reentrancy in TokenContract.withdraw() (TokenContract.sol#67-78)",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "source_mapping": {
                                    "start": 1337,
                                    "length": 430,
                                    "filename": "TokenContract.sol"
                                }
                            }
                        ]
                    },
                    {
                        "check": "unchecked-lowlevel",
                        "impact": "Medium",
                        "confidence": "Medium",
                        "description": "Unchecked low-level call in TokenContract.transfer() (TokenContract.sol#112)",
                        "elements": [
                            {
                                "type": "function",
                                "name": "transfer",
                                "source_mapping": {
                                    "start": 2337,
                                    "length": 230,
                                    "filename": "TokenContract.sol"
                                }
                            }
                        ]
                    },
                    {
                        "check": "solc-version",
                        "impact": "Low",
                        "confidence": "High",
                        "description": "Outdated Solidity version: consider updating to 0.8.0+",
                        "elements": [
                            {
                                "type": "pragma",
                                "name": "",
                                "source_mapping": {
                                    "start": 0,
                                    "length": 23,
                                    "filename": "TokenContract.sol"
                                }
                            }
                        ]
                    }
                ]
            }
        }, indent=2)
        
        return {
            "status": "success",
            "execution_time": execution_time,
            "findings": findings,
            "raw_output": raw_output
        }
    
    def _mock_solhint_results(self, target: str, execution_time: float) -> Dict:
        """Mock Solhint scanning results"""
        findings = [
            {
                "id": "solhint-naming-1",
                "name": "Variable Naming Convention",
                "severity": "Low",
                "description": "Variable name must be in camelCase",
                "location": "TokenContract.sol:34",
                "evidence": "uint256 Token_balance"
            },
            {
                "id": "solhint-visibility-1",
                "name": "Function Visibility",
                "severity": "Medium",
                "description": "Function visibility not specified",
                "location": "TokenContract.sol:45",
                "evidence": "function transfer(address to, uint256 amount)"
            }
        ]
        
        raw_output = """
TokenContract.sol
  34:16  error    Variable name must be in camelCase                      naming-convention
  45:3   warning  Function visibility is not specified. Default is public  func-visibility

✖ 2 problems (1 error, 1 warning)
"""
        
        return {
            "status": "success",
            "execution_time": execution_time,
            "findings": findings,
            "raw_output": raw_output
        }
    
    def _mock_mythril_results(self, target: str, execution_time: float) -> Dict:
        """Mock Mythril scanning results"""
        findings = [
            {
                "id": "mythril-dos-1",
                "name": "DoS With Failed Call",
                "severity": "Medium",
                "description": "External call in loop could lead to denial of service",
                "location": "TokenContract.sol:67-72",
                "evidence": "Loop containing external calls"
            },
            {
                "id": "mythril-integer-1",
                "name": "Integer Overflow",
                "severity": "High",
                "description": "Integer overflow in addition operation",
                "location": "TokenContract.sol:89",
                "evidence": "a + b where a and b can be controlled by an attacker"
            }
        ]
        
        raw_output = """
==== Denial Of Service ====
SWC ID: 113
Severity: Medium
Contract: TokenContract
Function name: processPayments(address[])
PC address: 1337
A denial-of-service vulnerability exists in function processPayments(). 
External calls inside a loop might lead to a denial-of-service attack.
--------------------
In file: TokenContract.sol:67

for (uint i=0; i < recipients.length; i++) {
    recipients[i].transfer(amount);
}

==== Integer Overflow ====
SWC ID: 101
Severity: High
Contract: TokenContract
Function name: add(uint256,uint256)
PC address: 1997
The arithmetic operation can result in integer overflow.
--------------------
In file: TokenContract.sol:89

function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a, "SafeMath: addition overflow");
    return c;
}
"""
        
        return {
            "status": "success",
            "execution_time": execution_time,
            "findings": findings,
            "raw_output": raw_output
        }
    
    def _mock_manticore_results(self, target: str, execution_time: float) -> Dict:
        """Mock Manticore scanning results"""
        findings = [
            {
                "id": "manticore-divzero-1",
                "name": "Division by Zero",
                "severity": "Medium",
                "description": "Potential division by zero",
                "location": "TokenContract.sol:124",
                "evidence": "Division where denominator could be zero"
            }
        ]
        
        raw_output = """
Manticore analysis results:
Number of explored states: 47
Number of analyzed instructions: 1337

=== Findings ===

- Division by zero at TokenContract.sol:124
  Severity: Medium
  Description: A division operation where the denominator could be zero was found
  PC: 0x1234
  
- Path constraints: (storage[6] == 0)
  Transaction sequence:
  1. Contract.divide(0)
"""
        
        return {
            "status": "success",
            "execution_time": execution_time,
            "findings": findings,
            "raw_output": raw_output
        } 