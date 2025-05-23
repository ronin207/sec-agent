#!/usr/bin/env python3
"""
Scan Executor module for the Security Agent.
Handles execution of security scans using the selected tools.
"""
import time
import json
import uuid
import os
from typing import Dict, List, Optional, Any, Union
import subprocess
from datetime import datetime
import re

# Import helpers
from backend.utils.helpers import get_logger, extract_code_snippet, generate_suggested_fix
from backend.core.result_summarizer import ResultSummarizer

# Get logger
logger = get_logger('security_agent')

class ScanExecutor:
    """
    Executes security scans using the selected tools.
    """
    
    def __init__(self, result_summarizer=None):
        """
        Initialize the Scan Executor.
        
        Args:
            result_summarizer: ResultSummarizer instance (optional)
        """
        self.result_summarizer = result_summarizer or ResultSummarizer()
    
    def execute_scans(self, input_data: Dict, selected_tools: Union[Dict, List]) -> Dict:
        """
        Execute security scans using the selected tools.
        
        Args:
            input_data: Dictionary containing input type and value
            selected_tools: List or Dictionary containing selected tools
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Executing security scans for input type: {input_data.get('type')}")
        
        # Get the input type and value
        input_type = input_data.get('type')
        input_value = input_data.get('input')
        is_multiple = input_data.get('is_multiple', False)
        
        # Initialize results
        scan_id = str(uuid.uuid4())
        scan_results = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "target": input_value,
            "input_type": input_type,
            "is_multiple": is_multiple,
            "tool_results": [],
            "execution_time": 0
        }
        
        # If we're dealing with multiple files
        if is_multiple and input_data.get('files'):
            scan_results["files"] = input_data.get('files')
            logger.info(f"Processing multiple files: {len(input_data.get('files'))} files to scan")
        
        # Track execution time
        start_time = time.time()
        
        # Handle both list and dictionary formats from tool selector
        tools_to_execute = []
        if isinstance(selected_tools, list):
            tools_to_execute = selected_tools
        elif isinstance(selected_tools, dict) and 'selected_tools' in selected_tools:
            tools_to_execute = selected_tools.get('selected_tools', [])
        else:
            logger.warning(f"Unexpected format for selected_tools: {type(selected_tools)}")
            tools_to_execute = []
        
        # Execute the selected tools
        for tool in tools_to_execute:
            try:
                logger.info(f"Executing tool: {tool.get('name')}")
                
                # If we're dealing with multiple files, we need to scan each one
                if is_multiple and input_data.get('files'):
                    combined_tool_result = {
                        "tool_id": tool.get('id'),
                        "tool_name": tool.get('name'),
                        "status": "success",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": "",
                        "file_results": []
                    }
                    
                    for file_path in input_data.get('files'):
                        file_relative_path = os.path.basename(file_path)
                        logger.info(f"Scanning file: {file_relative_path}")
                        
                        # Execute the actual tool on each file
                        tool_result = self._execute_tool(tool, input_type, file_path)
                        
                        # Log detailed tool execution results for this file
                        logger.debug(f"Tool execution details for {tool.get('name')} on {file_relative_path}:")
                        logger.debug(f"Command executed: {tool.get('command').format(target=file_path)}")
                        logger.debug(f"Execution time: {tool_result.get('execution_time'):.2f} seconds")
                        logger.debug(f"Status: {tool_result.get('status')}")
                        logger.debug(f"Number of findings (pre-deduplication): {len(tool_result.get('findings', []))}")
                        
                        # Standardize the tool output using LLM
                        if tool_result.get('status') == 'success' and tool_result.get('raw_output'):
                            logger.info(f"Standardizing output from {tool.get('name')} for file {file_relative_path}")
                            standardized_output = self.result_summarizer.standardize_tool_output(
                                tool.get('name'),
                                tool_result.get('raw_output', '')
                            )
                            
                            if standardized_output and 'findings' in standardized_output:
                                # Add file information to each finding
                                for finding in standardized_output.get('findings', []):
                                    finding['file'] = file_path
                                
                                # Update the tool result with standardized findings
                                tool_result['findings'] = standardized_output.get('findings', [])
                                tool_result['standardized'] = True
                                
                                # Add summary from standardization if available
                                if 'summary' in standardized_output:
                                    tool_result['summary'] = standardized_output.get('summary')
                        
                        # Add file-specific results
                        file_result = {
                            "file": file_path,
                            "findings": tool_result.get("findings", []),
                            "execution_time": tool_result.get("execution_time", 0),
                            "status": tool_result.get("status", "unknown"),
                            "summary": tool_result.get("summary", "")
                        }
                        combined_tool_result["file_results"].append(file_result)
                        
                        # Aggregate findings from this file
                        for finding in tool_result.get('findings', []):
                            # Add file information to the finding
                            finding['file'] = file_path
                            combined_tool_result['findings'].append(finding)
                        
                        # Combine execution time
                        combined_tool_result['execution_time'] += tool_result.get('execution_time', 0)
                        
                        # Append raw output with file header
                        combined_tool_result['raw_output'] += f"\n\n=== Results for {file_path} ===\n"
                        combined_tool_result['raw_output'] += tool_result.get('raw_output', '')
                    
                    # Add the combined results to scan_results
                    scan_results['tool_results'].append(combined_tool_result)
                    
                else:
                    # Regular single target scan
                    tool_result = self._execute_tool(tool, input_type, input_value)
                    
                    # Log detailed tool execution results
                    logger.debug(f"Tool execution details for {tool.get('name')}:")
                    logger.debug(f"Command executed: {tool.get('command').format(target=input_value)}")
                    logger.debug(f"Execution time: {tool_result.get('execution_time'):.2f} seconds")
                    logger.debug(f"Status: {tool_result.get('status')}")
                    logger.debug(f"Number of findings (pre-deduplication): {len(tool_result.get('findings', []))}")
                    
                    # Standardize the tool output using LLM
                    if tool_result.get('status') == 'success' and tool_result.get('raw_output'):
                        logger.info(f"Standardizing output from {tool.get('name')}")
                        standardized_output = self.result_summarizer.standardize_tool_output(
                            tool.get('name'),
                            tool_result.get('raw_output', '')
                        )
                        
                        if standardized_output and 'findings' in standardized_output:
                            # Update the tool result with standardized findings
                            tool_result['findings'] = standardized_output.get('findings', [])
                            tool_result['standardized'] = True
                            
                            # Add summary from standardization if available
                            if 'summary' in standardized_output:
                                tool_result['summary'] = standardized_output.get('summary')
                    
                    # Log each finding in detail
                    for i, finding in enumerate(tool_result.get('findings', []), 1):
                        logger.debug(f"Finding {i} from {tool.get('name')} (standardized):")
                        logger.debug(f"  Name: {finding.get('name')}")
                        logger.debug(f"  Severity: {finding.get('severity')}")
                        logger.debug(f"  Description: {finding.get('description')}")
                        logger.debug(f"  Location: {finding.get('location', 'Not specified')}")
                    
                    scan_results['tool_results'].append({
                        "tool_id": tool.get('id'),
                        "tool_name": tool.get('name'),
                        "command_executed": tool.get('command').format(target=input_value),
                        "execution_time": tool_result.get("execution_time"),
                        "status": tool_result.get("status"),
                        "findings": tool_result.get("findings"),
                        "raw_output": tool_result.get("raw_output"),
                        "summary": tool_result.get("summary", ""),
                        "standardized": tool_result.get("standardized", False)
                    })
                
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
    
    def _execute_tool(self, tool: Dict, input_type: str, target: str) -> Dict:
        """
        Execute a security tool on the target.
        
        Args:
            tool: Dictionary containing tool information
            input_type: Type of input (website, solidity, etc.)
            target: Target URL or file path
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Executing {tool.get('name')} on {target}")
        start_time = time.time()
        
        # Get tool details
        tool_id = tool.get('id')
        tool_name = tool.get('name')
        
        # Check if the tool is appropriate for this input type
        supported_input_types = tool.get('supported_types', [])
        if supported_input_types and input_type not in supported_input_types:
            logger.warning(f"Tool {tool_name} not designed for input type {input_type}")
            # We'll still try to run it unless specifically disabled
        
        try:
            # Execute the appropriate tool based on the ID
            result = None
            
            # Solidity Contract Analysis Tools
            if tool_id == 'slither':
                if not target.endswith('.sol'):
                    logger.warning(f"Tool {tool_name} requires a Solidity contract file. Skipping.")
                    return {
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            return None
                "status": "skipped",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": f"Skipped: {tool_name} requires a Solidity contract file. Target was: {target}"
                    }
                
                # Check if tool exists
                if not self._tool_exists('slither'):
                    logger.warning(f"Tool slither not found in system path. Install using: pip install slither-analyzer")
                    return {
                "status": "unavailable",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": "Tool not installed: slither not found in system path."
                    }
                
                # Execute slither
                result = self._execute_slither(target)
                
            elif tool_id == 'mythril':
                if not target.endswith('.sol'):
                    logger.warning(f"Tool {tool_name} requires a Solidity contract file. Skipping.")
                    return {
                "status": "skipped",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": f"Skipped: {tool_name} requires a Solidity contract file. Target was: {target}"
                    }
                
                # Check if tool exists
                if not self._tool_exists('myth'):
                    logger.warning(f"Tool mythril not found in system path. Install using: pip install mythril")
                    return {
                "status": "unavailable",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": "Tool not installed: mythril not found in system path."
                    }
                
                # Execute mythril
                result = self._execute_mythril(target)
                
            elif tool_id == 'solhint':
                if not target.endswith('.sol'):
                    logger.warning(f"Tool {tool_name} requires a Solidity contract file. Skipping.")
                    return {
                "status": "skipped",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": f"Skipped: {tool_name} requires a Solidity contract file. Target was: {target}"
                    }
                
                # Check if tool exists
                if not self._tool_exists('solhint'):
                    logger.warning(f"Tool solhint not found in system path. Install using: npm install -g solhint")
                    return {
                "status": "unavailable",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": "Tool not installed: solhint not found in system path."
                    }
                
                # Execute solhint
                result = self._execute_solhint(target)
                
            # Manticore
            elif tool_id == 'manticore':
                if not target.endswith('.sol'):
                    logger.warning(f"Tool {tool_name} requires a Solidity contract file. Skipping.")
                    return {
                "status": "skipped",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": f"Skipped: {tool_name} requires a Solidity contract file. Target was: {target}"
                    }
                
                # Check if tool exists
                if not self._tool_exists('manticore'):
                    logger.warning(f"Tool manticore not found in system path. Install using: pip install manticore")
                    return {
                "status": "unavailable",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": "Tool not installed: manticore not found in system path."
                    }
                
                # Execute command directly for now
                command = f"manticore {target} --solc-optimize --quick-mode"
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(timeout=120)
                
                result = {
                    "status": "success" if process.returncode == 0 else "error",
                    "execution_time": time.time() - start_time,
                    "findings": [], # Would need proper parser for Manticore output
                    "raw_output": stdout if stdout else stderr
                }
                
            # Echidna
            elif tool_id == 'echidna':
                if not target.endswith('.sol'):
                    logger.warning(f"Tool {tool_name} requires a Solidity contract file. Skipping.")
                    return {
                "status": "skipped",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": f"Skipped: {tool_name} requires a Solidity contract file. Target was: {target}"
                    }
                
                # Check if tool exists
                if not self._tool_exists('echidna'):
                    logger.warning(f"Tool echidna not found in system path. Please install echidna from https://github.com/crytic/echidna")
                    return {
                "status": "unavailable",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": "Tool not installed: echidna not found in system path."
                    }
                
                # Create a basic config file for echidna
                config_file = "echidna.config.yaml"
                with open(config_file, "w") as f:
                    f.write("""
                    # Basic Echidna configuration for security testing
                    corpusDir: "echidna-corpus"
                    testMode: assertion
                    testLimit: 50000
                    contractAddr: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
                    deployer: "0x30000"
                    sender: ["0x10000", "0x20000", "0x30000"]
                    """)
                
                # Execute echidna with the config
                command = f"echidna {target} --config {config_file}"
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(timeout=120)
                
                result = {
                    "status": "success" if process.returncode == 0 else "error",
                    "execution_time": time.time() - start_time,
                    "findings": [], # Would need proper parser for Echidna output
                    "raw_output": stdout if stdout else stderr
                }
                
            # Securify
            elif tool_id == 'securify':
                if not target.endswith('.sol'):
                    logger.warning(f"Tool {tool_name} requires a Solidity contract file. Skipping.")
                    return {
                "status": "skipped",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": f"Skipped: {tool_name} requires a Solidity contract file. Target was: {target}"
                    }
                
                # Check if Python module exists (Securify is a Python module)
                try:
                    import_result = subprocess.run(
                        ["python3", "-c", "import securify"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    if import_result.returncode != 0:
                        logger.warning("Securify Python module not found. Please install Securify from https://github.com/eth-sri/securify2")
                        return {
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            return None
                "status": "unavailable",
                            "execution_time": 0,
                            "findings": [],
                            "raw_output": "Tool not installed: securify Python module not found."
                        }
                except Exception:
                    logger.warning("Failed to check for Securify module.")
                    return {
                "status": "unavailable",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": "Tool not installed or not properly configured: securify"
                    }
                
                # Generate output file path
                output_file = f"{target}.securify.json"
                
                # Execute securify
                command = f"python -m securify {target} --output {output_file}"
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(timeout=120)
                
                # Try to read output file if it exists
                findings = []
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            securify_json = json.load(f)
                            # Parse the results (this would need to be implemented based on Securify's output format)
                    except Exception as e:
                        logger.error(f"Error reading Securify output file: {e}")
                
                result = {
                    "status": "success" if process.returncode == 0 else "error",
                    "execution_time": time.time() - start_time,
                    "findings": findings,
                    "raw_output": stdout if stdout else stderr
                }
                
            # Solana Tools
            elif tool_id in ['xray', 'vrust', 'substrate-scout']:
                # Implement these tools when needed based on your existing code
                pass
            else:
                # Default case - try to execute the command generically
                command = tool.get('command', '').format(target=target)
                
                if not command:
                    return {
                "status": "error",
                        "execution_time": 0,
                        "findings": [],
                        "raw_output": f"Invalid tool configuration: missing command for {tool_name}"
                    }
                
                # Execute the command
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(timeout=60)
                
                result = {
                    "status": "success" if process.returncode == 0 else "error",
                    "execution_time": time.time() - start_time,
                    "findings": [],
                    "raw_output": stdout if stdout else stderr
                }
            
            # Enhance findings with code snippets
            if result and result.get('findings'):
                self._enhance_findings_with_code(result.get('findings', []), target)
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing tool {tool_id}: {str(e)}")
            return {
                "status": "error",
                "execution_time": time.time() - start_time,
                "error_message": str(e),
                "findings": []
            }
    
    def _tool_exists(self, tool_name: str) -> bool:
        """
        Check if a command-line tool exists in the system path.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if the tool exists, False otherwise
        """
        try:
            result = subprocess.run(
                f"which {tool_name}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def _execute_slither(self, target: str) -> Dict:
        """
        Execute the Slither tool on a Solidity contract.
        
        Args:
            target: Path to the Solidity contract
            
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        
        try:
            # Run Slither with JSON output
            command = f"slither {target} --json -"
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=60)
            
            execution_time = time.time() - start_time
            
            # Parse JSON output
            findings = []
            if stdout:
                try:
                    slither_json = json.loads(stdout)
                    detectors = slither_json.get('results', {}).get('detectors', [])
                    
                    for idx, detector in enumerate(detectors):
                        # Extract relevant information
                        severity = detector.get('impact', 'Unknown')
                        description = detector.get('description', 'Unknown issue')
                        check = detector.get('check', 'unknown')
                        
                        # Process the elements to get file and line information
                        elements = detector.get('elements', [])
                        location = ""
                        
                        if elements:
                            element = elements[0]
                            source_mapping = element.get('source_mapping', {})
                            filename = source_mapping.get('filename', target)
                            
                            # Get just the base filename
                            if filename:
                                filename = os.path.basename(filename)
                                
                            start_line = None
                            end_line = None
                            
                            # Try to get line numbers
                            if source_mapping.get('lines'):
                                lines = source_mapping.get('lines', [])
                                if lines:
                                    start_line = min(lines)
                                    end_line = max(lines)
                            
                            if start_line is not None and end_line is not None:
                                location = f"{filename}:{start_line}-{end_line}"
                            elif start_line is not None:
                                location = f"{filename}:{start_line}"
                            elif filename:
                                location = filename
                        
                        # Create the finding object
                        finding = {
                            "id": f"slither-{check}-{idx+1}",
                            "name": check.replace('-', ' ').title(),
                            "severity": severity,
                            "description": description,
                            "location": location,
                            "evidence": description
                        }
                        
                        findings.append(finding)
                    
                except json.JSONDecodeError:
                    logger.error("Failed to parse Slither JSON output")
            
            return {
                "status": "success" if process.returncode == 0 else "error",
                "execution_time": execution_time,
                "findings": findings,
                "raw_output": stdout if stdout else stderr
            }
            
        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            return {
                "status": "timeout",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": "Execution timed out after 60 seconds"
            }
        except Exception as e:
            logger.error(f"Error executing Slither: {str(e)}")
            return {
                "status": "error",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": f"Error: {str(e)}"
            }

    def _execute_mythril(self, target: str) -> Dict:
        """
        Execute the Mythril tool on a Solidity contract.
        
        Args:
            target: Path to the Solidity contract
            
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        
        try:
            # Run Mythril with JSON output
            command = f"myth analyze {target} --json"
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=120)  # Mythril can take longer
            
            execution_time = time.time() - start_time
            
            # Parse JSON output
            findings = []
            if stdout:
                try:
                    mythril_json = json.loads(stdout)
                    issues = mythril_json.get('issues', [])
                    
                    for idx, issue in enumerate(issues):
                        # Extract relevant information
                        severity = issue.get('severity', 'Unknown')
                        title = issue.get('title', 'Unknown issue')
                        description = issue.get('description', '')
                        swc_id = issue.get('swc-id', '')
                        
                        # Get location information
                        filename = os.path.basename(target)
                        line_numbers = []
                        
                        if 'sourceMap' in issue:
                            source_map = issue.get('sourceMap', '')
                            line_numbers = [source_map]
                        elif 'lineno' in issue:
                            line_numbers = [str(issue.get('lineno'))]
                        
                        location = f"{filename}:{','.join(line_numbers)}" if line_numbers else filename
                        
                        # Create the finding object
                        finding = {
                            "id": f"mythril-{swc_id}-{idx+1}" if swc_id else f"mythril-issue-{idx+1}",
                            "name": title,
                            "severity": severity.capitalize(),
                            "description": description,
                            "location": location,
                            "evidence": issue.get('code', '')
                        }
                        
                        findings.append(finding)
                    
                except json.JSONDecodeError:
                    logger.error("Failed to parse Mythril JSON output")
            
            return {
                "status": "success" if process.returncode == 0 else "error",
                "execution_time": execution_time,
                "findings": findings,
                "raw_output": stdout if stdout else stderr
            }
            
        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            return {
                "status": "timeout",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": "Execution timed out after 120 seconds"
            }
        except Exception as e:
            logger.error(f"Error executing Mythril: {str(e)}")
            return {
                "status": "error",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": f"Error: {str(e)}"
            }

    def _execute_solhint(self, target: str) -> Dict:
        """
        Execute the Solhint tool on a Solidity contract.
        
        Args:
            target: Path to the Solidity contract
            
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        
        try:
            # Run Solhint with JSON output
            command = f"solhint {target} --formatter json"
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=30)
            
            execution_time = time.time() - start_time
            
            # Parse JSON output
            findings = []
            if stdout:
                try:
                    solhint_json = json.loads(stdout)
                    
                    for idx, issue in enumerate(solhint_json):
                        # Extract relevant information
                        severity_map = {"1": "Low", "2": "Medium", "3": "High"}
                        severity_num = issue.get('severity', 1)
                        severity = severity_map.get(str(severity_num), "Low")
                        
                        rule = issue.get('ruleId', 'unknown-rule')
                        message = issue.get('message', 'Unknown issue')
                        line = issue.get('line', 0)
                        column = issue.get('column', 0)
                        
                        # Create a readable name from the rule ID
                        name = ' '.join(word.capitalize() for word in rule.split('-'))
                        
                        # Get location information
                        filename = os.path.basename(target)
                        location = f"{filename}:{line}"
                        
                        # Create the finding object
                        finding = {
                            "id": f"solhint-{rule}-{idx+1}",
                            "name": name,
                            "severity": severity,
                            "description": message,
                            "location": location,
                            "evidence": f"At line {line}, column {column}"
                        }
                        
                        findings.append(finding)
                    
                except json.JSONDecodeError:
                    logger.error("Failed to parse Solhint JSON output")
            
            return {
                "status": "success" if process.returncode == 0 else "error",
                "execution_time": execution_time,
                "findings": findings,
                "raw_output": stdout if stdout else stderr
            }
            
        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            return {
                "status": "timeout",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": "Execution timed out after 30 seconds"
            }
        except Exception as e:
            logger.error(f"Error executing Solhint: {str(e)}")
            return {
                "status": "error",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": f"Error: {str(e)}"
            }

    def _execute_xray(self, target: str) -> Dict:
        """
        Execute the X-Ray tool on a Solana contract.
        
        Args:
            target: Path to the Solana contract
            
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        
        try:
            # Run X-Ray with JSON output
            command = f"xray scan {target} --output-format=json"
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=60)
            
            execution_time = time.time() - start_time
            
            # Parse JSON output
            findings = []
            if stdout:
                try:
                    xray_json = json.loads(stdout)
                    issues = xray_json.get('issues', [])
                    
                    for idx, issue in enumerate(issues):
                        # Extract relevant information
                        severity = issue.get('severity', 'Unknown')
                        title = issue.get('title', 'Unknown issue')
                        description = issue.get('description', '')
                        location = issue.get('location', '')
                        
                        # Create the finding object
                        finding = {
                            "id": f"xray-{idx+1}",
                            "name": title,
                            "severity": severity,
                            "description": description,
                            "location": location,
                            "evidence": issue.get('evidence', '')
                        }
                        
                        findings.append(finding)
                    
                except json.JSONDecodeError:
                    logger.error("Failed to parse X-Ray JSON output")
            
            return {
                "status": "success" if process.returncode == 0 else "error",
                "execution_time": execution_time,
                "findings": findings,
                "raw_output": stdout if stdout else stderr
            }
            
        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            return {
                "status": "timeout",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": "Execution timed out after 60 seconds"
            }
        except Exception as e:
            logger.error(f"Error executing X-Ray: {str(e)}")
            return {
                "status": "error",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": f"Error: {str(e)}"
            }

    def _execute_vrust(self, target: str) -> Dict:
        """
        Execute the VRust tool on a Solana contract.
        
        Args:
            target: Path to the Solana contract
            
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        
        try:
            # Run VRust with JSON output
            command = f"vrust analyze {target} --report-json"
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=60)
            
            execution_time = time.time() - start_time
            
            # Parse JSON output
            findings = []
            if stdout:
                try:
                    vrust_json = json.loads(stdout)
                    issues = vrust_json.get('issues', [])
                    
                    for idx, issue in enumerate(issues):
                        # Extract relevant information
                        severity = issue.get('severity', 'Unknown')
                        title = issue.get('title', 'Unknown issue')
                        description = issue.get('description', '')
                        location = issue.get('location', '')
                        
                        # Create the finding object
                        finding = {
                            "id": f"vrust-{idx+1}",
                            "name": title,
                            "severity": severity,
                            "description": description,
                            "location": location,
                            "evidence": issue.get('evidence', '')
                        }
                        
                        findings.append(finding)
                    
                except json.JSONDecodeError:
                    logger.error("Failed to parse VRust JSON output")
            
            return {
                "status": "success" if process.returncode == 0 else "error",
                "execution_time": execution_time,
                "findings": findings,
                "raw_output": stdout if stdout else stderr
            }
            
        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            return {
                "status": "timeout",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": "Execution timed out after 60 seconds"
            }
        except Exception as e:
            logger.error(f"Error executing VRust: {str(e)}")
            return {
                "status": "error",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": f"Error: {str(e)}"
            }

    def _execute_scout(self, target: str) -> Dict:
        """
        Execute the Scout tool on a Polkadot/ink! contract.
        
        Args:
            target: Path to the Polkadot/ink! contract
            
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        
        try:
            # Run Scout with JSON output
            command = f"scout scan {target} --output-json"
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=60)
            
            execution_time = time.time() - start_time
            
            # Parse JSON output
            findings = []
            if stdout:
                try:
                    scout_json = json.loads(stdout)
                    issues = scout_json.get('issues', [])
                    
                    for idx, issue in enumerate(issues):
                        # Extract relevant information
                        severity = issue.get('severity', 'Unknown')
                        title = issue.get('title', 'Unknown issue')
                        description = issue.get('description', '')
                        location = issue.get('location', '')
                        
                        # Create the finding object
                        finding = {
                            "id": f"scout-{idx+1}",
                            "name": title,
                            "severity": severity,
                            "description": description,
                            "location": location,
                            "evidence": issue.get('evidence', '')
                        }
                        
                        findings.append(finding)
                    
                except json.JSONDecodeError:
                    logger.error("Failed to parse Scout JSON output")
            
            return {
                "status": "success" if process.returncode == 0 else "error",
                "execution_time": execution_time,
                "findings": findings,
                "raw_output": stdout if stdout else stderr
            }
            
        except subprocess.TimeoutExpired:
            # Kill the process if it times out
            process.kill()
            return {
                "status": "timeout",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": "Execution timed out after 60 seconds"
            }
        except Exception as e:
            logger.error(f"Error executing Scout: {str(e)}")
            return {
                "status": "error",
                "execution_time": time.time() - start_time,
                "findings": [],
                "raw_output": f"Error: {str(e)}"
            }

    def _enhance_findings_with_code(self, findings: List[Dict], target_file: str) -> None:
        """
        Enhance findings with actual code snippets.
        
        Args:
            findings: List of findings to enhance
            target_file: Path to the target file
        """
        if not findings:
            logger.warning("No findings to enhance")
            return
            
        logger.info(f"Enhancing {len(findings)} findings with code snippets from {target_file}")
        
        # Create a copy of the file in a more predictable location if it's in a temp directory
        target_copy = None
        if '/tmp/' in target_file or '/var/folders/' in target_file and os.path.exists(target_file):
            try:
                filename = os.path.basename(target_file)
                target_copy = os.path.join(os.getcwd(), "cached_files", filename)
                os.makedirs(os.path.dirname(target_copy), exist_ok=True)
                with open(target_file, 'r', encoding='utf-8') as src_file:
                    content = src_file.read()
                with open(target_copy, 'w', encoding='utf-8') as dest_file:
                    dest_file.write(content)
                logger.info(f"Created persistent copy of temp file at {target_copy}")
            except Exception as e:
                logger.error(f"Failed to create persistent copy of file: {str(e)}")
        
        # Use the original path or the copy if available
        file_to_use = target_copy if target_copy and os.path.exists(target_copy) else target_file
        
        for finding in findings:
            # Skip if no location is provided
            if 'location' not in finding:
                logger.warning(f"Finding missing location: {finding.get('name', 'Unknown')}")
                continue
                
            # Extract code snippet based on the location
            location = finding.get('location', '')
            logger.info(f"Extracting code for location: {location}")
            
            # Special handling for pragma-related findings (common in Solidity)
            if ('solc ' in finding.get('name', '').lower() or 
                'pragma' in finding.get('name', '').lower() or
                'version' in finding.get('name', '').lower()):
                
                # Try to extract the pragma line directly from the file
                try:
                    with open(file_to_use, 'r', encoding='utf-8') as f:
                        content = f.read()
                        pragma_match = re.search(r'(pragma solidity [^;]+;)', content)
                        if pragma_match:
                            code_data = {
                                'vulnerable_code': pragma_match.group(1),
                                'line_range': location.split(':')[-1] if ':' in location else "1",
                                'suggested_fix': generate_suggested_fix(pragma_match.group(1), file_to_use)
                            }
                            logger.info(f"Directly extracted pragma statement: {pragma_match.group(1)}")
                        else:
                            code_data = extract_code_snippet(file_to_use, location)
                except Exception as e:
                    logger.error(f"Error extracting pragma: {str(e)}")
                    code_data = extract_code_snippet(file_to_use, location)
            else:
                code_data = extract_code_snippet(file_to_use, location)
            
            # Add code data to the finding
            finding['vulnerable_code'] = code_data.get('vulnerable_code')
            finding['line_range'] = code_data.get('line_range')
            finding['suggested_fix'] = code_data.get('suggested_fix')
            
            # Add file path if not already present
            if 'file' not in finding:
                finding['file'] = os.path.basename(target_file)  # Use just the basename for cleaner output
                
            # Log the result
            if finding['vulnerable_code'] == "// Unable to extract vulnerable code":
                logger.warning(f"Failed to extract code for finding: {finding.get('name', 'Unknown')} at {location}")
            else:
                logger.info(f"Successfully extracted code for finding: {finding.get('name', 'Unknown')} at {location}") 