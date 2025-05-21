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

# Import helpers
from backend.utils.helpers import get_logger, extract_code_snippet

# Get logger
logger = get_logger('security_agent')

class ScanExecutor:
    """
    Executes security scans using the selected tools.
    """
    
    def __init__(self):
        pass
    
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
                        
                        # Add file-specific results
                        file_result = {
                            "file": file_path,
                            "findings": tool_result.get("findings", []),
                            "execution_time": tool_result.get("execution_time", 0),
                            "status": tool_result.get("status", "unknown")
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
                    
                    # Log each finding in detail
                    for i, finding in enumerate(tool_result.get('findings', []), 1):
                        logger.debug(f"Finding {i} from {tool.get('name')} (raw, pre-deduplication):")
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
        Execute a security tool and return its results.
        
        Args:
            tool: Tool configuration
            input_type: Type of input ('website', 'solidity_contract', 'solana_contract', or 'polkadot_contract')
            target: Target to scan
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Executing {tool.get('name')} on {target}")
        
        tool_id = tool.get('id', 'unknown')
        start_time = time.time()
        
        # Check if the file exists to handle file permissions
        if os.path.isfile(target) and not os.access(target, os.R_OK):
            return {
                "status": "error",
                "execution_time": 0,
                "error_message": f"Cannot read file {target}: Permission denied",
                "findings": []
            }
        
        try:
            # Execute the tool based on its type
            result = None
            if input_type == 'solidity_contract' and os.path.exists(target):
                if tool_id == 'slither':
                    result = self._execute_slither(target)
                elif tool_id == 'mythril':
                    result = self._execute_mythril(target)
                elif tool_id == 'solhint':
                    result = self._execute_solhint(target)
                else:
                    logger.warning(f"Tool {tool_id} not supported for Solidity contracts")
                    return {
                        "status": "error",
                        "execution_time": 0,
                        "error_message": f"Tool {tool_id} not supported for Solidity contracts",
                        "findings": []
                    }
            elif input_type == 'solana_contract':
                if tool_id == 'xray':
                    result = self._execute_xray(target)
                elif tool_id == 'vrust':
                    result = self._execute_vrust(target)
                else:
                    logger.warning(f"Tool {tool_id} not supported for Solana contracts")
                    return {
                        "status": "error",
                        "execution_time": 0,
                        "error_message": f"Tool {tool_id} not supported for Solana contracts",
                        "findings": []
                    }
            elif input_type == 'polkadot_contract':
                if tool_id == 'scout':
                    result = self._execute_scout(target)
                else:
                    logger.warning(f"Tool {tool_id} not supported for Polkadot contracts")
                    return {
                        "status": "error",
                        "execution_time": 0,
                        "error_message": f"Tool {tool_id} not supported for Polkadot contracts",
                        "findings": []
                    }
            else:
                logger.warning(f"Tool {tool_id} not supported for input type {input_type}")
                return {
                    "status": "error",
                    "execution_time": 0,
                    "error_message": f"Tool {tool_id} not supported for input type {input_type}",
                    "findings": []
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
            return None

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
            return None

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
            return None

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
            return None

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
            return None

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
            return None

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
        
        for finding in findings:
            # Skip if no location is provided
            if 'location' not in finding:
                logger.warning(f"Finding missing location: {finding.get('name', 'Unknown')}")
                continue
                
            # Extract code snippet based on the location
            location = finding.get('location', '')
            logger.info(f"Extracting code for location: {location}")
            
            code_data = extract_code_snippet(target_file, location)
            
            # Add code data to the finding
            finding['vulnerable_code'] = code_data.get('vulnerable_code')
            finding['line_range'] = code_data.get('line_range')
            finding['suggested_fix'] = code_data.get('suggested_fix')
            
            # Add file path if not already present
            if 'file' not in finding:
                finding['file'] = target_file
                
            # Log the result
            if finding['vulnerable_code'] == "// Unable to extract vulnerable code":
                logger.warning(f"Failed to extract code for finding: {finding.get('name', 'Unknown')} at {location}")
            else:
                logger.info(f"Successfully extracted code for finding: {finding.get('name', 'Unknown')} at {location}") 