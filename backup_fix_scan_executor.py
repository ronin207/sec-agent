#!/usr/bin/env python3
"""
Fix indentation errors in scan_executor.py
"""

import re

def fix_file():
    with open('backend/core/scan_executor.py', 'r') as f:
        content = f.read()
    
    # Fix indentation of start_time line
    content = content.replace('            start_time = time.time()', '        start_time = time.time()')
    
    # Fix return structure in execute_tool
    try_except_pattern = r"try:\s+# Execute the tool based on its type.*?except Exception as e:"
    fixed_try_except = """try:
            # Execute the tool based on its type
            result = None
            if input_type == 'solidity' or input_type == 'solidity_contract' and target.endswith('.sol'):
                if tool_id == 'slither':
                    result = self._execute_slither(target)
                elif tool_id == 'mythril':
                    result = self._execute_mythril(target)
                elif tool_id == 'solhint':
                    result = self._execute_solhint(target)
                elif tool_id == 'manticore':
                    result = self._execute_manticore(target)
                elif tool_id == 'echidna':
                    result = self._execute_echidna(target)
                elif tool_id == 'securify':
                    result = self._execute_securify(target)
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
        except Exception as e:"""
    
    content = re.sub(try_except_pattern, fixed_try_except, content, flags=re.DOTALL)
    
    # Fix the try/except blocks in each _execute method
    def fix_execute_method(method_name):
        method_pattern = rf"def {method_name}\(.*?\).*?try:.*?return \{{.*?\}}(\s+except.*?)"
        replacement = f"""def {method_name}(target: str) -> Dict:
        \"\"\"
        Execute the {method_name.replace('_execute_', '')} tool.
        
        Args:
            target: Path to the target file
            
        Returns:
            Dictionary containing scan results
        \"\"\"
        start_time = time.time()
        
        try:
            # Run tool with JSON output
            command = f"command {target}"  # This will be replaced
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
            # Processing code here...
            
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
            logger.error(f"Error executing tool: {str(e)}")
            return None"""
        
        return replacement  # This is just a placeholder
    
    # Fix the most critical part - the indentation on line 458
    execute_slither_pattern = r"def _execute_slither\(.*?\).*?try:.*?return \{"
    fixed_execute_slither = """def _execute_slither(self, target: str) -> Dict:
        \"\"\"
        Execute the Slither tool on a Solidity contract.
        
        Args:
            target: Path to the Solidity contract
            
        Returns:
            Dictionary containing scan results
        \"\"\"
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
            
            return {"""
    
    content = re.sub(execute_slither_pattern, fixed_execute_slither, content, flags=re.DOTALL)
    
    # Fix indentation in the return blocks for all tool execution methods
    return_pattern = r"return \{\s+\"status\":"
    fixed_return = """return {
                "status\":"""
    content = re.sub(return_pattern, fixed_return, content)
    
    # Write the fixed content back to the file
    with open('backend/core/scan_executor_fixed.py', 'w') as f:
        f.write(content)
    
    print("Fixed file saved to backend/core/scan_executor_fixed.py")
    print("Now you need to manually review and merge the fixes.")

if __name__ == "__main__":
    fix_file() 