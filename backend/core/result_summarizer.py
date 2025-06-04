"""
Result Summarizer module for the Security Agent.
Generates human-readable summaries of security scan results using OpenAI API.
"""
from typing import Dict, List, Optional, Any, Union
import os
import json
import re
import uuid

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field

# Import helpers
from backend.utils.helpers import get_logger

# Get logger
logger = get_logger('security_agent')

class SecuritySummary(BaseModel):
    """Schema for security summary output"""
    summary: str = Field(description="Overall summary of the security scan findings")
    technical_findings: List[str] = Field(description="List of ALL technical findings in order of severity")
    remediation_suggestions: List[str] = Field(description="List of remediation suggestions")
    risk_assessment: str = Field(description="Overall risk assessment (Critical, High, Medium, Low)")

class StandardizedToolOutput(BaseModel):
    """Schema for standardized tool output"""
    findings: List[Dict] = Field(description="List of standardized findings")
    findings_count: int = Field(description="Total number of findings")
    findings_by_severity: Dict = Field(description="Count of findings by severity")
    summary: str = Field(description="Brief summary of the scan results")

class SecurityFindingsOutput(BaseModel):
    """Schema for security findings standardized output"""
    summary: Dict = Field(description="Summary information including totals and counts by severity")
    findings: List[Dict] = Field(description="List of formatted security findings")

class ResultSummarizer:
    """
    Generates human-readable summaries of security scan results using OpenAI API.
    """
    
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gpt-4o-mini"):
        """
        Initialize the Result Summarizer module.
        
        Args:
            api_key: OpenAI API key (falls back to environment variable)
            model_name: Model to use for summaries (default: gpt-4o-mini)
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        logger.info(f"Initializing ResultSummarizer with API key: {'Set' if self.api_key else 'Not set'}")
        self.model_name = model_name
        
        # Use rate-limited version to avoid 429 errors
        from backend.core.langchain_batch_wrapper import create_rate_limited_llm
        self.llm = create_rate_limited_llm(
            model=model_name, 
            temperature=0.0, 
            api_key=self.api_key,
            rate_limit_ms=1500,  # Reduced from 3000ms to 1500ms for faster processing
            max_retries=5
        )
    
    def extract_version_vulnerability_details(self, description: str) -> Dict[str, str]:
        """
        Extract specific details about compiler version vulnerabilities using GPT-4o-mini.
        
        Args:
            description: The vulnerability description containing version information
            
        Returns:
            Dictionary with extracted version details:
            {
                "vulnerable_version": "^0.8.9",
                "recommended_version": "^0.8.20",
                "vulnerable_code": "pragma solidity ^0.8.9;",
                "fixed_code": "pragma solidity ^0.8.20;",
                "issues": ["VerbatimInvalidDeduplication", "FullInlinerNonExpressionSplitArgumentEvaluationOrder", ...]
            }
        """
        logger.info(f"Extracting version vulnerability details using {self.model_name}")
        
        # Create a prompt template for extracting version details
        prompt = ChatPromptTemplate.from_template(
            """
            ### TASK
            You are a smart contract security expert. Extract details from the following vulnerability description about Solidity compiler version issues.
            
            ### VULNERABILITY DESCRIPTION
            {description}
            
            ### INSTRUCTIONS
            Parse the description and extract the following information in JSON format:
            1. vulnerable_version: The specific vulnerable version mentioned (e.g., "^0.8.9")
            2. recommended_version: A safe version to use instead (typically the latest stable, e.g., "^0.8.20" or higher)
            3. vulnerable_code: A DETAILED code snippet showing the vulnerable pragma statement with explanatory comments
            4. fixed_code: A DETAILED code snippet showing the fixed pragma statement with explanatory comments
            5. issues: Array of specific issues mentioned in the description
            
            For the code snippets, include a simple contract definition and detailed comments explaining the vulnerability and fix.
            Make the examples educational and explain the security implications.
            
            ### CODE EXAMPLE FORMATS
            vulnerable_code should look like:
            ```
            pragma solidity ^0.8.9;
            
            // This contract uses a Solidity compiler version with known vulnerabilities
            contract VulnerableContract {
                // Version ^0.8.9 has issues like VerbatimInvalidDeduplication
                // This can lead to security vulnerabilities in your contract
                
                // Rest of contract code...
            }
            ```
            
            fixed_code should look like:
            ```
            pragma solidity ^0.8.20; // Use latest stable version
            
            // This contract uses a more secure Solidity compiler version
            contract SecureContract {
                // Using a version without known vulnerabilities
                
                // Rest of contract code...
            }
            
            /* 
             * Solidity compiler version recommendations:
             * 1. Always use the latest stable version (^0.8.20 or higher)
             * 2. For production, consider a fixed version (0.8.20 instead of ^0.8.20)
             * 3. Regularly check for compiler updates and security patches
             */
            ```
            
            ### OUTPUT FORMAT
            Return ONLY a valid JSON object with the fields described above, nothing else:
            ```json
            {
              "vulnerable_version": "...",
              "recommended_version": "...",
              "vulnerable_code": "...",
              "fixed_code": "...",
              "issues": [...]
            }
            ```
            """
        )
        
        try:
            # Format the prompt with the description
            formatted_prompt = prompt.format(description=description)
            
            logger.info("🚀 Calling OpenAI API to extract version vulnerability details - START")
            response = self.llm.invoke(formatted_prompt)
            logger.info("🚀 Calling OpenAI API to extract version vulnerability details - COMPLETE")
            
            # Extract the JSON response
            content = response.content
            if isinstance(content, str):
                # Find JSON in the content if it's wrapped in text
                start_idx = content.find('{')
                end_idx = content.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = content[start_idx:end_idx]
                    extracted_details = json.loads(json_str)
                    
                    logger.info(f"✅ Successfully extracted version vulnerability details")
                    return extracted_details
            
            # If we couldn't extract valid JSON, return a fallback
            logger.warning(f"⚠️ Could not extract valid JSON from OpenAI API response")
            return self._get_fallback_version_details(description)
            
        except Exception as e:
            logger.error(f"❌ Error extracting version vulnerability details: {str(e)}")
            return self._get_fallback_version_details(description)
    
    def _get_fallback_version_details(self, description: str) -> Dict[str, str]:
        """
        Generate fallback version vulnerability details if the API call fails.
        
        Args:
            description: The vulnerability description
            
        Returns:
            Basic version vulnerability details
        """
        # Try to extract version from the description using regex
        version_match = re.search(r'\^?(\d+\.\d+\.\d+)', description)
        vulnerable_version = version_match.group(0) if version_match else "^0.8.9"
        
        # Extract issues using regex - look for capitalized words
        issues = re.findall(r'([A-Z][a-zA-Z]+(?:[A-Z][a-zA-Z]+)+)', description)
        
        # Create more detailed code examples
        vulnerable_code = f"""pragma solidity {vulnerable_version};

// This contract uses a Solidity compiler version with known vulnerabilities
contract VulnerableContract {{
    // Version {vulnerable_version} has the following issues:
    // {', '.join(issues) if issues else 'Multiple security vulnerabilities'}
    
    // Rest of contract code...
}}"""

        fixed_code = f"""pragma solidity ^0.8.20; // Use latest stable version

// This contract uses a more secure Solidity compiler version
contract FixedContract {{
    // Using a fixed version without known vulnerabilities
    
    // Rest of contract code...
}}

/* 
 * Solidity compiler version recommendations:
 * 1. Always use the latest stable version (^0.8.20 or higher)
 * 2. For production, consider a fixed version (0.8.20 instead of ^0.8.20)
 * 3. Regularly check for compiler updates and security patches
 */"""
        
        return {
            "vulnerable_version": vulnerable_version,
            "recommended_version": "^0.8.20",  # Safe default
            "vulnerable_code": vulnerable_code,
            "fixed_code": fixed_code,
            "issues": issues or ["Multiple security vulnerabilities"]
        }
    
    def standardize_security_findings(self, raw_findings: Dict) -> Dict:
        """
        Process security tool outputs using 4o model and standardize to the required format.
        
        Args:
            raw_findings: The raw security findings JSON from security tools
            
        Returns:
            Dictionary with standardized format:
            {
                "summary": {
                    "total_findings": <int>,
                    "by_severity": {
                        "critical": <int>,
                        "high": <int>,
                        "medium": <int>,
                        "low": <int>,
                        "info": <int>,
                        "optimization": <int>
                    }
                },
                "findings": [
                    {
                        "id": "slither-timestamp-1",
                        "title": "Timestamp dependence in withdraw()",
                        "severity": "Low",
                        "file": "Lock.sol",
                        "lines": "23-33 (If it is a single line, just use the line number)",
                        "description": "Lock.withdraw() compares block.timestamp to unlockTime, allowing miner time manipulation.",
                        "vulnerable_code": "<exact snippet>",
                        "suggested_fix": "<exact suggested_fix from input>"
                    },
                    ...
                ]
            }
        """
        logger.info(f"Standardizing security findings using {self.model_name}")

        # Initialize formatted_findings list to store any additional findings we process
        formatted_findings = []

        # Process the raw findings before sending to the model
        # Check for compiler version vulnerabilities
        if isinstance(raw_findings, dict) and 'findings' in raw_findings:
            raw_findings_list = raw_findings.get('findings', [])
            
            # Create a new list for processed findings
            processed_findings = []
            
            for finding in raw_findings_list:
                description = finding.get('description', '')
                title = finding.get('name', '')
                
                # Special handling for compiler version vulnerabilities
                if 'version' in title.lower() and ('constraint' in title.lower() or 'compiler' in title.lower()):
                    version_details = self.extract_version_vulnerability_details(description)
                    if version_details:
                        # Extract line information if it exists in the original finding
                        line_info = ""
                        line_match = re.search(r'Lines?:?\s*(\d+(?:-\d+)?)', description)
                        if line_match:
                            line_info = line_match.group(1)
                        elif re.search(r'\(.*?(\d+).*?\)', description):  # Look for line numbers in parentheses
                            line_match = re.search(r'\(.*?(\d+).*?\)', description)
                            line_info = line_match.group(1)
                        
                        # Ensure single line numbers are properly formatted
                        if line_info and not '-' in line_info:
                            line_info = f"{line_info}-{line_info}"  # Format as range for consistency
                            
                        formatted_findings.append({
                            'id': f"solc-{uuid.uuid4().hex[:8]}",
                            'title': 'Solc Version with known issues',
                            'severity': 'info',
                            'file': version_details.get('file_location', 'Unknown'),
                            'lines': line_info,
                            'description': f"Version constraint {version_details['vulnerable_version']} contains known severe issues.",
                            'vulnerable_code': version_details['vulnerable_code'],
                            'suggested_fix': version_details['fixed_code']
                        })
                        continue
                
                # Check for compiler version vulnerabilities
                is_version_issue = (
                    isinstance(description, str) and (
                        'version constraint' in description.lower() or 
                        'compiler version' in description.lower() or
                        'solidity version' in description.lower() or
                        'pragma solidity' in description.lower()
                    )
                ) or (
                    isinstance(title, str) and (
                        'version' in title.lower() or
                        'compiler' in title.lower() or
                        'solc' in title.lower()
                    )
                )
                
                if is_version_issue and (not finding.get('vulnerable_code') or not finding.get('suggested_fix')):
                    # This is likely a compiler version vulnerability with missing code
                    version_details = self.extract_version_vulnerability_details(description)
                    
                    # Always set vulnerable_code and suggested_fix for version issues
                    finding['vulnerable_code'] = version_details.get('vulnerable_code', '')
                    finding['suggested_fix'] = version_details.get('fixed_code', '')
                    
                    # Enhance description if needed
                    if len(description) < 100:  # If description is short, enhance it
                        issues = version_details.get('issues', [])
                        issues_str = ', '.join(issues) if issues else 'security issues'
                        enhanced_desc = (
                            f"Version {version_details.get('vulnerable_version', 'specified')} contains known "
                            f"security issues: {issues_str}. Recommend upgrading to "
                            f"{version_details.get('recommended_version', '^0.8.20')}."
                        )
                        finding['description'] = enhanced_desc
                
                processed_findings.append(finding)
                
            # Update raw_findings with processed findings
            raw_findings['findings'] = processed_findings
            
            # Add any formatted findings we created
            if formatted_findings:
                raw_findings['findings'].extend(formatted_findings)

        # Create a prompt template for standardizing the findings
        prompt = ChatPromptTemplate.from_template(
            """
            ### CONTEXT
            You are an assistant that prepares security-scan results for a web front-end.  
            The scan report is a single JSON object generated by the Security-Agent tool-chain (Slither, Mythril, …).  
            Each element inside `findings` already contains:
            
            * `id` – unique identifier  
            * `name` – short title of the issue  
            * `severity` – Critical / High / Medium / Low / Info / Optimization  
            * `file` – absolute path (we only need the filename)  
            * `line_range` – e.g. `"23-33"` (If it is a single line, just use the line number)  
            * `description` – full description from the tool  
            * `vulnerable_code` – snippet of the affected code  
            * `suggested_fix` – remediation snippet / guidance  
            
            ### TASK
            1. **Parse** the JSON raw findings I'll provide.
            2. **Produce ONE new JSON object** with two top-level keys:
            
            ```json
            {{
              "summary": {{
                "total_findings": <int>,
                "by_severity": {{
                  "critical": <int>,
                  "high": <int>,
                  "medium": <int>,
                  "low": <int>,
                  "info": <int>,
                  "optimization": <int>
                }}
              }},
              "findings": [
                {{
                  "id": "slither-timestamp-1",
                  "title": "Timestamp dependence in withdraw()",
                  "severity": "Low",
                  "file": "Lock.sol",
                  "lines": "23-33 (If it is a single line, just use the line number)",
                  "description": "Lock.withdraw() compares block.timestamp to unlockTime, allowing miner time manipulation.",
                  "vulnerable_code": "<exact snippet>",
                  "suggested_fix": "<exact suggested_fix from input>"
                }},
                …
              ]
            }}
            ```
            
            For each finding:
            1. Extract the basename from the file path
            2. Create a clear, concise title based on the name and description
            3. Use the existing severity, preserving its exact case (e.g., "Low" not "low")
            4. Use line_range for the lines field
            5. Keep the vulnerable_code and suggested_fix exactly as they appear in the input
            
            Return only the JSON object, nothing else.
            
            Raw findings JSON:
            {raw_findings}
            """
        )

        try:
            # Convert raw_findings to a string if it's a dict
            if isinstance(raw_findings, dict):
                raw_findings_str = json.dumps(raw_findings)
            else:
                raw_findings_str = str(raw_findings)
            
            # Format the prompt with the raw findings
            formatted_prompt = prompt.format(raw_findings=raw_findings_str[:32000])  # Limit size to avoid token limits
            
            logger.info("🚀 Calling OpenAI API to standardize security findings - START")
            response = self.llm.invoke(formatted_prompt)
            logger.info("🚀 Calling OpenAI API to standardize security findings - COMPLETE")
            
            # Extract the JSON response
            content = response.content
            if isinstance(content, str):
                # Find JSON in the content if it's wrapped in text
                start_idx = content.find('{')
                end_idx = content.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = content[start_idx:end_idx]
                    standardized_findings = json.loads(json_str)
                    
                    # Add model info
                    standardized_findings["model_used"] = self.model_name
                    
                    logger.info(f"✅ Successfully standardized security findings using {self.model_name}")
                    return standardized_findings
            
            # If we couldn't extract valid JSON, return a fallback
            logger.warning(f"⚠️ Could not extract valid JSON from OpenAI API response")
            return self._get_fallback_findings(raw_findings)
            
        except Exception as e:
            logger.error(f"❌ Error standardizing security findings: {str(e)}")
            return self._get_fallback_findings(raw_findings)
    
    def _get_fallback_findings(self, raw_findings: Dict) -> Dict:
        """
        Generate fallback standardized findings if the API call fails.
        
        Args:
            raw_findings: Raw security findings from tools
            
        Returns:
            Basic standardized findings
        """
        try:
            # Try to extract findings from raw_findings
            findings = []
            total_findings = 0
            by_severity = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "optimization": 0
            }
            
            if isinstance(raw_findings, dict) and 'findings' in raw_findings:
                raw_findings_list = raw_findings.get('findings', [])
                total_findings = len(raw_findings_list)
                
                for i, finding in enumerate(raw_findings_list):
                    severity = finding.get('severity', 'Unknown')
                    severity_lower = severity.lower()
                    
                    # Update severity counts
                    if severity_lower in by_severity:
                        by_severity[severity_lower] += 1
                    
                    # Extract filename from path
                    file_path = finding.get('file', '')
                    file_name = os.path.basename(file_path) if file_path else 'Unknown'
                    
                    # Create standardized finding
                    findings.append({
                        "id": finding.get('id', f"finding-{i+1}"),
                        "title": finding.get('name', 'Unknown Issue'),
                        "severity": severity,
                        "file": file_name,
                        "lines": finding.get('line_range', ''),
                        "description": finding.get('description', ''),
                        "vulnerable_code": finding.get('vulnerable_code', ''),
                        "suggested_fix": finding.get('suggested_fix', '')
                    })
            
            return {
                "summary": {
                    "total_findings": total_findings,
                    "by_severity": by_severity
                },
                "findings": findings,
                "model_used": self.model_name
            }
            
        except Exception as e:
            logger.error(f"❌ Error creating fallback findings: {str(e)}")
            
            # Return minimal structure
            return {
                "summary": {
                    "total_findings": 0,
                    "by_severity": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                        "optimization": 0
                    }
                },
                "findings": [],
                "model_used": self.model_name
            }
    
    def standardize_tool_output(self, tool_name: str, raw_output: str) -> Dict:
        """
        Standardize a security tool's raw output using LLM.
        
        Args:
            tool_name: Name of the security tool that generated the output
            raw_output: The raw output from the security tool
            
        Returns:
            Dictionary containing standardized findings and summary
        """
        logger.info(f"Standardizing output from {tool_name} using {self.model_name}")
        
        # Create a prompt for standardizing the tool output
        prompt = ChatPromptTemplate.from_template(
            """You are an expert security analyst tasked with standardizing security tool outputs.
            
            Tool: {tool_name}
            
            Parse the following raw output from the security tool and convert it into a standardized format:
            
            ```
            {raw_output}
            ```
            
            Extract all security findings from the tool output and standardize them.
            
            Each finding should have the following structure:
            - name: Brief name/title of the vulnerability
            - severity: Severity level (Critical, High, Medium, Low, or Info)
            - description: Detailed description of the vulnerability
            - location: Location in code where the vulnerability was found (if available)
            - mitigation: Recommended fix or mitigation (if available)
            
            Format your response as a JSON object with the following fields:
            - findings: Array of standardized findings with the structure described above
            - findings_count: Total number of findings
            - findings_by_severity: Object counting findings by severity (e.g., {"High": 2, "Medium": 3})
            - summary: Brief summary of the scan results
            
            Return only the JSON object without additional text.
            """
        )
        
        # Format the inputs
        try:
            formatted_prompt = prompt.format(
                tool_name=tool_name,
                raw_output=raw_output[:8000]  # Limit raw output to avoid token limits
            )
            logger.debug(f"🔍 Sending prompt to OpenAI for standardizing {tool_name} output")
            
            logger.info(f"🚀 CALLING OPENAI API TO STANDARDIZE {tool_name} OUTPUT - START")
            response = self.llm.invoke(formatted_prompt)
            logger.info(f"🚀 CALLING OPENAI API TO STANDARDIZE {tool_name} OUTPUT - COMPLETE")
            
            logger.info("✅ Successfully received response from OpenAI API")
            
            # Extract the JSON content from the message
            content = response.content
            if isinstance(content, str):
                # Find JSON in the content if it's wrapped in text
                start_idx = content.find('{')
                end_idx = content.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = content[start_idx:end_idx]
                    result = json.loads(json_str)
                    logger.info(f"✅ Successfully parsed standardized output for {tool_name}")
                    return result
            
            # If we couldn't extract valid JSON, return a fallback response
            logger.warning(f"⚠️ Could not extract valid JSON from OpenAI API response for {tool_name}")
            return self._get_fallback_standardized_output(tool_name, raw_output)
            
        except Exception as e:
            logger.error(f"❌ Error standardizing {tool_name} output: {str(e)}", exc_info=True)
            return self._get_fallback_standardized_output(tool_name, raw_output)
    
    def _get_fallback_standardized_output(self, tool_name: str, raw_output: str) -> Dict:
        """
        Generate a fallback standardized output if the API call fails.
        
        Args:
            tool_name: Name of the security tool
            raw_output: Raw output from the security tool
            
        Returns:
            Dictionary containing basic standardized output
        """
        # Extract some basic information from the raw output
        lines = raw_output.split('\n')
        findings_count = 0
        
        # Try to count findings based on common patterns in security tool outputs
        for line in lines:
            if "error" in line.lower() or "warning" in line.lower() or "vulnerability" in line.lower():
                findings_count += 1
        
        return {
            "findings": [{
                "name": f"Unprocessed {tool_name} Finding",
                "severity": "Unknown",
                "description": f"The system encountered an error while processing the raw output from {tool_name}. Please review the raw output manually.",
                "location": "Unknown",
                "mitigation": "Review the raw tool output manually to identify and address any security issues."
            }],
            "findings_count": max(findings_count, 1),
            "findings_by_severity": {"Unknown": max(findings_count, 1)},
            "summary": f"Failed to standardize {tool_name} output. Found approximately {findings_count} potential issues."
        }

    def generate_summary(self, aggregated_results: Union[Dict, str, Any]) -> Dict:
        """
        Generate a human-readable summary of the security scan results.
        
        Args:
            aggregated_results: Dictionary containing aggregated scan results
            
        Returns:
            Dictionary containing the generated summary
        """
        # Ensure aggregated_results is a dictionary to prevent attribute errors
        if not isinstance(aggregated_results, dict):
            logger.warning(f"Expected dict for aggregated_results but got {type(aggregated_results)}. Converting to empty dict.")
            aggregated_results = {}
            return self._get_fallback_summary(aggregated_results)
            
        logger.info(f"Generating summary for scan {aggregated_results.get('scan_id')}")
        logger.debug(f"🔍 Aggregated results keys: {aggregated_results.keys()}")
        logger.debug(f"🔍 Aggregated results total_findings: {aggregated_results.get('total_findings')}")
        
        # Extract key information for the summary
        target = aggregated_results.get('target', 'Unknown')
        input_type = aggregated_results.get('input_type', 'Unknown')
        total_findings = aggregated_results.get('total_findings', 0)
        findings_by_severity = aggregated_results.get('findings_by_severity', {})
        findings = aggregated_results.get('findings', [])
        cves = aggregated_results.get('cves', [])
        
        # Create a prompt for the summary generation
        prompt = ChatPromptTemplate.from_template(
            """You are an expert security analyst tasked with summarizing security scan results.
            
            Analyze the following security scan results and provide:
            1. A concise overall summary
            2. ALL technical findings in order of severity (include every finding, not just key ones)
            3. Remediation suggestions for each finding
            4. Overall risk assessment (Critical, High, Medium, Low)
            
            Target: {target}
            Type: {input_type}
            Total Findings: {total_findings}
            
            Findings by Severity:
            {severity_summary}
            
            Detailed Findings:
            {detailed_findings}
            
            Related CVEs:
            {cves}
            
            Format your response as a JSON object with the following fields:
            - summary: Overall summary of the security scan findings
            - technical_findings: List of ALL technical findings in order of severity
            - remediation_suggestions: List of remediation suggestions
            - risk_assessment: Overall risk assessment (Critical, High, Medium, Low)
            
            IMPORTANT: Make sure to include ALL findings in the technical_findings list, not just a subset of key findings.
            
            Return only the JSON object without additional text.
            """
        )
        
        # Format the inputs
        severity_summary = "\n".join([f"{severity}: {count}" for severity, count in findings_by_severity.items()])
        
        detailed_findings = ""
        for i, finding in enumerate(findings, 1):
            detailed_findings += f"Finding {i}:\n"
            detailed_findings += f"  Name: {finding.get('name')}\n"
            detailed_findings += f"  Severity: {finding.get('severity')}\n"
            detailed_findings += f"  Description: {finding.get('description')}\n"
            if 'cve_id' in finding:
                detailed_findings += f"  CVE ID: {finding.get('cve_id')}\n"
            if 'location' in finding:
                detailed_findings += f"  Location: {finding.get('location')}\n"
            if 'evidence' in finding:
                detailed_findings += f"  Evidence: {finding.get('evidence')}\n"
            if 'mitigation' in finding:
                detailed_findings += f"  Mitigation: {finding.get('mitigation')}\n"
            detailed_findings += "\n"
        
        cve_list = "\n".join(cves) if cves else "None"
        
        logger.info("🔍 About to call OpenAI API for generating summary. API key is: " + 
                    ('Set' if self.api_key else 'Not set') + 
                    f", Model: {self.model_name}")
        logger.debug(f"🔍 Detailed findings count: {len(findings)}")
        
        # Generate the summary
        try:
            formatted_prompt = prompt.format(
                target=target,
                input_type=input_type,
                total_findings=total_findings,
                severity_summary=severity_summary,
                detailed_findings=detailed_findings,
                cves=cve_list
            )
            logger.debug(f"🔍 Sending prompt to OpenAI (first 200 chars): {formatted_prompt[:200]}...")
            
            logger.info("🚀 CALLING OPENAI API NOW - START")
            response = self.llm.invoke(formatted_prompt)
            logger.info("🚀 CALLING OPENAI API NOW - COMPLETE")
            
            logger.info("✅ Successfully received response from OpenAI API")
            logger.debug(f"✅ Raw response from OpenAI: {response.content[:200]}...")  # Log first 200 chars of response
        except Exception as e:
            logger.error(f"❌ Failed to call OpenAI API: {str(e)}", exc_info=True)
            return self._get_fallback_summary(aggregated_results)
        
        # Try to parse the response as JSON
        try:
            # Extract the JSON content from the message
            content = response.content
            if isinstance(content, str):
                # Find JSON in the content if it's wrapped in text
                start_idx = content.find('{')
                end_idx = content.rfind('}') + 1
                if start_idx >= 0 and end_idx > start_idx:
                    json_str = content[start_idx:end_idx]
                    result = json.loads(json_str)
                    logger.info("✅ Successfully parsed JSON response from OpenAI API")
                    return result
            
            # If we couldn't extract valid JSON, return a fallback response
            logger.warning("⚠️ Could not extract valid JSON from OpenAI API response")
            return self._get_fallback_summary(aggregated_results)
        except Exception as e:
            logger.error(f"❌ Error parsing OpenAI API response: {str(e)}")
            return self._get_fallback_summary(aggregated_results)
    
    def _get_fallback_summary(self, aggregated_results: Dict) -> Dict:
        """
        Generate a fallback summary if the API call fails.
        
        Args:
            aggregated_results: Dictionary containing aggregated scan results
            
        Returns:
            Dictionary containing a fallback summary
        """
        total_findings = aggregated_results.get('total_findings', 0)
        findings_by_severity = aggregated_results.get('findings_by_severity', {})
        
        # Determine risk level based on severity counts
        risk_level = "Low"
        if findings_by_severity.get("Critical", 0) > 0:
            risk_level = "Critical"
        elif findings_by_severity.get("High", 0) > 0:
            risk_level = "High"
        elif findings_by_severity.get("Medium", 0) > 0:
            risk_level = "Medium"
        
        # Create technical findings list
        technical_findings = []
        for finding in aggregated_results.get('findings', []):
            technical_findings.append(f"{finding.get('name')} ({finding.get('severity')})")
        
        # Create remediation suggestions
        remediation_suggestions = []
        unique_mitigations = set()
        for finding in aggregated_results.get('findings', []):
            if 'mitigation' in finding and finding['mitigation'] not in unique_mitigations:
                remediation_suggestions.append(finding['mitigation'])
                unique_mitigations.add(finding['mitigation'])
        
        # Create a basic summary
        target = aggregated_results.get('target', 'Unknown')
        summary = f"Security scan of {target} identified {total_findings} potential security issues. "
        
        if findings_by_severity:
            summary += "The scan found "
            severity_items = []
            for severity, count in findings_by_severity.items():
                if count > 0:
                    severity_items.append(f"{count} {severity.lower()} severity issues")
            summary += ", ".join(severity_items) + "."
        
        # If no remediation suggestions, add some generic ones
        if not remediation_suggestions:
            if "High" in findings_by_severity and findings_by_severity["High"] > 0:
                remediation_suggestions.append("Address high severity issues immediately by applying the latest security patches.")
            if total_findings > 0:
                remediation_suggestions.append("Review all findings and prioritize fixes based on severity and impact.")
                remediation_suggestions.append("Implement a regular security scanning process to identify new vulnerabilities.")
        
        return {
            "summary": summary,
            "technical_findings": technical_findings,
            "remediation_suggestions": remediation_suggestions,
            "risk_assessment": risk_level
        } 