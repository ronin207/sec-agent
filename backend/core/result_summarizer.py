"""
Result Summarizer module for the Security Agent.
Generates human-readable summaries of security scan results using OpenAI API.
"""
from typing import Dict, List, Optional, Any, Union
import os
import json

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
        self.llm = ChatOpenAI(model=model_name, temperature=0.0, api_key=self.api_key)
    
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