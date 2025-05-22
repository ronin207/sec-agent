"""
CVE Knowledge Base Query module for the Security Agent.
Interacts with OpenAI API to retrieve and summarize CVE information.
"""
import os
from typing import Dict, List, Optional
import json

from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field

# Import from existing modules
from backend.utils.cve_loader import CVEDataLoader
from backend.utils.helpers import get_logger

# Get logger
logger = get_logger('security_agent')

class CVERisk(BaseModel):
    """Schema for CVE risk assessment"""
    risk_level: str = Field(description="Risk level (Critical, High, Medium, Low)")
    description: str = Field(description="Description of the risk")
    affected_components: List[str] = Field(description="Components affected by this vulnerability")
    mitigation: str = Field(description="Steps to mitigate this risk")

class CVEKnowledgeQuery:
    """
    Query CVE knowledge base using OpenAI API to provide security insights and risk assessment.
    """
    
    def __init__(self, api_key: Optional[str] = None, model_name: str = "gpt-4o-mini"):
        """
        Initialize the CVE Knowledge Query module.
        
        Args:
            api_key: OpenAI API key (falls back to environment variable)
            model_name: Model to use for queries (default: gpt-4o-mini)
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        logger.info(f"Initializing CVEKnowledgeQuery with API key: {'Set' if self.api_key else 'Not set'}")
        self.model_name = model_name
        self.llm = ChatOpenAI(model=model_name, temperature=0.0, api_key=self.api_key)
        self.cve_loader = CVEDataLoader()
    
    def query_by_input_type(self, input_type: str, input_value: str) -> Dict:
        """
        Query CVE knowledge base based on the input type.
        
        Args:
            input_type: Type of input ('website' or 'solidity_contract')
            input_value: Value of the input (URL or file path)
        
        Returns:
            Dictionary containing CVE knowledge and risk assessment
        """
        logger.info(f"🔍 CVEKnowledgeQuery.query_by_input_type called with input_type: {input_type}, input_value: {input_value}")
        
        # For demo, we'll use mocked responses
        # In a real implementation, this would query a knowledge base or API
        
        # Ensure input_value is a string to prevent attribute errors
        if not isinstance(input_value, str):
            logger.warning(f"Expected string input_value but got {type(input_value)}")
            input_value = str(input_value) if input_value is not None else ""
        
        if input_type == 'website':
            return self._query_website_vulnerabilities(input_value)
        elif input_type == 'solidity_contract':
            return self._query_solidity_vulnerabilities(input_value)
        else:
            logger.warning(f"Unsupported input type: {input_type}")
            return {
                "error": f"Unsupported input type: {input_type}",
                "cves": [],
                "risks": []
            }
    
    def _query_website_vulnerabilities(self, url: str) -> Dict:
        """
        Query for website vulnerabilities.
        
        Args:
            url: Website URL to check
            
        Returns:
            Dictionary with CVE information and risks
        """
        # First, try to fetch actual CVE data
        logger.info(f"Searching for website vulnerability information for {url}")
        cve_data = self.cve_loader.search_cves(keyword="web vulnerability", max_results=5)
        
        # Query LLM to analyze the URL and potential vulnerabilities
        prompt = ChatPromptTemplate.from_template(
            """You are a security expert specializing in web application security.
            
            Analyze this website URL: {url}
            
            Based on the URL and common web vulnerabilities, identify potential security risks.
            Consider common vulnerabilities like:
            - Cross-Site Scripting (XSS)
            - SQL Injection
            - Cross-Site Request Forgery (CSRF)
            - Server misconfigurations
            - Outdated software
            
            Here are some recent CVEs for reference:
            {cve_data}
            
            Format your response as a JSON object with these fields:
            - cves: List of relevant CVE IDs that could affect this website
            - risks: List of risk objects, each containing:
              - risk_level: Critical, High, Medium, or Low
              - description: Description of the risk
              - affected_components: Parts of the site likely affected
              - mitigation: Steps to mitigate this risk
            
            Return only the JSON object without additional text.
            """
        )
        
        # Convert CVE data to string format for prompt
        cve_string = self._format_cve_data_for_prompt(cve_data)
        
        # Get response from LLM
        logger.info("🔍 About to call OpenAI API for CVE knowledge query. API key is: " + 
                   ('Set' if self.api_key else 'Not set') + 
                   f", Model: {self.model_name}")
        try:
            formatted_prompt = prompt.format(url=url, cve_data=cve_string)
            logger.debug(f"Sending prompt to OpenAI: {formatted_prompt[:200]}...")  # Log first 200 chars
            
            response = self.llm.invoke(formatted_prompt)
            logger.info("✅ Successfully received response from OpenAI API for CVE query")
            logger.debug(f"Raw response from OpenAI: {response.content[:200]}...")  # Log first 200 chars
        except Exception as e:
            logger.error(f"❌ Failed to call OpenAI API for CVE query: {str(e)}", exc_info=True)
            return self._get_fallback_website_response(url)
        
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
                    return result
            
            # If we couldn't extract valid JSON, return a fallback response
            return self._get_fallback_website_response(url)
        except:
            return self._get_fallback_website_response(url)
    
    def _query_solidity_vulnerabilities(self, solidity_input: str) -> Dict:
        """
        Query for Solidity smart contract vulnerabilities.
        
        Args:
            solidity_input: Path to Solidity file or GitHub repo URL
            
        Returns:
            Dictionary with CVE information and risks
        """
        # First, try to load smart contract related CVEs
        logger.info("Searching for smart contract vulnerability information")
        documents = self.cve_loader.load_smart_contract_cves()
        
        # For demo, we'll use a mocked response
        # In a real implementation, this would analyze the smart contract code
        
        # Query LLM to analyze potential smart contract vulnerabilities
        prompt = ChatPromptTemplate.from_template(
            """You are a security expert specializing in blockchain and smart contract security.
            
            Analyze this smart contract: {input}
            
            Based on common smart contract vulnerabilities, identify potential security risks.
            Consider common vulnerabilities like:
            - Reentrancy attacks
            - Integer overflow/underflow
            - Front-running
            - Gas limitations
            - Access control issues
            
            Format your response as a JSON object with these fields:
            - cves: List of relevant CVE IDs that could affect smart contracts (if any)
            - risks: List of risk objects, each containing:
              - risk_level: Critical, High, Medium, or Low
              - description: Description of the risk
              - affected_components: Parts of the contract likely affected
              - mitigation: Steps to mitigate this risk
            
            Return only the JSON object without additional text.
            """
        )
        
        # Get response from LLM
        response = self.llm.invoke(prompt.format(input=solidity_input))
        
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
                    return result
            
            # If we couldn't extract valid JSON, return a fallback response
            return self._get_fallback_solidity_response()
        except:
            return self._get_fallback_solidity_response()
    
    def _format_cve_data_for_prompt(self, cve_data: Dict) -> str:
        """Format CVE data for inclusion in a prompt"""
        result = []
        
        if "vulnerabilities" in cve_data:
            for vuln in cve_data["vulnerabilities"][:5]:  # Limit to 5 vulnerabilities
                if "cve" in vuln:
                    cve = vuln["cve"]
                    cve_id = cve.get("id", "Unknown CVE")
                    description = "No description available"
                    
                    # Try to get description from different possible locations
                    if "descriptions" in cve and cve["descriptions"]:
                        for desc in cve["descriptions"]:
                            if desc.get("lang") == "en":
                                description = desc.get("value", "")
                                break
                    
                    result.append(f"ID: {cve_id}\nDescription: {description}\n")
        
        return "\n".join(result) if result else "No CVE data available."
    
    def _get_fallback_website_response(self, url: str) -> Dict:
        """Get a fallback response for website vulnerabilities"""
        return {
            "cves": ["CVE-2021-44228", "CVE-2023-23506", "CVE-2022-22965"],
            "risks": [
                {
                    "risk_level": "High",
                    "description": "Potential for Cross-Site Scripting (XSS) vulnerabilities in web forms",
                    "affected_components": ["Forms", "User input fields"],
                    "mitigation": "Implement proper input validation and output encoding"
                },
                {
                    "risk_level": "Medium",
                    "description": "SQL Injection vulnerability if the site uses a database backend",
                    "affected_components": ["Database interaction", "Search functionality"],
                    "mitigation": "Use parameterized queries and prepared statements"
                },
                {
                    "risk_level": "Low",
                    "description": "Missing security headers could expose the site to various attacks",
                    "affected_components": ["Server configuration"],
                    "mitigation": "Implement proper security headers (CSP, X-XSS-Protection, etc.)"
                }
            ]
        }
    
    def _get_fallback_solidity_response(self) -> Dict:
        """Get a fallback response for solidity vulnerabilities"""
        return {
            "cves": [],  # Most smart contract vulnerabilities don't have CVE IDs yet
            "risks": [
                {
                    "risk_level": "Critical",
                    "description": "Potential reentrancy vulnerability allowing attackers to drain funds",
                    "affected_components": ["External calls", "State changes after calls"],
                    "mitigation": "Implement checks-effects-interactions pattern and use ReentrancyGuard"
                },
                {
                    "risk_level": "High",
                    "description": "Integer overflow/underflow in arithmetic operations",
                    "affected_components": ["Token transfers", "Balance calculations"],
                    "mitigation": "Use SafeMath library or Solidity 0.8+ with built-in overflow checks"
                },
                {
                    "risk_level": "Medium",
                    "description": "Insufficient access controls for critical functions",
                    "affected_components": ["Owner functions", "Admin operations"],
                    "mitigation": "Implement proper role-based access control (RBAC)"
                }
            ]
        } 