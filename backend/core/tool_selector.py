"""
Security Tool Selector module for the Security Agent.
Selects appropriate security tools based on input type and CVE information.
"""
from typing import Dict, List, Optional, Any, Union
import logging

# Import helpers
from backend.utils.helpers import get_logger

# Get logger
logger = get_logger('security_agent')

class SecurityToolSelector:
    """
    Selects appropriate security tools based on input type and CVE information.
    """
    
    def __init__(self):
        # Available tools for website security scanning
        self.website_tools = {
            "owasp_zap": {
                "name": "OWASP ZAP",
                "description": "Zed Attack Proxy - an open source web app scanner",
                "capabilities": ["web", "api", "injection", "authentication"],
                "command": "zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' {target}"
            },
            "nikto": {
                "name": "Nikto",
                "description": "Web server scanner",
                "capabilities": ["web", "server", "misconfigurations"],
                "command": "nikto -h {target}"
            },
            "wappalyzer": {
                "name": "Wappalyzer",
                "description": "Technology profiler that identifies technologies used on websites",
                "capabilities": ["web", "technology", "fingerprinting"],
                "command": "npx -y wappalyzer {target} --pretty"
            },
            "nuclei": {
                "name": "Nuclei",
                "description": "Vulnerability scanner with a vast template library",
                "capabilities": ["web", "api", "vulnerabilities", "misconfigurations"],
                "command": "nuclei -u {target} -silent"
            }
        }
        
        # Available tools for Solidity contract security scanning
        self.solidity_tools = {
            "mythril": {
                "name": "Mythril",
                "description": "Security analysis tool for EVM bytecode",
                "capabilities": ["solidity", "bytecode", "symbolic_execution"],
                "command": "myth analyze {target} --execution-timeout 90"
            },
            "slither": {
                "name": "Slither",
                "description": "Static analysis framework for Solidity",
                "capabilities": ["solidity", "static_analysis"],
                "command": "slither {target} --json -"
            },
            "solhint": {
                "name": "Solhint",
                "description": "Linting utility for Solidity code",
                "capabilities": ["solidity", "linting"],
                "command": "solhint {target}"
            },
            "manticore": {
                "name": "Manticore",
                "description": "Symbolic execution tool for smart contracts",
                "capabilities": ["solidity", "symbolic_execution"],
                "command": "manticore {target} --quick-mode"
            }
        }
    
    def select_tools(self, input_type: str, cve_info: Union[Dict, str, Any]) -> List:
        """
        Select appropriate security tools based on input type and CVE information.
        
        Args:
            input_type: Type of input ('website' or 'solidity_contract')
            cve_info: CVE information and risk assessment, could be a dict or string
            
        Returns:
            List containing selected tools and their configuration
        """
        logger.info(f"Selecting security tools for input type: {input_type}")
        
        # Ensure cve_info is a dictionary to prevent 'str' has no attribute 'get' errors
        if not isinstance(cve_info, dict):
            logger.warning(f"Expected dict for cve_info but got {type(cve_info)}. Converting to empty dict.")
            cve_info = {}
        
        if input_type == 'website':
            return self._select_website_tools(cve_info)
        elif input_type == 'solidity_contract':
            return self._select_solidity_tools(cve_info)
        else:
            logger.warning(f"Unknown input type: {input_type}")
            return []
    
    def _select_website_tools(self, cve_info: Dict) -> List:
        """Select tools for website security scanning"""
        selected_tools = []
        
        # Always include the basic website scanner (ZAP)
        selected_tools.append({
            "id": "owasp_zap",
            "name": self.website_tools["owasp_zap"]["name"],
            "description": self.website_tools["owasp_zap"]["description"],
            "command": self.website_tools["owasp_zap"]["command"],
            "reason": "Basic comprehensive web scanner"
        })
        
        # Check the CVE information to determine if we need specialized tools
        # In a real implementation, this would be more sophisticated
        
        # Check for server misconfigurations
        server_misconfiguration = False
        for risk in cve_info.get("risks", []):
            if "server" in risk.get("description", "").lower() or "configuration" in risk.get("description", "").lower():
                server_misconfiguration = True
                break
        
        if server_misconfiguration:
            selected_tools.append({
                "id": "nikto",
                "name": self.website_tools["nikto"]["name"],
                "description": self.website_tools["nikto"]["description"],
                "command": self.website_tools["nikto"]["command"],
                "reason": "Specialized in detecting server misconfigurations"
            })
        
        # Always include technology profiling
        selected_tools.append({
            "id": "wappalyzer",
            "name": self.website_tools["wappalyzer"]["name"],
            "description": self.website_tools["wappalyzer"]["description"],
            "command": self.website_tools["wappalyzer"]["command"],
            "reason": "Identify technologies for targeted vulnerability detection"
        })
        
        # Add Nuclei for specialized vulnerability detection
        high_risk_detected = any(risk.get("risk_level", "").lower() == "high" or risk.get("risk_level", "").lower() == "critical" for risk in cve_info.get("risks", []))
        if high_risk_detected:
            selected_tools.append({
                "id": "nuclei",
                "name": self.website_tools["nuclei"]["name"],
                "description": self.website_tools["nuclei"]["description"],
                "command": self.website_tools["nuclei"]["command"],
                "reason": "Specialized vulnerability detection for high-risk issues"
            })
        
        return selected_tools
    
    def _select_solidity_tools(self, cve_info: Dict) -> List:
        """Select tools for Solidity contract security scanning"""
        selected_tools = []
        
        # Always include the main static analyzer (Slither)
        selected_tools.append({
            "id": "slither",
            "name": self.solidity_tools["slither"]["name"],
            "description": self.solidity_tools["slither"]["description"],
            "command": self.solidity_tools["slither"]["command"],
            "reason": "Basic static analysis for Solidity code"
        })
        
        # Always include a linter
        selected_tools.append({
            "id": "solhint",
            "name": self.solidity_tools["solhint"]["name"],
            "description": self.solidity_tools["solhint"]["description"],
            "command": self.solidity_tools["solhint"]["command"],
            "reason": "Code quality and security best practices"
        })
        
        # Check if symbolic execution is needed based on risk assessment
        symbolic_execution_needed = False
        for risk in cve_info.get("risks", []):
            if "critical" in risk.get("risk_level", "").lower() or "reentrancy" in risk.get("description", "").lower():
                symbolic_execution_needed = True
                break
        
        if symbolic_execution_needed:
            # Choose between Mythril and Manticore (Mythril is generally faster)
            selected_tools.append({
                "id": "mythril",
                "name": self.solidity_tools["mythril"]["name"],
                "description": self.solidity_tools["mythril"]["description"],
                "command": self.solidity_tools["mythril"]["command"],
                "reason": "In-depth symbolic execution for critical vulnerabilities"
            })
        
        return selected_tools 