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
                "description": "Symbolic execution tool for smart contracts by Trail of Bits",
                "capabilities": ["solidity", "symbolic_execution", "full_path_testing"],
                "command": "manticore {target} --solc-optimize --quick-mode"
            },
            "echidna": {
                "name": "Echidna",
                "description": "Property-based fuzzer for Solidity/Vyper smart contracts by Trail of Bits",
                "capabilities": ["solidity", "fuzzing", "property_testing"],
                "command": "echidna {target} --config echidna.config.yaml"
            },
            "aderyn": {
                "name": "Aderyn",
                "description": "Fast static analyzer for Solidity written in Rust by Cyfrin",
                "capabilities": ["solidity", "ast_analysis", "static_analysis"],
                "command": "aderyn {target} --json"
            },
            "securify2": {
                "name": "Securify v2",
                "description": "High-precision static analysis tool for Solidity using Datalog",
                "capabilities": ["solidity", "static_analysis", "formal_verification"],
                "command": "python -m securify {target} --output {target}.securify.json"
            }
        }
        
        # Available tools for Solana contract security scanning
        self.solana_tools = {
            "xray": {
                "name": "X-Ray",
                "description": "Static analyzer for Rust-based Solana programs by Sec3",
                "capabilities": ["solana", "rust", "static_analysis", "llvm"],
                "command": "xray scan {target} --output-format=json"
            },
            "vrust": {
                "name": "VRust",
                "description": "Vulnerability detection framework for Solana smart contracts",
                "capabilities": ["solana", "rust", "vulnerability_detection"],
                "command": "vrust analyze {target} --report-json"
            }
        }
        
        # Available tools for Polkadot contract security scanning
        self.polkadot_tools = {
            "scout": {
                "name": "Scout",
                "description": "Modular static analyzer for ink! (Rust-based) smart contracts by CoinFabrik",
                "capabilities": ["polkadot", "substrate", "soroban", "static_analysis"],
                "command": "scout scan {target} --output-json"
            }
        }
    
    def select_tools(self, input_type: str, cve_info: Union[Dict, str, Any]) -> List:
        """
        Select appropriate security tools based on input type and CVE information.
        
        Args:
            input_type: Type of input ('website', 'solidity_contract', 'solana_contract', or 'polkadot_contract')
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
        elif input_type == 'solana_contract':
            return self._select_solana_tools(cve_info)
        elif input_type == 'polkadot_contract':
            return self._select_polkadot_tools(cve_info)
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
        
        # Include Aderyn for fast AST-based analysis
        selected_tools.append({
            "id": "aderyn",
            "name": self.solidity_tools["aderyn"]["name"],
            "description": self.solidity_tools["aderyn"]["description"],
            "command": self.solidity_tools["aderyn"]["command"],
            "reason": "Fast static analysis with Rust-based parser"
        })
        
        # Determine if we need in-depth symbolic execution analysis
        deep_analysis_needed = False
        for risk in cve_info.get("risks", []):
            risk_desc = risk.get("description", "").lower()
            if "critical" in risk.get("risk_level", "").lower() or any(term in risk_desc for term in ["reentrancy", "overflow", "underflow", "logic error"]):
                deep_analysis_needed = True
                break
        
        # Use Mythril and/or Manticore for deep analysis
        if deep_analysis_needed:
            selected_tools.append({
                "id": "mythril",
                "name": self.solidity_tools["mythril"]["name"],
                "description": self.solidity_tools["mythril"]["description"],
                "command": self.solidity_tools["mythril"]["command"],
                "reason": "In-depth symbolic execution for critical vulnerabilities"
            })
            
            # Add Manticore for more comprehensive path analysis
            selected_tools.append({
                "id": "manticore",
                "name": self.solidity_tools["manticore"]["name"],
                "description": self.solidity_tools["manticore"]["description"],
                "command": self.solidity_tools["manticore"]["command"],
                "reason": "Full execution path testing for critical contracts"
            })
        
        # Use Echidna if the contract has property functions
        # In a real implementation, we would check for test properties in the code
        selected_tools.append({
            "id": "echidna",
            "name": self.solidity_tools["echidna"]["name"],
            "description": self.solidity_tools["echidna"]["description"],
            "command": self.solidity_tools["echidna"]["command"],
            "reason": "Fuzzing to discover edge cases in contract logic"
        })
        
        # Add Securify for formal verification
        high_value_contract = any("high value" in risk.get("description", "").lower() for risk in cve_info.get("risks", []))
        if high_value_contract or deep_analysis_needed:
            selected_tools.append({
                "id": "securify2",
                "name": self.solidity_tools["securify2"]["name"],
                "description": self.solidity_tools["securify2"]["description"],
                "command": self.solidity_tools["securify2"]["command"],
                "reason": "Formal verification for high-value contracts"
            })
        
        return selected_tools
    
    def _select_solana_tools(self, cve_info: Dict) -> List:
        """Select tools for Solana contract security scanning"""
        selected_tools = []
        
        # Always include X-Ray for Solana programs
        selected_tools.append({
            "id": "xray",
            "name": self.solana_tools["xray"]["name"],
            "description": self.solana_tools["xray"]["description"],
            "command": self.solana_tools["xray"]["command"],
            "reason": "Comprehensive static analysis for Solana programs"
        })
        
        # Include VRust for vulnerability detection
        selected_tools.append({
            "id": "vrust",
            "name": self.solana_tools["vrust"]["name"],
            "description": self.solana_tools["vrust"]["description"],
            "command": self.solana_tools["vrust"]["command"],
            "reason": "Specialized vulnerability detection for Solana contracts"
        })
        
        return selected_tools
    
    def _select_polkadot_tools(self, cve_info: Dict) -> List:
        """Select tools for Polkadot/Substrate contract security scanning"""
        selected_tools = []
        
        # Include Scout for ink! contracts
        selected_tools.append({
            "id": "scout",
            "name": self.polkadot_tools["scout"]["name"],
            "description": self.polkadot_tools["scout"]["description"],
            "command": self.polkadot_tools["scout"]["command"],
            "reason": "Static analysis for ink! smart contracts"
        })
        
        return selected_tools


class ToolSelector(SecurityToolSelector):
    """
    Alias for SecurityToolSelector for backward compatibility.
    """
    
    def select_tools_for_content_type(self, content_type: str) -> List:
        """
        Select appropriate security tools based on content type.
        
        Args:
            content_type: Type of content ('website', 'solidity_contract', 'solana_contract', or 'polkadot_contract')
            
        Returns:
            List containing selected tools and their configuration
        """
        return self.select_tools(content_type, {}) 