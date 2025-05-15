import os
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
import re
import openai
import logging

# Get logger
logger = logging.getLogger(__name__)

class AIAuditAnalyzer:
    """
    AI-powered Solidity code auditor that leverages knowledge from past audit reports
    to directly analyze smart contract code.
    """

    def __init__(self, api_key: Optional[str] = None, reports_dir: str = "security_agent/data/sources/audit_reports"):
        """
        Initialize the AI Audit Analyzer.

        Args:
            api_key: OpenAI API key (falls back to environment variables)
            reports_dir: Directory containing past audit reports
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.reports_dir = Path(reports_dir)
        self.vulnerability_patterns = {}
        self.knowledge_base = self._load_knowledge_base()

        if not self.api_key:
            logger.warning("OpenAI API key not found. AI-based analysis will be limited.")
            # Not raising an error here allows initialization to continue

    def _load_knowledge_base(self) -> List[Dict]:
        """
        Load knowledge from past audit reports.
        """
        knowledge = []

        if not self.reports_dir.exists():
            logger.warning(f"Reports directory not found: {self.reports_dir}")
            return knowledge

        # Collect information from audit report index if it exists
        index_path = self.reports_dir / "index.json"
        if index_path.exists():
            try:
                with open(index_path, 'r') as f:
                    index_data = json.load(f)
                    for report in index_data.get("reports", []):
                        if "findings" in report:
                            knowledge.extend(report["findings"])
                logger.info(f"Loaded {len(knowledge)} findings from {index_path}")
            except Exception as e:
                logger.error(f"Error loading audit knowledge base: {e}")
        else:
            logger.warning(f"Index file not found: {index_path}")

        # Extract common vulnerability patterns from knowledge
        self.vulnerability_patterns = self._extract_vulnerability_patterns(knowledge)

        return knowledge

    def _extract_vulnerability_patterns(self, knowledge: List[Dict]) -> Dict[str, List[str]]:
        """
        Extract common vulnerability patterns from knowledge base.

        Args:
            knowledge: List of findings from past audit reports

        Returns:
            Dictionary mapping vulnerability categories to patterns
        """
        patterns = {
            "reentrancy": [],
            "overflow": [],
            "access_control": [],
            "unchecked_return": [],
            "gas_optimization": [],
            "logic_issues": [],
            "oracle_manipulation": [],
            "front_running": [],
            "dos": [],
            "other": []
        }

        # Process each finding to identify patterns
        for finding in knowledge:
            description = finding.get("description", "").lower()

            if "reentrant" in description or "reentrancy" in description:
                patterns["reentrancy"].append(description)
            elif "overflow" in description or "underflow" in description:
                patterns["overflow"].append(description)
            elif "permission" in description or "access control" in description or "authorization" in description:
                patterns["access_control"].append(description)
            elif "return value" in description or "unchecked" in description:
                patterns["unchecked_return"].append(description)
            elif "gas" in description and ("optimization" in description or "efficient" in description):
                patterns["gas_optimization"].append(description)
            elif "logic" in description or "business logic" in description:
                patterns["logic_issues"].append(description)
            elif "oracle" in description or "price manipulation" in description:
                patterns["oracle_manipulation"].append(description)
            elif "front-run" in description or "frontrun" in description:
                patterns["front_running"].append(description)
            elif "dos" in description or "denial of service" in description:
                patterns["dos"].append(description)
            else:
                patterns["other"].append(description)

        return patterns

    def analyze_solidity_code(self, code: str, contract_name: str = "") -> List[Dict]:
        """
        Analyze Solidity code for security vulnerabilities using AI.

        Args:
            code: Solidity contract code
            contract_name: Name of the contract

        Returns:
            List of findings
        """
        # Check if API key is available
        if not self.api_key:
            logger.warning("Cannot perform AI analysis: OpenAI API key not available")
            # Return empty list if API key is not available
            return []

        # Prepare system message with knowledge from past audits
        system_message = self._create_system_message()

        # Load the code and ask GPT to analyze it
        return self._analyze_with_gpt(system_message, code, contract_name)

    def _create_system_message(self) -> str:
        """
        Create a system message with knowledge from past audits.
        """
        system_message = """
        You are an expert Solidity security auditor. Your task is to analyze a smart contract
        and identify any security vulnerabilities, potential bugs, or optimizations.

        Based on the knowledge from previous audit reports, pay special attention to these common vulnerability types:

        1. Reentrancy vulnerabilities
        2. Integer overflow/underflow
        3. Access control issues
        4. Unchecked return values
        5. Gas optimization issues
        6. Business logic issues
        7. Oracle manipulation vulnerabilities
        8. Front-running vulnerabilities
        9. Denial of Service (DoS) vulnerabilities
        10. Other security best practices

        For each finding, provide:
        1. A clear description of the issue
        2. The severity (Critical, High, Medium, Low, Informational)
        3. The exact location in the code (line numbers)
        4. A detailed explanation of why this is an issue
        5. A concrete recommendation for fixing the issue

        Format each vulnerability as a structured finding.
        """

        # Add specific examples from past reports
        for category, examples in self.vulnerability_patterns.items():
            if examples:
                system_message += f"\n\nExamples of {category.replace('_', ' ')} issues from past audits:\n"
                for example in examples[:3]:  # Limit to 3 examples per category
                    system_message += f"- {example}\n"

        return system_message

    def _analyze_with_gpt(self, system_message: str, code: str, contract_name: str) -> List[Dict]:
        """
        Analyze code with GPT to find vulnerabilities.

        Args:
            system_message: System instructions
            code: Solidity contract code
            contract_name: Name of the contract

        Returns:
            List of findings
        """
        try:
            # Try to get API key again (in case it was set after initialization)
            api_key = self.api_key or os.environ.get("OPENAI_API_KEY")
            if not api_key:
                logger.error("OpenAI API key is required for analysis")
                return []

            client = openai.OpenAI(api_key=api_key)

            message = f"Perform a comprehensive security audit on the following Solidity smart contract"
            if contract_name:
                message += f" named '{contract_name}'."
            else:
                message += "."

            message += "\n\nCode:\n```solidity\n" + code + "\n```"
            message += """

            For each vulnerability, provide the output in the following JSON format:
            {
                "type": "vulnerability_type",
                "severity": "severity_level",
                "description": "detailed_description",
                "location": "contract_name.sol:line_number",
                "recommendation": "specific_recommendation"
            }

            The output should be a list of these JSON objects wrapped in ```json and ``` markers.
            """

            logger.info(f"Sending request to OpenAI for smart contract analysis of {contract_name}")
            response = client.chat.completions.create(
                model="gpt-4o",  # Use a powerful model for code analysis
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": message}
                ],
                temperature=0.0,  # Use low temperature for deterministic results
                max_tokens=4000
            )
            logger.info("Received response from OpenAI")

            # Parse the response to extract findings
            findings = self._parse_response(response.choices[0].message.content)
            return findings

        except Exception as e:
            logger.error(f"Error analyzing code with GPT: {e}")
            return []

    def _parse_response(self, content: str) -> List[Dict]:
        """
        Parse GPT response to extract findings.

        Args:
            content: Response content from GPT

        Returns:
            List of findings
        """
        findings = []

        # Extract JSON blocks from the response
        json_pattern = r'```(?:json)?\s*([\s\S]*?)\s*```'
        matches = re.findall(json_pattern, content)

        if matches:
            for match in matches:
                try:
                    # Try to parse as array of objects
                    data = json.loads(match)
                    if isinstance(data, list):
                        findings.extend(data)
                    elif isinstance(data, dict):
                        findings.append(data)
                except json.JSONDecodeError:
                    # If not valid JSON, try to extract individual findings
                    finding_pattern = r'{[\s\S]*?}'
                    finding_matches = re.findall(finding_pattern, match)
                    for finding_match in finding_matches:
                        try:
                            finding = json.loads(finding_match)
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue

        # If no valid JSON was found, try to extract structured information from text
        if not findings and "severity" in content.lower() and "description" in content.lower():
            # Simplified parsing for text-based findings
            sections = content.split('\n\n')
            current_finding = {}

            for section in sections:
                if "severity:" in section.lower():
                    # Start a new finding
                    if current_finding and 'description' in current_finding:
                        findings.append(current_finding)
                    current_finding = {
                        'type': 'unknown',
                        'severity': 'unknown',
                        'description': '',
                        'location': '',
                        'recommendation': ''
                    }

                # Parse severity
                if "severity:" in section.lower():
                    severity_match = re.search(r'severity:[ \t]*(critical|high|medium|low|informational)',
                                              section.lower())
                    if severity_match:
                        current_finding['severity'] = severity_match.group(1)

                # Parse description
                if "description:" in section.lower():
                    desc_match = re.search(r'description:[ \t]*(.*)', section, re.DOTALL)
                    if desc_match:
                        current_finding['description'] = desc_match.group(1).strip()

                # Parse location
                if "location:" in section.lower():
                    loc_match = re.search(r'location:[ \t]*(.*)', section)
                    if loc_match:
                        current_finding['location'] = loc_match.group(1).strip()

                # Parse recommendation
                if "recommendation:" in section.lower():
                    rec_match = re.search(r'recommendation:[ \t]*(.*)', section, re.DOTALL)
                    if rec_match:
                        current_finding['recommendation'] = rec_match.group(1).strip()

            # Add the last finding
            if current_finding and 'description' in current_finding:
                findings.append(current_finding)

        return findings
