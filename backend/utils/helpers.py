"""
Helper utilities for the Security Agent application.
"""
import os
import logging
from typing import Dict, List, Optional, Any

from backend.config.settings import LOG_LEVEL
from langchain_core.documents import Document
from backend.core.knowledge_base import SecurityKnowledgeBase


# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger('security_agent')


def setup_directories(paths: List[str]) -> None:
    """Create directories if they don't exist"""
    for path in paths:
        os.makedirs(path, exist_ok=True)
        logger.debug(f"Ensured directory exists: {path}")


def format_scan_results(results: Dict) -> str:
    """Format scan results for display"""
    output = []
    
    # Add URL analysis if available
    if 'scan_results' in results and 'url_analysis' in results['scan_results']:
        url_analysis = results['scan_results']['url_analysis']
        output.append(f"\n--- URL ANALYSIS: {url_analysis.get('domain', 'Unknown')} ---")
        output.append(f"Analysis: {url_analysis.get('analysis', 'No analysis available')}")
    
    # Add vulnerabilities if available
    if 'vulnerabilities' in results and results['vulnerabilities']:
        output.append("\n--- VULNERABILITIES ---")
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            output.append(f"\n{i}. Type: {vuln.get('type', 'Unknown')}")
            output.append(f"   Description: {vuln.get('description', 'No description available')}")
    
    # Add error if available
    if 'error' in results and results['error']:
        output.append(f"\n--- ERROR ---\n{results['error']}")
    
    return "\n".join(output)


def validate_url(url: str) -> bool:
    """
    Validate that a URL is properly formatted
    This is a simple implementation that could be expanded
    """
    # Basic validation - could be expanded with regex or other checks
    if not url:
        return False
    
    # Ensure the URL has at least a domain
    if "." not in url:
        return False
    
    return True


def sanitize_input(input_text: str) -> str:
    """
    Sanitize user input to prevent injection attacks
    """
    # Remove potentially dangerous characters or sequences
    # This is a simple implementation that could be expanded
    sanitized = input_text.strip()
    
    # Remove common script tags
    dangerous_patterns = ["<script>", "</script>", "javascript:", "data:text/html"]
    for pattern in dangerous_patterns:
        sanitized = sanitized.replace(pattern, "")
    
    return sanitized


def populate_sample_data(kb: SecurityKnowledgeBase):
    """Populate the knowledge base with sample security data"""
    documents = [
        Document(
            page_content="Cross-Site Scripting (XSS) is a client-side code injection attack where attackers inject malicious scripts into websites. Mitigation includes input validation, output encoding, and Content Security Policy (CSP).",
            metadata={"type": "vulnerability", "id": "cve-2021-0001"}
        ),
        Document(
            page_content="SQL Injection occurs when untrusted data is sent to an interpreter as part of a command or query. Mitigation includes prepared statements, parameterized queries, and ORM frameworks.",
            metadata={"type": "vulnerability", "id": "cve-2021-0002"}
        ),
        Document(
            page_content="API Security best practices include using OAuth 2.0 or JWT for authentication, implementing rate limiting, validating all inputs, and using HTTPS.",
            metadata={"type": "best_practice", "category": "api"}
        ),
        Document(
            page_content="Smart Contract vulnerabilities include reentrancy attacks, integer overflow/underflow, and gas limit issues. Always use the latest version of Solidity and follow established patterns.",
            metadata={"type": "vulnerability", "category": "smart_contract"}
        ),
        Document(
            page_content="AI model security concerns include prompt injection, training data poisoning, and model inversion attacks. Implement input validation, output filtering, and regular model monitoring.",
            metadata={"type": "vulnerability", "category": "ai"}
        )
    ]
    
    kb.add_documents(documents)


# Export the logger for external use
def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for the given name
    """
    return logging.getLogger(name)