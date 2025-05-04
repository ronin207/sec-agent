import os
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv
import argparse

# Load environment variables from .env file
load_dotenv()

# LangChain imports
from langchain_core.documents import Document

# Import our components from backend modules
from backend.core.knowledge_base import SecurityKnowledgeBase
from backend.core.orchestrator import SecurityAgentOrchestrator
from backend.utils.cve_loader import CVEDataLoader

# Setup basic directory structures
CHROMA_DIR = os.environ.get("CHROMA_PERSIST_DIRECTORY", os.path.join(os.path.dirname(__file__), "data", "chroma"))
os.makedirs(CHROMA_DIR, exist_ok=True)

# Demo function to populate the vector store with some sample security data
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

# New function to load CVE data into the knowledge base
def load_cve_data(kb: SecurityKnowledgeBase, cve_id: str = None, keyword: str = None, 
                  max_results: int = 20, load_smart_contracts: bool = False):
    """
    Load CVE data into the knowledge base using the CVEDataLoader utility
    
    Args:
        kb: SecurityKnowledgeBase instance
        cve_id: Specific CVE ID to load (e.g., "CVE-2024-51427")
        keyword: Keyword to search for CVEs (e.g., "smart contract")
        max_results: Maximum number of search results to return
        load_smart_contracts: Whether to load smart contract related CVEs
    """
    print("\n--- Loading CVE Data ---")
    
    # Initialize the CVE data loader
    cve_loader = CVEDataLoader()
    documents = []
    
    # Process based on the provided options
    if cve_id:
        print(f"Loading specific CVE: {cve_id}")
        cve_data = cve_loader.fetch_cve_by_id(cve_id)
        if cve_data:
            # Wrap in structure expected by convert_to_documents
            formatted_data = {
                "vulnerabilities": [
                    {"cve": cve_data}
                ]
            }
            documents = cve_loader.convert_to_documents(formatted_data)
            print(f"Loaded 1 CVE: {cve_id}")
        else:
            print(f"Failed to load CVE: {cve_id}")
    
    elif keyword:
        print(f"Searching for CVEs with keyword: {keyword}")
        cve_data = cve_loader.search_cves(keyword, max_results=max_results)
        documents = cve_loader.convert_to_documents(cve_data)
        print(f"Loaded {len(documents)} CVEs related to '{keyword}'")
    
    elif load_smart_contracts:
        print("Loading smart contract related CVEs")
        documents = cve_loader.load_smart_contract_cves()
        print(f"Loaded {len(documents)} smart contract related CVEs")
    
    # Add the loaded documents to the knowledge base
    if documents:
        kb.add_documents(documents)
        print(f"Added {len(documents)} CVE documents to the knowledge base")
    else:
        print("No CVE documents were loaded")


if __name__ == "__main__":
    # Set up argument parser for command-line interface
    parser = argparse.ArgumentParser(description="Security Agent CLI")
    
    # Add subparsers for different operations
    subparsers = parser.add_subparsers(dest="operation", help="Operation to perform")
    
    # Basic agent run
    run_parser = subparsers.add_parser("run", help="Run the security agent on a URL")
    run_parser.add_argument("url", help="URL to analyze")
    run_parser.add_argument("--sample-data", action="store_true", help="Load sample data")
    
    # CVE loading
    cve_parser = subparsers.add_parser("load-cve", help="Load CVE data into knowledge base")
    cve_parser.add_argument("--id", help="Specific CVE ID to load (e.g., CVE-2024-51427)")
    cve_parser.add_argument("--keyword", help="Keyword to search for CVEs")
    cve_parser.add_argument("--max-results", type=int, default=20, help="Maximum search results")
    cve_parser.add_argument("--smart-contracts", action="store_true", help="Load smart contract CVEs")
    
    # Parse arguments
    args = parser.parse_args()

    # Check for API key
    if not os.environ.get("OPENAI_API_KEY"):
        print("Warning: OPENAI_API_KEY not found in environment variables.")
        print("Please set your API key in the .env file.")
    
    # Initialize the knowledge base
    kb = SecurityKnowledgeBase()
    
    # Process based on operation
    if args.operation == "run":
        # Load sample data if requested
        if args.sample_data:
            populate_sample_data(kb)
        
        # Create the agent orchestrator
        orchestrator = SecurityAgentOrchestrator(kb)
        
        # Run analysis on the provided URL
        result = orchestrator.run(args.url)
        
        print("\n--- Security Analysis Results ---")
        print(f"URL: {args.url}")
        print(f"Analysis Complete: {result.get('analysis_complete', False)}")
        
        if result.get('error'):
            print(f"Error: {result.get('error')}")
        else:
            print("\nScan Results:")
            scan_results = result.get('scan_results', {})
            for scan_type, data in scan_results.items():
                print(f"\n{scan_type.upper()}:")
                for key, value in data.items():
                    print(f"  {key}: {value}")
            
            print("\nVulnerabilities:")
            for vuln in result.get('vulnerabilities', []):
                print(f"\n- Type: {vuln['type']}")
                print(f"  Description: {vuln['description']}")
    
    elif args.operation == "load-cve":
        # Load CVE data based on provided arguments
        load_cve_data(
            kb,
            cve_id=args.id,
            keyword=args.keyword,
            max_results=args.max_results,
            load_smart_contracts=args.smart_contracts
        )
        
        print("\nCVE data loaded into knowledge base successfully.")
        print("You can now run the agent with: python main.py run <url>")
    
    else:
        # No operation specified, show help
        parser.print_help()