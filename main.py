import os
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv
import argparse  # Add argparse for command-line interface

# Load environment variables from .env file
load_dotenv()

# LangChain imports
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_chroma import Chroma

# LangGraph imports
from langgraph.graph import StateGraph, END

# Import our CVE loader utility
from backend.utils.cve_loader import CVEDataLoader

# Setup basic directory structures
CHROMA_DIR = os.environ.get("CHROMA_PERSIST_DIRECTORY", os.path.join(os.path.dirname(__file__), "data", "chroma"))
os.makedirs(CHROMA_DIR, exist_ok=True)

class SecurityKnowledgeBase:
    """
    A RAG-based knowledge base for security-related information including:
    - CVE details
    - Security best practices
    - Vulnerability mitigation strategies
    - Organizational security policies
    """
    
    def __init__(self, 
                 model_name: str = "gpt-3.5-turbo", 
                 temperature: float = 0.0,
                 api_key: Optional[str] = None,
                 collection_name: str = "security_knowledge"):
        # Initialize the LLM with API key from environment variable if not provided
        api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.llm = ChatOpenAI(model_name=model_name, temperature=temperature, api_key=api_key)
        
        # Initialize embeddings with API key
        self.embeddings = OpenAIEmbeddings(api_key=api_key)
        
        # Store collection name
        self.collection_name = collection_name
        
        # Initialize vector store
        # This will be populated later with security data
        self._initialize_vector_store()
        
    def _initialize_vector_store(self):
        """Initialize or load the vector store from disk"""
        import shutil
        
        try:
            # Try to create/load the vector store with an explicit collection name
            from chromadb import PersistentClient
            client = PersistentClient(path=CHROMA_DIR)
            
            self.vectorstore = Chroma(
                persist_directory=CHROMA_DIR,
                embedding_function=self.embeddings,
                collection_name=self.collection_name,
                client=client
            )
            print(f"Loaded/created vector store with collection name: {self.collection_name}")
            
        except Exception as e:
            print(f"Error initializing vector store: {e}")
            print("Attempting to recreate the vector store...")
            
            try:
                # If there's an existing directory and it's causing issues, try to remove it
                if os.path.exists(CHROMA_DIR):
                    # Only remove the contents, not the directory itself
                    for item in os.listdir(CHROMA_DIR):
                        item_path = os.path.join(CHROMA_DIR, item)
                        if os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                        else:
                            os.remove(item_path)
                    print(f"Cleared contents of {CHROMA_DIR}")
                
                # Create a fresh vector store
                from chromadb import PersistentClient
                client = PersistentClient(path=CHROMA_DIR)
                
                self.vectorstore = Chroma(
                    persist_directory=CHROMA_DIR,
                    embedding_function=self.embeddings,
                    collection_name=self.collection_name,
                    client=client
                )
                print(f"Successfully recreated vector store with collection name: {self.collection_name}")
                
            except Exception as e2:
                print(f"Failed to recreate vector store: {e2}")
                # Fall back to in-memory vector store to prevent the application from crashing
                self.vectorstore = Chroma(
                    embedding_function=self.embeddings,
                    collection_name=self.collection_name
                )
                print("Using in-memory vector store as fallback")
    
    def add_documents(self, documents: List[Document]):
        """Add documents to the knowledge base"""
        self.vectorstore.add_documents(documents)
        # The persist() method is no longer needed/supported in newer versions of Chroma
        # Data is automatically persisted when using PersistentClient
        print(f"Added {len(documents)} documents to the knowledge base")
    
    def get_retriever(self, search_type: str = "similarity", k: int = 5):
        """Get a retriever from the vector store"""
        return self.vectorstore.as_retriever(
            search_type=search_type,
            search_kwargs={"k": k}
        )
    
    def create_rag_chain(self):
        """Create a basic RAG chain for answering security-related queries"""
        retriever = self.get_retriever()
        
        template = """You are a security expert assistant focused on helping identify and mitigate vulnerabilities.
        Use the following pieces of context to answer the question at the end. 
        If you don't know the answer, just say that you don't know, don't try to make up an answer.
        
        Context:
        {context}
        
        Question: {question}
        """
        
        prompt = ChatPromptTemplate.from_template(template)
        
        chain = (
            {"context": retriever, "question": RunnablePassthrough()}
            | prompt
            | self.llm
            | StrOutputParser()
        )
        
        return chain


class SecurityAgentOrchestrator:
    """
    Orchestrates the workflow for security agents using LangGraph
    """
    
    def __init__(self, knowledge_base: SecurityKnowledgeBase):
        self.knowledge_base = knowledge_base
        self.graph = self._build_agent_graph()
    
    def _build_agent_graph(self):
        """Build the LangGraph for security agent orchestration"""
        
        # Define state schema for LangGraph
        from typing_extensions import TypedDict

        # Define the state schema
        class SecurityState(TypedDict, total=False):
            url: str
            scan_results: Dict
            vulnerabilities: List
            analysis_complete: bool
            error: Optional[str]
        
        # Define nodes/agents for the graph
        def url_analysis(state):
            """Analyze the URL input"""
            try:
                # In a real implementation, this would do more analysis
                # For now, we'll just do a RAG lookup for information about the domain
                rag_chain = self.knowledge_base.create_rag_chain()
                domain_info = rag_chain.invoke(f"What security information do we have about {state['url']}?")
                
                # Initialize scan_results if it doesn't exist
                if 'scan_results' not in state:
                    state['scan_results'] = {}
                
                state['scan_results']['url_analysis'] = {
                    "domain": state['url'],
                    "analysis": domain_info
                }
                return state
            except Exception as e:
                state['error'] = f"Error in URL analysis: {str(e)}"
                return state
        
        def task_dispatcher(state):
            """Dispatcher node to determine next steps based on URL analysis"""
            if state.get('error'):
                return "handle_error"
            
            # In a real implementation, this would make decisions about which
            # specialized agents to dispatch to (web scanner, API scanner, etc.)
            # For now, we'll just proceed to vulnerability analysis
            return "analyze_vulnerabilities"
        
        def analyze_vulnerabilities(state):
            """Perform vulnerability analysis using RAG"""
            try:
                rag_chain = self.knowledge_base.create_rag_chain()
                
                # This would integrate with actual scanning tools in a real implementation
                # For now, we'll simulate by querying our RAG system
                vulnerability_info = rag_chain.invoke(
                    f"What common vulnerabilities might be present in {state['url']}?"
                )
                
                # Initialize vulnerabilities if it doesn't exist
                if 'vulnerabilities' not in state:
                    state['vulnerabilities'] = []
                
                # In a real implementation, this would parse real scanner output
                state['vulnerabilities'].append({
                    "type": "simulated",
                    "description": vulnerability_info
                })
                state['analysis_complete'] = True
                return state
            except Exception as e:
                state['error'] = f"Error in vulnerability analysis: {str(e)}"
                return state
        
        def handle_error(state):
            """Handle any errors in the workflow"""
            print(f"Error encountered: {state.get('error')}")
            # In a real implementation, this would handle errors more gracefully
            return state
        
        # Build the graph with state schema
        workflow = StateGraph(state_schema=SecurityState)
        
        # Add nodes
        workflow.add_node("url_analysis", url_analysis)
        workflow.add_node("analyze_vulnerabilities", analyze_vulnerabilities)
        workflow.add_node("handle_error", handle_error)
        
        # Add conditional edges
        workflow.add_conditional_edges(
            "url_analysis",
            task_dispatcher
        )
        
        # Add final edges
        workflow.add_edge("analyze_vulnerabilities", END)
        workflow.add_edge("handle_error", END)
        
        # Set entry point
        workflow.set_entry_point("url_analysis")
        
        # Compile the graph
        return workflow.compile()
    
    def run(self, url: str) -> Dict:
        """Run the security agent workflow for a given URL"""
        # Initialize the state with just the URL
        initial_state = {
            "url": url,
            "scan_results": {},
            "vulnerabilities": [],
            "analysis_complete": False,
            "error": None
        }
        
        result = self.graph.invoke(initial_state)
        return result


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