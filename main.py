import os
import sys
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv
import argparse
import json

# Add rich library imports for colorful output
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from rich import box
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

# Initialize rich console
console = Console()

# Load environment variables from .env file
load_dotenv()

# LangChain imports
from langchain_core.documents import Document

# Import our components from backend modules
from backend.core.knowledge_base import SecurityKnowledgeBase
from backend.core.security_agent import SecurityAgent
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
    console.print("\n[bold blue]--- Loading CVE Data ---[/bold blue]")
    
    # Initialize the CVE data loader
    cve_loader = CVEDataLoader()
    documents = []
    
    # Process based on the provided options
    if cve_id:
        console.print(f"Loading specific CVE: [cyan]{cve_id}[/cyan]")
        cve_data = cve_loader.fetch_cve_by_id(cve_id)
        if cve_data:
            # Wrap in structure expected by convert_to_documents
            formatted_data = {
                "vulnerabilities": [
                    {"cve": cve_data}
                ]
            }
            documents = cve_loader.convert_to_documents(formatted_data)
            console.print(f"Loaded 1 CVE: [green]{cve_id}[/green]")
        else:
            console.print(f"[bold red]Failed to load CVE:[/bold red] {cve_id}")
    
    elif keyword:
        console.print(f"Searching for CVEs with keyword: [cyan]{keyword}[/cyan]")
        cve_data = cve_loader.search_cves(keyword, max_results=max_results)
        documents = cve_loader.convert_to_documents(cve_data)
        console.print(f"Loaded [green]{len(documents)}[/green] CVEs related to '[cyan]{keyword}[/cyan]'")
    
    elif load_smart_contracts:
        console.print("Loading smart contract related CVEs")
        documents = cve_loader.load_smart_contract_cves()
        console.print(f"Loaded [green]{len(documents)}[/green] smart contract related CVEs")
    
    # Add the loaded documents to the knowledge base
    if documents:
        kb.add_documents(documents)
        console.print(f"Added [green]{len(documents)}[/green] CVE documents to the knowledge base")
    else:
        console.print("[yellow]No CVE documents were loaded[/yellow]")

# Function to display scan results in a colorful, well-organized format
def display_scan_results(results):
    """Display scan results in a colorful, well-organized format"""
    if results.get('status') == 'error':
        console.print(f"[bold red]Error:[/bold red] {results.get('error')}")
        return
    
    # Display basic information
    if results.get('is_multiple'):
        num_files = len(results.get('files', []))
        console.print(Panel(f"[bold]Multiple Targets:[/bold] {num_files} files/URLs scanned", 
                          title="Scan Information", style="blue"))
        
        # Show file list if not too many
        if num_files <= 10:
            files_table = Table(box=box.SIMPLE)
            files_table.add_column("Files Scanned", style="cyan")
            for file in results.get('files', []):
                files_table.add_row(file)
            console.print(files_table)
    else:
        console.print(Panel(f"[bold]Target:[/bold] {results.get('input')}", 
                          title="Scan Information", style="blue"))
    
    # Create summary table
    console.print("\n[bold]Scan Summary[/bold]")
    
    summary_table = Table(box=box.ROUNDED)
    summary_table.add_column("Property", style="cyan")
    summary_table.add_column("Value", style="green")
    
    summary_table.add_row("Input Type", results.get('input_type', 'Unknown'))
    summary_table.add_row("Scan Status", results.get('status', 'Unknown'))
    summary_table.add_row("Execution Time", f"{results.get('execution_time', 0):.2f} seconds")
    summary_table.add_row("Total Findings", str(results.get('aggregated_results', {}).get('total_findings', 0)))
    
    console.print(summary_table)
    
    # Display severity breakdown
    severity_table = Table(title="Findings by Severity", box=box.SIMPLE)
    severity_table.add_column("Severity", style="yellow")
    severity_table.add_column("Count", style="green", justify="right")
    
    for severity, count in results.get('aggregated_results', {}).get('findings_by_severity', {}).items():
        severity_color = "green"
        if severity.lower() == "high":
            severity_color = "orange3"
        elif severity.lower() == "critical":
            severity_color = "red"
        elif severity.lower() == "medium":
            severity_color = "yellow"
            
        severity_table.add_row(f"[{severity_color}]{severity}[/{severity_color}]", str(count))
        
    console.print(severity_table)
    
    # Display summary from LLM if available
    summary = results.get('summary', {})
    if summary:
        console.print(Panel(summary.get('summary', "No summary available"), 
                            title="Executive Summary", style="cyan"))
        
        # Display risk assessment
        risk = summary.get('risk_assessment', 'Unknown')
        risk_color = "green"
        if risk.lower() == "high":
            risk_color = "orange3"
        elif risk.lower() == "critical":
            risk_color = "red"
        elif risk.lower() == "medium":
            risk_color = "yellow"
            
        console.print(f"\n[bold]Risk Assessment:[/bold] [{risk_color}]{risk}[/{risk_color}]")
        
        # Display technical findings
        console.print("\n[bold]Technical Findings:[/bold]")
        for i, finding in enumerate(summary.get('technical_findings', []), 1):
            console.print(f"{i}. {finding}")
        
        # Display remediation suggestions
        console.print("\n[bold]Remediation Suggestions:[/bold]")
        for i, suggestion in enumerate(summary.get('remediation_suggestions', []), 1):
            console.print(f"{i}. {suggestion}")
    
    # Tools used
    console.print("\n[bold]Tools Used:[/bold]")
    for tool in results.get('aggregated_results', {}).get('tools_used', []):
        console.print(f"- {tool}")
    
    # Deduplication stats if available
    if results.get('aggregated_results', {}).get('stats', {}).get('duplicates_removed'):
        stats = results.get('aggregated_results', {}).get('stats', {})
        console.print("\n[bold blue]Deduplication Statistics[/bold blue]")
        console.print(f"Total raw findings: [cyan]{stats.get('total_raw_findings', 0)}[/cyan]")
        console.print(f"Unique findings: [green]{stats.get('total_unique_findings', 0)}[/green]")
        console.print(f"Duplicates removed: [yellow]{stats.get('duplicates_removed', 0)}[/yellow]")
        console.print(f"Duplicate groups: [yellow]{stats.get('duplicate_groups', 0)}[/yellow]")
    
    # Add detailed comprehensive summary at the end
    console.print("\n[bold blue]=== COMPREHENSIVE SUMMARY ===[/bold blue]")
    
    # Create a table for detailed findings breakdown
    detail_table = Table(title="Detailed Findings Breakdown", box=box.ROUNDED)
    detail_table.add_column("Category", style="yellow")
    detail_table.add_column("Details", style="cyan")
    
    # Add relevant data to the table
    findings_by_severity = results.get('aggregated_results', {}).get('findings_by_severity', {})
    
    # Prepare severity breakdown string
    severity_breakdown = ""
    for severity, count in findings_by_severity.items():
        severity_color = "green"
        if severity.lower() == "high":
            severity_color = "orange3"
        elif severity.lower() == "critical":
            severity_color = "red"
        elif severity.lower() == "medium":
            severity_color = "yellow"
        severity_breakdown += f"[{severity_color}]{severity}[/{severity_color}]: {count}\n"
    
    # Add rows to the detailed table
    detail_table.add_row("Input Type", results.get('input_type', 'Unknown'))
    detail_table.add_row("Severity Breakdown", severity_breakdown)
    detail_table.add_row("Tools Used", "\n".join(results.get('aggregated_results', {}).get('tools_used', ["None"])))
    
    # Add tool success rates if available
    tool_success_count = 0
    tool_total_count = 0
    for tool_result in results.get('tool_results', []):
        tool_total_count += 1
        if tool_result.get('status') == 'success':
            tool_success_count += 1
    
    if tool_total_count > 0:
        success_rate = (tool_success_count / tool_total_count) * 100
        detail_table.add_row("Tool Success Rate", f"{success_rate:.1f}% ({tool_success_count}/{tool_total_count})")
    
    # Add execution time
    detail_table.add_row("Total Execution Time", f"{results.get('execution_time', 0):.2f} seconds")
    
    # Display the table
    console.print(detail_table)
    
    # Add top recommendations section if remediation suggestions available
    if results.get('summary', {}).get('remediation_suggestions'):
        console.print("\n[bold green]TOP RECOMMENDATIONS[/bold green]")
        
        # Create a numbered list of recommendations
        recs = results.get('summary', {}).get('remediation_suggestions', [])
        for i, rec in enumerate(recs[:min(5, len(recs))], 1):
            console.print(f"[bold]{i}.[/bold] {rec}")
        
        if len(recs) > 5:
            console.print(f"[dim]... and {len(recs) - 5} more recommendations[/dim]")
    
    # Add a footer with information about how to customize the output
    console.print("\n[bold dim]--- Scan Complete ---[/bold dim]")

# Function to display tool results
def display_tool_results(results, verbose=False):
    """
    Display detailed tool results.
    
    Args:
        results: Dictionary containing tool results
        verbose: Whether to display verbose output
    """
    console.print(Panel("[bold]Detailed Tool Results[/bold]", style="blue"))
    
    for tool_result in results.get('tool_results', []):
        tool_name = tool_result.get('tool_name', 'Unknown')
        status = tool_result.get('status', 'unknown')
        execution_time = tool_result.get('execution_time', 0)
        raw_output = tool_result.get('raw_output', '')
        findings = tool_result.get('findings', [])
        
        status_color = "green" if status == "success" else "red"
        tool_panel = Panel(
            f"[bold cyan]{tool_name}[/bold cyan]\n"
            f"Status: [{status_color}]{status}[/{status_color}]\n"
            f"Execution Time: {execution_time:.2f} seconds\n"
            f"Findings: {len(findings)}",
            border_style="blue"
        )
        console.print(tool_panel)
        
        # Group findings by ID to check for duplicates
        findings_by_id = {}
        for finding in findings:
            finding_id = finding.get('id', 'unknown')
            if finding_id not in findings_by_id:
                findings_by_id[finding_id] = []
            findings_by_id[finding_id].append(finding)
        
        # Print findings count information
        console.print(f"Unique finding IDs: [cyan]{len(findings_by_id)}[/cyan]")
        
        # In verbose mode, show findings details
        if verbose and findings:
            finding_table = Table(box=box.SIMPLE)
            finding_table.add_column("ID", style="dim")
            finding_table.add_column("Name", style="cyan")
            finding_table.add_column("Severity", style="yellow")
            finding_table.add_column("Location", style="green")
            
            # Show unique findings only
            shown_ids = set()
            for finding in findings:
                finding_id = finding.get('id', 'unknown')
                if finding_id in shown_ids:
                    continue
                    
                shown_ids.add(finding_id)
                name = finding.get('name', 'Unknown')
                severity = finding.get('severity', 'Unknown')
                location = finding.get('location', 'Unknown')
                
                # Determine severity color
                severity_color = "green"
                if severity.lower() == "high":
                    severity_color = "orange3"
                elif severity.lower() == "critical":
                    severity_color = "red"
                elif severity.lower() == "medium":
                    severity_color = "yellow"
                
                # Count duplicates
                duplicate_count = len(findings_by_id.get(finding_id, []))
                if duplicate_count > 1:
                    name += f" [dim](x{duplicate_count})[/dim]"
                
                finding_table.add_row(
                    finding_id,
                    name,
                    f"[{severity_color}]{severity}[/{severity_color}]",
                    location
                )
            
            console.print(finding_table)
            
            # Show raw output in verbose mode (with special handling for Mythril)
            if verbose and raw_output:
                console.print("\n[bold]Raw Output Preview:[/bold]")
                
                # For Mythril specifically, handle the duplicate sections
                if tool_name.lower() == "mythril":
                    # Split the raw output by sections and show only unique sections
                    sections = []
                    current_section = ""
                    for line in raw_output.split('\n'):
                        if line.startswith('===') and current_section:
                            sections.append(current_section)
                            current_section = line + '\n'
                        else:
                            current_section += line + '\n'
                    
                    if current_section:
                        sections.append(current_section)
                    
                    # Create fingerprints for sections to identify duplicates
                    section_fingerprints = set()
                    unique_sections = []
                    
                    for section in sections:
                        # Simple fingerprint from the first line and any line with "vulnerability"
                        fingerprint_lines = []
                        for line in section.split('\n')[:10]:
                            if line.startswith('===') or 'vulnerability' in line.lower():
                                fingerprint_lines.append(line)
                        
                        fingerprint = '\n'.join(fingerprint_lines)
                        
                        if fingerprint and fingerprint not in section_fingerprints:
                            section_fingerprints.add(fingerprint)
                            unique_sections.append(section)
                    
                    # Show a limited number of unique sections
                    sections_to_show = min(3, len(unique_sections))
                    for i in range(sections_to_show):
                        console.print(Panel(unique_sections[i][:500] + "...", 
                                           border_style="dim", title=f"Section {i+1}"))
                    
                    if len(unique_sections) > sections_to_show:
                        console.print(f"[dim]... and {len(unique_sections) - sections_to_show} more unique finding sections ...[/dim]")
                else:
                    # For other tools, show a limited amount of raw output
                    if len(raw_output) > 500:
                        console.print(Panel(raw_output[:500] + "...", border_style="dim"))
                    else:
                        console.print(Panel(raw_output, border_style="dim"))

if __name__ == "__main__":
    # Set up argument parser for command-line interface
    parser = argparse.ArgumentParser(description="Security Agent CLI")
    
    # Add subparsers for different operations
    subparsers = parser.add_subparsers(dest="operation", help="Operation to perform")
    
    # Scan operation - using the new SecurityAgent
    scan_parser = subparsers.add_parser("scan", help="Run a security scan on a target")
    scan_parser.add_argument("target", nargs='+', help="Target(s) to scan (URLs, files, directories, or GitHub repositories)")
    scan_parser.add_argument("--format", choices=["json", "markdown"], default="json", 
                            help="Output format (default: json)")
    scan_parser.add_argument("--output-file", help="File to save the output to")
    scan_parser.add_argument("--repo", action="store_true", help="Treat target as a GitHub repository URL")
    scan_parser.add_argument("--token", help="GitHub personal access token for private repositories")
    scan_parser.add_argument("--recursive", "-r", action="store_true", help="Scan directories recursively")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show verbose output including tool details")
    
    # Legacy run operation using the old orchestrator
    run_parser = subparsers.add_parser("run", help="Run the legacy security agent on a URL")
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
        console.print("[bold red]Warning:[/bold red] OPENAI_API_KEY not found in environment variables.")
        console.print("Please set your API key in the .env file.")
    
    # Process based on operation
    if args.operation == "scan":
        # Print header banner
        console.print("\n" + "=" * 80, style="blue")
        console.print("SECURITY AI AGENT SCAN".center(80), style="bold blue")
        console.print("=" * 80, style="blue")
        
        # Use the new SecurityAgent
        security_agent = SecurityAgent()
        
        # Configure logging based on verbose flag
        if args.verbose:
            import logging
            from backend.utils.helpers import get_logger
            logger = get_logger('security_agent')
            logger.setLevel(logging.DEBUG)
            console.print("\n[yellow]Verbose mode enabled - showing detailed execution logs[/yellow]")
        
        # Handle different scan types
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            scan_task = progress.add_task("Running security scan...", total=None)
            
            if args.repo:
                # Handle GitHub repository scanning
                repo_url = args.target[0]  # Use first target as repo URL
                console.print(f"\n[bold]Running Security Scan on GitHub Repository:[/bold] [cyan]{repo_url}[/cyan]")
                results = security_agent.scan_github_repo(repo_url, output_format=args.format, github_token=args.token)
            elif len(args.target) > 1:
                # Handle multiple file scanning
                console.print(f"\n[bold]Running Security Scan on[/bold] [cyan]{len(args.target)}[/cyan] [bold]files/URLs[/bold]")
                results = security_agent.scan_multiple(args.target, output_format=args.format, recursive=args.recursive)
            else:
                # Handle single target scanning
                target = args.target[0]
                console.print(f"\n[bold]Running Security Scan on:[/bold] [cyan]{target}[/cyan]")
                if args.recursive and os.path.isdir(target):
                    console.print(f"[yellow]Recursive scanning enabled for directory:[/yellow] {target}")
                results = security_agent.run(target, output_format=args.format, recursive=args.recursive)
            
            # Mark the task as complete
            progress.update(scan_task, completed=True)
        
        # Process scan results
        if results.get('status') == 'error':
            console.print(f"\n[bold red]Error:[/bold red] {results.get('error')}")
        else:
            # Display colorful, organized results
            display_scan_results(results)
            
            # If verbose, show detailed tool results
            if args.verbose:
                display_tool_results(results, verbose=True)
            
            # Save output to file if requested
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    f.write(results.get('formatted_output', json.dumps(results, indent=2)))
                console.print(f"\n[green]Full results saved to[/green] [cyan]{args.output_file}[/cyan]")
            else:
                console.print("\n[dim]Run with --output-file to save full results to a file[/dim]")
    
    elif args.operation == "run":
        # Print header banner
        console.print("\n" + "=" * 80, style="blue")
        console.print("LEGACY SECURITY AGENT".center(80), style="bold blue")
        console.print("=" * 80, style="blue")
        
        # Initialize the knowledge base (legacy mode)
        kb = SecurityKnowledgeBase()
        
        # Load sample data if requested
        if args.sample_data:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]Loading sample data...[/bold blue]"),
                console=console
            ) as progress:
                task = progress.add_task("Loading", total=None)
                populate_sample_data(kb)
                progress.update(task, completed=True)
            console.print("[green]Sample data loaded successfully![/green]")
        
        # Import orchestrator only when needed (legacy mode)
        from backend.core.orchestrator import SecurityAgentOrchestrator
        
        # Create the agent orchestrator
        orchestrator = SecurityAgentOrchestrator(kb)
        
        # Run analysis on the provided URL
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Analyzing {task.fields[url]}...[/bold blue]"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Analyzing", total=None, url=args.url)
            result = orchestrator.run(args.url)
            progress.update(task, completed=True)
        
        # Display results
        console.print(Panel(f"[bold]URL:[/bold] {args.url}", title="Security Analysis Results", style="blue"))
        
        if result.get('error'):
            console.print(f"[bold red]Error:[/bold red] {result.get('error')}")
        else:
            # Create a table for scan results
            console.print("\n[bold]Scan Results:[/bold]")
            for scan_type, data in result.get('scan_results', {}).items():
                scan_table = Table(title=scan_type.upper(), box=box.SIMPLE)
                scan_table.add_column("Property", style="cyan")
                scan_table.add_column("Value", style="green")
                
                for key, value in data.items():
                    scan_table.add_row(key, str(value))
                
                console.print(scan_table)
            
            # Create a table for vulnerabilities
            if result.get('vulnerabilities'):
                vuln_table = Table(title="Vulnerabilities", box=box.ROUNDED)
                vuln_table.add_column("Type", style="yellow")
                vuln_table.add_column("Description", style="cyan")
                
                for vuln in result.get('vulnerabilities', []):
                    vuln_table.add_row(vuln['type'], vuln['description'])
                
                console.print(vuln_table)
            else:
                console.print("[green]No vulnerabilities found.[/green]")
    
    elif args.operation == "load-cve":
        # Print header banner
        console.print("\n" + "=" * 80, style="blue")
        console.print("CVE DATA LOADER".center(80), style="bold blue")
        console.print("=" * 80, style="blue")
        
        # Initialize the knowledge base
        kb = SecurityKnowledgeBase()
        
        # Load CVE data based on provided arguments
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Loading CVE data...[/bold blue]"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Loading CVEs", total=None)
            load_cve_data(
                kb,
                cve_id=args.id,
                keyword=args.keyword,
                max_results=args.max_results,
                load_smart_contracts=args.smart_contracts
            )
            progress.update(task, completed=True)
        
        console.print("\n[bold green]CVE data loaded into knowledge base successfully.[/bold green]")
        console.print("\nYou can now run the agent with: [cyan]python main.py scan <target>[/cyan]")
    
    else:
        # No operation specified, show help with nice formatting
        console.print("\n[bold blue]Security AI Agent CLI[/bold blue]")
        console.print("[yellow]Please specify an operation:[/yellow] scan, run, or load-cve")
        console.print("\nExamples:")
        console.print("  [cyan]python main.py scan example.com[/cyan] - Scan a website")
        console.print("  [cyan]python main.py scan Contract.sol[/cyan] - Scan a Solidity contract")
        console.print("  [cyan]python main.py scan --repo https://github.com/user/repo[/cyan] - Scan a GitHub repository")
        console.print("  [cyan]python main.py load-cve --keyword \"smart contract\"[/cyan] - Load CVEs for smart contracts")
        console.print("\nFor more information, run: [cyan]python main.py -h[/cyan]")
        parser.print_help()