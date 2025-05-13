#!/usr/bin/env python3
"""
Demo script for the Security Agent.
This script provides a simple interface to demonstrate the functionality
of the Security AI Agent for vulnerability scanning.
"""
import os
import sys
import json
import argparse
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from rich import box

# Load environment variables from .env file
load_dotenv()

# Import the security agent
from backend.core.security_agent import SecurityAgent

# Initialize rich console
console = Console()

def print_banner():
    """Print a banner for the demo"""
    banner = """
    ╔═══════════════════════════════════════════════════╗
    ║                                                   ║
    ║   Security AI Agent - Vulnerability Scanner Demo  ║
    ║                                                   ║
    ╚═══════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")
    console.print("This demo showcases the functionality of the Security AI Agent.")
    console.print("It can scan websites and Solidity smart contracts for vulnerabilities.")
    console.print("\n")

def check_api_key():
    """Check if OpenAI API key is set"""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        console.print("[bold red]Error:[/bold red] OPENAI_API_KEY not found in environment variables.")
        console.print("Please set your API key in the .env file or as an environment variable.")
        console.print("Example: export OPENAI_API_KEY=your_api_key_here")
        return False
    return True

def display_results(results):
    """Display scan results in a nice format"""
    if results.get('status') == 'error':
        console.print(f"[bold red]Error:[/bold red] {results.get('error')}")
        return
    
    # Display basic information
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
    
    # Display summary from LLM
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
    
    console.print("\n[bold]Note:[/bold] This is a demo with simulated scan results.")

def main():
    """Main function for the demo"""
    parser = argparse.ArgumentParser(description="Security Agent Demo")
    parser.add_argument("target", nargs="?", help="Target to scan (URL or Solidity contract)")
    parser.add_argument("--output", "-o", help="Output file for full results")
    parser.add_argument("--format", "-f", choices=["json", "markdown"], default="json",
                       help="Output format (default: json)")
    
    args = parser.parse_args()
    
    print_banner()
    
    if not check_api_key():
        return 1
    
    if not args.target:
        console.print("[bold yellow]Please specify a target to scan.[/bold yellow]")
        console.print("Example: python demo.py https://example.com")
        console.print("Example: python demo.py path/to/contract.sol")
        return 1
    
    with console.status("[bold green]Initializing Security Agent...[/bold green]"):
        security_agent = SecurityAgent()
    
    console.print(f"\n[bold]Starting security scan for:[/bold] {args.target}")
    console.print("This process may take a few moments...\n")
    
    with console.status("[bold green]Running security scan...[/bold green]"):
        results = security_agent.run(args.target, output_format=args.format)
    
    display_results(results)
    
    # Save output to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write(results.get('formatted_output', json.dumps(results)))
        console.print(f"\n[bold green]Full results saved to:[/bold green] {args.output}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 