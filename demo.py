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
import logging
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from rich import box
from rich.logging import RichHandler

# Load environment variables from .env file
load_dotenv()

# Configure rich logging
logging.basicConfig(
    level=logging.getLevelName(os.environ.get("LOG_LEVEL", "INFO")),
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)

log = logging.getLogger("rich")

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

def display_tool_results(tool_results):
    """Display detailed tool execution results"""
    console.print("\n[bold blue]Detailed Tool Execution Results[/bold blue]")

    for tool_result in tool_results:
        tool_name = tool_result.get('tool_name', 'Unknown')
        status = tool_result.get('status', 'Unknown')

        # Determine status color
        status_color = "green" if status == "success" else "red"

        console.print(f"\n[bold]Tool:[/bold] {tool_name}")
        console.print(f"[bold]Status:[/bold] [{status_color}]{status}[/{status_color}]")
        console.print(f"[bold]Command:[/bold] {tool_result.get('command_executed', 'N/A')}")
        console.print(f"[bold]Execution Time:[/bold] {tool_result.get('execution_time', 0):.2f} seconds")

        # Display findings
        findings = tool_result.get('findings', [])
        if findings:
            console.print(f"\n[bold]Findings ({len(findings)}):[/bold]")

            findings_table = Table(box=box.SIMPLE)
            findings_table.add_column("ID", style="cyan")
            findings_table.add_column("Name", style="blue")
            findings_table.add_column("Severity", style="magenta")
            findings_table.add_column("Location", style="green")

            for finding in findings:
                severity = finding.get('severity', 'Unknown')
                severity_color = "green"
                if severity.lower() == "high":
                    severity_color = "orange3"
                elif severity.lower() == "critical":
                    severity_color = "red"
                elif severity.lower() == "medium":
                    severity_color = "yellow"

                findings_table.add_row(
                    finding.get('id', 'Unknown'),
                    finding.get('name', 'Unknown'),
                    f"[{severity_color}]{severity}[/{severity_color}]",
                    finding.get('location', 'Unknown')
                )

            console.print(findings_table)

        # Display raw output sample
        raw_output = tool_result.get('raw_output', '')
        if raw_output:
            console.print("\n[bold]Raw Output Sample:[/bold]")
            console.print(Panel(raw_output[:500] + "..." if len(raw_output) > 500 else raw_output,
                               width=100, expand=False))

def display_ai_analysis_results(scan_results):
    """Display AI-based code analysis results"""
    if 'ai_analysis' not in scan_results:
        return

    ai_analysis = scan_results.get('ai_analysis', {})
    findings = ai_analysis.get('findings', [])

    if not findings:
        return

    console.print("\n[bold magenta]🤖 AI Smart Contract Analysis Results[/bold magenta]")
    console.print(f"Based on knowledge from past audit reports, the AI identified {len(findings)} potential vulnerabilities.")

    findings_table = Table(box=box.SIMPLE)
    findings_table.add_column("Type", style="cyan")
    findings_table.add_column("Severity", style="magenta")
    findings_table.add_column("Description", style="blue", max_width=60)
    findings_table.add_column("Location", style="green")

    for finding in findings:
        severity = finding.get('severity', 'Unknown')
        severity_color = "green"
        if severity.lower() == "high":
            severity_color = "orange3"
        elif severity.lower() == "critical":
            severity_color = "red"
        elif severity.lower() == "medium":
            severity_color = "yellow"

        description = finding.get('description', 'Unknown')
        if len(description) > 60:
            description = description[:57] + "..."

        findings_table.add_row(
            finding.get('type', 'Unknown'),
            f"[{severity_color}]{severity}[/{severity_color}]",
            description,
            finding.get('location', 'Unknown')
        )

    console.print(findings_table)

    # Display sample recommendation
    if findings and 'recommendation' in findings[0]:
        console.print("\n[bold]Sample Recommendation:[/bold]")
        console.print(Panel(findings[0]['recommendation'][:500] + "..." if len(findings[0]['recommendation']) > 500 else findings[0]['recommendation'],
                           width=100, expand=False))

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

    # Display AI analysis results
    if results.get('scan_results'):
        display_ai_analysis_results(results.get('scan_results', {}))

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

    # Display detailed tool results if available
    if results.get('scan_results', {}).get('tool_results', []):
        display_tool_results(results.get('scan_results', {}).get('tool_results', []))

    console.print("\n[bold]Note:[/bold] This is a demo with simulated scan results.")

def main():
    """Main function for the demo"""
    parser = argparse.ArgumentParser(description="Security Agent Demo")
    parser.add_argument("target", nargs="?", help="Target to scan (URL or Solidity contract)")
    parser.add_argument("--output", "-o", help="Output file for full results")
    parser.add_argument("--format", "-f", choices=["json", "markdown"], default="json",
                       help="Output format (default: json)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show verbose output including tool details")

    args = parser.parse_args()

    print_banner()

    # Check environment and data directories
    data_dir = os.environ.get("DATA_DIR", "security_agent/data")
    log.info(f"Using data directory: {data_dir}")

    audit_reports_dir = os.path.join(data_dir, "sources/audit_reports")
    if os.path.exists(audit_reports_dir):
        log.info(f"Audit reports directory: {audit_reports_dir}")
        index_file = os.path.join(audit_reports_dir, "index.json")
        if os.path.exists(index_file):
            log.info(f"Found audit reports index: {index_file}")
        else:
            log.warning(f"Audit reports index not found: {index_file}")
    else:
        log.warning(f"Audit reports directory not found: {audit_reports_dir}")

    if not check_api_key():
        return 1

    if not args.target:
        console.print("[bold yellow]Please specify a target to scan.[/bold yellow]")
        console.print("Example: python demo.py https://example.com")
        console.print("Example: python demo.py path/to/contract.sol")
        return 1

    # Set logging level based on verbose flag
    if args.verbose:
        log.setLevel(logging.DEBUG)
        console.print("[bold green]Verbose mode enabled. Showing detailed logs.[/bold green]\n")

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