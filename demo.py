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
import time
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from rich import box
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

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

def display_tool_results(results, verbose=False):
    """
    Display detailed tool results.
    
    Args:
        results: Dictionary containing tool results
        verbose: Whether to display verbose output
    """
    print("\n" + "=" * 80)
    print("DETAILED TOOL RESULTS")
    print("=" * 80)
    
    for tool_result in results.get('tool_results', []):
        tool_name = tool_result.get('tool_name', 'Unknown')
        status = tool_result.get('status', 'unknown')
        execution_time = tool_result.get('execution_time', 0)
        raw_output = tool_result.get('raw_output', '')
        findings = tool_result.get('findings', [])
        
        print(f"\n\n{'-' * 40}")
        print(f"TOOL: {tool_name}")
        print(f"Status: {status}")
        print(f"Execution Time: {execution_time:.2f} seconds")
        
        # Group findings by ID to check for duplicates
        findings_by_id = {}
        for finding in findings:
            finding_id = finding.get('id', 'unknown')
            if finding_id not in findings_by_id:
                findings_by_id[finding_id] = []
            findings_by_id[finding_id].append(finding)
        
        # Print findings count information
        print(f"Total raw findings: {len(findings)}")
        print(f"Unique finding IDs: {len(findings_by_id)}")
        
        # Display findings in a compact format
        if findings:
            print("\nFindings:")
            
            # In non-verbose mode, we'll just show counts by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for finding in findings:
                severity = finding.get('severity', '').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Print severity summary
            for severity, count in severity_counts.items():
                if count > 0:
                    print(f"  {severity.upper()}: {count}")
            
            # In verbose mode, show more details about findings
            if verbose:
                # Limit to showing only unique findings
                shown_ids = set()
                print("\nDetailed findings (showing only unique entries):")
                
                for finding in findings:
                    finding_id = finding.get('id', 'unknown')
                    # Skip if we've already shown this ID
                    if finding_id in shown_ids:
                        continue
                    
                    shown_ids.add(finding_id)
                    name = finding.get('name', 'Unknown')
                    severity = finding.get('severity', 'Unknown')
                    location = finding.get('location', 'Unknown')
                    
                    # Count duplicates of this finding
                    duplicate_count = len(findings_by_id.get(finding_id, []))
                    
                    print(f"\n  ID: {finding_id}")
                    print(f"  Name: {name}")
                    print(f"  Severity: {severity}")
                    print(f"  Location: {location}")
                    
                    if duplicate_count > 1:
                        print(f"  [Appears {duplicate_count} times in raw output]")
                    
                    # Only show description in verbose mode and truncate if too long
                    description = finding.get('description', '')
                    if description:
                        if len(description) > 200:
                            print(f"  Description: {description[:200]}...")
                        else:
                            print(f"  Description: {description}")
        
        # Display raw output if verbose
        if verbose and raw_output:
            print("\nRaw Output Preview:")
            
            # For Mythril specifically, we need to handle the duplicate sections issue
            if tool_name.lower() == "mythril":
                # Split the raw output by sections and show only unique sections
                # A section typically starts with "===" and ends with a blank line
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
                    # Create a simple fingerprint by taking the first line and any line containing "vulnerability"
                    fingerprint_lines = []
                    for line in section.split('\n')[:10]:  # Only consider first 10 lines
                        if line.startswith('===') or 'vulnerability' in line.lower():
                            fingerprint_lines.append(line)
                    
                    fingerprint = '\n'.join(fingerprint_lines)
                    
                    if fingerprint and fingerprint not in section_fingerprints:
                        section_fingerprints.add(fingerprint)
                        unique_sections.append(section)
                
                # Show the first few unique sections and indicate if there are more
                sections_to_show = min(3, len(unique_sections))
                for i in range(sections_to_show):
                    print(f"\n{unique_sections[i][:500]}...")  # Show first 500 chars of each section
                
                if len(unique_sections) > sections_to_show:
                    print(f"\n... and {len(unique_sections) - sections_to_show} more unique finding sections ...")
            else:
                # For other tools, just show the first 500 characters
                if len(raw_output) > 500:
                    print(f"{raw_output[:500]}...")
                else:
                    print(raw_output)

def display_results(results):
    """Display scan results in a nice format"""
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
    
    # For multiple files, display per-file findings if available
    if results.get('is_multiple') and results.get('scan_results', {}).get('tool_results'):
        console.print("\n[bold blue]Per-File Findings Summary[/bold blue]")
        
        # Get all file results
        file_findings = {}
        
        for tool_result in results.get('scan_results', {}).get('tool_results', []):
            if 'file_results' in tool_result:
                for file_result in tool_result.get('file_results', []):
                    file_path = file_result.get('file', 'unknown')
                    
                    if file_path not in file_findings:
                        file_findings[file_path] = {
                            'total': 0,
                            'by_severity': {},
                            'findings': []
                        }
                    
                    # Count findings for this file
                    findings = file_result.get('findings', [])
                    file_findings[file_path]['total'] += len(findings)
                    
                    # Add findings
                    file_findings[file_path]['findings'].extend(findings)
                    
                    # Count by severity
                    for finding in findings:
                        severity = finding.get('severity', 'Unknown')
                        if severity not in file_findings[file_path]['by_severity']:
                            file_findings[file_path]['by_severity'][severity] = 0
                        file_findings[file_path]['by_severity'][severity] += 1
        
        # Create a table of files and their findings
        if file_findings:
            files_table = Table(title="File Findings", box=box.SIMPLE)
            files_table.add_column("File", style="cyan")
            files_table.add_column("Total", style="blue", justify="right")
            files_table.add_column("Critical", style="red", justify="right")
            files_table.add_column("High", style="orange3", justify="right")
            files_table.add_column("Medium", style="yellow", justify="right")
            files_table.add_column("Low", style="green", justify="right")
            files_table.add_column("Info", style="blue", justify="right")
            
            for file_path, data in file_findings.items():
                files_table.add_row(
                    os.path.basename(file_path),
                    str(data['total']),
                    str(data['by_severity'].get('Critical', 0)),
                    str(data['by_severity'].get('High', 0)),
                    str(data['by_severity'].get('Medium', 0)),
                    str(data['by_severity'].get('Low', 0)),
                    str(data['by_severity'].get('Info', 0))
                )
            
            console.print(files_table)
    
    # Display detailed tool results if available
    if results.get('scan_results', {}).get('tool_results', []):
        display_tool_results(results, verbose=True)
    
    console.print("\n[bold]Note:[/bold] This is a demo with simulated scan results.")

def main():
    """
    Main function to run the demo Security AI Agent.
    """
    parser = argparse.ArgumentParser(description='Security AI Agent Demo')
    parser.add_argument('target', help='Target to scan (URL, file path, or GitHub repository)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--repo', help='GitHub repository URL to scan')
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Welcome message
    print("\n" + "=" * 80)
    print("SECURITY AI AGENT".center(80))
    print("=" * 80)
    print("\nWelcome to the Security AI Agent!")
    print("This tool automates security vulnerability assessments using AI.")
    
    # Initialize the security agent
    agent = SecurityAgent()
    
    # Determine what we're scanning
    target = args.target
    if args.repo:
        target = args.repo
    
    start_time = time.time()
    
    # Run the security scan
    if args.repo:
        print(f"\nStarting security scan for GitHub repository: {args.repo}")
        print("This may take a few minutes...")
        # Use the new scan_github_repo method
        result = agent.scan_github_repo(args.repo)
    else:
        print(f"\nStarting security scan for: {target}")
        print("This may take a few minutes...")
        # Use the regular run method
        result = agent.run(target)
    
    # Display the results
    if result:
        execution_time = time.time() - start_time
        print(f"\nScan completed in {execution_time:.2f} seconds.")
        
        # Display deduplication statistics
        if "stats" in result:
            stats = result.get("stats", {})
            print("\n" + "=" * 80)
            print("DEDUPLICATION STATISTICS")
            print("=" * 80)
            print(f"Total raw findings: {stats.get('total_raw_findings', 0)}")
            print(f"Total unique findings: {stats.get('total_unique_findings', 0)}")
            print(f"Duplicates removed: {stats.get('duplicates_removed', 0)}")
            print(f"Duplicate groups: {stats.get('duplicate_groups', 0)}")
            
            # Show tool-specific statistics
            print("\nFindings by tool:")
            for tool, tool_stats in stats.get("findings_by_tool", {}).items():
                print(f"  {tool}: {tool_stats.get('total', 0)} raw, {tool_stats.get('unique', 0)} unique")
        
        # Display findings by severity
        if "findings_by_severity" in result:
            print("\n" + "=" * 80)
            print("FINDINGS BY SEVERITY")
            print("=" * 80)
            
            for severity in ["critical", "high", "medium", "low", "info"]:
                findings = result["findings_by_severity"][severity]
                if findings:
                    print(f"\n{severity.upper()} ({len(findings)}):")
                    for idx, finding in enumerate(findings, 1):
                        print(f"  {idx}. {finding.get('name')} - {finding.get('location')}")
        
        # Display summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(result.get("summary", "No summary available."))
        
        # Display detailed tool results if verbose
        if args.verbose:
            display_tool_results(result, verbose=args.verbose)
        
        # Display remediation suggestions
        if "remediation" in result:
            print("\n" + "=" * 80)
            print("REMEDIATION SUGGESTIONS")
            print("=" * 80)
            print(result.get("remediation", "No remediation suggestions available."))
        
        # Overall risk assessment
        print("\n" + "=" * 80)
        print("RISK ASSESSMENT")
        print("=" * 80)
        print(f"Overall Risk: {result.get('risk_assessment', 'Unknown')}")
        
        # If there are affected CVEs
        if "cves" in result and result["cves"]:
            print("\n" + "=" * 80)
            print("RELATED CVEs")
            print("=" * 80)
            for cve in result["cves"]:
                print(f"- {cve.get('id')}: {cve.get('description')}")
    else:
        print("\nScan failed or returned no results.")

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user.[/bold red]")
        sys.exit(1) 