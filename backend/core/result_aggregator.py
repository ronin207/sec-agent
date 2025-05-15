"""
Result Aggregator module for combining and deduplicating scan results.
"""
from typing import Dict, List, Any
import json
from datetime import datetime

class ResultAggregator:
    def __init__(self):
        """Initialize the Result Aggregator."""
        pass

    def aggregate_results(self, scan_results: Dict, cve_info: Dict, ai_analysis_findings: List[Dict] = None) -> Dict:
        """
        Aggregate and deduplicate results from multiple sources.

        Args:
            scan_results: Results from security tools
            cve_info: Information from CVE database
            ai_analysis_findings: Findings from AI-based code analysis

        Returns:
            Dictionary containing aggregated results
        """
        aggregated = {
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "summary": {
                "total_findings": 0,
                "severity_counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            }
        }

        # Process tool scan results
        for tool_name, results in scan_results.items():
            if tool_name == 'ai_analysis':
                continue  # Skip AI analysis as it's processed separately

            if isinstance(results, dict) and 'findings' in results:
                for finding in results['findings']:
                    self._add_finding(aggregated, finding, source=tool_name)

        # Process CVE information
        if cve_info and 'vulnerabilities' in cve_info:
            for vuln in cve_info['vulnerabilities']:
                finding = {
                    'type': 'cve',
                    'severity': vuln.get('severity', 'medium'),
                    'description': vuln.get('description', ''),
                    'cve_id': vuln.get('id', ''),
                    'source': 'cve_database'
                }
                self._add_finding(aggregated, finding)

        # Process AI analysis findings
        if ai_analysis_findings:
            for finding in ai_analysis_findings:
                finding['source'] = 'ai_analysis'
                self._add_finding(aggregated, finding)

        # Update summary
        aggregated['summary']['total_findings'] = len(aggregated['findings'])

        return aggregated

    def _add_finding(self, aggregated: Dict, finding: Dict, source: str = None):
        """
        Add a finding to the aggregated results, handling deduplication.

        Args:
            aggregated: The aggregated results dictionary
            finding: The finding to add
            source: The source of the finding
        """
        # Normalize severity
        severity = finding.get('severity', 'medium').lower()
        if severity not in aggregated['summary']['severity_counts']:
            severity = 'medium'

        # Create normalized finding
        normalized_finding = {
            'type': finding.get('type', 'unknown'),
            'severity': severity,
            'description': finding.get('description', ''),
            'source': source or finding.get('source', 'unknown'),
            'location': finding.get('location', ''),
            'recommendation': finding.get('recommendation', '')
        }

        # Check for duplicates
        is_duplicate = False
        for existing in aggregated['findings']:
            if (existing['description'] == normalized_finding['description'] and
                existing['severity'] == normalized_finding['severity']):
                is_duplicate = True
                break

        if not is_duplicate:
            aggregated['findings'].append(normalized_finding)
            aggregated['summary']['severity_counts'][severity] += 1

    def export_to_json(self, results: Dict) -> str:
        """
        Export results to JSON format.

        Args:
            results: Aggregated results dictionary

        Returns:
            JSON string of the results
        """
        return json.dumps(results, indent=2)

    def export_to_markdown(self, results: Dict) -> str:
        """
        Export results to Markdown format.

        Args:
            results: Aggregated results dictionary

        Returns:
            Markdown string of the results
        """
        markdown = f"# Security Assessment Report\n\n"
        markdown += f"Generated at: {results['timestamp']}\n\n"

        # Summary section
        markdown += "## Summary\n\n"
        markdown += f"Total Findings: {results['summary']['total_findings']}\n\n"
        markdown += "Severity Distribution:\n"
        for severity, count in results['summary']['severity_counts'].items():
            markdown += f"- {severity.title()}: {count}\n"
        markdown += "\n"

        # Findings section
        markdown += "## Detailed Findings\n\n"

        # Sort findings by severity (critical first, then high, medium, low, info)
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1, "unknown": 0}
        sorted_findings = sorted(
            results['findings'],
            key=lambda x: severity_order.get(x.get('severity', 'unknown').lower(), 0),
            reverse=True
        )

        # Group findings by source
        source_findings = {}
        for finding in sorted_findings:
            source = finding.get('source', 'unknown')
            if source not in source_findings:
                source_findings[source] = []
            source_findings[source].append(finding)

        # First present AI analysis findings if available
        if 'ai_analysis' in source_findings:
            markdown += "### 🤖 AI Smart Contract Analysis\n\n"
            markdown += "The following vulnerabilities were identified by AI analysis of the smart contract code using learned knowledge from past audit reports:\n\n"

            for finding in source_findings['ai_analysis']:
                markdown += f"#### {finding['severity'].title()} - {finding['type'].title()}\n\n"
                markdown += f"**Description**: {finding['description']}\n\n"
                if finding.get('location'):
                    markdown += f"**Location**: {finding['location']}\n\n"
                if finding.get('recommendation'):
                    markdown += f"**Recommendation**: {finding['recommendation']}\n\n"
                markdown += "---\n\n"

            # Remove AI findings from source_findings to avoid duplication
            del source_findings['ai_analysis']

        # Present remaining findings
        for source, findings in source_findings.items():
            markdown += f"### Findings from {source.title()}\n\n"

            for finding in findings:
                markdown += f"#### {finding['severity'].title()} - {finding.get('type', 'Issue').title()}\n\n"
                markdown += f"**Description**: {finding['description']}\n\n"
                if finding.get('location'):
                    markdown += f"**Location**: {finding['location']}\n\n"
                if finding.get('recommendation'):
                    markdown += f"**Recommendation**: {finding['recommendation']}\n\n"
                markdown += "---\n\n"

        return markdown