"""
Result Aggregator module for combining and deduplicating scan results.
"""
from typing import Dict, List, Optional, Any, Union
import json
from datetime import datetime
import itertools
import logging
import hashlib
from collections import defaultdict

# Import helpers
from backend.utils.helpers import get_logger

# Get logger
logger = get_logger('security_agent')

class ResultAggregator:
    def __init__(self):
        """Initialize ResultAggregator."""
        logger.info("Initializing ResultAggregator")
    
    def aggregate_results(self, scan_results: Dict, cve_info: Union[Dict, str, Any], ai_analysis_findings: Union[Dict, List, Any] = None) -> Dict:
        """
        Aggregate and deduplicate results from multiple sources.

        Args:
            scan_results: Results from security tools
            cve_info: Information from CVE database
            ai_analysis_findings: Findings from AI-based code analysis (optional)

        Returns:
            Dictionary containing aggregated results
        """
        logger.info(f"Aggregating results for scan {scan_results.get('scan_id')}")
        
        # Ensure cve_info is a dictionary to prevent attribute errors
        if not isinstance(cve_info, dict):
            logger.warning(f"Expected dict for cve_info but got {type(cve_info)}. Converting to empty dict.")
            cve_info = {}
        
        # Ensure ai_analysis_findings is a dictionary
        if ai_analysis_findings is None:
            ai_analysis_findings = {}
        elif not isinstance(ai_analysis_findings, dict):
            logger.warning(f"Expected dict for ai_analysis_findings but got {type(ai_analysis_findings)}. Converting to empty dict.")
            ai_analysis_findings = {}
        
        # Copy scan metadata
        aggregated_results = {
            "scan_id": scan_results.get("scan_id", ""),
            "timestamp": scan_results.get("timestamp", ""),
            "target": scan_results.get("target", ""),
            "input_type": scan_results.get("input_type", ""),
            "is_multiple": scan_results.get("is_multiple", False),
            "execution_time": scan_results.get("execution_time", 0),
            "findings_by_severity": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            },
            "stats": {
                "total_findings": 0,
                "total_unique_findings": 0,
                "findings_by_severity_count": {
                    "critical": 0,
                    "high": 0, 
                    "medium": 0,
                    "low": 0,
                    "info": 0
                },
                "findings_by_tool": {},
                "duplicates_removed": 0
            }
        }
        
        # If multiple files were scanned, include file list
        if scan_results.get("is_multiple") and scan_results.get("files"):
            aggregated_results["files"] = scan_results.get("files")
        
        # Extract all findings
        all_findings = []
        for tool_result in scan_results.get("tool_results", []):
            tool_name = tool_result.get("tool_name", "unknown")
            findings = tool_result.get("findings", [])
            
            # Initialize stats for this tool
            aggregated_results["stats"]["findings_by_tool"][tool_name] = {
                "total": len(findings),
                "unique": 0,
                "by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            }
            
            # Add tool name to each finding
            for finding in findings:
                finding["tool"] = tool_name
                all_findings.append(finding)
        
        # Add AI analysis findings if available
        if ai_analysis_findings and ai_analysis_findings.get("findings"):
            ai_findings = ai_analysis_findings.get("findings", [])
            # Add AI tool identifier to each finding
            for finding in ai_findings:
                finding["tool"] = "AI Analysis"
                all_findings.append(finding)
            
            # Add stats for AI analysis
            aggregated_results["stats"]["findings_by_tool"]["AI Analysis"] = {
                "total": len(ai_findings),
                "unique": 0,
                "by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0
                }
            }
        
        # Total raw findings before deduplication
        total_raw_findings = len(all_findings)
        aggregated_results["stats"]["total_raw_findings"] = total_raw_findings
        
        # Deduplicate findings
        unique_findings, duplicates_info = self._deduplicate_findings(all_findings)
        
        aggregated_results["stats"]["total_findings"] = total_raw_findings
        aggregated_results["stats"]["total_unique_findings"] = len(unique_findings)
        aggregated_results["stats"]["duplicates_removed"] = duplicates_info["total_duplicates"]
        aggregated_results["stats"]["duplicate_groups"] = duplicates_info["duplicate_groups"]
        
        # Categorize findings by severity
        for finding in unique_findings:
            severity = finding.get("severity", "").lower()
            if severity not in aggregated_results["findings_by_severity"]:
                severity = "info"  # Default to info if severity is unknown
            
            # Add to the appropriate severity category
            aggregated_results["findings_by_severity"][severity].append(finding)
            
            # Update severity count
            aggregated_results["stats"]["findings_by_severity_count"][severity] += 1
            
            # Update tool-specific stats
            tool_name = finding.get("tool", "unknown")
            if tool_name in aggregated_results["stats"]["findings_by_tool"]:
                aggregated_results["stats"]["findings_by_tool"][tool_name]["unique"] += 1
                aggregated_results["stats"]["findings_by_tool"][tool_name]["by_severity"][severity] += 1
        
        # Map findings to CVE IDs when possible
        mapped_findings = self._map_findings_to_cves(unique_findings, cve_info)
        
        # Group findings by severity
        grouped_findings = self._group_findings_by_severity(mapped_findings)
        
        # Create aggregated result
        aggregated_result = {
            "scan_id": scan_results.get('scan_id'),
            "timestamp": datetime.now().isoformat(),
            "target": scan_results.get('target'),
            "input_type": scan_results.get('input_type'),
            "total_findings": len(mapped_findings),
            "findings_by_severity": grouped_findings,
            "findings": mapped_findings,
            "cves": cve_info.get('cves', []),
            "execution_time": scan_results.get('execution_time', 0),
            "tools_used": [tool.get('tool_name') for tool in scan_results.get('tool_results', [])],
            "stats": aggregated_results["stats"]
        }
        
        return aggregated_result
    
    def export_to_json(self, aggregated_results: Dict) -> str:
        """
        Export aggregated results to JSON format.
        
        Args:
            aggregated_results: Dictionary containing aggregated results
            
        Returns:
            JSON string of the aggregated results
        """
        # Create a clean copy of the results with all relevant information
        export_data = {
            "scan_id": aggregated_results.get('scan_id'),
            "timestamp": aggregated_results.get('timestamp'),
            "target": aggregated_results.get('target'),
            "input_type": aggregated_results.get('input_type'),
            "total_findings": aggregated_results.get('total_findings'),
            "findings_by_severity": aggregated_results.get('findings_by_severity', {}),
            "findings": aggregated_results.get('findings', []),
            "cves": aggregated_results.get('cves', []),
            "execution_time": aggregated_results.get('execution_time', 0),
            "tools_used": aggregated_results.get('tools_used', []),
            "stats": aggregated_results.get('stats', {})
        }
        
        # Include deduplication statistics if available
        if 'deduplication_stats' in aggregated_results:
            export_data["deduplication_stats"] = aggregated_results.get('deduplication_stats')
        
        return json.dumps(export_data, indent=2)
    
    def export_to_markdown(self, aggregated_results: Dict) -> str:
        """
        Export aggregated results to Markdown format.
        
        Args:
            aggregated_results: Dictionary containing aggregated results
            
        Returns:
            Markdown string of the aggregated results
        """
        markdown = f"# Security Scan Results\n\n"
        markdown += f"**Scan ID**: {aggregated_results.get('scan_id')}\n"
        markdown += f"**Target**: {aggregated_results.get('target')}\n"
        markdown += f"**Scan Date**: {aggregated_results.get('timestamp')}\n"
        markdown += f"**Total Findings**: {aggregated_results.get('total_findings')}\n\n"
        
        # Add deduplication stats if available
        if 'deduplication_stats' in aggregated_results:
            stats = aggregated_results.get('deduplication_stats')
            markdown += "## Deduplication Statistics\n\n"
            markdown += f"- **Raw Findings**: {stats.get('total_raw_findings', 0)}\n"
            markdown += f"- **Unique Findings**: {aggregated_results.get('total_findings', 0)}\n"
            markdown += f"- **Duplicates Removed**: {stats.get('duplicates_removed', 0)}\n"
            markdown += f"- **Deduplication Ratio**: {stats.get('deduplication_ratio', 0)}%\n\n"
        
        # Add severity summary
        markdown += "## Summary by Severity\n\n"
        for severity, count in aggregated_results.get('findings_by_severity', {}).items():
            markdown += f"- **{severity}**: {count} findings\n"
        
        # Add findings
        markdown += "\n## Detailed Findings\n\n"
        for i, finding in enumerate(aggregated_results.get('findings', []), 1):
            markdown += f"### {i}. {finding.get('name')}\n\n"
            markdown += f"**Severity**: {finding.get('severity')}\n"
            markdown += f"**Description**: {finding.get('description')}\n"
            
            if 'cve_id' in finding:
                markdown += f"**CVE ID**: {finding.get('cve_id')}\n"
                
            markdown += f"**Location**: {finding.get('location')}\n"
            
            if 'source_tool' in finding:
                markdown += f"**Source Tool**: {finding.get('source_tool')}\n"
            elif 'source_tools' in finding:
                markdown += f"**Source Tools**: {', '.join(finding.get('source_tools'))}\n"
            
            if 'evidence' in finding:
                markdown += f"**Evidence**:\n```\n{finding.get('evidence')}\n```\n"
                
            if 'mitigation' in finding:
                markdown += f"**Mitigation**: {finding.get('mitigation')}\n"
            
            if 'related_ids' in finding and finding.get('related_ids'):
                markdown += f"**Related IDs**: {', '.join(finding.get('related_ids'))}\n"
                
            markdown += "\n"
        
        # Add related CVEs
        if aggregated_results.get('cves'):
            markdown += "## Related CVEs\n\n"
            for cve_id in aggregated_results.get('cves', []):
                markdown += f"- {cve_id}\n"
        
        # Add tools used
        markdown += "\n## Tools Used\n\n"
        for tool in aggregated_results.get('tools_used', []):
            markdown += f"- {tool}\n"
            
        return markdown
    
    def _deduplicate_findings(self, findings: List[Dict]) -> tuple:
        """
        Deduplicate findings based on key attributes.
        
        Args:
            findings: List of findings to deduplicate
            
        Returns:
            List of deduplicated findings and info about duplicates
        """
        unique_findings = []
        seen_fingerprints = set()
        duplicates_by_fingerprint = defaultdict(list)
        
        logger.info(f"Deduplicating findings: {len(findings)} total raw findings")
        
        for finding in findings:
            # Generate a fingerprint for the finding
            fingerprint = self._generate_finding_fingerprint(finding)
            
            if fingerprint in seen_fingerprints:
                # This is a duplicate
                duplicates_by_fingerprint[fingerprint].append(finding)
                continue
            
            # New unique finding
            seen_fingerprints.add(fingerprint)
            unique_findings.append(finding)
        
        # Count total duplicates and groups
        total_duplicates = len(findings) - len(unique_findings)
        duplicate_groups = len([fp for fp, dups in duplicates_by_fingerprint.items() if dups])
        
        # Log deduplication results
        logger.info(f"Deduplication complete: {len(unique_findings)} unique findings, {total_duplicates} duplicates removed")
        logger.info(f"Found {duplicate_groups} groups of duplicate findings")
        
        # Log details about each duplicate group
        for fingerprint, dups in duplicates_by_fingerprint.items():
            if dups:
                sample = dups[0]
                logger.debug(f"Duplicate group: {len(dups) + 1} instances of '{sample.get('name')}' severity: {sample.get('severity')}, location: {sample.get('location')}")
        
        duplicates_info = {
            "total_duplicates": total_duplicates,
            "duplicate_groups": duplicate_groups,
            "duplicates_by_fingerprint": {k: len(v) for k, v in duplicates_by_fingerprint.items()}
        }
        
        return unique_findings, duplicates_info
    
    def _generate_finding_fingerprint(self, finding: Dict) -> str:
        """
        Generate a unique fingerprint for a finding based on its attributes.
        
        Args:
            finding: The finding dictionary
            
        Returns:
            A string fingerprint
        """
        # Extract key attributes for fingerprinting
        # Use a combination of attributes that uniquely identify a finding
        key_attrs = {
            "name": finding.get("name", ""),
            "location": finding.get("location", ""),
            "description": finding.get("description", ""),
            "severity": finding.get("severity", ""),
            # Don't use tool name as we want to deduplicate across tools
        }
        
        # Generate a stable representation of the key attributes
        fingerprint_data = json.dumps(key_attrs, sort_keys=True).encode('utf-8')
        
        # Create a hash of the data
        return hashlib.md5(fingerprint_data).hexdigest()
    
    def _map_findings_to_cves(self, findings: List[Dict], cve_info: Dict) -> List[Dict]:
        """
        Map findings to CVE IDs when possible.
        
        Args:
            findings: List of findings to map
            cve_info: Dictionary containing CVE information
            
        Returns:
            List of findings with CVE information added where applicable
        """
        # If no CVE info provided, return findings as is
        if not cve_info or not isinstance(cve_info, dict) or not cve_info.get('cves'):
            return findings
            
        # Try to map findings to CVEs based on descriptions and patterns
        mapped_findings = []
        
        for finding in findings:
            # Copy the finding to avoid modifying the original
            mapped_finding = finding.copy()
            
            # Look for CVE matches
            if cve_info.get('cves'):
                for cve in cve_info.get('cves', []):
                    # Simple matching based on keywords
                    if cve.get('description') and finding.get('description'):
                        if any(keyword.lower() in finding.get('description').lower() for keyword in cve.get('keywords', [])):
                            mapped_finding['cve_id'] = cve.get('id')
                            mapped_finding['cve_description'] = cve.get('description')
                            break
            
            mapped_findings.append(mapped_finding)
            
        return mapped_findings

    def _group_findings_by_severity(self, findings: List[Dict]) -> Dict:
        """
        Group findings by severity level.
        
        Args:
            findings: List of findings to group
            
        Returns:
            Dictionary with findings grouped by severity
        """
        grouped = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for finding in findings:
            severity = finding.get('severity', '').lower()
            if severity not in grouped:
                severity = 'info'  # Default to info if severity is unknown
                
            grouped[severity].append(finding)
            
        return grouped

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