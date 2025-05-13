"""
Result Aggregator module for the Security Agent.
Handles aggregation and deduplication of security scan results.
"""
from typing import Dict, List, Optional, Any
import json
from datetime import datetime
import itertools

# Import helpers
from backend.utils.helpers import get_logger

# Get logger
logger = get_logger('security_agent')

class ResultAggregator:
    """
    Aggregates and deduplicates results from different security tools.
    """
    
    def __init__(self):
        pass
    
    def aggregate_results(self, scan_results: Dict, cve_info: Dict) -> Dict:
        """
        Aggregate and deduplicate results from different security tools.
        
        Args:
            scan_results: Dictionary containing raw scan results
            cve_info: Dictionary containing CVE information and risk assessment
            
        Returns:
            Dictionary containing aggregated and deduplicated results
        """
        logger.info(f"Aggregating results for scan {scan_results.get('scan_id')}")
        
        # Extract vulnerabilities from all tool results
        all_findings = []
        for tool_result in scan_results.get('tool_results', []):
            findings = tool_result.get('findings', [])
            
            # Add tool information to each finding
            for finding in findings:
                finding['source_tool'] = tool_result.get('tool_name')
                finding['tool_id'] = tool_result.get('tool_id')
                all_findings.append(finding)
        
        # Deduplicate findings
        deduplicated_findings = self._deduplicate_findings(all_findings)
        
        # Map findings to CVE IDs when possible
        mapped_findings = self._map_findings_to_cves(deduplicated_findings, cve_info)
        
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
            "tools_used": [tool.get('tool_name') for tool in scan_results.get('tool_results', [])]
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
        return json.dumps(aggregated_results, indent=2)
    
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
            markdown += f"**Source Tool**: {finding.get('source_tool')}\n"
            
            if 'evidence' in finding:
                markdown += f"**Evidence**:\n```\n{finding.get('evidence')}\n```\n"
                
            if 'mitigation' in finding:
                markdown += f"**Mitigation**: {finding.get('mitigation')}\n"
                
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
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Deduplicate findings based on similarity.
        
        Args:
            findings: List of findings from all tools
            
        Returns:
            List of deduplicated findings
        """
        # Simplified deduplication based on finding name and location
        # In a real implementation, this would use more sophisticated comparison
        
        # Group findings by name
        findings_by_name = {}
        for finding in findings:
            name = finding.get('name', '').lower()
            
            if name not in findings_by_name:
                findings_by_name[name] = []
                
            findings_by_name[name].append(finding)
        
        # For each group, deduplicate by comparing locations
        deduplicated = []
        for name, group in findings_by_name.items():
            # If only one finding with this name, add it directly
            if len(group) == 1:
                deduplicated.append(group[0])
                continue
            
            # Group by location
            by_location = {}
            for finding in group:
                location = finding.get('location', '')
                
                if location not in by_location:
                    by_location[location] = []
                    
                by_location[location].append(finding)
            
            # For each location, take the finding with the highest severity
            for location, loc_findings in by_location.items():
                # Sort by severity (Critical > High > Medium > Low > Info)
                severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                sorted_findings = sorted(
                    loc_findings, 
                    key=lambda x: severity_order.get(x.get('severity', '').lower(), 0),
                    reverse=True
                )
                
                # Take the highest severity finding and merge any additional information
                merged = sorted_findings[0].copy()
                
                # Merge evidence and source tools
                evidence = set()
                source_tools = set()
                for f in sorted_findings:
                    if 'evidence' in f:
                        evidence.add(f['evidence'])
                    if 'source_tool' in f:
                        source_tools.add(f['source_tool'])
                
                if evidence:
                    merged['evidence'] = ' | '.join(evidence)
                if source_tools:
                    merged['source_tools'] = list(source_tools)
                    
                deduplicated.append(merged)
        
        return deduplicated
    
    def _map_findings_to_cves(self, findings: List[Dict], cve_info: Dict) -> List[Dict]:
        """
        Map findings to CVE IDs when possible.
        
        Args:
            findings: List of deduplicated findings
            cve_info: Dictionary containing CVE information and risk assessment
            
        Returns:
            List of findings with mapped CVE IDs
        """
        cve_ids = cve_info.get('cves', [])
        
        # For demo purposes, we'll match some findings with CVEs based on name
        for finding in findings:
            # Try to extract CVE ID from the finding name
            name = finding.get('name', '').lower()
            
            # Check if finding name contains a CVE ID
            if 'cve-' in name:
                # Extract the CVE ID using a simple approach
                parts = name.split('cve-')
                if len(parts) > 1:
                    cve_id = 'CVE-' + parts[1].split(')')[0].split(' ')[0]
                    finding['cve_id'] = cve_id
                    continue
            
            # Otherwise check for matches with known CVEs
            for cve_id in cve_ids:
                # For each risk in the CVE info
                for risk in cve_info.get('risks', []):
                    # If the finding name matches parts of the risk description
                    description = risk.get('description', '').lower()
                    if name in description or description in name:
                        finding['cve_id'] = cve_id
                        
                        # Add mitigation information if available
                        if 'mitigation' in risk and 'mitigation' not in finding:
                            finding['mitigation'] = risk['mitigation']
                        
                        break
        
        return findings
    
    def _group_findings_by_severity(self, findings: List[Dict]) -> Dict:
        """
        Group findings by severity.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary with counts by severity
        """
        severity_counts = {
            "Critical": 0,
            "High": 0, 
            "Medium": 0, 
            "Low": 0,
            "Info": 0
        }
        
        for finding in findings:
            severity = finding.get('severity', '').capitalize()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["Info"] += 1
        
        return severity_counts 