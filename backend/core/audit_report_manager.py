import os
import json
from pathlib import Path
from typing import List, Dict, Optional
import PyPDF2
from datetime import datetime

class AuditReportManager:
    def __init__(self, reports_dir: str = "security_agent/data/sources/audit_reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.reports_index = self.reports_dir / "index.json"
        self._load_index()

    def _load_index(self):
        """Load the index of audit reports."""
        if self.reports_index.exists():
            with open(self.reports_index, 'r') as f:
                self.index = json.load(f)
        else:
            self.index = {"reports": []}
            self._save_index()

    def _save_index(self):
        """Save the index of audit reports."""
        with open(self.reports_index, 'w') as f:
            json.dump(self.index, f, indent=2)

    def add_report(self, contract_name: str, report_path: str, findings: List[Dict]):
        """Add a new audit report to the index."""
        report_info = {
            "contract_name": contract_name,
            "report_path": report_path,
            "findings": findings,
            "timestamp": datetime.now().isoformat()
        }
        self.index["reports"].append(report_info)
        self._save_index()

    def get_relevant_reports(self, contract_name: str) -> List[Dict]:
        """Get relevant audit reports for a specific contract."""
        relevant_reports = []
        for report in self.index["reports"]:
            if contract_name.lower() in report["contract_name"].lower():
                relevant_reports.append(report)
        return relevant_reports

    def extract_findings_from_pdf(self, pdf_path: str) -> List[Dict]:
        """Extract findings from a PDF report."""
        findings = []
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                text = ""
                for page in pdf_reader.pages:
                    text += page.extract_text()

                # Basic parsing of findings (can be enhanced based on PDF structure)
                # This is a simple implementation - you might want to enhance this
                # based on your specific PDF format
                sections = text.split("Finding")
                for section in sections[1:]:  # Skip the first split as it's usually header
                    if "Severity:" in section and "Description:" in section:
                        finding = {
                            "description": "",
                            "severity": "",
                            "location": "",
                            "recommendation": ""
                        }

                        # Extract severity
                        if "Severity:" in section:
                            severity_start = section.find("Severity:") + len("Severity:")
                            severity_end = section.find("\n", severity_start)
                            finding["severity"] = section[severity_start:severity_end].strip()

                        # Extract description
                        if "Description:" in section:
                            desc_start = section.find("Description:") + len("Description:")
                            desc_end = section.find("\n\n", desc_start)
                            finding["description"] = section[desc_start:desc_end].strip()

                        findings.append(finding)
        except Exception as e:
            print(f"Error extracting findings from PDF: {e}")

        return findings

    def analyze_contract_with_historical_data(self, contract_code: str, contract_name: str) -> List[Dict]:
        """Analyze a contract using historical audit data."""
        relevant_reports = self.get_relevant_reports(contract_name)
        historical_findings = []

        for report in relevant_reports:
            if os.path.exists(report["report_path"]):
                findings = self.extract_findings_from_pdf(report["report_path"])
                historical_findings.extend(findings)

        return historical_findings