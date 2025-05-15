"""
Security Agent module for automating vulnerability assessments.
Main module that integrates all the components.
"""
from typing import Dict, List, Optional, Any
import os
import json
import time
from datetime import datetime

# Import all required components
from backend.core.input_handler import InputHandler
from backend.core.cve_knowledge_base import CVEKnowledgeQuery
from backend.core.tool_selector import SecurityToolSelector
from backend.core.scan_executor import ScanExecutor
from backend.core.result_aggregator import ResultAggregator
from backend.core.result_summarizer import ResultSummarizer
from backend.core.ai_audit_analyzer import AIAuditAnalyzer

# Import helpers
from backend.utils.helpers import get_logger

# Get logger
logger = get_logger('security_agent')

class SecurityAgent:
    """
    Main Security Agent class that orchestrates the entire vulnerability assessment process.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the Security Agent with all necessary components.

        Args:
            api_key: OpenAI API key (falls back to environment variable)
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")

        # Initialize all components
        self.input_handler = InputHandler()
        self.cve_knowledge_query = CVEKnowledgeQuery(api_key=self.api_key)
        self.tool_selector = SecurityToolSelector()
        self.scan_executor = ScanExecutor()
        self.result_aggregator = ResultAggregator()
        self.result_summarizer = ResultSummarizer(api_key=self.api_key)
        self.ai_audit_analyzer = AIAuditAnalyzer(api_key=self.api_key)

        logger.info("SecurityAgent initialized successfully")

    def run(self, user_input: str, output_format: str = "json") -> Dict:
        """
        Run the security agent on the provided input.

        Args:
            user_input: Either a website URL or a Solidity contract file/URL
            output_format: Format of the output ("json" or "markdown")

        Returns:
            Dictionary containing the assessment results
        """
        start_time = time.time()
        results = {
            "timestamp": datetime.now().isoformat(),
            "input": user_input,
            "status": "running",
            "execution_time": 0,
            "error": None
        }

        try:
            # Step 1: Validate and classify input
            logger.info(f"Validating input: {user_input}")
            input_result = self.input_handler.validate_and_classify(user_input)

            if input_result.get('type') == 'error':
                results['status'] = 'error'
                results['error'] = input_result.get('message')
                return results

            results['input_type'] = input_result.get('type')

            # Step 2: Query CVE knowledge base
            logger.info(f"Querying CVE knowledge base for {input_result.get('type')}")
            cve_info = self.cve_knowledge_query.query_by_input_type(
                input_result.get('type'),
                input_result.get('input')
            )

            # Step 3: Select appropriate security tools
            logger.info("Selecting security tools")
            selected_tools = self.tool_selector.select_tools(
                input_result.get('type'),
                cve_info
            )

            # Step 4: Execute security scans
            logger.info("Executing security scans")
            scan_results = self.scan_executor.execute_scans(
                input_result,
                selected_tools
            )

            # Step 5: Perform AI-based code analysis for smart contracts
            ai_analysis_findings = []
            logger.info("Performing AI-based smart contract analysis with learned knowledge")
            contract_name = os.path.basename(input_result.get('input'))

            # Load the code from the file
            try:
                with open(input_result.get('input'), 'r') as file:
                    contract_code = file.read()

                # Check if API key is available
                if not self.api_key:
                    logger.warning("OpenAI API key not available in security_agent, trying to get from environment")
                    self.api_key = os.environ.get("OPENAI_API_KEY")
                    if self.api_key:
                        logger.info("Successfully retrieved API key from environment")
                    else:
                        logger.error("Failed to get OpenAI API key from environment")

                # Update AIAuditAnalyzer with the API key
                self.ai_audit_analyzer.api_key = self.api_key

                # Log knowledge base size
                kb_size = len(self.ai_audit_analyzer.knowledge_base) if self.ai_audit_analyzer.knowledge_base else 0
                logger.info(f"AI Audit Analyzer knowledge base contains {kb_size} findings")

                # Analyze the code with AI
                logger.info(f"Analyzing {contract_name} with AI using knowledge from {kb_size} findings")
                ai_analysis_findings = self.ai_audit_analyzer.analyze_solidity_code(
                    contract_code,
                    contract_name
                )
                logger.info(f"AI Analysis completed - Found {len(ai_analysis_findings)} potential vulnerabilities")

                scan_results['ai_analysis'] = {
                    "tool_name": "AI Smart Contract Analyzer",
                    "status": "completed",
                    "findings": ai_analysis_findings
                }
            except Exception as e:
                logger.error(f"Error during AI analysis: {str(e)}")
                scan_results['ai_analysis'] = {
                    "tool_name": "AI Smart Contract Analyzer",
                    "status": "error",
                    "error_message": str(e),
                    "findings": []
                }

            # Step 6: Aggregate and deduplicate results
            logger.info("Aggregating scan results")
            aggregated_results = self.result_aggregator.aggregate_results(
                scan_results,
                cve_info,
                ai_analysis_findings
            )

            # Step 7: Generate summary
            logger.info("Generating result summary")
            summary = self.result_summarizer.generate_summary(aggregated_results)

            # Combine all results
            results['scan_results'] = scan_results
            results['aggregated_results'] = aggregated_results
            results['summary'] = summary
            results['status'] = 'completed'

            # Format output based on requested format
            if output_format.lower() == "markdown":
                results['formatted_output'] = self.result_aggregator.export_to_markdown(aggregated_results)
            else:
                results['formatted_output'] = self.result_aggregator.export_to_json(aggregated_results)

        except Exception as e:
            logger.error(f"Error in SecurityAgent.run: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)

        # Calculate execution time
        results['execution_time'] = time.time() - start_time

        return results

    def quick_scan(self, url: str) -> Dict:
        """
        Convenience method for quick website security scanning.

        Args:
            url: Website URL to scan

        Returns:
            Dictionary containing scan summary
        """
        results = self.run(url)

        if results.get('status') == 'error':
            return {
                "status": "error",
                "error": results.get('error'),
                "url": url
            }

        # Extract just the summary for quick results
        return {
            "status": "success",
            "url": url,
            "summary": results.get('summary', {}),
            "execution_time": results.get('execution_time', 0)
        }