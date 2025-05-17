"""
Security Agent module for automating vulnerability assessments.
Main module that integrates all the components.
"""
from typing import Dict, List, Optional, Any, Union
import os
import json
import time
from datetime import datetime
import tempfile
import shutil
import subprocess
import glob
from github import Github

# Import all required components
from backend.core.input_handler import InputHandler
from backend.core.cve_knowledge_base import CVEKnowledgeQuery
from backend.core.tool_selector import SecurityToolSelector
from backend.core.scan_executor import ScanExecutor
from backend.core.result_aggregator import ResultAggregator
from backend.core.result_summarizer import ResultSummarizer

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
        
        # Keep track of last input and partial results for recovery
        self._last_input = None
        self._partial_results = None
        
        logger.info("SecurityAgent initialized successfully")
    
    def run(self, user_input: Union[str, List[str]], output_format: str = "json", recursive: bool = False) -> Dict:
        """
        Run the security agent on the provided input.
        
        Args:
            user_input: Either a website URL, Solidity contract file/URL, directory, or GitHub repository URL.
                        Can also be a list of files to scan.
            output_format: Format of the output ("json" or "markdown")
            recursive: Whether to scan directories recursively
            
        Returns:
            Dictionary containing the assessment results
        """
        start_time = time.time()
        self._last_input = user_input
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "input": user_input,
            "status": "running",
            "execution_time": 0,
            "error": None
        }
        
        # Store some minimal results in case of interruption
        self._partial_results = results.copy()
        
        try:
            # Handle multiple inputs (list of files/URLs)
            if isinstance(user_input, list):
                if not user_input:
                    results['status'] = 'error'
                    results['error'] = "Empty input list provided."
                    return results
                
                # Process multiple inputs using the enhanced input handler method
                logger.info(f"Processing multiple inputs: {len(user_input)} items")
                input_result = self.input_handler.validate_multiple_inputs(user_input, recursive=recursive)
                
            # Check if the input is a GitHub repository
            elif user_input and isinstance(user_input, str) and self.input_handler._is_valid_url(user_input) and self.input_handler._is_github_repo(user_input):
                logger.info(f"Processing GitHub repository: {user_input}")
                input_result = self.input_handler._process_github_repo(user_input)
                
            # Check if the input is a directory and recursive flag is set
            elif os.path.isdir(user_input) and recursive:
                logger.info(f"Processing directory recursively: {user_input}")
                input_result = self.input_handler._process_directory(user_input, recursive=True)
                
            else:
                # Process single input (string)
                logger.info(f"Validating input: {user_input}")
                input_result = self.input_handler.validate_and_classify(user_input)
            
            if input_result.get('type') == 'error':
                results['status'] = 'error'
                results['error'] = input_result.get('message')
                self._partial_results = results
                return results
                
            # Update partial results with validated input info
            results['input_type'] = input_result.get('type')
            results['is_multiple'] = input_result.get('is_multiple', False)
            
            if input_result.get('is_multiple'):
                logger.info(f"Processing multiple files/inputs: {len(input_result.get('files', []))} items")
                results['files'] = input_result.get('files', [])
            
            # Update partial results as we go
            self._partial_results = results.copy()
            
            # Check if we got partial results from GitHub due to rate limits
            if input_result.get('partial'):
                logger.warning("Partial GitHub repository processing due to rate limits")
                results['partial'] = True
                results['warning'] = input_result.get('warning')
            
            # Step 2: Query CVE knowledge base
            logger.info(f"Querying CVE knowledge base for {input_result.get('type')}")
            cve_info = self.cve_knowledge_query.query_by_input_type(
                input_result.get('type'),
                input_result.get('input')
            )
            
            # Update partial results
            results['cve_info'] = {'count': len(cve_info) if hasattr(cve_info, '__len__') else 0}
            self._partial_results = results.copy()
            
            # Step 3: Select appropriate security tools
            logger.info("Selecting security tools")
            selected_tools = self.tool_selector.select_tools(
                input_result.get('type'),
                cve_info
            )
            
            # Update partial results - handle the new list format from tool selector
            results['selected_tools'] = [tool.get('name') for tool in selected_tools] if isinstance(selected_tools, list) else []
            self._partial_results = results.copy()
            
            # Step 4: Execute security scans
            logger.info("Executing security scans")
            scan_results = self.scan_executor.execute_scans(
                input_result,
                selected_tools
            )
            
            # Count total raw findings before deduplication
            total_raw_findings = 0
            for tool_result in scan_results.get('tool_results', []):
                total_raw_findings += len(tool_result.get('findings', []))
            
            # Update partial results with scan results
            results['scan_results'] = scan_results
            self._partial_results = results.copy()
            
            # Step 5: Aggregate and deduplicate results
            logger.info("Aggregating scan results")
            aggregated_results = self.result_aggregator.aggregate_results(
                scan_results,
                cve_info
            )
            
            # Log deduplication stats
            total_deduplicated = aggregated_results.get('total_findings', 0)
            duplicates_removed = total_raw_findings - total_deduplicated
            logger.info(f"Deduplication removed {duplicates_removed} duplicate findings ({total_raw_findings} raw → {total_deduplicated} unique)")
            
            # Add deduplication stats to results
            aggregated_results['deduplication_stats'] = {
                'total_raw_findings': total_raw_findings,
                'duplicates_removed': duplicates_removed,
                'deduplication_ratio': round((duplicates_removed / total_raw_findings * 100), 1) if total_raw_findings > 0 else 0
            }
            
            # Update partial results
            results['aggregated_results'] = aggregated_results
            self._partial_results = results.copy()
            
            # Step 6: Generate summary
            logger.info("Generating result summary")
            summary = self.result_summarizer.generate_summary(aggregated_results)
            
            # Combine all results
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
        finally:
            # Clean up any temporary directories created during processing
            self._cleanup()
        
        # Calculate execution time
        results['execution_time'] = time.time() - start_time
        
        # Store final results
        self._partial_results = results
        
        return results
    
    def get_partial_results(self) -> Dict:
        """
        Return any partial results that were collected before an interruption or error
        
        Returns:
            Dictionary containing partial scan results, or error information
        """
        if not self._partial_results:
            return {
                "status": "error",
                "error": "No scan results available",
                "timestamp": datetime.now().isoformat()
            }
            
        # If we have partial results, add a note that they're incomplete
        results = self._partial_results.copy()
        
        if results.get('status') == 'running':
            results['status'] = 'incomplete'
            results['partial'] = True
            results['warning'] = "Scan was interrupted before completion. Results are incomplete."
            
        return results
    
    def _cleanup(self):
        """Clean up temporary files and resources"""
        try:
            # Clean up input handler resources (like cloned repositories)
            self.input_handler.cleanup()
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
    
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
        
    def scan_multiple(self, file_paths: List[str], output_format: str = "json", recursive: bool = False) -> Dict:
        """
        Convenience method for scanning multiple files at once.
        
        Args:
            file_paths: List of file paths to scan
            output_format: Format of the output ("json" or "markdown")
            recursive: Whether to scan directories recursively
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Scanning multiple files: {len(file_paths)} files")
        
        if not file_paths or not isinstance(file_paths, list):
            return {
                "status": "error",
                "error": "Invalid input: file_paths must be a non-empty list",
            }
        
        # Filter out any empty strings or None values
        file_paths = [path for path in file_paths if path]
        
        if not file_paths:
            return {
                "status": "error",
                "error": "No valid files provided for scanning",
            }
        
        # Run the scan with multiple inputs
        return self.run(file_paths, output_format=output_format, recursive=recursive)
    
    def scan_github_repo(self, repo_url: str, output_format: str = "json", github_token: str = None) -> Dict:
        """
        Convenience method for scanning a GitHub repository.
        
        Args:
            repo_url: GitHub repository URL
            output_format: Format of the output ("json" or "markdown")
            github_token: Optional GitHub personal access token for private repositories
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Scanning GitHub repository: {repo_url}")
        
        if not repo_url or not isinstance(repo_url, str):
            return {
                "status": "error",
                "error": "Invalid GitHub repository URL",
                "repo_url": repo_url
            }
        
        # Validate that it's a GitHub URL
        if not self.input_handler._is_valid_url(repo_url) or not self.input_handler._is_github_repo(repo_url):
            return {
                "status": "error",
                "error": "Invalid GitHub repository URL. Expected format: https://github.com/username/repository",
                "repo_url": repo_url
            }
        
        # Set GitHub token if provided
        if github_token:
            os.environ["GITHUB_TOKEN"] = github_token
            # Reinitialize GitHub client with the new token
            self.input_handler.github_token = github_token
            self.input_handler.github_client = Github(github_token)
        
        # Scan with recursive directory support
        return self.run(repo_url, output_format=output_format, recursive=True) 