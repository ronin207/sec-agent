"""
Security Agent module for automating vulnerability assessments.
Main module that integrates all the components.
"""
from typing import Dict, List, Optional, Any
import os
import json
import time
from datetime import datetime
import tempfile
import shutil
import subprocess
import glob

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
        
        logger.info("SecurityAgent initialized successfully")
    
    def run(self, user_input: str, output_format: str = "json", recursive: bool = False) -> Dict:
        """
        Run the security agent on the provided input.
        
        Args:
            user_input: Either a website URL or a Solidity contract file/URL
            output_format: Format of the output ("json" or "markdown")
            recursive: Whether to scan directories recursively (only applies to local files/dirs)
            
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
            
            # Step 5: Aggregate and deduplicate results
            logger.info("Aggregating scan results")
            aggregated_results = self.result_aggregator.aggregate_results(
                scan_results,
                cve_info
            )
            
            # Step 6: Generate summary
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
    
    def scan_github_repo(self, repo_url: str, github_token: Optional[str] = None, output_format: str = "json") -> Dict:
        """
        Scan a GitHub repository for security vulnerabilities.
        
        Args:
            repo_url: GitHub repository URL
            github_token: Optional GitHub personal access token for private repositories
            output_format: Format of the output ("json" or "markdown")
            
        Returns:
            Dictionary containing the assessment results
        """
        start_time = time.time()
        results = {
            "timestamp": datetime.now().isoformat(),
            "input": repo_url,
            "status": "running",
            "execution_time": 0,
            "error": None,
            "input_type": "github_repo"
        }
        
        try:
            # Create a temporary directory
            temp_dir = tempfile.mkdtemp()
            
            try:
                # Clone the repository
                logger.info(f"Cloning GitHub repo: {repo_url}")
                
                # Prepare the git clone command
                if github_token:
                    # Add token to the URL for authentication
                    url_with_token = repo_url.replace("https://", f"https://{github_token}@")
                    clone_cmd = ["git", "clone", url_with_token, temp_dir]
                else:
                    clone_cmd = ["git", "clone", repo_url, temp_dir]
                
                # Execute git clone
                process = subprocess.run(
                    clone_cmd,
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    check=True
                )
                
                # Now scan the cloned repository directory
                scan_results = self.scan_directory(temp_dir, recursive=True, output_format=output_format)
                
                # Add GitHub-specific information to the results
                scan_results["github_repo"] = repo_url
                
                # Return scan results
                return scan_results
                
            except subprocess.CalledProcessError as e:
                error_msg = f"Git clone error: {e.stderr}"
                logger.error(error_msg)
                results['status'] = 'error'
                results['error'] = error_msg
                return results
            finally:
                # Clean up the temporary directory
                shutil.rmtree(temp_dir, ignore_errors=True)
                
        except Exception as e:
            logger.error(f"Error in scan_github_repo: {str(e)}")
            results['status'] = 'error'
            results['error'] = str(e)
        
        # Calculate execution time
        results['execution_time'] = time.time() - start_time
        
        return results
    
    def scan_directory(self, directory_path: str, recursive: bool = False, output_format: str = "json") -> Dict:
        """
        Scan a directory for security vulnerabilities.
        
        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories recursively
            output_format: Format of the output ("json" or "markdown")
            
        Returns:
            Dictionary containing the assessment results
        """
        start_time = time.time()
        results = {
            "timestamp": datetime.now().isoformat(),
            "input": directory_path,
            "status": "running",
            "execution_time": 0,
            "error": None,
            "input_type": "directory",
            "is_multiple": True
        }
        
        try:
            # Check if directory exists
            if not os.path.isdir(directory_path):
                results['status'] = 'error'
                results['error'] = f"Directory not found: {directory_path}"
                return results
            
            # Find all relevant files
            file_patterns = ["*.sol", "*.js", "*.ts", "*.py", "*.java", "*.go", "*.cpp", "*.c", "*.h", "*.cs", "*.rb", "*.php"]
            
            all_files = []
            for pattern in file_patterns:
                if recursive:
                    glob_pattern = os.path.join(directory_path, '**', pattern)
                    all_files.extend(glob.glob(glob_pattern, recursive=True))
                else:
                    glob_pattern = os.path.join(directory_path, pattern)
                    all_files.extend(glob.glob(glob_pattern))
            
            # If no files found
            if not all_files:
                results['status'] = 'completed'
                results['files'] = []
                results['warning'] = "No relevant files found to scan"
                results['execution_time'] = time.time() - start_time
                return results
            
            # Initialize scan results
            scan_results = []
            total_vulnerabilities = []
            
            # Process each file
            for file_path in all_files:
                try:
                    logger.info(f"Scanning file: {file_path}")
                    file_result = self.run(file_path, output_format=output_format)
                    
                    # Add to scan results
                    scan_results.append({
                        "file_path": file_path,
                        "status": file_result.get("status"),
                        "summary": file_result.get("summary"),
                        "findings": file_result.get("aggregated_results", {}).get("findings", [])
                    })
                    
                    # Collect vulnerabilities for summary
                    if file_result.get("status") == "completed":
                        findings = file_result.get("aggregated_results", {}).get("findings", [])
                        for finding in findings:
                            finding["file"] = os.path.basename(file_path)
                            total_vulnerabilities.append(finding)
                            
                except Exception as e:
                    logger.error(f"Error scanning {file_path}: {str(e)}")
                    scan_results.append({
                        "file_path": file_path,
                        "status": "error",
                        "error": str(e)
                    })
            
            # Aggregate results
            aggregated = {
                "total_findings": len(total_vulnerabilities),
                "findings": total_vulnerabilities,
                "tools_used": [],
                "findings_by_severity": {}
            }
            
            # Count findings by severity
            severity_counts = {}
            for vuln in total_vulnerabilities:
                severity = vuln.get("severity", "unknown").lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            aggregated["findings_by_severity"] = severity_counts
            
            # Collect all tools used
            all_tools = set()
            for file_result in scan_results:
                if file_result.get("status") == "completed":
                    tools = file_result.get("tools_used", [])
                    all_tools.update(tools)
            
            aggregated["tools_used"] = list(all_tools)
            
            # Generate a summary using the result summarizer
            summary = self.result_summarizer.generate_summary(aggregated)
            
            # Compile the final results
            results['status'] = 'completed'
            results['files'] = [result.get("file_path") for result in scan_results]
            results['file_results'] = scan_results
            results['aggregated_results'] = aggregated
            results['summary'] = summary
            
            # Format output based on requested format
            if output_format.lower() == "markdown":
                results['formatted_output'] = self.result_aggregator.export_to_markdown(aggregated)
            else:
                results['formatted_output'] = self.result_aggregator.export_to_json(aggregated)
                
        except Exception as e:
            logger.error(f"Error in scan_directory: {str(e)}")
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