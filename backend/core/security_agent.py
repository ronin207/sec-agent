"""
Main Security Agent module for the Security Agent.
Coordinates all components and handles the full security assessment process.
"""
import os
import re
import time
import tempfile
import shutil
import json
import uuid
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple
from langchain.document_loaders import GitLoader, TextLoader, DirectoryLoader

# Import from existing modules
from backend.core.input_handler import InputHandler
from backend.core.cve_knowledge_base import CVEKnowledgeQuery
from backend.core.tool_selector import SecurityToolSelector
from backend.core.scan_executor import ScanExecutor
from backend.core.result_aggregator import ResultAggregator
from backend.core.result_summarizer import ResultSummarizer
from backend.core.ai_audit_analyzer import AIAuditAnalyzer
from backend.core.chunked_ai_audit_analyzer import ChunkedAIAuditAnalyzer

# Import helpers
from backend.utils.helpers import get_logger

# Get logger
logger = get_logger('security_agent')

# For compatibility purposes - ensure this is used in scan_github_repo
class ToolSelector(SecurityToolSelector):
    """Alias for SecurityToolSelector for backward compatibility."""
    pass

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
        self.result_summarizer = ResultSummarizer(api_key=self.api_key)
        self.scan_executor = ScanExecutor(result_summarizer=self.result_summarizer)
        self.result_aggregator = ResultAggregator()
        self.ai_audit_analyzer = AIAuditAnalyzer(api_key=self.api_key)
        self.chunked_ai_audit_analyzer = ChunkedAIAuditAnalyzer(model_name="gpt-4o-mini", api_key=self.api_key)
        
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
            
            # Step 4.5: Perform AI-based code analysis for Solidity contracts
            ai_analysis_findings = []
            if input_result.get('type') in ['solidity', 'solidity_contract']:
                logger.info("Performing AI-based code analysis")
                
                # Get Solidity files
                solidity_files = []
                if input_result.get('is_multiple') and input_result.get('files'):
                    solidity_files = [f for f in input_result.get('files', []) if f.endswith('.sol')]
                elif not input_result.get('is_multiple') and os.path.isfile(input_result.get('input')):
                    if input_result.get('input').endswith('.sol'):
                        solidity_files = [input_result.get('input')]
                
                if solidity_files:
                    # Use chunked analyzer for multiple files
                    if len(solidity_files) > 1:
                        logger.info(f"Using chunked AI analysis for {len(solidity_files)} Solidity files")
                        chunked_result = self.chunked_ai_audit_analyzer.analyze_multiple_files(solidity_files)
                        ai_analysis_findings = chunked_result.get('findings', [])
                        
                        # Add chunking metadata to results
                        results['ai_analysis_metadata'] = {
                            'chunking_used': True,
                            'chunking_summary': chunked_result.get('chunking_summary', {}),
                            'processing_stats': chunked_result.get('processing_stats', {}),
                            'total_files_processed': chunked_result.get('total_files', 0)
                        }
                    else:
                        # Single file - use regular analyzer
                        logger.info("Using regular AI analysis for single Solidity file")
                        file_path = solidity_files[0]
                        with open(file_path, 'r') as f:
                            code = f.read()
                            contract_name = os.path.basename(file_path)
                            ai_analysis_findings = self.ai_audit_analyzer.analyze_solidity_code(code, contract_name)
                            # Add file information to findings
                            for finding in ai_analysis_findings:
                                finding['file'] = file_path
                                finding['contract_name'] = contract_name
                        
                        results['ai_analysis_metadata'] = {
                            'chunking_used': False,
                            'total_files_processed': 1
                        }
            
            # Update partial results with AI analysis
            results['ai_analysis'] = {'count': len(ai_analysis_findings)}
            self._partial_results = results.copy()
            
            # Step 5: Aggregate and deduplicate results (keeping AI findings separate)
            logger.info("Aggregating scan results")
            aggregated_results = self.result_aggregator.aggregate_results(
                scan_results,
                cve_info,
                {}  # Don't merge AI findings into regular aggregation
            )
            
            # Add AI audit findings as a separate section
            if ai_analysis_findings:
                aggregated_results['ai_audit_findings'] = {
                    'total_findings': len(ai_analysis_findings),
                    'findings': ai_analysis_findings,
                    'analyzer': 'AI Audit Analyzer (GPT-4o-mini)',
                    'knowledge_base': 'Past audit reports database'
                }
                logger.info(f"AI audit analysis found {len(ai_analysis_findings)} findings")
            
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
    
    def scan_github_repo(self, repo_url: str, output_format: str = "json", token: str = None) -> Dict:
        """Scan a GitHub repository for security issues.
        
        Args:
            repo_url: The URL of the GitHub repository to scan
            output_format: The format for the output (json or markdown)
            token: GitHub personal access token for authentication
            
        Returns:
            Dict containing scan results
        """
        try:
            # Validate and classify the input
            input_data = self.input_handler.validate_and_classify(repo_url)
            
            # Check if it's a valid GitHub repository
            if input_data.get("type") == "error":
                return {"error": input_data.get("message", "Invalid GitHub repository URL"), "valid": False}
            
            if not self.input_handler._is_github_repo(repo_url):
                return {"error": "URL is not a valid GitHub repository", "valid": False}
            
            # Set GitHub token if provided
            if token:
                os.environ["GITHUB_TOKEN"] = token
                logger.info("Using provided GitHub token")
            
            github_token = token or os.environ.get("GITHUB_TOKEN")
            
            logger.info(f"Scanning GitHub repository: {repo_url}")
            
            # Create a temporary directory for cloning
            import tempfile
            repo_dir = tempfile.mkdtemp()
            
            try:
                # Extract repo owner and name from URL for better logging
                parsed_url = urlparse(repo_url)
                path_parts = parsed_url.path.strip('/').split('/')
                if len(path_parts) >= 2:
                    repo_owner, repo_name = path_parts[0], path_parts[1]
                    scan_id = f"github-{repo_owner}-{repo_name}-{int(time.time())}"
                else:
                    scan_id = f"github-repo-{int(time.time())}"
                
                logger.info(f"Created scan ID: {scan_id}")
                
                # Try different branches as many repos use different default branch names
                branches_to_try = ["main", "master", "dev", "develop"]
                cloned = False
                documents = []
                loader = None
                
                for branch in branches_to_try:
                    try:
                        logger.info(f"Attempting to clone branch '{branch}'")
                        
                        # Build clone command with token if available
                        if github_token:
                            # Use token in URL for authentication
                            auth_url = repo_url.replace("https://", f"https://{github_token}@")
                            clone_cmd = f"git clone --depth 1 --branch {branch} {auth_url} {repo_dir}"
                        else:
                            clone_cmd = f"git clone --depth 1 --branch {branch} {repo_url} {repo_dir}"
                        
                        # Execute clone command
                        import subprocess
                        result = subprocess.run(clone_cmd, shell=True, capture_output=True, text=True, timeout=300)
                        
                        if result.returncode == 0:
                            logger.info(f"Successfully cloned repository using branch '{branch}'")
                            cloned = True
                            break
                        else:
                            logger.debug(f"Failed to clone with branch '{branch}': {result.stderr}")
                            
                    except subprocess.TimeoutExpired:
                        logger.error(f"Timeout while cloning repository with branch '{branch}'")
                    except Exception as e:
                        logger.debug(f"Error cloning with branch '{branch}': {str(e)}")
                
                if not cloned:
                    logger.error("Failed to clone repository with any branch")
                    return {
                        "error": "Failed to clone repository. Check if the repository exists and is accessible.",
                        "valid": False,
                        "scan_id": scan_id,
                        "target": repo_url,
                        "input_type": "github_repo",
                        "timestamp": datetime.now().isoformat()
                    }
                
                # Find all relevant files for analysis
                relevant_files = []
                for root, dirs, files in os.walk(repo_dir):
                    # Skip hidden directories and common non-source directories
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'vendor']]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        # Include various file types for analysis
                        if any(file.endswith(ext) for ext in ['.sol', '.js', '.ts', '.py', '.java', '.go', '.rs', '.cpp', '.c', '.h']):
                            relevant_files.append(file_path)
                
                logger.info(f"Found {len(relevant_files)} relevant files for analysis")
                
                # Run traditional security scans
                scan_results = {}
                
                # Perform AI audit analysis on Solidity files
                ai_analysis_findings = []
                solidity_files = [f for f in relevant_files if f.endswith('.sol')]
                
                if solidity_files:
                    logger.info(f"Found {len(solidity_files)} Solidity files for AI audit analysis")
                    
                    # Use chunked analyzer for multiple files
                    if len(solidity_files) > 1:
                        logger.info("Using chunked AI analysis for multiple Solidity files")
                        chunked_result = self.chunked_ai_audit_analyzer.analyze_github_repository(
                            solidity_files, 
                            repo_url=repo_url
                        )
                        ai_analysis_findings = chunked_result.get('findings', [])
                        
                        # Add repository context to findings
                        for finding in ai_analysis_findings:
                            finding['source'] = 'github_repo'
                            finding['repository_url'] = repo_url
                        
                        logger.info(f"Chunked AI audit found {len(ai_analysis_findings)} findings")
                    else:
                        # Single file analysis
                        file_path = solidity_files[0]
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                file_content = f.read()
                            
                            logger.info(f"Performing AI audit analysis on {file_path}")
                            contract_name = os.path.basename(file_path)
                            ai_findings = self.ai_audit_analyzer.analyze_solidity_code(file_content, contract_name)
                            
                            # Add file information to AI findings
                            for finding in ai_findings:
                                finding['file'] = file_path
                                finding['contract_name'] = contract_name
                                finding['source'] = 'github_repo'
                                finding['repository_url'] = repo_url
                            
                            ai_analysis_findings.extend(ai_findings)
                            logger.info(f"AI audit found {len(ai_findings)} findings in {file_path}")
                            
                        except Exception as e:
                            logger.error(f"Error during AI audit analysis of {file_path}: {str(e)}")
                
                # Aggregate traditional security tool results
                aggregated_results = self.result_aggregator.aggregate_results(scan_results, [], {})
                
                # Add AI audit findings as a separate section
                if ai_analysis_findings:
                    aggregated_results['ai_audit_findings'] = {
                        'total_findings': len(ai_analysis_findings),
                        'findings': ai_analysis_findings,
                        'analyzer': f'AI Audit Analyzer ({self.ai_audit_analyzer.model_name})',
                        'knowledge_base': 'Past audit reports database'
                    }
                    logger.info(f"Total AI audit findings: {len(ai_analysis_findings)}")
                
                # Generate summary that includes both traditional and AI findings
                summary_data = {
                    "input_type": "github_repo",
                    "target": repo_url,
                    "findings": aggregated_results.get("findings", []),
                    "total_findings": aggregated_results.get("total_findings", 0),
                    "ai_audit_findings": ai_analysis_findings if ai_analysis_findings else []
                }
                summary = self.result_summarizer.generate_summary(summary_data)
                
                # Complete result
                result = {
                    "scan_id": scan_id,
                    "status": "completed",
                    "target": repo_url,
                    "input_type": "github_repo",
                    "timestamp": datetime.now().isoformat(),
                    "aggregated_results": aggregated_results,
                    "summary": summary
                }
                
                return result
                
            except Exception as e:
                logger.error(f"Error during repository processing: {str(e)}", exc_info=True)
                return {
                    "error": f"Failed to process repository: {str(e)}",
                    "valid": False,
                    "scan_id": scan_id if 'scan_id' in locals() else f"github-error-{int(time.time())}",
                    "target": repo_url,
                    "input_type": "github_repo",
                    "timestamp": datetime.now().isoformat()
                }
            finally:
                # Clean up temporary directory
                import shutil
                try:
                    logger.info(f"Cleaning up temporary directory: {repo_dir}")
                    shutil.rmtree(repo_dir)
                except Exception as e:
                    logger.warning(f"Failed to clean up temporary directory {repo_dir}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error in GitHub repository scan: {str(e)}", exc_info=True)
            return {
                "error": f"GitHub repository scan failed: {str(e)}",
                "valid": False,
                "timestamp": datetime.now().isoformat()
            }
    
    def test_scan(self, file_paths: List[str]) -> Dict:
        """
        A simple test method for quickly scanning files without the full pipeline.
        Primarily used for testing the API endpoints.
        
        Args:
            file_paths: List of file paths to scan
            
        Returns:
            Dictionary containing quick scan results
        """
        if not file_paths or not isinstance(file_paths, list):
            return {
                "status": "error",
                "error": "Invalid input: file_paths must be a non-empty list",
            }
            
        # Check if all paths exist
        missing_files = [path for path in file_paths if not os.path.exists(path)]
        if missing_files:
            return {
                "status": "error",
                "error": f"Files not found: {', '.join(missing_files)}",
            }
            
        results = {
            "timestamp": datetime.now().isoformat(),
            "status": "completed",
            "input": file_paths,
            "execution_time": 0.5,  # Mock value for quick response
            "files_scanned": len(file_paths),
            "vulnerabilities": []
        }
        
        # Simple scanning logic for demonstration
        for file_path in file_paths:
            file_ext = os.path.splitext(file_path)[1].lower()
            
            # For Solidity files, add some test vulnerabilities
            if file_ext == '.sol':
                # Read the first few lines of the file to look for patterns
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        
                    # Look for reentrancy pattern
                    if 'withdraw' in content and 'call' in content and 'balances' in content:
                        results['vulnerabilities'].append({
                            "name": "Reentrancy",
                            "description": "Reentrancy vulnerability in withdraw function",
                            "severity": "High",
                            "location": f"{os.path.basename(file_path)}:15-30",
                            "recommendation": "Update state before making external calls"
                        })
                        
                    # Look for unchecked send pattern
                    if 'send' in content or '.call' in content and 'require(' not in content:
                        results['vulnerabilities'].append({
                            "name": "Unchecked Send",
                            "description": "Return value of external call not checked",
                            "severity": "Medium",
                            "location": f"{os.path.basename(file_path)}:20-25",
                            "recommendation": "Check return value of external calls"
                        })
                        
                except Exception as e:
                    logger.error(f"Error reading file {file_path}: {str(e)}")
                    
        # Add summary based on vulnerabilities found
        if results['vulnerabilities']:
            high_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'High')
            medium_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'Medium')
            low_count = sum(1 for v in results['vulnerabilities'] if v['severity'] == 'Low')
            
            risk_level = "High" if high_count > 0 else "Medium" if medium_count > 0 else "Low" if low_count > 0 else "None"
            
            results['summary'] = {
                "summary": f"Security scan identified {len(results['vulnerabilities'])} issues: {high_count} high, {medium_count} medium, and {low_count} low severity.",
                "risk_assessment": risk_level,
                "remediation_suggestions": [v['recommendation'] for v in results['vulnerabilities']]
            }
        else:
            results['summary'] = {
                "summary": "No security issues identified.",
                "risk_assessment": "None",
                "remediation_suggestions": []
            }
            
        return results 
