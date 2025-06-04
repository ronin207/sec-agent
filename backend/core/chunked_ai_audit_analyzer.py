# SPDX-FileCopyrightText: 2025 Security Agent
# SPDX-License-Identifier: GPL-3.0

"""
Chunked AI Audit Analyzer for processing large sets of Solidity files.
Extends the base AIAuditAnalyzer with chunking capabilities.
"""

import os
import json
import time
from typing import List, Dict, Any
from pathlib import Path
from backend.core.ai_audit_analyzer import AIAuditAnalyzer
from backend.core.chunking_manager import ChunkingManager
from backend.utils.helpers import get_logger

logger = get_logger('chunked_ai_audit_analyzer')

class ChunkedAIAuditAnalyzer(AIAuditAnalyzer):
    """
    AI Audit Analyzer with chunking capabilities for processing large file sets.
    """
    
    def __init__(self, model_name: str = "gpt-4o-mini", api_key: str = None):
        """
        Initialize the chunked AI audit analyzer.
        
        Args:
            model_name: The model name to use for analysis
            api_key: Optional OpenAI API key
        """
        # Initialize the base class with proper parameters
        super().__init__(api_key=api_key)
        
        # Store the model name for our use
        self.model_name = model_name
        self.chunking_manager = ChunkingManager(model_name=model_name)
        logger.info(f"ChunkedAIAuditAnalyzer initialized with {model_name}")
    
    def analyze_multiple_files(self, file_paths: List[str], progress_callback=None) -> Dict[str, Any]:
        """
        Analyze multiple Solidity files using chunking to stay within token limits.
        
        Args:
            file_paths: List of Solidity file paths to analyze
            progress_callback: Optional callback function for progress updates
            
        Returns:
            Dictionary containing all findings and metadata
        """
        logger.info(f"Starting chunked analysis of {len(file_paths)} files")
        
        # Filter for Solidity files only
        solidity_files = [f for f in file_paths if f.endswith('.sol')]
        if not solidity_files:
            logger.warning("No Solidity files found for analysis")
            return {
                "status": "completed",
                "total_files": 0,
                "total_findings": 0,
                "findings": [],
                "message": "No Solidity files found for analysis"
            }
        
        logger.info(f"Processing {len(solidity_files)} Solidity files")
        
        # Create chunks
        chunks = self.chunking_manager.chunk_files(solidity_files)
        chunk_summary = self.chunking_manager.get_chunk_summary(chunks)
        
        logger.info(f"Created {chunk_summary['total_chunks']} chunks for processing")
        logger.info(f"Estimated processing time: {chunk_summary['estimated_processing_time']:.1f} seconds")
        
        # Process each chunk
        all_chunk_results = []
        processing_stats = {
            "chunks_processed": 0,
            "chunks_failed": 0,
            "total_processing_time": 0,
            "files_processed": 0
        }
        
        start_time = time.time()
        
        for i, chunk in enumerate(chunks):
            chunk_start_time = time.time()
            
            try:
                logger.info(f"Processing chunk {i+1}/{len(chunks)} with {len(chunk['files'])} files")
                
                # Update progress
                if progress_callback:
                    progress_callback({
                        "stage": "processing_chunks",
                        "current_chunk": i + 1,
                        "total_chunks": len(chunks),
                        "files_in_chunk": len(chunk['files']),
                        "estimated_time_remaining": chunk_summary['estimated_processing_time'] * (len(chunks) - i) / len(chunks)
                    })
                
                # Process this chunk
                chunk_results = self._process_chunk(chunk, i)
                all_chunk_results.append(chunk_results)
                
                processing_stats["chunks_processed"] += 1
                processing_stats["files_processed"] += len(chunk['files'])
                
                chunk_time = time.time() - chunk_start_time
                processing_stats["total_processing_time"] += chunk_time
                
                logger.info(f"Chunk {i+1} completed in {chunk_time:.1f}s with {len(chunk_results)} findings")
                
                # Rate limiting is now handled by the batch client internally
                # No need for manual delays between chunks
                
            except Exception as e:
                logger.error(f"Error processing chunk {i+1}: {e}")
                processing_stats["chunks_failed"] += 1
                all_chunk_results.append([])  # Add empty result for failed chunk
        
        # Merge all results
        logger.info("Merging results from all chunks")
        merged_findings = self.chunking_manager.merge_chunk_results(all_chunk_results)
        
        total_time = time.time() - start_time
        processing_stats["total_processing_time"] = total_time
        
        # Create final result
        result = {
            "status": "completed",
            "analysis_type": "chunked_ai_audit",
            "model_used": self.model_name,
            "total_files": len(solidity_files),
            "total_findings": len(merged_findings),
            "findings": merged_findings,
            "chunking_summary": chunk_summary,
            "processing_stats": processing_stats,
            "severity_breakdown": self._calculate_severity_breakdown(merged_findings),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "processing_time_seconds": total_time
        }
        
        logger.info(f"Chunked analysis completed: {len(merged_findings)} findings from {len(solidity_files)} files in {total_time:.1f}s")
        
        return result
    
    def _process_chunk(self, chunk: Dict[str, Any], chunk_index: int) -> List[Dict]:
        """
        Process a single chunk of files using batch processing with rate limiting.
        
        Args:
            chunk: Chunk information containing files and metadata
            chunk_index: Index of the current chunk
            
        Returns:
            List of findings from this chunk
        """
        chunk_findings = []
        
        # Handle oversized files differently (process individually)
        if chunk.get("is_oversized", False):
            logger.warning(f"Processing oversized chunk {chunk_index} with {len(chunk['files'])} files")
            # For oversized files, we might need to split them further
            for file_info in chunk['files']:
                try:
                    # Try to process the large file by splitting it
                    file_chunks = self.chunking_manager.chunk_large_file(file_info['path'])
                    for file_chunk in file_chunks:
                        findings = self.analyze_solidity_code(
                            file_chunk['content'], 
                            file_chunk['name']
                        )
                        # Add chunk information to findings
                        for finding in findings:
                            finding['file'] = file_info['path']
                            finding['chunk_info'] = {
                                'chunk_index': file_chunk['chunk_index'],
                                'start_line': file_chunk['start_line'],
                                'end_line': file_chunk['end_line']
                            }
                        chunk_findings.extend(findings)
                except Exception as e:
                    logger.error(f"Error processing oversized file {file_info['path']}: {e}")
        else:
            # Process normal chunk using batch processing
            try:
                # Import the batch client
                from backend.core.openai_batch_client import (
                    get_batch_client, 
                    create_chat_completion_request, 
                    BatchOptions
                )
                
                # Get the API key
                api_key = self.api_key or os.environ.get("OPENAI_API_KEY")
                if not api_key:
                    logger.error("OpenAI API key is required for batch analysis")
                    return []
                
                # Create system message
                system_message = self._create_system_message()
                
                # Prepare batch requests for all files in the chunk
                batch_requests = []
                file_infos = []  # Keep track of file info for each request
                
                for file_info in chunk['files']:
                    try:
                        message = f"Perform a comprehensive security audit on the following Solidity smart contract named '{file_info['name']}'."
                        message += "\n\nCode:\n```solidity\n" + file_info['content'] + "\n```"
                        message += """

                        For each vulnerability, provide the output in the following JSON format:
                        {
                            "type": "vulnerability_type",
                            "severity": "severity_level",
                            "description": "detailed_description",
                            "location": "contract_name.sol:line_number",
                            "recommendation": "specific_recommendation"
                        }

                        The output should be a list of these JSON objects wrapped in ```json and ``` markers.
                        """
                        
                        request = create_chat_completion_request(
                            model=self.model_name,
                            system_message=system_message,
                            user_message=message,
                            temperature=0.0,
                            max_tokens=4000
                        )
                        
                        batch_requests.append(request)
                        file_infos.append(file_info)
                        
                    except Exception as e:
                        logger.error(f"Error preparing request for file {file_info['path']}: {e}")
                
                if not batch_requests:
                    logger.warning(f"No valid requests prepared for chunk {chunk_index}")
                    return []
                
                # Configure batch options for processing this chunk
                batch_options = BatchOptions(
                    rate_limit_ms=1500,  # Reduced from 3000ms to 1500ms for faster processing
                    max_retries=5,
                    initial_backoff_ms=5000,  # Reduced from 10000ms to 5000ms
                    max_backoff_ms=60000,  # Reduced from 120000ms to 60000ms
                    backoff_multiplier=2.0
                )
                
                logger.info(f"Processing chunk {chunk_index} with {len(batch_requests)} files using batch client")
                
                # Process all requests in the chunk as a batch
                batch_client = get_batch_client(api_key)
                responses = batch_client.batch_chat_completions_sync(
                    batch_requests, 
                    batch_options,
                    progress_callback=lambda current, total: logger.debug(f"Chunk {chunk_index}: {current}/{total} requests completed")
                )
                
                # Process responses and extract findings
                for i, (response, file_info) in enumerate(zip(responses, file_infos)):
                    try:
                        findings = self._parse_response(response.choices[0].message.content)
                        # Add file information to findings
                        for finding in findings:
                            finding['file'] = file_info['path']
                            finding['chunk_id'] = chunk_index
                        chunk_findings.extend(findings)
                        logger.debug(f"Processed file {file_info['name']} in chunk {chunk_index}: {len(findings)} findings")
                    except Exception as e:
                        logger.error(f"Error processing response for file {file_info['path']}: {e}")
                
                logger.info(f"Chunk {chunk_index} batch processing completed: {len(chunk_findings)} total findings from {len(file_infos)} files")
                
            except Exception as e:
                logger.error(f"Error in batch processing for chunk {chunk_index}: {e}")
                # Fallback to individual processing if batch fails
                logger.info(f"Falling back to individual processing for chunk {chunk_index}")
                for file_info in chunk['files']:
                    try:
                        findings = self.analyze_solidity_code(
                            file_info['content'], 
                            file_info['name']
                        )
                        # Add file information to findings
                        for finding in findings:
                            finding['file'] = file_info['path']
                            finding['chunk_id'] = chunk_index
                        chunk_findings.extend(findings)
                    except Exception as e:
                        logger.error(f"Error processing file {file_info['path']} in fallback: {e}")
        
        return chunk_findings
    
    def _calculate_severity_breakdown(self, findings: List[Dict]) -> Dict[str, int]:
        """
        Calculate severity breakdown of findings.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary with severity counts
        """
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'medium').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                # Map alternative severity names
                if severity in ['info', 'information']:
                    severity_counts['informational'] += 1
                else:
                    severity_counts['medium'] += 1  # Default to medium
        
        return severity_counts
    
    def analyze_github_repository(self, repo_files: List[str], repo_url: str = None, progress_callback=None) -> Dict[str, Any]:
        """
        Analyze a GitHub repository's Solidity files using chunking.
        
        Args:
            repo_files: List of file paths from the repository
            repo_url: Optional repository URL for metadata
            progress_callback: Optional callback for progress updates
            
        Returns:
            Analysis results
        """
        logger.info(f"Starting GitHub repository analysis for {len(repo_files)} files")
        
        result = self.analyze_multiple_files(repo_files, progress_callback)
        
        # Add repository-specific metadata
        result.update({
            "analysis_type": "github_repository_chunked_audit",
            "repository_url": repo_url,
            "repository_files_total": len(repo_files)
        })
        
        return result
    
    def get_analysis_summary(self, analysis_result: Dict[str, Any]) -> str:
        """
        Generate a human-readable summary of the analysis results.
        
        Args:
            analysis_result: Result from analyze_multiple_files or analyze_github_repository
            
        Returns:
            Formatted summary string
        """
        if not analysis_result or analysis_result.get("status") != "completed":
            return "Analysis failed or incomplete."
        
        total_files = analysis_result.get("total_files", 0)
        total_findings = analysis_result.get("total_findings", 0)
        severity_breakdown = analysis_result.get("severity_breakdown", {})
        processing_time = analysis_result.get("processing_time_seconds", 0)
        chunking_summary = analysis_result.get("chunking_summary", {})
        
        summary_lines = [
            f"🔍 AI Security Audit Summary",
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"📁 Files Analyzed: {total_files}",
            f"🔍 Total Findings: {total_findings}",
            f"⏱️  Processing Time: {processing_time:.1f} seconds",
            f"📦 Chunks Processed: {chunking_summary.get('total_chunks', 0)}",
            "",
            f"🚨 Severity Breakdown:",
            f"   🔴 Critical: {severity_breakdown.get('critical', 0)}",
            f"   🟠 High: {severity_breakdown.get('high', 0)}",
            f"   🟡 Medium: {severity_breakdown.get('medium', 0)}",
            f"   🔵 Low: {severity_breakdown.get('low', 0)}",
            f"   ℹ️  Informational: {severity_breakdown.get('informational', 0)}"
        ]
        
        if chunking_summary.get('oversized_chunks', 0) > 0:
            summary_lines.append(f"⚠️  Oversized Files: {chunking_summary['oversized_chunks']} files required special handling")
        
        return "\n".join(summary_lines) 