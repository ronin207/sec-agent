# SPDX-FileCopyrightText: 2025 Security Agent
# SPDX-License-Identifier: GPL-3.0

"""
Chunking Manager for handling large file processing with token limits.
Implements the chunking strategy described in the user requirements.
"""

import os
import json
import time
from typing import List, Dict, Any, Tuple
from pathlib import Path
import tiktoken
from backend.utils.helpers import get_logger

logger = get_logger('chunking_manager')

class ChunkingManager:
    """
    Manages chunking of Solidity files for AI audit analysis to stay within token limits.
    """
    
    def __init__(self, model_name: str = "gpt-4o-mini", max_tokens_per_chunk: int = 60000):
        """
        Initialize the chunking manager.
        
        Args:
            model_name: The model name for token counting
            max_tokens_per_chunk: Maximum tokens per chunk (reduced for rate limit compliance)
        """
        self.model_name = model_name
        self.max_tokens_per_chunk = max_tokens_per_chunk
        self.encoding = tiktoken.encoding_for_model("gpt-4")  # Use gpt-4 encoding as fallback
        
        # Conservative settings for rate limit compliance
        # gpt-4o-mini has 30,000 tokens/minute rate limit
        # Reduced base limit to 60k total, with 15k reserved for system prompt
        self.reserved_tokens = 15000  # Conservative but reasonable
        self.effective_max_tokens = max_tokens_per_chunk - self.reserved_tokens
        
        logger.info(f"ChunkingManager initialized for {model_name} with {self.effective_max_tokens} effective tokens per chunk")
    
    def count_tokens(self, text: str) -> int:
        """Count tokens in a text string."""
        try:
            return len(self.encoding.encode(text))
        except Exception as e:
            logger.warning(f"Error counting tokens: {e}, using character-based estimation")
            # Fallback: rough estimation (1 token ≈ 4 characters)
            return len(text) // 4
    
    def chunk_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Chunk files into groups that fit within token limits.
        
        Args:
            file_paths: List of file paths to chunk
            
        Returns:
            List of chunks, each containing file information and metadata
        """
        logger.info(f"Chunking {len(file_paths)} files for processing")
        
        chunks = []
        current_chunk = {
            "files": [],
            "total_tokens": 0,
            "chunk_id": 0
        }
        
        for file_path in file_paths:
            try:
                # Read file content
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Count tokens for this file
                file_tokens = self.count_tokens(content)
                file_info = {
                    "path": file_path,
                    "content": content,
                    "tokens": file_tokens,
                    "size_bytes": len(content.encode('utf-8')),
                    "name": os.path.basename(file_path)
                }
                
                # Check if this single file exceeds the limit
                if file_tokens > self.effective_max_tokens:
                    logger.warning(f"File {file_path} ({file_tokens} tokens) exceeds chunk limit, will be processed separately")
                    
                    # If current chunk has files, finalize it
                    if current_chunk["files"]:
                        chunks.append(current_chunk)
                        current_chunk = {
                            "files": [],
                            "total_tokens": 0,
                            "chunk_id": len(chunks)
                        }
                    
                    # Create a chunk for this large file alone
                    large_file_chunk = {
                        "files": [file_info],
                        "total_tokens": file_tokens,
                        "chunk_id": len(chunks),
                        "is_oversized": True
                    }
                    chunks.append(large_file_chunk)
                    
                    # Reset current chunk
                    current_chunk = {
                        "files": [],
                        "total_tokens": 0,
                        "chunk_id": len(chunks)
                    }
                    continue
                
                # Check if adding this file would exceed the limit
                if current_chunk["total_tokens"] + file_tokens > self.effective_max_tokens:
                    # Finalize current chunk
                    if current_chunk["files"]:
                        chunks.append(current_chunk)
                    
                    # Start new chunk
                    current_chunk = {
                        "files": [file_info],
                        "total_tokens": file_tokens,
                        "chunk_id": len(chunks)
                    }
                else:
                    # Add to current chunk
                    current_chunk["files"].append(file_info)
                    current_chunk["total_tokens"] += file_tokens
                    
            except Exception as e:
                logger.error(f"Error processing file {file_path}: {e}")
                continue
        
        # Add the last chunk if it has files
        if current_chunk["files"]:
            chunks.append(current_chunk)
        
        logger.info(f"Created {len(chunks)} chunks from {len(file_paths)} files")
        
        # Log chunk statistics
        for i, chunk in enumerate(chunks):
            file_count = len(chunk["files"])
            tokens = chunk["total_tokens"]
            oversized = chunk.get("is_oversized", False)
            logger.info(f"Chunk {i}: {file_count} files, {tokens} tokens{' (OVERSIZED)' if oversized else ''}")
        
        return chunks
    
    def chunk_large_file(self, file_path: str, max_lines_per_chunk: int = 500) -> List[Dict[str, Any]]:
        """
        Chunk a single large file into smaller pieces based on contracts or functions.
        
        Args:
            file_path: Path to the large file
            max_lines_per_chunk: Maximum lines per chunk
            
        Returns:
            List of file chunks
        """
        logger.info(f"Chunking large file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            chunks = []
            current_chunk_lines = []
            current_contract = None
            brace_count = 0
            
            for i, line in enumerate(lines):
                current_chunk_lines.append(line)
                
                # Track contract boundaries
                if line.strip().startswith('contract ') or line.strip().startswith('interface ') or line.strip().startswith('library '):
                    if current_chunk_lines and len(current_chunk_lines) > 1:
                        # Finalize previous chunk
                        chunk_content = ''.join(current_chunk_lines[:-1])
                        if chunk_content.strip():
                            chunks.append({
                                "path": file_path,
                                "content": chunk_content,
                                "tokens": self.count_tokens(chunk_content),
                                "chunk_index": len(chunks),
                                "start_line": max(1, i - len(current_chunk_lines) + 2),
                                "end_line": i,
                                "name": f"{os.path.basename(file_path)}_chunk_{len(chunks)}"
                            })
                        current_chunk_lines = [line]
                    current_contract = line.strip()
                    brace_count = 0
                
                # Track braces to detect contract end
                brace_count += line.count('{') - line.count('}')
                
                # If we've reached max lines or completed a contract, create a chunk
                if (len(current_chunk_lines) >= max_lines_per_chunk or 
                    (brace_count == 0 and current_contract and len(current_chunk_lines) > 10)):
                    
                    chunk_content = ''.join(current_chunk_lines)
                    if chunk_content.strip():
                        chunks.append({
                            "path": file_path,
                            "content": chunk_content,
                            "tokens": self.count_tokens(chunk_content),
                            "chunk_index": len(chunks),
                            "start_line": max(1, i - len(current_chunk_lines) + 1),
                            "end_line": i + 1,
                            "name": f"{os.path.basename(file_path)}_chunk_{len(chunks)}"
                        })
                    current_chunk_lines = []
                    current_contract = None
            
            # Add remaining lines as final chunk
            if current_chunk_lines:
                chunk_content = ''.join(current_chunk_lines)
                if chunk_content.strip():
                    chunks.append({
                        "path": file_path,
                        "content": chunk_content,
                        "tokens": self.count_tokens(chunk_content),
                        "chunk_index": len(chunks),
                        "start_line": max(1, len(lines) - len(current_chunk_lines) + 1),
                        "end_line": len(lines),
                        "name": f"{os.path.basename(file_path)}_chunk_{len(chunks)}"
                    })
            
            logger.info(f"Split {file_path} into {len(chunks)} chunks")
            return chunks
            
        except Exception as e:
            logger.error(f"Error chunking large file {file_path}: {e}")
            return []
    
    def merge_chunk_results(self, chunk_results: List[List[Dict]]) -> List[Dict]:
        """
        Merge results from multiple chunks, removing duplicates.
        
        Args:
            chunk_results: List of results from each chunk
            
        Returns:
            Merged and deduplicated results
        """
        logger.info(f"Merging results from {len(chunk_results)} chunks")
        
        all_findings = []
        seen_findings = set()
        
        for chunk_result in chunk_results:
            if not chunk_result:
                continue
                
            for finding in chunk_result:
                # Create a unique key for deduplication
                finding_key = (
                    finding.get('type', ''),
                    finding.get('description', ''),
                    finding.get('location', ''),
                    finding.get('severity', '')
                )
                
                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    all_findings.append(finding)
                else:
                    logger.debug(f"Removed duplicate finding: {finding.get('type', 'Unknown')}")
        
        logger.info(f"Merged {sum(len(cr) for cr in chunk_results)} findings into {len(all_findings)} unique findings")
        return all_findings
    
    def estimate_processing_time(self, chunks: List[Dict]) -> float:
        """
        Estimate total processing time for all chunks.
        
        Args:
            chunks: List of chunks to process
            
        Returns:
            Estimated time in seconds
        """
        # Rough estimation: 2-5 seconds per chunk depending on size
        base_time_per_chunk = 3.0
        total_time = 0
        
        for chunk in chunks:
            chunk_time = base_time_per_chunk
            if chunk.get("is_oversized"):
                chunk_time *= 2  # Oversized chunks take longer
            total_time += chunk_time
        
        return total_time
    
    def get_chunk_summary(self, chunks: List[Dict]) -> Dict[str, Any]:
        """
        Get a summary of the chunking results.
        
        Args:
            chunks: List of chunks
            
        Returns:
            Summary information
        """
        total_files = sum(len(chunk["files"]) for chunk in chunks)
        total_tokens = sum(chunk["total_tokens"] for chunk in chunks)
        oversized_chunks = sum(1 for chunk in chunks if chunk.get("is_oversized", False))
        
        return {
            "total_chunks": len(chunks),
            "total_files": total_files,
            "total_tokens": total_tokens,
            "oversized_chunks": oversized_chunks,
            "estimated_processing_time": self.estimate_processing_time(chunks),
            "average_tokens_per_chunk": total_tokens / len(chunks) if chunks else 0,
            "max_tokens_per_chunk": self.effective_max_tokens
        } 