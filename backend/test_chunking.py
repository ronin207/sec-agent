#!/usr/bin/env python3
"""
Test script for the chunking system.
Tests the ChunkingManager and ChunkedAIAuditAnalyzer with the cached Solidity files.
"""

import os
import sys
import time
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir.parent))

from backend.core.chunking_manager import ChunkingManager
from backend.core.chunked_ai_audit_analyzer import ChunkedAIAuditAnalyzer
from backend.utils.helpers import get_logger

logger = get_logger('test_chunking')

def test_chunking_manager():
    """Test the ChunkingManager with cached files."""
    logger.info("Testing ChunkingManager...")
    
    # Get cached Solidity files
    cached_files_dir = Path(__file__).parent.parent / "cached_files"
    if not cached_files_dir.exists():
        logger.error(f"Cached files directory not found: {cached_files_dir}")
        return False
    
    # Find all .sol files
    sol_files = list(cached_files_dir.glob("*.sol"))
    if not sol_files:
        logger.error("No Solidity files found in cached_files directory")
        return False
    
    logger.info(f"Found {len(sol_files)} Solidity files")
    
    # Test chunking
    chunking_manager = ChunkingManager(model_name="gpt-4o-mini")
    
    # Convert Path objects to strings
    file_paths = [str(f) for f in sol_files]
    
    # Create chunks
    chunks = chunking_manager.chunk_files(file_paths)
    
    # Get summary
    summary = chunking_manager.get_chunk_summary(chunks)
    
    logger.info(f"Chunking results:")
    logger.info(f"  Total chunks: {summary['total_chunks']}")
    logger.info(f"  Total files: {summary['total_files']}")
    logger.info(f"  Total tokens: {summary['total_tokens']}")
    logger.info(f"  Oversized chunks: {summary['oversized_chunks']}")
    logger.info(f"  Estimated processing time: {summary['estimated_processing_time']:.1f} seconds")
    
    return True

def test_chunked_analyzer():
    """Test the ChunkedAIAuditAnalyzer with a subset of files."""
    logger.info("Testing ChunkedAIAuditAnalyzer...")
    
    # Get cached Solidity files
    cached_files_dir = Path(__file__).parent.parent / "cached_files"
    if not cached_files_dir.exists():
        logger.error(f"Cached files directory not found: {cached_files_dir}")
        return False
    
    # Find all .sol files and take first 5 for testing
    sol_files = list(cached_files_dir.glob("*.sol"))[:5]
    if not sol_files:
        logger.error("No Solidity files found in cached_files directory")
        return False
    
    logger.info(f"Testing with {len(sol_files)} Solidity files")
    
    # Test chunked analysis
    analyzer = ChunkedAIAuditAnalyzer(model_name="gpt-4o-mini")
    
    # Convert Path objects to strings
    file_paths = [str(f) for f in sol_files]
    
    # Note: This would make actual API calls to OpenAI
    # For testing without API calls, we'll just test the chunking logic
    logger.info("Note: Skipping actual AI analysis to avoid API costs")
    logger.info("Testing chunking logic only...")
    
    # Test just the chunking part
    chunks = analyzer.chunking_manager.chunk_files(file_paths)
    summary = analyzer.chunking_manager.get_chunk_summary(chunks)
    
    logger.info(f"Chunked analyzer results:")
    logger.info(f"  Would process {summary['total_chunks']} chunks")
    logger.info(f"  Covering {summary['total_files']} files")
    logger.info(f"  With {summary['total_tokens']} total tokens")
    
    return True

def main():
    """Run all tests."""
    logger.info("Starting chunking system tests...")
    
    success = True
    
    # Test 1: ChunkingManager
    try:
        if not test_chunking_manager():
            success = False
    except Exception as e:
        logger.error(f"ChunkingManager test failed: {e}")
        success = False
    
    # Test 2: ChunkedAIAuditAnalyzer
    try:
        if not test_chunked_analyzer():
            success = False
    except Exception as e:
        logger.error(f"ChunkedAIAuditAnalyzer test failed: {e}")
        success = False
    
    if success:
        logger.info("All tests passed! ✅")
        return 0
    else:
        logger.error("Some tests failed! ❌")
        return 1

if __name__ == "__main__":
    exit(main()) 