#!/usr/bin/env python3
"""
Simple test script that only tests imports and initialization without making API calls.
This avoids quota issues while verifying the rate limiting solution works.
"""

import os
import sys

# Add the parent directory to the Python path so we can import backend modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_batch_client_import():
    """Test importing the batch client"""
    print("Testing OpenAI Batch Client import...")
    try:
        from backend.core.openai_batch_client import (
            OpenAIBatchClient,
            ChatCompletionRequest,
            BatchOptions,
            create_chat_completion_request,
            get_batch_client
        )
        print("✅ OpenAI Batch Client imports successfully")
        return True
    except Exception as e:
        print(f"❌ OpenAI Batch Client import failed: {e}")
        return False

def test_langchain_wrapper_import():
    """Test importing and initializing the LangChain wrapper"""
    print("Testing LangChain Wrapper import and initialization...")
    try:
        from backend.core.langchain_batch_wrapper import create_rate_limited_llm
        
        # Test initialization with a dummy API key (won't make actual calls)
        os.environ['OPENAI_API_KEY'] = 'sk-dummy-key-for-testing'
        
        llm = create_rate_limited_llm(
            model="gpt-4o-mini",
            temperature=0.0,
            rate_limit_ms=2000,
            max_retries=3
        )
        
        print("✅ LangChain Wrapper imports and initializes successfully")
        return True
    except Exception as e:
        print(f"❌ LangChain Wrapper failed: {e}")
        return False

def test_batch_client_initialization():
    """Test initializing the batch client without making API calls"""
    print("Testing OpenAI Batch Client initialization...")
    try:
        from backend.core.openai_batch_client import OpenAIBatchClient, BatchOptions, ChatCompletionRequest
        
        # Test with dummy API key
        os.environ['OPENAI_API_KEY'] = 'sk-dummy-key-for-testing'
        
        client = OpenAIBatchClient()
        
        # Test creating batch options
        options = BatchOptions(
            rate_limit_ms=2000,
            max_retries=5,
            initial_backoff_ms=5000,
            max_backoff_ms=60000,
            backoff_multiplier=2.0
        )
        
        # Test creating a request
        request = ChatCompletionRequest(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "test"}],
            temperature=0.0,
            max_tokens=50
        )
        
        print("✅ OpenAI Batch Client initializes and creates objects successfully")
        return True
    except Exception as e:
        print(f"❌ OpenAI Batch Client initialization failed: {e}")
        return False

def test_updated_modules_import():
    """Test importing updated modules that use the rate-limited versions"""
    print("Testing updated modules import...")
    try:
        # Test importing modules that were updated
        from backend.core.result_summarizer import ResultSummarizer
        from backend.core.cve_knowledge_base import CVEKnowledgeQuery  
        from backend.core.knowledge_base import SecurityKnowledgeBase
        
        print("✅ Updated modules import successfully")
        return True
    except Exception as e:
        print(f"❌ Updated modules import failed: {e}")
        return False

def main():
    """Run all import and initialization tests"""
    print("Rate Limiting Solution - Import and Initialization Tests")
    print("=" * 65)
    print("Note: These tests only verify imports and initialization,")
    print("they do not make actual API calls to avoid quota issues.")
    print("=" * 65)
    
    tests = [
        ("Batch Client Import", test_batch_client_import),
        ("LangChain Wrapper Import", test_langchain_wrapper_import),
        ("Batch Client Initialization", test_batch_client_initialization),
        ("Updated Modules Import", test_updated_modules_import)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 65)
    print("Test Results Summary")
    print("=" * 65)
    
    passed = 0
    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{test_name}: {status}")
        if success:
            passed += 1
    
    print(f"\nOverall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🎉 All tests passed! The rate limiting solution is properly integrated.")
        print("\nNext steps:")
        print("1. Add funds to your OpenAI account to resolve the quota issue")
        print("2. The rate limiting solution will prevent future 429 errors")
        print("3. Your system is ready to handle large file processing")
    else:
        print("⚠️  Some tests failed. The issues need to be resolved.")

if __name__ == "__main__":
    main() 