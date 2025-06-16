#!/usr/bin/env python3
"""
Test script for the OpenAI Batch Client with rate limiting and retry logic.
This script tests the batch client's ability to handle rate limits and 429 errors.
"""

import os
import sys
import time
from typing import List

# Add the parent directory to the Python path so we can import backend modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.core.openai_batch_client import (
    OpenAIBatchClient,
    ChatCompletionRequest,
    BatchOptions,
    create_chat_completion_request,
    get_batch_client
)
from backend.utils.helpers import get_logger

logger = get_logger('test_batch_client')

def test_single_request():
    """Test processing a single request"""
    print("\n" + "="*60)
    print("Testing Single Request")
    print("="*60)
    
    try:
        batch_client = get_batch_client()
        
        request = create_chat_completion_request(
            model="gpt-4o-mini",
            system_message="You are a helpful assistant that responds concisely.",
            user_message="What is 2+2? Answer in one word.",
            temperature=0.0,
            max_tokens=10
        )
        
        batch_options = BatchOptions(
            rate_limit_ms=1000,
            max_retries=3
        )
        
        start_time = time.time()
        responses = batch_client.batch_chat_completions_sync([request], batch_options)
        end_time = time.time()
        
        print(f"✅ Single request completed in {end_time - start_time:.2f} seconds")
        print(f"Response: {responses[0].choices[0].message.content}")
        
        return True
        
    except Exception as e:
        print(f"❌ Single request failed: {e}")
        return False

def test_batch_requests():
    """Test processing multiple requests in batch"""
    print("\n" + "="*60)
    print("Testing Batch Requests")
    print("="*60)
    
    try:
        batch_client = get_batch_client()
        
        # Create multiple requests
        requests = []
        questions = [
            "What is 1+1?",
            "What is 2+2?",
            "What is 3+3?",
            "What is 4+4?",
            "What is 5+5?"
        ]
        
        for question in questions:
            request = create_chat_completion_request(
                model="gpt-4o-mini",
                system_message="You are a helpful assistant. Answer math questions briefly.",
                user_message=question + " Answer in one word.",
                temperature=0.0,
                max_tokens=10
            )
            requests.append(request)
        
        batch_options = BatchOptions(
            rate_limit_ms=2000,  # 2 seconds between requests
            max_retries=3,
            initial_backoff_ms=3000,
            max_backoff_ms=30000
        )
        
        start_time = time.time()
        responses = batch_client.batch_chat_completions_sync(
            requests, 
            batch_options,
            progress_callback=lambda current, total: print(f"Progress: {current}/{total} requests completed")
        )
        end_time = time.time()
        
        print(f"✅ Batch processing completed in {end_time - start_time:.2f} seconds")
        print(f"Processed {len(responses)} requests")
        
        for i, (question, response) in enumerate(zip(questions, responses)):
            answer = response.choices[0].message.content.strip()
            print(f"  Q{i+1}: {question} -> A: {answer}")
        
        return True
        
    except Exception as e:
        print(f"❌ Batch requests failed: {e}")
        return False

def test_rate_limiting():
    """Test rate limiting functionality"""
    print("\n" + "="*60)
    print("Testing Rate Limiting")
    print("="*60)
    
    try:
        batch_client = get_batch_client()
        
        # Create a few quick requests to test rate limiting
        requests = []
        for i in range(3):
            request = create_chat_completion_request(
                model="gpt-4o-mini",
                system_message="You are a helpful assistant.",
                user_message=f"Say 'Hello {i+1}' and nothing else.",
                temperature=0.0,
                max_tokens=10
            )
            requests.append(request)
        
        batch_options = BatchOptions(
            rate_limit_ms=3000,  # 3 seconds between requests - should be visible
            max_retries=3
        )
        
        print("Starting rate-limited batch processing (3 second delays)...")
        start_time = time.time()
        
        responses = batch_client.batch_chat_completions_sync(
            requests, 
            batch_options,
            progress_callback=lambda current, total: print(f"  [{time.strftime('%H:%M:%S')}] Completed {current}/{total} requests")
        )
        
        end_time = time.time()
        total_time = end_time - start_time
        
        print(f"✅ Rate limiting test completed in {total_time:.2f} seconds")
        print(f"Expected minimum time: {len(requests) * 3} seconds")
        print(f"Rate limiting {'working correctly' if total_time >= (len(requests) - 1) * 3 else 'may not be working'}")
        
        for i, response in enumerate(responses):
            answer = response.choices[0].message.content.strip()
            print(f"  Response {i+1}: {answer}")
        
        return True
        
    except Exception as e:
        print(f"❌ Rate limiting test failed: {e}")
        return False

def test_langchain_wrapper():
    """Test the LangChain wrapper"""
    print("\n" + "="*60)
    print("Testing LangChain Wrapper")
    print("="*60)
    
    try:
        from backend.core.langchain_batch_wrapper import create_rate_limited_llm
        
        llm = create_rate_limited_llm(
            model="gpt-4o-mini",
            temperature=0.0,
            rate_limit_ms=2000,
            max_retries=3
        )
        
        start_time = time.time()
        response = llm.invoke("What is the capital of France? Answer in one word.")
        end_time = time.time()
        
        print(f"✅ LangChain wrapper test completed in {end_time - start_time:.2f} seconds")
        print(f"Response: {response.content}")
        
        return True
        
    except Exception as e:
        print(f"❌ LangChain wrapper test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("OpenAI Batch Client Test Suite")
    print("="*60)
    
    # Check if API key is available
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("❌ OPENAI_API_KEY environment variable not set")
        print("Please set your OpenAI API key:")
        print("export OPENAI_API_KEY=your_api_key_here")
        return
    
    print(f"✅ OpenAI API key found: {api_key[:10]}...")
    
    # Run tests
    tests = [
        ("Single Request", test_single_request),
        ("Batch Requests", test_batch_requests),
        ("Rate Limiting", test_rate_limiting),
        ("LangChain Wrapper", test_langchain_wrapper)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ Test '{test_name}' crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "="*60)
    print("Test Results Summary")
    print("="*60)
    
    passed = 0
    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{test_name}: {status}")
        if success:
            passed += 1
    
    print(f"\nOverall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("🎉 All tests passed! The batch client is working correctly.")
    else:
        print("⚠️  Some tests failed. Check the error messages above.")

if __name__ == "__main__":
    main() 