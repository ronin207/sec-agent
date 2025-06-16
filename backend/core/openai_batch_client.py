"""
OpenAI Batch Client with Rate Limiting and Exponential Backoff

This module provides a wrapper around the OpenAI client that handles:
- Rate limiting with configurable delays between requests
- Exponential backoff for 429 "Too Many Requests" errors
- Batch processing of multiple chat completion requests
- Support for both direct OpenAI client calls and LangChain integration
"""

import os
import time
import asyncio
from typing import List, Dict, Any, Optional, Union, Callable
from dataclasses import dataclass
import openai
from openai.types.chat import ChatCompletion
import logging

logger = logging.getLogger(__name__)

@dataclass
class ChatCompletionRequest:
    """Represents a single chat completion request"""
    model: str
    messages: List[Dict[str, str]]
    temperature: float = 0.0
    max_tokens: Optional[int] = None
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    stop: Optional[Union[str, List[str]]] = None
    stream: bool = False

@dataclass
class BatchOptions:
    """Configuration options for batch processing"""
    rate_limit_ms: int = 1000  # Default 1 second between requests
    max_retries: int = 5
    initial_backoff_ms: int = 1000
    max_backoff_ms: int = 30000
    backoff_multiplier: float = 2.0
    timeout_seconds: int = 300  # 5 minutes timeout per request

class OpenAIBatchClient:
    """
    Batch client for OpenAI API with rate limiting and retry logic
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the batch client
        
        Args:
            api_key: OpenAI API key (falls back to environment variable)
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key is required")
        
        self.client = openai.OpenAI(api_key=self.api_key)
        self.last_request_time = 0
    
    async def batch_chat_completions(
        self, 
        requests: List[ChatCompletionRequest], 
        options: Optional[BatchOptions] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[ChatCompletion]:
        """
        Process multiple chat completion requests with rate limiting and retry logic
        
        Args:
            requests: List of chat completion requests
            options: Batch processing options
            progress_callback: Optional callback for progress updates (current, total)
            
        Returns:
            List of ChatCompletion responses in the same order as requests
        """
        if not requests:
            return []
        
        options = options or BatchOptions()
        results = []
        
        logger.info(f"Starting batch processing of {len(requests)} requests")
        logger.info(f"Rate limit: {options.rate_limit_ms}ms, Max retries: {options.max_retries}")
        
        for i, request in enumerate(requests):
            if progress_callback:
                progress_callback(i, len(requests))
            
            logger.debug(f"Processing request {i+1}/{len(requests)}")
            
            # Rate limiting: ensure minimum time between requests
            await self._enforce_rate_limit(options.rate_limit_ms)
            
            # Process single request with retry logic
            try:
                response = await self._process_single_request_with_retry(request, options)
                results.append(response)
                logger.debug(f"Request {i+1} completed successfully")
            except Exception as e:
                logger.error(f"Request {i+1} failed after all retries: {e}")
                # You might want to append None or a default response for failed requests
                # depending on your error handling strategy
                raise e
        
        if progress_callback:
            progress_callback(len(requests), len(requests))
        
        logger.info(f"Batch processing completed: {len(results)} successful responses")
        return results
    
    def batch_chat_completions_sync(
        self,
        requests: List[ChatCompletionRequest],
        options: Optional[BatchOptions] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[ChatCompletion]:
        """
        Synchronous version of batch_chat_completions
        
        Args:
            requests: List of chat completion requests
            options: Batch processing options
            progress_callback: Optional callback for progress updates (current, total)
            
        Returns:
            List of ChatCompletion responses in the same order as requests
        """
        if not requests:
            return []
        
        options = options or BatchOptions()
        results = []
        
        logger.info(f"Starting synchronous batch processing of {len(requests)} requests")
        logger.info(f"Rate limit: {options.rate_limit_ms}ms, Max retries: {options.max_retries}")
        
        for i, request in enumerate(requests):
            if progress_callback:
                progress_callback(i, len(requests))
            
            logger.debug(f"Processing request {i+1}/{len(requests)}")
            
            # Rate limiting: ensure minimum time between requests
            self._enforce_rate_limit_sync(options.rate_limit_ms)
            
            # Process single request with retry logic
            try:
                response = self._process_single_request_with_retry_sync(request, options)
                results.append(response)
                logger.debug(f"Request {i+1} completed successfully")
            except Exception as e:
                logger.error(f"Request {i+1} failed after all retries: {e}")
                raise e
        
        if progress_callback:
            progress_callback(len(requests), len(requests))
        
        logger.info(f"Synchronous batch processing completed: {len(results)} successful responses")
        return results
    
    async def _process_single_request_with_retry(
        self, 
        request: ChatCompletionRequest, 
        options: BatchOptions
    ) -> ChatCompletion:
        """
        Process a single request with exponential backoff retry logic
        
        Args:
            request: Single chat completion request
            options: Batch processing options
            
        Returns:
            ChatCompletion response
        """
        last_exception = None
        backoff_ms = options.initial_backoff_ms
        
        for attempt in range(options.max_retries + 1):
            try:
                # Create the request parameters
                request_params = {
                    "model": request.model,
                    "messages": request.messages,
                    "temperature": request.temperature,
                    "max_tokens": request.max_tokens,
                    "top_p": request.top_p,
                    "frequency_penalty": request.frequency_penalty,
                    "presence_penalty": request.presence_penalty,
                    "stop": request.stop,
                    "stream": request.stream,
                }
                
                # Remove None values
                request_params = {k: v for k, v in request_params.items() if v is not None}
                
                # Make the API call
                response = self.client.chat.completions.create(**request_params)
                return response
                
            except openai.RateLimitError as e:
                last_exception = e
                if attempt < options.max_retries:
                    wait_time_ms = min(backoff_ms, options.max_backoff_ms)
                    logger.warning(f"Rate limit hit (attempt {attempt + 1}), waiting {wait_time_ms}ms before retry")
                    await asyncio.sleep(wait_time_ms / 1000.0)
                    backoff_ms = int(backoff_ms * options.backoff_multiplier)
                else:
                    logger.error(f"Rate limit exceeded after {options.max_retries} retries")
                    
            except Exception as e:
                last_exception = e
                logger.error(f"Unexpected error in API call (attempt {attempt + 1}): {e}")
                if attempt < options.max_retries:
                    # For non-rate-limit errors, use a shorter backoff
                    await asyncio.sleep(1.0)
                else:
                    break
        
        # If we get here, all retries failed
        raise last_exception
    
    def _process_single_request_with_retry_sync(
        self, 
        request: ChatCompletionRequest, 
        options: BatchOptions
    ) -> ChatCompletion:
        """
        Synchronous version of _process_single_request_with_retry
        """
        last_exception = None
        backoff_ms = options.initial_backoff_ms
        
        for attempt in range(options.max_retries + 1):
            try:
                # Create the request parameters
                request_params = {
                    "model": request.model,
                    "messages": request.messages,
                    "temperature": request.temperature,
                    "max_tokens": request.max_tokens,
                    "top_p": request.top_p,
                    "frequency_penalty": request.frequency_penalty,
                    "presence_penalty": request.presence_penalty,
                    "stop": request.stop,
                    "stream": request.stream,
                }
                
                # Remove None values
                request_params = {k: v for k, v in request_params.items() if v is not None}
                
                # Make the API call
                response = self.client.chat.completions.create(**request_params)
                return response
                
            except openai.RateLimitError as e:
                last_exception = e
                if attempt < options.max_retries:
                    wait_time_ms = min(backoff_ms, options.max_backoff_ms)
                    logger.warning(f"Rate limit hit (attempt {attempt + 1}), waiting {wait_time_ms}ms before retry")
                    time.sleep(wait_time_ms / 1000.0)
                    backoff_ms = int(backoff_ms * options.backoff_multiplier)
                else:
                    logger.error(f"Rate limit exceeded after {options.max_retries} retries")
                    
            except Exception as e:
                last_exception = e
                logger.error(f"Unexpected error in API call (attempt {attempt + 1}): {e}")
                if attempt < options.max_retries:
                    # For non-rate-limit errors, use a shorter backoff
                    time.sleep(1.0)
                else:
                    break
        
        # If we get here, all retries failed
        raise last_exception
    
    async def _enforce_rate_limit(self, rate_limit_ms: int):
        """
        Enforce rate limiting by waiting if necessary
        
        Args:
            rate_limit_ms: Minimum milliseconds between requests
        """
        current_time = time.time() * 1000  # Convert to milliseconds
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < rate_limit_ms:
            wait_time = (rate_limit_ms - time_since_last) / 1000.0  # Convert back to seconds
            logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            await asyncio.sleep(wait_time)
        
        self.last_request_time = time.time() * 1000
    
    def _enforce_rate_limit_sync(self, rate_limit_ms: int):
        """
        Synchronous version of _enforce_rate_limit
        """
        current_time = time.time() * 1000  # Convert to milliseconds
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < rate_limit_ms:
            wait_time = (rate_limit_ms - time_since_last) / 1000.0  # Convert back to seconds
            logger.debug(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)
        
        self.last_request_time = time.time() * 1000

# Convenience function to create requests from common parameters
def create_chat_completion_request(
    model: str,
    system_message: str,
    user_message: str,
    temperature: float = 0.0,
    max_tokens: Optional[int] = None
) -> ChatCompletionRequest:
    """
    Create a ChatCompletionRequest from common parameters
    
    Args:
        model: Model name (e.g., "gpt-4o", "gpt-4o-mini")
        system_message: System message content
        user_message: User message content
        temperature: Temperature for response generation
        max_tokens: Maximum tokens in response
        
    Returns:
        ChatCompletionRequest object
    """
    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message}
    ]
    
    return ChatCompletionRequest(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens
    )

# Global instance for easy access
_global_batch_client = None

def get_batch_client(api_key: Optional[str] = None) -> OpenAIBatchClient:
    """
    Get or create a global batch client instance
    
    Args:
        api_key: OpenAI API key (falls back to environment variable)
        
    Returns:
        OpenAIBatchClient instance
    """
    global _global_batch_client
    if _global_batch_client is None or (api_key and api_key != _global_batch_client.api_key):
        _global_batch_client = OpenAIBatchClient(api_key)
    return _global_batch_client 