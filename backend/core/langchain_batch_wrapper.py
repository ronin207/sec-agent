"""
LangChain Batch Wrapper with Rate Limiting

This module provides a wrapper around LangChain's ChatOpenAI that uses
the batch client for rate limiting and retry logic.
"""

import os
import time
from typing import List, Dict, Any, Optional, Union
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, AIMessage
from langchain_core.language_models.base import BaseLanguageModel
from langchain_openai import ChatOpenAI
from backend.core.openai_batch_client import (
    get_batch_client, 
    create_chat_completion_request, 
    BatchOptions,
    ChatCompletionRequest
)
from backend.utils.helpers import get_logger

logger = get_logger('langchain_batch_wrapper')

class RateLimitedChatOpenAI(ChatOpenAI):
    """
    ChatOpenAI wrapper that uses the batch client for rate limiting
    """
    
    def __init__(self, 
                 model: str = "gpt-4o-mini", 
                 temperature: float = 0.0,
                 api_key: Optional[str] = None,
                 rate_limit_ms: int = 2000,
                 max_retries: int = 5,
                 **kwargs):
        """
        Initialize the rate-limited ChatOpenAI wrapper
        
        Args:
            model: Model name
            temperature: Temperature for generation
            api_key: OpenAI API key
            rate_limit_ms: Rate limit in milliseconds
            max_retries: Maximum number of retries
            **kwargs: Additional arguments for ChatOpenAI
        """
        # Initialize the parent class first
        super().__init__(
            model=model,
            temperature=temperature,
            api_key=api_key or os.environ.get("OPENAI_API_KEY"),
            **kwargs
        )
        
        # Store batch client configuration directly in __dict__ to bypass Pydantic validation
        object.__setattr__(self, '_rate_limit_config', {
            'rate_limit_ms': rate_limit_ms,
            'max_retries': max_retries,
            'batch_client': get_batch_client(self.openai_api_key)
        })
        
        logger.info(f"Initialized RateLimitedChatOpenAI with {model}, rate_limit={rate_limit_ms}ms")
    
    def invoke(self, input, config=None, **kwargs):
        """
        Invoke the model with rate limiting
        
        Args:
            input: Input messages or prompt
            config: Configuration
            **kwargs: Additional arguments
            
        Returns:
            AIMessage response
        """
        try:
            # Get configuration
            rate_config = object.__getattribute__(self, '_rate_limit_config')
            
            # Convert input to messages
            if isinstance(input, str):
                messages = [{"role": "user", "content": input}]
            elif isinstance(input, list):
                messages = self._convert_langchain_messages_to_openai(input)
            else:
                # Handle other input types
                messages = [{"role": "user", "content": str(input)}]
            
            # Create batch request
            request = ChatCompletionRequest(
                model=self.model_name,
                messages=messages,
                temperature=self.temperature,
                max_tokens=getattr(self, 'max_tokens', None),
                top_p=getattr(self, 'top_p', 1.0),
                frequency_penalty=getattr(self, 'frequency_penalty', 0.0),
                presence_penalty=getattr(self, 'presence_penalty', 0.0)
            )
            
            # Configure batch options
            batch_options = BatchOptions(
                rate_limit_ms=rate_config['rate_limit_ms'],
                max_retries=rate_config['max_retries'],
                initial_backoff_ms=5000,
                max_backoff_ms=60000,
                backoff_multiplier=2.0
            )
            
            # Process single request using batch client
            responses = rate_config['batch_client'].batch_chat_completions_sync([request], batch_options)
            response = responses[0]
            
            # Convert back to LangChain format
            content = response.choices[0].message.content
            return AIMessage(content=content)
            
        except Exception as e:
            logger.error(f"Error in RateLimitedChatOpenAI.invoke: {e}")
            # Fallback to parent implementation
            return super().invoke(input, config, **kwargs)
    
    def _convert_langchain_messages_to_openai(self, messages: List[BaseMessage]) -> List[Dict[str, str]]:
        """
        Convert LangChain messages to OpenAI format
        
        Args:
            messages: List of LangChain messages
            
        Returns:
            List of OpenAI message dictionaries
        """
        openai_messages = []
        
        for message in messages:
            if isinstance(message, SystemMessage):
                openai_messages.append({"role": "system", "content": message.content})
            elif isinstance(message, HumanMessage):
                openai_messages.append({"role": "user", "content": message.content})
            elif isinstance(message, AIMessage):
                openai_messages.append({"role": "assistant", "content": message.content})
            else:
                # Default to user message
                openai_messages.append({"role": "user", "content": str(message.content)})
        
        return openai_messages

def create_rate_limited_llm(
    model: str = "gpt-4o-mini",
    temperature: float = 0.0,
    api_key: Optional[str] = None,
    rate_limit_ms: int = 1500,
    max_retries: int = 5
) -> RateLimitedChatOpenAI:
    """
    Create a rate-limited ChatOpenAI instance
    
    Args:
        model: Model name
        temperature: Temperature for generation
        api_key: OpenAI API key
        rate_limit_ms: Rate limit in milliseconds
        max_retries: Maximum number of retries
        
    Returns:
        RateLimitedChatOpenAI instance
    """
    return RateLimitedChatOpenAI(
        model=model,
        temperature=temperature,
        api_key=api_key,
        rate_limit_ms=rate_limit_ms,
        max_retries=max_retries
    ) 