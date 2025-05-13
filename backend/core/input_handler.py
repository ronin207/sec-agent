"""
Input handler module for the Security Agent.
Validates and classifies user input (website URL or Solidity contract).
"""
import os
import re
from typing import Dict, Literal, Union
import requests
from urllib.parse import urlparse

class InputHandler:
    """
    Validates and classifies user input as either a website URL or Solidity contract.
    """
    
    def __init__(self):
        pass
    
    def validate_and_classify(self, user_input: str) -> Dict:
        """
        Validate the user input and classify it as a website URL or Solidity contract.
        
        Args:
            user_input: Either a URL or a path to a Solidity contract file or a GitHub repository URL
            
        Returns:
            Dictionary containing the input type and the validated input
        """
        # Sanitize the input
        user_input = user_input.strip()
        
        # Check if it's a URL
        is_url = self._is_valid_url(user_input)
        
        if is_url:
            # Determine if it's a website URL or a GitHub repo URL with Solidity code
            if self._is_github_repo(user_input) and self._repo_contains_solidity(user_input):
                return {
                    "type": "solidity_contract",
                    "input": user_input,
                    "source": "github"
                }
            else:
                # Assume it's a regular website URL
                return {
                    "type": "website",
                    "input": user_input,
                    "source": "url"
                }
        
        # Check if it's a local Solidity file
        elif self._is_solidity_file(user_input):
            return {
                "type": "solidity_contract",
                "input": user_input,
                "source": "local_file"
            }
        
        # If it's not a recognized input type, return an error
        return {
            "type": "error",
            "message": "Invalid input format. Please provide a valid website URL or Solidity contract file/URL."
        }
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if the input is a valid URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _is_github_repo(self, url: str) -> bool:
        """Check if the URL is a GitHub repository"""
        github_pattern = r"https?://github\.com/[\w-]+/[\w-]+"
        return bool(re.match(github_pattern, url))
    
    def _repo_contains_solidity(self, repo_url: str) -> bool:
        """
        Check if the GitHub repository contains Solidity files (very basic check)
        In a real implementation, this would do a more thorough check
        """
        # Convert github.com URL to raw.githubusercontent.com for API access
        api_url = repo_url.replace("github.com", "api.github.com/repos") + "/contents"
        
        try:
            response = requests.get(api_url)
            if response.status_code != 200:
                return False
            
            # Check if any files have a .sol extension
            contents = response.json()
            for item in contents:
                if item.get("name", "").endswith(".sol"):
                    return True
                    
            return False
        except:
            # If there's any error, assume it's not a Solidity repo
            return False
    
    def _is_solidity_file(self, file_path: str) -> bool:
        """Check if the input is a path to a Solidity file"""
        if not os.path.isfile(file_path):
            return False
        
        return file_path.endswith(".sol") 