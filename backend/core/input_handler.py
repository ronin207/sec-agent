"""
Input handler module for the Security Agent.
Validates and classifies user input (website URL, Solidity contract, multiple files, or GitHub repositories).
"""
import os
import re
from typing import Dict, Literal, Union, List
import requests
import time
from urllib.parse import urlparse
import glob
import tempfile
import subprocess
from github import Github, RateLimitExceededException
from backend.utils.helpers import get_logger

# Get logger
logger = get_logger('security_agent')

class InputHandler:
    """
    Validates and classifies user input as website URL, Solidity contract, multiple files, or GitHub repository.
    """
    
    def __init__(self):
        self.temp_dir = None
        # Initialize GitHub client with no authentication for public repos
        # For private repos, token can be passed from environment variable
        self.github_token = os.environ.get("GITHUB_TOKEN")
        self.github_client = Github(self.github_token, retry=3, timeout=30) if self.github_token else Github(retry=3, timeout=30)
        self.batch_size = 5  # Number of files to process in each batch
        self.delay_between_batches = 2  # Seconds to wait between batches
    
    def validate_and_classify(self, user_input: str) -> Dict:
        """
        Validate the user input and classify it as a website URL, Solidity contract, multiple files, or GitHub repository.
        
        Args:
            user_input: Either a URL, path to file(s), directory, or GitHub repository URL
            
        Returns:
            Dictionary containing the input type, the validated input, and additional context
        """
        # Sanitize the input
        user_input = user_input.strip()
        
        # Check if it's a URL
        if self._is_valid_url(user_input):
            # Determine if it's a GitHub repo URL
            if self._is_github_repo(user_input):
                # Process the repository using the GitHub API
                return self._process_github_repo(user_input)
            else:
                # Assume it's a regular website URL
                return {
                    "type": "website",
                    "input": user_input,
                    "source": "url",
                    "is_multiple": False
                }
        
        # Check if it's a directory
        elif os.path.isdir(user_input):
            return self._process_directory(user_input)
        
        # Check if it's a glob pattern for multiple files
        elif '*' in user_input or '?' in user_input:
            return self._process_glob_pattern(user_input)
        
        # Check if it's a single Solidity file
        elif self._is_solidity_file(user_input):
            return {
                "type": "solidity_contract",
                "input": user_input,
                "source": "local_file",
                "is_multiple": False
            }
        
        # If it's not a recognized input type, return an error
        return {
            "type": "error",
            "message": "Invalid input format. Please provide a valid website URL, Solidity contract file/URL, directory path, or GitHub repository URL."
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
        github_pattern = r"https?://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
        return bool(re.match(github_pattern, url))
    
    def _get_repo_owner_and_name(self, url: str) -> tuple:
        """Extract owner and repository name from a GitHub URL"""
        github_pattern = r"https?://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)"
        match = re.match(github_pattern, url)
        if match:
            return match.group('owner'), match.group('repo')
        return None, None
    
    def _process_github_repo(self, repo_url: str) -> Dict:
        """
        Process a GitHub repository using the GitHub API instead of cloning
        """
        try:
            logger.info(f"Processing GitHub repository: {repo_url}")
            
            # Extract owner and repo name from the URL
            owner, repo_name = self._get_repo_owner_and_name(repo_url)
            if not owner or not repo_name:
                logger.error(f"Invalid GitHub URL format: {repo_url}")
                return {
                    "type": "error",
                    "message": f"Invalid GitHub URL format: {repo_url}"
                }
            
            # Check remaining rate limit before starting
            rate_limit = self.github_client.get_rate_limit()
            logger.info(f"GitHub API Rate Limit: {rate_limit.core.remaining}/{rate_limit.core.limit} remaining")
            
            if rate_limit.core.remaining < 100:
                reset_time = rate_limit.core.reset.timestamp() - time.time()
                logger.warning(f"Low rate limit remaining. Reset in {reset_time:.0f} seconds")
                
                # If severely limited, suggest using a token or wait
                if rate_limit.core.remaining < 20:
                    if not self.github_token:
                        logger.warning("Rate limit very low. Consider providing a GitHub token using --token")
                    
                    # If extremely low, wait a bit before proceeding
                    if rate_limit.core.remaining < 10:
                        wait_time = min(30, max(5, reset_time/10))  # Wait up to 30 seconds
                        logger.info(f"Waiting {wait_time:.0f} seconds to avoid rate limit errors...")
                        time.sleep(wait_time)
            
            # Get the repository through the API
            try:
                repo = self.github_client.get_repo(f"{owner}/{repo_name}")
                logger.info(f"Successfully accessed repository: {repo.full_name}")
            except RateLimitExceededException:
                logger.error("GitHub API rate limit exceeded")
                return {
                    "type": "error",
                    "message": "GitHub API rate limit exceeded. Try again later or use a GitHub token."
                }
            
            # Create a temporary directory for storing files we want to analyze
            self.temp_dir = tempfile.mkdtemp(prefix="security_agent_")
            logger.info(f"Created temporary directory: {self.temp_dir}")
            
            # Get all files in the repository
            files = []
            solidity_files = []
            file_count = 0
            web_files_count = 0
            
            # Get the root contents
            try:
                contents = repo.get_contents("")
            except RateLimitExceededException:
                logger.error("GitHub API rate limit exceeded when accessing repository content")
                return {
                    "type": "error",
                    "message": "GitHub API rate limit exceeded. Try again later or use a GitHub token."
                }
            
            # Track files to process in batches
            files_to_process = []
            
            # Process all files in the repository recursively with batching
            while contents:
                try:
                    file_content = contents.pop(0)
                    
                    # Process directory
                    if file_content.type == "dir":
                        try:
                            # Add directory contents to our queue
                            dir_contents = repo.get_contents(file_content.path)
                            contents.extend(dir_contents)
                        except RateLimitExceededException:
                            logger.warning(f"Rate limit hit when accessing {file_content.path}. Slowing down...")
                            time.sleep(10)  # Wait 10 seconds
                            try:
                                # Retry once after waiting
                                dir_contents = repo.get_contents(file_content.path)
                                contents.extend(dir_contents)
                            except Exception as e:
                                logger.error(f"Failed to access directory {file_content.path}: {str(e)}")
                                # Continue with what we have
                                continue
                    else:
                        # Only download and process relevant files
                        file_ext = os.path.splitext(file_content.name)[1].lower()
                        if file_ext in ['.sol', '.js', '.ts', '.html', '.css', '.json', '.md']:
                            files_to_process.append(file_content)
                            
                            # Sol files are counted separately for classification
                            if file_ext == '.sol':
                                solidity_files.append(file_content.path)
                            
                            # Process files in batches to avoid rate limits
                            if len(files_to_process) >= self.batch_size:
                                self._process_file_batch(repo, files_to_process, files)
                                files_to_process = []
                                
                                # Add delay between batches to avoid rate limiting
                                time.sleep(self.delay_between_batches)
                
                except RateLimitExceededException:
                    logger.error("GitHub API rate limit exceeded during processing")
                    
                    # Process any remaining files before returning
                    if files_to_process:
                        self._process_file_batch(repo, files_to_process, files)
                    
                    # Return what we have so far with a warning
                    if files:
                        logger.warning(f"Rate limit exceeded. Only {len(files)} files were processed")
                        if any(f.endswith('.sol') for f in files):
                            return {
                                "type": "solidity_contract",
                                "input": repo_url,
                                "files": [f for f in files if f.endswith('.sol')],
                                "source": "github",
                                "repo_url": repo_url,
                                "is_multiple": True,
                                "partial": True,
                                "warning": "GitHub API rate limit exceeded. Analysis is incomplete."
                            }
                        else:
                            return {
                                "type": "web_application",
                                "input": repo_url,
                                "files": files,
                                "source": "github",
                                "repo_url": repo_url,
                                "is_multiple": True,
                                "partial": True,
                                "warning": "GitHub API rate limit exceeded. Analysis is incomplete."
                            }
                    else:
                        return {
                            "type": "error",
                            "message": "GitHub API rate limit exceeded. No files could be processed."
                        }
                        
                except Exception as e:
                    logger.error(f"Error processing repository content: {str(e)}")
                    # Continue with next file
            
            # Process any remaining files
            if files_to_process:
                self._process_file_batch(repo, files_to_process, files)
            
            logger.info(f"Downloaded {len(files)} files for analysis")
            
            # If no relevant files were found
            if not files:
                logger.warning(f"No relevant files found in repository: {repo.full_name}")
                return {
                    "type": "unknown",
                    "input": repo_url,
                    "source": "github",
                    "repo_url": repo_url,
                    "message": "No analyzable files found in the repository."
                }
            
            # Check if any Solidity files were found
            if solidity_files:
                return {
                    "type": "solidity_contract",
                    "input": repo_url,
                    "files": [f for f in files if f.endswith('.sol')],
                    "source": "github",
                    "repo_url": repo_url,
                    "is_multiple": len(solidity_files) > 1
                }
            
            # Otherwise, classify as a web application
            return {
                "type": "web_application",
                "input": repo_url,
                "files": files,
                "source": "github",
                "repo_url": repo_url,
                "is_multiple": len(files) > 1
            }
            
        except Exception as e:
            logger.error(f"Error processing GitHub repository: {str(e)}")
            return {
                "type": "error",
                "message": f"Error processing GitHub repository: {str(e)}"
            }
    
    def _process_file_batch(self, repo, files_to_process, result_files):
        """Process a batch of files from GitHub repository"""
        for file_content in files_to_process:
            try:
                file_path = os.path.join(self.temp_dir, file_content.path)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # Download file content safely
                try:
                    # Get the decoded content with error handling
                    file_data = file_content.decoded_content
                    
                    # Save to the temp directory
                    with open(file_path, 'wb') as f:
                        f.write(file_data)
                    
                    result_files.append(file_path)
                    logger.debug(f"Downloaded: {file_content.path}")
                    
                except RateLimitExceededException:
                    logger.warning(f"Rate limit exceeded when downloading {file_content.path}")
                    time.sleep(5)  # Wait before continuing
                    
                except Exception as e:
                    logger.error(f"Error downloading {file_content.path}: {str(e)}")
            except Exception as e:
                logger.error(f"Error processing file {getattr(file_content, 'path', 'unknown')}: {str(e)}")
    
    def _process_directory(self, directory_path: str, source: str = "local_directory", repo_url: str = None) -> Dict:
        """
        Process a directory to identify files for scanning
        """
        # Check for Solidity files
        solidity_files = glob.glob(os.path.join(directory_path, "**", "*.sol"), recursive=True)
        
        # If Solidity files are found, classify as solidity_contracts
        if solidity_files:
            return {
                "type": "solidity_contract",
                "input": directory_path,
                "files": solidity_files,
                "source": source,
                "repo_url": repo_url,
                "is_multiple": len(solidity_files) > 1
            }
        
        # Otherwise, look for other file types to determine type
        # Check for web application files
        web_files = []
        for ext in ['.html', '.js', '.php', '.py', '.jsx', '.ts', '.tsx']:
            web_files.extend(glob.glob(os.path.join(directory_path, "**", f"*{ext}"), recursive=True))
        
        if web_files:
            return {
                "type": "web_application",
                "input": directory_path,
                "files": web_files,
                "source": source,
                "repo_url": repo_url,
                "is_multiple": len(web_files) > 1
            }
        
        # If no recognized files are found
        return {
            "type": "unknown",
            "input": directory_path,
            "source": source,
            "repo_url": repo_url,
            "message": "No recognizable files found for security scanning."
        }
    
    def _process_glob_pattern(self, glob_pattern: str) -> Dict:
        """
        Process a glob pattern to find matching files
        """
        matching_files = glob.glob(glob_pattern, recursive=True)
        
        if not matching_files:
            return {
                "type": "error",
                "message": f"No files match the pattern: {glob_pattern}"
            }
        
        # Check for Solidity files
        solidity_files = [f for f in matching_files if f.endswith('.sol')]
        
        if solidity_files:
            return {
                "type": "solidity_contract",
                "input": glob_pattern,
                "files": solidity_files,
                "source": "local_files",
                "is_multiple": len(solidity_files) > 1
            }
        
        # Otherwise, assume they're web application files
        return {
            "type": "web_application",
            "input": glob_pattern,
            "files": matching_files,
            "source": "local_files",
            "is_multiple": len(matching_files) > 1
        }
    
    def _is_solidity_file(self, file_path: str) -> bool:
        """Check if the input is a path to a Solidity file"""
        if not os.path.isfile(file_path):
            return False
        
        return file_path.endswith(".sol")
    
    def cleanup(self):
        """Clean up any temporary directories created during processing"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            import shutil
            try:
                shutil.rmtree(self.temp_dir)
                self.temp_dir = None
            except Exception as e:
                logger.error(f"Error cleaning up temporary directory: {str(e)}")

    def validate_multiple_inputs(self, inputs: List[str], recursive: bool = False) -> Dict:
        """
        Process multiple inputs (files, URLs, directories) and classify them.
        
        Args:
            inputs: List of inputs to process
            recursive: Whether to scan directories recursively
            
        Returns:
            Dictionary containing classified inputs
        """
        logger.info(f"Processing {len(inputs)} inputs with recursive={recursive}")
        
        # If it's a single directory and recursive is True, expand it to all relevant files
        if len(inputs) == 1 and os.path.isdir(inputs[0]) and recursive:
            return self._process_directory(inputs[0], recursive=True)
        
        # Process each input individually
        files = []
        input_types = set()
        errors = []
        
        for user_input in inputs:
            # Sanitize the input
            user_input = user_input.strip()
            
            # Validate and classify the input
            result = self.validate_and_classify(user_input)
            
            if result.get('type') == 'error':
                errors.append(result.get('message'))
                continue
            
            # Add the input type to the set
            input_types.add(result.get('type'))
            
            # Handle multiple files (directory or glob pattern)
            if result.get('is_multiple') and result.get('files'):
                files.extend(result.get('files'))
            else:
                files.append(user_input)
        
        # If all inputs resulted in errors
        if len(errors) == len(inputs):
            return {
                "type": "error",
                "message": "All inputs are invalid. Errors: " + "; ".join(errors)
            }
        
        # If mixed input types, prioritize by specificity
        if len(input_types) > 1:
            if 'solidity_contract' in input_types:
                primary_type = 'solidity_contract'
                # Filter only Solidity files
                files = [f for f in files if f.endswith('.sol') or (self._is_valid_url(f) and self._is_github_repo(f))]
            elif 'web_application' in input_types:
                primary_type = 'web_application'
            elif 'website' in input_types:
                primary_type = 'website'
            else:
                primary_type = list(input_types)[0]
        else:
            primary_type = list(input_types)[0] if input_types else 'unknown'
        
        return {
            "type": primary_type,
            "input": inputs,
            "files": files,
            "source": "multiple_inputs",
            "is_multiple": True
        }

    def _process_directory(self, directory_path: str, source: str = "local_directory", repo_url: str = None, recursive: bool = False) -> Dict:
        """
        Process a directory to identify files for scanning
        
        Args:
            directory_path: Path to the directory
            source: Source of the directory (local_directory, github)
            repo_url: URL of the GitHub repository, if applicable
            recursive: Whether to scan subdirectories recursively
        
        Returns:
            Dictionary containing classified files
        """
        # Define the recursive flag for glob
        recursion = "**/" if recursive else ""
        
        # Check for Solidity files
        solidity_files = glob.glob(os.path.join(directory_path, f"{recursion}*.sol"), recursive=recursive)
        
        # If Solidity files are found, classify as solidity_contracts
        if solidity_files:
            return {
                "type": "solidity_contract",
                "input": directory_path,
                "files": solidity_files,
                "source": source,
                "repo_url": repo_url,
                "is_multiple": len(solidity_files) > 1
            }
        
        # Otherwise, look for other file types to determine type
        # Check for web application files
        web_files = []
        for ext in ['.html', '.js', '.php', '.py', '.jsx', '.ts', '.tsx', '.css', '.scss', '.json']:
            web_files.extend(glob.glob(os.path.join(directory_path, f"{recursion}*{ext}"), recursive=recursive))
        
        if web_files:
            return {
                "type": "web_application",
                "input": directory_path,
                "files": web_files,
                "source": source,
                "repo_url": repo_url,
                "is_multiple": len(web_files) > 1
            }
        
        # If no recognized files are found
        return {
            "type": "unknown",
            "input": directory_path,
            "source": source,
            "repo_url": repo_url,
            "message": "No recognizable files found for security scanning."
        } 