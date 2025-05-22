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
        Validate and classify user input.
        
        Args:
            user_input: Website URL, file path, or GitHub repository
            
        Returns:
            Dictionary containing the classified input
        """
        logger.info(f"Validating input: {user_input}")
        
        # Check if input is a valid URL
        if self._is_valid_url(user_input):
            # Check if it's a GitHub repository
            if self._is_github_repo(user_input):
                return self._process_github_repo(user_input)
            else:
                return self._process_website(user_input)
        
        # Check if input is a valid file path
        elif os.path.exists(user_input):
            # Check if it's a directory
            if os.path.isdir(user_input):
                return self._process_directory(user_input)
            else:
                # Check if it's a valid Solidity file
                if user_input.endswith('.sol'):
                    return self._process_solidity_contract(user_input)
                # Check if it's a Solana program (Rust file in a Solana project)
                elif user_input.endswith('.rs') and self._is_solana_program(user_input):
                    return self._process_solana_contract(user_input)
                # Check if it's an ink! contract for Polkadot/Substrate
                elif (user_input.endswith('.rs') and self._is_ink_contract(user_input)) or user_input.endswith('.ink'):
                    return self._process_polkadot_contract(user_input)
                # Check if it's a Python file
                elif user_input.endswith('.py'):
                    return self._process_python_file(user_input)
                # Check if it's a JavaScript file
                elif user_input.endswith('.js'):
                    return self._process_javascript_file(user_input)
                else:
                    return self._process_generic_file(user_input)
        
        # If input is neither a valid URL nor a valid file path
        else:
            return {
                "type": "error",
                "message": "Invalid input. Please provide a valid URL, file path, or GitHub repository."
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
            
            # Use token if provided (use the latest value from environment)
            token = os.environ.get("GITHUB_TOKEN")
            if token and token != self.github_token:
                logger.info("Using GitHub token from environment variable")
                self.github_token = token
                self.github_client = Github(self.github_token, retry=3, timeout=30)
            
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
                    
                    # If no requests remaining, return an error immediately without making more requests
                    if rate_limit.core.remaining < 5:
                        logger.error("GitHub API rate limit too low to proceed")
                        return {
                            "type": "error",
                            "message": f"GitHub API rate limit too low ({rate_limit.core.remaining} remaining). Please try again in {int(reset_time/60)} minutes or provide a GitHub token."
                        }
                        
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
            
            # First try to determine if the repository contains Solidity files using the search API
            # This is more efficient than downloading all files
            try:
                solidity_search = repo.get_contents("", ref="master")
                has_solidity = False
                
                # Quick check for Solidity files in the root
                for item in solidity_search:
                    if item.name.endswith('.sol'):
                        has_solidity = True
                        break
                
                # If not found in root, check for common Solidity directories
                if not has_solidity:
                    common_solidity_dirs = ["contracts", "src", "solidity", "ethereum"]
                    for dir_name in common_solidity_dirs:
                        try:
                            contents = repo.get_contents(dir_name)
                            for item in contents:
                                if item.name.endswith('.sol'):
                                    has_solidity = True
                                    break
                            if has_solidity:
                                break
                        except:
                            continue
                
                # If we detected Solidity files, set the type early
                if has_solidity:
                    logger.info(f"Detected Solidity contract repository: {repo.full_name}")
                    repo_type = "solidity_contract"
                else:
                    logger.info(f"No Solidity files found in common directories, treating as web application")
                    repo_type = "web_application"
            except Exception as e:
                logger.warning(f"Error during preliminary Solidity detection: {str(e)}")
                repo_type = "unknown"  # Will be determined after file download
            
            # Create a temporary directory for storing files we want to analyze
            self.temp_dir = tempfile.mkdtemp(prefix="security_agent_")
            logger.info(f"Created temporary directory: {self.temp_dir}")
            
            # Get all files in the repository
            files = []
            solidity_files = []
            file_count = 0
            
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
                        # Check if we found any Solidity files despite rate limit
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
                                "type": repo_type,  # Use the type we detected earlier
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
            
            # Perform final check for Solidity files in downloaded files
            downloaded_solidity_files = [f for f in files if f.endswith('.sol')]
            
            # Check for Solana and Polkadot contracts
            solana_files = []
            polkadot_files = []
            
            # Look for Rust files that might be Solana or Polkadot contracts
            rust_files = [f for f in files if f.endswith('.rs')]
            for rust_file in rust_files:
                if self._is_solana_program(rust_file):
                    solana_files.append(rust_file)
                elif self._is_ink_contract(rust_file):
                    polkadot_files.append(rust_file)
            
            # Also add .ink files for Polkadot
            ink_files = [f for f in files if f.endswith('.ink')]
            polkadot_files.extend(ink_files)
            
            # If Solidity files were found, classify as solidity_contract regardless of initial determination
            if downloaded_solidity_files:
                logger.info(f"Found {len(downloaded_solidity_files)} Solidity files in repository")
                return {
                    "type": "solidity_contract",
                    "input": repo_url,
                    "files": downloaded_solidity_files,
                    "source": "github",
                    "repo_url": repo_url,
                    "is_multiple": len(downloaded_solidity_files) > 1
                }
            # If Solana files were found, classify as solana_contract
            elif solana_files:
                logger.info(f"Found {len(solana_files)} Solana program files in repository")
                return {
                    "type": "solana_contract",
                    "input": repo_url,
                    "files": solana_files,
                    "source": "github",
                    "repo_url": repo_url,
                    "is_multiple": len(solana_files) > 1
                }
            # If Polkadot files were found, classify as polkadot_contract
            elif polkadot_files:
                logger.info(f"Found {len(polkadot_files)} Polkadot/ink! contract files in repository")
                return {
                    "type": "polkadot_contract",
                    "input": repo_url,
                    "files": polkadot_files,
                    "source": "github",
                    "repo_url": repo_url,
                    "is_multiple": len(polkadot_files) > 1
                }
            
            # Otherwise, use the preliminary type or classify as a web application
            logger.info(f"Classifying repository as: {repo_type}")
            return {
                "type": repo_type,
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
    
    def _read_file_content(self, file_path: str) -> str:
        """
        Read the content of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            String containing the file content
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try with a different encoding if utf-8 fails
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Error reading file {file_path}: {str(e)}")
                return ""
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
            return ""
    
    def _process_directory(self, directory_path: str, source: str = "local_directory", repo_url: str = None, recursive: bool = False) -> Dict:
        """
        Process a directory to identify files for scanning
        """
        # Check for Solidity files
        solidity_files = glob.glob(os.path.join(directory_path, "**", "*.sol"), recursive=True)
        
        # Check for Rust files that might be Solana programs
        rust_files = glob.glob(os.path.join(directory_path, "**", "*.rs"), recursive=True)
        
        # Filter Rust files to find Solana programs
        solana_files = []
        polkadot_files = []
        for rust_file in rust_files:
            if self._is_solana_program(rust_file):
                solana_files.append(rust_file)
            elif self._is_ink_contract(rust_file):
                polkadot_files.append(rust_file)
        
        # Also look for .ink files specifically for Polkadot
        ink_files = glob.glob(os.path.join(directory_path, "**", "*.ink"), recursive=True)
        polkadot_files.extend(ink_files)
        
        # Determine the primary type of contracts in this directory
        if solidity_files:
            return {
                "type": "solidity_contract",
                "input": directory_path,
                "files": solidity_files,
                "source": source,
                "repo_url": repo_url,
                "is_multiple": len(solidity_files) > 1
            }
        elif solana_files:
            return {
                "type": "solana_contract",
                "input": directory_path,
                "files": solana_files,
                "source": source,
                "repo_url": repo_url,
                "is_multiple": len(solana_files) > 1
            }
        elif polkadot_files:
            return {
                "type": "polkadot_contract", 
                "input": directory_path,
                "files": polkadot_files,
                "source": source,
                "repo_url": repo_url,
                "is_multiple": len(polkadot_files) > 1
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
    
    def _process_solidity_contract(self, file_path: str) -> Dict:
        """
        Process a Solidity contract file.
        
        Args:
            file_path: Path to the Solidity file
            
        Returns:
            Dictionary containing the processed Solidity contract
        """
        logger.info(f"Processing Solidity contract: {file_path}")
        return {
            "type": "solidity_contract",
            "input": file_path,
            "file_content": self._read_file_content(file_path),
            "file_size": os.path.getsize(file_path),
            "file_extension": os.path.splitext(file_path)[1]
        }
    
    def _process_solana_contract(self, file_path: str) -> Dict:
        """
        Process a Solana smart contract.
        
        Args:
            file_path: Path to the Solana program file
            
        Returns:
            Dictionary containing the processed Solana contract
        """
        logger.info(f"Processing Solana contract: {file_path}")
        return {
            "type": "solana_contract",
            "input": file_path,
            "file_content": self._read_file_content(file_path),
            "file_size": os.path.getsize(file_path),
            "file_extension": os.path.splitext(file_path)[1]
        }
    
    def _process_polkadot_contract(self, file_path: str) -> Dict:
        """
        Process a Polkadot/Substrate smart contract.
        
        Args:
            file_path: Path to the ink! contract file
            
        Returns:
            Dictionary containing the processed Polkadot contract
        """
        logger.info(f"Processing Polkadot contract: {file_path}")
        return {
            "type": "polkadot_contract",
            "input": file_path,
            "file_content": self._read_file_content(file_path),
            "file_size": os.path.getsize(file_path),
            "file_extension": os.path.splitext(file_path)[1]
        }
    
    def _process_python_file(self, file_path: str) -> Dict:
        """
        Process a Python file.
        
        Args:
            file_path: Path to the Python file
            
        Returns:
            Dictionary containing the processed Python file
        """
        logger.info(f"Processing Python file: {file_path}")
        return {
            "type": "python_file",
            "input": file_path,
            "file_content": self._read_file_content(file_path),
            "file_size": os.path.getsize(file_path),
            "file_extension": os.path.splitext(file_path)[1]
        }
    
    def _process_javascript_file(self, file_path: str) -> Dict:
        """
        Process a JavaScript file.
        
        Args:
            file_path: Path to the JavaScript file
            
        Returns:
            Dictionary containing the processed JavaScript file
        """
        logger.info(f"Processing JavaScript file: {file_path}")
        return {
            "type": "javascript_file",
            "input": file_path,
            "file_content": self._read_file_content(file_path),
            "file_size": os.path.getsize(file_path),
            "file_extension": os.path.splitext(file_path)[1]
        }
    
    def _process_generic_file(self, file_path: str) -> Dict:
        """
        Process a generic file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary containing the processed file
        """
        logger.info(f"Processing generic file: {file_path}")
        return {
            "type": "generic_file",
            "input": file_path,
            "file_content": self._read_file_content(file_path),
            "file_size": os.path.getsize(file_path),
            "file_extension": os.path.splitext(file_path)[1]
        }
    
    def _is_solana_program(self, file_path: str) -> bool:
        """
        Check if a Rust file is part of a Solana program.
        
        Args:
            file_path: Path to the Rust file
            
        Returns:
            Boolean indicating if the file is part of a Solana program
        """
        # Check if the file is a Rust file
        if not file_path.endswith('.rs'):
            return False
        
        # Look for Solana-specific imports or Cargo.toml with Solana dependencies
        try:
            # Check file content for Solana-specific imports
            with open(file_path, 'r') as f:
                content = f.read()
                if any(marker in content for marker in [
                    'solana_program', 'anchor_lang', 'solana_sdk', 
                    '#[program]', 'entrypoint!', 'ProgramResult'
                ]):
                    return True
            
            # Check if there's a Cargo.toml file in the parent directory with Solana dependencies
            cargo_path = os.path.join(os.path.dirname(file_path), 'Cargo.toml')
            if os.path.exists(cargo_path):
                with open(cargo_path, 'r') as f:
                    cargo_content = f.read()
                    if any(dep in cargo_content for dep in [
                        'solana-program', 'anchor-lang', 'solana-sdk'
                    ]):
                        return True
        except Exception as e:
            logger.warning(f"Error checking if file is a Solana program: {str(e)}")
        
        return False
    
    def _is_ink_contract(self, file_path: str) -> bool:
        """
        Check if a Rust file is an ink! smart contract for Polkadot/Substrate.
        
        Args:
            file_path: Path to the Rust file
            
        Returns:
            Boolean indicating if the file is an ink! contract
        """
        # Check if the file is a Rust file
        if not file_path.endswith('.rs'):
            return False
        
        # Look for ink!-specific markers
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                if any(marker in content for marker in [
                    '#[ink::contract]', '#[ink(storage)]', '#[ink::trait]',
                    'ink_lang', 'ink_storage', 'ink_env', 'ink_prelude',
                    '#[ink_lang::contract]', '#[derive(ink::Storage)]'
                ]):
                    return True
            
            # Check if there's a Cargo.toml file in the parent directory with ink! dependencies
            cargo_path = os.path.join(os.path.dirname(file_path), 'Cargo.toml')
            if os.path.exists(cargo_path):
                with open(cargo_path, 'r') as f:
                    cargo_content = f.read()
                    if any(dep in cargo_content for dep in [
                        'ink_lang', 'ink-lang', 'ink_storage', 'ink_env', 'parity-scale-codec'
                    ]):
                        return True
        except Exception as e:
            logger.warning(f"Error checking if file is an ink! contract: {str(e)}")
        
        return False
    
    def process_input(self, user_input: str) -> Dict:
        """
        Process input and return validated result.
        This method is a wrapper for validate_and_classify to maintain backward compatibility.
        
        Args:
            user_input: Input string to process
            
        Returns:
            Dictionary containing the processed input result
        """
        logger.debug(f"Processing input: {user_input}")
        return self.validate_and_classify(user_input)
    
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