"""
Configuration settings for the Security Agent application.
"""
import os
import platform
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Platform-specific data directories (following OS conventions)
def get_data_dir():
    system = platform.system()
    home = Path.home()
    
    if system == "Darwin":  # macOS
        return os.path.join(home, "Library", "Application Support", "SecurityAgent")
    elif system == "Windows":
        return os.path.join(os.environ.get("APPDATA", str(home)), "SecurityAgent")
    else:  # Linux and others
        return os.path.join(home, ".local", "share", "security-agent")

# Data directories
USER_DATA_DIR = get_data_dir()
CHROMA_DIR = os.environ.get("CHROMA_PERSIST_DIRECTORY", os.path.join(USER_DATA_DIR, "chroma"))
SOURCES_DIR = os.path.join(BASE_DIR, "security_agent", "data", "sources")

# Create directories if they don't exist
os.makedirs(CHROMA_DIR, exist_ok=True)
os.makedirs(SOURCES_DIR, exist_ok=True)

# API Keys
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
CVE_API_KEY = os.environ.get("CVE_API_KEY")

# LLM Settings
DEFAULT_MODEL_NAME = "gpt-3.5-turbo"
DEFAULT_TEMPERATURE = 0.0

# Vector DB Settings
DEFAULT_COLLECTION_NAME = "security_knowledge"

# Security settings
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# API settings
API_HOST = os.environ.get("API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", 8080))  # Changed to 8080 since 5000 is used by macOS Control Center
API_DEBUG = os.environ.get("API_DEBUG", "True").lower() == "true"