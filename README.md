# Security Agent

A security scanning and analysis tool for web applications and APIs powered by AI.

## Project Structure

This project follows industry best practices with a clean separation of backend and frontend components:

### Backend (`security_agent/`)

The backend is organized as a Python package with modular components:

- `security_agent/core/` - Core business logic and functionality
  - `knowledge_base.py` - RAG-based security knowledge base
  - `orchestrator.py` - Workflow orchestration using LangGraph

- `security_agent/data/` - Data handling utilities
  - `loader.py` - Utilities for loading security data
  - `sources/` - Source data files (CVEs, best practices, etc.)

- `security_agent/config/` - Configuration management
  - `settings.py` - Application settings and environment variables

- `security_agent/utils/` - Helper utilities
  - `helpers.py` - Common utility functions

### Frontend (`frontend/`)

A React-based user interface for the security agent:

- Standard Create React App structure
- Separate from the backend for clean separation of concerns

### Data Storage

- Runtime data (e.g., vector database) is stored in OS-appropriate user data locations
- Source data is stored within the package structure at `security_agent/data/sources/`

## Getting Started

1. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Set up environment variables:
   Create a `.env` file in the project root with:
   ```
   OPENAI_API_KEY=your_api_key_here
   CVE_API_KEY=your_cve_api_key_here (optional)
   ```

3. Run the security agent:
   ```
   python main.py --url example.com
   ```

## Frontend Development

1. Navigate to the frontend directory:
   ```
   cd frontend
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Start the development server:
   ```
   npm start
   ```