# Security AI Agent

A Security AI Agent for automating vulnerability assessments for websites and smart contracts.

## Features

- **Input Handling**: Accepts website URLs or Solidity smart contract code/repositories
- **CVE Knowledge Base**: Queries for known CVEs related to the target
- **Tool Selection**: Dynamically selects appropriate security tools based on the target type
- **Scan Execution**: Executes selected security tools against the target
- **Result Aggregation**: Merges and deduplicates results from multiple tools
- **Summary Generation**: Produces human-readable reports with remediation suggestions

## Project Structure

This project follows industry best practices with a clean separation of backend and frontend components:

### Backend (`backend/`)

The backend is organized as a Python package with modular components:

- `backend/core/` - Core business logic and functionality
  - `security_agent.py` - Main Security Agent module
  - `input_handler.py` - Input validation and classification
  - `cve_knowledge_base.py` - CVE querying and analysis
  - `tool_selector.py` - Security tool selection
  - `scan_executor.py` - Tool execution (mocked for demo)
  - `result_aggregator.py` - Result aggregation and deduplication
  - `result_summarizer.py` - Report generation using LLMs

- `backend/utils/` - Helper utilities
  - `cve_loader.py` - CVE data loading utilities
  - `helpers.py` - Common utility functions

### Frontend (`frontend/`)

A React-based user interface for the security agent is planned for future development.

## Getting Started

1. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Set up environment variables:
   ```
   cp env.example .env
   ```
   Edit the `.env` file and add your OpenAI API key.

3. Run the security agent:
   ```
   python main.py scan https://example.com
   ```
   or
   ```
   python demo.py https://example.com
   ```

## Usage

### Command-line Interface

The main entry point provides several commands:

```
# Run a security scan on a website or Solidity contract
python main.py scan <target> [--format json|markdown] [--output-file results.json]

# Load CVE data into the knowledge base
python main.py load-cve [--id CVE-ID] [--keyword search_term] [--smart-contracts]

# Run the legacy mode (RAG-based only, less features)
python main.py run <url> [--sample-data]
```

### Demo Script

A friendly demo interface is provided for easy usage:

```
python demo.py <target> [--output results.json] [--format json|markdown]
```

## Example Output

The security agent produces detailed reports including:

- Overall security risk assessment
- Detailed vulnerability findings
- Technical analysis of detected issues
- Remediation suggestions for each vulnerability

## Note on Tool Execution

In the current demo version, security tool execution is simulated. In a production environment, actual tools like OWASP ZAP, Nikto, Wappalyzer (for websites) and Mythril, Slither (for Solidity contracts) would be integrated.

## Requirements

- Python 3.8+
- OpenAI API key (GPT-4 or GPT-4o-mini recommended)
- Python packages listed in requirements.txt