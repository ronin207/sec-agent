# Security AI Agent

A Security AI Agent for automating vulnerability assessments for websites and smart contracts.

## Features

- **Input Handling**: Accepts website URLs, Solidity smart contract code/repositories, or multiple files
- **CVE Knowledge Base**: Queries for known CVEs related to the target
- **Tool Selection**: Dynamically selects appropriate security tools based on the target type
- **Scan Execution**: Executes selected security tools against the target
- **Result Aggregation**: Merges and deduplicates results from multiple tools
- **Summary Generation**: Produces human-readable reports with remediation suggestions
- **Detailed Logging**: View comprehensive logs of tool execution and scan results
- **Multiple File Scanning**: Scan multiple files or entire directories at once
- **GitHub Repository Support**: Directly scan code from GitHub repositories
- **Web Interface**: User-friendly frontend for scanning and viewing results

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

## Architecture Diagram

```mermaid
flowchart TD
    %% Entry Points
    User((User)) --> Demo[demo.py]
    User --> Main[main.py]

    %% Main Components
    Main --> SecurityAgent
    Demo --> SecurityAgent

    %% Core modules
    subgraph BackendCore[Backend Core]
        SecurityAgent[SecurityAgent]
        InputHandler[InputHandler]
        CVEKnowledgeBase[CVEKnowledgeBase]
        ToolSelector[ToolSelector]
        ScanExecutor[ScanExecutor]
        ResultAggregator[ResultAggregator]
        ResultSummarizer[ResultSummarizer]
    end

    %% Connections between core components
    SecurityAgent --> InputHandler
    SecurityAgent --> CVEKnowledgeBase
    SecurityAgent --> ToolSelector
    SecurityAgent --> ScanExecutor
    SecurityAgent --> ResultAggregator
    SecurityAgent --> ResultSummarizer

    %% Data flow
    InputHandler --> CVEKnowledgeBase
    CVEKnowledgeBase --> ToolSelector
    ToolSelector --> ScanExecutor
    ScanExecutor --> ResultAggregator
    ResultAggregator --> ResultSummarizer

    %% Utilities
    subgraph BackendUtils[Backend Utils]
        CVELoader[CVE Loader]
        Helpers[Helper Utilities]
    end

    %% External Services
    OpenAI[OpenAI API]
    OpenAI -.-> CVEKnowledgeBase
    OpenAI -.-> ResultSummarizer

    %% Tool execution - simulated in demo
    subgraph WebTools[Web Tools]
        ZAP[OWASP ZAP]
        Nikto[Nikto]
        Wappalyzer[Wappalyzer]
        Nuclei[Nuclei]
    end

    subgraph SmartContractTools[Smart Contract Tools]
        Slither[Slither]
        Mythril[Mythril]
        Solhint[Solhint]
    end

    %% Connect executor to individual tools
    ScanExecutor --> ZAP
    ScanExecutor --> Nikto
    ScanExecutor --> Wappalyzer
    ScanExecutor --> Nuclei
    ScanExecutor --> Slither
    ScanExecutor --> Mythril
    ScanExecutor --> Solhint

    %% Connection to utilities
    CVEKnowledgeBase --> CVELoader
    BackendCore --> Helpers

    %% Result flow
    ResultSummarizer --> User

    %% Output formats
    ResultSummarizer --> OutputFile[(Output File)]

    %% Styling
    classDef core fill:#f9f,stroke:#333,stroke-width:2px;
    classDef utils fill:#bbf,stroke:#333,stroke-width:1px;
    classDef external fill:#bfb,stroke:#333,stroke-width:1px;
    classDef entry fill:#fbb,stroke:#333,stroke-width:2px;

    class SecurityAgent,InputHandler,CVEKnowledgeBase,ToolSelector,ScanExecutor,ResultAggregator,ResultSummarizer core;
    class CVELoader,Helpers utils;
    class OpenAI external;
    class Demo,Main entry;
```

## Installation

This project has several dependencies with potential conflicts. The `requirements.txt` file contains everything you need with clear instructions.

### Basic Installation

```bash
# Install core dependencies
pip install -r requirements.txt
```

### Installing Security Tools (Optional)

Due to dependency conflicts, security analysis tools need to be installed separately after installing the core requirements:

```bash
# For Slither (Solidity analyzer)
pip install slither-analyzer==0.9.5 web3==6.0.0

# For Mythril (smart contract security analyzer)
pip install mythril==0.23.15

# For Manticore (symbolic execution tool)
pip install manticore==0.3.7 crytic-compile==0.2.2
```

### Note on Dependencies

Some tools have conflicting dependencies, particularly with Ethereum library versions. The recommended approach is to:

1. Install core requirements first
2. Install optional security tools in a clean environment when needed
3. Some tools like aderyn and securify2 require separate installation from their GitHub repositories

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

# Scan multiple files/URLs at once
python main.py scan file1.sol file2.sol file3.sol [--output-file results.json]

# Scan a directory recursively
python main.py scan src/ --recursive [--output-file results.json]

# Scan a GitHub repository
python main.py scan https://github.com/username/repository --repo [--output-file results.json]

# Scan a private GitHub repository (requires authentication)
python main.py scan https://github.com/username/repository --repo --token YOUR_GITHUB_TOKEN

# Load CVE data into the knowledge base
python main.py load-cve [--id CVE-ID] [--keyword search_term] [--smart-contracts]

# Run the legacy mode (RAG-based only, less features)
python main.py run <url> [--sample-data]
```

### Demo Script

A friendly demo interface is provided for easy usage:

```
# Basic usage - single target
python demo.py <target> [--output results.json] [--format json|markdown]

# Scan multiple files
python demo.py file1.sol file2.sol file3.sol [--output results.json]

# Scan a directory recursively
python demo.py src/ --recursive [--output results.json]

# Scan a GitHub repository
python demo.py --repo https://github.com/username/repository [--output results.json]

# With verbose logging enabled
python demo.py <target> --verbose
```

#### Multiple File Scanning

When scanning multiple files or repositories, the tool will:

1. Analyze each file individually
2. Aggregate findings across all files
3. Generate a comprehensive report that includes:
   - Per-file vulnerability counts
   - Overall severity summary
   - Consolidated remediation suggestions

Example scanning multiple files:
```
python demo.py contract1.sol contract2.sol --output results.json
```

#### GitHub Repository Scanning

You can scan a GitHub repository for security vulnerabilities by entering a GitHub URL in the frontend. This feature allows you to analyze Solidity smart contracts hosted on GitHub repositories.

### Requirements

1. Both the backend server and frontend application must be running locally.
2. For private repositories or to avoid API rate limits, a GitHub Personal Access Token is recommended.

### How to Use

1. Start the backend server:
   ```
   cd /path/to/sec-agent
   PORT=8080 GITHUB_TOKEN=your_github_token OPENAI_API_KEY=your_openai_key python -m api.server
   ```

2. Start the frontend:
   ```
   cd /path/to/sec-agent/frontend
   npm start
   ```

3. Open your browser and navigate to `http://localhost:3000`

4. Enter a GitHub repository URL in the input field and click the submit button.

5. Optionally, you can provide a GitHub token for scanning private repositories or to avoid rate limits.

6. View the scan results organized by severity in the tabbed interface:
   - Summary tab: Shows the executive summary and overall assessment
   - Issues tab: Displays security issues categorized by severity (High, Medium, Low, Info)
   - Debug tab: Shows raw response data for debugging

For more detailed information about the GitHub scanning feature, please refer to [README-github-scanning.md](./README-github-scanning.md).

#### Recursive Directory Scanning

Scan all files in a directory structure:

```
python demo.py --recursive ./src
```

#### Verbose Mode

The `--verbose` (or `-v`) flag enables detailed logging of all tool execution steps and results:

- View API calls to OpenAI
- See detailed execution steps for each security tool
- Display all findings from each tool with full details
- Show raw output from security tools

Example:
```
python demo.py https://example.com --verbose
```

### Logging Configuration

Logging levels can be configured in the `.env` file:

```
# Log Level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
LOG_LEVEL=DEBUG
```

## Example Output

The security agent produces detailed reports including:

- Overall security risk assessment
- Detailed vulnerability findings
- Technical analysis of detected issues
- Remediation suggestions for each vulnerability
- Complete tool execution results (when using `--verbose` mode)

## Note on Tool Execution

In the current demo version, security tool execution is simulated. In a production environment, actual tools like OWASP ZAP, Nikto, Wappalyzer (for websites) and Mythril, Slither (for Solidity contracts) would be integrated.

## Requirements

- Python 3.8+
- OpenAI API key (GPT-4 or GPT-4o-mini recommended)
- Python packages listed in requirements.txt

## Audit Report Processing

To process audit reports and create the necessary index file, follow these simple steps:

1. Place your PDF audit reports in the directory:
   ```
   cp /path/to/your/audit/reports/*.pdf security_agent/data/sources/audit_reports/
   ```

2. Run the audit report processing script:
   ```
   python scripts/extract_findings_from_pdfs.py
   ```

The script will automatically extract findings from all PDF reports and create an index.json file that the AI analyzer will use for enhanced vulnerability detection.

## Web Interface

The project includes a web-based frontend interface for easier interaction with the security agent:

### Starting the Web Interface

1. Start the backend server:
   ```bash
   cd /path/to/sec-agent
   PORT=8080 GITHUB_TOKEN=your_github_token OPENAI_API_KEY=your_openai_key python -m api.server
   ```

2. Start the frontend development server:
   ```bash
   cd /path/to/sec-agent/frontend
   npm start
   ```

3. Open your browser and navigate to `http://localhost:3000`

### Using the Web Interface

The web interface allows you to:

1. Input a GitHub repository URL or paste Solidity code directly
2. View detailed security scan results in a user-friendly format
3. See vulnerability findings with severity ratings and remediation suggestions

For detailed information about scanning GitHub repositories through the frontend, see [README-github-scanning.md](./README-github-scanning.md).

**Note**: Both the backend server and frontend must be running locally for all features to work properly.
