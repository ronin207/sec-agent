# Security AI Agent

A Security AI Agent for automating vulnerability assessments for websites and smart contracts.

## Features

- **Input Handling**: Accepts website URLs or Solidity smart contract code/repositories
- **CVE Knowledge Base**: Queries for known CVEs related to the target
- **Tool Selection**: Dynamically selects appropriate security tools based on the target type
- **Scan Execution**: Executes selected security tools against the target
- **Result Aggregation**: Merges and deduplicates results from multiple tools
- **Summary Generation**: Produces human-readable reports with remediation suggestions
- **Detailed Logging**: View comprehensive logs of tool execution and scan results

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
graph TD
    %% Entry Points
    User((User)) --> |Input Target| Demo[demo.py]
    User --> |Commands| Main[main.py]
    
    %% Main Components
    Main --> SecurityAgent
    Demo --> SecurityAgent
    
    %% Core modules
    subgraph Backend Core
        SecurityAgent[SecurityAgent] --> InputHandler[InputHandler]
        SecurityAgent --> CVEKnowledgeBase[CVEKnowledgeBase]
        SecurityAgent --> ToolSelector[ToolSelector]
        SecurityAgent --> ScanExecutor[ScanExecutor]
        SecurityAgent --> ResultAggregator[ResultAggregator]
        SecurityAgent --> ResultSummarizer[ResultSummarizer]
        
        %% Data flow
        InputHandler --> |Validated Input| CVEKnowledgeBase
        CVEKnowledgeBase --> |CVE Information| ToolSelector
        ToolSelector --> |Selected Tools| ScanExecutor
        ScanExecutor --> |Scan Results| ResultAggregator
        ResultAggregator --> |Aggregated Results| ResultSummarizer
    end
    
    %% Utilities
    subgraph Backend Utils
        CVELoader[CVE Loader]
        Helpers[Helper Utilities]
    end
    
    %% External Services
    OpenAI[OpenAI API] -.-> CVEKnowledgeBase
    OpenAI -.-> ResultSummarizer
    
    %% Tool execution - simulated in demo
    subgraph Security Tools
        subgraph Web Tools
            ZAP[OWASP ZAP]
            Nikto[Nikto]
            Wappalyzer[Wappalyzer]
            Nuclei[Nuclei]
        end
        subgraph Smart Contract Tools
            Slither[Slither]
            Mythril[Mythril]
            Solhint[Solhint]
        end
    end
    
    ScanExecutor --> Security Tools
    
    %% Connection to utilities
    CVEKnowledgeBase --> CVELoader
    Backend Core --> Helpers
    
    %% Result flow
    ResultSummarizer --> |Final Report| User
    
    %% Output formats
    ResultSummarizer --> |JSON/Markdown| OutputFile[(Output File)]
    
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
# Basic usage
python demo.py <target> [--output results.json] [--format json|markdown]

# With verbose logging enabled
python demo.py <target> --verbose
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