from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import tempfile
import shutil
import logging
import traceback
from werkzeug.utils import secure_filename
from typing import Dict, Any, List
from datetime import datetime

# Add parent directory to path so we can import backend modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import security agent modules
from backend.core.knowledge_base import SecurityKnowledgeBase
from backend.core.security_agent import SecurityAgent
from backend.utils.helpers import populate_sample_data, get_logger
from backend.config.settings import API_HOST, API_PORT, API_DEBUG
from backend.core.input_handler import InputHandler  # Make sure we can access InputHandler directly
from backend.core.result_summarizer import ResultSummarizer
from backend.core.ai_audit_analyzer import AIAuditAnalyzer

# Configure logging
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("security_agent")

# Initialize Flask app
app = Flask(__name__)
# Enable CORS with more specific settings
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST"]}})

# Initialize the security agent components
kb = SecurityKnowledgeBase()
result_summarizer = ResultSummarizer(model_name="gpt-4o")
security_agent = SecurityAgent()
ai_audit_analyzer = AIAuditAnalyzer()

# Set up temp directory for file uploads
UPLOAD_FOLDER = tempfile.mkdtemp()
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

ALLOWED_EXTENSIONS = {'sol', 'js', 'ts', 'py', 'java', 'go', 'cpp', 'c', 'h', 'cs', 'rb', 'php', 'html', 'xml', 'json'}

# GitHub token for API access
github_token = os.environ.get("GITHUB_TOKEN")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """API root endpoint to confirm server is running"""
    return jsonify({
        "status": "running",
        "message": "Security Agent API is running",
        "version": "1.0.0",
        "llm_model": "gpt-4o",
        "ai_audit_model": "gpt-4o",
        "features": {
            "traditional_security_scanning": True,
            "ai_powered_audit": True,
            "github_repository_scanning": True,
            "batch_file_upload": True,
            "cve_knowledge_base": True
        },
        "endpoints": {
            "/api/scan": "General security scanning",
            "/api/scan/github": "GitHub repository scanning", 
            "/api/scan/files": "File upload scanning",
            "/api/ai-audit": "AI-powered smart contract audit",
            "/api/ai-audit/batch": "Batch AI audit analysis",
            "/api/status": "API status and capabilities"
        }
    })

@app.route('/api/scan', methods=['POST'])
def scan():
    """General scanning endpoint that can handle different types of inputs"""
    try:
        data = request.json
        
        # Check if it's a GitHub repository scan
        if 'url' in data and data.get('is_repo', False):
            # Call the GitHub repository scanning function with the data from this request
            repo_url = data['url']
            token = data.get('token') or github_token
            output_format = data.get('output_format', 'json')
            
            # Run the scan
            result = security_agent.scan_github_repo(
                repo_url=repo_url,
                output_format=output_format,
                token=token
            )
            
            # Standardize the security findings using 4o
            standardized_result = result_summarizer.standardize_security_findings(result.get('aggregated_results', {}))
            
            # Add model info and combine results
            standardized_result["model_used"] = "gpt-4o"
            result["formatted_results"] = standardized_result
            result["model_used"] = "gpt-4o"
            
            return jsonify(result)
        
        # Handle regular target scanning
        if 'target' not in data:
            return jsonify({
                'error': 'Missing required parameter: target',
                'status': 'error'
            }), 400
        
        target = data['target']
        recursive = data.get('recursive', False)
        output_format = data.get('output_format', 'json')
        
        # Run the scan
        result = security_agent.run(target, output_format=output_format, recursive=recursive)
        
        # Standardize the security findings using 4o-mini
        standardized_result = result_summarizer.standardize_security_findings(result.get('aggregated_results', {}))
        
        # Add model info and combine results
        standardized_result["model_used"] = "gpt-4o"
        result["formatted_results"] = standardized_result
        result["model_used"] = "gpt-4o"
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in scan endpoint: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/scan/github', methods=['POST'])
def scan_github_repo():
    """Scan a GitHub repository for security vulnerabilities"""
    try:
        data = request.json
        
        # Validate required parameters
        if 'url' not in data:
            return jsonify({
                'error': 'Missing required parameter: url',
                'status': 'error'
            }), 400
        
        repo_url = data['url']
        token = data.get('token') or github_token  # Use provided token or global one
        output_format = data.get('output_format', 'json')
        
        logger.info(f"Scanning GitHub repository: {repo_url}")
        
        # Make sure to set the token in environment if it's provided
        if token:
            os.environ["GITHUB_TOKEN"] = token
            logger.info("Using provided GitHub token for repository scan")
        
        # Use the GitHub scanning method
        result = security_agent.scan_github_repo(
            repo_url=repo_url,
            output_format=output_format,
            token=token
        )
        
        # Standardize the security findings using 4o-mini
        standardized_result = result_summarizer.standardize_security_findings(result.get('aggregated_results', {}))
        
        # Add model info and combine results
        standardized_result["model_used"] = "gpt-4o"
        result["formatted_results"] = standardized_result
        result["model_used"] = "gpt-4o"
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in GitHub scan endpoint: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error',
            'timestamp': datetime.now().isoformat(),
            'scan_type': 'github_repo',
            'model_used': 'gpt-4o'
        }), 500

@app.route('/api/scan/files', methods=['POST'])
def scan_files_endpoint():
    """Endpoint to scan uploaded files"""
    try:
        # Check if files were uploaded
        if 'files[]' not in request.files:
            return jsonify({"result": "error", "message": "No files uploaded"})
        
        files = request.files.getlist('files[]')
        if not files or files[0].filename == '':
            return jsonify({"result": "error", "message": "No files selected"})
        
        # Save uploaded files to temp directory
        file_paths = []
        for file in files:
            if file:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                file_paths.append(file_path)
        
        # Call security agent to scan files
        results = security_agent.scan_multiple(file_paths)
        
        # Standardize the security findings using 4o-mini
        standardized_result = result_summarizer.standardize_security_findings(results.get('aggregated_results', {}))
        
        # Add model info and combine results
        standardized_result["model_used"] = "gpt-4o"
        results["formatted_results"] = standardized_result
        results["model_used"] = "gpt-4o"
        
        # Clean up temp files
        for file_path in file_paths:
            if os.path.exists(file_path):
                os.remove(file_path)
        
        return jsonify(results)
    
    except Exception as e:
        logger.error(f"Error in file upload scan: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/status', methods=['GET'])
def status_endpoint():
    """Endpoint to check server status"""
    return jsonify({"status": "online", "model": "gpt-4o"})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "model": "gpt-4o"})

@app.route('/api/set-github-token', methods=['POST'])
def set_github_token():
    """Set GitHub token for API access"""
    try:
        data = request.json
        if 'token' not in data:
            return jsonify({
                'error': 'Missing required parameter: token',
                'status': 'error'
            }), 400
        
        # Update the token in environment and global variable
        token = data['token']
        global github_token
        github_token = token
        os.environ["GITHUB_TOKEN"] = token
        
        return jsonify({
            'status': 'success',
            'message': 'GitHub token updated successfully'
        })
    except Exception as e:
        logger.error(f"Error setting GitHub token: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/ai-audit', methods=['POST'])
def ai_audit_endpoint():
    """Dedicated endpoint for AI-powered smart contract security analysis"""
    try:
        data = request.json
        
        # Validate required parameters
        if 'code' not in data:
            return jsonify({
                'error': 'Missing required parameter: code (Solidity contract code)',
                'status': 'error'
            }), 400
        
        contract_code = data['code']
        contract_name = data.get('contract_name', 'unnamed_contract.sol')
        
        logger.info(f"Performing AI audit analysis on contract: {contract_name}")
        
        # Perform AI audit analysis
        ai_findings = ai_audit_analyzer.analyze_solidity_code(contract_code, contract_name)
        
        # Create response with detailed AI audit results
        result = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'contract_name': contract_name,
            'ai_audit_findings': {
                'total_findings': len(ai_findings),
                'findings': ai_findings,
                'analyzer': 'AI Audit Analyzer (GPT-4o)',
                'knowledge_base': 'Past audit reports database',
                'analysis_timestamp': datetime.now().isoformat()
            },
            'model_used': 'gpt-4o'
        }
        
        # Add finding statistics
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for finding in ai_findings:
            severity = finding.get('severity', 'Medium')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        result['ai_audit_findings']['severity_breakdown'] = severity_counts
        result['ai_audit_findings']['has_critical_issues'] = severity_counts.get('Critical', 0) > 0
        result['ai_audit_findings']['has_high_issues'] = severity_counts.get('High', 0) > 0
        
        logger.info(f"AI audit completed. Found {len(ai_findings)} findings for {contract_name}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in AI audit endpoint: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error',
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'ai_audit'
        }), 500

@app.route('/api/ai-audit/batch', methods=['POST'])
def ai_audit_batch_endpoint():
    """Batch AI audit endpoint for analyzing multiple contracts"""
    try:
        data = request.json
        
        # Validate required parameters
        if 'contracts' not in data or not isinstance(data['contracts'], list):
            return jsonify({
                'error': 'Missing required parameter: contracts (array of contract objects)',
                'status': 'error'
            }), 400
        
        contracts = data['contracts']
        all_findings = []
        contract_results = []
        
        logger.info(f"Performing batch AI audit analysis on {len(contracts)} contracts")
        
        for i, contract in enumerate(contracts):
            if 'code' not in contract:
                logger.warning(f"Skipping contract {i}: missing 'code' field")
                continue
                
            contract_code = contract['code']
            contract_name = contract.get('name', f'contract_{i}.sol')
            
            try:
                # Perform AI audit analysis
                ai_findings = ai_audit_analyzer.analyze_solidity_code(contract_code, contract_name)
                
                # Add contract context to findings
                for finding in ai_findings:
                    finding['contract_index'] = i
                    finding['contract_name'] = contract_name
                
                all_findings.extend(ai_findings)
                
                # Individual contract result
                contract_result = {
                    'contract_name': contract_name,
                    'contract_index': i,
                    'findings_count': len(ai_findings),
                    'has_critical': any(f.get('severity') == 'Critical' for f in ai_findings),
                    'has_high': any(f.get('severity') == 'High' for f in ai_findings),
                    'status': 'completed'
                }
                contract_results.append(contract_result)
                
                logger.info(f"AI audit completed for {contract_name}: {len(ai_findings)} findings")
                
            except Exception as e:
                logger.error(f"Error analyzing contract {contract_name}: {str(e)}")
                contract_results.append({
                    'contract_name': contract_name,
                    'contract_index': i,
                    'status': 'error',
                    'error': str(e)
                })
        
        # Create consolidated response
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for finding in all_findings:
            severity = finding.get('severity', 'Medium')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        result = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'batch_summary': {
                'total_contracts': len(contracts),
                'contracts_analyzed': len([r for r in contract_results if r['status'] == 'completed']),
                'contracts_failed': len([r for r in contract_results if r['status'] == 'error']),
                'total_findings': len(all_findings)
            },
            'ai_audit_findings': {
                'total_findings': len(all_findings),
                'findings': all_findings,
                'analyzer': 'AI Audit Analyzer (GPT-4o)',
                'knowledge_base': 'Past audit reports database',
                'analysis_timestamp': datetime.now().isoformat(),
                'severity_breakdown': severity_counts,
                'has_critical_issues': severity_counts.get('Critical', 0) > 0,
                'has_high_issues': severity_counts.get('High', 0) > 0
            },
            'contract_results': contract_results,
            'model_used': 'gpt-4o'
        }
        
        logger.info(f"Batch AI audit completed. Analyzed {len(contract_results)} contracts with {len(all_findings)} total findings")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in batch AI audit endpoint: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error',
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'ai_audit_batch'
        }), 500

def start_server(host='127.0.0.1', port=8080):
    """Start the API server"""
    print(f"Starting Security Agent API server on {host}:{port}")
    app.run(host=host, port=port, debug=API_DEBUG)

if __name__ == '__main__':
    start_server(host=API_HOST, port=API_PORT)