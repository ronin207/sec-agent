from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Add parent directory to path so we can import backend modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import security agent modules
from backend.core.knowledge_base import SecurityKnowledgeBase
from backend.core.orchestrator import SecurityAgentOrchestrator
from backend.utils.helpers import populate_sample_data
from backend.config.settings import API_HOST, API_PORT, API_DEBUG

# Initialize Flask app
app = Flask(__name__)
# Enable CORS with more specific settings
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST"]}})

# Initialize the security agent components
kb = SecurityKnowledgeBase()
orchestrator = SecurityAgentOrchestrator(kb)

@app.route('/api/scan', methods=['POST'])
def scan_url():
    """
    Endpoint to scan a URL for security vulnerabilities
    """
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL parameter'}), 400
    
    url = data['url']
    
    try:
        # Run security analysis
        result = orchestrator.run(url)
        
        # Format response
        response = {
            'url': url,
            'analysis_complete': result.get('analysis_complete', False),
            'scan_results': result.get('scan_results', {}),
            'vulnerabilities': result.get('vulnerabilities', []),
            'error': result.get('error')
        }
        
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Simple health check endpoint
    """
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    # Initialize with sample data 
    populate_sample_data(kb)
    
    # Start the Flask development server
    print(f"Starting Security Agent API server on {API_HOST}:{API_PORT}")
    # Make Flask listen on all interfaces (0.0.0.0) to ensure it's accessible
    app.run(debug=API_DEBUG, host="0.0.0.0", port=API_PORT)