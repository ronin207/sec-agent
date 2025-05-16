from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import tempfile
import shutil
from werkzeug.utils import secure_filename

# Add parent directory to path so we can import backend modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Import security agent modules
from backend.core.knowledge_base import SecurityKnowledgeBase
from backend.core.security_agent import SecurityAgent
from backend.utils.helpers import populate_sample_data
from backend.config.settings import API_HOST, API_PORT, API_DEBUG

# Initialize Flask app
app = Flask(__name__)
# Enable CORS with more specific settings
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST"]}})

# Initialize the security agent components
kb = SecurityKnowledgeBase()
security_agent = SecurityAgent()

ALLOWED_EXTENSIONS = {'sol', 'js', 'ts', 'py', 'java', 'go', 'cpp', 'c', 'h', 'cs', 'rb', 'php', 'html', 'xml', 'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    """
    Endpoint to scan a URL or GitHub repository for security vulnerabilities
    """
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing URL parameter'}), 400
    
    url = data['url']
    scan_type = data.get('scan_type', 'url')
    
    try:
        # Run security analysis
        if scan_type == 'github_repo':
            result = security_agent.scan_github_repo(url)
        else:
            result = security_agent.run(url)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/api/scan/files', methods=['POST'])
def scan_files():
    """
    Endpoint to scan uploaded files for security vulnerabilities
    """
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded', 'status': 'error'}), 400
    
    files = request.files.getlist('files')
    
    if not files or len(files) == 0:
        return jsonify({'error': 'No selected files', 'status': 'error'}), 400
    
    # Create a temporary directory to store the uploaded files
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Save all files to the temporary directory
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(temp_dir, filename)
                file.save(file_path)
        
        # Scan the temporary directory
        result = security_agent.scan_directory(temp_dir, recursive=True)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)

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