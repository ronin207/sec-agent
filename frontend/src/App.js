import React, { useState } from 'react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!url) {
      setError('Please enter a URL');
      return;
    }
    
    setLoading(true);
    setError(null);
    setResults(null);
    
    try {
      console.log('Sending request to:', 'http://localhost:8080/api/scan');
      console.log('Request body:', { url });
      
      const response = await fetch('http://localhost:8080/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });
      
      console.log('Response status:', response.status);
      
      if (!response.ok) {
        throw new Error(`Error: ${response.status} - ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('Response data:', data);
      setResults(data);
      
      // Add to scan history
      setScanHistory(prev => [...prev, { url, timestamp: new Date(), results: data }]);
    } catch (err) {
      console.error('Error details:', err);
      setError(`Failed to scan URL: ${err.message}. Make sure the backend server is running at http://localhost:8080`);
    } finally {
      setLoading(false);
    }
  };
  
  const renderVulnerabilities = (vulnerabilities) => {
    if (!vulnerabilities || vulnerabilities.length === 0) {
      return (
        <div className="no-vulnerabilities">
          <div className="success-icon">✓</div>
          <p>No vulnerabilities detected.</p>
        </div>
      );
    }
    
    return (
      <div className="vulnerabilities-container">
        <h3>
          <span className="icon-warning">⚠️</span>
          Detected Vulnerabilities
        </h3>
        {vulnerabilities.map((vuln, index) => (
          <div key={index} className="vulnerability-card">
            <div className="vulnerability-header">
              <h4>Type: {vuln.type}</h4>
              <span className="severity-badge high">High Risk</span>
            </div>
            <p>{vuln.description}</p>
            {vuln.recommendation && (
              <div className="recommendation">
                <strong>Recommendation:</strong> {vuln.recommendation}
              </div>
            )}
          </div>
        ))}
      </div>
    );
  };
  
  const renderScanResults = (scanResults) => {
    if (!scanResults) return null;
    
    return (
      <div className="scan-results-wrapper">
        {Object.entries(scanResults).map(([key, value]) => (
          <div key={key} className="scan-result-section">
            <h3>
              <span className="section-icon">🔍</span>
              {key.replace('_', ' ').toUpperCase()}
            </h3>
            <div className="result-content">
              <div className="domain-badge">
                <span className="domain-icon">🌐</span>
                {value.domain}
              </div>
              <div className="analysis">
                <h4>Analysis</h4>
                <p>{value.analysis}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="App">
      <main>
        <div className="app-title">Security Agent</div>
        <form onSubmit={handleSubmit} className="scan-form">
          <div className="form-group">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to scan for security vulnerabilities"
              className="url-input"
            />
            <button 
              type="submit" 
              disabled={loading} 
              className="scan-button"
              aria-label="Scan URL"
            >
              <span className="scan-icon">🔍</span>
            </button>
          </div>
          
          {error && <div className="error-message">{error}</div>}
        </form>
        
        {loading && (
          <div className="loading">
            <p>Analyzing URL security...</p>
          </div>
        )}
        
        {results && (
          <div className="report-container">
            <div className="report-header">
              <div className="report-title">
                <span className="results-icon">🔒</span>
                <h2>Security Analysis Report</h2>
              </div>
              
              <div className="report-meta">
                <div className="report-url">
                  <span className="meta-label">URL:</span>
                  <span className="meta-value">{url}</span>
                </div>
                
                <div className="report-time">
                  <span className="meta-label">Scan Date:</span>
                  <span className="meta-value">{new Date().toLocaleString()}</span>
                </div>
                
                <div className="report-status">
                  <span className="status">
                    {results.analysis_complete ? 'Analysis Complete' : 'Analysis Incomplete'}
                  </span>
                </div>
              </div>
            </div>
            
            <div className="report-section">
              <div className="section-title">Executive Summary</div>
              <div className="summary-content">
                <p>
                  {results.vulnerabilities && results.vulnerabilities.length > 0 
                    ? `We've identified ${results.vulnerabilities.length} potential security ${results.vulnerabilities.length === 1 ? 'issue' : 'issues'} with this URL. Review the detailed analysis below for specific findings and recommendations.`
                    : 'No significant security issues were detected in our initial scan. The URL appears to implement standard security practices, but a comprehensive security audit is recommended for production systems.'}
                </p>
              </div>
            </div>
            
            <div className="report-section">
              <div className="section-title">Security Assessment Results</div>
              {renderScanResults(results.scan_results)}
            </div>
            
            <div className="report-section">
              <div className="section-title">Security Vulnerabilities</div>
              {renderVulnerabilities(results.vulnerabilities)}
            </div>
            
            {results.error && (
              <div className="report-section">
                <div className="section-title error-title">Errors During Analysis</div>
                <div className="error-section">
                  <h3>
                    <span className="error-icon">⚠️</span>
                    Error
                  </h3>
                  <p>{results.error}</p>
                </div>
              </div>
            )}
            
            <div className="report-section">
              <div className="section-title">Recommendations</div>
              <div className="recommendations-content">
                <ul className="recommendation-list">
                  {results.vulnerabilities && results.vulnerabilities.length > 0 ? (
                    results.vulnerabilities.map((vuln, index) => (
                      <li key={index} className="recommendation-item">
                        {vuln.recommendation || `Address the ${vuln.type} vulnerability through proper security controls.`}
                      </li>
                    ))
                  ) : (
                    <>
                      <li className="recommendation-item">Maintain regular security assessments for your web applications.</li>
                      <li className="recommendation-item">Implement Content Security Policy (CSP) if not already in place.</li>
                      <li className="recommendation-item">Keep all software dependencies and platforms updated.</li>
                    </>
                  )}
                </ul>
              </div>
            </div>
          </div>
        )}
        
        {scanHistory.length > 0 && !results && !loading && (
          <div className="scan-history">
            <h3>Recent Scans</h3>
            <ul className="history-list">
              {scanHistory.slice(0, 5).map((scan, index) => (
                <li key={index} className="history-item" onClick={() => setResults(scan.results)}>
                  <span className="history-url">{scan.url}</span>
                  <span className="history-time">
                    {scan.timestamp.toLocaleTimeString()}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </main>
      
      <footer>
        <p>Security Analysis powered by LangChain and LangGraph</p>
      </footer>
    </div>
  );
}

export default App;
