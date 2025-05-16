import React, { useState } from 'react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [scanType, setScanType] = useState('url'); // 'url' or 'smart_contract'
  const [outputFormat, setOutputFormat] = useState('json'); // 'json' or 'markdown'
  const [cveData, setCveData] = useState({
    id: '',
    keyword: '',
    maxResults: 20,
    loadSmartContracts: false
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (scanType === 'url' && !url) {
      setError('Please enter a URL');
      return;
    }
    
    setLoading(true);
    setError(null);
    setResults(null);
    
    try {
      const endpoint = scanType === 'url' ? '/api/scan' : '/api/scan/smart-contract';
      const requestBody = scanType === 'url' 
        ? { url, format: outputFormat }
        : { contract: url, format: outputFormat };
      
      console.log('Sending request to:', `http://localhost:8080${endpoint}`);
      console.log('Request body:', requestBody);
      
      const response = await fetch(`http://localhost:8080${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });
      
      if (!response.ok) {
        throw new Error(`Error: ${response.status} - ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('Response data:', data);
      setResults(data);
      
      // Add to scan history
      setScanHistory(prev => [...prev, { 
        url, 
        timestamp: new Date(), 
        results: data,
        type: scanType,
        format: outputFormat
      }]);
    } catch (err) {
      console.error('Error details:', err);
      setError(`Failed to scan: ${err.message}. Make sure the backend server is running at http://localhost:8080`);
    } finally {
      setLoading(false);
    }
  };

  const handleCveLoad = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch('http://localhost:8080/api/load-cve', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(cveData),
      });
      
      if (!response.ok) {
        throw new Error(`Error: ${response.status} - ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('CVE data loaded:', data);
      setResults({ message: 'CVE data loaded successfully', details: data });
    } catch (err) {
      console.error('Error loading CVE data:', err);
      setError(`Failed to load CVE data: ${err.message}`);
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
              <span className={`severity-badge ${vuln.severity?.toLowerCase() || 'high'}`}>
                {vuln.severity || 'High'} Risk
              </span>
            </div>
            <p>{vuln.description}</p>
            {vuln.recommendation && (
              <div className="recommendation">
                <strong>Recommendation:</strong> {vuln.recommendation}
              </div>
            )}
            {vuln.cve_id && (
              <div className="cve-reference">
                <strong>CVE ID:</strong> {vuln.cve_id}
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
              {value.domain && (
                <div className="domain-badge">
                  <span className="domain-icon">🌐</span>
                  {value.domain}
                </div>
              )}
              <div className="analysis">
                <h4>Analysis</h4>
                <p>{value.analysis}</p>
              </div>
              {value.findings && (
                <div className="findings">
                  <h4>Findings</h4>
                  <ul>
                    {value.findings.map((finding, idx) => (
                      <li key={idx}>{finding}</li>
                    ))}
                  </ul>
                </div>
              )}
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
        
        <div className="scan-options">
          <div className="option-group">
            <label>
              <input
                type="radio"
                value="url"
                checked={scanType === 'url'}
                onChange={(e) => setScanType(e.target.value)}
              />
              URL Scan
            </label>
            <label>
              <input
                type="radio"
                value="smart_contract"
                checked={scanType === 'smart_contract'}
                onChange={(e) => setScanType(e.target.value)}
              />
              Smart Contract Scan
            </label>
          </div>
          
          <div className="option-group">
            <label>
              <input
                type="radio"
                value="json"
                checked={outputFormat === 'json'}
                onChange={(e) => setOutputFormat(e.target.value)}
              />
              JSON Output
            </label>
            <label>
              <input
                type="radio"
                value="markdown"
                checked={outputFormat === 'markdown'}
                onChange={(e) => setOutputFormat(e.target.value)}
              />
              Markdown Output
            </label>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="scan-form">
          <div className="form-group">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder={scanType === 'url' ? "Enter URL to scan" : "Enter smart contract address or code"}
              className="url-input"
            />
            <button 
              type="submit" 
              disabled={loading} 
              className="scan-button"
              aria-label="Scan"
            >
              <span className="scan-icon">🔍</span>
            </button>
          </div>
          
          {error && <div className="error-message">{error}</div>}
        </form>

        <div className="cve-loader">
          <h3>Load CVE Data</h3>
          <form onSubmit={handleCveLoad} className="cve-form">
            <div className="form-group">
              <input
                type="text"
                value={cveData.id}
                onChange={(e) => setCveData(prev => ({ ...prev, id: e.target.value }))}
                placeholder="CVE ID (e.g., CVE-2024-51427)"
                className="cve-input"
              />
            </div>
            <div className="form-group">
              <input
                type="text"
                value={cveData.keyword}
                onChange={(e) => setCveData(prev => ({ ...prev, keyword: e.target.value }))}
                placeholder="Search keyword"
                className="cve-input"
              />
            </div>
            <div className="form-group">
              <input
                type="number"
                value={cveData.maxResults}
                onChange={(e) => setCveData(prev => ({ ...prev, maxResults: parseInt(e.target.value) }))}
                placeholder="Max results"
                className="cve-input"
              />
            </div>
            <div className="form-group checkbox">
              <label>
                <input
                  type="checkbox"
                  checked={cveData.loadSmartContracts}
                  onChange={(e) => setCveData(prev => ({ ...prev, loadSmartContracts: e.target.checked }))}
                />
                Load Smart Contract CVEs
              </label>
            </div>
            <button type="submit" disabled={loading} className="load-cve-button">
              Load CVE Data
            </button>
          </form>
        </div>
        
        {loading && (
          <div className="loading">
            <p>Analyzing security...</p>
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
                  <span className="meta-label">Target:</span>
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
            
            {results.message ? (
              <div className="message-section">
                <p>{results.message}</p>
                {results.details && (
                  <pre className="details-json">
                    {JSON.stringify(results.details, null, 2)}
                  </pre>
                )}
              </div>
            ) : (
              <>
                <div className="report-section">
                  <div className="section-title">Executive Summary</div>
                  <div className="summary-content">
                    <p>
                      {results.vulnerabilities && results.vulnerabilities.length > 0 
                        ? `We've identified ${results.vulnerabilities.length} potential security ${results.vulnerabilities.length === 1 ? 'issue' : 'issues'}. Review the detailed analysis below for specific findings and recommendations.`
                        : 'No significant security issues were detected in our initial scan. The target appears to implement standard security practices, but a comprehensive security audit is recommended for production systems.'}
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
                          <li className="recommendation-item">Maintain regular security assessments.</li>
                          <li className="recommendation-item">Implement Content Security Policy (CSP) if not already in place.</li>
                          <li className="recommendation-item">Keep all software dependencies and platforms updated.</li>
                        </>
                      )}
                    </ul>
                  </div>
                </div>
              </>
            )}
          </div>
        )}
        
        {scanHistory.length > 0 && !results && !loading && (
          <div className="scan-history">
            <h3>Recent Scans</h3>
            <ul className="history-list">
              {scanHistory.slice(0, 5).map((scan, index) => (
                <li key={index} className="history-item" onClick={() => setResults(scan.results)}>
                  <span className="history-url">{scan.url}</span>
                  <span className="history-type">{scan.type}</span>
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