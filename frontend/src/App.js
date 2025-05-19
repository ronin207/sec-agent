import React, { useState, useRef } from 'react';
import './App.css';

function App() {
  const [inputType, setInputType] = useState('url'); // 'url' or 'file'
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [files, setFiles] = useState([]);
  const fileInputRef = useRef(null);
  const [scanType, setScanType] = useState('url'); // 'url' or 'smart_contract'
  const [outputFormat, setOutputFormat] = useState('json'); // 'json' or 'markdown'
  const [cveData, setCveData] = useState({
    id: '',
    keyword: '',
    maxResults: 20,
    loadSmartContracts: false
  });
  const [githubToken, setGithubToken] = useState('');
  const [tokenSaved, setTokenSaved] = useState(false);
  const [activeTab, setActiveTab] = useState('summary');
  const [activeSeverity, setActiveSeverity] = useState('high');
  const [inputExpanded, setInputExpanded] = useState(false);

  // Handle expanding/collapsing input container
  const toggleInputContainer = () => {
    setInputExpanded(!inputExpanded);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (inputType === 'url' && !url) {
      setError('Please enter a GitHub URL');
      return;
    }
    
    if (inputType === 'file' && files.length === 0) {
      setError('Please upload at least one file');
      return;
    }
    
    setLoading(true);
    setError(null);
    setResults(null);
    
    try {
      // Set GitHub token if provided and this is a repository scan
      const isGithubRepo = url.includes('github.com');
      if (isGithubRepo && githubToken && !tokenSaved) {
        try {
          const tokenResponse = await fetch('http://localhost:8080/api/set-github-token', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token: githubToken }),
          });
          
          if (tokenResponse.ok) {
            setTokenSaved(true);
            console.log('GitHub token saved');
          } else {
            const tokenError = await tokenResponse.json();
            console.error('Error saving token:', tokenError);
          }
        } catch (err) {
          console.error('Error setting GitHub token:', err);
        }
      }

      let response;
      
      if (inputType === 'url') {
        // Handle URL scan
        const isRepo = url.includes('github.com');
        response = await fetch('http://localhost:8080/api/scan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ 
            target: url,
            is_repo: isRepo
          }),
        });
      } else {
        // Handle file upload
        const formData = new FormData();
        files.forEach(file => {
          formData.append('files', file);
        });
        
        response = await fetch('http://localhost:8080/api/scan/files', {
          method: 'POST',
          body: formData,
        });
      }
      
      if (!response.ok) {
        throw new Error(`Error: ${response.status} - ${response.statusText}`);
      }
      
      const data = await response.json();
      console.log('Response data:', data);
      setResults(data);
      
      // Add to scan history
      setScanHistory(prev => [...prev, { 
        input: inputType === 'url' ? url : 'Uploaded Files',
        timestamp: new Date(), 
        results: data,
        type: inputType
      }]);
    } catch (err) {
      console.error('Error details:', err);
      setError(`Failed to scan: ${err.message}. Make sure the backend server is running at http://localhost:8080`);
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (e) => {
    setFiles(Array.from(e.target.files));
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer.files.length > 0) {
      setFiles(Array.from(e.dataTransfer.files));
    }
  };

  const handleBrowseClick = () => {
    fileInputRef.current.click();
  };

  const removeFile = (indexToRemove) => {
    setFiles(files.filter((_, index) => index !== indexToRemove));
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

  const renderFindings = () => {
    if (!results) return null;
    
    // Helper function to get default code suggestions based on vulnerability type
    const getDefaultSuggestion = (vulnType) => {
      const lowerType = vulnType.toLowerCase();
      
      if (lowerType.includes('reentrancy')) {
        return {
          vulnerable: `function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}`,
          fixed: `function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount; // Update state before external call
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}`
        };
      } 
      else if (lowerType.includes('integer overflow') || lowerType.includes('underflow')) {
        return {
          vulnerable: `function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a + b; // Can overflow
}`,
          fixed: `// Option 1: Manual check
function add(uint256 a, uint256 b) public pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a, "Addition overflow");
    return c;
}

// Option 2: SafeMath library (Solidity < 0.8.0)
using SafeMath for uint256;
function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a.add(b);
}

// Option 3: Use built-in overflow checks (Solidity >= 0.8.0)`
        };
      }
      else if (lowerType.includes('unchecked') && (lowerType.includes('send') || lowerType.includes('call'))) {
        return {
          vulnerable: `function sendFunds(address payable recipient, uint256 amount) public {
    recipient.send(amount); // Return value not checked
}`,
          fixed: `function sendFunds(address payable recipient, uint256 amount) public {
    bool success = recipient.send(amount);
    require(success, "Transfer failed");
}

// Or use transfer() which automatically reverts on failure
function sendFunds(address payable recipient, uint256 amount) public {
    recipient.transfer(amount);
}`
        };
      }
      else if (lowerType.includes('dos')) {
        return {
          vulnerable: `function distribute(address[] memory recipients) public {
    for(uint i = 0; i < recipients.length; i++) {
        recipients[i].transfer(1 ether); // Will revert entire tx if one transfer fails
    }
}`,
          fixed: `function distribute(address[] memory recipients) public {
    for(uint i = 0; i < recipients.length; i++) {
        (bool success, ) = recipients[i].call{value: 1 ether}("");
        // Log failure but continue execution
        if (!success) {
            emit TransferFailed(recipients[i]);
        }
    }
}`
        };
      }
      else if (lowerType.includes('visibility')) {
        return {
          vulnerable: `function initializeContract(address _owner) {
    owner = _owner; // Missing visibility modifier (public by default)
}`,
          fixed: `function initializeContract(address _owner) private {
    owner = _owner;
}

// Or
function initializeContract(address _owner) internal {
    owner = _owner;
}`
        };
      }
      else if (lowerType.includes('compiler')) {
        return {
          vulnerable: `pragma solidity ^0.4.25;

contract VulnerableContract {
    // Vulnerable to older compiler bugs
}`,
          fixed: `pragma solidity ^0.8.20;

contract SecureContract {
    // Uses latest compiler with security improvements
}`
        };
      }
      
      // Default suggestion if no specific pattern matched
      return {
        vulnerable: "// Vulnerable code with security issues",
        fixed: "// Improved code implementing security best practices"
      };
    };
    
    const findingsBySeverity = {
      high: [],
      medium: [],
      low: [],
      info: []
    };
    
    // Extract vulnerabilities from the correct location in the response
    // The backend puts them in aggregated_results or directly in findings
    let vulnerabilities = [];
    
    // Check for findings in various locations in the response structure
    if (results.aggregated_results && results.aggregated_results.findings) {
      vulnerabilities = results.aggregated_results.findings;
    } else if (results.findings) {
      vulnerabilities = results.findings;
    } else if (results.tool_results) {
      // Extract findings from tool results if that's where they are
      results.tool_results.forEach(toolResult => {
        if (toolResult.findings && Array.isArray(toolResult.findings)) {
          vulnerabilities = [...vulnerabilities, ...toolResult.findings];
        }
      });
    } else if (results.vulnerabilities) {
      // Fall back to the original location if somehow that's used
      vulnerabilities = results.vulnerabilities;
    }
    
    console.log('Extracted vulnerabilities:', vulnerabilities);
    
    // Process findings by severity
    if (Array.isArray(vulnerabilities)) {
      vulnerabilities.forEach(vuln => {
        const severity = vuln.severity?.toLowerCase() || 'high';
        if (findingsBySeverity[severity]) {
          findingsBySeverity[severity].push(vuln);
        } else {
          findingsBySeverity.high.push(vuln);
        }
      });
    } else if (results.aggregated_results && results.aggregated_results.findings_by_severity) {
      // Handle case where backend provides findings already organized by severity
      const findingsBySeverityObj = results.aggregated_results.findings_by_severity;
      
      // Get full findings details from appropriate place in response
      const findingDetails = {};
      if (results.aggregated_results.details && Array.isArray(results.aggregated_results.details)) {
        results.aggregated_results.details.forEach(detail => {
          if (detail.id) {
            findingDetails[detail.id] = detail;
          }
        });
      }
      
      // Process each severity level
      Object.entries(findingsBySeverityObj).forEach(([severity, count]) => {
        const lowercaseSeverity = severity.toLowerCase();
        if (lowercaseSeverity in findingsBySeverity) {
          // Create placeholder findings based on the count
          for (let i = 0; i < count; i++) {
            findingsBySeverity[lowercaseSeverity].push({
              name: `${severity} Severity Issue`,
              severity: severity,
              description: `Security issue detected with ${severity} severity`
            });
          }
        }
      });
    }
    
    // Get total count of findings
    const totalFindings = Object.values(findingsBySeverity).reduce(
      (sum, findings) => sum + findings.length, 0
    );
    
    // If the backend returns total findings but we couldn't extract them correctly,
    // use the backend's count
    if (totalFindings === 0 && results.aggregated_results && results.aggregated_results.total_findings > 0) {
      // Check if we have findings by severity from backend
      if (results.aggregated_results.findings_by_severity) {
        const findingsBySeverityFromBackend = results.aggregated_results.findings_by_severity;
        
        // Create simple findings objects for each severity level
        Object.entries(findingsBySeverityFromBackend).forEach(([severity, count]) => {
          const lowercaseSeverity = severity.toLowerCase();
          if (lowercaseSeverity in findingsBySeverity) {
            for (let i = 0; i < count; i++) {
              findingsBySeverity[lowercaseSeverity].push({
                name: `${severity} Severity Issue`,
                severity: severity,
                description: `Security issue detected with ${severity} severity. See summary for details.`
              });
            }
          }
        });
      }
    }
    
    // Recalculate total findings after possible adjustments
    const recalculatedTotalFindings = Object.values(findingsBySeverity).reduce(
      (sum, findings) => sum + findings.length, 0
    );
    
    if (recalculatedTotalFindings === 0) {
      return (
        <div className="gemini-card no-vulnerabilities">
          <div className="success-icon">✓</div>
          <h3>Great news!</h3>
          <p>No vulnerabilities detected in your code.</p>
        </div>
      );
    }
    
    // Render tabs and findings based on active tab
    return (
      <div className="findings-section">
        <div className="findings-summary">
          <h3>Security Scan Results</h3>
          
          {/* Main tabs */}
          <div className="findings-tabs">
            <button 
              className={`tab-button ${activeTab === 'summary' ? 'active' : ''}`}
              onClick={() => setActiveTab('summary')}
            >
              Summary
            </button>
            <button 
              className={`tab-button ${activeTab === 'issues' ? 'active' : ''}`}
              onClick={() => setActiveTab('issues')}
            >
              Issues
            </button>
            <button 
              className={`tab-button ${activeTab === 'debug' ? 'active' : ''}`}
              onClick={() => setActiveTab('debug')}
            >
              Debug
            </button>
          </div>
          
          {/* Severity count badges - always visible */}
          <div className="findings-summary-counts">
            <div 
              className={`severity-count high ${activeTab === 'issues' && activeSeverity === 'high' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('issues');
                setActiveSeverity('high');
              }}
            >
              <span className="count">{findingsBySeverity.high.length}</span>
              <span className="label">High</span>
            </div>
            <div 
              className={`severity-count medium ${activeTab === 'issues' && activeSeverity === 'medium' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('issues');
                setActiveSeverity('medium');
              }}
            >
              <span className="count">{findingsBySeverity.medium.length}</span>
              <span className="label">Medium</span>
            </div>
            <div 
              className={`severity-count low ${activeTab === 'issues' && activeSeverity === 'low' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('issues');
                setActiveSeverity('low');
              }}
            >
              <span className="count">{findingsBySeverity.low.length}</span>
              <span className="label">Low</span>
            </div>
            <div 
              className={`severity-count info ${activeTab === 'issues' && activeSeverity === 'info' ? 'active' : ''}`}
              onClick={() => {
                setActiveTab('issues');
                setActiveSeverity('info');
              }}
            >
              <span className="count">{findingsBySeverity.info.length}</span>
              <span className="label">Info</span>
            </div>
          </div>
        </div>
        
        {/* Conditional rendering based on active tab */}
        {activeTab === 'summary' && (
          <div className="tab-content">
            {results.summary && (
              <div className="summary-container">
                <div className="gemini-card summary-card">
                  <div className="summary-header">
                    <h4>Executive Summary</h4>
                    <div className={`risk-badge ${results.summary.risk_assessment?.toLowerCase()}`}>
                      {results.summary.risk_assessment || 'Unknown'} Risk
                    </div>
                  </div>
                  
                  <div className="summary-content">
                    <p>{results.summary.summary}</p>
                  </div>
                </div>
                
                {results.summary.remediation_suggestions && results.summary.remediation_suggestions.length > 0 && (
                  <div className="gemini-card remediation-card">
                    <h4>Remediation Suggestions</h4>
                    <ul className="remediation-list">
                      {results.summary.remediation_suggestions.map((suggestion, idx) => (
                        <li key={idx} className="remediation-item">
                          {typeof suggestion === 'object' ? 
                            (suggestion.finding ? 
                              <>
                                <span className="suggestion-title">{suggestion.finding}</span>
                                {suggestion.suggestion && <span className="suggestion-detail">: {suggestion.suggestion}</span>}
                              </> 
                              : JSON.stringify(suggestion))
                            : suggestion}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {results.summary && results.summary.technical_findings && results.summary.technical_findings.length > 0 && (
                  <div className="gemini-card technical-card">
                    <h4>Technical Findings</h4>
                    {(() => {
                      // Group findings by vulnerability type
                      const groupedFindings = {};
                      
                      results.summary.technical_findings.forEach(finding => {
                        // Extract base text from different formats
                        let text = '';
                        
                        if (typeof finding === 'string') {
                          text = finding;
                          // Try to extract suggestion if in format "vulnerability: description => suggestion"
                          const suggestionMatch = text.match(/=>(.+)$/);
                          if (suggestionMatch) {
                            text = text.replace(/=>(.+)$/, '').trim();
                          }
                        } else if (typeof finding === 'object') {
                          text = finding.name || finding.description || JSON.stringify(finding);
                        }
                        
                        // Extract vulnerability type using various patterns
                        let vulnType = '';
                        
                        // Common vulnerability naming patterns
                        const patterns = [
                          /^(Reentrancy|Integer Overflow|Unchecked (Send|Return|Call)|DoS|Function Visibility|Outdated Compiler|Variable Naming)(?:\s+[^:]+)?:/i,
                          /^(Reentrancy|Integer Overflow|Unchecked (Send|Return|Call)|DoS|Function Visibility|Outdated Compiler|Variable Naming)/i
                        ];
                        
                        // Try to match against known vulnerability patterns
                        for (const pattern of patterns) {
                          const match = text.match(pattern);
                          if (match) {
                            vulnType = match[1];
                            break;
                          }
                        }
                        
                        // If no pattern matched, use first part of text or before colon
                        if (!vulnType) {
                          const colonMatch = text.match(/^([^:]+):/);
                          if (colonMatch) {
                            vulnType = colonMatch[1].trim();
                          } else {
                            // Fallback to first few words
                            const words = text.split(' ');
                            vulnType = words.length > 1 ? words.slice(0, 2).join(' ') : text;
                          }
                        }
                        
                        // Extract location from object or text
                        let location = '';
                        if (typeof finding === 'object' && finding.location) {
                          location = finding.location;
                        } else {
                          // Try to extract line numbers from the text using various patterns
                          const linePatterns = [
                            /line[s]?\s+(\d+(?:-\d+)?)/i,
                            /at line[s]?\s+(\d+(?:-\d+)?)/i,
                            /in line[s]?\s+(\d+(?:-\d+)?)/i,
                            /\(line[s]?\s+(\d+(?:-\d+)?)\)/i
                          ];
                          
                          for (const pattern of linePatterns) {
                            const match = text.match(pattern);
                            if (match) {
                              location = match[1];
                              break;
                            }
                          }
                        }
                        
                        // Create or add to grouped findings
                        if (!groupedFindings[vulnType]) {
                          groupedFindings[vulnType] = {
                            description: text,
                            locations: []
                          };
                        }
                        
                        if (location && !groupedFindings[vulnType].locations.includes(location)) {
                          groupedFindings[vulnType].locations.push(location);
                        }
                      });
                      
                      // Render grouped findings
                      return (
                        <div className="findings-grid">
                          {Object.entries(groupedFindings).map(([type, data], idx) => (
                            <div key={idx} className="finding-item">
                              <div className="finding-header">
                                <h5>{type}</h5>
                                <div className="finding-tag">Security</div>
                              </div>
                              {data.locations.length > 0 && (
                                <div className="finding-location">
                                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0118 0z"></path>
                                    <circle cx="12" cy="10" r="3"></circle>
                                  </svg>
                                  Lines: {data.locations.join(', ')}
                                </div>
                              )}
                              <p className="finding-description">{data.description}</p>
                            </div>
                          ))}
                        </div>
                      );
                    })()}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
        
        {activeTab === 'issues' && (
          <div className="tab-content">
            {/* Display findings of the active severity */}
            {findingsBySeverity[activeSeverity].length > 0 ? (
              <div className="findings-list">
                <h3 className="severity-heading">
                  <span className={`severity-indicator ${activeSeverity}`}></span>
                  {activeSeverity.charAt(0).toUpperCase() + activeSeverity.slice(1)} Severity Issues ({findingsBySeverity[activeSeverity].length})
                </h3>
                {findingsBySeverity[activeSeverity].map((finding, idx) => (
                  <div key={idx} className="gemini-card finding-card">
                    <div className="finding-header">
                      <h5>{finding.name || 'Security Vulnerability'}</h5>
                      <span className={`severity-badge ${activeSeverity}`}>
                        {activeSeverity.charAt(0).toUpperCase() + activeSeverity.slice(1)}
                      </span>
                    </div>
                    <p className="finding-description">{finding.description}</p>
                    {finding.location && (
                      <div className="finding-location">
                        <strong>Location:</strong> {finding.location}
                      </div>
                    )}
                    {finding.recommendation && (
                      <div className="finding-recommendation">
                        <strong>Recommendation:</strong> {finding.recommendation}
                      </div>
                    )}
                    
                    {/* Add code suggestion */}
                    <div className="code-suggestion">
                      <h6>Code Suggestion</h6>
                      
                      <div className="code-sections">
                        <div className="code-section vulnerable">
                          <div className="code-header">
                            <span className="section-title">Vulnerable Code</span>
                            <button 
                              className="copy-btn" 
                              onClick={() => navigator.clipboard.writeText(getDefaultSuggestion(finding.name || '').vulnerable)}
                            >
                              Copy
                            </button>
                          </div>
                          <div className="code-content">
                            {getDefaultSuggestion(finding.name || '').vulnerable}
                          </div>
                        </div>
                        
                        <div className="code-section fixed">
                          <div className="code-header">
                            <span className="section-title">Suggested Fix</span>
                            <button 
                              className="copy-btn" 
                              onClick={() => navigator.clipboard.writeText(getDefaultSuggestion(finding.name || '').fixed)}
                            >
                              Copy
                            </button>
                          </div>
                          <div className="code-content">
                            {getDefaultSuggestion(finding.name || '').fixed}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="gemini-card no-findings-card">
                <div className="no-findings-content">
                  <div className="info-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10"></circle>
                      <line x1="12" y1="16" x2="12" y2="12"></line>
                      <line x1="12" y1="8" x2="12.01" y2="8"></line>
                    </svg>
                  </div>
                  <h4>No {activeSeverity} severity findings detected</h4>
                  <p>Great news! No security issues were found with this severity level.</p>
                </div>
              </div>
            )}
          </div>
        )}
        
        {activeTab === 'debug' && (
          <div className="tab-content">
            <div className="summary-container">
              <div className="gemini-card debug-intro-card">
                <div className="debug-header">
                  <h4>Debug Information</h4>
                  <div className="debug-tag">Developer Tools</div>
                </div>
                <p className="debug-intro">This section shows the raw response data from the backend for debugging and developer insights.</p>
              </div>
                
              <div className="gemini-card debug-data-card">
                <div className="debug-controls">
                  <h4>API Response</h4>
                  <div className="debug-actions">
                    <button 
                      className="debug-action-btn"
                      onClick={() => {
                        navigator.clipboard.writeText(JSON.stringify(results, null, 2));
                      }}
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path>
                      </svg>
                      Copy JSON
                    </button>
                  </div>
                </div>
                <div className="debug-json-container">
                  <pre className="debug-json">
                    {JSON.stringify(results, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="gemini-app">
      <header className="gemini-header">
        <h1>Security AI Agent</h1>
      </header>
      
      <main className="gemini-main">
        {!results && !loading && (
          <div className="ready-message">
            Hello World
          </div>
        )}
        
        {loading && (
          <div className="content-area">
            <div className="gemini-card loading-card">
              <div className="loading-spinner"></div>
              <p>Scanning your code for security vulnerabilities...</p>
              <p className="loading-detail">This may take a few moments</p>
            </div>
          </div>
        )}
        
        {!loading && results && (
          <div className="content-area">
            {renderFindings()}
            
            {/* Display any error messages */}
            {error && (
              <div className="gemini-card error-card">
                <div className="error-icon">❌</div>
                <p>{error}</p>
              </div>
            )}
          </div>
        )}
        
        <div className={`input-container ${inputExpanded ? 'expanded' : ''}`}>
          <div className="input-handle" onClick={toggleInputContainer}></div>
          <div className="input-wrapper">
            <div className="input-type-selection">
              <button 
                className={`input-type-btn ${inputType === 'url' ? 'active' : ''}`}
                onClick={() => setInputType('url')}
              >
                GitHub URL
              </button>
              <button 
                className={`input-type-btn ${inputType === 'file' ? 'active' : ''}`}
                onClick={() => setInputType('file')}
              >
                Upload Files
              </button>
            </div>
            
            <form onSubmit={handleSubmit}>
              {inputType === 'url' ? (
                <div className="gemini-card input-card">
                  <div className="url-input-container">
                    <input
                      type="text"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="https://github.com/username/repository"
                      className="modern-input"
                      aria-label="GitHub repository URL"
                    />
                    <button 
                      type="submit" 
                      className="arrow-submit-btn"
                      disabled={loading || !url}
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 19V5M5 12l7-7 7 7" />
                      </svg>
                    </button>
                  </div>
                  
                  {url.includes('github.com') && (
                    <div className="token-section">
                      <div className="token-header">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M15 7a2 2 0 0 1 2 2M9 17a2 2 0 0 0 2 2M12 15V5M5 12h14" />
                          <circle cx="12" cy="12" r="9" />
                        </svg>
                        <span>GitHub Token (Optional)</span>
                      </div>
                      <div className="token-input-wrapper">
                        <input
                          type="password"
                          id="github-token"
                          value={githubToken}
                          onChange={(e) => {
                            setGithubToken(e.target.value);
                            setTokenSaved(false);
                          }}
                          placeholder="Enter personal access token for private repositories"
                          className="modern-input"
                        />
                        {tokenSaved && 
                          <div className="token-saved-badge">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <path d="M20 6L9 17l-5-5" />
                            </svg>
                            Token set
                          </div>
                        }
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div 
                  className="file-drop-area"
                  onDragOver={handleDragOver}
                  onDrop={handleDrop}
                >
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    multiple
                    style={{ display: 'none' }}
                  />
                  {files.length === 0 ? (
                    <>
                      <div className="upload-icon">📂</div>
                      <p>Drag and drop files here, or <button type="button" className="browse-btn" onClick={handleBrowseClick}>browse</button></p>
                      <p className="file-help">Supports .sol, .js, .py, and other code files</p>
                    </>
                  ) : (
                    <div className="file-list">
                      <h4>Files to scan:</h4>
                      <ul>
                        {files.map((file, index) => (
                          <li key={index}>
                            {file.name}
                            <button 
                              type="button" 
                              className="remove-file-btn"
                              onClick={() => removeFile(index)}
                            >
                              ×
                            </button>
                          </li>
                        ))}
                      </ul>
                      <button 
                        type="submit" 
                        className="scan-files-btn"
                        disabled={loading}
                      >
                        Scan Files
                      </button>
                    </div>
                  )}
                </div>
              )}
              
              {error && <div className="error-message">{error}</div>}
            </form>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;