"""
CVE Data Loader utility for the Security Agent.
Handles fetching CVE data from the MITRE CVE database.
"""
import os
import json
import requests
import re
import time
from typing import List, Dict, Optional, Any
import logging
from datetime import datetime
from bs4 import BeautifulSoup

# Import Selenium components for headless browser
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.webdriver.common.by import By
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from webdriver_manager.chrome import ChromeDriverManager
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False

from langchain_core.documents import Document
from backend.config.settings import CVE_API_KEY, SOURCES_DIR
from backend.utils.helpers import get_logger

# Get logger instance
logger = get_logger('security_agent')

class CVEDataLoader:
    """
    Utility for loading CVE (Common Vulnerabilities and Exposures) data
    from various sources including MITRE's CVE database.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("CVE_API_KEY")
        self.cache_dir = os.path.join(SOURCES_DIR, "cve_cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        
    def fetch_cve_by_id(self, cve_id: str, extract_json: bool = True) -> Optional[Dict]:
        """
        Fetch a specific CVE by its ID from the MITRE CVE database
        
        Args:
            cve_id: The CVE ID (e.g., "CVE-2024-51427")
            extract_json: Whether to try extracting the official JSON record
        
        Returns:
            Dictionary containing CVE data
        """
        cache_file = os.path.join(self.cache_dir, f"{cve_id}.json")
        
        # Check if we have this cached
        if os.path.exists(cache_file):
            logger.info(f"Loading {cve_id} from cache")
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # If not cached, fetch from the MITRE CVE website
        logger.info(f"Fetching {cve_id} from MITRE CVE website")
        mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        
        try:
            response = requests.get(mitre_url)
            response.raise_for_status()
            
            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Try to extract the embedded JSON record if requested
            if extract_json:
                json_data = self._extract_json_from_page(soup, cve_id)
                if json_data:
                    logger.info(f"Successfully extracted JSON record for {cve_id}")
                    
                    # Import the JSON data using our import function
                    cve_data = self.import_cve_json(json_data)
                    if cve_data:
                        # Cache the result
                        with open(cache_file, 'w') as f:
                            json.dump(cve_data, f)
                        
                        return cve_data
            
            # Fall back to extracting data from HTML if JSON extraction failed
            logger.info(f"Falling back to HTML extraction for {cve_id}")
            cve_data = self._extract_cve_data_from_html(soup, cve_id)
            
            # Cache the result
            with open(cache_file, 'w') as f:
                json.dump(cve_data, f)
                
            return cve_data
        except Exception as e:
            logger.error(f"Error fetching CVE data for {cve_id}: {e}")
            return None
    
    def search_cves(self, keyword: str, max_results: int = 20) -> Dict:
        """
        Search for CVEs using a keyword
        """
        # Check if the keyword is a CVE ID
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        if cve_pattern.match(keyword):
            # If it's a CVE ID, use fetch_cve_by_id instead
            cve_data = self.fetch_cve_by_id(keyword)
            if cve_data:
                # Format as if it came from a search
                return {"vulnerabilities": [{"cve": cve_data}]}
            return {"vulnerabilities": []}
        
        # Otherwise, proceed with keyword search
        cache_file = os.path.join(self.cache_dir, f"search_{keyword.replace(' ', '_')}.json")
        
        # Check if we have this search cached and it's not older than 1 day
        if os.path.exists(cache_file):
            file_time = os.path.getmtime(cache_file)
            if (datetime.now().timestamp() - file_time) < 86400:  # 24 hours in seconds
                logger.info(f"Loading search results for '{keyword}' from cache")
                with open(cache_file, 'r') as f:
                    return json.load(f)
        
        # If not cached or too old, fetch from the MITRE CVE website
        logger.info(f"Searching for CVEs with keyword '{keyword}'")
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={keyword}"
        
        try:
            response = requests.get(url)
            response.raise_for_status()
            
            # Parse HTML with BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract search results from the page
            vulnerabilities = self._extract_search_results_from_html(soup, max_results)
            search_results = {"vulnerabilities": vulnerabilities}
            
            # Cache the result
            with open(cache_file, 'w') as f:
                json.dump(search_results, f)
                
            return search_results
        except Exception as e:
            logger.error(f"Error searching CVEs with keyword '{keyword}': {e}")
            return {"vulnerabilities": []}
    
    def _extract_cve_data_from_html(self, soup, cve_id: str) -> Dict:
        """
        Extract CVE data from the MITRE CVE HTML page
        """
        try:
            # Check if CVE exists or if we're looking at a "CVE Not Found" page
            if "ERROR: CVE ID Not Found" in soup.text:
                logger.warning(f"CVE ID {cve_id} not found in MITRE database")
                return {"id": cve_id, "descriptions": [{"lang": "en", "value": "CVE ID not found in MITRE database"}]}
            
            # Extract description - there are multiple possible locations
            description = "No description available"
            
            # Method 1: Look in the vulnerability section
            vuln_section = soup.find('div', {'class': 'vuln-detail-table-container'})
            if vuln_section:
                desc_rows = vuln_section.find_all('tr')
                for row in desc_rows:
                    cells = row.find_all('td')
                    if len(cells) >= 2:
                        if "Description" in cells[0].get_text():
                            description = cells[1].get_text(strip=True)
                            break
            
            # Method 2: Look for a dedicated description section
            if description == "No description available":
                desc_div = soup.find('div', string=lambda text: text and 'Description' in text)
                if desc_div:
                    next_p = desc_div.find_next('p')
                    if next_p:
                        description = next_p.get_text(strip=True)
            
            # Method 3: Look for specific description divs or IDs
            if description == "No description available":
                desc_div = soup.find('div', {'id': 'vulnDescription'}) or soup.find('div', {'class': 'cvedetailssummary'})
                if desc_div:
                    description = desc_div.get_text(strip=True)
            
            # Method 4: Look for description in table format
            if description == "No description available":
                table = soup.find('table', {'id': 'GeneratedTable'})
                if table:
                    rows = table.find_all('tr')
                    for row in rows:
                        header = row.find('th')
                        if header and "Description" in header.get_text():
                            desc_cell = row.find('td')
                            if desc_cell:
                                description = desc_cell.get_text(strip=True)
                                break
            
            # Method 5: Last resort - look for any tag containing "description" in the page
            if description == "No description available":
                for elem in soup.find_all(['p', 'div', 'td', 'span']):
                    if "Description:" in elem.get_text():
                        next_elem = elem.next_sibling
                        if next_elem and next_elem.string:
                            description = next_elem.string.strip()
                            break
            
            # Extract references - look for specific reference sections
            references = []
            
            # Method 1: Look for reference links in a table
            ref_table = soup.find('table', {'id': 'vulnrefstable'})
            if ref_table:
                for link in ref_table.find_all('a'):
                    href = link.get('href')
                    if href and not href.startswith('#') and not href.startswith('/'):
                        references.append({"url": href})
            
            # Method 2: Look for a references section header
            if not references:
                ref_header = soup.find(string=lambda text: text and 'References' in text)
                if ref_header:
                    ref_section = ref_header.parent
                    if ref_section:
                        for link in ref_section.find_all('a'):
                            href = link.get('href')
                            if href and not href.startswith('#') and not href.startswith('/'):
                                references.append({"url": href})
            
            # Extract published date
            published = "Unknown"
            
            # Method 1: Look for published date in a table
            for row in soup.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) >= 2:
                    cell_text = cells[0].get_text()
                    if "Published" in cell_text:
                        published = cells[1].get_text(strip=True)
                        break
                        
            # Method 2: Look for published date anywhere in the text
            if published == "Unknown":
                published_pattern = re.compile(r'Published:\s*([\d\-]+)')
                published_match = soup.find(string=published_pattern)
                if published_match:
                    match = published_pattern.search(published_match)
                    if match:
                        published = match.group(1)

            # Debug: Print some info about what we found
            logger.debug(f"Extracted description for {cve_id}: {description[:50]}...")
            logger.debug(f"Found {len(references)} references for {cve_id}")
            logger.debug(f"Published date for {cve_id}: {published}")
                        
            # Construct the CVE data object
            cve_data = {
                "id": cve_id,
                "published": published,
                "descriptions": [
                    {
                        "lang": "en",
                        "value": description
                    }
                ],
                "references": references
            }
            
            return cve_data
        
        except Exception as e:
            logger.error(f"Error extracting CVE data from HTML: {e}")
            return {"id": cve_id, "descriptions": [{"lang": "en", "value": "Error processing CVE data"}]}
    
    def _extract_search_results_from_html(self, soup, max_results: int) -> List[Dict]:
        """
        Extract CVE search results from the MITRE CVE HTML page
        """
        vulnerabilities = []
        
        try:
            # Find all CVE entries in the search results
            table = soup.find('div', {'id': 'TableWithRules'})
            if not table:
                return vulnerabilities
                
            cve_rows = table.find_all('tr')[1:]  # Skip header row
            
            # Limit to max_results
            cve_rows = cve_rows[:max_results]
            
            for row in cve_rows:
                cells = row.find_all('td')
                if len(cells) >= 2:
                    # Extract CVE ID and description
                    cve_id_cell = cells[0]
                    desc_cell = cells[1]
                    
                    cve_id = cve_id_cell.get_text(strip=True)
                    description = desc_cell.get_text(strip=True)
                    
                    # Create a CVE entry
                    cve_entry = {
                        "cve": {
                            "id": cve_id,
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "value": description
                                }
                            ]
                        }
                    }
                    vulnerabilities.append(cve_entry)
        
        except Exception as e:
            logger.error(f"Error extracting search results from HTML: {e}")
            
        return vulnerabilities
        
    def import_cve_json(self, cve_json: Dict) -> Dict:
        """
        Import a CVE record from its structured JSON format.
        This format is the official CVE Record format available from MITRE/NIST.
        
        Args:
            cve_json: A dictionary containing the CVE JSON record
        
        Returns:
            A normalized CVE data dictionary for the knowledge base
        """
        try:
            # Basic validation - ensure we have required fields
            if not cve_json or "dataType" not in cve_json or cve_json["dataType"] != "CVE_RECORD":
                logger.error("Invalid CVE JSON format - missing required fields")
                return None
                
            # Extract key information
            cve_metadata = cve_json.get("cveMetadata", {})
            containers = cve_json.get("containers", {})
            cna_container = containers.get("cna", {})
            adp_container = containers.get("adp", [{}])[0] if "adp" in containers and containers["adp"] else {}
            
            # Get CVE ID
            cve_id = cve_metadata.get("cveId", "Unknown")
            
            # Get description
            description = "No description available"
            descriptions = cna_container.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", description)
                    break
                    
            # Get published date
            published = cve_metadata.get("datePublished", "Unknown")
            
            # Get references
            references = []
            for ref in cna_container.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append({"url": url})
            
            # Get severity and CVSS score if available
            severity = "Unknown"
            base_score = "Unknown"
            vector_string = "Unknown"
            
            if "metrics" in adp_container:
                for metric in adp_container["metrics"]:
                    if "cvssV3_1" in metric:
                        cvss = metric["cvssV3_1"]
                        severity = cvss.get("baseSeverity", severity)
                        base_score = cvss.get("baseScore", base_score)
                        vector_string = cvss.get("vectorString", vector_string)
                        break
            
            # Get CWE information
            cwe_id = "Unknown"
            problem_types = adp_container.get("problemTypes", [])
            for problem in problem_types:
                for desc in problem.get("descriptions", []):
                    if desc.get("type") == "CWE":
                        cwe_id = desc.get("cweId", cwe_id)
                        break
            
            # Get affected products
            affected_products = []
            for affected in adp_container.get("affected", []):
                vendor = affected.get("vendor", "")
                product = affected.get("product", "")
                if vendor and product:
                    for version in affected.get("versions", []):
                        version_str = version.get("version", "")
                        status = version.get("status", "")
                        if version_str and status:
                            affected_products.append(f"{vendor} {product} {version_str}")
            
            # Return normalized CVE data
            cve_data = {
                "id": cve_id,
                "published": published,
                "descriptions": [
                    {
                        "lang": "en",
                        "value": description
                    }
                ],
                "references": references,
                "severity": severity,
                "base_score": base_score,
                "vector_string": vector_string,
                "cwe_id": cwe_id,
                "affected_products": affected_products,
                "tags": cna_container.get("tags", [])
            }
            
            # Cache the processed data
            cache_file = os.path.join(self.cache_dir, f"{cve_id}.json")
            with open(cache_file, 'w') as f:
                json.dump(cve_data, f)
                
            logger.info(f"Successfully imported {cve_id} from JSON record")
            return cve_data
            
        except Exception as e:
            logger.error(f"Error importing CVE JSON: {e}")
            return None
    
    def convert_to_documents(self, cve_data: Dict) -> List[Document]:
        """
        Convert CVE data to Document objects for the knowledge base
        """
        documents = []
        
        if not cve_data or "vulnerabilities" not in cve_data:
            return documents
            
        for vuln in cve_data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            
            # Extract key information
            cve_id = cve.get("id", "Unknown")
            published = cve.get("published", "Unknown")
            descriptions = cve.get("descriptions", [])
            
            # Get English description
            description = "No description available"
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", description)
                    break
            
            # Extract severity and score if available
            severity = cve.get("severity", "Unknown")
            base_score = cve.get("base_score", "Unknown")
            vector_string = cve.get("vector_string", "Unknown")
            cwe_id = cve.get("cwe_id", "Unknown")
            
            # Extract references
            references = []
            for ref in cve.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)
            
            # Format content for the document
            content = f"CVE ID: {cve_id}\n"
            content += f"Description: {description}\n"
            if published != "Unknown":
                content += f"Published: {published}\n"
            if severity != "Unknown":
                content += f"Severity: {severity}\n"
            if base_score != "Unknown":
                content += f"CVSS Score: {base_score}\n"
            if vector_string != "Unknown":
                content += f"CVSS Vector: {vector_string}\n"
            if cwe_id != "Unknown":
                content += f"CWE: {cwe_id}\n"
            if references:
                content += f"References: {', '.join(references[:3])}\n"
            
            # Add affected products if available
            affected_products = cve.get("affected_products", [])
            if affected_products:
                content += f"Affected Products: {', '.join(affected_products[:3])}\n"
            
            # Add tags if available
            tags = cve.get("tags", [])
            if tags:
                content += f"Tags: {', '.join(tags)}\n"
            
            # Create document with enhanced metadata
            # Convert any lists to strings to ensure compatibility with Chroma
            metadata = {
                "type": "vulnerability",
                "id": cve_id,
                "published": str(published),
                "severity": str(severity),
                "score": str(base_score),
                "cwe_id": str(cwe_id)
            }
            
            # Convert any list to a comma-separated string for Chroma compatibility
            if tags:
                metadata["tags"] = ", ".join(tags) if isinstance(tags, list) else str(tags)
            
            document = Document(
                page_content=content,
                metadata=metadata
            )
            
            documents.append(document)
        
        return documents

    def load_smart_contract_cves(self) -> List[Document]:
        """
        Load CVEs related to smart contracts
        """
        # Search for smart contract related CVEs
        cve_data = self.search_cves("smart contract", max_results=50)
        documents = self.convert_to_documents(cve_data)
        
        # Also search for blockchain security CVEs since they're often related
        blockchain_cve_data = self.search_cves("blockchain", max_results=50)
        blockchain_documents = self.convert_to_documents(blockchain_cve_data)
        
        documents.extend(blockchain_documents)
        
        return documents
    
    def _extract_json_from_page(self, soup, cve_id: str) -> Optional[Dict]:
        """
        Extract the embedded JSON record from a CVE page
        
        Args:
            soup: BeautifulSoup parsed HTML
            cve_id: CVE ID for logging
            
        Returns:
            Dictionary containing the JSON record or None if not found
        """
        try:
            # Check if we can use Selenium (headless browser) for extraction
            if HAS_SELENIUM:
                logger.info(f"Attempting to extract JSON using headless browser for {cve_id}")
                json_data = self._extract_json_with_selenium(cve_id)
                if json_data:
                    logger.info(f"Successfully extracted JSON with headless browser for {cve_id}")
                    return json_data
            
            # Look for the JSON data in the page using the specific button ID
            logger.info(f"Attempting to extract JSON from #cve-view-json button for {cve_id}")
            
            # Method 1: Look for the specific button with ID "cve-view-json"
            json_button = soup.find('button', {'id': 'cve-view-json'})
            if json_button:
                logger.info(f"Found #cve-view-json button for {cve_id}")
                
                # The JSON might be in the data attributes of the button
                for attr_name, attr_value in json_button.attrs.items():
                    if attr_name.startswith('data-') and isinstance(attr_value, str) and '{' in attr_value:
                        try:
                            cve_data = json.loads(attr_value)
                            logger.info(f"Successfully extracted JSON from button data attribute for {cve_id}")
                            return cve_data
                        except json.JSONDecodeError:
                            logger.warning(f"Found JSON-like data in button attribute but failed to parse")
                
                # The button might be used to toggle a modal that contains JSON
                modal_target = json_button.get('data-target') or json_button.get('data-bs-target')
                if modal_target and modal_target.startswith('#'):
                    modal_id = modal_target[1:]  # Remove the # prefix
                    modal = soup.find('div', {'id': modal_id})
                    if modal:
                        # Look for JSON within the modal
                        pre_tags = modal.find_all('pre')
                        for pre in pre_tags:
                            json_text = pre.get_text(strip=True)
                            if json_text and json_text.startswith('{') and json_text.endswith('}'):
                                try:
                                    cve_data = json.loads(json_text)
                                    logger.info(f"Successfully extracted JSON from modal content for {cve_id}")
                                    return cve_data
                                except json.JSONDecodeError:
                                    logger.warning(f"Found JSON-like content in modal but failed to parse")
            
            # Method 2: Look for specific script tag with JSON data
            logger.info(f"Looking for JSON in script tags for {cve_id}")
            for script in soup.find_all('script'):
                if script.string:
                    # Look for JSON data in script
                    # First check for the specific button's click handler or data
                    button_patterns = [
                        re.compile(r'document\.getElementById\([\'"]cve-view-json[\'"]\).*?({.*?dataType.*?CVE_RECORD.*?})', re.DOTALL),
                        re.compile(r'[\'"](#cve-view-json|cve-view-json)[\'"].*?({.*?dataType.*?CVE_RECORD.*?})', re.DOTALL)
                    ]
                    
                    for pattern in button_patterns:
                        match = pattern.search(script.string)
                        if match:
                            try:
                                json_str = match.group(1)
                                json_str = json_str.replace('\\', '')  # Remove escape characters
                                cve_data = json.loads(json_str)
                                logger.info(f"Successfully extracted JSON associated with button from script for {cve_id}")
                                return cve_data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Found potential button JSON in script but failed to parse: {e}")
                    
                    # More general patterns
                    json_patterns = [
                        # Pattern for CVE record variable assignment
                        re.compile(r'var\s+cveRecord\s*=\s*({.*?dataType.*?CVE_RECORD.*?});', re.DOTALL),
                        re.compile(r'cveRecord\s*=\s*({.*?dataType.*?CVE_RECORD.*?});', re.DOTALL),
                        # Pattern for specific CVE ID in JSON
                        re.compile(r'({.*?"cveId"\s*:\s*"' + re.escape(cve_id) + '".*?})', re.DOTALL)
                    ]
                    
                    for pattern in json_patterns:
                        match = pattern.search(script.string)
                        if match:
                            try:
                                json_str = match.group(1)
                                # Clean up the JSON string if needed
                                json_str = json_str.replace('\\\\', '\\').replace("\\'", "'")
                                cve_data = json.loads(json_str)
                                logger.info(f"Successfully extracted JSON data from script for {cve_id}")
                                return cve_data
                            except json.JSONDecodeError as e:
                                logger.warning(f"Found potential JSON in script but failed to parse: {e}")
            
            # Method 3: Check if there's an AJAX call to fetch the JSON data
            logger.info(f"Looking for AJAX calls to fetch JSON for {cve_id}")
            ajax_patterns = [
                re.compile(r'\.get\([\'"]([^\'"]*/cve/[^\'"]*/json)[\'"]'),
                re.compile(r'fetch\([\'"]([^\'"]*/cve/[^\'"]*/json)[\'"]')
            ]
            
            for script in soup.find_all('script'):
                if script.string:
                    for pattern in ajax_patterns:
                        match = pattern.search(script.string)
                        if match:
                            json_url = match.group(1)
                            if not json_url.startswith('http'):
                                # Relative URL - make it absolute
                                json_url = f"https://cve.mitre.org{json_url}"
                            
                            try:
                                logger.info(f"Attempting to fetch JSON from URL: {json_url}")
                                json_response = requests.get(json_url, timeout=10)
                                json_response.raise_for_status()
                                cve_data = json_response.json()
                                logger.info(f"Successfully fetched JSON data from URL for {cve_id}")
                                return cve_data
                            except Exception as e:
                                logger.warning(f"Failed to fetch JSON from URL {json_url}: {e}")
            
            # Method 4: Try direct NVD API as fallback
            try:
                logger.info(f"Attempting to fetch {cve_id} from NVD API")
                nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                headers = {}
                if self.api_key:
                    headers['apiKey'] = self.api_key
                
                nvd_response = requests.get(nvd_url, headers=headers, timeout=10)
                if nvd_response.status_code == 200:
                    nvd_data = nvd_response.json()
                    if "vulnerabilities" in nvd_data and nvd_data["vulnerabilities"]:
                        logger.info(f"Successfully fetched {cve_id} from NVD API")
                        return nvd_data
                    else:
                        logger.warning(f"NVD API returned no vulnerabilities for {cve_id}")
            except Exception as e:
                logger.warning(f"Failed to fetch {cve_id} from NVD API: {e}")
            
            logger.warning(f"Could not find embedded JSON record for {cve_id}")
            return None
            
        except Exception as e:
            logger.error(f"Error extracting JSON from page for {cve_id}: {e}")
            return None
    
    def _extract_json_with_selenium(self, cve_id: str) -> Optional[Dict]:
        """
        Extract JSON data by simulating a click on the 'View JSON' button using Selenium
        
        Args:
            cve_id: The CVE ID to look up
            
        Returns:
            Dictionary containing the JSON data or None if unsuccessful
        """
        driver = None
        try:
            # Set up headless Chrome browser
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")  # Required for some environments
            chrome_options.add_argument("--disable-dev-shm-usage")  # Required for some environments
            
            # Initialize the Chrome driver
            driver = webdriver.Chrome(
                service=ChromeService(ChromeDriverManager().install()),
                options=chrome_options
            )
            
            # Navigate to the CVE page
            url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
            logger.info(f"Navigating to {url} with headless browser")
            driver.get(url)
            
            # Wait for the page to fully load and for the button to be present
            wait = WebDriverWait(driver, 10)
            try:
                # Find and click the "View JSON" button
                view_json_button = wait.until(EC.element_to_be_clickable((By.ID, "cve-view-json")))
                logger.info(f"Found 'View JSON' button for {cve_id}, clicking it")
                view_json_button.click()
                
                # Wait for the modal to appear
                logger.info(f"Waiting for JSON modal to appear for {cve_id}")
                modal = wait.until(EC.visibility_of_element_located((By.ID, "cveRecordModal")))
                
                # Get the JSON content from the modal
                pre_tag = modal.find_element(By.TAG_NAME, "pre")
                json_text = pre_tag.text
                
                # Parse the JSON
                if json_text:
                    logger.info(f"Found JSON text in modal for {cve_id}, parsing it")
                    return json.loads(json_text)
            except Exception as e:
                logger.warning(f"Error interacting with 'View JSON' button: {e}")
            
            # If we couldn't get the JSON via the button, try finding it in the page source
            logger.info(f"Looking for JSON in page source for {cve_id}")
            page_source = driver.page_source
            
            # Look for patterns in the page source that might contain the JSON data
            patterns = [
                r'var\s+cveRecord\s*=\s*({.*?dataType.*?CVE_RECORD.*?});',
                r'cveRecord\s*=\s*({.*?dataType.*?CVE_RECORD.*?});',
                r'({.*?"cveId"\s*:\s*"' + re.escape(cve_id) + '".*?dataType.*?CVE_RECORD.*?})'
            ]
            
            for pattern in patterns:
                matches = re.search(pattern, page_source, re.DOTALL)
                if matches:
                    json_str = matches.group(1)
                    # Clean up the JSON string if needed
                    json_str = json_str.replace('\\\\', '\\').replace("\\'", "'")
                    try:
                        json_data = json.loads(json_str)
                        logger.info(f"Successfully extracted JSON from page source for {cve_id}")
                        return json_data
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON from page source: {e}")
            
            return None
        
        except Exception as e:
            logger.error(f"Error extracting JSON with Selenium: {e}")
            return None
        
        finally:
            # Always close the WebDriver
            if driver:
                driver.quit()
    
    def fetch_from_nvd_api(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch CVE data directly from the NIST National Vulnerability Database API
        
        Args:
            cve_id: The CVE ID (e.g., "CVE-2024-51427")
            
        Returns:
            Processed CVE data dictionary or None if unsuccessful
        """
        logger.info(f"Fetching {cve_id} from NVD API")
        
        cache_file = os.path.join(self.cache_dir, f"{cve_id}_nvd.json")
        
        # Check if we have this cached
        if os.path.exists(cache_file):
            logger.info(f"Loading {cve_id} from NVD cache")
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # Build the API URL
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        # Set up headers
        headers = {
            'Accept': 'application/json',
            'User-Agent': 'Security-Agent/1.0 (https://github.com/your-repo/security-agent)'
        }
        
        # Add API key if available
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            logger.info(f"Requesting data from NVD API for {cve_id}")
            response = requests.get(api_url, headers=headers, timeout=10)
            
            # Check for rate limiting (common with NVD API)
            if response.status_code == 403:
                logger.warning(f"NVD API returned 403 Forbidden. You may need an API key. See https://nvd.nist.gov/developers/request-an-api-key")
                return None
                
            # Check for other errors
            if response.status_code != 200:
                logger.warning(f"NVD API returned status code {response.status_code}")
                return None
            
            # Parse the response
            nvd_data = response.json()
            
            # Check if we got any vulnerabilities
            if "vulnerabilities" not in nvd_data or not nvd_data["vulnerabilities"]:
                logger.warning(f"NVD API returned no vulnerabilities for {cve_id}")
                return None
            
            # Process the NVD data into our normalized format
            cve_item = nvd_data["vulnerabilities"][0]["cve"]
            
            # Extract key information
            published = cve_item.get("published", "Unknown")
            descriptions = cve_item.get("descriptions", [])
            
            # Get English description
            description = "No description available"
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "No description")
                    break
            
            # Get references
            references = []
            for ref in cve_item.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append({"url": url})
            
            # Extract CVSS data
            severity = "Unknown"
            base_score = "Unknown"
            vector_string = "Unknown"
            
            if "metrics" in cve_item:
                metrics = cve_item["metrics"]
                # Try CVSS 3.1 first
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    severity = cvss_data.get("baseSeverity", "Unknown")
                    base_score = cvss_data.get("baseScore", "Unknown")
                    vector_string = cvss_data.get("vectorString", "Unknown")
                # Fall back to CVSS 3.0
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    severity = cvss_data.get("baseSeverity", "Unknown")
                    base_score = cvss_data.get("baseScore", "Unknown")
                    vector_string = cvss_data.get("vectorString", "Unknown")
                # Fall back to CVSS 2.0
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                    # V2 uses different severity values
                    score = cvss_data.get("baseScore", 0)
                    if score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    base_score = score
                    vector_string = cvss_data.get("vectorString", "Unknown")
            
            # Extract CWE information
            cwe_id = "Unknown"
            if "weaknesses" in cve_item:
                for weakness in cve_item["weaknesses"]:
                    for desc in weakness.get("description", []):
                        if desc.get("value", "").startswith("CWE-"):
                            cwe_id = desc.get("value")
                            break
                    if cwe_id != "Unknown":
                        break
            
            # Extract affected configurations
            affected_products = []
            if "configurations" in cve_item:
                for config in cve_item["configurations"]:
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            cpe = cpe_match.get("criteria", "")
                            if cpe:
                                # Parse CPE string to get product information
                                cpe_parts = cpe.split(":")
                                if len(cpe_parts) >= 5:
                                    vendor = cpe_parts[3]
                                    product = cpe_parts[4]
                                    version = cpe_parts[5] if len(cpe_parts) > 5 else ""
                                    affected_products.append(f"{vendor} {product} {version}".strip())
            
            # Construct normalized CVE data
            processed_data = {
                "id": cve_id,
                "published": published,
                "descriptions": [{"lang": "en", "value": description}],
                "references": references,
                "severity": severity,
                "base_score": base_score,
                "vector_string": vector_string,
                "cwe_id": cwe_id,
                "affected_products": affected_products,
                "source": "NVD API"
            }
            
            # Cache the result
            with open(cache_file, 'w') as f:
                json.dump(processed_data, f, indent=2)
            
            logger.info(f"Successfully fetched and processed {cve_id} from NVD API")
            return processed_data
        
        except Exception as e:
            logger.error(f"Error fetching data from NVD API for {cve_id}: {e}")
            return None
    
    def fetch_cve_json_from_mitre(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch the official JSON data for a CVE directly from MITRE's API endpoint.
        This is a more direct approach that bypasses the need to scrape the HTML page.
        
        Args:
            cve_id: The CVE ID (e.g., "CVE-2024-51427")
            
        Returns:
            Dictionary containing the CVE JSON data or None if unsuccessful
        """
        logger.info(f"Fetching JSON directly for {cve_id} from MITRE API endpoint")
        
        # Check for cached data first
        cache_file = os.path.join(self.cache_dir, f"{cve_id}_mitre_json.json")
        if os.path.exists(cache_file):
            logger.info(f"Loading {cve_id} JSON from cache")
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        try:
            # Construct the URL for the JSON API endpoint
            # This is the direct endpoint for JSON data that the "View JSON" button uses
            json_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            
            # Make the request with proper headers
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'Security-Agent/1.0 (Vulnerability Research Tool)'
            }
            
            logger.info(f"Requesting JSON from {json_url}")
            response = requests.get(json_url, headers=headers, timeout=10)
            
            # Check if successful
            if response.status_code == 200:
                cve_data = response.json()
                
                # Cache the result
                with open(cache_file, 'w') as f:
                    json.dump(cve_data, f, indent=2)
                
                logger.info(f"Successfully fetched JSON for {cve_id} from MITRE API endpoint")
                
                # Process the JSON into our normalized format
                processed_data = self.import_cve_json(cve_data)
                return processed_data
            else:
                logger.warning(f"MITRE API returned status code {response.status_code} for {cve_id}")
                
                # Check for specific error codes
                if response.status_code == 404:
                    logger.warning(f"CVE {cve_id} not found in MITRE JSON API")
                elif response.status_code == 429:
                    logger.warning("Rate limit exceeded when accessing MITRE JSON API")
                    
                return None
                
        except Exception as e:
            logger.error(f"Error fetching JSON from MITRE API for {cve_id}: {e}")
            return None