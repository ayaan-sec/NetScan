import requests
import time


class CVELookup:
    """NVD API v2 integration for CVE lookup."""
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self):
        # Cache to avoid duplicate API calls in the same session
        self.cache = {}
    
    def build_query(self, product, version=''):
        """
        Build a search query from product and version.
        
        Args:
            product: Product name from nmap
            version: Version string from nmap
        
        Returns:
            Search query string
        """
        # Clean up the product name
        product = product.strip() if product else ''
        version = version.strip() if version else ''
        
        # Build keyword search
        keywords = []
        if product:
            keywords.append(product)
        if version:
            keywords.append(version)
        
        return ' '.join(keywords)
    
    def parse_cvss(self, cve_data):
        """
        Extract CVSS score and severity from CVE data.
        
        Args:
            cve_data: CVE dictionary from NVD API
        
        Returns:
            Tuple (cvss_score, severity, cvss_version)
        """
        metrics = cve_data.get('metrics', {})
        
        # Try CVSS v3 first, fall back to v2
        cvss_data = None
        cvss_version = None
        
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            cvss_version = '3.1'
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            cvss_version = '3.0'
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
            cvss_version = '2.0'
        
        if cvss_data:
            score = cvss_data.get('baseScore', 0.0)
            
            # Determine severity based on CVSS v3 or v2 ranges
            if cvss_version in ['3.1', '3.0']:
                if score == 0:
                    severity = 'NONE'
                elif score < 4:
                    severity = 'LOW'
                elif score < 7:
                    severity = 'MEDIUM'
                elif score < 9:
                    severity = 'HIGH'
                else:
                    severity = 'CRITICAL'
            else:  # CVSS v2
                if score == 0:
                    severity = 'NONE'
                elif score < 4:
                    severity = 'LOW'
                elif score < 7:
                    severity = 'MEDIUM'
                else:
                    severity = 'HIGH'
            
            return score, severity, cvss_version
        
        return 0.0, 'NONE', None
    
    def lookup_cves(self, product, version=''):
        """
        Look up CVEs for a given product and version.
        
        Args:
            product: Product name
            version: Version string
        
        Returns:
            List of CVE dictionaries
        """
        # Build cache key
        cache_key = f"{product}:{version}"
        
        # Check cache first
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Build search query
        query = self.build_query(product, version)
        
        if not query:
            self.cache[cache_key] = []
            return []
        
        # Prepare API request
        params = {
            'keywordSearch': query,
            'resultsPerPage': 20  # Limit results
        }
        
        max_retries = 2
        retry_delay = 1  # 1 second delay for rate limiting
        
        for attempt in range(max_retries):
            try:
                # Rate limiting - wait between requests
                if attempt > 0:
                    time.sleep(retry_delay)
                
                response = requests.get(
                    self.NVD_API_BASE,
                    params=params,
                    timeout=10,
                    headers={'Accept': 'application/json'}
                )
                
                # Handle rate limiting (429)
                if response.status_code == 429:
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay * 2)  # Wait longer on rate limit
                        continue
                    else:
                        # Return empty list on rate limit after retries
                        self.cache[cache_key] = []
                        return []
                
                response.raise_for_status()
                data = response.json()
                
                # Parse vulnerabilities
                cves = []
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id', 'Unknown')
                    
                    # Get description (English only)
                    descriptions = cve.get('descriptions', [])
                    description = ''
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # Truncate description to 200 chars
                    if len(description) > 200:
                        description = description[:197] + '...'
                    
                    # Get published date
                    published = cve.get('published', '')
                    
                    # Get CVSS score and severity
                    score, severity, cvss_version = self.parse_cvss(cve)
                    
                    cve_info = {
                        'id': cve_id,
                        'description': description or 'No description available',
                        'cvss_score': score,
                        'severity': severity,
                        'cvss_version': cvss_version,
                        'published': published[:10] if published else 'Unknown'  # Just the date part
                    }
                    
                    cves.append(cve_info)
                
                # Cache results
                self.cache[cache_key] = cves
                
                # Rate limiting delay after successful request
                time.sleep(0.6)  # NVD API allows ~1.5 requests per second
                
                return cves
                
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                # Return empty list on final failure
                self.cache[cache_key] = []
                return []
            
            except Exception as e:
                # On any other error, cache empty result and return
                self.cache[cache_key] = []
                return []
        
        # Shouldn't reach here, but return empty list just in case
        self.cache[cache_key] = []
        return []
    
    def lookup_service(self, service_info):
        """
        Look up CVEs for a service/port entry.
        
        Args:
            service_info: Dictionary with service details from scanner
        
        Returns:
            List of CVE dictionaries
        """
        # Prefer product from nmap, fall back to service name
        product = service_info.get('product', '') or service_info.get('service', '')
        version = service_info.get('version', '')
        
        # If we have a banner but no product, try to extract from banner
        if not product and service_info.get('banner'):
            banner = service_info['banner']
            # Simple extraction - first word is often the service
            parts = banner.split()
            if parts:
                product = parts[0]
                # Try to find version in banner
                for i, part in enumerate(parts):
                    if any(c.isdigit() for c in part) and '.' in part:
                        version = part
                        break
        
        return self.lookup_cves(product, version)
    
    def clear_cache(self):
        """Clear the CVE lookup cache."""
        self.cache.clear()
