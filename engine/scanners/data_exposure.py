"""
Sensitive Data Exposure Scanner
Tests for exposure of sensitive data
"""
import logging
import re
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class SensitiveDataExposureScanner(BaseScanner):
    """Scanner for detecting sensitive data exposure"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "Sensitive Data Exposure Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Data Exposure vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Data Exposure scan on {target.url}")
        
        # Patterns for sensitive data
        patterns = {
            'API Key': r'(?i)(api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
            'Private Key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            'Password': r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\'\\s]{6,})',
            'JWT Token': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'Database URL': r'(?i)(mysql|postgresql|mongodb)://[^\s<>"]+',
            'Email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'IP Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        }
        
        try:
            response = self.session.get(target.url, timeout=10)
            
            # Check response body for sensitive data
            for data_type, pattern in patterns.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    # Filter out common false positives
                    if data_type == 'Email' and len(matches) > 10:
                        continue  # Likely legitimate email list
                    if data_type == 'IP Address' and len(matches) > 5:
                        continue  # Likely legitimate IP references
                    
                    vulnerabilities.append(Vulnerability(
                        name=f"Sensitive Data Exposure: {data_type}",
                        severity="HIGH" if data_type in ['API Key', 'AWS Key', 'Private Key', 'Password'] else "MEDIUM",
                        description=f"{data_type} detected in response",
                        evidence=f"Found {len(matches)} instance(s) of {data_type}. First match: {str(matches[0])[:50]}...",
                        url=target.url
                    ))
            
            # Test for sensitive files
            sensitive_files = [
                '/.env',
                '/config.json',
                '/database.yml',
                '/secrets.yml',
                '/.git/config',
                '/web.config',
                '/WEB-INF/web.xml',
                '/server.xml'
            ]
            
            for file_path in sensitive_files:
                test_url = target.url.rstrip('/') + file_path
                try:
                    file_response = self.session.get(test_url, timeout=5)
                    if file_response.status_code == 200 and len(file_response.text) > 10:
                        vulnerabilities.append(Vulnerability(
                            name="Sensitive File Exposure",
                            severity="CRITICAL",
                            description=f"Sensitive configuration file accessible: {file_path}",
                            evidence=f"File contents (first 100 chars): {file_response.text[:100]}",
                            url=test_url
                        ))
                except Exception:
                    pass
            
            # Check for unencrypted transmission (HTTP instead of HTTPS)
            if target.url.startswith('http://'):
                vulnerabilities.append(Vulnerability(
                    name="Unencrypted Communication",
                    severity="HIGH",
                    description="API uses HTTP instead of HTTPS, data transmitted in cleartext",
                    evidence=f"URL scheme: {target.url.split(':')[0]}",
                    url=target.url
                ))
                
        except Exception as e:
            logger.error(f"Error during sensitive data scan: {e}")
        
        logger.info(f"Sensitive data scan complete. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
