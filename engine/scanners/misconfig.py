"""
Security Misconfiguration Scanner
Tests for common security misconfigurations
"""
import logging
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class SecurityMisconfigurationScanner(BaseScanner):
    """Scanner for detecting security misconfigurations"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "Security Misconfiguration Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Security Misconfiguration vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Misconfiguration scan on {target.url}")
        
        try:
            response = self.session.get(target.url, timeout=10)
            
            # Test 1: Missing security headers
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking protection)',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'Strict-Transport-Security': 'Missing HSTS header (HTTPS enforcement)',
                'Content-Security-Policy': 'Missing Content-Security-Policy header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header'
            }
            
            for header, description in security_headers.items():
                if header not in response.headers:
                    vulnerabilities.append(Vulnerability(
                        name="Missing Security Header",
                        severity="MEDIUM",
                        description=description,
                        evidence=f"Response headers: {dict(response.headers)}",
                        url=target.url
                    ))
            
            # Test 2: Debug mode / verbose errors
            debug_indicators = [
                'Traceback',
                'DEBUG = True',
                'Stack trace',
                'Exception',
                'at line',
                'syntax error',
                'mysql_',
                'SQLSTATE',
                'Warning:',
                'Fatal error:'
            ]
            
            for indicator in debug_indicators:
                if indicator in response.text:
                    vulnerabilities.append(Vulnerability(
                        name="Debug Mode Enabled",
                        severity="HIGH",
                        description="Application appears to be running in debug mode or exposing error details",
                        evidence=f"Found indicator: '{indicator}' in response",
                        url=target.url
                    ))
                    break
            
            # Test 3: Server information disclosure
            if 'Server' in response.headers:
                server_header = response.headers['Server']
                if any(version in server_header for version in ['/', '.']):  # Contains version
                    vulnerabilities.append(Vulnerability(
                        name="Server Version Disclosure",
                        severity="LOW",
                        description="Server header discloses version information",
                        evidence=f"Server: {server_header}",
                        url=target.url
                    ))
            
            # Test 4: Directory listing
            test_dirs = ['/uploads/', '/files/', '/static/', '/images/', '/backup/']
            for test_dir in test_dirs:
                test_url = target.url.rstrip('/') + test_dir
                try:
                    dir_response = self.session.get(test_url, timeout=5)
                    if dir_response.status_code == 200 and 'Index of' in dir_response.text:
                        vulnerabilities.append(Vulnerability(
                            name="Directory Listing Enabled",
                            severity="MEDIUM",
                            description=f"Directory listing is enabled for {test_dir}",
                            evidence=f"Found 'Index of' in response from {test_url}",
                            url=test_url
                        ))
                except Exception:
                    pass
            
            # Test 5: HTTP methods allowed
            try:
                options_response = self.session.options(target.url, timeout=5)
                if 'Allow' in options_response.headers:
                    allowed_methods = options_response.headers['Allow']
                    dangerous_methods = ['TRACE', 'TRACK', 'DELETE', 'PUT']
                    found_dangerous = [m for m in dangerous_methods if m in allowed_methods]
                    if found_dangerous:
                        vulnerabilities.append(Vulnerability(
                            name="Dangerous HTTP Methods Enabled",
                            severity="MEDIUM",
                            description=f"Potentially dangerous HTTP methods are allowed: {', '.join(found_dangerous)}",
                            evidence=f"Allow header: {allowed_methods}",
                            url=target.url
                        ))
            except Exception:
                pass
                
        except Exception as e:
            logger.error(f"Error during misconfiguration scan: {e}")
        
        logger.info(f"Misconfiguration scan complete. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
