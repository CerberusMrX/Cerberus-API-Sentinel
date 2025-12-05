"""
Broken Access Control Scanner
Tests for missing authorization and privilege escalation vulnerabilities
"""
from typing import List
import logging
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class BrokenAccessControlScanner(BaseScanner):
    """Scanner for detecting broken access control vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "Broken Access Control Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Access Control vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Access Control scan on {target.url}")
        
        # Test 1: Direct object reference without auth
        test_paths = [
            '/admin',
            '/api/admin',
            '/api/users',
            '/api/user/1',
            '/dashboard',
            '/config',
            '/.env',
            '/api/settings'
        ]
        
        for path in test_paths:
            test_url = target.url.rstrip('/') + path
            try:
                # Test without any authentication headers
                response = self.session.get(test_url, timeout=5)
                
                # Check if we got unauthorized access
                if response.status_code == 200:
                    # Look for indicators of sensitive data
                    indicators = ['admin', 'user', 'password', 'token', 'config', 'apikey']
                    if any(ind in response.text.lower() for ind in indicators):
                        vulnerabilities.append(Vulnerability(
                            name="Broken Access Control",
                            severity="HIGH",
                            description=f"Unauthenticated access to protected resource: {path}",
                            evidence=f"Accessed {test_url} without authentication. Status: {response.status_code}",
                            url=test_url
                        ))
                        
            except Exception as e:
                logger.debug(f"Error testing {test_url}: {e}")
        
        # Test 2: Horizontal privilege escalation (IDOR variant)
        user_ids = ['1', '2', '100', '999']
        for uid in user_ids:
            test_url = f"{target.url.rstrip('/')}/api/user/{uid}/profile"
            try:
                response = self.session.get(test_url, timeout=5)
                if response.status_code == 200 and len(response.text) > 50:
                    vulnerabilities.append(Vulnerability(
                        name="Horizontal Privilege Escalation",
                        severity="HIGH",
                        description=f"Able to access other users' data without proper authorization",
                        evidence=f"Accessed user {uid} profile without authorization check",
                        url=test_url
                    ))
                    break  # Found one, don't spam
            except Exception as e:
                logger.debug(f"Error testing user {uid}: {e}")
        
        # Test 3: Method-based bypass
        protected_endpoints = ['/api/delete', '/api/admin/users']
        for endpoint in protected_endpoints:
            test_url = target.url.rstrip('/') + endpoint
            try:
                # Try different HTTP methods
                for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    response = self.session.request(method, test_url, timeout=5)
                    if response.status_code in [200, 201, 204]:
                        vulnerabilities.append(Vulnerability(
                            name="HTTP Method Bypass",
                            severity="MEDIUM",
                            description=f"Protected endpoint accessible via {method} method",
                            evidence=f"{method} {test_url} returned {response.status_code}",
                            url=test_url
                        ))
                        break
            except Exception as e:
                logger.debug(f"Error testing method bypass on {endpoint}: {e}")
        
        logger.info(f"Access Control scan complete. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
