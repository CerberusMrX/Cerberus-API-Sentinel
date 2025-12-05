"""
Insufficient Logging & Monitoring Scanner
Tests for logging deficiencies
"""
import logging
from .base import BaseScanner, Vulnerability
from typing import List
from ..core.target import Target

logger = logging.getLogger(__name__)

class LoggingScanner(BaseScanner):
    """Scanner for detecting insufficient logging"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "Logging & Monitoring Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Logging vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Logging scan on {target.url}")
        
        try:
            # Test authentication logging
            # Attempt failed login
            response = self.session.post(
                target.url.rstrip('/') + '/login',
                json={'username': 'admin', 'password': 'wrong'},
                timeout=5
            )
            
            # Check if response provides timing attack vector
            # (same response time/message for valid vs invalid users)
            if response.status_code in [200, 401]:
                if 'login failed' in response.text.lower() or 'invalid' in response.text.lower():
                    vulnerabilities.append(Vulnerability(
                        name="Generic Error Messages",
                        severity="LOW",
                        description="Application uses generic error messages that may hinder security monitoring",
                        evidence="Login error message does not distinguish between invalid user and invalid password",
                        url=target.url + '/login'
                    ))
            
            # Test for security event logging endpoints
            logging_endpoints = ['/logs', '/api/logs', '/admin/logs', '/metrics']
            for endpoint in logging_endpoints:
                test_url = target.url.rstrip('/') + endpoint
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200 and len(response.text) < 50:
                    vulnerabilities.append(Vulnerability(
                        name="Insufficient Logging",
                        severity="MEDIUM",
                        description="Logging endpoint exists but appears to have minimal data",
                        evidence=f"Logging endpoint {endpoint} accessible but limited",
                        url=test_url
                    ))
                        
        except Exception as e:
            logger.debug(f"Error testing logging: {e}")
        
        return vulnerabilities
