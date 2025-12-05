
"""
LDAP Injection Scanner
Tests for LDAP injection vulnerabilities
"""
from typing import List
import logging
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class LDAPInjectionScanner(BaseScanner):
    """Scanner for detecting LDAP injection vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "LDAP Injection Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for LDAP vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting LDAP scan on {target.url}")
        
        # LDAP injection payloads
        payloads = [
            '*',
            '*)(&',
            '*)(uid=*))(|(uid=*',
            'admin)(|(password=*))',
            '*)(objectClass=*',
        ]
        
        error_indicators = [
            'LDAP',
            'javax.naming',
            'LDAPException',
            'Invalid DN syntax'
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    target.url,
                    params={'username': payload, 'user': payload},
                    timeout=5
                )
                
                for indicator in error_indicators:
                    if indicator in response.text:
                        vulnerabilities.append(Vulnerability(
                            name="LDAP Injection",
                            severity="HIGH",
                            description="Application vulnerable to LDAP injection attacks",
                            evidence=f"Payload '{payload}' triggered LDAP error",
                            url=target.url
                        ))
                        return vulnerabilities
                        
            except Exception as e:
                logger.debug(f"Error testing LDAP injection: {e}")
        
        return vulnerabilities
