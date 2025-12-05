
"""
XML Injection Scanner
Tests for XML injection vulnerabilities (different from XXE)
"""
import logging
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class XMLInjectionScanner(BaseScanner):
    """Scanner for detecting XML injection vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "XML Injection Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for XML Injection vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting XML Injection scan on {target.url}")
        
        # XML injection payloads
        payloads = [
            '<foo>test</foo>',
            '"><script>alert(1)</script>',
            '</tag><injected>test</injected><tag>',
            '<?xml version="1.0"?><test>data</test>',
        ]
        
        for payload in payloads:
            try:
                response = self.session.post(
                    target.url,
                    data={'xml': payload, 'data': payload},
                    timeout=5
                )
                
                # Check if payload is reflected in XML context
                if payload in response.text and 'text/xml' in response.headers.get('Content-Type', ''):
                    vulnerabilities.append(Vulnerability(
                        name="XML Injection",
                        severity="MEDIUM",
                        description="Application vulnerable to XML injection",
                        evidence=f"XML payload reflected in response",
                        url=target.url
                    ))
                    return vulnerabilities
                    
            except Exception as e:
                logger.debug(f"Error testing XML injection: {e}")
        
        return vulnerabilities
