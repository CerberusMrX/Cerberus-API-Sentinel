"""
XPath Injection Scanner
Tests for XPath injection vulnerabilities
"""
import logging
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class XPathInjectionScanner(BaseScanner):
    """Scanner for detecting XPath injection vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "XPath Injection Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for XPath vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting XPath scan on {target.url}")
        
        # XPath injection payloads
        payloads = [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "' and count(/*)=1 and '1'='1",
        ]
        
        error_indicators = [
            'XPathException',
            'XPath',
            'org.apache.xpath',
            'libxml2',
            'xmlXPathEval',
        ]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    target.url,
                    params={'search': payload, 'query': payload},
                    timeout=5
                )
                
                for indicator in error_indicators:
                    if indicator in response.text:
                        vulnerabilities.append(Vulnerability(
                            name="XPath Injection",
                            severity="HIGH",
                            description="Application vulnerable to XPath injection attacks",
                            evidence=f"Payload '{payload}' triggered XPath error",
                            url=target.url
                        ))
                        return vulnerabilities
                        
            except Exception as e:
                logger.debug(f"Error testing XPath injection: {e}")
        
        return vulnerabilities
