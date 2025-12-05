"""
HTTP Parameter Pollution Scanner
Tests for HPP vulnerabilities
"""
from typing import List
import logging
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class HTTPParameterPollutionScanner(BaseScanner):
    """Scanner for detecting HTTP Parameter Pollution"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "HTTP Parameter Pollution Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for HPP vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting HPP scan on {target.url}")
        
        try:
            # Test duplicate parameters
            response1 = self.session.get(
                target.url,
                params={'id': '1'},
                timeout=5
            )
            
            # Send duplicate parameter with different value
            response2 = self.session.get(
                f"{target.url}?id=1&id=2",
                timeout=5
            )
            
            # If responses differ, HPP may be present
            if response1.text != response2.text and response2.status_code == 200:
                vulnerabilities.append(Vulnerability(
                    name="HTTP Parameter Pollution",
                    severity="MEDIUM",
                    description="Application handles duplicate parameters inconsistently",
                    evidence="Duplicate parameters produced different responses",
                    url=target.url
                ))
                    
        except Exception as e:
            logger.debug(f"Error testing HPP: {e}")
        
        return vulnerabilities
