"""
Business Logic Flaws Scanner
Tests for business logic vulnerabilities
"""
import logging
from .base import BaseScanner, Vulnerability
from typing import List
from ..core.target import Target

logger = logging.getLogger(__name__)

class BusinessLogicScanner(BaseScanner):
    """Scanner for detecting business logic flaws"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "Business Logic Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Business Logic vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Business Logic scan on {target.url}")
        
        try:
            # Test 1: Negative quantity
            response = self.session.post(
                target.url,
                json={'quantity': -1, 'amount': -100},
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                if '-' in response.text or 'negative' not in response.text.lower():
                    vulnerabilities.append(Vulnerability(
                        name="Negative Value Accepted",
                        severity="HIGH",
                        description="Application accepts negative values where positive expected",
                        evidence="Negative quantity/amount accepted",
                        url=target.url
                    ))
            
            # Test 2: Price manipulation
            test_data = [
                {'price': '0', 'cost': '0'},
                {'price': '0.01'},
                {'discount': '100'},
                {'discount': '999'}
            ]
            
            for data in test_data:
                response = self.session.post(target.url, json=data, timeout=5)
                if response.status_code in [200, 201]:
                    vulnerabilities.append(Vulnerability(
                        name="Price Manipulation Possible",
                        severity="CRITICAL",
                        description="Application may allow price/cost manipulation",
                        evidence=f"Suspicious pricing data accepted: {data}",
                        url=target.url
                    ))
                    break
                        
        except Exception as e:
            logger.debug(f"Error testing business logic: {e}")
        
        return vulnerabilities
