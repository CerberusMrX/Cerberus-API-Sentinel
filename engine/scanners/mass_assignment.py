"""
Mass Assignment Scanner
Tests for over-posting vulnerabilities
"""
import logging
from .base import BaseScanner, Vulnerability
from typing import List
from ..core.target import Target

logger = logging.getLogger(__name__)

class MassAssignmentScanner(BaseScanner):
    """Scanner for detecting mass assignment vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "Mass Assignment Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Mass Assignment vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Mass Assignment scan on {target.url}")
        
        # Common privileged fields that shouldn't be user-modifiable
        test_fields = {
            'admin': 'true',
            'is_admin': 'true',
            'role': 'admin',
            'is_superuser': '1',
            'permissions': 'all',
            'price': '0',
            'status': 'approved'
        }
        
        try:
            # Test POST with privileged fields
            response = self.session.post(
                target.url,
                json=test_fields,
                timeout=5
            )
            
            # If request succeeds, mass assignment may be possible
            if response.status_code in [200, 201]:
                # Check if any privileged field appears in response
                for field in test_fields:
                    if field in response.text.lower():
                        vulnerabilities.append(Vulnerability(
                            name="Mass Assignment Vulnerability",
                            severity="HIGH",
                            description="Application accepts privileged fields in user input",
                            evidence=f"Privileged field '{field}' accepted in request",
                            url=target.url
                        ))
                        break
                        
        except Exception as e:
            logger.debug(f"Error testing mass assignment: {e}")
        
        return vulnerabilities
