
"""
OAuth Misconfigurations Scanner
Tests for OAuth security issues
"""
from typing import List
import logging
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class OAuthScanner(BaseScanner):
    """Scanner for detecting OAuth misconfigurations"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "OAuth Misconfigurations Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for OAuth vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting OAuth scan on {target.url}")
        
        # Test for OAuth endpoints
        oauth_endpoints = [
            '/oauth/authorize',
            '/oauth/token',
            '/oauth2/authorize',
            '/auth/oauth',
            '/.well-known/oauth-authorization-server'
        ]
        
        for endpoint in oauth_endpoints:
            test_url = target.url.rstrip('/') + endpoint
            try:
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    # Check for redirect_uri validation issues
                    test_redirect = self.session.get(
                        test_url,
                        params={'redirect_uri': 'https://evil.com', 'client_id': 'test'},
                        allow_redirects=False,
                        timeout=5
                    )
                    
                    if test_redirect.status_code in [301, 302, 303, 307, 308]:
                        location = test_redirect.headers.get('Location', '')
                        if 'evil.com' in location:
                            vulnerabilities.append(Vulnerability(
                                name="OAuth Open Redirect",
                                severity="HIGH",
                                description="OAuth redirect_uri parameter not properly validated",
                                evidence=f"Arbitrary redirect accepted: {location}",
                                url=test_url
                            ))
                            
            except Exception as e:
                logger.debug(f"Error testing OAuth endpoint {endpoint}: {e}")
        
        return vulnerabilities
