from .base import BaseScanner, Vulnerability
from ..core.target import Target
from typing import List
import logging

logger = logging.getLogger(__name__)

class AuthScanner(BaseScanner):
    """Scanner for Authentication and Session Management vulnerabilities"""
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Authentication vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Authentication scan on {target.url}")
        
        # Test 1: Missing Authentication
        vulnerabilities.extend(self._test_missing_auth(target))
        
        # Test 2: Weak Session Management
        vulnerabilities.extend(self._test_session_management(target))
        
        # Test 3: JWT Vulnerabilities
        vulnerabilities.extend(self._test_jwt(target))
        
        return vulnerabilities
    
    def _test_missing_auth(self, target: Target) -> List[Vulnerability]:
        """Test for missing authentication"""
        vulns = []
        
        try:
            # Try accessing without auth headers
            clean_session = self.session.__class__()
            response = clean_session.request(
                method=target.method,
                url=target.url,
                timeout=10
            )
            
            # If we get 200 without auth, it might be a vulnerability
            if response.status_code == 200:
                vuln = Vulnerability(
                    name="Missing Authentication",
                    description="The API endpoint is accessible without authentication. Sensitive endpoints should require proper authentication.",
                    severity="MEDIUM",
                    evidence=f"URL: {target.url}, Status: {response.status_code} (unauthenticated)"
                )
                vulns.append(vuln)
                logger.warning(f"Missing authentication at {target.url}")
                
        except Exception as e:
            logger.debug(f"Error testing missing auth: {str(e)}")
        
        return vulns
    
    def _test_session_management(self, target: Target) -> List[Vulnerability]:
        """Test for weak session management"""
        vulns = []
        
        try:
            response = self.session.request(
                method=target.method,
                url=target.url,
                timeout=10
            )
            
            # Check for insecure cookies
            if response.cookies:
                for cookie_name, cookie in response.cookies.items():
                    if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
                        vuln = Vulnerability(
                            name="Insecure Cookie Configuration",
                            description=f"The cookie '{cookie_name}' lacks security flags. Cookies should have Secure and HttpOnly flags set.",
                            severity="MEDIUM",
                            evidence=f"Cookie: {cookie_name}, Secure: {cookie.secure}, HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}"
                        )
                        vulns.append(vuln)
                        logger.warning(f"Insecure cookie found: {cookie_name}")
                        
        except Exception as e:
            logger.debug(f"Error testing session management: {str(e)}")
        
        return vulns
    
    def _test_jwt(self, target: Target) -> List[Vulnerability]:
        """Test for JWT vulnerabilities"""
        vulns = []
        
        try:
            # Look for JWT in Authorization header
            auth_header = self.session.headers.get('Authorization', '')
            
            if 'Bearer' in auth_header and '.' in auth_header:
                # Test none algorithm
                token_parts = auth_header.replace('Bearer ', '').split('.')
                if len(token_parts) == 3:
                    # Try to access with 'none' algorithm
                    # This is a simplified test - real implementation would decode and modify
                    vuln = Vulnerability(
                        name="JWT Usage Detected",
                        description="JWT authentication is being used. Ensure proper validation including algorithm verification, signature checking, and expiration validation.",
                        severity="INFO",
                        evidence="JWT token detected in Authorization header"
                    )
                    vulns.append(vuln)
                    logger.info("JWT usage detected, manual verification recommended")
                    
        except Exception as e:
            logger.debug(f"Error testing JWT: {str(e)}")
        
        return vulns
