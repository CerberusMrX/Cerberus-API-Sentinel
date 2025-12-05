"""
API Rate Limiting Scanner
Tests for missing rate limiting
"""
import logging
import time
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class RateLimitScanner(BaseScanner):
    """Scanner for detecting missing rate limiting"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "Rate Limiting Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Rate Limiting vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Rate Limit scan on {target.url}")
        
        try:
            # Send multiple rapid requests
            num_requests = 20
            successful_requests = 0
            
            for i in range(num_requests):
                response = self.session.get(target.url, timeout=5)
                if response.status_code == 200:
                    successful_requests += 1
            
            # If most requests succeeded, rate limiting likely missing
            if successful_requests >= num_requests * 0.9:
                vulnerabilities.append(Vulnerability(
                    name="Missing Rate Limiting",
                    severity="MEDIUM",
                    description=f"No rate limiting detected. {successful_requests}/{num_requests} requests succeeded",
                    evidence=f"Sent {num_requests} rapid requests, all succeeded",
                    url=target.url
                ))
                    
        except Exception as e:
            logger.debug(f"Error testing rate limiting: {e}")
        
        return vulnerabilities
