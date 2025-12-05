"""
GraphQL Injection Scanner
Tests for GraphQL-specific injection vulnerabilities
"""
from typing import List
import logging
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class GraphQLInjectionScanner(BaseScanner):
    """Scanner for detecting GraphQL injection vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "GraphQL Injection Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for GraphQL vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting GraphQL scan on {target.url}")
        
        # GraphQL introspection query
        introspection_query = """
        {
            __schema {
                types {
                    name
                }
            }
        }
        """
        
        # GraphQL injection payloads
        payloads = [
            '{ __typename }',
            '{ __schema { queryType { name } } }',
            introspection_query,
        ]
        
        # Try common GraphQL endpoints
        graphql_endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        for endpoint in graphql_endpoints:
            test_url = target.url.rstrip('/') + endpoint
            
            for payload in payloads:
                try:
                    response = self.session.post(
                        test_url,
                        json={'query': payload},
                        headers={'Content-Type': 'application/json'},
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        if '__schema' in response.text or '__typename' in response.text:
                            vulnerabilities.append(Vulnerability(
                                name="GraphQL Introspection Enabled",
                                severity="MEDIUM",
                                description="GraphQL introspection is enabled, exposing schema",
                                evidence=f"Introspection query successful at {test_url}",
                                url=test_url
                            ))
                            return vulnerabilities
                            
                except Exception as e:
                    logger.debug(f"Error testing GraphQL injection: {e}")
        
        return vulnerabilities
