"""
Technology Detection Module
Identifies web technologies, frameworks, and stack components
"""
import requests
import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class TechDetector:
    def __init__(self, target_url, timeout=5):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
    
    def detect(self):
        """Detect all technologies"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            
            tech = {
                'server': self._detect_server(response),
                'backend': self._detect_backend(response),
                'database': self._detect_database(response),
                'frontend': self._detect_frontend(response),
                'cms': self._detect_cms(response),
                'languages': self._detect_languages(response),
                'frameworks': self._detect_frameworks(response),
                'headers': self._extract_headers(response),
                'cookies': self._extract_cookies(response)
            }
            
            logger.info(f"Technology detection complete for {self.target_url}")
            return tech
            
        except Exception as e:
            logger.error(f"Technology detection failed: {e}")
            return self._get_default_tech()
    
    def _detect_server(self, response):
        """Detect web server"""
        server = response.headers.get('Server', 'Unknown')
        if 'nginx' in server.lower():
            return 'Nginx'
        elif 'apache' in server.lower():
            return 'Apache'
        elif 'iis' in server.lower() or 'microsoft' in server.lower():
            return 'IIS'
        elif 'cloudflare' in server.lower():
            return 'Cloudflare'
        return server
    
    def _detect_backend(self, response):
        """Detect backend framework"""
        powered_by = response.headers.get('X-Powered-By', '').lower()
        
        # Check headers
        if 'php' in powered_by:
            return 'PHP'
        elif 'asp.net' in powered_by:
            return 'ASP.NET'
        elif 'express' in powered_by:
            return 'Express.js'
        
        # Check cookies
        cookies = str(response.cookies).lower()
        if 'django' in cookies or 'csrftoken' in cookies:
            return 'Django'
        elif 'laravel_session' in cookies:
            return 'Laravel'
        elif 'phpsessid' in cookies:
            return 'PHP'
        elif 'jsessionid' in cookies:
            return 'Java/JSP'
        
        # Check response body
        body = response.text.lower()
        if 'django' in body[:1000]:
            return 'Django'
        elif 'laravel' in body[:1000]:
            return 'Laravel'
        elif 'flask' in body[:1000]:
            return 'Flask'
        
        return 'Unknown'
    
    def _detect_database(self, response):
        """Infer database from framework"""
        backend = self._detect_backend(response)
        framework_db_map = {
            'Django': 'PostgreSQL/MySQL',
            'Laravel': 'MySQL',
            'PHP': 'MySQL',
            'ASP.NET': 'MSSQL',
            'Express.js': 'MongoDB/MySQL',
            'Flask': 'PostgreSQL/SQLite'
        }
        return framework_db_map.get(backend, 'Unknown')
    
    def _detect_frontend(self, response):
        """Detect frontend framework"""
        body = response.text
        
        # React
        if 'react' in body.lower() or '_app' in body:
            return 'React'
        # Angular
        elif 'ng-' in body or 'angular' in body.lower():
            return 'Angular'
        # Vue
        elif 'vue' in body.lower() or 'v-' in body:
            return 'Vue.js'
        # Next.js
        elif '__next' in body or '__NEXT' in body:
            return 'Next.js'
        
        return 'Unknown'
    
    def _detect_cms(self, response):
        """Detect CMS"""
        body = response.text.lower()
        
        if 'wp-content' in body or 'wordpress' in body:
            return 'WordPress'
        elif 'joomla' in body:
            return 'Joomla'
        elif 'drupal' in body:
            return 'Drupal'
        elif 'shopify' in body:
            return 'Shopify'
        
        return 'None'
    
    def _detect_languages(self, response):
        """Detect programming languages"""
        langs = []
        powered_by = response.headers.get('X-Powered-By', '').lower()
        body = response.text.lower()
        
        if 'php' in powered_by or '.php' in body: 
            langs.append('PHP')
        if 'python' in body or 'django' in body or 'flask' in body:
            langs.append('Python')
        if 'node' in powered_by or 'express' in body:
            langs.append('Node.js')
        if 'java' in body or 'jsp' in body:
            langs.append('Java')
        if '.net' in powered_by or 'asp.net' in body:
            langs.append('C#/.NET')
        
        return langs if langs else ['Unknown']
    
    def _detect_frameworks(self, response):
        """Detect frameworks"""
        frameworks = []
        body = response.text.lower()
        
        framework_patterns = {
            'Bootstrap': r'bootstrap',
            'jQuery': r'jquery',
            'Tailwind': r'tailwind',
            'MaterialUI': r'material-ui',
            'GraphQL': r'graphql',
        }
        
        for name, pattern in framework_patterns.items():
            if re.search(pattern, body):
                frameworks.append(name)
        
        return frameworks
    
    def _extract_headers(self, response):
        """Extract security-relevant headers"""
        return {
            'X-Frame-Options': response.headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Missing'),
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Missing'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Missing')
        }
    
    def _extract_cookies(self, response):
        """Extract cookie information"""
        cookies = {}
        for cookie in response.cookies:
            cookies[cookie.name] = {
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                'samesite': cookie.get_nonstandard_attr('SameSite', 'None')
            }
        return cookies
    
    def _get_default_tech(self):
        """Default tech stack when detection fails"""
        return {
            'server': 'Unknown',
            'backend': 'Unknown',
            'database': 'Unknown',
            'frontend': 'Unknown',
            'cms': 'None',
            'languages': ['Unknown'],
            'frameworks': [],
            'headers': {},
            'cookies': {}
        }
