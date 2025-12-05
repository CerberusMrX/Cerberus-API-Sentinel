"""
Target Profiler - Professional Reconnaissance
Comprehensive attack surface discovery using parallel workers
"""
import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class Profiler:
    """
    Professional-grade reconnaissance profiler
    Uses new parallel reconnaissance modules for comprehensive discovery
    """
    
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Cerberus-API-Sentinel/1.0'
        })
    
    def profile(self):
        """
        Complete reconnaissance phase with professional modules
        """
        logger.info(f"Starting professional reconnaissance for {self.target.url}")
        
        # Import new reconnaissance modules
        try:
            from engine.core.port_scanner import PortScanner
            from engine.core.tech_detector import TechDetector
            from engine.core.subdomain_enum import SubdomainEnumerator
            from engine.core.dir_discovery import DirectoryDiscoverer
            from engine.core.crawler import Crawler
        except ImportError as e:
            logger.warning(f"Could not import reconnaissance modules: {e}")
            logger.warning("Falling back to basic profiling")
            self._basic_profile()
            return self.target
        
        # Phase 1: Port Scanning
        logger.info("Phase 1: Port Scanning...")
        try:
            port_scanner = PortScanner(self.target.url, timeout=1)
            self.target.open_ports = port_scanner.scan(max_workers=20)
            logger.info(f"Found {len(self.target.open_ports)} open ports")
        except Exception as e:
            logger.error(f"Port scanning failed: {e}")
            self.target.open_ports = []
        
        # Phase 2: Technology Detection
        logger.info("Phase 2: Technology Detection...")
        try:
            tech_detector = TechDetector(self.target.url)
            tech = tech_detector.detect()
            self.target.detailed_tech_stack = tech
            logger.info(f"Detected: Server={tech.get('server')}, Backend={tech.get('backend')}, Database={tech.get('database')}")
        except Exception as e:
            logger.error(f"Technology detection failed: {e}")
            self.target.detailed_tech_stack = {}
        
        # Phase 3: Subdomain Enumeration
        logger.info("Phase 3: Subdomain Enumeration...")
        try:
            subdomain_enum = SubdomainEnumerator(self.target.url)
            self.target.subdomains = subdomain_enum.enumerate(max_workers=30)
            logger.info(f"Found {len(self.target.subdomains)} subdomains")
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {e}")
            self.target.subdomains = []
        
        # Phase 4: Directory Discovery
        logger.info("Phase 4: Directory Discovery...")
        try:
            dir_discoverer = DirectoryDiscoverer(self.target.url)
            directories = dir_discoverer.discover(max_workers=30)
            self.target.subdirectories = [d['path'] for d in directories]
            logger.info(f"Found {len(self.target.subdirectories)} directories/files")
        except Exception as e:
            logger.error(f"Directory discovery failed: {e}")
            self.target.subdirectories = []
        
        # Phase 5: Web Crawling
        logger.info("Phase 5: Web Crawling...")
        try:
            discovered_urls = []
            def on_url_found(url):
                discovered_urls.append(url)
                
            crawler = Crawler(self.target.url, max_depth=2, max_pages=30, callback=on_url_found)
            crawler.crawl()
            self.target.discovered_urls = discovered_urls
            logger.info(f"Crawled {len(discovered_urls)} URLs")
        except Exception as e:
            logger.error(f"Crawling failed: {e}")
            self.target.discovered_urls = [self.target.url]
        
        logger.info("Reconnaissance complete!")
        logger.info(f"Attack Surface: {len(self.target.open_ports)} ports, {len(self.target.subdomains)} subdomains, {len(self.target.subdirectories)} paths, {len(getattr(self.target, 'discovered_urls', [self.target.url]))} URLs")
        
        return self.target
    
    def _basic_profile(self):
        """Fallback basic profiling if new modules unavailable"""
        logger.info("Using basic profiling...")
        try:
            response = self.session.get(self.target.url, timeout=5, verify=False)
            self.target.detailed_tech_stack = {
                'server': response.headers.get('Server', 'Unknown'),
                'backend': response.headers.get('X-Powered-By', 'Unknown'),
                'database': 'Unknown',
                'frontend': 'Unknown',
                'languages': [],
                'frameworks': []
            }
            logger.info(f"Basic profiling complete. Server: {self.target.detailed_tech_stack['server']}")
        except Exception as e:
            logger.error(f"Basic profiling failed: {e}")
            self.target.detailed_tech_stack = {
                'server': 'Unknown',
                'backend': 'Unknown', 
                'database': 'Unknown',
                'frontend': 'Unknown',
                'languages': [],
                'frameworks': []
            }
        
        self.target.open_ports = []
        self.target.subdomains = []
        self.target.subdirectories = []
        return self.target
