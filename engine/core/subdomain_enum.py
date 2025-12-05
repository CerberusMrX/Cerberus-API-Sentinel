"""
Subdomain Enumerator
Discovers subdomains using DNS queries and common patterns
"""
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SubdomainEnumerator:
    # Common subdomain patterns
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'demo',
        'api', 'admin', 'blog', 'shop', 'forum', 'test', 'dev', 'staging', 'stage',
        'beta', 'alpha', 'app', 'portal', 'vpn', 'secure', 'git', 'mysql', 'database',
        'assets', 'static', 'media', 'images', 'img', 'cdn', 'files', 'backup', 'old',
        'new', 'internal', 'private', 'public', 'dashboard',  'panel', 'status'
    ]
    
    def __init__(self, target_url):
        parsed = urlparse(target_url)
        hostname = parsed.hostname or parsed.netloc
        
        # Extract base domain (remove www if present)
        if hostname.startswith('www.'):
            self.base_domain = hostname[4:]
        else:
            self.base_domain = hostname
    
    def check_subdomain(self, subdomain):
        """Check if subdomain exists via DNS"""
        full_domain = f"{subdomain}.{self.base_domain}"
        try:
            socket.gethostbyname(full_domain)
            logger.info(f"Found subdomain: {full_domain}")
            return full_domain
        except socket.gaierror:
            return None
    
    def enumerate(self, subdomains=None, max_workers=20, callback=None):
        """
        Enumerate subdomains in parallel
        Args:
            subdomains: List of subdomains to check (default: common list)
            max_workers: Number of parallel DNS queries
            callback: Callback for each found subdomain
        Returns:
            List of discovered subdomains
        """
        if subdomains is None:
            subdomains = self.COMMON_SUBDOMAINS
        
        found_subdomains = []
        
        logger.info(f"Starting subdomain enumeration for {self.base_domain}")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_sub = {executor.submit(self.check_subdomain, sub): sub for sub in subdomains}
            
            for future in as_completed(future_to_sub):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    if callback:
                        callback(result)
        
        logger.info(f"Subdomain enumeration complete. Found {len(found_subdomains)} subdomains")
        return found_subdomains
