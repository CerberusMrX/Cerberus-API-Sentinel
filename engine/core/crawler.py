import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
import time

logger = logging.getLogger(__name__)

class Crawler:
    def __init__(self, start_url, max_depth=2, max_pages=50, callback=None):
        self.start_url = start_url
        self.domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.callback = callback  # Function to call when a URL is found
        self.visited = set()
        self.urls = set()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Cerberus-Sentinel-Crawler/1.0'})

    def crawl(self):
        """Start the crawling process"""
        self._crawl_recursive(self.start_url, 0)
        return list(self.urls)

    def _crawl_recursive(self, url, depth):
        if depth > self.max_depth or len(self.visited) >= self.max_pages:
            return
        
        if url in self.visited:
            return

        self.visited.add(url)
        
        try:
            # Notify callback
            if self.callback:
                self.callback(url)
            
            logger.info(f"Crawling: {url}")
            response = self.session.get(url, timeout=5)
            
            if response.status_code != 200:
                return

            # Parse content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                parsed_url = urlparse(full_url)
                
                # Stay within domain and avoid fragments/queries for simplicity in visited check
                clean_url = full_url.split('#')[0]
                
                if parsed_url.netloc == self.domain and clean_url not in self.visited:
                    self.urls.add(clean_url)
                    self._crawl_recursive(clean_url, depth + 1)
                    
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
