"""
Port Scanner Module
Scans common ports to identify open services
"""
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class PortScanner:
    # Common ports and their services
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB',
        9200: 'Elasticsearch',
    }
    
    def __init__(self, target_url, timeout=1):
        """
        Initialize port scanner
        Args:
            target_url: Target URL to scan
            timeout: Socket connection timeout in seconds
        """
        parsed = urlparse(target_url)
        self.target_host = parsed.hostname or parsed.netloc
        self.timeout = timeout
        
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target_host, port))
            sock.close()
            
            if result == 0:
                service = self.COMMON_PORTS.get(port, 'Unknown')
                logger.info(f"Port {port} ({service}) is OPEN on {self.target_host}")
                return {
                    'port': port,
                    'service': service,
                    'state': 'open'
                }
            return None
        except socket.gaierror:
            logger.error(f"Hostname {self.target_host} could not be resolved")
            return None
        except socket.error:
            return None
    
    def scan(self, ports=None, max_workers=10, callback=None):
        """
        Scan multiple ports in parallel
        Args:
            ports: List of ports to scan (default: common ports)
            max_workers: Number of parallel workers
            callback: Callback function for each found port
        Returns:
            List of open ports with service info
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        open_ports = []
        
        logger.info(f"Starting port scan on {self.target_host} ({len(ports)} ports)")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
                    if callback:
                        callback(result)
        
        logger.info(f"Port scan complete. Found {len(open_ports)} open ports")
        return open_ports
