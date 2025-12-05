from .base import BaseScanner, Vulnerability
from ..core.target import Target
from typing import List
import logging
import re

logger = logging.getLogger(__name__)

class BOLAScanner(BaseScanner):
    """Scanner for Broken Object Level Authorization (BOLA/IDOR) vulnerabilities"""
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for BOLA vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting BOLA scan on {target.url}")
        
        for payload in self.PAYLOADS:
            if callback:
                callback(payload)
                
            try:
                # Test in URL parameters
                if '?' in target.url:
                    test_url = f"{target.url}&id={payload}"
                else:
                    test_url = f"{target.url}?id={payload}"
                
                response = self.session.get(test_url, timeout=3)
                # Further processing of response for BOLA vulnerability
                # This part is missing in the provided snippet and needs to be implemented
                # based on the scanner's logic. For now, we'll just log.
                logger.debug(f"Tested URL parameter with payload {payload}: {test_url}, Status: {response.status_code}")
                
            except Exception as e:
                logger.debug(f"Error testing URL parameter with payload {payload}: {str(e)}")
                continue

        # Extract numeric IDs from URL
        id_pattern = r'/(\d+)/?'
        matches = re.findall(id_pattern, target.url)
        
        if not matches:
            logger.info("No numeric IDs found in URL, skipping BOLA scan")
            return vulnerabilities
        
        original_id = matches[0]
        base_url = target.url.replace(f"/{original_id}", "")
        
        # Test ID manipulation
        test_ids = [
            str(int(original_id) + 1),
            str(int(original_id) - 1),
            "1",
            "999999",
            str(int(original_id) * 2)
        ]
        
        try:
            # Get baseline response
            baseline_response = self.session.request(
                method=target.method,
                url=target.url,
                timeout=10
            )
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.content)
            
            for test_id in test_ids:
                test_url = f"{base_url}/{test_id}"
                
                try:
                    test_response = self.session.request(
                        method=target.method,
                        url=test_url,
                        timeout=10
                    )
                    
                    # Check if unauthorized access succeeded
                    if (test_response.status_code == 200 and 
                        baseline_status == 200 and
                        abs(len(test_response.content) - baseline_length) < baseline_length * 0.3):
                        
                        vuln = Vulnerability(
                            name="Broken Object Level Authorization (BOLA/IDOR)",
                            description=f"The API endpoint allows accessing resources belonging to other users without proper authorization checks. ID {original_id} can be replaced with {test_id}.",
                            severity="HIGH",
                            evidence=f"Original URL: {target.url} (Status: {baseline_status}), Test URL: {test_url} (Status: {test_response.status_code}), Similar response size indicates possible IDOR."
                        )
                        vulnerabilities.append(vuln)
                        logger.warning(f"Potential BOLA/IDOR vulnerability at {test_url}")
                        break
                        
                except Exception as e:
                    logger.debug(f"Error testing ID {test_id}: {str(e)}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error during BOLA scan: {str(e)}")
        
        return vulnerabilities
