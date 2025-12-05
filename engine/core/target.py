from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlparse

@dataclass
class Target:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    
    # Recon data
    ip_address: Optional[str] = None
    server_header: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    
    # Enhanced Recon Data
    subdomains: List[str] = field(default_factory=list)
    subdirectories: List[str] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    detailed_tech_stack: Dict = field(default_factory=dict)

    @property
    def domain(self) -> str:
        return urlparse(self.url).netloc

    @property
    def scheme(self) -> str:
        return urlparse(self.url).scheme
