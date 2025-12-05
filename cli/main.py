import argparse
import logging
import sys
from colorama import init, Fore, Style
from engine.core.target import Target
from engine.core.profiler import Profiler
from engine.core.auth import Authenticator, AuthType
from engine.scanners.injection import SQLInjectionScanner
from engine.scanners.xss import XSSScanner
from engine.scanners.cmdi import CommandInjectionScanner
from engine.scanners.bola import BOLAScanner
from engine.scanners.ssrf import SSRFScanner
from engine.scanners.xxe import XXEScanner
from engine.scanners.auth import AuthScanner
from engine.scanners.access_control import BrokenAccessControlScanner
from engine.scanners.misconfig import SecurityMisconfigurationScanner
from engine.scanners.data_exposure import SensitiveDataExposureScanner
from engine.scanners.nosql import NoSQLInjectionScanner
from engine.scanners.graphql import GraphQLInjectionScanner
from engine.scanners.ssti import SSTIScanner
from engine.scanners.ldap import LDAPInjectionScanner
from engine.scanners.xpath import XPathInjectionScanner
from engine.scanners.xml_injection import XMLInjectionScanner
from engine.scanners.jwt import JWTScanner
from engine.scanners.oauth import OAuthScanner
from engine.scanners.hpp import HTTPParameterPollutionScanner
from engine.scanners.rate_limit import RateLimitScanner
from engine.scanners.mass_assignment import MassAssignmentScanner
from engine.scanners.business_logic import BusinessLogicScanner
from engine.scanners.logging import LoggingScanner
from engine.reporting.reporter import Reporter

# Initialize colorama
init()

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("cerberus.cli")

def print_banner():
    banner = fr"""{Fore.RED}
   (                                 
   )\ )             (                
  (()/(   (   (     )\ )  (       )  
   /(_))  )\  )(   (()/(  )(   ( /(  
  (_))   ((_)(()\   /(_))(()\  )(_)) 
  {Fore.WHITE}|ced|{Fore.RED}  | __| | _ ) ((_) (_))   ((_)((_) 
  | (__  | _ \ | '_| / -_) | '_| | U | 
   \___| |___/ |_|   \___| |_|   |___| 
                                       
  {Fore.BLUE}Cerberus API Sentinel v1.0{Style.RESET_ALL}
  {Fore.WHITE}Professional API Security Scanner{Style.RESET_ALL}
  {Fore.CYAN}Author: Sudeepa Wanigarathna{Style.RESET_ALL}
    """
    print(banner)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Cerberus API Sentinel - API Security Scanner")
    parser.add_argument("-u", "--url", help="Target API URL (e.g., https://example.com/api)")
    parser.add_argument("-m", "--method", default="GET", help="HTTP Method (GET, POST, etc.)")
    parser.add_argument("--gui", action="store_true", help="Launch the Web GUI Dashboard")
    parser.add_argument("--headers", help="Custom headers (JSON format)")
    
    # Auth Arguments
    parser.add_argument("--auth-type", choices=["basic", "bearer", "api_key"], help="Authentication Type")
    parser.add_argument("--auth-token", help="Bearer Token")
    parser.add_argument("--auth-user", help="Basic Auth Username")
    parser.add_argument("--auth-pass", help="Basic Auth Password")
    
    # Scan Options
    parser.add_argument("--scan-all", action="store_true", help="Enable all scans")
    parser.add_argument("--scan-sqli", action="store_true", help="SQL Injection")
    parser.add_argument("--scan-xss", action="store_true", help="Cross-Site Scripting")
    parser.add_argument("--scan-cmdi", action="store_true", help="Command Injection")
    parser.add_argument("--scan-bola", action="store_true", help="BOLA/IDOR")
    parser.add_argument("--scan-ssrf", action="store_true", help="SSRF")
    parser.add_argument("--scan-xxe", action="store_true", help="XXE")
    parser.add_argument("--scan-auth", action="store_true", help="Broken Authentication")
    parser.add_argument("--scan-access", action="store_true", help="Broken Access Control")
    parser.add_argument("--scan-misconfig", action="store_true", help="Security Misconfiguration")
    parser.add_argument("--scan-data", action="store_true", help="Sensitive Data Exposure")
    parser.add_argument("--scan-nosql", action="store_true", help="NoSQL Injection")
    parser.add_argument("--scan-graphql", action="store_true", help="GraphQL Injection")
    parser.add_argument("--scan-ssti", action="store_true", help="SSTI")
    parser.add_argument("--scan-ldap", action="store_true", help="LDAP Injection")
    parser.add_argument("--scan-xpath", action="store_true", help="XPath Injection")
    parser.add_argument("--scan-xml", action="store_true", help="XML Injection")
    parser.add_argument("--scan-jwt", action="store_true", help="JWT Vulnerabilities")
    parser.add_argument("--scan-oauth", action="store_true", help="OAuth Misconfigurations")
    parser.add_argument("--scan-hpp", action="store_true", help="HTTP Parameter Pollution")
    parser.add_argument("--scan-ratelimit", action="store_true", help="Rate Limiting Issues")
    parser.add_argument("--scan-mass", action="store_true", help="Mass Assignment")
    parser.add_argument("--scan-logic", action="store_true", help="Business Logic Flaws")
    parser.add_argument("--scan-logging", action="store_true", help="Insufficient Logging")
    
    # Report Options
    parser.add_argument("--report-json", help="Output JSON report to file")
    parser.add_argument("--report-html", help="Output HTML report to file")

    args = parser.parse_args()

    if args.gui:
        print(f"{Fore.GREEN}[*] Please use 'cerberus --gui' to launch the interface.{Style.RESET_ALL}")
        return

    if not args.url:
        parser.print_help()
        print(f"\n{Fore.RED}[!] Error: Target URL is required.{Style.RESET_ALL}")
        return

    # 1. Initialize Target
    print(f"{Fore.BLUE}[*] Initializing Target: {args.url}{Style.RESET_ALL}")
    target = Target(url=args.url, method=args.method)

    # 2. Setup Authentication
    auth_credentials = {}
    auth_type = AuthType.NONE
    
    if args.auth_type == "bearer" and args.auth_token:
        auth_type = AuthType.BEARER
        auth_credentials = {"token": args.auth_token}
    elif args.auth_type == "basic" and args.auth_user and args.auth_pass:
        auth_type = AuthType.BASIC
        auth_credentials = {"username": args.auth_user, "password": args.auth_pass}
    
    authenticator = Authenticator(auth_type=auth_type, credentials=auth_credentials)

    # 3. Profiling
    profiler = Profiler(target)
    # Apply auth to profiler session
    authenticator.authenticate(profiler.session)
    profiler.profile()
    
    print_recon_data(target)

    # 4. Scanning
    vulnerabilities = []
    
    if args.scan_all or args.scan_sqli:
        logger.info("Running SQL Injection scan...")
        scanner = SQLInjectionScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))

    if args.scan_all or args.scan_xss:
        logger.info("Running XSS scan...")
        scanner = XSSScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_cmdi:
        logger.info("Running Command Injection scan...")
        scanner = CommandInjectionScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_bola:
        logger.info("Running BOLA/IDOR scan...")
        scanner = BOLAScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_ssrf:
        logger.info("Running SSRF scan...")
        scanner = SSRFScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_xxe:
        logger.info("Running XXE scan...")
        scanner = XXEScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_auth:
        logger.info("Running Authentication scan...")
        scanner = AuthScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_access:
        logger.info("Running Access Control scan...")
        scanner = BrokenAccessControlScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_misconfig:
        logger.info("Running Security Misconfiguration scan...")
        scanner = SecurityMisconfigurationScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_data:
        logger.info("Running Sensitive Data Exposure scan...")
        scanner = SensitiveDataExposureScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_nosql:
        logger.info("Running NoSQL Injection scan...")
        scanner = NoSQLInjectionScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_graphql:
        logger.info("Running GraphQL Injection scan...")
        scanner = GraphQLInjectionScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_ssti:
        logger.info("Running SSTI scan...")
        scanner = SSTIScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_ldap:
        logger.info("Running LDAP Injection scan...")
        scanner = LDAPInjectionScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_xpath:
        logger.info("Running XPath Injection scan...")
        scanner = XPathInjectionScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_xml:
        logger.info("Running XML Injection scan...")
        scanner = XMLInjectionScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_jwt:
        logger.info("Running JWT Vulnerabilities scan...")
        scanner = JWTScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_oauth:
        logger.info("Running OAuth Misconfiguration scan...")
        scanner = OAuthScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_hpp:
        logger.info("Running HTTP Parameter Pollution scan...")
        scanner = HTTPParameterPollutionScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_ratelimit:
        logger.info("Running Rate Limiting scan...")
        scanner = RateLimitScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_mass:
        logger.info("Running Mass Assignment scan...")
        scanner = MassAssignmentScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_logic:
        logger.info("Running Business Logic scan...")
        scanner = BusinessLogicScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))
    
    if args.scan_all or args.scan_logging:
        logger.info("Running Logging & Monitoring scan...")
        scanner = LoggingScanner(session=profiler.session)
        vulnerabilities.extend(scanner.scan(target))

    # 5. Reporting
    reporter = Reporter(target, vulnerabilities)
    
    if args.report_json:
        reporter.generate_json(args.report_json)
        logger.info(f"JSON report saved to {args.report_json}")
    if args.report_html:
        reporter.generate_html(args.report_html)
        logger.info(f"HTML report saved to {args.report_html}")

    # Print Vulnerability Report to Terminal
    print_vulnerability_report(vulnerabilities)

    logger.info(f"Scan completed. Found {len(vulnerabilities)} total vulnerabilities.")

def print_recon_data(target):
    """Prints enhanced reconnaissance data in a structured format"""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Reconnaissance Report{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    # 1. Tech Stack
    print(f"\n{Fore.YELLOW}[*] Technology Stack:{Style.RESET_ALL}")
    ts = target.detailed_tech_stack
    if ts:
        print(f"  {Fore.GREEN}Server:{Style.RESET_ALL}   {ts.get('server', 'Unknown')}")
        print(f"  {Fore.GREEN}Backend:{Style.RESET_ALL}  {ts.get('backend', 'Unknown')}")
        print(f"  {Fore.GREEN}Frontend:{Style.RESET_ALL} {ts.get('frontend', 'Unknown')}")
        
        if ts.get('frameworks'):
            print(f"  {Fore.GREEN}Frameworks:{Style.RESET_ALL} {', '.join(ts['frameworks'])}")
        
        if ts.get('languages'):
            print(f"  {Fore.GREEN}Languages:{Style.RESET_ALL}  {', '.join(ts['languages'])}")
    else:
        print("  No detailed tech stack information available.")

    # 2. Open Ports
    if target.open_ports:
        print(f"\n{Fore.YELLOW}[*] Open Ports:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}{'PORT':<10} {'SERVICE':<15} {'STATE':<10}{Style.RESET_ALL}")
        print(f"  {'-'*35}")
        for port in target.open_ports:
            state_color = Fore.GREEN if port['state'] == 'open' else Fore.RED
            print(f"  {port['port']:<10} {port['service']:<15} {state_color}{port['state']}{Style.RESET_ALL}")

    # 3. Subdomains
    if target.subdomains:
        print(f"\n{Fore.YELLOW}[*] Discovered Subdomains ({len(target.subdomains)}):{Style.RESET_ALL}")
        for sub in target.subdomains[:5]:  # Show first 5
            print(f"  - {sub}")
        if len(target.subdomains) > 5:
            print(f"  ... and {len(target.subdomains) - 5} more")

    # 4. Subdirectories
    if target.subdirectories:
        print(f"\n{Fore.YELLOW}[*] Interesting Directories ({len(target.subdirectories)}):{Style.RESET_ALL}")
        for sub in target.subdirectories[:5]:  # Show first 5
            print(f"  - {sub}")
        if len(target.subdirectories) > 5:
            print(f"  ... and {len(target.subdirectories) - 5} more")
            
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

def print_vulnerability_report(vulnerabilities):
    """Prints detailed vulnerability report to terminal"""
    if not vulnerabilities:
        return

    print(f"\n{Fore.RED}{Style.BRIGHT}[!] Vulnerability Report ({len(vulnerabilities)} Found){Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")

    for i, vuln in enumerate(vulnerabilities, 1):
        # Determine severity color
        sev_color = Fore.WHITE
        if vuln.severity == "CRITICAL":
            sev_color = Fore.RED + Style.BRIGHT
        elif vuln.severity == "HIGH":
            sev_color = Fore.RED
        elif vuln.severity == "MEDIUM":
            sev_color = Fore.YELLOW
        elif vuln.severity == "LOW":
            sev_color = Fore.BLUE
        
        print(f"\n{Fore.WHITE}[{i}] {sev_color}{vuln.name}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Severity:{Style.RESET_ALL}    {sev_color}{vuln.severity}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Description:{Style.RESET_ALL} {vuln.description}")
        
        if hasattr(vuln, 'url') and vuln.url:
             print(f"    {Fore.WHITE}URL:{Style.RESET_ALL}         {vuln.url}")
             
        print(f"    {Fore.WHITE}Evidence:{Style.RESET_ALL}    {Fore.CYAN}{vuln.evidence}{Style.RESET_ALL}")

    print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
