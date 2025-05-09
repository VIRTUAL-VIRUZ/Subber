#!/usr/bin/env python3
"""
Subber - Subdomain Takeover Vulnerability Scanner
A tool to scan for potential subdomain takeover vulnerabilities by detecting
unclaimed services referenced in DNS records.
"""

import argparse
import concurrent.futures
import dns.resolver
import json
import os
import re
import requests
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# Default user agent for HTTP requests
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

# Service fingerprints for detecting vulnerable services
SERVICE_FINGERPRINTS = {
    "aws-s3": {
        "cname": [".s3.amazonaws.com", ".s3-website", ".s3-website-"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
        "status_code": [404]
    },
    "github-pages": {
        "cname": ["github.io"],
        "fingerprint": ["There isn't a GitHub Pages site here", "Page not found"],
        "status_code": [404]
    },
    "heroku": {
        "cname": ["herokuapp.com", "herokudns.com", "herokussl.com"],
        "fingerprint": ["No such app", "Heroku | No such app", "heroku.com/no-such-app"],
        "status_code": [404]
    },
    "azure": {
        "cname": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net"],
        "fingerprint": ["404 Web Site not found", "This website is temporarily unavailable", "The specified blob does not exist"],
        "status_code": [404]
    },
    "cloudfront": {
        "cname": ["cloudfront.net"],
        "fingerprint": ["The request could not be satisfied", "ERROR: The request could not be satisfied"],
        "status_code": [404, 403]
    },
    "shopify": {
        "cname": ["myshopify.com"],
        "fingerprint": ["Sorry, this shop is currently unavailable"],
        "status_code": [404]
    },
    "fastly": {
        "cname": ["fastly.net"],
        "fingerprint": ["Fastly error: unknown domain", "Please check that this domain has been added to a service"],
        "status_code": [404]
    },
    "pantheon": {
        "cname": ["pantheonsite.io"],
        "fingerprint": ["The gods are wise", "404 - Site Not Found"],
        "status_code": [404]
    },
    "tumblr": {
        "cname": ["tumblr.com"],
        "fingerprint": ["There's nothing here", "Whatever you were looking for doesn't currently exist at this address"],
        "status_code": [404]
    },
    "wordpress": {
        "cname": ["wordpress.com"],
        "fingerprint": ["Do you want to register", "doesn't exist"],
        "status_code": [404]
    },
    "surge": {
        "cname": ["surge.sh"],
        "fingerprint": ["project not found", "Surge - 404"],
        "status_code": [404]
    },
    "bitbucket": {
        "cname": ["bitbucket.io"],
        "fingerprint": ["Repository not found", "The page you're looking for doesn't exist"],
        "status_code": [404]
    },
    "netlify": {
        "cname": ["netlify.app", "netlify.com"],
        "fingerprint": ["Not found", "no site configured at this address"],
        "status_code": [404]
    },
    "vercel": {
        "cname": ["vercel.app", "now.sh"],
        "fingerprint": ["404 - This page could not be found", "The deployment could not be found on Vercel"],
        "status_code": [404]
    }
}

class SubdomainTakeoverScanner:
    def __init__(self, timeout=10, threads=10, verbose=False, output=None, https=True, bypass_403=True):
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.output = output
        self.https = https
        self.bypass_403 = bypass_403
        self.results = []
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Configure custom headers for 403/401 bypass
        self.custom_headers = [
            {"Host": "localhost"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "localhost"},
            {"X-Forwarded-Server": "localhost"},
            {"X-Original-URL": "/"},
            {"X-Rewrite-URL": "/"},
        ]
        
        # HTTP session with default headers
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close"
        })

    def print_banner(self):
        """Print the tool banner."""
        banner = f"""
{Fore.CYAN}
███████╗██╗   ██╗██████╗ ██████╗ ███████╗██████╗ 
██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
███████╗██║   ██║██████╔╝██████╔╝█████╗  ██████╔╝
╚════██║██║   ██║██╔══██╗██╔══██╗██╔══╝  ██╔══██╗
███████║╚██████╔╝██████╔╝██████╔╝███████╗██║  ██║
╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}[*] Subdomain Takeover Vulnerability Scanner{Style.RESET_ALL}
[*] Starting scan at {time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        print(banner)

    def load_subdomains(self, subdomain_file):
        """Load subdomains from a file."""
        try:
            with open(subdomain_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            
            if self.verbose:
                print(f"{Fore.GREEN}[+] Loaded {len(subdomains)} subdomains from {subdomain_file}{Style.RESET_ALL}")
            
            return subdomains
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading subdomain file: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

    def resolve_cname(self, subdomain):
        """Resolve CNAME record for a subdomain."""
        try:
            answers = self.resolver.resolve(subdomain, 'CNAME')
            return str(answers[0]).rstrip('.')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return None
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Error resolving CNAME for {subdomain}: {str(e)}{Style.RESET_ALL}")
            return None

    def resolve_a_record(self, subdomain):
        """Resolve A record for a subdomain."""
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            return [str(answer) for answer in answers]
        except Exception:
            return []

    def resolve_aaaa_record(self, subdomain):
        """Resolve AAAA record for a subdomain."""
        try:
            answers = self.resolver.resolve(subdomain, 'AAAA')
            return [str(answer) for answer in answers]
        except Exception:
            return []

    def detect_wildcard_dns(self, domain):
        """Detect if domain has wildcard DNS entries."""
        random_subdomain = f"random{int(time.time())}.{domain}"
        
        try:
            # Check if random subdomain resolves (indicating wildcard DNS)
            self.resolver.resolve(random_subdomain, 'A')
            return True
        except Exception:
            return False

    def check_service_fingerprint(self, response_text, service):
        """Check if response contains service fingerprint."""
        for fingerprint in SERVICE_FINGERPRINTS[service]["fingerprint"]:
            if fingerprint.lower() in response_text.lower():
                return True
        return False

    def check_takeover_possibility(self, subdomain, cname):
        """Check if subdomain is vulnerable to takeover based on CNAME."""
        vulnerable_service = None
        
        # Check if CNAME matches any known service
        for service, data in SERVICE_FINGERPRINTS.items():
            for cname_pattern in data["cname"]:
                if cname_pattern in cname:
                    vulnerable_service = service
                    break
            if vulnerable_service:
                break
        
        if not vulnerable_service:
            return None
            
        # Make HTTP request to validate
        for protocol in ["https", "http"]:
            if protocol == "http" and self.https:
                continue  # Skip HTTP if HTTPS-only scanning is enabled
                
            try:
                url = f"{protocol}://{subdomain}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
                response_text = response.text.lower()
                
                # Check if status code matches expected for the service
                if response.status_code in SERVICE_FINGERPRINTS[vulnerable_service]["status_code"]:
                    # Check for service fingerprint in response
                    if self.check_service_fingerprint(response_text, vulnerable_service):
                        return {
                            "subdomain": subdomain,
                            "cname": cname,
                            "service": vulnerable_service,
                            "status_code": response.status_code,
                            "url": url,
                            "vulnerable": True
                        }
                
                # Try 403/401 bypass if enabled
                if self.bypass_403 and response.status_code in [401, 403]:
                    bypass_result = self.try_403_bypass(url, vulnerable_service)
                    if bypass_result:
                        return bypass_result
                        
            except requests.exceptions.RequestException:
                continue
                
        return None

    def try_403_bypass(self, url, service):
        """Try to bypass 403/401 errors with custom headers."""
        for headers in self.custom_headers:
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True, verify=False)
                if response.status_code not in [401, 403]:
                    if self.check_service_fingerprint(response.text.lower(), service):
                        parsed_url = urlparse(url)
                        return {
                            "subdomain": parsed_url.netloc,
                            "cname": None,  # We don't have this info here
                            "service": service,
                            "status_code": response.status_code,
                            "url": url,
                            "vulnerable": True,
                            "bypass_header": list(headers.keys())[0]
                        }
            except requests.exceptions.RequestException:
                continue
                
        return None

    def scan_subdomain(self, subdomain):
        """Scan a single subdomain for takeover vulnerability."""
        if self.verbose:
            print(f"{Fore.BLUE}[*] Scanning {subdomain}{Style.RESET_ALL}")
            
        # Ensure the subdomain is properly formatted
        if not subdomain or "." not in subdomain:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Invalid subdomain format: {subdomain}{Style.RESET_ALL}")
            return None
            
        # Extract base domain for wildcard detection
        domain_parts = subdomain.split('.')
        if len(domain_parts) > 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = subdomain
            
        # Check for wildcard DNS
        has_wildcard = self.detect_wildcard_dns(base_domain)
        if has_wildcard and self.verbose:
            print(f"{Fore.YELLOW}[!] Wildcard DNS detected for {base_domain}{Style.RESET_ALL}")
            
        # 1. Check CNAME record
        cname = self.resolve_cname(subdomain)
        if cname:
            result = self.check_takeover_possibility(subdomain, cname)
            if result:
                print(f"{Fore.GREEN}[+] Potential subdomain takeover: {subdomain} -> {cname} ({result['service']}){Style.RESET_ALL}")
                return result
                
        # 2. Check A/AAAA records for IP-based services
        a_records = self.resolve_a_record(subdomain)
        aaaa_records = self.resolve_aaaa_record(subdomain)
        
        if not a_records and not aaaa_records:
            # Dangling DNS record (no IP) - could be a takeover opportunity 
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Dangling DNS record (no IP): {subdomain}{Style.RESET_ALL}")
            
            # Try HTTP request to see if it resolves anyway
            for protocol in ["https", "http"]:
                if protocol == "http" and self.https:
                    continue
                    
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
                    
                    # Check all service fingerprints
                    for service, data in SERVICE_FINGERPRINTS.items():
                        if response.status_code in data["status_code"]:
                            if self.check_service_fingerprint(response.text.lower(), service):
                                print(f"{Fore.GREEN}[+] Potential takeover via dangling record: {subdomain} ({service}){Style.RESET_ALL}")
                                return {
                                    "subdomain": subdomain,
                                    "cname": None,
                                    "service": service,
                                    "status_code": response.status_code,
                                    "url": url,
                                    "vulnerable": True,
                                    "note": "Dangling DNS record"
                                }
                except requests.exceptions.RequestException:
                    continue
        
        return None

    def scan(self, subdomains):
        """Scan multiple subdomains for takeover vulnerabilities."""
        self.print_banner()
        
        results = []
        start_time = time.time()
        
        print(f"{Fore.BLUE}[*] Starting scan of {len(subdomains)} subdomains with {self.threads} threads{Style.RESET_ALL}")
        
        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {executor.submit(self.scan_subdomain, subdomain): subdomain for subdomain in subdomains}
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"{Fore.RED}[!] Error scanning {subdomain}: {str(e)}{Style.RESET_ALL}")
        
        # Print summary
        scan_time = time.time() - start_time
        print(f"\n{Fore.BLUE}[*] Scan completed in {scan_time:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Found {len(results)} potential subdomain takeover vulnerabilities{Style.RESET_ALL}")
        
        # Save results to file if specified
        if self.output and results:
            try:
                with open(self.output, 'w') as f:
                    for result in results:
                        f.write(f"Subdomain: {result['subdomain']}\n")
                        f.write(f"CNAME: {result['cname']}\n") if result['cname'] else f.write("CNAME: None\n")
                        f.write(f"Service: {result['service']}\n")
                        f.write(f"URL: {result['url']}\n")
                        f.write(f"Status Code: {result['status_code']}\n")
                        if 'bypass_header' in result:
                            f.write(f"Bypass Header: {result['bypass_header']}\n")
                        if 'note' in result:
                            f.write(f"Note: {result['note']}\n")
                        f.write("---\n")
                print(f"{Fore.GREEN}[+] Results saved to {self.output}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error saving results: {str(e)}{Style.RESET_ALL}")
        
        return results

def main():
    """Main function to parse arguments and run the scanner."""
    parser = argparse.ArgumentParser(description="Subdomain Takeover Vulnerability Scanner")
    
    parser.add_argument("-l", "--list", required=True, help="File containing list of subdomains to scan")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout for requests in seconds (default: 10)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--https-only", action="store_true", help="Only test HTTPS connections, skip HTTP")
    parser.add_argument("--no-bypass", action="store_true", help="Disable 403/401 bypass attempts")
    
    args = parser.parse_args()
    
    try:
        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Load subdomains
        scanner = SubdomainTakeoverScanner(
            timeout=args.timeout,
            threads=args.concurrency,
            verbose=args.verbose,
            output=args.output,
            https=args.https_only,
            bypass_403=not args.no_bypass
        )
        
        subdomains = scanner.load_subdomains(args.list)
        scanner.scan(subdomains)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
