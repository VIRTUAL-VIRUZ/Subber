# Subber - Subdomain Takeover Vulnerability Scanner

A powerful tool to detect potential subdomain takeover vulnerabilities by identifying unclaimed services referenced in DNS records.

## Overview

Subdomain takeover vulnerabilities occur when a subdomain points to a service (like AWS S3, Heroku, GitHub Pages) that hasn't been properly claimed or configured. Attackers can register the service and take control of the subdomain.

Subber helps identify these vulnerabilities by:
- Checking DNS records (CNAME, A, AAAA)
- Fingerprinting service responses
- Testing for common bypass techniques
- Multi-threaded scanning for speed

## Features

- **CNAME Detection**: Identifies subdomains with CNAME records pointing to third-party services
- **A/AAAA Record Checks**: Tests IP-based services for takeover possibilities
- **Wildcard DNS Detection**: Identifies wildcard DNS entries that might lead to false positives
- **HTTPS Support**: Tests subdomains over both HTTP and HTTPS protocols
- **403/401 Bypass**: Attempts to bypass HTTP errors using custom headers
- **Service Fingerprinting**: Includes a database of known service error messages to confirm vulnerabilities
- **Multi-threading**: Scans multiple subdomains concurrently for efficiency

## Supported Services

Subber can detect takeover vulnerabilities in these services (and more):
- AWS S3 Buckets
- GitHub Pages
- Heroku Apps
- Azure Services
- Cloudfront
- Shopify
- Fastly
- Pantheon
- Wordpress
- Tumblr
- Surge
- Bitbucket
- Netlify
- Vercel

## Installation

```bash
# Clone the repository
git clone https://github.com/VIRTUAL-VIRUZ/Subber.git
cd subber

# Install dependencies
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python3 subber.py -l subdomains.txt -o results.txt
```

Full options:

```bash
python3 subber.py --help

usage: subber.py [-h] -l LIST [-o OUTPUT] [-t TIMEOUT] [-c CONCURRENCY] [-v] [--https-only] [--no-bypass]

Subdomain Takeover Vulnerability Scanner

optional arguments:
  -h, --help            show this help message and exit
  -l LIST, --list LIST  File containing list of subdomains to scan
  -o OUTPUT, --output OUTPUT
                        Output file to save results
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout for requests in seconds (default: 10)
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent threads (default: 10)
  -v, --verbose         Enable verbose output
  --https-only          Only test HTTPS connections, skip HTTP
  --no-bypass           Disable 403/401 bypass attempts
```

## Example

```bash
# Create a file with subdomains to test
echo "test.example.com" > subdomains.txt
echo "dev.example.com" >> subdomains.txt
echo "staging.example.com" >> subdomains.txt

# Run the scanner with verbose output
python3 subber.py -l subdomains.txt -o vulnerable.txt -v
```

## Output

The tool will output results to the console and optionally to a file:

```
███████╗██╗   ██╗██████╗ ██████╗ ███████╗██████╗ 
██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗
███████╗██║   ██║██████╔╝██████╔╝█████╗  ██████╔╝
╚════██║██║   ██║██╔══██╗██╔══██╗██╔══╝  ██╔══██╗
███████║╚██████╔╝██████╔╝██████╔╝███████╗██║  ██║
╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

[*] Subdomain Takeover Vulnerability Scanner
[*] Starting scan at 2025-05-09 10:15:30
[*] Starting scan of 3 subdomains with 10 threads
[+] Potential subdomain takeover: dev.example.com -> dev-app.herokuapp.com (heroku)

[*] Scan completed in 5.43 seconds
[+] Found 1 potential subdomain takeover vulnerabilities
[+] Results saved to vulnerable.txt
```

## Security Note

This tool is intended for security professionals to test their own systems or systems they have permission to test. Do not use this tool against systems without proper authorization.

## License

MIT License

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests to improve the tool.
