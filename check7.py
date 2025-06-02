import requests
from urllib.parse import urlparse
from colorama import Fore, Style, init
import re
import sys
from datetime import datetime

# Initialize colorama
init(autoreset=True)

# RFC Validation Rules
RFC_RULES = {
    # General header rules (RFC 7230, 2616)
    'general': {
        'header-name': re.compile(r'^[!#$%&\'*+-.^_`|~0-9a-zA-Z]+$'),
        'header-value': re.compile(r'^[ \t\x21-\x7e\x80-\xff]*$'),
        'obs-fold': re.compile(r'\r\n[ \t]+')
    },
    
    # Specific header rules
    'headers': {
        'Content-Type': {
            'required': True,
            'format': re.compile(r'^[a-zA-Z0-9!#$%&\'*+-.^_`|~]+\/[a-zA-Z0-9!#$%&\'*+-.^_`|~]+(;\s*charset=[a-zA-Z0-9-]+)?$'),
            'rfc': '7231'
        },
        'Cache-Control': {
            'required': False,
            'directives': [
                'max-age', 's-maxage', 'no-cache', 'no-store', 'no-transform',
                'must-revalidate', 'proxy-revalidate', 'public', 'private',
                'immutable', 'stale-while-revalidate', 'stale-if-error'
            ],
            'rfc': '7234'
        },
        'Date': {
            'required': True,
            'format': re.compile(r'^(Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s\d{2}\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{4}\s\d{2}:\d{2}:\d{2}\sGMT$'),
            'rfc': '7231'
        },
        'Server': {
            'required': False,
            'format': re.compile(r'^[a-zA-Z0-9\-\._\s\/]+$'),
            'rfc': '7231'
        }
    },
    
    # Security headers (not RFC specific but best practices)
    'security': {
        'Strict-Transport-Security': {
            'required': False,
            'format': re.compile(r'^max-age=\d+(;\s*includeSubDomains)?(;\s*preload)?$'),
            'recommended': 'max-age=31536000; includeSubDomains'
        },
        'X-Content-Type-Options': {
            'required': False,
            'values': ['nosniff'],
            'recommended': 'nosniff'
        },
        'X-Frame-Options': {
            'required': False,
            'values': ['DENY', 'SAMEORIGIN', 'ALLOW-FROM'],
            'recommended': 'DENY'
        },
        'Content-Security-Policy': {
            'required': False,
            'recommended': "default-src 'self'"
        },
        'X-XSS-Protection': {
            'required': False,
            'values': ['0', '1', '1; mode=block'],
            'recommended': '1; mode=block'
        }
    }
}

def validate_header_rfc(header_name, header_value):
    """Validate a header against RFC rules."""
    violations = []
    
    # Check general header format (RFC 7230 section 3.2)
    if not RFC_RULES['general']['header-name'].match(header_name):
        violations.append(f"Invalid header name (RFC 7230)")
    
    if RFC_RULES['general']['obs-fold'].search(header_value):
        violations.append(f"Contains obsolete line folding (RFC 7230)")
    
    if not RFC_RULES['general']['header-value'].match(header_value):
        violations.append(f"Invalid header value (RFC 7230)")
    
    # Check specific header rules
    if header_name in RFC_RULES['headers']:
        rules = RFC_RULES['headers'][header_name]
        
        if 'format' in rules and not rules['format'].match(header_value):
            violations.append(f"Invalid format (RFC {rules['rfc']})")
        
        if 'directives' in rules:
            directives = [d.split('=')[0] for d in header_value.split(',')]
            for d in directives:
                if d.strip() not in rules['directives']:
                    violations.append(f"Invalid Cache-Control directive: {d} (RFC {rules['rfc']})")
    
    return violations

def check_security_headers(headers):
    """Check security headers against best practices."""
    results = []
    
    for header, rules in RFC_RULES['security'].items():
        if header not in headers:
            results.append((header, "MISSING", False, f"Recommended: {rules.get('recommended', '')}"))
            continue
        
        value = headers[header]
        valid = True
        issues = []
        
        if 'values' in rules and value not in rules['values']:
            valid = False
            issues.append(f"Should be one of: {', '.join(rules['values'])}")
        
        if 'format' in rules and not rules['format'].match(value):
            valid = False
            issues.append(f"Should match format: {rules['format'].pattern}")
        
        if not issues:
            results.append((header, value, True, ""))
        else:
            results.append((header, value, False, "; ".join(issues)))
    
    return results

def analyze_headers(headers):
    """Analyze headers for RFC compliance and security."""
    rfc_results = []
    for header, value in headers.items():
        violations = validate_header_rfc(header, value)
        if violations:
            rfc_results.append((header, value, False, "; ".join(violations)))
        else:
            rfc_results.append((header, value, True, ""))
    
    security_results = check_security_headers(headers)
    return rfc_results, security_results

def get_cache_info(headers):
    """Extract cache-related information from headers."""
    cache_info = {}
    
    # Cache-Control
    if 'Cache-Control' in headers:
        directives = [d.strip() for d in headers['Cache-Control'].split(',')]
        cache_info['Cache-Control'] = directives
    
    # Expires
    if 'Expires' in headers:
        cache_info['Expires'] = headers['Expires']
    
    # ETag
    if 'ETag' in headers:
        cache_info['ETag'] = headers['ETag']
    
    # Last-Modified
    if 'Last-Modified' in headers:
        cache_info['Last-Modified'] = headers['Last-Modified']
    
    # Age
    if 'Age' in headers:
        cache_info['Age'] = headers['Age']
    
    return cache_info

def follow_redirects(url, max_redirects=5):
    """Follow redirects and return the final URL and response chain."""
    session = requests.Session()
    session.max_redirects = max_redirects
    response = session.get(url, allow_redirects=False)
    
    redirect_chain = []
    final_url = url
    
    try:
        while response.is_redirect:
            redirect_url = response.headers['Location']
            status_code = response.status_code
            redirect_chain.append({
                'from': final_url,
                'to': redirect_url,
                'status': status_code,
                'headers': dict(response.headers)
            })
            final_url = redirect_url
            response = session.get(redirect_url, allow_redirects=False)
    except requests.exceptions.TooManyRedirects:
        print(f"{Fore.RED}Error: Too many redirects (> {max_redirects}){Style.RESET_ALL}")
        return None, None
    
    return final_url, redirect_chain

def analyze_url(url):
    """Analyze the given URL with redirect handling."""
    try:
        # Follow redirects first
        final_url, redirect_chain = follow_redirects(url)
        if not final_url:
            return {'url': url, 'error': "Too many redirects"}
        
        # Get final response
        response = requests.get(final_url, timeout=10)
        headers = dict(response.headers)
        
        # Calculate sizes
        header_size = len(str(headers).encode('utf-8'))
        cookie_size = len(str(response.cookies).encode('utf-8'))
        
        # Analyze headers
        rfc_results, security_results = analyze_headers(headers)
        
        # Get cache info
        cache_info = get_cache_info(headers)
        
        return {
            'original_url': url,
            'final_url': final_url,
            'redirect_chain': redirect_chain,
            'status_code': response.status_code,
            'headers': headers,
            'header_size': header_size,
            'cookies': dict(response.cookies),
            'cookie_size': cookie_size,
            'rfc_results': rfc_results,
            'security_results': security_results,
            'cache_info': cache_info,
            'error': None
        }
    except Exception as e:
        return {
            'url': url,
            'error': str(e)
        }

def print_results(results):
    """Print the analysis results with colored output."""
    if results.get('error'):
        print(f"{Fore.RED}Error analyzing {results.get('url', 'URL')}: {results['error']}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.YELLOW}=== Analysis Report ==={Style.RESET_ALL}")
    print(f"Original URL: {results['original_url']}")
    print(f"Final URL: {results['final_url']}")
    print(f"Status Code: {results['status_code']}")
    
    # Print redirect chain if any
    if results.get('redirect_chain'):
        print(f"\n{Fore.CYAN}=== Redirect Chain ==={Style.RESET_ALL}")
        for i, redirect in enumerate(results['redirect_chain'], 1):
            print(f"{i}. {redirect['from']} -> {redirect['to']} ({redirect['status']})")
    
    # Print header and cookie sizes in blue
    print(f"\n{Fore.BLUE}Header Size: {results['header_size']} bytes{Style.RESET_ALL}")
    print(f"{Fore.BLUE}Cookie Size: {results['cookie_size']} bytes{Style.RESET_ALL}")
    
    # Print cookies in blue
    if results['cookies']:
        print(f"\n{Fore.BLUE}Cookies:{Style.RESET_ALL}")
        for name, value in results['cookies'].items():
            print(f"  {name}: {value}")
    
    # Print cache information in blue
    if results['cache_info']:
        print(f"\n{Fore.BLUE}Cache Information:{Style.RESET_ALL}")
        for key, value in results['cache_info'].items():
            print(f"  {key}: {value}")
    
    # Print RFC compliance results
    print(f"\n{Fore.YELLOW}=== RFC Compliance Checks ==={Style.RESET_ALL}")
    for header, value, valid, message in results['rfc_results']:
        if valid:
            print(f"{Fore.GREEN}PASS{Style.RESET_ALL}: {header}: {value}")
        else:
            print(f"{Fore.RED}FAIL{Style.RESET_ALL}: {header}: {value} - {message}")
    
    # Print security checks
    print(f"\n{Fore.YELLOW}=== Security Header Checks ==={Style.RESET_ALL}")
    for header, value, valid, message in results['security_results']:
        if valid:
            print(f"{Fore.GREEN}PASS{Style.RESET_ALL}: {header}: {value}")
        else:
            print(f"{Fore.RED}FAIL{Style.RESET_ALL}: {header}: {value} - {message}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <URL>")
        sys.exit(1)
    
    url = sys.argv[1]
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    results = analyze_url(url)
    print_results(results)
