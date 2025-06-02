import re
import argparse
from urllib.parse import urlparse
import requests
from collections import defaultdict
import sys

# RFC 7230, 7540 header field syntax rules
TOKEN = r'[-!#$%&\'*+.^_`|~0-9a-zA-Z]+'
HEADER_NAME = re.compile(f'^{TOKEN}$')
HEADER_VALUE = re.compile(r'^[ \t]*(?:[\x21-\x7E\x80-\xFF][ \t]*)*$')

# Standard headers from various RFCs and common conventions
STANDARD_HEADERS = {
    # HTTP/1.0 and HTTP/1.1 (RFC 7230, 7231, etc.)
    'Accept', 'Accept-Charset', 'Accept-Encoding', 'Accept-Language',
    'Accept-Ranges', 'Age', 'Allow', 'Authorization', 'Cache-Control',
    'Connection', 'Content-Encoding', 'Content-Language', 'Content-Length',
    'Content-Location', 'Content-Range', 'Content-Type', 'Date', 'ETag',
    'Expect', 'Expires', 'From', 'Host', 'If-Match', 'If-Modified-Since',
    'If-None-Match', 'If-Range', 'If-Unmodified-Since', 'Last-Modified',
    'Location', 'Max-Forwards', 'Pragma', 'Proxy-Authenticate',
    'Proxy-Authorization', 'Range', 'Referer', 'Retry-After', 'Server',
    'TE', 'Trailer', 'Transfer-Encoding', 'Upgrade', 'User-Agent', 'Vary',
    'Via', 'Warning', 'WWW-Authenticate',
    
    # HTTP/2 (RFC 7540)
    ':method', ':path', ':authority', ':scheme', ':status',
    
    # Common non-standard but widely used headers
    'X-Forwarded-For', 'X-Forwarded-Proto', 'X-Forwarded-Host',
    'X-Requested-With', 'X-CSRF-Token', 'X-Content-Type-Options',
    'X-Frame-Options', 'X-XSS-Protection', 'DNT', 'Forwarded'
}

# Security headers and their recommended values
SECURITY_HEADERS = {
    'Content-Security-Policy': {
        'required': False,
        'description': 'Prevents XSS, clickjacking and other code injection attacks',
        'recommended': "default-src 'self'; script-src 'self'",
        'severity': 'high'
    },
    'X-Content-Type-Options': {
        'required': True,
        'description': 'Prevents MIME type sniffing',
        'recommended': 'nosniff',
        'severity': 'medium'
    },
    'X-Frame-Options': {
        'required': True,
        'description': 'Prevents clickjacking attacks',
        'recommended': 'DENY or SAMEORIGIN',
        'severity': 'high'
    },
    'X-XSS-Protection': {
        'required': True,
        'description': 'Enables XSS filtering protection',
        'recommended': '1; mode=block',
        'severity': 'medium'
    },
    'Strict-Transport-Security': {
        'required': False,  # Only for HTTPS sites
        'description': 'Enforces HTTPS connections',
        'recommended': 'max-age=31536000; includeSubDomains; preload',
        'severity': 'high'
    },
    'Referrer-Policy': {
        'required': False,
        'description': 'Controls referrer information in requests',
        'recommended': 'no-referrer-when-downgrade',
        'severity': 'low'
    },
    'Permissions-Policy': {
        'required': False,
        'description': 'Controls browser features and APIs',
        'recommended': 'geolocation=(self), microphone=()',
        'severity': 'medium'
    },
    'Cross-Origin-Opener-Policy': {
        'required': False,
        'description': 'Prevents cross-origin attacks',
        'recommended': 'same-origin',
        'severity': 'medium'
    },
    'Cross-Origin-Resource-Policy': {
        'required': False,
        'description': 'Prevents cross-origin resource attacks',
        'recommended': 'same-origin',
        'severity': 'medium'
    }
}

def validate_header_name(name):
    """Validate header name against RFC 7230 syntax rules."""
    if not HEADER_NAME.match(name):
        return False, f"Invalid header name syntax: '{name}'"
    
    if '\r' in name or '\n' in name:
        return False, "Header name contains obs-fold (CR/LF)"
    
    return True, "Valid header name"

def validate_header_value(value):
    """Validate header value against RFC 7230 syntax rules."""
    if not HEADER_VALUE.match(value):
        return False, f"Invalid header value syntax: '{value}'"
    
    if '\r' in value or '\n' in value:
        return False, "Header value contains obs-fold (CR/LF)"
    
    return True, "Valid header value"

def check_standard_header(name):
    """Check if header is in the standard headers list."""
    if name.startswith(':'):
        return name in STANDARD_HEADERS, "Pseudo-header (HTTP/2)"
    return name in STANDARD_HEADERS, "Standard header" if name in STANDARD_HEADERS else "Non-standard header"

def check_host_header_presence(headers):
    """Check if Host header is present (required in HTTP/1.1)."""
    return 'Host' in headers, "Host header is required in HTTP/1.1"

def check_content_length_conditions(headers, method, status_code):
    """Check Content-Length header conditions."""
    issues = []
    content_length = headers.get('Content-Length')
    
    if method.upper() == 'HEAD' and content_length is None:
        issues.append("HEAD response should include Content-Length if GET would")
    
    if status_code in (204, 304) or (100 <= status_code < 200):
        if content_length is not None and content_length != '0':
            issues.append(f"Content-Length should be absent or zero for status {status_code}")
    
    return not bool(issues), issues if issues else "Content-Length conditions OK"

def check_security_headers(headers, is_https):
    """Check for important security headers and their values."""
    results = []
    stats = defaultdict(int)
    
    for header, config in SECURITY_HEADERS.items():
        present = header in headers
        recommendation = config['recommended']
        severity = config['severity']
        
        # Skip HSTS check for non-HTTPS sites
        if header == 'Strict-Transport-Security' and not is_https:
            results.append((f"Security: {header}", True, "Not applicable for HTTP sites"))
            continue
        
        # Check if header is present
        if not present:
            if config['required']:
                status = False
                message = f"Missing recommended security header (severity: {severity})"
                stats['missing_required_security'] += 1
            else:
                status = True
                message = "Optional security header missing"
                stats['missing_optional_security'] += 1
            results.append((f"Security: {header}", status, message))
            continue
        
        # Validate header values
        header_value = headers[header]
        valid = True
        notes = []
        
        if header == 'X-Content-Type-Options' and header_value.lower() != 'nosniff':
            valid = False
            notes.append("Should be 'nosniff'")
        
        if header == 'X-Frame-Options' and header_value.upper() not in ('DENY', 'SAMEORIGIN'):
            valid = False
            notes.append("Should be 'DENY' or 'SAMEORIGIN'")
        
        if header == 'X-XSS-Protection' and header_value.lower() != '1; mode=block':
            valid = False
            notes.append("Should be '1; mode=block'")
        
        if header == 'Strict-Transport-Security':
            if 'max-age' not in header_value.lower():
                valid = False
                notes.append("Should include max-age")
            if 'preload' in header_value.lower() and 'includeSubDomains' not in header_value.lower():
                valid = False
                notes.append("preload requires includeSubDomains")
        
        if not valid:
            stats['invalid_security_values'] += 1
            message = f"Invalid value: '{header_value}'. Notes: {', '.join(notes)}"
        else:
            message = f"Properly configured: '{header_value}'"
        
        results.append((f"Security: {header}", valid, message))
    
    return results, stats

def analyze_headers(headers, method='GET', status_code=200, is_https=False):
    """Comprehensive analysis of HTTP headers."""
    results = []
    stats = defaultdict(int)
    
    # Check required headers
    host_ok, host_msg = check_host_header_presence(headers)
    results.append(('Host header check', host_ok, host_msg))
    stats['required_headers'] += 0 if host_ok else 1
    
    # Validate each header
    for name, value in headers.items():
        # Header name validation
        name_ok, name_msg = validate_header_name(name)
        results.append((f"Header name: '{name}'", name_ok, name_msg))
        stats['name_issues'] += 0 if name_ok else 1
        
        # Header value validation
        value_ok, value_msg = validate_header_value(value)
        results.append((f"Header value: '{value}'", value_ok, value_msg))
        stats['value_issues'] += 0 if value_ok else 1
        
        # Standard header check
        std_ok, std_msg = check_standard_header(name)
        results.append((f"Standard header: '{name}'", std_ok, std_msg))
        stats['non_standard'] += 0 if std_ok or name.startswith('X-') else 1
    
    # Special header condition checks
    cl_ok, cl_msg = check_content_length_conditions(headers, method, status_code)
    if isinstance(cl_msg, list):
        for msg in cl_msg:
            results.append(('Content-Length condition', False, msg))
            stats['special_conditions'] += 1
    else:
        results.append(('Content-Length condition', cl_ok, cl_msg))
        stats['special_conditions'] += 0 if cl_ok else 1
    
    # Security header checks
    security_results, security_stats = check_security_headers(headers, is_https)
    results.extend(security_results)
    for k, v in security_stats.items():
        stats[k] += v
    
    return results, stats

def print_report(results, stats, url):
    """Print a formatted compliance report."""
    print(f"\nHTTP Header Compliance and Security Report for {url}")
    print("=" * 80)
    
    # Print security findings first
    print("\n[SECURITY HEADER CHECKS]")
    security_results = [r for r in results if r[0].startswith('Security:')]
    for title, passed, message in security_results:
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {title}: {message}")
    
    # Print other results
    print("\n[RFC COMPLIANCE CHECKS]")
    other_results = [r for r in results if not r[0].startswith('Security:')]
    for title, passed, message in other_results:
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {title}: {message}")
    
    # Print summary
    print("\nSUMMARY STATISTICS:")
    print(f"- Header name issues: {stats['name_issues']}")
    print(f"- Header value issues: {stats['value_issues']}")
    print(f"- Non-standard headers (excluding X-*): {stats['non_standard']}")
    print(f"- Required header issues: {stats['required_headers']}")
    print(f"- Special condition issues: {stats['special_conditions']}")
    print("\nSECURITY STATISTICS:")
    print(f"- Missing required security headers: {stats['missing_required_security']}")
    print(f"- Missing optional security headers: {stats['missing_optional_security']}")
    print(f"- Security headers with invalid values: {stats['invalid_security_values']}")
    
    # Calculate security score (0-100)
    total_security_checks = len(SECURITY_HEADERS)
    security_failures = (
        stats['missing_required_security'] +
        stats['invalid_security_values']
    )
    security_score = max(0, 100 - (security_failures * 100 // total_security_checks))
    print(f"\nSECURITY SCORE: {security_score}/100")

def check_url(url, method='GET'):
    """Check headers from a given URL."""
    try:
        # First make a HEAD request to check if it's allowed
        try:
            head_response = requests.head(url, allow_redirects=True, timeout=10)
            use_head = True
        except requests.exceptions.RequestException:
            use_head = False
        
        # Then make the actual request with the specified method
        response = requests.request(
            method if not use_head else 'HEAD',
            url,
            allow_redirects=True,
            timeout=10
        )
        
        is_https = urlparse(url).scheme == 'https'
        results, stats = analyze_headers(
            response.headers,
            method=method,
            status_code=response.status_code,
            is_https=is_https
        )
        print_report(results, stats, url)
        return True
    except requests.RequestException as e:
        print(f"Error fetching {url}: {str(e)}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(
        description="HTTP Header RFC Compliance and Security Checker"
    )
    parser.add_argument(
        'url',
        help="URL to check HTTP headers from"
    )
    parser.add_argument(
        '-m', '--method',
        default='GET',
        help="HTTP method to use (default: GET)"
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help="Show more detailed output"
    )
    
    args = parser.parse_args()
    
    if not urlparse(args.url).scheme:
        args.url = 'http://' + args.url
    
    check_url(args.url, args.method)

if __name__ == '__main__':
    main()
