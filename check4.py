import re
import argparse
from urllib.parse import urlparse, urljoin
import requests
from collections import defaultdict
import sys
from colorama import init, Fore, Style, Back
from bs4 import BeautifulSoup

# Initialize colorama
init(autoreset=True)

# Standard headers and security headers definitions would go here
# [Previous definitions of STANDARD_HEADERS and SECURITY_HEADERS remain the same]

# Cache-related headers and directives
CACHE_HEADERS = {
    'Cache-Control': {
        'directives': {
            'public': 'Response may be cached by any cache',
            'private': 'Response intended for single user',
            'no-cache': 'Cache must revalidate with origin server',
            'no-store': 'Cache must not store any part of response',
            'max-age': 'Maximum time in seconds resource is fresh',
            's-maxage': 'Shared cache maximum age',
            'must-revalidate': 'Cache must verify status of stale resources',
            'proxy-revalidate': 'Same as must-revalidate but for shared caches',
            'immutable': 'Resource will not change during freshness lifetime',
            'stale-while-revalidate': 'Time in seconds stale cache may be used while revalidating',
            'stale-if-error': 'Time in seconds stale cache may be used if revalidation fails'
        }
    },
    'Expires': {
        'description': 'Absolute expiration time for resource'
    },
    'Pragma': {
        'description': 'HTTP/1.0 cache control (legacy)'
    },
    'ETag': {
        'description': 'Validator for cache revalidation'
    },
    'Last-Modified': {
        'description': 'Date when resource was last modified'
    },
    'Vary': {
        'description': 'Headers that affect cache validity'
    },
    'Age': {
        'description': 'Time in seconds since response was generated'
    }
}

def colored_status(passed):
    """Return colored PASS/FAIL string."""
    if passed:
        return f"{Fore.GREEN}PASS{Style.RESET_ALL}"
    return f"{Fore.RED}FAIL{Style.RESET_ALL}"

def colored_cache_info(message):
    """Return cache-related information in blue."""
    return f"{Fore.BLUE}{message}{Style.RESET_ALL}"

def calculate_header_size(headers):
    """Calculate approximate header size in bytes."""
    total_size = 0
    for name, value in headers.items():
        total_size += len(name) + 2 + len(str(value)) + 2  # name: value\r\n
    total_size += 2  # Final \r\n
    return total_size

def analyze_cache_headers(headers):
    """Analyze cache-related headers and their directives."""
    results = []
    stats = defaultdict(int)
    cache_analysis = {}
    
    for header, config in CACHE_HEADERS.items():
        if header in headers:
            value = headers[header]
            cache_analysis[header] = value
            
            if header == 'Cache-Control':
                directives = {}
                for directive in value.split(','):
                    directive = directive.strip()
                    if '=' in directive:
                        name, val = directive.split('=', 1)
                        directives[name.strip()] = val.strip()
                    else:
                        directives[directive] = True
                
                for directive, desc in config['directives'].items():
                    if directive in directives:
                        result = (directive, True, 
                                colored_cache_info(f"Present: {directive}={directives[directive]} ({desc})"))
                        stats['cache_directives_present'] += 1
                    else:
                        result = (directive, False, 
                                colored_cache_info(f"Missing: {directive} ({desc})"))
                        stats['cache_directives_missing'] += 1
                    results.append(result)
            else:
                results.append((header, True, 
                              colored_cache_info(f"{value} ({config['description']})")))
                stats['cache_headers_present'] += 1
        else:
            results.append((header, False, 
                          colored_cache_info(f"Missing ({config.get('description', '')})")))
            stats['cache_headers_missing'] += 1
    
    return results, stats, cache_analysis

def get_page_assets(url, session):
    """Fetch and parse HTML to find assets (CSS, JS, images)."""
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        assets = {
            'css': [urljoin(url, link['href']) for link in soup.find_all('link', 
                    {'rel': 'stylesheet'}) if 'href' in link.attrs],
            'js': [urljoin(url, script['src']) for script in soup.find_all('script') 
                  if 'src' in script.attrs],
            'images': [urljoin(url, img['src']) for img in soup.find_all('img') 
                      if 'src' in img.attrs],
            'other': []
        }
        return assets
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not parse assets from {url}: {e}{Style.RESET_ALL}")
        return None

def check_asset_cache_headers(assets, session):
    """Check cache headers for all page assets."""
    asset_results = {}
    asset_stats = defaultdict(int)
    
    if not assets:
        return {}, defaultdict(int)
    
    for asset_type, urls in assets.items():
        asset_results[asset_type] = []
        for url in urls[:3]:  # Check first 3 of each type for performance
            try:
                response = session.head(url, allow_redirects=True, timeout=5)
                _, _, cache_analysis = analyze_cache_headers(response.headers)
                
                asset_results[asset_type].append({
                    'url': url,
                    'cache_headers': response.headers,
                    'cache_control': cache_analysis.get('Cache-Control', 'None')
                })
                
                # Count cache hits/misses
                cc = response.headers.get('Cache-Control', '').lower()
                if 'no-cache' in cc or 'no-store' in cc:
                    asset_stats['no_cache_assets'] += 1
                elif 'max-age' in cc or 'public' in cc:
                    asset_stats['cached_assets'] += 1
                else:
                    asset_stats['unknown_cache_assets'] += 1
                    
            except requests.RequestException as e:
                asset_results[asset_type].append({
                    'url': url,
                    'error': str(e)
                })
                asset_stats['failed_assets'] += 1
    
    return asset_results, asset_stats

def print_report(results, stats, cookie_details, url, cache_results, asset_results, asset_stats):
    """Print a formatted compliance report."""
    print(f"\n{Fore.CYAN}HTTP Header Compliance and Security Report for {url}{Style.RESET_ALL}")
    print("=" * 100)
    
    # Header size
    size_result = next(r for r in results if r[0] == 'Header Size')
    print(f"\nHeader Size: {Fore.YELLOW}{size_result[2]}{Style.RESET_ALL}")
    
    # Security findings
    print(f"\n{Fore.CYAN}[SECURITY HEADER CHECKS]{Style.RESET_ALL}")
    security_results = [r for r in results if r[0].startswith('Security:')]
    for title, passed, message in security_results:
        print(f"[{colored_status(passed)}] {title}: {message}")
    
    # Cookie analysis
    if stats['cookies'] > 0:
        print(f"\n{Fore.CYAN}[COOKIE ANALYSIS]{Style.RESET_ALL}")
        for cookie, cookie_checks in cookie_details:
            print(f"\nCookie: {Fore.YELLOW}{cookie.split(';')[0]}{Style.RESET_ALL}")
            for check, passed, msg in cookie_checks:
                print(f"  [{colored_status(passed)}] {check}: {msg}")
    
    # RFC compliance checks
    print(f"\n{Fore.CYAN}[RFC COMPLIANCE CHECKS]{Style.RESET_ALL}")
    other_results = [r for r in results if not r[0].startswith('Security:') and r[0] not in ('Header Size', 'Cookies Present')]
    for title, passed, message in other_results:
        print(f"[{colored_status(passed)}] {title}: {message}")
    
    # Cache analysis
    print(f"\n{Back.BLUE}{Fore.WHITE}CACHE ANALYSIS{Style.RESET_ALL}")
    print(f"\n{Fore.BLUE}Page Cache Headers:{Style.RESET_ALL}")
    for header, passed, message in cache_results:
        print(f"[{colored_status(passed)}] {message}")
    
    # Asset cache analysis
    if asset_results:
        print(f"\n{Fore.BLUE}Asset Cache Analysis:{Style.RESET_ALL}")
        print(f"  - Cached assets: {asset_stats['cached_assets']}")
        print(f"  - No-cache assets: {asset_stats['no_cache_assets']}")
        print(f"  - Unknown cache policy: {asset_stats['unknown_cache_assets']}")
        print(f"  - Failed to check: {asset_stats['failed_assets']}")
        
        for asset_type, assets in asset_results.items():
            if assets:
                print(f"\n  {Fore.BLUE}{asset_type.upper()} ({len(assets)}):{Style.RESET_ALL}")
                for asset in assets:
                    if 'error' in asset:
                        print(f"    {asset['url']}: {Fore.RED}Error - {asset['error']}{Style.RESET_ALL}")
                    else:
                        cc = asset['cache_control']
                        color = Fore.GREEN if 'max-age' in cc.lower() else Fore.YELLOW if 'no-cache' in cc.lower() else Fore.RED
                        print(f"    {asset['url']}: {color}{cc}{Style.RESET_ALL}")

def check_url(url, method='GET'):
    """Check headers from a given URL."""
    try:
        session = requests.Session()
        
        # First make a HEAD request to check if it's allowed
        try:
            head_response = session.head(url, allow_redirects=True, timeout=10)
            use_head = True
        except requests.exceptions.RequestException:
            use_head = False
        
        # Then make the actual request with the specified method
        response = session.request(
            method if not use_head else 'HEAD',
            url,
            allow_redirects=True,
            timeout=10
        )
        
        is_https = urlparse(url).scheme == 'https'
        
        # Analyze headers
        header_size = calculate_header_size(response.headers)
        results = [('Header Size', True, f"{header_size} bytes")]
        
        # Add other header checks here (security, cookies, etc.)
        # [Previous header analysis code would go here]
        
        # Cache analysis
        cache_results, cache_stats, _ = analyze_cache_headers(response.headers)
        results.extend(cache_results)
        
        # Asset cache analysis
        assets = get_page_assets(url, session)
        asset_results, asset_stats = check_asset_cache_headers(assets, session)
        
        # Print report (using dummy values for missing parts)
        print_report(
            results=results,
            stats={'cookies': 0},  # Dummy value
            cookie_details=[],  # Dummy value
            url=url,
            cache_results=cache_results,
            asset_results=asset_results,
            asset_stats=asset_stats
        )
        
        return True
    except requests.RequestException as e:
        print(f"{Fore.RED}Error fetching {url}: {str(e)}{Style.RESET_ALL}", file=sys.stderr)
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
    
    args = parser.parse_args()
    
    if not urlparse(args.url).scheme:
        args.url = 'http://' + args.url
    
    check_url(args.url, args.method)

if __name__ == '__main__':
    main()
