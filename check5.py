import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
from colorama import Fore, Style, init
import http.client
import json

# Initialize colorama
init(autoreset=True)

def check_header_compliance(headers):
    """Check HTTP headers for RFC compliance and security best practices."""
    results = []
    required_headers = [
        'Content-Type',
        'Cache-Control',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Content-Security-Policy',
        'Strict-Transport-Security'
    ]
    
    # Check for required headers
    for header in required_headers:
        if header not in headers:
            results.append((header, "MISSING", False))
        else:
            # Validate specific headers
            value = headers[header]
            valid = True
            suggestion = ""
            
            if header == 'Content-Type' and 'charset' not in value:
                valid = False
                suggestion = "Should include charset (e.g., 'text/html; charset=utf-8')"
            
            if header == 'Cache-Control' and 'no-cache' not in value and 'max-age' not in value:
                valid = False
                suggestion = "Should specify caching policy (e.g., 'max-age=3600' or 'no-cache')"
            
            if header == 'X-Content-Type-Options' and value.lower() != 'nosniff':
                valid = False
                suggestion = "Should be 'nosniff'"
            
            if header == 'X-Frame-Options' and value.upper() not in ('DENY', 'SAMEORIGIN'):
                valid = False
                suggestion = "Should be 'DENY' or 'SAMEORIGIN'"
            
            if header == 'X-XSS-Protection' and value != '1; mode=block':
                valid = False
                suggestion = "Should be '1; mode=block'"
            
            if header == 'Content-Security-Policy' and not value:
                valid = False
                suggestion = "Should define a content security policy"
            
            if header == 'Strict-Transport-Security' and not re.match(r'max-age=\d+', value):
                valid = False
                suggestion = "Should include max-age (e.g., 'max-age=31536000')"
            
            results.append((header, value, valid, suggestion))
    
    return results

def extract_assets(url, html_content):
    """Extract all assets (CSS, JS, images) from the HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    assets = {
        'css': [],
        'js': [],
        'images': [],
        'other': []
    }
    
    # Extract CSS files
    for link in soup.find_all('link', {'rel': 'stylesheet'}):
        href = link.get('href')
        if href:
            assets['css'].append(urljoin(url, href))
    
    # Extract JavaScript files
    for script in soup.find_all('script', {'src': True}):
        src = script.get('src')
        if src:
            assets['js'].append(urljoin(url, src))
    
    # Extract images (including lazy-loaded ones)
    for img in soup.find_all('img'):
        src = img.get('src') or img.get('data-src') or img.get('data-lazy')
        if src:
            assets['images'].append(urljoin(url, src))
    
    # Extract other potential assets
    for tag in soup.find_all(['source', 'iframe', 'embed', 'object']):
        src = tag.get('src') or tag.get('data-src')
        if src:
            assets['other'].append(urljoin(url, src))
    
    return assets

def analyze_url(url):
    """Analyze the given URL for headers, security, and assets."""
    try:
        response = requests.get(url, timeout=10)
        headers = dict(response.headers)
        
        # Header compliance check
        compliance_results = check_header_compliance(headers)
        
        # Extract assets
        assets = extract_assets(url, response.text)
        
        # Calculate header and cookie sizes
        header_size = len(str(headers).encode('utf-8'))
        cookies = response.cookies
        cookie_size = len(str(cookies).encode('utf-8'))
        
        return {
            'url': url,
            'status_code': response.status_code,
            'headers': headers,
            'compliance_results': compliance_results,
            'assets': assets,
            'header_size': header_size,
            'cookies': cookies,
            'cookie_size': cookie_size,
            'error': None
        }
    except Exception as e:
        return {
            'url': url,
            'error': str(e)
        }

def print_results(results):
    """Print the analysis results with colored output."""
    if results['error']:
        print(f"{Fore.RED}Error analyzing {results['url']}: {results['error']}{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.YELLOW}=== Analysis for {results['url']} ==={Style.RESET_ALL}")
    print(f"Status Code: {results['status_code']}")
    
    # Print header size in blue
    print(f"\n{Fore.BLUE}Header Size: {results['header_size']} bytes{Style.RESET_ALL}")
    
    # Print cookies in blue with size
    print(f"\n{Fore.BLUE}Cookies ({results['cookie_size']} bytes):{Style.RESET_ALL}")
    for cookie in results['cookies']:
        print(f"  {cookie.name}: {cookie.value}")
    
    # Print header compliance results
    print(f"\n{Fore.YELLOW}=== Header Compliance Checks ==={Style.RESET_ALL}")
    for check in results['compliance_results']:
        if len(check) == 3:  # Missing header
            header, status, valid = check
            if valid:
                print(f"{Fore.GREEN}PASS{Style.RESET_ALL}: {header}: {status}")
            else:
                print(f"{Fore.RED}FAIL{Style.RESET_ALL}: {header}: {status} - Header is missing")
        else:  # Header exists
            header, value, valid, suggestion = check
            if valid:
                print(f"{Fore.GREEN}PASS{Style.RESET_ALL}: {header}: {value}")
            else:
                print(f"{Fore.RED}FAIL{Style.RESET_ALL}: {header}: {value} - {suggestion}")
    
    # Print assets
    print(f"\n{Fore.YELLOW}=== Assets ==={Style.RESET_ALL}")
    for asset_type, urls in results['assets'].items():
        print(f"\n{asset_type.upper()}:")
        for url in urls:
            print(f"  {url}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python script.py <URL>")
        sys.exit(1)
    
    url = sys.argv[1]
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    results = analyze_url(url)
    print_results(results)
