import asyncio
from playwright.async_api import async_playwright
import requests
from urllib.parse import urlparse

REPORT_FILE = "cache_report.html"

async def fetch_cache_headers(url):
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        if response.status_code == 405:  # Method Not Allowed
            response = requests.get(url, stream=True, timeout=10)
        return {
            'Cache-Control': response.headers.get('Cache-Control', ''),
            'Expires': response.headers.get('Expires', ''),
            'ETag': response.headers.get('ETag', ''),
            'Last-Modified': response.headers.get('Last-Modified', ''),
            'Status': response.status_code
        }
    except Exception as e:
        return {'Error': str(e)}

async def analyze_page(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()

        assets = {}

        # Intercepter toutes les requêtes réseau
        page.on("requestfinished", lambda request: assets.setdefault(request.url, None))
        
        print(f"Chargement de la page {url}...")
        await page.goto(url, wait_until='networkidle')

        print(f"Récupération des headers de cache pour {len(assets)} assets...")
        for asset_url in assets.keys():
            # Filtrer uniquement les URLs HTTP/HTTPS
            parsed = urlparse(asset_url)
            if parsed.scheme not in ('http', 'https'):
                assets[asset_url] = {'Error': 'Non HTTP(S) resource'}
                continue
            assets[asset_url] = await fetch_cache_headers(asset_url)

        await browser.close()
        return assets

def generate_html_report(url, assets):
    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8" />
<title>Rapport Cache HTTP pour {url}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
th {{ background-color: #f4f4f4; }}
tr:nth-child(even) {{ background-color: #fafafa; }}
.error {{ color: red; }}
</style>
</head>
<body>
<h1>Rapport Cache HTTP</h1>
<p>URL analysée : <a href="{url}">{url}</a></p>
<table>
<thead>
<tr>
<th>URL de l’asset</th>
<th>Status</th>
<th>Cache-Control</th>
<th>Expires</th>
<th>ETag</th>
<th>Last-Modified</th>
<th>Erreur</th>
</tr>
</thead>
<tbody>
"""

    for asset_url, headers in assets.items():
        error = headers.get('Error', '') if headers else 'Aucune donnée'
        status = headers.get('Status', '') if headers else ''
        cache_control = headers.get('Cache-Control', '') if headers else ''
        expires = headers.get('Expires', '') if headers else ''
        etag = headers.get('ETag', '') if headers else ''
        last_modified = headers.get('Last-Modified', '') if headers else ''

        html += f"<tr>"
        html += f'<td><a href="{asset_url}" target="_blank">{asset_url}</a></td>'
        html += f'<td>{status}</td>'
        html += f'<td>{cache_control}</td>'
        html += f'<td>{expires}</td>'
        html += f'<td>{etag}</td>'
        html += f'<td>{last_modified}</td>'
        html += f'<td class="error">{error}</td>'
        html += "</tr>"

    html += """
</tbody>
</table>
</body>
</html>"""
    return html

async def main(url):
    assets = await analyze_page(url)

    # Affichage console synthétique
    print(f"\nRapport des assets ({len(assets)}):")
    for asset_url, headers in assets.items():
        print(f"\nURL: {asset_url}")
        if 'Error' in headers:
            print(f"  Erreur: {headers['Error']}")
        else:
            for k in ['Status', 'Cache-Control', 'Expires', 'ETag', 'Last-Modified']:
                print(f"  {k}: {headers.get(k, '')}")

    # Génération rapport HTML
    report_html = generate_html_report(url, assets)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report_html)
    print(f"\nRapport HTML généré : {REPORT_FILE}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python cache_analyzer_playwright.py <URL>")
        sys.exit(1)
    url_to_check = sys.argv[1]
    asyncio.run(main(url_to_check))

