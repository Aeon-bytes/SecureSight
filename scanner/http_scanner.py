import requests
from bs4 import BeautifulSoup

def try_request(url):
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True)
        return resp
    except Exception as e:
        return e

def scan_http(target):
    findings = []
    headers = {}
    url_https = f"https://{target}"
    url_http = f"http://{target}"
    resp = try_request(url_https)
    used_https = True
    if isinstance(resp, Exception):
        resp = try_request(url_http)
        used_https = False
    if isinstance(resp, Exception):
        return {"error": str(resp)}
    headers = resp.headers
    # Directory listing
    if "Index of /" in resp.text:
        findings.append("Directory listing is enabled.")
    # Missing security headers
    missing_headers = []
    for header in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]:
        if header not in headers:
            missing_headers.append(header)
    if missing_headers:
        findings.append(f"Missing security headers: {', '.join(missing_headers)}")
    # CORS
    if 'Access-Control-Allow-Origin' in headers:
        if headers['Access-Control-Allow-Origin'] == '*':
            findings.append("CORS policy is too permissive (Access-Control-Allow-Origin: *).")
    # X-Powered-By
    if 'X-Powered-By' in headers:
        findings.append(f"X-Powered-By header present: {headers['X-Powered-By']}")
    # Server header
    if 'Server' in headers:
        findings.append(f"Server header present: {headers['Server']}")
    # Outdated CMS (WordPress, Joomla, Drupal, etc.)
    if "wp-content" in resp.text:
        findings.append("WordPress detected. Check for outdated plugins/themes.")
    if "Joomla!" in resp.text:
        findings.append("Joomla detected. Check for outdated extensions.")
    if "Drupal.settings" in resp.text:
        findings.append("Drupal detected. Check for outdated modules.")
    # Error pages
    if "error" in resp.text.lower():
        findings.append("Error page detected. May reveal sensitive info.")
    # robots.txt
    try:
        robots = try_request((url_https if used_https else url_http) + "/robots.txt")
        if not isinstance(robots, Exception) and robots.status_code == 200:
            if "Disallow: /" not in robots.text:
                findings.append("robots.txt found and may expose sensitive paths.")
    except Exception:
        pass
    # Exposed .git directory
    try:
        git_resp = try_request((url_https if used_https else url_http) + "/.git/HEAD")
        if not isinstance(git_resp, Exception) and git_resp.status_code == 200:
            findings.append("Exposed .git directory detected!")
    except Exception:
        pass
    return {
        "findings": findings,
        "advice": "Review findings and apply recommended security headers, restrict CORS, and update CMS/plugins as needed."
    }
