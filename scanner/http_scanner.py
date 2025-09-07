import requests
from bs4 import BeautifulSoup

def scan_http(target):
    url = f"https://{target}"
    try:
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        findings = []

        # Check for directory listing
        if "Index of /" in resp.text:
            findings.append("Directory listing is enabled.")

        # Check for missing security headers
        missing_headers = []
        for header in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]:
            if header not in headers:
                missing_headers.append(header)
        if missing_headers:
            findings.append(f"Missing security headers: {', '.join(missing_headers)}")

        # Check for outdated CMS (simple check for WordPress)
        if "wp-content" in resp.text:
            findings.append("WordPress detected. Check for outdated plugins/themes.")

        # Check for error pages
        if "error" in resp.text.lower():
            findings.append("Error page detected. May reveal sensitive info.")

        return {
            "findings": findings,
            "advice": "Review findings and apply recommended security headers and CMS/plugin updates."
        }
    except Exception as e:
        return {"error": str(e)}
