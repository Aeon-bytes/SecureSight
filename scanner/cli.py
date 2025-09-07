import argparse
from scanner.port_scanner import scan_ports
from scanner.ssl_scanner import scan_ssl
from scanner.http_scanner import scan_http
from scanner.dns_scanner import scan_dns
from scanner.report import generate_report

def run_all_scans(target, enabled_modules=None):
    results = {}
    if enabled_modules is None or "ports" in enabled_modules:
        print(f"Scanning ports for {target}...")
        results['ports'] = scan_ports(target)
    if enabled_modules is None or "ssl" in enabled_modules:
        print(f"Scanning SSL/TLS for {target}...")
        results['ssl'] = scan_ssl(target)
    if enabled_modules is None or "http" in enabled_modules:
        print(f"Scanning web configuration for {target}...")
        results['http'] = scan_http(target)
    if enabled_modules is None or "dns" in enabled_modules:
        print(f"Scanning DNS records for {target}...")
        results['dns'] = scan_dns(target)
    return results

def print_summary(results):
    print("\n--- Scan Summary ---")
    # Ports
    if 'ports' in results:
        ports = results['ports']
        if 'error' in ports:
            print(f"[Ports] Error: {ports['error']}")
        elif ports.get('open_ports'):
            print(f"[Ports] Open ports: {', '.join(map(str, ports['open_ports']))}")
        else:
            print("[Ports] No open ports detected.")
    # SSL
    if 'ssl' in results:
        ssl = results['ssl']
        if 'error' in ssl:
            print(f"[SSL] Error: {ssl['error']}")
        else:
            print(f"[SSL] Expires: {ssl.get('not_after', 'N/A')}, Advice: {ssl.get('advice', 'N/A')}")
    # HTTP/Web
    if 'http' in results:
        http = results['http']
        if 'error' in http:
            print(f"[Web] Error: {http['error']}")
        else:
            if http.get('findings'):
                print("[Web] Findings:")
                for finding in http['findings']:
                    print(f"  - {finding}")
            else:
                print("[Web] No major web config issues detected.")
    # DNS
    if 'dns' in results:
        dns_res = results['dns']
        if 'error' in dns_res:
            print(f"[DNS] Error: {dns_res['error']}")
        else:
            print("[DNS] A Records:", ', '.join(dns_res['a']))
            print("[DNS] AAAA Records:", ', '.join(dns_res['aaaa']))
            print("[DNS] MX Records:", ', '.join(dns_res['mx']))
            print("[DNS] NS Records:", ', '.join(dns_res['ns']))
            print("[DNS] TXT Records:", ', '.join(dns_res['txt']))

def main():
    parser = argparse.ArgumentParser(
        description="Open-Source Configuration Exposure Scanner"
    )
    parser.add_argument("target", help="Domain or IP to scan")
    parser.add_argument("--output", default="scan_report.html", help="Report output file")
    parser.add_argument("--modules", nargs='*', help="Specify modules to run (e.g., ports ssl http dns). Default: all")
    args = parser.parse_args()

    print(f"Scanning {args.target}...")

    results = run_all_scans(args.target, args.modules)

    generate_report(args.target, results, args.output)
    print(f"Scan complete! Report saved to {args.output}")
    print_summary(results)
