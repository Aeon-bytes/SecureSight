import argparse
from scanner.port_scanner import scan_ports
from scanner.ssl_scanner import scan_ssl
from scanner.http_scanner import scan_http
from scanner.report import generate_report

def print_summary(results):
    print("\n--- Scan Summary ---")
    # Ports
    ports = results.get('ports', {})
    if 'error' in ports:
        print(f"[Ports] Error: {ports['error']}")
    elif ports.get('open_ports'):
        print(f"[Ports] Open ports: {', '.join(map(str, ports['open_ports']))}")
    else:
        print("[Ports] No open ports detected.")
    # SSL
    ssl = results.get('ssl', {})
    if 'error' in ssl:
        print(f"[SSL] Error: {ssl['error']}")
    else:
        print(f"[SSL] Expires: {ssl.get('not_after', 'N/A')}, Advice: {ssl.get('advice', 'N/A')}")
    # HTTP/Web
    http = results.get('http', {})
    if 'error' in http:
        print(f"[Web] Error: {http['error']}")
    else:
        if http.get('findings'):
            print("[Web] Findings:")
            for finding in http['findings']:
                print(f"  - {finding}")
        else:
            print("[Web] No major web config issues detected.")

def main():
    parser = argparse.ArgumentParser(
        description="Open-Source Configuration Exposure Scanner"
    )
    parser.add_argument("target", help="Domain or IP to scan")
    parser.add_argument("--output", default="scan_report.html", help="Report output file")
    args = parser.parse_args()

    print(f"Scanning {args.target}...")

    results = {}
    results['ports'] = scan_ports(args.target)
    results['ssl'] = scan_ssl(args.target)
    results['http'] = scan_http(args.target)

    generate_report(args.target, results, args.output)
    print(f"Scan complete! Report saved to {args.output}")
    print_summary(results)
