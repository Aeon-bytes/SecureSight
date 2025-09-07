import argparse
from scanner.port_scanner import scan_ports
from scanner.ssl_scanner import scan_ssl
from scanner.http_scanner import scan_http
from scanner.report import generate_report

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
