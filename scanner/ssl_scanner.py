from sslyze import ServerNetworkLocation, Scanner, ServerScanRequest, ScanCommand
from sslyze.plugins.certificate_info.implementation import CertificateInfoScanResult

def scan_ssl(target):
    try:
        server_location = ServerNetworkLocation(hostname=target, port=443)
        scan_request = ServerScanRequest(
            server_location=server_location,
            scan_commands={ScanCommand.CERTIFICATE_INFO}
        )
        scanner = Scanner()
        scanner.queue_scans([scan_request])
        for scan_result in scanner.get_results():
            cert_info = scan_result.scan_commands_results.get(ScanCommand.CERTIFICATE_INFO)
            if isinstance(cert_info, CertificateInfoScanResult):
                expired = cert_info.certificate_has_expired
                advice = "Renew SSL certificate." if expired else "SSL certificate is valid."
                return {
                    "expired": expired,
                    "subject": cert_info.subject,
                    "issuer": cert_info.issuer,
                    "not_after": cert_info.not_after,
                    "advice": advice
                }
            else:
                return {"error": "Could not retrieve certificate info."}
        return {"error": "No scan results returned."}
    except Exception as e:
        return {"error": str(e)}
